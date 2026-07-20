use super::*;
#[cfg(any(test, feature = "libsql", feature = "postgres"))]
use crate::matrix_product_outbound::{
    DefaultMatrixOutboundPolicyAuthorizer, FilesystemMatrixPolicySnapshotSource,
    MatrixOutboundPolicyAuthorizer, MatrixPolicySnapshotSource,
};
#[cfg(any(test, feature = "libsql", feature = "postgres"))]
use crate::matrix_product_outbound::{
    matrix_policy_projection_cache_path_for_route,
    matrix_policy_projection_resource_scope_for_route,
};
#[cfg(any(test, feature = "libsql", feature = "postgres"))]
use ironclaw_matrix_adapter::installation_policy::{
    EgressTargetIndex as AdapterEgressTargetIndex, MatrixInstallationPolicyRejection,
    MatrixOutboundPolicyCheck as AdapterMatrixOutboundPolicyCheck,
    MatrixPolicySnapshot as AdapterMatrixPolicySnapshot, PolicyRevision as AdapterPolicyRevision,
};
#[cfg(any(test, feature = "libsql", feature = "postgres"))]
use ironclaw_product_adapters::{AdapterInstallationId, ProductAdapterId};

// Executes one Matrix retry schedule. Production worker ticks use the
// rehydrating entrypoint so stored route/grant context is validated again by
// the shared orchestrator before every send.
pub struct MatrixRetryExecutor;

impl MatrixRetryExecutor {
    pub async fn execute_due_retry_from_store<F>(
        metadata_store: &FilesystemMatrixOutboundMetadataStore<F>,
        pending_store: &FilesystemMatrixPendingIntentStore<F>,
        bridge: &MatrixProductionDeliveryBridge<'_, F>,
        retry_send_authorizer: &dyn MatrixRetrySendAuthorizer,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        now: DateTime<Utc>,
    ) -> Result<Option<MatrixOrchestratorOutcome>, DeliveryError>
    where
        F: RootFilesystem,
    {
        let context = metadata_store
            .load_retry_execution_context(scope, delivery_id)
            .await?
            .ok_or_else(|| DeliveryError::new(DeliveryReasonCode::MissingMatrixRoute))?;
        let (route, grant) = context.into_parts();
        Self::execute_due_retry(
            metadata_store,
            pending_store,
            bridge,
            retry_send_authorizer,
            route,
            grant,
            now,
        )
        .await
    }

    pub async fn execute_due_retry<F>(
        metadata_store: &FilesystemMatrixOutboundMetadataStore<F>,
        pending_store: &FilesystemMatrixPendingIntentStore<F>,
        bridge: &MatrixProductionDeliveryBridge<'_, F>,
        retry_send_authorizer: &dyn MatrixRetrySendAuthorizer,
        route: FrozenProductDeliveryRoute,
        grant: SealedDeliveryGrant,
        now: DateTime<Utc>,
    ) -> Result<Option<MatrixOrchestratorOutcome>, DeliveryError>
    where
        F: RootFilesystem,
    {
        Self::execute_due_retry_inner(
            metadata_store,
            pending_store,
            bridge,
            retry_send_authorizer,
            route,
            grant,
            now,
        )
        .await
    }

    async fn execute_due_retry_inner<F>(
        metadata_store: &FilesystemMatrixOutboundMetadataStore<F>,
        pending_store: &FilesystemMatrixPendingIntentStore<F>,
        bridge: &MatrixProductionDeliveryBridge<'_, F>,
        retry_send_authorizer: &dyn MatrixRetrySendAuthorizer,
        route: FrozenProductDeliveryRoute,
        grant: SealedDeliveryGrant,
        now: DateTime<Utc>,
    ) -> Result<Option<MatrixOrchestratorOutcome>, DeliveryError>
    where
        F: RootFilesystem,
    {
        let scope = route.scope().clone();
        let delivery_id = route.delivery_id;
        let schedule = metadata_store
            .load_retry_schedule(scope.clone(), delivery_id)
            .await?
            .ok_or_else(|| DeliveryError::new(DeliveryReasonCode::MissingMatrixRoute))?;
        let due_at = schedule
            .recorded_at
            .checked_add_signed(
                chrono_duration_from_std(schedule.retry_after)
                    .map_err(|_| DeliveryError::new(DeliveryReasonCode::MatrixMalformedResponse))?,
            )
            .ok_or_else(|| DeliveryError::new(DeliveryReasonCode::MatrixMalformedResponse))?;
        if now < due_at {
            return Ok(None);
        }
        let Some(schedule) = metadata_store
            .claim_due_retry_schedule(scope.clone(), delivery_id, now, MATRIX_RETRY_CLAIM_LEASE)
            .await?
        else {
            return Ok(None);
        };
        let command = pending_store
            .load_pending_command(scope.clone(), delivery_id, delivery_id.as_uuid())
            .await?
            .ok_or_else(|| DeliveryError::new(DeliveryReasonCode::MissingMatrixRoute))?;
        let exhausted_decision = bridge.orchestrator.retry_policy.classify(
            &DeliveryError::new(schedule.reason),
            schedule.attempt_number,
        );
        if let MatrixRetryDecision::DoNotRetry { terminal_status } = exhausted_decision {
            bridge
                .orchestrator
                .persist_terminal_status(
                    delivery_id,
                    scope.clone(),
                    terminal_status,
                    Some(DeliveryReasonCode::MaxAttemptsExceeded),
                )
                .await?;
            pending_store
                .mark_pending_command_consumed(scope, delivery_id, delivery_id.as_uuid())
                .await?;
            return Err(DeliveryError::new(DeliveryReasonCode::MaxAttemptsExceeded));
        }
        let context = MatrixRetryExecutionContext::new(route.clone(), grant.clone())
            .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))?;
        retry_send_authorizer
            .authorize_retry_send(&context, &command)
            .await?;
        let attempt = DeliveryAttemptContext {
            delivery_id,
            transaction_id: command.transaction_id,
            attempt_number: schedule.attempt_number + 1,
            started_at: now,
        };

        bridge
            .recover_pending_command(route, grant, attempt)
            .await
            .map(Some)
    }
}

pub const MATRIX_RETRY_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRetryWorkerSettings {
    pub enabled: bool,
    pub poll_interval: Duration,
    pub startup_jitter_max: Duration,
    pub tick_jitter_max: Duration,
    pub max_entries_per_scope: usize,
}

impl Default for MatrixRetryWorkerSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_interval: Duration::from_secs(30),
            startup_jitter_max: Duration::ZERO,
            tick_jitter_max: Duration::ZERO,
            max_entries_per_scope: 50,
        }
    }
}

impl MatrixRetryWorkerSettings {
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            startup_jitter_max: Duration::from_secs(30),
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<(), MatrixOutboundContractError> {
        if self.enabled && self.poll_interval.is_zero() {
            return Err(MatrixOutboundContractError::Backend(
                "matrix retry worker poll interval must be non-zero".to_string(),
            ));
        }
        if self.enabled && self.max_entries_per_scope == 0 {
            return Err(MatrixOutboundContractError::Backend(
                "matrix retry worker max entries per scope must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
pub trait MatrixRetrySendAuthorizer: Send + Sync {
    async fn authorize_retry_send(
        &self,
        context: &MatrixRetryExecutionContext,
        command: &MatrixOutboundCommand,
    ) -> Result<(), DeliveryError>;
}

#[cfg(test)]
pub(crate) struct MatrixSnapshotRetrySendAuthorizer {
    snapshot_source: Arc<dyn MatrixPolicySnapshotSource>,
}

#[cfg(test)]
impl MatrixSnapshotRetrySendAuthorizer {
    pub(crate) fn new(snapshot_source: Arc<dyn MatrixPolicySnapshotSource>) -> Self {
        Self { snapshot_source }
    }
}

#[async_trait]
#[cfg(test)]
impl MatrixRetrySendAuthorizer for MatrixSnapshotRetrySendAuthorizer {
    async fn authorize_retry_send(
        &self,
        context: &MatrixRetryExecutionContext,
        command: &MatrixOutboundCommand,
    ) -> Result<(), DeliveryError> {
        validate_retry_execution_context(context.route(), context.grant())
            .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))?;
        authorize_retry_send_from_policy_snapshot_source(
            context,
            command,
            self.snapshot_source.as_ref(),
        )
        .await
    }
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
pub(crate) struct MatrixFilesystemRetrySendAuthorizer<F: ?Sized> {
    filesystem: Arc<ScopedFilesystem<F>>,
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
impl<F> MatrixFilesystemRetrySendAuthorizer<F>
where
    F: RootFilesystem + ?Sized,
{
    pub(crate) fn new(filesystem: Arc<ScopedFilesystem<F>>) -> Self {
        Self { filesystem }
    }
}

#[async_trait]
#[cfg(any(test, feature = "libsql", feature = "postgres"))]
impl<F> MatrixRetrySendAuthorizer for MatrixFilesystemRetrySendAuthorizer<F>
where
    F: RootFilesystem + Send + Sync + ?Sized,
{
    async fn authorize_retry_send(
        &self,
        context: &MatrixRetryExecutionContext,
        command: &MatrixOutboundCommand,
    ) -> Result<(), DeliveryError> {
        validate_retry_execution_context(context.route(), context.grant())
            .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))?;
        let cache_path = matrix_policy_projection_cache_path_for_route(context.route())
            .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))?;
        let policy_scope = matrix_policy_projection_resource_scope_for_route(context.route());
        let snapshot_source = FilesystemMatrixPolicySnapshotSource::new(
            Arc::clone(&self.filesystem),
            policy_scope,
            cache_path,
        );
        authorize_retry_send_from_policy_snapshot_source(context, command, &snapshot_source).await
    }
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
async fn authorize_retry_send_from_policy_snapshot_source(
    context: &MatrixRetryExecutionContext,
    command: &MatrixOutboundCommand,
    snapshot_source: &dyn MatrixPolicySnapshotSource,
) -> Result<(), DeliveryError> {
    let adapter_id = ProductAdapterId::new(context.route().adapter_id.clone())
        .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))?;
    let installation_id = AdapterInstallationId::new(context.route().installation_id.clone())
        .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))?;
    let snapshot = snapshot_source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .map_err(|rejection| {
            DeliveryError::new(delivery_reason_for_matrix_policy_rejection(rejection))
        })?;
    let check = retry_matrix_outbound_policy_check(context, command, &snapshot)?;
    DefaultMatrixOutboundPolicyAuthorizer
        .authorize_matrix_outbound(&snapshot, &check)
        .map_err(|rejection| {
            DeliveryError::new(delivery_reason_for_matrix_policy_rejection(rejection))
        })
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
fn retry_matrix_outbound_policy_check(
    context: &MatrixRetryExecutionContext,
    command: &MatrixOutboundCommand,
    snapshot: &AdapterMatrixPolicySnapshot,
) -> Result<AdapterMatrixOutboundPolicyCheck, DeliveryError> {
    let metadata = context.route().matrix_metadata();
    let adapter_id = ProductAdapterId::new(context.route().adapter_id.clone())
        .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))?;
    let installation_id = AdapterInstallationId::new(context.route().installation_id.clone())
        .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))?;
    verify_retry_fingerprint(
        &metadata.homeserver_origin_fingerprint,
        snapshot.homeserver.as_origin().as_bytes(),
        DeliveryReasonCode::UnauthorizedTarget,
    )?;
    let room_id =
        ironclaw_matrix_adapter::installation_policy::MatrixRoomId::new(command.room_id.as_str())
            .map_err(|_| DeliveryError::new(DeliveryReasonCode::RoomNotAllowed))?;
    let egress_target_index = AdapterEgressTargetIndex::new(command.egress_target_index);
    verify_retry_fingerprint(
        &metadata.credential_handle_fingerprint,
        snapshot.credential_handle.as_str().as_bytes(),
        DeliveryReasonCode::CredentialMismatch,
    )?;
    let policy_revision = AdapterPolicyRevision::new(
        metadata
            .policy_revision
            .parse()
            .map_err(|_| DeliveryError::new(DeliveryReasonCode::StalePolicyRevision))?,
    )
    .map_err(|_| DeliveryError::new(DeliveryReasonCode::StalePolicyRevision))?;
    let path = matrix_send_policy_path(room_id.as_str(), command.transaction_id.as_str());
    Ok(AdapterMatrixOutboundPolicyCheck {
        adapter_id,
        installation_id,
        homeserver: snapshot.homeserver.clone(),
        room_id,
        egress_target_index,
        credential_handle: snapshot.credential_handle.clone(),
        path,
        guest_authorization_header_present: false,
        policy_revision,
    })
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
fn verify_retry_fingerprint(
    expected_fingerprint: &str,
    current_value: &[u8],
    reason: DeliveryReasonCode,
) -> Result<(), DeliveryError> {
    if expected_fingerprint == matrix_retry_sha256_fingerprint(current_value) {
        Ok(())
    } else {
        Err(DeliveryError::new(reason))
    }
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
fn matrix_retry_sha256_fingerprint(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
fn delivery_reason_for_matrix_policy_rejection(
    rejection: MatrixInstallationPolicyRejection,
) -> DeliveryReasonCode {
    match rejection {
        MatrixInstallationPolicyRejection::InstallationDisabled
        | MatrixInstallationPolicyRejection::InstallationDeleting
        | MatrixInstallationPolicyRejection::InstallationNotFound => {
            DeliveryReasonCode::InstallationInactive
        }
        MatrixInstallationPolicyRejection::PolicyRevisionMismatch
        | MatrixInstallationPolicyRejection::PolicySnapshotExpired => {
            DeliveryReasonCode::StalePolicyRevision
        }
        MatrixInstallationPolicyRejection::CredentialHandleMissing
        | MatrixInstallationPolicyRejection::CredentialHandleMismatch
        | MatrixInstallationPolicyRejection::CredentialHandleRevoked => {
            DeliveryReasonCode::CredentialMismatch
        }
        MatrixInstallationPolicyRejection::RoomNotAllowed => DeliveryReasonCode::RoomNotAllowed,
        MatrixInstallationPolicyRejection::DirectHttpEgressDenied
        | MatrixInstallationPolicyRejection::EgressTargetUndeclared
        | MatrixInstallationPolicyRejection::EgressTargetOutOfBounds
        | MatrixInstallationPolicyRejection::PrivateNetworkTarget
        | MatrixInstallationPolicyRejection::UnsafeRedirect => {
            DeliveryReasonCode::EgressTargetDenied
        }
        _ => DeliveryReasonCode::UnauthorizedTarget,
    }
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
pub(crate) struct MatrixStaticHttpEndpointResolver {
    endpoint: MatrixHttpDeliveryEndpoint,
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
impl MatrixStaticHttpEndpointResolver {
    pub(crate) fn new(endpoint: MatrixHttpDeliveryEndpoint) -> Self {
        Self { endpoint }
    }
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
impl MatrixHttpDeliveryEndpointResolver for MatrixStaticHttpEndpointResolver {
    fn resolve_endpoint(
        &self,
        route: &ValidatedDeliveryRoute,
        credential: &ResolvedCredentialHandle,
    ) -> Option<MatrixHttpDeliveryEndpoint> {
        let metadata = route.matrix_metadata();
        if self.endpoint.credential_handle_fingerprint()
            == metadata.credential_handle_fingerprint.as_str()
            && self.endpoint.credential_handle_fingerprint()
                == credential.credential_handle_fingerprint.as_str()
            && self.endpoint.homeserver_origin_fingerprint()
                == metadata.homeserver_origin_fingerprint
        {
            Some(self.endpoint.clone())
        } else {
            None
        }
    }
}

#[async_trait]
pub trait MatrixRetryWorkPort: Send + Sync {
    async fn list_retry_scopes(
        &self,
        discovery_roots: &[TurnScope],
    ) -> Result<Vec<TurnScope>, MatrixOutboundContractError>;

    async fn list_due_retry_schedules(
        &self,
        scope: TurnScope,
        now: DateTime<Utc>,
        max_entries: usize,
    ) -> Result<Vec<MatrixRetrySchedule>, MatrixOutboundContractError>;

    async fn execute_due_retry(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        now: DateTime<Utc>,
    ) -> Result<Option<MatrixOrchestratorOutcome>, DeliveryError>;
}

pub struct MatrixRetryProductionWorkPort<F>
where
    F: RootFilesystem + 'static,
{
    metadata_store: Arc<FilesystemMatrixOutboundMetadataStore<F>>,
    pending_store: Arc<FilesystemMatrixPendingIntentStore<F>>,
    delivery_port: Arc<dyn MatrixDeliveryPort>,
    credential_resolver: Arc<dyn MatrixCredentialResolver>,
    retry_policy: Arc<dyn RetryPolicy>,
    retry_send_authorizer: Arc<dyn MatrixRetrySendAuthorizer>,
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
pub(crate) struct MatrixRetryProductionDependencyBundleInput<F>
where
    F: RootFilesystem + 'static,
{
    pub settings: MatrixRetryWorkerSettings,
    pub metadata_filesystem: Arc<ScopedFilesystem<F>>,
    pub pending_filesystem: Arc<ScopedFilesystem<F>>,
    pub outbound_state_store: Arc<dyn OutboundStateStore>,
    pub host_egress: Arc<dyn MatrixHostHttpEgress>,
    pub endpoint_resolver: Arc<dyn MatrixHttpDeliveryEndpointResolver>,
    pub credential_material_provider: Arc<dyn MatrixHttpCredentialMaterialProvider>,
    pub retry_policy: Arc<dyn RetryPolicy>,
    pub retry_send_authorizer: Arc<dyn MatrixRetrySendAuthorizer>,
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
pub(crate) struct MatrixRetryProductionDependencyBundle {
    settings: MatrixRetryWorkerSettings,
    work_port: Arc<dyn MatrixRetryWorkPort>,
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
impl MatrixRetryProductionDependencyBundle {
    pub(crate) fn new<F>(
        input: MatrixRetryProductionDependencyBundleInput<F>,
    ) -> Result<Self, MatrixOutboundContractError>
    where
        F: RootFilesystem + Send + Sync + 'static,
    {
        input.settings.validate()?;
        let metadata_store = Arc::new(FilesystemMatrixOutboundMetadataStore::new(
            input.metadata_filesystem,
            input.outbound_state_store,
        ));
        let pending_store = Arc::new(FilesystemMatrixPendingIntentStore::new(
            input.pending_filesystem,
        ));
        let delivery_port = Arc::new(MatrixHttpDeliveryPort::new(
            input.host_egress,
            input.endpoint_resolver,
            input.credential_material_provider,
        ));
        let delivery_port_dyn: Arc<dyn MatrixDeliveryPort> = delivery_port.clone();
        let credential_resolver: Arc<dyn MatrixCredentialResolver> =
            Arc::new(MatrixRouteMetadataCredentialResolver);
        let work_port = Arc::new(MatrixRetryProductionWorkPort::new(
            Arc::clone(&metadata_store),
            Arc::clone(&pending_store),
            Arc::clone(&delivery_port_dyn),
            credential_resolver,
            input.retry_policy,
            input.retry_send_authorizer,
        ));
        Ok(Self {
            settings: input.settings,
            work_port,
        })
    }

    pub(crate) fn settings(&self) -> &MatrixRetryWorkerSettings {
        &self.settings
    }

    pub(crate) fn worker_deps(&self, discovery_roots: Vec<TurnScope>) -> MatrixRetryWorkerDeps {
        MatrixRetryWorkerDeps {
            work_port: Arc::clone(&self.work_port),
            discovery_roots,
        }
    }
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
struct MatrixRouteMetadataCredentialResolver;

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
impl MatrixCredentialResolver for MatrixRouteMetadataCredentialResolver {
    fn resolve(&self, route: &ValidatedDeliveryRoute) -> Option<ResolvedCredentialHandle> {
        Some(ResolvedCredentialHandle {
            credential_handle_fingerprint: route
                .matrix_metadata()
                .credential_handle_fingerprint
                .clone(),
        })
    }
}

impl<F> MatrixRetryProductionWorkPort<F>
where
    F: RootFilesystem + 'static,
{
    pub fn new(
        metadata_store: Arc<FilesystemMatrixOutboundMetadataStore<F>>,
        pending_store: Arc<FilesystemMatrixPendingIntentStore<F>>,
        delivery_port: Arc<dyn MatrixDeliveryPort>,
        credential_resolver: Arc<dyn MatrixCredentialResolver>,
        retry_policy: Arc<dyn RetryPolicy>,
        retry_send_authorizer: Arc<dyn MatrixRetrySendAuthorizer>,
    ) -> Self {
        Self {
            metadata_store,
            pending_store,
            delivery_port,
            credential_resolver,
            retry_policy,
            retry_send_authorizer,
        }
    }
}

#[async_trait]
impl<F> MatrixRetryWorkPort for MatrixRetryProductionWorkPort<F>
where
    F: RootFilesystem + Send + Sync + 'static,
{
    async fn list_retry_scopes(
        &self,
        discovery_roots: &[TurnScope],
    ) -> Result<Vec<TurnScope>, MatrixOutboundContractError> {
        self.metadata_store
            .list_indexed_retry_scopes(discovery_roots)
            .await
    }

    async fn list_due_retry_schedules(
        &self,
        scope: TurnScope,
        now: DateTime<Utc>,
        max_entries: usize,
    ) -> Result<Vec<MatrixRetrySchedule>, MatrixOutboundContractError> {
        self.metadata_store
            .list_due_retry_schedules(scope, now, max_entries)
            .await
    }

    async fn execute_due_retry(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        now: DateTime<Utc>,
    ) -> Result<Option<MatrixOrchestratorOutcome>, DeliveryError> {
        let context = self
            .metadata_store
            .load_retry_execution_context(scope.clone(), delivery_id)
            .await?
            .ok_or_else(|| DeliveryError::new(DeliveryReasonCode::MissingMatrixRoute));
        let context = match context {
            Ok(context) => context,
            Err(error) => {
                self.record_retry_failure(scope, delivery_id, error.reason)
                    .await?;
                return Err(error);
            }
        };
        let (route, grant) = context.clone().into_parts();
        let orchestrator = MatrixOutboundOrchestrator::new(
            self.delivery_port.as_ref(),
            self.credential_resolver.as_ref(),
            self.metadata_store.as_ref(),
            self.retry_policy.as_ref(),
        );
        let bridge =
            MatrixProductionDeliveryBridge::new(self.pending_store.as_ref(), &orchestrator);
        let outcome = MatrixRetryExecutor::execute_due_retry(
            self.metadata_store.as_ref(),
            self.pending_store.as_ref(),
            &bridge,
            self.retry_send_authorizer.as_ref(),
            route,
            grant,
            now,
        )
        .await;
        if let Err(error) = &outcome
            && delivery_failure_kind_for_reason(error.reason)
                == DeliveryFailureKind::AuthorizationRevoked
        {
            self.record_retry_failure(scope, delivery_id, error.reason)
                .await?;
        }
        outcome
    }
}

impl<F> MatrixRetryProductionWorkPort<F>
where
    F: RootFilesystem + 'static,
{
    async fn record_retry_failure(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        reason: DeliveryReasonCode,
    ) -> Result<(), MatrixOutboundContractError> {
        self.metadata_store
            .update_delivery_status(UpdateDeliveryStatusRequest {
                delivery_id,
                scope,
                status: OutboundDeliveryStatus::Failed,
                updated_at: Utc::now(),
                failure_kind: Some(delivery_failure_kind_for_reason(reason)),
            })
            .await
    }
}

#[derive(Clone)]
pub struct MatrixRetryWorkerDeps {
    pub work_port: Arc<dyn MatrixRetryWorkPort>,
    pub discovery_roots: Vec<TurnScope>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatrixRetryWorkerTickReport {
    pub scopes_scanned: usize,
    pub due_schedules: usize,
    pub attempted: usize,
    pub delivered: usize,
    pub retry_scheduled: usize,
    pub skipped: usize,
    pub failed: usize,
}

pub struct MatrixRetryWorkerRuntimeHandle {
    pub(crate) cancel: CancellationToken,
    pub(crate) handle: JoinHandle<()>,
}

impl MatrixRetryWorkerRuntimeHandle {
    pub async fn shutdown(self, timeout: Duration) {
        self.cancel.cancel();
        self.join_with_timeout(timeout).await;
    }

    pub async fn join_with_timeout(self, timeout: Duration) {
        let mut handle = self.handle;
        match tokio::time::timeout(timeout, &mut handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                observability::record_retry_worker_task_failed(&error);
            }
            Err(_) => {
                observability::record_retry_worker_shutdown_timeout(timeout);
                handle.abort();
                if let Err(error) = handle.await
                    && error.is_panic()
                {
                    observability::record_retry_worker_task_panicked(&error);
                }
            }
        }
    }
}

pub fn spawn_matrix_retry_worker(
    settings: MatrixRetryWorkerSettings,
    deps: MatrixRetryWorkerDeps,
) -> Result<Option<MatrixRetryWorkerRuntimeHandle>, MatrixOutboundContractError> {
    if !settings.enabled {
        return Ok(None);
    }
    settings.validate()?;
    if deps.discovery_roots.is_empty() {
        return Err(MatrixOutboundContractError::Backend(
            "matrix retry worker requires at least one discovery root".to_string(),
        ));
    }
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let handle = tokio::spawn(async move {
        run_matrix_retry_worker(settings, deps, task_cancel).await;
    });
    Ok(Some(MatrixRetryWorkerRuntimeHandle { cancel, handle }))
}

async fn run_matrix_retry_worker(
    settings: MatrixRetryWorkerSettings,
    deps: MatrixRetryWorkerDeps,
    cancel: CancellationToken,
) {
    if !matrix_retry_sleep_or_cancel(
        matrix_retry_jitter_delay(settings.startup_jitter_max),
        &cancel,
    )
    .await
    {
        return;
    }
    loop {
        match matrix_retry_worker_tick_once(&settings, &deps, Utc::now(), &cancel).await {
            Ok(report) => {
                observability::record_retry_worker_tick_completed(&report);
            }
            Err(error) => {
                observability::record_retry_worker_tick_failed(&error);
            }
        }
        let delay = settings.poll_interval + matrix_retry_jitter_delay(settings.tick_jitter_max);
        if !matrix_retry_sleep_or_cancel(delay, &cancel).await {
            return;
        }
    }
}

pub async fn matrix_retry_worker_tick_once(
    settings: &MatrixRetryWorkerSettings,
    deps: &MatrixRetryWorkerDeps,
    now: DateTime<Utc>,
    cancel: &CancellationToken,
) -> Result<MatrixRetryWorkerTickReport, MatrixOutboundContractError> {
    settings.validate()?;
    if deps.discovery_roots.is_empty() {
        return Err(MatrixOutboundContractError::Backend(
            "matrix retry worker requires at least one discovery root".to_string(),
        ));
    }
    let retry_scopes = deps
        .work_port
        .list_retry_scopes(&deps.discovery_roots)
        .await?;
    let mut report = MatrixRetryWorkerTickReport {
        scopes_scanned: retry_scopes.len(),
        ..MatrixRetryWorkerTickReport::default()
    };
    for scope in &retry_scopes {
        if cancel.is_cancelled() {
            break;
        }
        let schedules = deps
            .work_port
            .list_due_retry_schedules(scope.clone(), now, settings.max_entries_per_scope)
            .await?;
        report.due_schedules += schedules.len();
        for schedule in schedules {
            if cancel.is_cancelled() {
                break;
            }
            report.attempted += 1;
            match deps
                .work_port
                .execute_due_retry(schedule.scope, schedule.delivery_id, now)
                .await
            {
                Ok(Some(outcome)) => match outcome.status {
                    MatrixTerminalStatus::Delivered => report.delivered += 1,
                    MatrixTerminalStatus::RetryScheduled => report.retry_scheduled += 1,
                    MatrixTerminalStatus::FailedPermanent
                    | MatrixTerminalStatus::FailedUnauthorized
                    | MatrixTerminalStatus::FailedExhausted => report.failed += 1,
                },
                Ok(None) => report.skipped += 1,
                Err(error) => {
                    report.failed += 1;
                    observability::record_retry_attempt_failed(schedule.delivery_id, error.reason);
                }
            }
        }
    }
    Ok(report)
}

async fn matrix_retry_sleep_or_cancel(delay: Duration, cancel: &CancellationToken) -> bool {
    if delay.is_zero() {
        return !cancel.is_cancelled();
    }
    tokio::select! {
        _ = cancel.cancelled() => false,
        _ = tokio::time::sleep(delay) => true,
    }
}

fn matrix_retry_jitter_delay(max: Duration) -> Duration {
    if max.is_zero() {
        return Duration::ZERO;
    }
    let max_nanos = max.as_nanos().min(u64::MAX as u128);
    let nanos = rand::rng().random_range(0..=max_nanos);
    let nanos = u64::try_from(nanos).unwrap_or(u64::MAX);
    Duration::from_nanos(nanos)
}
