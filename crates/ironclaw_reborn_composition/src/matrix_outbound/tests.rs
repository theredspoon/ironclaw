use super::*;
use crate::matrix_outbound::fakes::{
    FakeMatrixCredentialResolver, FakeMatrixDeliveryPort, FakeMatrixOutboundMetadataStore,
    route_forgery_fixture,
};
use crate::matrix_product_outbound::{
    FilesystemMatrixPolicySnapshotSource, MatrixOutboundPolicyAuthorizer,
    MatrixPolicySnapshotSource, MatrixProductOutboundDeliveryError,
    MatrixProductOutboundDeliveryInput, MatrixProductOutboundEntrypoint,
    matrix_policy_projection_cache_path_for_route_scope,
    matrix_policy_projection_commit_marker_entry,
    matrix_policy_projection_commit_marker_path_for_cache_path,
    matrix_policy_projection_resource_scope_for_provider_scope,
};
use async_trait::async_trait;
use ironclaw_event_projections::ProjectionCursor;
use ironclaw_extensions::{
    ExtensionActivationState, ExtensionHealthSnapshot, ExtensionInstallation,
    ExtensionInstallationError, ExtensionInstallationId, ExtensionInstallationStore,
    ExtensionManifestRecord, ExtensionManifestRef, InMemoryExtensionInstallationStore,
    InstallationOwner, MANIFEST_SCHEMA_VERSION, ManifestHash, ManifestSource,
};
use ironclaw_filesystem::{CasExpectation, ContentType, Entry, InMemoryBackend, ScopedFilesystem};
use ironclaw_host_api::{
    AgentId, ExtensionId, HostPortCatalog, MountAlias, MountGrant, MountPermissions, MountView,
    ProjectId, ScopedPath, TenantId, ThreadId, UserId, VirtualPath,
};
use ironclaw_matrix_adapter::installation_policy::{
    ArtifactSha256, ComponentArtifactBinding, ComponentArtifactId,
    EgressTargetIndex as AdapterEgressTargetIndex, InstallationAuditMetadata,
    MatrixActivationState, MatrixHomeserverOrigin as AdapterMatrixHomeserverOrigin,
    MatrixInstallationPolicy,
    MatrixInstallationPolicyRejection as AdapterMatrixInstallationPolicyRejection,
    MatrixInstallationProjectionCache,
    MatrixOutboundPolicyCheck as AdapterMatrixOutboundPolicyCheck,
    MatrixPolicySnapshot as AdapterMatrixPolicySnapshot, MatrixProductAdapterInstallation,
    MatrixRoomId as AdapterMatrixRoomId, MatrixUserId as AdapterMatrixUserId,
    PolicyRevision as AdapterPolicyRevision, StaticManifestBinding, WitPackageName, WitWorldName,
    authorize_matrix_outbound as authorize_adapter_matrix_outbound,
};
use ironclaw_matrix_adapter::{
    MatrixParsePolicy, MatrixProductAdapter, MatrixProductAdapterConfig,
};
use ironclaw_outbound::test_support::in_memory_backed_outbound_state_store;
use ironclaw_outbound::{
    AdvanceSubscriptionCursorRequest, CommunicationDeliveryIntent,
    CommunicationDeliveryResolutionRequest, CommunicationModality, CommunicationPreferenceKey,
    CommunicationPreferenceRecord, CommunicationPreferenceRepository,
    CommunicationPreferenceVersion, DeliveryDefaultScope, LoadSubscriptionCursorRequest,
    OutboundDeliveryAttempt, OutboundPolicyService, OutboundPushPlan, OutboundPushTargetRequest,
    ProjectionSubscriptionRecord, ReplyTargetBindingClaim, ReplyTargetBindingValidator,
    RequestedOutboundContext, RequestedOutboundKind, ThreadNotificationPolicy,
    ThreadProjectionAccessClaim, ThreadProjectionAccessPolicy, ThreadProjectionAccessRequest,
    VersionedCommunicationPreferenceRecord, WriteCommunicationPreferenceRequest,
};
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, DeclaredEgressHost, DeclaredEgressTarget,
    ExternalConversationRef, FakeOutboundDeliverySink, FakeProtocolHttpEgress, FinalReplyView,
    OutboundDeliverySink, ParsedProductInbound, ProductAdapter, ProductAdapterCapabilities,
    ProductAdapterError, ProductAdapterHealth, ProductAdapterId, ProductOutboundEnvelope,
    ProductOutboundPayload, ProductRenderOutcome, ProductSurfaceKind,
    ProjectionCursor as ProductProjectionCursor, ProtocolAuthEvidence, ProtocolHttpEgress,
};
use ironclaw_product_workflow::{
    ProductOutboundDeliveryOutcome, ProductOutboundTargetResolver, ProductWorkflowError,
    VerifiedProductOutboundTargetMetadata,
};
use ironclaw_turns::{TurnActor, TurnRunId};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;

type StageTimeline = Arc<Mutex<Vec<&'static str>>>;

struct RecordingExtensionInstallationStore {
    inner: InMemoryExtensionInstallationStore,
    timeline: StageTimeline,
}

impl RecordingExtensionInstallationStore {
    fn new(inner: InMemoryExtensionInstallationStore, timeline: StageTimeline) -> Self {
        Self { inner, timeline }
    }
}

#[async_trait]
impl ExtensionInstallationStore for RecordingExtensionInstallationStore {
    async fn list_manifests(
        &self,
    ) -> Result<Vec<ExtensionManifestRecord>, ExtensionInstallationError> {
        self.inner.list_manifests().await
    }

    async fn get_manifest(
        &self,
        extension_id: &ExtensionId,
    ) -> Result<Option<ExtensionManifestRecord>, ExtensionInstallationError> {
        self.inner.get_manifest(extension_id).await
    }

    async fn upsert_manifest(
        &self,
        manifest: ExtensionManifestRecord,
    ) -> Result<(), ExtensionInstallationError> {
        self.inner.upsert_manifest(manifest).await
    }

    async fn upsert_manifest_and_installation(
        &self,
        manifest: ExtensionManifestRecord,
        installation: ExtensionInstallation,
    ) -> Result<(), ExtensionInstallationError> {
        self.inner
            .upsert_manifest_and_installation(manifest, installation)
            .await
    }

    async fn list_installations(
        &self,
    ) -> Result<Vec<ExtensionInstallation>, ExtensionInstallationError> {
        self.inner.list_installations().await
    }

    async fn list_enabled_installations(
        &self,
    ) -> Result<Vec<ExtensionInstallation>, ExtensionInstallationError> {
        self.inner.list_enabled_installations().await
    }

    async fn get_installation(
        &self,
        installation_id: &ExtensionInstallationId,
    ) -> Result<Option<ExtensionInstallation>, ExtensionInstallationError> {
        self.timeline
            .lock()
            .expect("timeline lock")
            .push("lifecycle.check");
        self.inner.get_installation(installation_id).await
    }

    async fn upsert_installation(
        &self,
        installation: ExtensionInstallation,
    ) -> Result<(), ExtensionInstallationError> {
        self.inner.upsert_installation(installation).await
    }

    async fn set_activation_state(
        &self,
        installation_id: &ExtensionInstallationId,
        state: ExtensionActivationState,
    ) -> Result<(), ExtensionInstallationError> {
        self.inner
            .set_activation_state(installation_id, state)
            .await
    }

    async fn delete_installation(
        &self,
        installation_id: &ExtensionInstallationId,
    ) -> Result<(), ExtensionInstallationError> {
        self.inner.delete_installation(installation_id).await
    }

    async fn delete_manifest(
        &self,
        extension_id: &ExtensionId,
    ) -> Result<(), ExtensionInstallationError> {
        self.inner.delete_manifest(extension_id).await
    }

    async fn update_health(
        &self,
        installation_id: &ExtensionInstallationId,
        health: ExtensionHealthSnapshot,
    ) -> Result<(), ExtensionInstallationError> {
        self.inner.update_health(installation_id, health).await
    }
}

fn binding() -> ReplyTargetBindingRef {
    ReplyTargetBindingRef::new("matrix-room-binding").expect("valid binding")
}

fn command() -> MatrixOutboundCommand {
    MatrixOutboundCommand {
        command_kind: MatrixCommandKind::SendText,
        transaction_id: MatrixTransactionId::new("txn-matrix-1").expect("valid txn"),
        reply_target_binding_ref: binding(),
        egress_target_index: 0,
        room_id: MatrixRoomId::new("!room:matrix.example").expect("valid room"),
        body: MatrixMessageBody::new(json!({
            "msgtype": "m.text",
            "body": "hello matrix"
        }))
        .expect("valid body"),
    }
}

fn command_with_transaction_id(transaction_id: &str) -> MatrixOutboundCommand {
    MatrixOutboundCommand {
        transaction_id: MatrixTransactionId::new(transaction_id).expect("valid transaction id"),
        ..command()
    }
}

#[derive(Debug, Default)]
struct FakeOutboundStateStore {
    statuses: Mutex<Vec<UpdateDeliveryStatusRequest>>,
    fail_update_delivery_status: bool,
}

#[async_trait]
impl OutboundStateStore for FakeOutboundStateStore {
    async fn put_thread_notification_policy(
        &self,
        _policy: ThreadNotificationPolicy,
    ) -> Result<(), OutboundError> {
        Ok(())
    }

    async fn load_thread_notification_policy(
        &self,
        scope: TurnScope,
    ) -> Result<ThreadNotificationPolicy, OutboundError> {
        Ok(ThreadNotificationPolicy::default_for_scope(scope))
    }

    async fn plan_push_targets(
        &self,
        _request: OutboundPushTargetRequest,
    ) -> Result<OutboundPushPlan, OutboundError> {
        Err(OutboundError::Backend)
    }

    async fn upsert_subscription(
        &self,
        _record: ProjectionSubscriptionRecord,
    ) -> Result<(), OutboundError> {
        Err(OutboundError::Backend)
    }

    async fn load_subscription_cursor(
        &self,
        _request: LoadSubscriptionCursorRequest,
    ) -> Result<Option<ProjectionCursor>, OutboundError> {
        Err(OutboundError::Backend)
    }

    async fn advance_subscription_cursor(
        &self,
        _request: AdvanceSubscriptionCursorRequest,
    ) -> Result<(), OutboundError> {
        Err(OutboundError::Backend)
    }

    async fn record_delivery_attempt(
        &self,
        _attempt: OutboundDeliveryAttempt,
    ) -> Result<(), OutboundError> {
        Ok(())
    }

    async fn update_delivery_status(
        &self,
        request: UpdateDeliveryStatusRequest,
    ) -> Result<(), OutboundError> {
        if self.fail_update_delivery_status {
            return Err(OutboundError::Backend);
        }
        self.statuses.lock().expect("status lock").push(request);
        Ok(())
    }

    async fn list_delivery_attempts(
        &self,
        _scope: TurnScope,
    ) -> Result<Vec<OutboundDeliveryAttempt>, OutboundError> {
        Ok(Vec::new())
    }
}

fn outbound_state_store() -> Arc<dyn OutboundStateStore> {
    Arc::new(FakeOutboundStateStore::default())
}

fn scope() -> TurnScope {
    TurnScope::new_with_owner(
        TenantId::new("tenant-matrix-outbound").expect("valid tenant"),
        Some(AgentId::new("agent-matrix-outbound").expect("valid agent")),
        Some(ProjectId::new("project-matrix-outbound").expect("valid project")),
        ThreadId::new("thread-matrix-outbound").expect("valid thread"),
        Some(UserId::new("user-matrix-outbound").expect("valid user")),
    )
}

fn owner() -> MatrixRoutePolicyOwnerToken {
    MatrixRoutePolicyOwnerToken::matrix_policy_owner()
}

fn retry_policy() -> BoundedMatrixRetryPolicy {
    BoundedMatrixRetryPolicy {
        max_attempts: 3,
        fallback_after: Duration::from_secs(1),
        max_retry_after: Duration::from_secs(60),
    }
}

fn canonical_fingerprint(value: &str) -> String {
    format!("sha256:{}", sha256_hex(value.as_bytes()))
}

fn route() -> FrozenProductDeliveryRoute {
    let command = command();
    let owner = owner();
    FrozenProductDeliveryRoute::mint_for_matrix(
        &owner,
        OutboundDeliveryId::new(),
        scope(),
        "matrix-install",
        "matrix-adapter",
        MatrixRouteMetadata {
            policy_revision: "policy-rev-1".into(),
            homeserver_origin_fingerprint: canonical_fingerprint("homeserver-1"),
            room_fingerprint: command.room_id.fingerprint(),
            egress_target_index: 0,
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            reply_target_binding_ref: binding(),
            allowed_command_kinds: vec![MatrixCommandKind::SendText],
            policy_provider_scope: None,
        },
    )
}

fn route_for_homeserver_origin(origin: &str) -> FrozenProductDeliveryRoute {
    let command = command();
    let owner = owner();
    FrozenProductDeliveryRoute::mint_for_matrix(
        &owner,
        OutboundDeliveryId::new(),
        scope(),
        "matrix-install",
        "matrix-adapter",
        MatrixRouteMetadata {
            policy_revision: "policy-rev-1".into(),
            homeserver_origin_fingerprint: canonical_fingerprint(origin),
            room_fingerprint: command.room_id.fingerprint(),
            egress_target_index: 0,
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            reply_target_binding_ref: binding(),
            allowed_command_kinds: vec![MatrixCommandKind::SendText],
            policy_provider_scope: None,
        },
    )
}

fn attempt(
    route: &FrozenProductDeliveryRoute,
    command: &MatrixOutboundCommand,
) -> DeliveryAttemptContext {
    DeliveryAttemptContext {
        delivery_id: route.delivery_id,
        attempt_number: 1,
        transaction_id: command.transaction_id.clone(),
        started_at: Utc::now(),
    }
}

fn accepted_evidence(
    command: &MatrixOutboundCommand,
    route: &FrozenProductDeliveryRoute,
    attempt: &DeliveryAttemptContext,
) -> MatrixDeliveryEvidenceV1 {
    MatrixDeliveryEvidenceV1 {
        schema_version: 1,
        delivery_id: attempt.delivery_id,
        attempt_number: attempt.attempt_number,
        event_id_fingerprint: canonical_fingerprint("event-1"),
        transaction_id: command.transaction_id.clone(),
        command_kind: command.command_kind,
        delivered_at: Utc::now(),
        verified: true,
        homeserver_origin_fingerprint: route
            .matrix_metadata()
            .homeserver_origin_fingerprint
            .clone(),
        room_fingerprint: command.room_id.fingerprint(),
        installation_scoped_credential_ref: route
            .matrix_metadata()
            .credential_handle_fingerprint
            .clone(),
        http_status: 200,
        latency_ms: 12,
    }
}

fn retry_schedule(route: &FrozenProductDeliveryRoute) -> MatrixRetrySchedule {
    MatrixRetrySchedule {
        delivery_id: route.delivery_id,
        scope: route.scope().clone(),
        attempt_number: 2,
        retry_after: Duration::from_secs(30),
        reason: DeliveryReasonCode::MatrixRateLimited,
        recorded_at: Utc::now(),
    }
}

fn retry_context(route: &FrozenProductDeliveryRoute) -> MatrixRetryExecutionContext {
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, route);
    MatrixRetryExecutionContext::new(route.clone(), grant).expect("valid retry context")
}

fn delivery_status_request(
    route: &FrozenProductDeliveryRoute,
    status: OutboundDeliveryStatus,
) -> UpdateDeliveryStatusRequest {
    UpdateDeliveryStatusRequest {
        delivery_id: route.delivery_id,
        scope: route.scope().clone(),
        status,
        updated_at: Utc::now(),
        failure_kind: match status {
            OutboundDeliveryStatus::Failed | OutboundDeliveryStatus::DeadLettered => {
                Some(DeliveryFailureKind::Rejected)
            }
            OutboundDeliveryStatus::Pending | OutboundDeliveryStatus::Delivered => None,
        },
    }
}

#[derive(Debug, Default)]
struct RecordingMatrixDeliveryPort {
    calls: Mutex<Vec<(ProtocolDeliveryIntent, DeliveryAttemptContext)>>,
}

impl RecordingMatrixDeliveryPort {
    fn calls(&self) -> Vec<(ProtocolDeliveryIntent, DeliveryAttemptContext)> {
        self.calls.lock().expect("recorded call lock").clone()
    }
}

#[async_trait]
impl MatrixDeliveryPort for RecordingMatrixDeliveryPort {
    async fn deliver(
        &self,
        command: ProtocolDeliveryIntent,
        route: ValidatedDeliveryRoute,
        _credential: ResolvedCredentialHandle,
        attempt: DeliveryAttemptContext,
    ) -> DeliveryPortResult {
        self.calls
            .lock()
            .expect("recorded call lock")
            .push((command.clone(), attempt.clone()));
        let ProtocolDeliveryIntent::Matrix(matrix_command) = command;
        DeliveryPortResult::Accepted(ProtocolDeliveryEvidence::Matrix(accepted_evidence(
            &matrix_command,
            &route.route,
            &attempt,
        )))
    }
}

#[derive(Debug, Default)]
struct AllowRetrySendAuthorizer;

#[async_trait]
impl MatrixRetrySendAuthorizer for AllowRetrySendAuthorizer {
    async fn authorize_retry_send(
        &self,
        _context: &MatrixRetryExecutionContext,
        _command: &MatrixOutboundCommand,
    ) -> Result<(), DeliveryError> {
        Ok(())
    }
}

#[derive(Debug)]
struct RejectRetrySendAuthorizer {
    reason: DeliveryReasonCode,
}

#[async_trait]
impl MatrixRetrySendAuthorizer for RejectRetrySendAuthorizer {
    async fn authorize_retry_send(
        &self,
        _context: &MatrixRetryExecutionContext,
        _command: &MatrixOutboundCommand,
    ) -> Result<(), DeliveryError> {
        Err(DeliveryError::new(self.reason))
    }
}

fn retry_work_port(
    metadata_store: Arc<FilesystemMatrixOutboundMetadataStore<InMemoryBackend>>,
    pending_store: Arc<FilesystemMatrixPendingIntentStore<InMemoryBackend>>,
    delivery_port: Arc<dyn MatrixDeliveryPort>,
    credential_resolver: Arc<dyn MatrixCredentialResolver>,
    retry_send_authorizer: Arc<dyn MatrixRetrySendAuthorizer>,
) -> Arc<dyn MatrixRetryWorkPort> {
    Arc::new(MatrixRetryProductionWorkPort::new(
        metadata_store,
        pending_store,
        delivery_port,
        credential_resolver,
        Arc::new(retry_policy()),
        retry_send_authorizer,
    ))
}

struct StaticMatrixHttpEndpointResolver {
    endpoint: Option<MatrixHttpDeliveryEndpoint>,
}

impl MatrixHttpDeliveryEndpointResolver for StaticMatrixHttpEndpointResolver {
    fn resolve_endpoint(
        &self,
        _route: &ValidatedDeliveryRoute,
        _credential: &ResolvedCredentialHandle,
    ) -> Option<MatrixHttpDeliveryEndpoint> {
        self.endpoint.clone()
    }
}

struct StaticMatrixHttpCredentialMaterialProvider;

#[async_trait]
impl MatrixHttpCredentialMaterialProvider for StaticMatrixHttpCredentialMaterialProvider {
    async fn resolve_matrix_credential_material(
        &self,
        _scope: &ResourceScope,
        endpoint: &MatrixHttpDeliveryEndpoint,
    ) -> Result<HostRuntimeCredentialMaterial, DeliveryError> {
        Ok(HostRuntimeCredentialMaterial {
            handle: endpoint.credential_secret().clone(),
            material: ironclaw_secrets::SecretMaterial::from("matrix-access-token".to_string()),
            target: RuntimeCredentialTarget::Header {
                name: "authorization".to_string(),
                prefix: Some("Bearer ".to_string()),
            },
            required: true,
        })
    }
}

fn matrix_credential_material_provider() -> Arc<dyn MatrixHttpCredentialMaterialProvider> {
    Arc::new(StaticMatrixHttpCredentialMaterialProvider)
}

#[derive(Debug, Clone)]
struct RecordedMatrixHostRequest {
    request: RuntimeHttpEgressRequest,
    credential_targets: Vec<RuntimeCredentialTarget>,
    credential_count: usize,
}

struct RecordingMatrixHostEgress {
    response: Mutex<Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError>>,
    requests: Mutex<Vec<RecordedMatrixHostRequest>>,
}

impl RecordingMatrixHostEgress {
    fn ok(status: u16, headers: Vec<(String, String)>, body: Value) -> Self {
        Self {
            response: Mutex::new(Ok(RuntimeHttpEgressResponse {
                status,
                headers,
                body: serde_json::to_vec(&body).expect("json response body"),
                saved_body: None,
                request_bytes: 128,
                response_bytes: 64,
                redaction_applied: false,
            })),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<RecordedMatrixHostRequest> {
        self.requests.lock().expect("request lock").clone()
    }
}

#[async_trait]
impl MatrixHostHttpEgress for RecordingMatrixHostEgress {
    async fn execute_matrix_http(
        &self,
        request: HostRuntimeHttpEgressRequest,
    ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
        let credential_count = request.credentials.len();
        let recorded = RecordedMatrixHostRequest {
            request: request.request,
            credential_targets: request
                .credentials
                .into_iter()
                .map(|credential| credential.target)
                .collect(),
            credential_count,
        };
        self.requests.lock().expect("request lock").push(recorded);
        self.response.lock().expect("response lock").clone()
    }
}

#[derive(Debug, Default)]
struct EmptyRetryWorkPort;

#[async_trait]
impl MatrixRetryWorkPort for EmptyRetryWorkPort {
    async fn list_due_retry_schedules(
        &self,
        _scope: TurnScope,
        _now: DateTime<Utc>,
        _max_entries: usize,
    ) -> Result<Vec<MatrixRetrySchedule>, MatrixOutboundContractError> {
        Ok(Vec::new())
    }

    async fn execute_due_retry(
        &self,
        _scope: TurnScope,
        _delivery_id: OutboundDeliveryId,
        _now: DateTime<Utc>,
    ) -> Result<Option<MatrixOrchestratorOutcome>, DeliveryError> {
        Ok(None)
    }
}

struct CancellingRetryWorkPort {
    cancel: CancellationToken,
    schedule: MatrixRetrySchedule,
}

#[async_trait]
impl MatrixRetryWorkPort for CancellingRetryWorkPort {
    async fn list_due_retry_schedules(
        &self,
        _scope: TurnScope,
        _now: DateTime<Utc>,
        _max_entries: usize,
    ) -> Result<Vec<MatrixRetrySchedule>, MatrixOutboundContractError> {
        self.cancel.cancel();
        Ok(vec![self.schedule.clone()])
    }

    async fn execute_due_retry(
        &self,
        _scope: TurnScope,
        _delivery_id: OutboundDeliveryId,
        _now: DateTime<Utc>,
    ) -> Result<Option<MatrixOrchestratorOutcome>, DeliveryError> {
        panic!("cancelled tick must not execute a due retry");
    }
}

fn matrix_metadata_filesystem(
    backend: Arc<InMemoryBackend>,
) -> Arc<ScopedFilesystem<InMemoryBackend>> {
    let mounts = MountView::new(vec![MountGrant::new(
        MountAlias::new("/outbound").expect("alias"),
        VirtualPath::new("/engine/matrix-outbound-test").expect("target"),
        MountPermissions::read_write_list_delete(),
    )])
    .expect("mount view");
    Arc::new(ScopedFilesystem::with_fixed_view(backend, mounts))
}

fn tenant_scoped_matrix_metadata_filesystem(
    backend: Arc<InMemoryBackend>,
) -> Arc<ScopedFilesystem<InMemoryBackend>> {
    Arc::new(ScopedFilesystem::new(backend, |scope| {
        let tenant_root = format!(
            "/engine/matrix-outbound-test/tenants/{}",
            scope.tenant_id.as_str()
        );
        MountView::new(vec![
            MountGrant::new(
                MountAlias::new("/outbound").expect("alias"),
                VirtualPath::new(format!("{tenant_root}/outbound")).expect("target"),
                MountPermissions::read_write_list_delete(),
            ),
            MountGrant::new(
                MountAlias::new("/tenant-shared").expect("alias"),
                VirtualPath::new(format!("{tenant_root}/tenant-shared")).expect("target"),
                MountPermissions::read_write_list_delete(),
            ),
        ])
        .map_err(Into::into)
    }))
}

async fn put_pending_intent_bytes(
    filesystem: &ScopedFilesystem<InMemoryBackend>,
    scope: &TurnScope,
    delivery_id: OutboundDeliveryId,
    attempt_id: Uuid,
    bytes: Vec<u8>,
) {
    let path =
        matrix_pending_intent_path(scope, delivery_id, attempt_id).expect("pending intent path");
    filesystem
        .put(
            &scope.to_resource_scope(),
            &path,
            Entry::bytes(bytes).with_content_type(ContentType::json()),
            CasExpectation::Any,
        )
        .await
        .expect("write pending intent fixture");
}

#[derive(Default)]
struct AllowAllProjectionAccessPolicy;

#[async_trait]
impl ThreadProjectionAccessPolicy for AllowAllProjectionAccessPolicy {
    async fn authorize_projection_access(
        &self,
        request: ThreadProjectionAccessRequest,
    ) -> Result<ThreadProjectionAccessClaim, OutboundError> {
        Ok(ThreadProjectionAccessClaim {
            actor: request.actor,
            scope: request.scope,
            thread_id: request.thread_id,
        })
    }
}

#[derive(Default)]
struct RecordingReplyTargetBindingValidator {
    allowed_targets: Mutex<HashSet<ReplyTargetBindingRef>>,
    calls: Mutex<Vec<ReplyTargetBindingRef>>,
    timeline: StageTimeline,
}

impl RecordingReplyTargetBindingValidator {
    fn allow(&self, target: ReplyTargetBindingRef) {
        self.allowed_targets
            .lock()
            .expect("validator lock")
            .insert(target);
    }

    fn calls(&self) -> Vec<ReplyTargetBindingRef> {
        self.calls.lock().expect("validator lock").clone()
    }
}

#[async_trait]
impl ReplyTargetBindingValidator for RecordingReplyTargetBindingValidator {
    async fn validate_reply_target(
        &self,
        request: ironclaw_outbound::ReplyTargetValidationRequest,
    ) -> Result<ReplyTargetBindingClaim, OutboundError> {
        self.calls
            .lock()
            .expect("validator lock")
            .push(request.candidate.target.clone());
        self.timeline
            .lock()
            .expect("timeline lock")
            .push("outbound.validate_reply_target");
        if self
            .allowed_targets
            .lock()
            .expect("validator lock")
            .contains(&request.candidate.target)
        {
            Ok(ReplyTargetBindingClaim::new(request.candidate.target))
        } else {
            Err(OutboundError::AccessDenied)
        }
    }
}

#[derive(Default)]
struct RecordingPreferenceRepository {
    records: Mutex<HashMap<CommunicationPreferenceKey, VersionedCommunicationPreferenceRecord>>,
}

impl RecordingPreferenceRepository {
    fn seed(&self, record: CommunicationPreferenceRecord) {
        self.records.lock().expect("preference lock").insert(
            record.key(),
            VersionedCommunicationPreferenceRecord {
                record,
                version: CommunicationPreferenceVersion::from_raw(1),
            },
        );
    }
}

#[async_trait]
impl CommunicationPreferenceRepository for RecordingPreferenceRepository {
    async fn put_communication_preference(
        &self,
        record: CommunicationPreferenceRecord,
    ) -> Result<(), OutboundError> {
        self.seed(record);
        Ok(())
    }

    async fn load_communication_preference(
        &self,
        key: CommunicationPreferenceKey,
    ) -> Result<Option<VersionedCommunicationPreferenceRecord>, OutboundError> {
        Ok(self
            .records
            .lock()
            .expect("preference lock")
            .get(&key)
            .cloned())
    }

    async fn write_communication_preference(
        &self,
        request: WriteCommunicationPreferenceRequest,
    ) -> Result<VersionedCommunicationPreferenceRecord, OutboundError> {
        let record = VersionedCommunicationPreferenceRecord {
            record: request.record,
            version: CommunicationPreferenceVersion::from_raw(1),
        };
        self.records
            .lock()
            .expect("preference lock")
            .insert(record.record.key(), record.clone());
        Ok(record)
    }
}

#[derive(Debug)]
struct RecordingProductOutboundTargetResolver {
    calls: Mutex<Vec<ReplyTargetBindingRef>>,
    room_id: String,
    fail: bool,
    timeline: StageTimeline,
}

impl Default for RecordingProductOutboundTargetResolver {
    fn default() -> Self {
        Self {
            calls: Mutex::default(),
            room_id: "!room:example.org".to_string(),
            fail: false,
            timeline: StageTimeline::default(),
        }
    }
}

impl RecordingProductOutboundTargetResolver {
    fn for_room(room_id: impl Into<String>) -> Self {
        Self {
            room_id: room_id.into(),
            ..Default::default()
        }
    }

    fn for_room_with_timeline(room_id: impl Into<String>, timeline: StageTimeline) -> Self {
        Self {
            calls: Mutex::default(),
            room_id: room_id.into(),
            fail: false,
            timeline,
        }
    }

    fn failing() -> Self {
        Self {
            fail: true,
            ..Default::default()
        }
    }

    fn calls(&self) -> Vec<ReplyTargetBindingRef> {
        self.calls.lock().expect("target resolver lock").clone()
    }
}

#[async_trait]
impl ProductOutboundTargetResolver for RecordingProductOutboundTargetResolver {
    async fn resolve_product_outbound_target_metadata(
        &self,
        target: &ironclaw_outbound::ValidatedReplyTargetBinding,
        _require_direct_message: bool,
    ) -> Result<VerifiedProductOutboundTargetMetadata, ProductWorkflowError> {
        self.calls
            .lock()
            .expect("target resolver lock")
            .push(target.target().clone());
        self.timeline
            .lock()
            .expect("timeline lock")
            .push("outbound.resolve_target");
        if self.fail {
            return Err(ProductWorkflowError::BindingRequired {
                reason: "Matrix target not resolved".to_string(),
            });
        }
        Ok(VerifiedProductOutboundTargetMetadata {
            external_conversation_ref: ExternalConversationRef::new(
                None,
                &self.room_id,
                Some("$root:example.org"),
                Some("$reply:example.org"),
            )
            .expect("valid Matrix conversation ref"),
            external_actor_ref: None,
        })
    }
}

#[derive(Debug, Default)]
struct RecordingMatrixOutboundPolicyAuthorizer {
    calls: Mutex<Vec<AdapterMatrixOutboundPolicyCheck>>,
    timeline: StageTimeline,
}

impl RecordingMatrixOutboundPolicyAuthorizer {
    fn calls(&self) -> Vec<AdapterMatrixOutboundPolicyCheck> {
        self.calls.lock().expect("policy lock").clone()
    }
}

impl MatrixOutboundPolicyAuthorizer for RecordingMatrixOutboundPolicyAuthorizer {
    fn authorize_matrix_outbound(
        &self,
        snapshot: &AdapterMatrixPolicySnapshot,
        check: &AdapterMatrixOutboundPolicyCheck,
    ) -> Result<(), AdapterMatrixInstallationPolicyRejection> {
        self.calls.lock().expect("policy lock").push(check.clone());
        self.timeline
            .lock()
            .expect("timeline lock")
            .push("matrix.policy");
        authorize_adapter_matrix_outbound(snapshot, check)
    }
}

struct StaticMatrixPolicySnapshotSource {
    snapshot: AdapterMatrixPolicySnapshot,
}

impl Default for StaticMatrixPolicySnapshotSource {
    fn default() -> Self {
        Self {
            snapshot: matrix_policy_snapshot(),
        }
    }
}

#[async_trait]
impl MatrixPolicySnapshotSource for StaticMatrixPolicySnapshotSource {
    async fn resolve_matrix_policy_snapshot(
        &self,
        adapter_id: &ProductAdapterId,
        installation_id: &AdapterInstallationId,
    ) -> Result<AdapterMatrixPolicySnapshot, AdapterMatrixInstallationPolicyRejection> {
        if adapter_id != &self.snapshot.adapter_id {
            return Err(AdapterMatrixInstallationPolicyRejection::AdapterMismatch);
        }
        if installation_id != &self.snapshot.installation_id {
            return Err(AdapterMatrixInstallationPolicyRejection::InstallationMismatch);
        }
        Ok(self.snapshot.clone())
    }
}

#[derive(Debug)]
struct RetryMatrixPolicySnapshotSource {
    result: Mutex<Result<AdapterMatrixPolicySnapshot, AdapterMatrixInstallationPolicyRejection>>,
    calls: Mutex<Vec<(ProductAdapterId, AdapterInstallationId)>>,
}

impl RetryMatrixPolicySnapshotSource {
    fn returning(snapshot: AdapterMatrixPolicySnapshot) -> Self {
        Self {
            result: Mutex::new(Ok(snapshot)),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn rejecting(rejection: AdapterMatrixInstallationPolicyRejection) -> Self {
        Self {
            result: Mutex::new(Err(rejection)),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<(ProductAdapterId, AdapterInstallationId)> {
        self.calls.lock().expect("snapshot source calls").clone()
    }
}

#[async_trait]
impl MatrixPolicySnapshotSource for RetryMatrixPolicySnapshotSource {
    async fn resolve_matrix_policy_snapshot(
        &self,
        adapter_id: &ProductAdapterId,
        installation_id: &AdapterInstallationId,
    ) -> Result<AdapterMatrixPolicySnapshot, AdapterMatrixInstallationPolicyRejection> {
        self.calls
            .lock()
            .expect("snapshot source calls")
            .push((adapter_id.clone(), installation_id.clone()));
        self.result.lock().expect("snapshot source result").clone()
    }
}

struct MatrixProductOutboundEntrypointFixture<'a> {
    extension_installation_store: &'a dyn ExtensionInstallationStore,
    snapshot_source: &'a dyn MatrixPolicySnapshotSource,
    policy_authorizer: &'a dyn MatrixOutboundPolicyAuthorizer,
    outbound_policy: &'a OutboundPolicyService<'a>,
    communication_preferences: &'a dyn CommunicationPreferenceRepository,
    target_resolver: &'a dyn ProductOutboundTargetResolver,
    adapter: &'a dyn ProductAdapter,
    egress: &'a dyn ProtocolHttpEgress,
    delivery_sink: &'a dyn OutboundDeliverySink,
}

fn matrix_product_outbound_entrypoint<'a>(
    fixture: MatrixProductOutboundEntrypointFixture<'a>,
) -> MatrixProductOutboundEntrypoint<'a> {
    MatrixProductOutboundEntrypoint {
        extension_installation_store: fixture.extension_installation_store,
        snapshot_source: fixture.snapshot_source,
        policy_authorizer: fixture.policy_authorizer,
        outbound_policy: fixture.outbound_policy,
        communication_preferences: fixture.communication_preferences,
        target_resolver: fixture.target_resolver,
        adapter: fixture.adapter,
        egress: fixture.egress,
        delivery_sink: fixture.delivery_sink,
    }
}

struct RecordingMatrixRenderAdapter<'a> {
    inner: &'a dyn ProductAdapter,
    timeline: StageTimeline,
}

impl<'a> RecordingMatrixRenderAdapter<'a> {
    fn new(inner: &'a dyn ProductAdapter, timeline: StageTimeline) -> Self {
        Self { inner, timeline }
    }
}

#[async_trait]
impl ProductAdapter for RecordingMatrixRenderAdapter<'_> {
    fn adapter_id(&self) -> &ProductAdapterId {
        self.inner.adapter_id()
    }

    fn installation_id(&self) -> &AdapterInstallationId {
        self.inner.installation_id()
    }

    fn surface_kind(&self) -> ProductSurfaceKind {
        self.inner.surface_kind()
    }

    fn capabilities(&self) -> &ProductAdapterCapabilities {
        self.inner.capabilities()
    }

    fn auth_requirement(&self) -> &AuthRequirement {
        self.inner.auth_requirement()
    }

    fn declared_egress(&self) -> &[DeclaredEgressTarget] {
        self.inner.declared_egress()
    }

    fn parse_inbound(
        &self,
        raw_payload: &[u8],
        auth_evidence: &ProtocolAuthEvidence,
    ) -> Result<ParsedProductInbound, ProductAdapterError> {
        self.inner.parse_inbound(raw_payload, auth_evidence)
    }

    async fn render_outbound(
        &self,
        envelope: ProductOutboundEnvelope,
        egress: &dyn ProtocolHttpEgress,
        delivery_sink: &dyn OutboundDeliverySink,
    ) -> Result<ProductRenderOutcome, ProductAdapterError> {
        self.timeline
            .lock()
            .expect("timeline lock")
            .push("matrix.render");
        self.inner
            .render_outbound(envelope, egress, delivery_sink)
            .await
    }

    fn health(&self) -> ProductAdapterHealth {
        self.inner.health()
    }
}

fn matrix_product_adapter() -> MatrixProductAdapter {
    MatrixProductAdapter::new(MatrixProductAdapterConfig {
        adapter_id: ProductAdapterId::new("matrix").expect("valid adapter id"),
        installation_id: AdapterInstallationId::new("inst_matrix").expect("valid installation id"),
        parse_policy: MatrixParsePolicy {
            allowed_rooms: vec!["!room:example.org".to_string()],
            allowed_senders: vec!["@alice:example.org".to_string()],
        },
        auth_requirement: AuthRequirement::SharedSecretHeader {
            header_name: "x-matrix-webhook-secret".to_string(),
        },
    })
    .expect("explicit Matrix policy")
}

fn matrix_policy_snapshot() -> AdapterMatrixPolicySnapshot {
    AdapterMatrixPolicySnapshot {
        adapter_id: ProductAdapterId::new("matrix").expect("valid adapter id"),
        installation_id: AdapterInstallationId::new("inst_matrix").expect("valid installation id"),
        homeserver: AdapterMatrixHomeserverOrigin::parse("https://matrix.example.org")
            .expect("homeserver"),
        allowed_rooms: std::collections::BTreeSet::from([AdapterMatrixRoomId::new(
            "!room:example.org",
        )
        .expect("room")]),
        allowed_senders: std::collections::BTreeSet::from([AdapterMatrixUserId::new(
            "@alice:example.org",
        )
        .expect("sender")]),
        egress_target_index: AdapterEgressTargetIndex::new(0),
        credential_handle: ironclaw_product_adapters::EgressCredentialHandle::new(
            "matrix-access-token",
        )
        .expect("credential handle"),
        policy_revision: AdapterPolicyRevision::new(7).expect("policy revision"),
    }
}

fn matrix_projection_installation(
    snapshot: &AdapterMatrixPolicySnapshot,
) -> MatrixProductAdapterInstallation {
    let component = ComponentArtifactBinding {
        artifact_id: ComponentArtifactId::new("matrix-component").expect("artifact id"),
        artifact_sha256: ArtifactSha256::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("artifact sha"),
        wit_package: WitPackageName::new("near:product-adapter@0.1.0").expect("wit package"),
        wit_world: WitWorldName::new("product-adapter-component").expect("wit world"),
        manifest: StaticManifestBinding::new("manifest-hash-matrix").expect("manifest hash"),
        declared_egress_targets: vec![DeclaredEgressTarget::new(
            DeclaredEgressHost::new("matrix.example.org").expect("declared Matrix host"),
            Some(snapshot.credential_handle.clone()),
        )],
    };
    let policy = MatrixInstallationPolicy::new(
        snapshot.homeserver.clone(),
        snapshot.allowed_rooms.clone(),
        snapshot.allowed_senders.clone(),
        snapshot.egress_target_index,
        snapshot.credential_handle.clone(),
    )
    .expect("valid Matrix installation policy");
    MatrixProductAdapterInstallation::new(
        snapshot.adapter_id.clone(),
        snapshot.installation_id.clone(),
        component,
        policy,
        MatrixActivationState::Enabled,
        snapshot.policy_revision,
        InstallationAuditMetadata::new("matrix-policy-owner", 1_710_000_000_000)
            .expect("audit metadata"),
    )
    .expect("valid Matrix projection installation")
}

#[tokio::test]
async fn filesystem_matrix_policy_snapshot_source_reads_projection_cache_via_scoped_filesystem() {
    let snapshot = matrix_policy_snapshot();
    let mut cache = MatrixInstallationProjectionCache::new();
    cache
        .insert_projection(
            matrix_projection_installation(&snapshot),
            "matrix-policy-owner",
            1_710_000_000_001,
        )
        .expect("projection cache accepts installation");

    let backend = Arc::new(InMemoryBackend::default());
    let filesystem = matrix_metadata_filesystem(backend);
    let resource_scope = scope().to_resource_scope();
    let cache_path = ScopedPath::new("/outbound/matrix/policy/installation-projection-cache.json")
        .expect("policy cache path");
    let cache_bytes = cache.to_json_bytes().expect("policy cache json");
    filesystem
        .put(
            &resource_scope,
            &cache_path,
            Entry::bytes(cache_bytes.clone()).with_content_type(ContentType::json()),
            CasExpectation::Any,
        )
        .await
        .expect("write policy projection cache");
    filesystem
        .put(
            &resource_scope,
            &matrix_policy_projection_commit_marker_path_for_cache_path(&cache_path)
                .expect("policy cache commit marker path"),
            matrix_policy_projection_commit_marker_entry(&cache_bytes),
            CasExpectation::Any,
        )
        .await
        .expect("write policy projection cache commit marker");

    let source = FilesystemMatrixPolicySnapshotSource::new(
        Arc::clone(&filesystem),
        resource_scope,
        cache_path,
    );
    let resolved = source
        .resolve_matrix_policy_snapshot(&snapshot.adapter_id, &snapshot.installation_id)
        .await
        .expect("projection-backed policy snapshot resolves");

    assert_eq!(resolved, snapshot);
}

async fn matrix_extension_store(
    activation: ExtensionActivationState,
) -> InMemoryExtensionInstallationStore {
    let store = InMemoryExtensionInstallationStore::default();
    let manifest = matrix_extension_manifest();
    let installation = ExtensionInstallation::new(
        ExtensionInstallationId::new("inst_matrix").expect("extension installation id"),
        ExtensionId::new("matrix-component").expect("extension id"),
        activation,
        ExtensionManifestRef::new(
            ExtensionId::new("matrix-component").expect("extension id"),
            Some(ManifestHash::new("sha256:matrix-component").expect("manifest hash")),
        ),
        vec![],
        Utc::now(),
        InstallationOwner::Tenant,
    )
    .expect("extension installation");
    store
        .upsert_manifest_and_installation(manifest, installation)
        .await
        .expect("seed Matrix extension lifecycle");
    store
}

fn matrix_extension_manifest() -> ExtensionManifestRecord {
    ExtensionManifestRecord::from_toml(
        format!(
            r#"
schema_version = "{schema}"
id = "matrix-component"
name = "Matrix Component"
version = "0.1.0"
description = "Matrix ProductAdapter test component"
trust = "third_party"

[runtime]
kind = "wasm"
module = "wasm/matrix.wasm"

[[capabilities]]
id = "matrix-component.echo"
description = "Echoes input"
default_permission = "allow"
visibility = "model"
input_schema_ref = "schemas/matrix/echo.input.v1.json"
output_schema_ref = "schemas/matrix/echo.output.v1.json"
prompt_doc_ref = "prompts/matrix/echo.md"
"#,
            schema = MANIFEST_SCHEMA_VERSION
        ),
        ManifestSource::HostBundled,
        &HostPortCatalog::empty(),
        Some(ManifestHash::new("sha256:matrix-component").expect("manifest hash")),
    )
    .expect("Matrix extension manifest")
}

fn workflow_actor() -> TurnActor {
    TurnActor::new(UserId::new("user-matrix-outbound").expect("valid user"))
}

fn workflow_reply_target() -> ReplyTargetBindingRef {
    ReplyTargetBindingRef::new("matrix:!room:example.org").expect("valid reply target")
}

fn requested_matrix_delivery(
    scope: TurnScope,
) -> ironclaw_outbound::PrepareCommunicationDeliveryRequest {
    ironclaw_outbound::PrepareCommunicationDeliveryRequest {
        resolution_request: CommunicationDeliveryResolutionRequest {
            scope,
            actor: workflow_actor(),
            modality: CommunicationModality::Text,
            intent: CommunicationDeliveryIntent::RequestedOutbound(RequestedOutboundContext {
                requested_target: workflow_reply_target(),
                requested_kind: RequestedOutboundKind::ProductMessage,
            }),
        },
        turn_run_id: Some(TurnRunId::new()),
        projection_ref: ironclaw_outbound::ProjectionUpdateRef::new(
            "projection:matrix:composition-bridge",
        )
        .expect("valid projection ref"),
        attempted_at: Utc::now(),
    }
}

fn workflow_preference_record(scope: &TurnScope) -> CommunicationPreferenceRecord {
    CommunicationPreferenceRecord {
        scope: DeliveryDefaultScope::personal(
            scope.tenant_id.clone(),
            workflow_actor().user_id.clone(),
        ),
        final_reply_target: Some(workflow_reply_target()),
        progress_target: None,
        approval_prompt_target: None,
        auth_prompt_target: None,
        default_modality: Some(CommunicationModality::Text),
        updated_at: Utc::now(),
        updated_by: UserId::new("pref-updater").expect("valid updater"),
    }
}

fn matrix_workflow_payload() -> ProductOutboundPayload {
    ProductOutboundPayload::FinalReply(FinalReplyView {
        turn_run_id: TurnRunId::new(),
        text: "hello Matrix through ProductWorkflow".to_string(),
        generated_at: Utc::now(),
    })
}

fn matrix_endpoint(origin: &str) -> MatrixHttpDeliveryEndpoint {
    MatrixHttpDeliveryEndpoint::new(
        origin,
        SecretHandle::new("matrix_access_token").expect("valid secret handle"),
        canonical_fingerprint("credential-handle-1"),
        CapabilityId::new("matrix.send").expect("valid capability"),
    )
    .expect("valid Matrix endpoint")
}

#[tokio::test]
async fn matrix_http_delivery_port_sends_one_attempt_through_runtime_egress() {
    let origin = "https://matrix.example";
    let command = command();
    let route = route_for_homeserver_origin(origin);
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner(), &route);
    let attempt = attempt(&route, &command);
    let validated = validate_matrix_route_grant(&command, route, &grant)
        .expect("route and grant should validate");
    let endpoint = matrix_endpoint(origin);
    let egress = Arc::new(RecordingMatrixHostEgress::ok(
        200,
        Vec::new(),
        json!({"event_id":"$event:matrix.example"}),
    ));
    let port = MatrixHttpDeliveryPort::new(
        egress.clone(),
        Arc::new(StaticMatrixHttpEndpointResolver {
            endpoint: Some(endpoint),
        }),
        matrix_credential_material_provider(),
    );

    let result = port
        .deliver(
            ProtocolDeliveryIntent::Matrix(command.clone()),
            validated,
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            },
            attempt,
        )
        .await;

    let DeliveryPortResult::Accepted(ProtocolDeliveryEvidence::Matrix(evidence)) = result else {
        panic!("expected accepted Matrix evidence");
    };
    assert_eq!(evidence.transaction_id, command.transaction_id);
    assert_eq!(
        evidence.event_id_fingerprint,
        canonical_fingerprint("$event:matrix.example")
    );
    assert_eq!(
        evidence.homeserver_origin_fingerprint,
        canonical_fingerprint(origin)
    );
    assert_eq!(evidence.room_fingerprint, command.room_id.fingerprint());
    assert_eq!(
        evidence.installation_scoped_credential_ref,
        canonical_fingerprint("credential-handle-1")
    );
    let requests = egress.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].request.method, NetworkMethod::Put);
    assert_eq!(
        requests[0].request.url,
        "https://matrix.example/_matrix/client/v3/rooms/%21room%3Amatrix.example/send/m.room.message/txn-matrix-1"
    );
    assert_eq!(
        requests[0].request.headers,
        vec![("content-type".to_string(), "application/json".to_string())]
    );
    assert!(requests[0].request.credential_injections.is_empty());
    assert_eq!(requests[0].credential_count, 1);
    assert_eq!(
        requests[0].credential_targets[0],
        RuntimeCredentialTarget::Header {
            name: "authorization".to_string(),
            prefix: Some("Bearer ".to_string()),
        }
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].request.body).expect("json request body"),
        *command.body.as_json()
    );
}

#[tokio::test]
async fn matrix_http_delivery_port_records_redacted_send_observability() {
    let origin = "https://matrix.example";
    let command = command();
    let route = route_for_homeserver_origin(origin);
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner(), &route);
    let attempt = attempt(&route, &command);
    let validated = validate_matrix_route_grant(&command, route, &grant)
        .expect("route and grant should validate");
    let endpoint = matrix_endpoint(origin);
    let egress = Arc::new(RecordingMatrixHostEgress::ok(
        200,
        Vec::new(),
        json!({"event_id":"$event:matrix.example"}),
    ));
    let port = MatrixHttpDeliveryPort::new(
        egress,
        Arc::new(StaticMatrixHttpEndpointResolver {
            endpoint: Some(endpoint),
        }),
        matrix_credential_material_provider(),
    );
    let capture = observability::test_capture::start();

    let result = port
        .deliver(
            ProtocolDeliveryIntent::Matrix(command.clone()),
            validated,
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            },
            attempt.clone(),
        )
        .await;

    assert!(
        matches!(
            result,
            DeliveryPortResult::Accepted(ProtocolDeliveryEvidence::Matrix(_))
        ),
        "send should succeed before inspecting observability"
    );
    let events = capture.finish();
    assert!(
        events.iter().any(|event| matches!(
            event,
            observability::MatrixObservabilityEvent::SendAttemptStarted {
                delivery_id,
                attempt_number: 1,
                command_kind: MatrixCommandKind::SendText,
                homeserver_origin_fingerprint,
                room_fingerprint,
            } if *delivery_id == attempt.delivery_id
                && homeserver_origin_fingerprint == &canonical_fingerprint(origin)
                && room_fingerprint == &command.room_id.fingerprint()
        )),
        "send attempt start should be recorded with redacted route metadata: {events:?}"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            observability::MatrixObservabilityEvent::HttpResponseClassified {
                delivery_id,
                attempt_number: 1,
                http_status: 200,
                matrix_errcode: None,
                reason: None,
                homeserver_origin_fingerprint,
                room_fingerprint,
                ..
            } if *delivery_id == attempt.delivery_id
                && homeserver_origin_fingerprint == &canonical_fingerprint(origin)
                && room_fingerprint == &command.room_id.fingerprint()
        )),
        "HTTP response classification should be recorded with redacted route metadata: {events:?}"
    );
    let debug = format!("{events:?}");
    assert!(!debug.contains("!room:matrix.example"));
    assert!(!debug.contains("$event:matrix.example"));
    assert!(!debug.contains("matrix-access-token"));
}

#[tokio::test]
async fn matrix_http_delivery_port_classifies_rate_limit_retry_hint() {
    let origin = "https://matrix.example";
    let command = command();
    let route = route_for_homeserver_origin(origin);
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner(), &route);
    let attempt = attempt(&route, &command);
    let validated = validate_matrix_route_grant(&command, route, &grant)
        .expect("route and grant should validate");
    let endpoint = matrix_endpoint(origin);
    let egress = Arc::new(RecordingMatrixHostEgress::ok(
        429,
        vec![("retry-after".to_string(), "99".to_string())],
        json!({"errcode":"M_LIMIT_EXCEEDED","retry_after_ms":5000}),
    ));
    let port = MatrixHttpDeliveryPort::new(
        egress,
        Arc::new(StaticMatrixHttpEndpointResolver {
            endpoint: Some(endpoint),
        }),
        matrix_credential_material_provider(),
    );
    let capture = observability::test_capture::start();

    let result = port
        .deliver(
            ProtocolDeliveryIntent::Matrix(command),
            validated,
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            },
            attempt,
        )
        .await;

    let DeliveryPortResult::Rejected(error) = result else {
        panic!("expected rejected rate limit");
    };
    assert_eq!(error.reason, DeliveryReasonCode::MatrixRateLimited);
    assert_eq!(error.status_family, Some(HttpStatusFamily::ClientError));
    assert_eq!(error.matrix_errcode, Some(MatrixErrcode::LimitExceeded));
    assert_eq!(
        error.retry_hint.expect("retry hint").after,
        Duration::from_secs(5)
    );
    let events = capture.finish();
    assert!(
        events.iter().any(|event| matches!(
            event,
            observability::MatrixObservabilityEvent::HttpResponseClassified {
                http_status: 429,
                status_family: Some(HttpStatusFamily::ClientError),
                matrix_errcode: Some(MatrixErrcode::LimitExceeded),
                reason: Some(DeliveryReasonCode::MatrixRateLimited),
                ..
            }
        )),
        "rate-limit response classification should be recorded with bounded reason: {events:?}"
    );
}

#[tokio::test]
async fn matrix_http_delivery_port_rejects_endpoint_fingerprint_mismatch_before_egress() {
    let command = command();
    let route = route_for_homeserver_origin("https://matrix.example");
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner(), &route);
    let attempt = attempt(&route, &command);
    let validated = validate_matrix_route_grant(&command, route, &grant)
        .expect("route and grant should validate");
    let endpoint = matrix_endpoint("https://evil.example");
    let egress = Arc::new(RecordingMatrixHostEgress::ok(
        200,
        Vec::new(),
        json!({"event_id":"$event:matrix.example"}),
    ));
    let port = MatrixHttpDeliveryPort::new(
        egress.clone(),
        Arc::new(StaticMatrixHttpEndpointResolver {
            endpoint: Some(endpoint),
        }),
        matrix_credential_material_provider(),
    );

    let result = port
        .deliver(
            ProtocolDeliveryIntent::Matrix(command),
            validated,
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            },
            attempt,
        )
        .await;

    let DeliveryPortResult::Rejected(error) = result else {
        panic!("expected rejected endpoint mismatch");
    };
    assert_eq!(error.reason, DeliveryReasonCode::UnauthorizedTarget);
    assert!(egress.requests().is_empty());
}

#[tokio::test]
async fn matrix_http_delivery_port_rejects_missing_current_secret_before_egress() {
    let origin = "https://matrix.example";
    let command = command();
    let route = route_for_homeserver_origin(origin);
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner(), &route);
    let attempt = attempt(&route, &command);
    let validated = validate_matrix_route_grant(&command, route, &grant)
        .expect("route and grant should validate");
    let egress = Arc::new(RecordingMatrixHostEgress::ok(
        200,
        Vec::new(),
        json!({"event_id":"$event:matrix.example"}),
    ));
    let port = MatrixHttpDeliveryPort::new(
        egress.clone(),
        Arc::new(StaticMatrixHttpEndpointResolver {
            endpoint: Some(matrix_endpoint(origin)),
        }),
        Arc::new(MatrixSecretStoreCredentialMaterialProvider::new(Arc::new(
            ironclaw_secrets::InMemorySecretStore::new(),
        ))),
    );

    let result = port
        .deliver(
            ProtocolDeliveryIntent::Matrix(command),
            validated,
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            },
            attempt,
        )
        .await;

    let DeliveryPortResult::Rejected(error) = result else {
        panic!("missing current secret must reject before HTTP egress");
    };
    assert_eq!(error.reason, DeliveryReasonCode::UnauthorizedTarget);
    assert!(egress.requests().is_empty());
}

#[test]
fn matrix_http_delivery_endpoint_rejects_plaintext_and_private_origins() {
    for origin in [
        "http://matrix.example",
        "https://user:pass@matrix.example",
        "https://matrix.example/path",
        "https://matrix.example?access_token=secret",
        "https://matrix.example#fragment",
        "https://localhost",
        "https://matrix.local",
        "https://matrix.internal",
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://172.16.0.1",
        "https://192.168.1.10",
        "https://[::1]",
        "https://[fd00::1]",
    ] {
        let error = MatrixHttpDeliveryEndpoint::new(
            origin,
            SecretHandle::new("matrix_access_token").expect("valid secret handle"),
            canonical_fingerprint("credential-handle-1"),
            CapabilityId::new("matrix.send").expect("valid capability"),
        )
        .expect_err("unsafe Matrix origin must be rejected");

        assert_eq!(
            error.reason,
            DeliveryReasonCode::UnauthorizedTarget,
            "origin {origin:?} should fail closed"
        );
    }
}

#[test]
fn matrix_http_delivery_endpoint_validates_limits_and_fingerprint() {
    let bad_fingerprint = MatrixHttpDeliveryEndpoint::new(
        "https://matrix.example",
        SecretHandle::new("matrix_access_token").expect("valid secret handle"),
        "credential-handle-1",
        CapabilityId::new("matrix.send").expect("valid capability"),
    )
    .expect_err("non-fingerprint credential refs must be rejected");
    assert_eq!(
        bad_fingerprint.reason,
        DeliveryReasonCode::UnauthorizedTarget
    );

    assert_eq!(
        matrix_endpoint("https://matrix.example")
            .with_response_body_limit(0)
            .expect_err("zero response body limit must be rejected")
            .reason,
        DeliveryReasonCode::MatrixBadRequest
    );
    assert_eq!(
        matrix_endpoint("https://matrix.example")
            .with_timeout_ms(Some(0))
            .expect_err("zero timeout must be rejected")
            .reason,
        DeliveryReasonCode::MatrixBadRequest
    );
}

#[test]
fn matrix_path_segments_are_percent_encoded() {
    assert_eq!(
        encode_matrix_path_segment("!room/../?#% snow:matrix.example"),
        "%21room%2F..%2F%3F%23%25%20snow%3Amatrix.example"
    );
    assert_eq!(
        encode_matrix_path_segment("txn/with spaces/☃"),
        "txn%2Fwith%20spaces%2F%E2%98%83"
    );
}

#[test]
fn matrix_http_status_taxonomy_keeps_permanent_protocol_errors_non_retryable() {
    for (status, errcode, reason) in [
        (
            403,
            Some(MatrixErrcode::Forbidden),
            DeliveryReasonCode::UnauthorizedTarget,
        ),
        (
            403,
            Some(MatrixErrcode::UserDeactivated),
            DeliveryReasonCode::UnauthorizedTarget,
        ),
        (
            404,
            Some(MatrixErrcode::NotFound),
            DeliveryReasonCode::MatrixNotFound,
        ),
        (
            400,
            Some(MatrixErrcode::BadJson),
            DeliveryReasonCode::MatrixBadRequest,
        ),
        (
            413,
            Some(MatrixErrcode::TooLarge),
            DeliveryReasonCode::MatrixMessageTooLarge,
        ),
        (
            400,
            Some(MatrixErrcode::UnsupportedRoomVersion),
            DeliveryReasonCode::MatrixUnsupportedRoomVersion,
        ),
    ] {
        let error = DeliveryError::new(reason_for_matrix_http_status(status, errcode));
        assert_eq!(error.reason, reason);
        assert_eq!(
            retry_policy().classify(&error, 1),
            MatrixRetryDecision::DoNotRetry {
                terminal_status: MatrixTerminalStatus::FailedPermanent
            }
        );
    }
}

#[tokio::test]
async fn matrix_http_delivery_port_rejects_malformed_success_response() {
    let origin = "https://matrix.example";
    let command = command();
    let route = route_for_homeserver_origin(origin);
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner(), &route);
    let attempt = attempt(&route, &command);
    let validated = validate_matrix_route_grant(&command, route, &grant)
        .expect("route and grant should validate");
    let egress = Arc::new(RecordingMatrixHostEgress::ok(200, Vec::new(), json!({})));
    let port = MatrixHttpDeliveryPort::new(
        egress,
        Arc::new(StaticMatrixHttpEndpointResolver {
            endpoint: Some(matrix_endpoint(origin)),
        }),
        matrix_credential_material_provider(),
    );

    let result = port
        .deliver(
            ProtocolDeliveryIntent::Matrix(command),
            validated,
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            },
            attempt,
        )
        .await;

    let DeliveryPortResult::Rejected(error) = result else {
        panic!("expected malformed success response to be rejected");
    };
    assert_eq!(error.reason, DeliveryReasonCode::MatrixMalformedResponse);
}

#[tokio::test]
async fn matrix_http_delivery_port_preserves_explicit_homeserver_port() {
    let origin = "https://matrix.example:8448";
    let command = command();
    let route = route_for_homeserver_origin(origin);
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner(), &route);
    let attempt = attempt(&route, &command);
    let validated = validate_matrix_route_grant(&command, route, &grant)
        .expect("route and grant should validate");
    let egress = Arc::new(RecordingMatrixHostEgress::ok(
        200,
        Vec::new(),
        json!({"event_id":"$event:matrix.example"}),
    ));
    let port = MatrixHttpDeliveryPort::new(
        egress.clone(),
        Arc::new(StaticMatrixHttpEndpointResolver {
            endpoint: Some(matrix_endpoint(origin)),
        }),
        matrix_credential_material_provider(),
    );

    let result = port
        .deliver(
            ProtocolDeliveryIntent::Matrix(command),
            validated,
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            },
            attempt,
        )
        .await;

    assert!(
        matches!(
            result,
            DeliveryPortResult::Accepted(ProtocolDeliveryEvidence::Matrix(_))
        ),
        "explicit port delivery should succeed"
    );
    let requests = egress.requests();
    assert_eq!(
        requests[0].request.url,
        "https://matrix.example:8448/_matrix/client/v3/rooms/%21room%3Amatrix.example/send/m.room.message/txn-matrix-1"
    );
    assert_eq!(
        requests[0].request.network_policy.allowed_targets[0].port,
        Some(8448)
    );
}

#[tokio::test]
async fn orchestrator_consumes_pending_matrix_intent_and_records_delivered_evidence() {
    let command = command();
    let route = route();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let attempt_ctx = attempt(&route, &command);
    let port = FakeMatrixDeliveryPort::default();
    port.push_result(DeliveryPortResult::Accepted(
        ProtocolDeliveryEvidence::Matrix(accepted_evidence(&command, &route, &attempt_ctx)),
    ));
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);

    let outcome = orchestrator
        .consume_pending_intent(command.clone(), route.clone(), grant, attempt_ctx)
        .await
        .expect("pending intent should be consumed");

    assert_eq!(outcome.status, MatrixTerminalStatus::Delivered);
    assert_eq!(outcome.retry, None);
    assert_eq!(
        port.calls(),
        vec![ProtocolDeliveryIntent::Matrix(command.clone())]
    );
    assert_eq!(store.statuses(), vec![OutboundDeliveryStatus::Delivered]);
    assert_eq!(store.failure_kinds(), vec![None]);
    assert_eq!(store.evidence().len(), 1);
    assert_eq!(
        store.evidence()[0].1.event_id_fingerprint,
        canonical_fingerprint("event-1")
    );
}

#[tokio::test]
async fn orchestrator_records_redacted_delivery_status_observability() {
    let command = command();
    let route = route();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let attempt_ctx = attempt(&route, &command);
    let port = FakeMatrixDeliveryPort::default();
    port.push_result(DeliveryPortResult::Accepted(
        ProtocolDeliveryEvidence::Matrix(accepted_evidence(&command, &route, &attempt_ctx)),
    ));
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);
    let capture = observability::test_capture::start();

    let outcome = orchestrator
        .consume_pending_intent(command, route.clone(), grant, attempt_ctx.clone())
        .await
        .expect("pending intent should be consumed");

    assert_eq!(outcome.status, MatrixTerminalStatus::Delivered);
    let events = capture.finish();
    assert!(
        events.iter().any(|event| matches!(
            event,
            observability::MatrixObservabilityEvent::DeliveryStatusUpdated {
                delivery_id,
                status: MatrixTerminalStatus::Delivered,
                reason: None,
            } if *delivery_id == attempt_ctx.delivery_id
        )),
        "delivered status update should be recorded: {events:?}"
    );
    let debug = format!("{events:?}");
    assert!(!debug.contains("!room:matrix.example"));
    assert!(!debug.contains("event-1"));
}

#[tokio::test]
async fn adapter_pending_matrix_intent_can_join_composition_orchestrator_without_http() {
    let timeline = StageTimeline::default();
    let workflow_scope = scope();
    let outbound_store = in_memory_backed_outbound_state_store();
    let validator = RecordingReplyTargetBindingValidator {
        timeline: timeline.clone(),
        ..Default::default()
    };
    validator.allow(workflow_reply_target());
    let preferences = RecordingPreferenceRepository::default();
    preferences.seed(workflow_preference_record(&workflow_scope));
    let resolver = RecordingProductOutboundTargetResolver::for_room_with_timeline(
        "!room:example.org",
        timeline.clone(),
    );
    let access_policy = AllowAllProjectionAccessPolicy;
    let outbound_policy = OutboundPolicyService::new(&outbound_store, &access_policy, &validator);
    let inner_adapter = matrix_product_adapter();
    let adapter = RecordingMatrixRenderAdapter::new(&inner_adapter, timeline.clone());
    let extension_store = RecordingExtensionInstallationStore::new(
        matrix_extension_store(ExtensionActivationState::Enabled).await,
        timeline.clone(),
    );
    let policy_authorizer = RecordingMatrixOutboundPolicyAuthorizer {
        timeline: timeline.clone(),
        ..Default::default()
    };
    let snapshot_source = StaticMatrixPolicySnapshotSource::default();
    let egress = FakeProtocolHttpEgress::new(Vec::<String>::new());
    let delivery_sink = FakeOutboundDeliverySink::new();

    let entrypoint = matrix_product_outbound_entrypoint(MatrixProductOutboundEntrypointFixture {
        extension_installation_store: &extension_store,
        snapshot_source: &snapshot_source,
        policy_authorizer: &policy_authorizer,
        outbound_policy: &outbound_policy,
        communication_preferences: &preferences,
        target_resolver: &resolver,
        adapter: &adapter,
        egress: &egress,
        delivery_sink: &delivery_sink,
    });
    let outcome = entrypoint
        .prepare_and_render(MatrixProductOutboundDeliveryInput {
            delivery: requested_matrix_delivery(workflow_scope.clone()),
            payload: matrix_workflow_payload(),
            projection_cursor: ProductProjectionCursor::new("cursor:matrix:composition-bridge")
                .expect("valid projection cursor"),
            require_direct_message_target: false,
        })
        .await
        .expect("Matrix adapter should render through shared ProductWorkflow outbound");

    let ProductOutboundDeliveryOutcome::Rendered {
        attempt: outbound_attempt,
        render_outcome,
    } = outcome
    else {
        panic!("expected Matrix outbound to reach shared render path");
    };
    assert!(matches!(render_outcome, ProductRenderOutcome::Deferred));
    let attempts = outbound_store
        .list_delivery_attempts(workflow_scope.clone())
        .await
        .expect("list attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].delivery_id, outbound_attempt.delivery_id);
    assert_eq!(attempts[0].status, OutboundDeliveryStatus::Pending);
    assert_eq!(
        timeline.lock().expect("timeline lock").as_slice(),
        [
            "lifecycle.check",
            "outbound.validate_reply_target",
            "outbound.resolve_target",
            "matrix.policy",
            "matrix.render"
        ],
        "Matrix outbound must pass lifecycle, shared target resolution, R002C policy, and render in order"
    );

    let adapter_intent = inner_adapter
        .pending_matrix_intent(outbound_attempt.delivery_id.as_uuid())
        .expect("adapter should hold pending Matrix intent for bridge handoff");
    let command = MatrixOutboundCommand::from_adapter_pending_intent(
        adapter_intent,
        MatrixPendingIntentBridgeContext {
            reply_target_binding_ref: workflow_reply_target(),
            egress_target_index: 0,
        },
    )
    .expect("composition bridge should convert trusted Matrix intent");
    let owner = owner();
    let route = FrozenProductDeliveryRoute::mint_for_matrix(
        &owner,
        outbound_attempt.delivery_id,
        workflow_scope,
        "inst_matrix",
        "matrix",
        MatrixRouteMetadata {
            policy_revision: "7".into(),
            homeserver_origin_fingerprint: canonical_fingerprint("homeserver-1"),
            room_fingerprint: command.room_id.fingerprint(),
            egress_target_index: 0,
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            reply_target_binding_ref: workflow_reply_target(),
            allowed_command_kinds: vec![MatrixCommandKind::SendText],
            policy_provider_scope: None,
        },
    );
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let attempt_ctx = DeliveryAttemptContext {
        delivery_id: outbound_attempt.delivery_id,
        attempt_number: 1,
        transaction_id: command.transaction_id.clone(),
        started_at: Utc::now(),
    };
    let port = FakeMatrixDeliveryPort::default();
    port.push_result(DeliveryPortResult::Accepted(
        ProtocolDeliveryEvidence::Matrix(accepted_evidence(&command, &route, &attempt_ctx)),
    ));
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);

    let outcome = orchestrator
        .consume_pending_intent(command.clone(), route.clone(), grant, attempt_ctx)
        .await
        .expect("converted pending intent should be delivered by fake port");

    assert_eq!(outcome.status, MatrixTerminalStatus::Delivered);
    assert_eq!(port.calls(), vec![ProtocolDeliveryIntent::Matrix(command)]);
    assert_eq!(store.statuses(), vec![OutboundDeliveryStatus::Delivered]);
    assert_eq!(store.failure_kinds(), vec![None]);
    assert_eq!(store.evidence().len(), 1);
}

#[tokio::test]
async fn matrix_product_outbound_disabled_lifecycle_rejects_before_target_resolution_policy_or_render()
 {
    let workflow_scope = scope();
    let outbound_store = in_memory_backed_outbound_state_store();
    let validator = RecordingReplyTargetBindingValidator::default();
    validator.allow(workflow_reply_target());
    let preferences = RecordingPreferenceRepository::default();
    preferences.seed(workflow_preference_record(&workflow_scope));
    let resolver = RecordingProductOutboundTargetResolver::default();
    let access_policy = AllowAllProjectionAccessPolicy;
    let outbound_policy = OutboundPolicyService::new(&outbound_store, &access_policy, &validator);
    let adapter = matrix_product_adapter();
    let extension_store = matrix_extension_store(ExtensionActivationState::Disabled).await;
    let policy_authorizer = RecordingMatrixOutboundPolicyAuthorizer::default();
    let snapshot_source = StaticMatrixPolicySnapshotSource::default();
    let egress = FakeProtocolHttpEgress::new(Vec::<String>::new());
    let delivery_sink = FakeOutboundDeliverySink::new();

    let entrypoint = matrix_product_outbound_entrypoint(MatrixProductOutboundEntrypointFixture {
        extension_installation_store: &extension_store,
        snapshot_source: &snapshot_source,
        policy_authorizer: &policy_authorizer,
        outbound_policy: &outbound_policy,
        communication_preferences: &preferences,
        target_resolver: &resolver,
        adapter: &adapter,
        egress: &egress,
        delivery_sink: &delivery_sink,
    });
    let error = entrypoint
        .prepare_and_render(MatrixProductOutboundDeliveryInput {
            delivery: requested_matrix_delivery(workflow_scope.clone()),
            payload: matrix_workflow_payload(),
            projection_cursor: ProductProjectionCursor::new("cursor:matrix:disabled")
                .expect("valid projection cursor"),
            require_direct_message_target: false,
        })
        .await
        .expect_err("disabled lifecycle should fail before target resolution");

    assert!(matches!(
        error,
        MatrixProductOutboundDeliveryError::Lifecycle(
            AdapterMatrixInstallationPolicyRejection::InstallationDisabled
        )
    ));
    assert!(validator.calls().is_empty());
    assert!(resolver.calls().is_empty());
    assert!(policy_authorizer.calls().is_empty());
    assert!(egress.calls().is_empty());
    assert!(delivery_sink.statuses().is_empty());
    assert!(
        outbound_store
            .list_delivery_attempts(workflow_scope)
            .await
            .expect("list attempts")
            .is_empty()
    );
}

#[tokio::test]
async fn matrix_product_outbound_deleting_lifecycle_rejects_before_target_resolution_policy_or_render()
 {
    let workflow_scope = scope();
    let outbound_store = in_memory_backed_outbound_state_store();
    let validator = RecordingReplyTargetBindingValidator::default();
    validator.allow(workflow_reply_target());
    let preferences = RecordingPreferenceRepository::default();
    preferences.seed(workflow_preference_record(&workflow_scope));
    let resolver = RecordingProductOutboundTargetResolver::default();
    let access_policy = AllowAllProjectionAccessPolicy;
    let outbound_policy = OutboundPolicyService::new(&outbound_store, &access_policy, &validator);
    let adapter = matrix_product_adapter();
    let extension_store = InMemoryExtensionInstallationStore::default();
    let policy_authorizer = RecordingMatrixOutboundPolicyAuthorizer::default();
    let snapshot_source = StaticMatrixPolicySnapshotSource::default();
    let egress = FakeProtocolHttpEgress::new(Vec::<String>::new());
    let delivery_sink = FakeOutboundDeliverySink::new();

    let entrypoint = matrix_product_outbound_entrypoint(MatrixProductOutboundEntrypointFixture {
        extension_installation_store: &extension_store,
        snapshot_source: &snapshot_source,
        policy_authorizer: &policy_authorizer,
        outbound_policy: &outbound_policy,
        communication_preferences: &preferences,
        target_resolver: &resolver,
        adapter: &adapter,
        egress: &egress,
        delivery_sink: &delivery_sink,
    });
    let error = entrypoint
        .prepare_and_render(MatrixProductOutboundDeliveryInput {
            delivery: requested_matrix_delivery(workflow_scope.clone()),
            payload: matrix_workflow_payload(),
            projection_cursor: ProductProjectionCursor::new("cursor:matrix:deleting")
                .expect("valid projection cursor"),
            require_direct_message_target: false,
        })
        .await
        .expect_err("deleting lifecycle should fail before target resolution");

    assert!(matches!(
        error,
        MatrixProductOutboundDeliveryError::Lifecycle(
            AdapterMatrixInstallationPolicyRejection::InstallationDeleting
        )
    ));
    assert!(validator.calls().is_empty());
    assert!(resolver.calls().is_empty());
    assert!(policy_authorizer.calls().is_empty());
    assert!(egress.calls().is_empty());
    assert!(delivery_sink.statuses().is_empty());
    assert!(
        outbound_store
            .list_delivery_attempts(workflow_scope)
            .await
            .expect("list attempts")
            .is_empty()
    );
}

#[tokio::test]
async fn matrix_product_outbound_unresolved_target_stops_before_matrix_policy_and_render() {
    let workflow_scope = scope();
    let outbound_store = in_memory_backed_outbound_state_store();
    let validator = RecordingReplyTargetBindingValidator::default();
    validator.allow(workflow_reply_target());
    let preferences = RecordingPreferenceRepository::default();
    preferences.seed(workflow_preference_record(&workflow_scope));
    let resolver = RecordingProductOutboundTargetResolver::failing();
    let access_policy = AllowAllProjectionAccessPolicy;
    let outbound_policy = OutboundPolicyService::new(&outbound_store, &access_policy, &validator);
    let adapter = matrix_product_adapter();
    let extension_store = matrix_extension_store(ExtensionActivationState::Enabled).await;
    let policy_authorizer = RecordingMatrixOutboundPolicyAuthorizer::default();
    let snapshot_source = StaticMatrixPolicySnapshotSource::default();
    let egress = FakeProtocolHttpEgress::new(Vec::<String>::new());
    let delivery_sink = FakeOutboundDeliverySink::new();

    let entrypoint = matrix_product_outbound_entrypoint(MatrixProductOutboundEntrypointFixture {
        extension_installation_store: &extension_store,
        snapshot_source: &snapshot_source,
        policy_authorizer: &policy_authorizer,
        outbound_policy: &outbound_policy,
        communication_preferences: &preferences,
        target_resolver: &resolver,
        adapter: &adapter,
        egress: &egress,
        delivery_sink: &delivery_sink,
    });
    let error = entrypoint
        .prepare_and_render(MatrixProductOutboundDeliveryInput {
            delivery: requested_matrix_delivery(workflow_scope.clone()),
            payload: matrix_workflow_payload(),
            projection_cursor: ProductProjectionCursor::new("cursor:matrix:unresolved")
                .expect("valid projection cursor"),
            require_direct_message_target: false,
        })
        .await
        .expect_err("unresolved target should stop before Matrix policy");

    assert!(matches!(
        error,
        MatrixProductOutboundDeliveryError::TargetResolution { .. }
    ));
    assert_eq!(validator.calls(), vec![workflow_reply_target()]);
    assert_eq!(resolver.calls(), vec![workflow_reply_target()]);
    assert!(policy_authorizer.calls().is_empty());
    assert!(egress.calls().is_empty());
    assert!(delivery_sink.statuses().is_empty());
    let attempts = outbound_store
        .list_delivery_attempts(workflow_scope)
        .await
        .expect("list attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].status, OutboundDeliveryStatus::Failed);
    assert_eq!(
        attempts[0].failure_kind,
        Some(DeliveryFailureKind::Rejected)
    );
}

#[tokio::test]
async fn matrix_product_outbound_invalid_resolved_room_reports_policy_stage_without_render() {
    let workflow_scope = scope();
    let outbound_store = in_memory_backed_outbound_state_store();
    let validator = RecordingReplyTargetBindingValidator::default();
    validator.allow(workflow_reply_target());
    let preferences = RecordingPreferenceRepository::default();
    preferences.seed(workflow_preference_record(&workflow_scope));
    let resolver = RecordingProductOutboundTargetResolver::for_room("not-a-matrix-room");
    let access_policy = AllowAllProjectionAccessPolicy;
    let outbound_policy = OutboundPolicyService::new(&outbound_store, &access_policy, &validator);
    let adapter = matrix_product_adapter();
    let extension_store = matrix_extension_store(ExtensionActivationState::Enabled).await;
    let policy_authorizer = RecordingMatrixOutboundPolicyAuthorizer::default();
    let snapshot_source = StaticMatrixPolicySnapshotSource::default();
    let egress = FakeProtocolHttpEgress::new(Vec::<String>::new());
    let delivery_sink = FakeOutboundDeliverySink::new();

    let entrypoint = matrix_product_outbound_entrypoint(MatrixProductOutboundEntrypointFixture {
        extension_installation_store: &extension_store,
        snapshot_source: &snapshot_source,
        policy_authorizer: &policy_authorizer,
        outbound_policy: &outbound_policy,
        communication_preferences: &preferences,
        target_resolver: &resolver,
        adapter: &adapter,
        egress: &egress,
        delivery_sink: &delivery_sink,
    });
    let error = entrypoint
        .prepare_and_render(MatrixProductOutboundDeliveryInput {
            delivery: requested_matrix_delivery(workflow_scope.clone()),
            payload: matrix_workflow_payload(),
            projection_cursor: ProductProjectionCursor::new("cursor:matrix:invalid-room")
                .expect("valid projection cursor"),
            require_direct_message_target: false,
        })
        .await
        .expect_err("invalid Matrix room should be reported as a Matrix policy-stage failure");

    assert!(matches!(
        error,
        MatrixProductOutboundDeliveryError::Policy {
            rejection: AdapterMatrixInstallationPolicyRejection::InvalidPolicyValue,
            ..
        }
    ));
    assert_eq!(validator.calls(), vec![workflow_reply_target()]);
    assert_eq!(resolver.calls(), vec![workflow_reply_target()]);
    assert!(policy_authorizer.calls().is_empty());
    assert!(egress.calls().is_empty());
    assert!(delivery_sink.statuses().is_empty());
    let attempts = outbound_store
        .list_delivery_attempts(workflow_scope)
        .await
        .expect("list attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].status, OutboundDeliveryStatus::Failed);
    assert_eq!(
        attempts[0].failure_kind,
        Some(DeliveryFailureKind::Rejected)
    );
    assert!(
        adapter
            .pending_matrix_intent(attempts[0].delivery_id.as_uuid())
            .is_none(),
        "policy-check construction failure must not leave a pending Matrix intent"
    );
}

#[tokio::test]
async fn matrix_product_outbound_policy_denial_after_target_resolution_stops_before_render() {
    let workflow_scope = scope();
    let outbound_store = in_memory_backed_outbound_state_store();
    let validator = RecordingReplyTargetBindingValidator::default();
    validator.allow(workflow_reply_target());
    let preferences = RecordingPreferenceRepository::default();
    preferences.seed(workflow_preference_record(&workflow_scope));
    let resolver = RecordingProductOutboundTargetResolver::for_room("!other:example.org");
    let access_policy = AllowAllProjectionAccessPolicy;
    let outbound_policy = OutboundPolicyService::new(&outbound_store, &access_policy, &validator);
    let adapter = matrix_product_adapter();
    let extension_store = matrix_extension_store(ExtensionActivationState::Enabled).await;
    let policy_authorizer = RecordingMatrixOutboundPolicyAuthorizer::default();
    let snapshot_source = StaticMatrixPolicySnapshotSource::default();
    let egress = FakeProtocolHttpEgress::new(Vec::<String>::new());
    let delivery_sink = FakeOutboundDeliverySink::new();

    let entrypoint = matrix_product_outbound_entrypoint(MatrixProductOutboundEntrypointFixture {
        extension_installation_store: &extension_store,
        snapshot_source: &snapshot_source,
        policy_authorizer: &policy_authorizer,
        outbound_policy: &outbound_policy,
        communication_preferences: &preferences,
        target_resolver: &resolver,
        adapter: &adapter,
        egress: &egress,
        delivery_sink: &delivery_sink,
    });
    let error = entrypoint
        .prepare_and_render(MatrixProductOutboundDeliveryInput {
            delivery: requested_matrix_delivery(workflow_scope.clone()),
            payload: matrix_workflow_payload(),
            projection_cursor: ProductProjectionCursor::new("cursor:matrix:policy-denied")
                .expect("valid projection cursor"),
            require_direct_message_target: false,
        })
        .await
        .expect_err("policy-denied Matrix room should not render");

    assert!(matches!(
        error,
        MatrixProductOutboundDeliveryError::Policy {
            rejection: AdapterMatrixInstallationPolicyRejection::RoomNotAllowed,
            ..
        }
    ));
    assert_eq!(validator.calls(), vec![workflow_reply_target()]);
    assert_eq!(resolver.calls(), vec![workflow_reply_target()]);
    assert_eq!(policy_authorizer.calls().len(), 1);
    assert_eq!(
        policy_authorizer.calls()[0].room_id.as_str(),
        "!other:example.org"
    );
    assert!(egress.calls().is_empty());
    assert!(delivery_sink.statuses().is_empty());
    let attempts = outbound_store
        .list_delivery_attempts(workflow_scope)
        .await
        .expect("list attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].status, OutboundDeliveryStatus::Failed);
    assert_eq!(
        attempts[0].failure_kind,
        Some(DeliveryFailureKind::Rejected)
    );
    assert!(
        adapter
            .pending_matrix_intent(attempts[0].delivery_id.as_uuid())
            .is_none(),
        "Matrix policy denial must not leave a pending Matrix intent"
    );
}

#[tokio::test]
async fn orchestrator_fails_closed_before_port_when_credential_fingerprint_mismatches() {
    let command = command();
    let route = route();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = FakeMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("wrong-credential-handle"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);

    let error = orchestrator
        .consume_pending_intent(
            command.clone(),
            route.clone(),
            grant,
            attempt(&route, &command),
        )
        .await
        .expect_err("credential mismatch must fail");

    assert_eq!(error.reason, DeliveryReasonCode::UnauthorizedTarget);
    assert!(port.calls().is_empty());
    assert_eq!(store.statuses(), vec![OutboundDeliveryStatus::Failed]);
    assert_eq!(
        store.failure_kinds(),
        vec![Some(DeliveryFailureKind::AuthorizationRevoked)]
    );
    assert!(store.evidence().is_empty());
}

#[tokio::test]
async fn orchestrator_fails_closed_before_port_when_policy_revision_is_stale() {
    let command = command();
    let route = route();
    let mut stale_route = route.clone();
    stale_route.metadata.policy_revision = "policy-rev-stale".into();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &stale_route);
    let port = FakeMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);

    let error = orchestrator
        .consume_pending_intent(
            command.clone(),
            route.clone(),
            grant,
            attempt(&route, &command),
        )
        .await
        .expect_err("stale policy grant must fail");

    assert_eq!(error.reason, DeliveryReasonCode::UnauthorizedTarget);
    assert!(port.calls().is_empty());
    assert_eq!(store.statuses(), vec![OutboundDeliveryStatus::Failed]);
    assert!(store.evidence().is_empty());
}

#[tokio::test]
async fn orchestrator_fails_closed_before_port_when_room_fingerprint_differs() {
    let command = command();
    let route = route();
    let mut wrong_room_route = route.clone();
    wrong_room_route.metadata.room_fingerprint = canonical_fingerprint("room-other");
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &wrong_room_route);
    let port = FakeMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);

    let error = orchestrator
        .consume_pending_intent(
            command.clone(),
            route.clone(),
            grant,
            attempt(&route, &command),
        )
        .await
        .expect_err("wrong room grant must fail");

    assert_eq!(error.reason, DeliveryReasonCode::UnauthorizedTarget);
    assert!(port.calls().is_empty());
    assert_eq!(store.statuses(), vec![OutboundDeliveryStatus::Failed]);
    assert!(store.evidence().is_empty());
}

#[tokio::test]
async fn orchestrator_fails_closed_before_port_when_command_room_differs_from_route() {
    let mut command = command();
    command.room_id = MatrixRoomId::new("!other-room:matrix.example").expect("valid room");
    let route = route();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = FakeMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);

    let error = orchestrator
        .consume_pending_intent(
            command.clone(),
            route.clone(),
            grant,
            attempt(&route, &command),
        )
        .await
        .expect_err("command room mismatch must fail before delivery");

    assert_eq!(error.reason, DeliveryReasonCode::UnauthorizedTarget);
    assert!(port.calls().is_empty());
    assert_eq!(store.statuses(), vec![OutboundDeliveryStatus::Failed]);
    assert!(store.evidence().is_empty());
}

#[test]
fn forged_route_grant_fails_before_delivery_port() {
    let route = route();
    let forged_grant = route_forgery_fixture(&route, 9);

    let error = validate_matrix_route_grant(&command(), route, &forged_grant)
        .expect_err("forged grant must fail");

    assert_eq!(error.reason, DeliveryReasonCode::StalePolicyRevision);
}

#[test]
fn matrix_evidence_rejects_raw_identifiers() {
    let route = route();
    let evidence = MatrixDeliveryEvidenceV1 {
        schema_version: 1,
        delivery_id: route.delivery_id,
        attempt_number: 1,
        event_id_fingerprint: "$raw-event-id".into(),
        transaction_id: MatrixTransactionId::new("txn-matrix-1").expect("valid txn"),
        command_kind: MatrixCommandKind::SendText,
        delivered_at: Utc::now(),
        verified: true,
        homeserver_origin_fingerprint: canonical_fingerprint("homeserver-1"),
        room_fingerprint: "room_fp_1".into(),
        installation_scoped_credential_ref: "cred_ref_1".into(),
        http_status: 200,
        latency_ms: 12,
    };

    assert_eq!(
        evidence.validate_redacted(),
        Err(MatrixOutboundContractError::UnsafeEvidence)
    );
}

#[test]
fn matrix_evidence_rejects_secret_like_credential_refs() {
    for credential_ref in [
        "matrix_access_token",
        "secret:matrix",
        "matrix.secret.handle",
    ] {
        let command = command();
        let route = route();
        let attempt = attempt(&route, &command);
        let mut evidence = accepted_evidence(&command, &route, &attempt);
        evidence.installation_scoped_credential_ref = credential_ref.into();

        assert_eq!(
            evidence.validate_redacted(),
            Err(MatrixOutboundContractError::UnsafeEvidence),
            "credential ref {credential_ref:?} must not be persisted as delivery evidence"
        );
    }
}

#[test]
fn matrix_evidence_fingerprint_fields_require_canonical_sha256_format() {
    let command = command();
    let route = route();
    let valid_fingerprint = canonical_fingerprint("valid-fingerprint");
    let invalid_cases = [
        ("event_id_fingerprint", "event_fp_1"),
        (
            "homeserver_origin_fingerprint",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
        ),
        (
            "room_fingerprint",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("installation_scoped_credential_ref", "credential-ref-1"),
    ];

    for (field, invalid_fingerprint) in invalid_cases {
        let mut evidence = MatrixDeliveryEvidenceV1 {
            schema_version: 1,
            delivery_id: route.delivery_id,
            attempt_number: 1,
            event_id_fingerprint: valid_fingerprint.clone(),
            transaction_id: command.transaction_id.clone(),
            command_kind: command.command_kind,
            delivered_at: Utc::now(),
            verified: true,
            homeserver_origin_fingerprint: valid_fingerprint.clone(),
            room_fingerprint: valid_fingerprint.clone(),
            installation_scoped_credential_ref: valid_fingerprint.clone(),
            http_status: 200,
            latency_ms: 12,
        };
        match field {
            "event_id_fingerprint" => {
                evidence.event_id_fingerprint = invalid_fingerprint.into();
            }
            "homeserver_origin_fingerprint" => {
                evidence.homeserver_origin_fingerprint = invalid_fingerprint.into();
            }
            "room_fingerprint" => {
                evidence.room_fingerprint = invalid_fingerprint.into();
            }
            "installation_scoped_credential_ref" => {
                evidence.installation_scoped_credential_ref = invalid_fingerprint.into();
            }
            _ => unreachable!("covered by invalid_cases"),
        }

        assert_eq!(
            evidence.validate_redacted(),
            Err(MatrixOutboundContractError::UnsafeEvidence),
            "{field} must use sha256:<64 lowercase hex> fingerprint format"
        );
    }
}

#[test]
fn matrix_evidence_must_match_delivery_attempt_identity() {
    let command = command();
    let route = route();
    let attempt = attempt(&route, &command);
    let metadata = route.matrix_metadata().clone();

    let mut wrong_delivery = accepted_evidence(&command, &route, &attempt);
    wrong_delivery.delivery_id = OutboundDeliveryId::new();
    assert_eq!(
        wrong_delivery.validate_for_delivery(&command, &metadata, &attempt),
        Err(MatrixOutboundContractError::UnverifiedEvidence)
    );

    let mut wrong_attempt = accepted_evidence(&command, &route, &attempt);
    wrong_attempt.attempt_number += 1;
    assert_eq!(
        wrong_attempt.validate_for_delivery(&command, &metadata, &attempt),
        Err(MatrixOutboundContractError::UnverifiedEvidence)
    );
}

#[test]
fn matrix_outbound_contract_error_display_preserves_serde_cause() {
    let serde_error = serde_json::from_str::<StoredMatrixOutboundMetadataV1>("{")
        .expect_err("malformed json should produce serde error");
    let serde_cause = serde_error.to_string();
    let contract_error = MatrixOutboundContractError::from(serde_error);

    assert!(
        contract_error.to_string().contains(&serde_cause),
        "display must include serde cause {serde_cause:?}, got {contract_error}"
    );
}

#[tokio::test]
async fn durable_matrix_metadata_store_does_not_write_local_status_when_canonical_update_fails() {
    let backend = Arc::new(InMemoryBackend::new());
    let failing_outbound_store = Arc::new(FakeOutboundStateStore {
        statuses: Mutex::new(Vec::new()),
        fail_update_delivery_status: true,
    });
    let writer = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        failing_outbound_store,
    );
    let route = route();

    let error = writer
        .update_delivery_status(delivery_status_request(
            &route,
            OutboundDeliveryStatus::Delivered,
        ))
        .await
        .expect_err("canonical outbound status failure must be returned");

    assert!(matches!(error, MatrixOutboundContractError::Backend(_)));

    let reader = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(backend),
        outbound_state_store(),
    );
    let loaded_status = reader
        .load_delivery_status(route.scope().clone(), route.delivery_id)
        .await
        .expect("load status after failed canonical update");

    assert_eq!(
        loaded_status, None,
        "Matrix-local status must not be written when canonical status update fails"
    );
}

#[tokio::test]
async fn durable_matrix_metadata_store_reloads_delivered_evidence_and_terminal_status() {
    let backend = Arc::new(InMemoryBackend::new());
    let writer = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let command = command();
    let route = route();
    let attempt = attempt(&route, &command);
    let evidence = ValidatedMatrixDeliveryEvidence::new_for_delivery(
        accepted_evidence(&command, &route, &attempt),
        &command,
        route.matrix_metadata(),
        &attempt,
    )
    .expect("fixture evidence is valid for delivery");

    writer
        .persist_evidence(route.delivery_id, route.scope().clone(), evidence)
        .await
        .expect("persist evidence");
    writer
        .update_delivery_status(UpdateDeliveryStatusRequest {
            delivery_id: route.delivery_id,
            scope: route.scope().clone(),
            status: OutboundDeliveryStatus::Delivered,
            updated_at: Utc::now(),
            failure_kind: None,
        })
        .await
        .expect("persist delivered status");

    let reader = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(backend),
        outbound_state_store(),
    );
    let loaded_evidence = reader
        .load_evidence(route.scope().clone(), route.delivery_id)
        .await
        .expect("load evidence")
        .expect("evidence should persist across store instances");
    let loaded_status = reader
        .load_delivery_status(route.scope().clone(), route.delivery_id)
        .await
        .expect("load status")
        .expect("status should persist across store instances");

    assert_eq!(
        loaded_evidence.event_id_fingerprint,
        canonical_fingerprint("event-1")
    );
    assert_eq!(loaded_evidence.transaction_id, command.transaction_id);
    assert_eq!(loaded_status.status, OutboundDeliveryStatus::Delivered);
    assert_eq!(loaded_status.failure_kind, None);
}

#[tokio::test]
async fn durable_matrix_metadata_store_reloads_retry_schedule_without_terminal_status() {
    let backend = Arc::new(InMemoryBackend::new());
    let writer = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let route = route();
    let schedule = MatrixRetrySchedule {
        delivery_id: route.delivery_id,
        scope: route.scope().clone(),
        attempt_number: 2,
        retry_after: Duration::from_secs(30),
        reason: DeliveryReasonCode::MatrixRateLimited,
        recorded_at: Utc::now(),
    };

    writer
        .record_retry_scheduled(schedule.clone(), retry_context(&route))
        .await
        .expect("persist retry schedule");

    let reader = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(backend),
        outbound_state_store(),
    );
    let loaded_schedule = reader
        .load_retry_schedule(route.scope().clone(), route.delivery_id)
        .await
        .expect("load retry schedule")
        .expect("retry schedule should persist across store instances");
    let loaded_status = reader
        .load_delivery_status(route.scope().clone(), route.delivery_id)
        .await
        .expect("load absent status");

    assert_eq!(loaded_schedule.delivery_id, route.delivery_id);
    assert_eq!(loaded_schedule.scope, route.scope().clone());
    assert_eq!(loaded_schedule.attempt_number, 2);
    assert_eq!(loaded_schedule.retry_after, Duration::from_secs(30));
    assert_eq!(
        loaded_schedule.reason,
        DeliveryReasonCode::MatrixRateLimited
    );
    assert_eq!(loaded_status, None);
}

#[tokio::test]
async fn durable_matrix_pending_intent_store_reloads_pending_command_across_store_instances() {
    let backend = Arc::new(InMemoryBackend::new());
    let writer =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let attempt_id = route.delivery_id.as_uuid();

    writer
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            attempt_id,
            command.clone(),
        )
        .await
        .expect("persist pending Matrix command");

    let reader = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(backend));
    let loaded = reader
        .take_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect("take pending Matrix command")
        .expect("pending command should persist across store instances");

    assert_eq!(loaded, command);

    let loaded_again = reader
        .take_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect("take pending Matrix command again");

    assert_eq!(
        loaded_again, None,
        "taking a pending command should consume the durable record exactly once"
    );
}

#[tokio::test]
async fn durable_matrix_pending_intent_load_is_non_destructive_until_consumed() {
    let backend = Arc::new(InMemoryBackend::new());
    let writer =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let attempt_id = route.delivery_id.as_uuid();

    writer
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            attempt_id,
            command.clone(),
        )
        .await
        .expect("persist pending Matrix command");

    let first_reader =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let first_load = first_reader
        .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect("load pending Matrix command")
        .expect("pending command should load");

    assert_eq!(first_load, command);

    let fresh_reader = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(backend));
    let second_load = fresh_reader
        .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect("load pending Matrix command after prior load")
        .expect("load must not consume the durable pending command");

    assert_eq!(second_load, command);

    let consumed = fresh_reader
        .mark_pending_command_consumed(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect("mark pending Matrix command consumed");

    assert!(
        consumed,
        "consuming a present pending command should report a state change"
    );

    let after_consumed = fresh_reader
        .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect("load pending Matrix command after explicit consume");

    assert_eq!(
        after_consumed, None,
        "explicit consume should tombstone the pending command"
    );
}

#[tokio::test]
async fn production_bridge_recovers_pending_command_after_restart() {
    let backend = Arc::new(InMemoryBackend::new());
    let pending_writer =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let attempt_id = route.delivery_id.as_uuid();

    pending_writer
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            attempt_id,
            command.clone(),
        )
        .await
        .expect("persist pending Matrix command before adapter instance is dropped");

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let attempt_ctx = attempt(&route, &command);
    let port = FakeMatrixDeliveryPort::default();
    port.push_result(DeliveryPortResult::Accepted(
        ProtocolDeliveryEvidence::Matrix(accepted_evidence(&command, &route, &attempt_ctx)),
    ));
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let pending_reader =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let bridge = MatrixProductionDeliveryBridge::new(&pending_reader, &orchestrator);

    let outcome = bridge
        .recover_pending_command(route.clone(), grant, attempt_ctx)
        .await
        .expect("production bridge should recover and deliver the durable pending command");

    assert_eq!(outcome.status, MatrixTerminalStatus::Delivered);
    assert_eq!(port.calls(), vec![ProtocolDeliveryIntent::Matrix(command)]);

    let metadata_reader = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    assert!(
        metadata_reader
            .load_evidence(route.scope().clone(), route.delivery_id)
            .await
            .expect("load durable evidence after recovered delivery")
            .is_some(),
        "bridge must persist delivery evidence before tombstoning the pending command"
    );
    assert_eq!(
        metadata_reader
            .load_delivery_status(route.scope().clone(), route.delivery_id)
            .await
            .expect("load durable status after recovered delivery")
            .expect("status should be durable before pending consume")
            .status,
        OutboundDeliveryStatus::Delivered
    );
    assert_eq!(
        pending_reader
            .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
            .await
            .expect("load pending command after recovered delivery"),
        None,
        "bridge must tombstone the pending command only after durable evidence/status"
    );
}

#[tokio::test]
async fn production_bridge_preserves_pending_command_when_retry_is_scheduled() {
    let backend = Arc::new(InMemoryBackend::new());
    let pending_writer =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let attempt_id = route.delivery_id.as_uuid();

    pending_writer
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            attempt_id,
            command.clone(),
        )
        .await
        .expect("persist pending Matrix command before adapter instance is dropped");

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = FakeMatrixDeliveryPort::default();
    port.push_result(DeliveryPortResult::Rejected(DeliveryError::new(
        DeliveryReasonCode::MatrixTimeout,
    )));
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let pending_reader =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let bridge = MatrixProductionDeliveryBridge::new(&pending_reader, &orchestrator);

    let outcome = bridge
        .recover_pending_command(
            route.clone(),
            grant,
            DeliveryAttemptContext {
                delivery_id: route.delivery_id,
                attempt_number: 1,
                transaction_id: command.transaction_id.clone(),
                started_at: Utc::now(),
            },
        )
        .await
        .expect("retryable delivery should schedule retry");

    assert_eq!(outcome.status, MatrixTerminalStatus::RetryScheduled);
    assert_eq!(
        pending_reader
            .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
            .await
            .expect("load pending command after retry scheduling"),
        Some(command),
        "bridge must preserve the durable command while retry remains scheduled"
    );
    assert!(
        metadata_store
            .load_retry_schedule(route.scope().clone(), route.delivery_id)
            .await
            .expect("load retry schedule")
            .is_some()
    );
    assert!(
        metadata_store
            .load_retry_execution_context(route.scope().clone(), route.delivery_id)
            .await
            .expect("load retry execution context")
            .is_some(),
        "retryable production delivery must persist executable route/grant context"
    );
}

#[tokio::test]
async fn metadata_store_lists_due_unclaimed_retry_schedules_within_scope() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let now = Utc::now();
    let due_route = route();
    let second_due_route = route();
    let not_due_route = route();

    let due_schedule = MatrixRetrySchedule {
        recorded_at: now - chrono::Duration::seconds(60),
        retry_after: Duration::from_secs(30),
        ..retry_schedule(&due_route)
    };
    let second_due_schedule = MatrixRetrySchedule {
        recorded_at: now - chrono::Duration::seconds(45),
        retry_after: Duration::from_secs(30),
        ..retry_schedule(&second_due_route)
    };
    let not_due_schedule = MatrixRetrySchedule {
        recorded_at: now,
        retry_after: Duration::from_secs(30),
        ..retry_schedule(&not_due_route)
    };

    metadata_store
        .record_retry_scheduled(due_schedule.clone(), retry_context(&due_route))
        .await
        .expect("persist due retry schedule");
    metadata_store
        .record_retry_scheduled(
            second_due_schedule.clone(),
            retry_context(&second_due_route),
        )
        .await
        .expect("persist second due retry schedule");
    metadata_store
        .record_retry_scheduled(not_due_schedule, retry_context(&not_due_route))
        .await
        .expect("persist not-due retry schedule");

    let due = metadata_store
        .list_due_retry_schedules(scope(), now, 10)
        .await
        .expect("list due retry schedules");
    let due_ids: HashSet<_> = due.iter().map(|schedule| schedule.delivery_id).collect();

    assert_eq!(due.len(), 2);
    assert!(due_ids.contains(&due_route.delivery_id));
    assert!(due_ids.contains(&second_due_route.delivery_id));
    assert!(!due_ids.contains(&not_due_route.delivery_id));
    assert!(
        metadata_store
            .list_due_retry_schedules(scope(), now, 0)
            .await
            .expect("zero bound due retry list")
            .is_empty()
    );
}

#[tokio::test]
async fn metadata_store_returns_exact_max_due_retries_after_filtering() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let now = Utc::now();
    let routes = [route(), route(), route()];

    for route in &routes {
        metadata_store
            .record_retry_scheduled(
                MatrixRetrySchedule {
                    recorded_at: now - chrono::Duration::seconds(60),
                    retry_after: Duration::from_secs(30),
                    ..retry_schedule(route)
                },
                retry_context(route),
            )
            .await
            .expect("persist due retry schedule");
    }

    let due = metadata_store
        .list_due_retry_schedules(scope(), now, 2)
        .await
        .expect("list due retry schedules with max bound");

    assert_eq!(due.len(), 2);
}

#[tokio::test]
async fn metadata_store_due_retry_bound_applies_after_filtering_skipped_records() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let now = Utc::now();
    let not_due_route = route();
    let due_route = route();

    metadata_store
        .record_retry_scheduled(
            MatrixRetrySchedule {
                recorded_at: now,
                retry_after: Duration::from_secs(30),
                ..retry_schedule(&not_due_route)
            },
            retry_context(&not_due_route),
        )
        .await
        .expect("persist skipped not-due retry schedule");
    metadata_store
        .record_retry_scheduled(
            MatrixRetrySchedule {
                recorded_at: now - chrono::Duration::seconds(60),
                retry_after: Duration::from_secs(30),
                ..retry_schedule(&due_route)
            },
            retry_context(&due_route),
        )
        .await
        .expect("persist due retry schedule");

    let due = metadata_store
        .list_due_retry_schedules(scope(), now, 1)
        .await
        .expect("list due retry schedules");

    assert_eq!(due.len(), 1);
    assert_eq!(due[0].delivery_id, due_route.delivery_id);
}

#[tokio::test]
async fn metadata_store_lists_empty_due_retries_before_metadata_exists() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );

    let due = metadata_store
        .list_due_retry_schedules(scope(), Utc::now(), 10)
        .await
        .expect("empty retry queue should list successfully");

    assert!(due.is_empty());
}

#[tokio::test]
async fn metadata_store_lists_retry_after_claim_lease_expires() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let route = route();
    let now = Utc::now();
    let schedule = MatrixRetrySchedule {
        recorded_at: now - chrono::Duration::seconds(60),
        retry_after: Duration::from_secs(30),
        ..retry_schedule(&route)
    };

    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist retry schedule");
    metadata_store
        .claim_due_retry_schedule(
            route.scope().clone(),
            route.delivery_id,
            now,
            MATRIX_RETRY_CLAIM_LEASE,
        )
        .await
        .expect("claim retry schedule")
        .expect("retry should be claimed");

    let after_lease = now
        + chrono::Duration::from_std(MATRIX_RETRY_CLAIM_LEASE).expect("claim lease")
        + chrono::Duration::milliseconds(1);
    let due = metadata_store
        .list_due_retry_schedules(scope(), after_lease, 10)
        .await
        .expect("list due retries after lease expiry");

    assert_eq!(due.len(), 1);
    assert_eq!(due[0].delivery_id, route.delivery_id);
}

#[tokio::test]
async fn metadata_store_concurrent_due_retry_claims_allow_one_winner() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = Arc::new(FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    ));
    let route = route();
    let now = Utc::now();
    let schedule = MatrixRetrySchedule {
        recorded_at: now - chrono::Duration::seconds(60),
        retry_after: Duration::from_secs(30),
        ..retry_schedule(&route)
    };

    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist retry schedule");

    let first_store = Arc::clone(&metadata_store);
    let second_store = Arc::clone(&metadata_store);
    let first_scope = route.scope().clone();
    let second_scope = route.scope().clone();
    let delivery_id = route.delivery_id;
    let (first, second) = tokio::join!(
        async move {
            first_store
                .claim_due_retry_schedule(first_scope, delivery_id, now, MATRIX_RETRY_CLAIM_LEASE)
                .await
        },
        async move {
            second_store
                .claim_due_retry_schedule(second_scope, delivery_id, now, MATRIX_RETRY_CLAIM_LEASE)
                .await
        }
    );

    let claimed = [first.expect("first claim"), second.expect("second claim")]
        .into_iter()
        .filter(Option::is_some)
        .count();
    assert_eq!(claimed, 1);
}

#[tokio::test]
async fn metadata_store_excludes_claimed_and_terminal_retry_schedules_from_due_list() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let now = Utc::now();
    let claimed_route = route();
    let terminal_route = route();
    let claimed_schedule = MatrixRetrySchedule {
        recorded_at: now - chrono::Duration::seconds(60),
        retry_after: Duration::from_secs(30),
        ..retry_schedule(&claimed_route)
    };
    let terminal_schedule = MatrixRetrySchedule {
        recorded_at: now - chrono::Duration::seconds(60),
        retry_after: Duration::from_secs(30),
        ..retry_schedule(&terminal_route)
    };

    metadata_store
        .record_retry_scheduled(claimed_schedule.clone(), retry_context(&claimed_route))
        .await
        .expect("persist claimed retry schedule");
    metadata_store
        .record_retry_scheduled(terminal_schedule, retry_context(&terminal_route))
        .await
        .expect("persist terminal retry schedule");
    metadata_store
        .claim_due_retry_schedule(
            claimed_route.scope().clone(),
            claimed_route.delivery_id,
            now,
            Duration::from_secs(60),
        )
        .await
        .expect("claim due retry schedule")
        .expect("schedule should be claimed");
    metadata_store
        .update_delivery_status(delivery_status_request(
            &terminal_route,
            OutboundDeliveryStatus::Delivered,
        ))
        .await
        .expect("persist terminal delivery status");

    let due = metadata_store
        .list_due_retry_schedules(scope(), now, 10)
        .await
        .expect("list due retry schedules");

    assert!(due.is_empty());
}

#[tokio::test]
async fn metadata_store_rehydrates_retry_execution_context() {
    let backend = Arc::new(InMemoryBackend::new());
    let writer = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let reader = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let route = route();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);

    writer
        .persist_retry_execution_context(&owner, &route, &grant)
        .await
        .expect("persist retry execution context");
    writer
        .record_retry_scheduled(retry_schedule(&route), retry_context(&route))
        .await
        .expect("persist retry schedule");

    let context = reader
        .load_retry_execution_context(route.scope().clone(), route.delivery_id)
        .await
        .expect("load retry execution context")
        .expect("retry execution context should exist");
    let (rehydrated_route, rehydrated_grant) = context.into_parts();

    assert_eq!(rehydrated_route, route);
    assert_eq!(rehydrated_grant, grant);
}

#[tokio::test]
async fn metadata_store_does_not_rehydrate_retry_execution_context_without_schedule() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let route = route();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);

    metadata_store
        .persist_retry_execution_context(&owner, &route, &grant)
        .await
        .expect("persist retry execution context without retry schedule");

    assert!(
        metadata_store
            .load_retry_execution_context(route.scope().clone(), route.delivery_id)
            .await
            .expect("load retry execution context")
            .is_none()
    );
}

#[tokio::test]
async fn metadata_store_rejects_mismatched_retry_execution_context() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let route = route();
    let owner = owner();
    let forged_grant = route_forgery_fixture(&route, 9);

    let error = metadata_store
        .persist_retry_execution_context(&owner, &route, &forged_grant)
        .await
        .expect_err("mismatched route/grant context must fail");

    assert!(matches!(error, MatrixOutboundContractError::Backend(_)));
}

#[tokio::test]
async fn metadata_store_clears_retry_execution_context_on_all_terminal_statuses() {
    for status in [
        OutboundDeliveryStatus::Delivered,
        OutboundDeliveryStatus::Failed,
        OutboundDeliveryStatus::DeadLettered,
    ] {
        let backend = Arc::new(InMemoryBackend::new());
        let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
            matrix_metadata_filesystem(Arc::clone(&backend)),
            outbound_state_store(),
        );
        let route = route();
        let owner = owner();
        let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);

        metadata_store
            .persist_retry_execution_context(&owner, &route, &grant)
            .await
            .expect("persist retry execution context");
        metadata_store
            .record_retry_scheduled(retry_schedule(&route), retry_context(&route))
            .await
            .expect("persist retry schedule");
        metadata_store
            .update_delivery_status(delivery_status_request(&route, status))
            .await
            .expect("persist terminal delivery status");

        assert!(
            metadata_store
                .load_retry_execution_context(route.scope().clone(), route.delivery_id)
                .await
                .expect("load retry execution context after terminal status")
                .is_none(),
            "terminal status {status:?} must clear retry execution context"
        );
        assert!(
            metadata_store
                .load_retry_schedule(route.scope().clone(), route.delivery_id)
                .await
                .expect("load retry schedule after terminal status")
                .is_none(),
            "terminal status {status:?} must clear retry schedule"
        );
    }
}

#[tokio::test]
async fn production_bridge_refuses_terminal_delivery_without_port_call() {
    let backend = Arc::new(InMemoryBackend::new());
    let pending_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let attempt_id = route.delivery_id.as_uuid();

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            attempt_id,
            command.clone(),
        )
        .await
        .expect("persist durable pending Matrix command");

    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    metadata_store
        .update_delivery_status(delivery_status_request(
            &route,
            OutboundDeliveryStatus::Delivered,
        ))
        .await
        .expect("persist terminal status");

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = RecordingMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let bridge = MatrixProductionDeliveryBridge::new(&pending_store, &orchestrator);

    let error = bridge
        .recover_pending_command(route.clone(), grant, attempt(&route, &command))
        .await
        .expect_err("terminal delivery should not be retried through bridge");

    assert_eq!(error.reason, DeliveryReasonCode::MissingMatrixRoute);
    assert!(port.calls().is_empty());
    assert_eq!(
        pending_store
            .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
            .await
            .expect("load pending command after terminal bridge refusal"),
        None
    );
}

#[tokio::test]
async fn retry_executor_invokes_production_bridge_with_next_attempt_from_durable_schedule() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let pending_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let attempt_id = route.delivery_id.as_uuid();
    let mut schedule = retry_schedule(&route);
    schedule.attempt_number = 2;

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            attempt_id,
            command.clone(),
        )
        .await
        .expect("persist durable pending Matrix command");
    metadata_store
        .record_retry_scheduled(schedule.clone(), retry_context(&route))
        .await
        .expect("persist durable Matrix retry schedule");

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = RecordingMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let bridge = MatrixProductionDeliveryBridge::new(&pending_store, &orchestrator);
    let authorizer = AllowRetrySendAuthorizer;

    let outcome = MatrixRetryExecutor::execute_due_retry(
        &metadata_store,
        &pending_store,
        &bridge,
        &authorizer,
        route.clone(),
        grant,
        schedule.recorded_at
            + chrono::Duration::from_std(schedule.retry_after).expect("retry after"),
    )
    .await
    .expect("retry executor should execute durable retry through production bridge");

    let outcome = outcome.expect("due retry should execute");
    assert_eq!(outcome.status, MatrixTerminalStatus::Delivered);
    let calls = port.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, ProtocolDeliveryIntent::Matrix(command.clone()));
    assert_eq!(calls[0].1.delivery_id, route.delivery_id);
    assert_eq!(calls[0].1.transaction_id, command.transaction_id);
    assert_eq!(calls[0].1.attempt_number, schedule.attempt_number + 1);
    assert_eq!(
        calls[0].1.started_at,
        schedule.recorded_at
            + chrono::Duration::from_std(schedule.retry_after).expect("retry after")
    );
}

#[tokio::test]
async fn retry_executor_rehydrates_route_grant_context_before_execution() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let pending_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let schedule = retry_schedule(&route);
    let due_at =
        schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            route.delivery_id.as_uuid(),
            command.clone(),
        )
        .await
        .expect("persist durable pending Matrix command");
    metadata_store
        .record_retry_scheduled(schedule.clone(), retry_context(&route))
        .await
        .expect("persist retry schedule and execution context");

    let port = RecordingMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let bridge = MatrixProductionDeliveryBridge::new(&pending_store, &orchestrator);
    let authorizer = AllowRetrySendAuthorizer;

    let outcome = MatrixRetryExecutor::execute_due_retry_from_store(
        &metadata_store,
        &pending_store,
        &bridge,
        &authorizer,
        route.scope().clone(),
        route.delivery_id,
        due_at,
    )
    .await
    .expect("rehydrated retry should execute")
    .expect("due retry should produce outcome");

    assert_eq!(outcome.status, MatrixTerminalStatus::Delivered);
    let calls = port.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, ProtocolDeliveryIntent::Matrix(command));
}

#[tokio::test]
async fn matrix_retry_worker_tick_executes_due_rehydrated_retry() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = Arc::new(FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    ));
    let pending_store = Arc::new(FilesystemMatrixPendingIntentStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
    ));
    let route = route();
    let command = command();
    let schedule = retry_schedule(&route);
    let due_at =
        schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            route.delivery_id.as_uuid(),
            command.clone(),
        )
        .await
        .expect("persist pending command");
    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist retry schedule and context");

    let port = Arc::new(RecordingMatrixDeliveryPort::default());
    let work_port = retry_work_port(
        Arc::clone(&metadata_store),
        pending_store,
        Arc::clone(&port) as Arc<dyn MatrixDeliveryPort>,
        Arc::new(FakeMatrixCredentialResolver::with_credential(
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            },
        )),
        Arc::new(AllowRetrySendAuthorizer),
    );
    let deps = MatrixRetryWorkerDeps {
        work_port,
        scopes: vec![route.scope().clone()],
    };
    let settings = MatrixRetryWorkerSettings {
        enabled: true,
        max_entries_per_scope: 10,
        ..MatrixRetryWorkerSettings::default()
    };

    let report = matrix_retry_worker_tick_once(&settings, &deps, due_at, &CancellationToken::new())
        .await
        .expect("worker tick succeeds");

    assert_eq!(report.scopes_scanned, 1);
    assert_eq!(report.due_schedules, 1);
    assert_eq!(report.attempted, 1);
    assert_eq!(report.delivered, 1);
    assert_eq!(report.failed, 0);
    let calls = port.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, ProtocolDeliveryIntent::Matrix(command));
}

#[tokio::test]
async fn matrix_retry_production_dependency_bundle_uses_real_delivery_port_stores_and_config() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_filesystem = matrix_metadata_filesystem(Arc::clone(&backend));
    let pending_filesystem = matrix_metadata_filesystem(Arc::clone(&backend));
    let outbound_state = outbound_state_store();
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        Arc::clone(&metadata_filesystem),
        Arc::clone(&outbound_state),
    );
    let pending_store = FilesystemMatrixPendingIntentStore::new(Arc::clone(&pending_filesystem));
    let host_egress = Arc::new(RecordingMatrixHostEgress::ok(
        200,
        Vec::new(),
        json!({"event_id":"$event:matrix.example"}),
    ));
    let endpoint_resolver = Arc::new(StaticMatrixHttpEndpointResolver {
        endpoint: Some(matrix_endpoint("https://matrix.example")),
    });
    let settings = MatrixRetryWorkerSettings {
        enabled: true,
        poll_interval: Duration::from_millis(50),
        startup_jitter_max: Duration::ZERO,
        tick_jitter_max: Duration::ZERO,
        max_entries_per_scope: 10,
    };
    let route = route_for_homeserver_origin("https://matrix.example");
    let command = command();
    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            route.delivery_id.as_uuid(),
            command,
        )
        .await
        .expect("persist pending command");
    let mut schedule = retry_schedule(&route);
    schedule.recorded_at = Utc::now() - chrono::Duration::seconds(60);
    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist retry schedule");

    let bundle =
        MatrixRetryProductionDependencyBundle::new(MatrixRetryProductionDependencyBundleInput {
            settings: settings.clone(),
            metadata_filesystem,
            pending_filesystem,
            outbound_state_store: outbound_state,
            host_egress: host_egress.clone(),
            endpoint_resolver,
            credential_material_provider: matrix_credential_material_provider(),
            retry_policy: Arc::new(retry_policy()),
            retry_send_authorizer: Arc::new(AllowRetrySendAuthorizer),
        })
        .expect("production Matrix retry dependencies should compose");

    assert_eq!(bundle.settings(), &settings);
    let report = matrix_retry_worker_tick_once(
        bundle.settings(),
        &bundle.worker_deps(vec![route.scope().clone()]),
        Utc::now(),
        &CancellationToken::new(),
    )
    .await
    .expect("retry tick uses production bundle");
    assert_eq!(report.delivered, 1);
    let requests = host_egress.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].request.method, NetworkMethod::Put);
    assert!(
        requests[0]
            .request
            .url
            .contains("/_matrix/client/v3/rooms/")
    );
    assert_eq!(requests[0].credential_count, 1);
}

fn source_backed_retry_route() -> FrozenProductDeliveryRoute {
    let mut route = route_for_homeserver_origin("https://matrix.example.org");
    route.adapter_id = "matrix".into();
    route.installation_id = "inst_matrix".into();
    route.metadata.policy_revision = "7".into();
    route.metadata.credential_handle_fingerprint = canonical_fingerprint("credential-handle-1");
    route
}

fn source_backed_retry_policy_snapshot(
    route: &FrozenProductDeliveryRoute,
) -> AdapterMatrixPolicySnapshot {
    let command = command();
    AdapterMatrixPolicySnapshot {
        adapter_id: ProductAdapterId::new(route.adapter_id.clone()).expect("adapter id"),
        installation_id: AdapterInstallationId::new(route.installation_id.clone())
            .expect("installation id"),
        homeserver: AdapterMatrixHomeserverOrigin::parse("https://matrix.example.org")
            .expect("homeserver"),
        allowed_rooms: std::collections::BTreeSet::from([AdapterMatrixRoomId::new(
            command.room_id.as_str(),
        )
        .expect("room")]),
        allowed_senders: std::collections::BTreeSet::from([AdapterMatrixUserId::new(
            "@alice:example.org",
        )
        .expect("sender")]),
        egress_target_index: AdapterEgressTargetIndex::new(route.metadata.egress_target_index),
        credential_handle: ironclaw_product_adapters::EgressCredentialHandle::new(
            "credential-handle-1",
        )
        .expect("credential handle"),
        policy_revision: AdapterPolicyRevision::new(
            route
                .metadata
                .policy_revision
                .parse()
                .expect("numeric retry policy revision"),
        )
        .expect("policy revision"),
    }
}

#[tokio::test]
async fn matrix_retry_filesystem_reauthorization_reads_provider_tenant_shared_policy_scope() {
    let backend = Arc::new(InMemoryBackend::new());
    let filesystem = tenant_scoped_matrix_metadata_filesystem(Arc::clone(&backend));
    let metadata_store = Arc::new(FilesystemMatrixOutboundMetadataStore::new(
        Arc::clone(&filesystem),
        outbound_state_store(),
    ));
    let pending_store = Arc::new(FilesystemMatrixPendingIntentStore::new(Arc::clone(
        &filesystem,
    )));
    let provider_scope = MatrixPolicyProviderScope {
        tenant_id: TenantId::new("matrix-retry-provider-tenant").expect("provider tenant"),
        agent_id: AgentId::new("matrix-retry-provider-agent").expect("provider agent"),
        project_id: Some(
            ProjectId::new("matrix-retry-provider-project").expect("provider project"),
        ),
    };
    let lifecycle_scope = TurnScope::new_with_owner(
        TenantId::new("matrix-retry-lifecycle-tenant").expect("lifecycle tenant"),
        Some(provider_scope.agent_id.clone()),
        provider_scope.project_id.clone(),
        ThreadId::new("matrix-retry-lifecycle-thread").expect("lifecycle thread"),
        Some(UserId::new("matrix-retry-lifecycle-user").expect("lifecycle user")),
    )
    .to_resource_scope();
    let mut route = source_backed_retry_route();
    route.metadata.policy_provider_scope = Some(provider_scope.clone());
    let command = command();
    let mut cache = MatrixInstallationProjectionCache::new();
    cache
        .insert_projection(
            matrix_projection_installation(&source_backed_retry_policy_snapshot(&route)),
            "matrix-retry-policy-owner",
            1_710_000_000_002,
        )
        .expect("policy projection");
    let cache_scope = matrix_policy_projection_resource_scope_for_provider_scope(
        &lifecycle_scope,
        &provider_scope,
    );
    let cache_path = matrix_policy_projection_cache_path_for_route_scope(
        &provider_scope.tenant_id,
        Some(&provider_scope.agent_id),
        provider_scope.project_id.as_ref(),
        &AdapterInstallationId::new(route.installation_id.clone()).expect("installation id"),
    )
    .expect("policy cache path");
    let cache_bytes = cache.to_json_bytes().expect("policy cache json");
    filesystem
        .put(
            &cache_scope,
            &cache_path,
            Entry::bytes(cache_bytes.clone()).with_content_type(ContentType::json()),
            CasExpectation::Any,
        )
        .await
        .expect("write provider-scoped policy cache");
    filesystem
        .put(
            &cache_scope,
            &matrix_policy_projection_commit_marker_path_for_cache_path(&cache_path)
                .expect("policy cache commit marker path"),
            matrix_policy_projection_commit_marker_entry(&cache_bytes),
            CasExpectation::Any,
        )
        .await
        .expect("write provider-scoped policy cache commit marker");
    assert!(
        filesystem
            .get(&route.scope().to_resource_scope(), &cache_path)
            .await
            .expect("route-scoped policy cache lookup")
            .is_none(),
        "fixture must not seed the route/request tenant policy scope"
    );
    let schedule = retry_schedule(&route);
    let due_at =
        schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");
    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            route.delivery_id.as_uuid(),
            command,
        )
        .await
        .expect("persist pending command");
    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist retry schedule and context");

    let port = Arc::new(RecordingMatrixDeliveryPort::default());
    let work_port = retry_work_port(
        Arc::clone(&metadata_store),
        pending_store,
        Arc::clone(&port) as Arc<dyn MatrixDeliveryPort>,
        Arc::new(FakeMatrixCredentialResolver::with_credential(
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            },
        )),
        Arc::new(MatrixFilesystemRetrySendAuthorizer::new(filesystem)),
    );

    work_port
        .execute_due_retry(route.scope().clone(), route.delivery_id, due_at)
        .await
        .expect("retry reads provider-scoped policy cache");

    assert_eq!(port.calls().len(), 1);
}

struct SourceBackedRetryReauthorizationFixture {
    route: FrozenProductDeliveryRoute,
    command: MatrixOutboundCommand,
    source: Arc<RetryMatrixPolicySnapshotSource>,
}

impl SourceBackedRetryReauthorizationFixture {
    fn new(
        route: FrozenProductDeliveryRoute,
        source: Arc<RetryMatrixPolicySnapshotSource>,
    ) -> Self {
        Self::with_command(route, command(), source)
    }

    fn with_command(
        route: FrozenProductDeliveryRoute,
        command: MatrixOutboundCommand,
        source: Arc<RetryMatrixPolicySnapshotSource>,
    ) -> Self {
        Self {
            route,
            command,
            source,
        }
    }

    async fn reject_before_delivery(self, expected_reason: DeliveryReasonCode) {
        let backend = Arc::new(InMemoryBackend::new());
        let metadata_store = Arc::new(FilesystemMatrixOutboundMetadataStore::new(
            matrix_metadata_filesystem(Arc::clone(&backend)),
            outbound_state_store(),
        ));
        let pending_store = Arc::new(FilesystemMatrixPendingIntentStore::new(
            matrix_metadata_filesystem(Arc::clone(&backend)),
        ));
        let schedule = retry_schedule(&self.route);
        let due_at =
            schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");

        pending_store
            .persist_pending_command(
                self.route.scope().clone(),
                self.route.delivery_id,
                self.route.delivery_id.as_uuid(),
                self.command,
            )
            .await
            .expect("persist durable pending Matrix command");
        metadata_store
            .record_retry_scheduled(schedule, retry_context(&self.route))
            .await
            .expect("persist retry schedule and context");

        let port = Arc::new(RecordingMatrixDeliveryPort::default());
        let snapshot_source: Arc<dyn MatrixPolicySnapshotSource> = self.source.clone();
        let work_port = retry_work_port(
            Arc::clone(&metadata_store),
            pending_store,
            Arc::clone(&port) as Arc<dyn MatrixDeliveryPort>,
            Arc::new(FakeMatrixCredentialResolver::with_credential(
                ResolvedCredentialHandle {
                    credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
                },
            )),
            Arc::new(MatrixSnapshotRetrySendAuthorizer::new(snapshot_source)),
        );

        let error = work_port
            .execute_due_retry(self.route.scope().clone(), self.route.delivery_id, due_at)
            .await
            .expect_err("source-backed retry reauthorization must reject before delivery");

        assert_eq!(error.reason, expected_reason);
        assert_eq!(
            self.source.calls(),
            vec![(
                ProductAdapterId::new(self.route.adapter_id.clone()).expect("adapter id"),
                AdapterInstallationId::new(self.route.installation_id.clone())
                    .expect("installation id")
            )],
            "retry authorizer must re-read the current Matrix policy projection"
        );
        assert!(
            port.calls().is_empty(),
            "retry reauthorization must reject before MatrixDeliveryPort or HTTP delivery"
        );
    }
}

async fn assert_source_backed_retry_reauthorization_rejects_before_delivery(
    route: FrozenProductDeliveryRoute,
    source: Arc<RetryMatrixPolicySnapshotSource>,
    expected_reason: DeliveryReasonCode,
) {
    SourceBackedRetryReauthorizationFixture::new(route, source)
        .reject_before_delivery(expected_reason)
        .await;
}

async fn assert_source_backed_retry_reauthorization_rejects_before_delivery_with_command(
    route: FrozenProductDeliveryRoute,
    command: MatrixOutboundCommand,
    source: Arc<RetryMatrixPolicySnapshotSource>,
    expected_reason: DeliveryReasonCode,
) {
    SourceBackedRetryReauthorizationFixture::with_command(route, command, source)
        .reject_before_delivery(expected_reason)
        .await;
}

#[tokio::test]
async fn matrix_retry_worker_revalidates_source_policy_revision_before_retry_send() {
    let route = source_backed_retry_route();
    let mut snapshot = source_backed_retry_policy_snapshot(&route);
    snapshot.policy_revision = AdapterPolicyRevision::new(8).expect("newer policy revision");

    assert_source_backed_retry_reauthorization_rejects_before_delivery(
        route,
        Arc::new(RetryMatrixPolicySnapshotSource::returning(snapshot)),
        DeliveryReasonCode::StalePolicyRevision,
    )
    .await;
}

#[tokio::test]
async fn matrix_retry_worker_revalidates_source_installation_active_before_retry_send() {
    let route = source_backed_retry_route();

    assert_source_backed_retry_reauthorization_rejects_before_delivery(
        route,
        Arc::new(RetryMatrixPolicySnapshotSource::rejecting(
            AdapterMatrixInstallationPolicyRejection::InstallationDisabled,
        )),
        DeliveryReasonCode::InstallationInactive,
    )
    .await;
}

#[tokio::test]
async fn matrix_retry_worker_revalidates_source_installation_not_deleting_before_retry_send() {
    let route = source_backed_retry_route();

    assert_source_backed_retry_reauthorization_rejects_before_delivery(
        route,
        Arc::new(RetryMatrixPolicySnapshotSource::rejecting(
            AdapterMatrixInstallationPolicyRejection::InstallationDeleting,
        )),
        DeliveryReasonCode::InstallationInactive,
    )
    .await;
}

#[tokio::test]
async fn matrix_retry_worker_revalidates_source_installation_exists_before_retry_send() {
    let route = source_backed_retry_route();

    assert_source_backed_retry_reauthorization_rejects_before_delivery(
        route,
        Arc::new(RetryMatrixPolicySnapshotSource::rejecting(
            AdapterMatrixInstallationPolicyRejection::InstallationNotFound,
        )),
        DeliveryReasonCode::InstallationInactive,
    )
    .await;
}

#[tokio::test]
async fn matrix_retry_worker_revalidates_source_credential_before_retry_send() {
    let route = source_backed_retry_route();
    let mut snapshot = source_backed_retry_policy_snapshot(&route);
    snapshot.credential_handle =
        ironclaw_product_adapters::EgressCredentialHandle::new("rotated-credential-handle")
            .expect("credential handle");

    assert_source_backed_retry_reauthorization_rejects_before_delivery(
        route,
        Arc::new(RetryMatrixPolicySnapshotSource::returning(snapshot)),
        DeliveryReasonCode::CredentialMismatch,
    )
    .await;
}

#[tokio::test]
async fn matrix_retry_worker_revalidates_source_credential_not_revoked_before_retry_send() {
    let route = source_backed_retry_route();

    assert_source_backed_retry_reauthorization_rejects_before_delivery(
        route,
        Arc::new(RetryMatrixPolicySnapshotSource::rejecting(
            AdapterMatrixInstallationPolicyRejection::CredentialHandleRevoked,
        )),
        DeliveryReasonCode::CredentialMismatch,
    )
    .await;
}

#[tokio::test]
async fn matrix_retry_worker_revalidates_source_egress_target_before_retry_send() {
    let route = source_backed_retry_route();
    let mut snapshot = source_backed_retry_policy_snapshot(&route);
    snapshot.egress_target_index = AdapterEgressTargetIndex::new(1);

    assert_source_backed_retry_reauthorization_rejects_before_delivery(
        route,
        Arc::new(RetryMatrixPolicySnapshotSource::returning(snapshot)),
        DeliveryReasonCode::EgressTargetDenied,
    )
    .await;
}

#[tokio::test]
async fn matrix_retry_worker_revalidates_source_room_allowed_before_retry_send() {
    let route = source_backed_retry_route();
    let mut snapshot = source_backed_retry_policy_snapshot(&route);
    snapshot.allowed_rooms = std::collections::BTreeSet::from([AdapterMatrixRoomId::new(
        "!different-room:matrix.example.org",
    )
    .expect("different room")]);

    assert_source_backed_retry_reauthorization_rejects_before_delivery(
        route,
        Arc::new(RetryMatrixPolicySnapshotSource::returning(snapshot)),
        DeliveryReasonCode::RoomNotAllowed,
    )
    .await;
}

#[tokio::test]
async fn matrix_retry_worker_revalidates_raw_transaction_policy_path_before_retry_send() {
    let route = source_backed_retry_route();
    let snapshot = source_backed_retry_policy_snapshot(&route);

    assert_source_backed_retry_reauthorization_rejects_before_delivery_with_command(
        route,
        command_with_transaction_id("txn%2Fmatrix-1"),
        Arc::new(RetryMatrixPolicySnapshotSource::returning(snapshot)),
        DeliveryReasonCode::UnauthorizedTarget,
    )
    .await;
}

#[tokio::test]
async fn matrix_retry_worker_revalidates_current_credential_before_retry_send() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = Arc::new(FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    ));
    let pending_store = Arc::new(FilesystemMatrixPendingIntentStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
    ));
    let route = route();
    let command = command();
    let schedule = retry_schedule(&route);
    let due_at =
        schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            route.delivery_id.as_uuid(),
            command,
        )
        .await
        .expect("persist pending command");
    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist retry schedule and context");

    let port = Arc::new(RecordingMatrixDeliveryPort::default());
    let work_port = retry_work_port(
        Arc::clone(&metadata_store),
        pending_store,
        Arc::clone(&port) as Arc<dyn MatrixDeliveryPort>,
        Arc::new(FakeMatrixCredentialResolver::with_credential(
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("revoked-credential"),
            },
        )),
        Arc::new(AllowRetrySendAuthorizer),
    );
    let deps = MatrixRetryWorkerDeps {
        work_port,
        scopes: vec![route.scope().clone()],
    };
    let settings = MatrixRetryWorkerSettings {
        enabled: true,
        max_entries_per_scope: 10,
        ..MatrixRetryWorkerSettings::default()
    };

    let report = matrix_retry_worker_tick_once(&settings, &deps, due_at, &CancellationToken::new())
        .await
        .expect("worker tick succeeds");

    assert_eq!(report.due_schedules, 1);
    assert_eq!(report.attempted, 1);
    assert_eq!(report.delivered, 0);
    assert_eq!(report.failed, 1);
    assert!(port.calls().is_empty());
    let status = metadata_store
        .load_delivery_status(route.scope().clone(), route.delivery_id)
        .await
        .expect("load terminal status")
        .expect("status recorded");
    assert_eq!(status.status, OutboundDeliveryStatus::Failed);
    assert_eq!(
        status.failure_kind,
        Some(DeliveryFailureKind::AuthorizationRevoked)
    );
}

#[tokio::test]
async fn matrix_retry_worker_revalidates_live_send_policy_before_retry_send() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = Arc::new(FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    ));
    let pending_store = Arc::new(FilesystemMatrixPendingIntentStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
    ));
    let route = route();
    let command = command();
    let schedule = retry_schedule(&route);
    let due_at =
        schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            route.delivery_id.as_uuid(),
            command,
        )
        .await
        .expect("persist pending command");
    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist retry schedule and context");

    let port = Arc::new(RecordingMatrixDeliveryPort::default());
    let work_port = retry_work_port(
        Arc::clone(&metadata_store),
        pending_store,
        Arc::clone(&port) as Arc<dyn MatrixDeliveryPort>,
        Arc::new(FakeMatrixCredentialResolver::with_credential(
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            },
        )),
        Arc::new(RejectRetrySendAuthorizer {
            reason: DeliveryReasonCode::UnauthorizedTarget,
        }),
    );
    let deps = MatrixRetryWorkerDeps {
        work_port,
        scopes: vec![route.scope().clone()],
    };
    let settings = MatrixRetryWorkerSettings {
        enabled: true,
        max_entries_per_scope: 10,
        ..MatrixRetryWorkerSettings::default()
    };

    let report = matrix_retry_worker_tick_once(&settings, &deps, due_at, &CancellationToken::new())
        .await
        .expect("worker tick succeeds");

    assert_eq!(report.due_schedules, 1);
    assert_eq!(report.attempted, 1);
    assert_eq!(report.delivered, 0);
    assert_eq!(report.failed, 1);
    assert!(port.calls().is_empty());
    let status = metadata_store
        .load_delivery_status(route.scope().clone(), route.delivery_id)
        .await
        .expect("load terminal status")
        .expect("status recorded");
    assert_eq!(status.status, OutboundDeliveryStatus::Failed);
    assert_eq!(
        status.failure_kind,
        Some(DeliveryFailureKind::AuthorizationRevoked)
    );
}

#[tokio::test]
async fn matrix_retry_worker_settings_reject_invalid_values() {
    let deps = MatrixRetryWorkerDeps {
        work_port: Arc::new(EmptyRetryWorkPort),
        scopes: vec![scope()],
    };
    let invalid_poll_interval = MatrixRetryWorkerSettings {
        enabled: true,
        poll_interval: Duration::ZERO,
        ..MatrixRetryWorkerSettings::default()
    };
    assert!(spawn_matrix_retry_worker(invalid_poll_interval, deps.clone()).is_err());

    let invalid_max_entries = MatrixRetryWorkerSettings {
        enabled: true,
        max_entries_per_scope: 0,
        ..MatrixRetryWorkerSettings::default()
    };
    assert!(spawn_matrix_retry_worker(invalid_max_entries, deps.clone()).is_err());

    let empty_scopes = MatrixRetryWorkerDeps {
        work_port: Arc::new(EmptyRetryWorkPort),
        scopes: Vec::new(),
    };
    assert!(
        spawn_matrix_retry_worker(
            MatrixRetryWorkerSettings {
                enabled: true,
                ..MatrixRetryWorkerSettings::default()
            },
            empty_scopes,
        )
        .is_err()
    );
}

#[tokio::test]
async fn matrix_retry_worker_stops_after_cancellation_during_tick() {
    let route = route();
    let schedule = retry_schedule(&route);
    let due_at =
        schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");
    let cancel = CancellationToken::new();
    let deps = MatrixRetryWorkerDeps {
        work_port: Arc::new(CancellingRetryWorkPort {
            cancel: cancel.clone(),
            schedule,
        }),
        scopes: vec![route.scope().clone()],
    };
    let settings = MatrixRetryWorkerSettings {
        enabled: true,
        max_entries_per_scope: 10,
        ..MatrixRetryWorkerSettings::default()
    };

    let report = matrix_retry_worker_tick_once(&settings, &deps, due_at, &cancel)
        .await
        .expect("cancelled tick exits cleanly");

    assert_eq!(report.scopes_scanned, 1);
    assert_eq!(report.due_schedules, 1);
    assert_eq!(report.attempted, 0);
    assert_eq!(report.delivered, 0);
    assert_eq!(report.failed, 0);
}

#[tokio::test]
async fn matrix_retry_worker_shutdown_aborts_after_timeout() {
    let cancel = CancellationToken::new();
    let handle = tokio::spawn(async { std::future::pending::<()>().await });
    let worker = MatrixRetryWorkerRuntimeHandle { cancel, handle };

    worker.shutdown(Duration::from_millis(1)).await;
}

#[tokio::test]
async fn matrix_retry_worker_spawn_disabled_and_shutdown_paths_are_explicit() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = Arc::new(FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    ));
    let pending_store = Arc::new(FilesystemMatrixPendingIntentStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
    ));
    let work_port = retry_work_port(
        metadata_store,
        pending_store,
        Arc::new(RecordingMatrixDeliveryPort::default()),
        Arc::new(FakeMatrixCredentialResolver::with_credential(
            ResolvedCredentialHandle {
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
            },
        )),
        Arc::new(AllowRetrySendAuthorizer),
    );
    let deps = MatrixRetryWorkerDeps {
        work_port,
        scopes: vec![scope()],
    };

    let disabled = spawn_matrix_retry_worker(MatrixRetryWorkerSettings::default(), deps.clone())
        .expect("disabled worker is valid");
    assert!(disabled.is_none());

    let enabled = spawn_matrix_retry_worker(
        MatrixRetryWorkerSettings {
            enabled: true,
            poll_interval: Duration::from_secs(3600),
            startup_jitter_max: Duration::from_secs(3600),
            tick_jitter_max: Duration::ZERO,
            max_entries_per_scope: 10,
        },
        deps,
    )
    .expect("enabled worker starts")
    .expect("runtime handle returned");

    enabled.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn retry_executor_skips_retry_before_persisted_schedule_is_due() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let pending_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let attempt_id = route.delivery_id.as_uuid();
    let schedule = MatrixRetrySchedule {
        retry_after: Duration::from_secs(30),
        recorded_at: Utc::now(),
        ..retry_schedule(&route)
    };

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            attempt_id,
            command,
        )
        .await
        .expect("persist durable pending Matrix command");
    metadata_store
        .record_retry_scheduled(schedule.clone(), retry_context(&route))
        .await
        .expect("persist durable Matrix retry schedule");

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = RecordingMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let bridge = MatrixProductionDeliveryBridge::new(&pending_store, &orchestrator);
    let authorizer = AllowRetrySendAuthorizer;

    let outcome = MatrixRetryExecutor::execute_due_retry(
        &metadata_store,
        &pending_store,
        &bridge,
        &authorizer,
        route,
        grant,
        schedule.recorded_at,
    )
    .await
    .expect("not-yet-due retry should not error");

    assert_eq!(outcome, None);
    assert!(port.calls().is_empty());
}

#[tokio::test]
async fn retry_executor_skips_due_retry_when_schedule_is_already_claimed() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let pending_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let schedule = retry_schedule(&route);
    let due_at =
        schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            route.delivery_id.as_uuid(),
            command,
        )
        .await
        .expect("persist durable pending Matrix command");
    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist retry schedule");
    let claimed = metadata_store
        .claim_due_retry_schedule(
            route.scope().clone(),
            route.delivery_id,
            due_at,
            MATRIX_RETRY_CLAIM_LEASE,
        )
        .await
        .expect("claim retry schedule");
    assert!(claimed.is_some());

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = RecordingMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let bridge = MatrixProductionDeliveryBridge::new(&pending_store, &orchestrator);
    let authorizer = AllowRetrySendAuthorizer;

    let outcome = MatrixRetryExecutor::execute_due_retry(
        &metadata_store,
        &pending_store,
        &bridge,
        &authorizer,
        route,
        grant,
        due_at,
    )
    .await
    .expect("already-claimed retry should be skipped");

    assert_eq!(outcome, None);
    assert!(port.calls().is_empty());
}

#[tokio::test]
async fn retry_executor_reclaims_due_retry_after_claim_lease_expires() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let pending_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let schedule = retry_schedule(&route);
    let due_at =
        schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");
    let after_lease = due_at
        + chrono::Duration::from_std(MATRIX_RETRY_CLAIM_LEASE).expect("claim lease")
        + chrono::Duration::milliseconds(1);

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            route.delivery_id.as_uuid(),
            command.clone(),
        )
        .await
        .expect("persist durable pending Matrix command");
    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist retry schedule");
    metadata_store
        .claim_due_retry_schedule(
            route.scope().clone(),
            route.delivery_id,
            due_at,
            MATRIX_RETRY_CLAIM_LEASE,
        )
        .await
        .expect("claim retry schedule")
        .expect("due retry should be claimed");

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = RecordingMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let bridge = MatrixProductionDeliveryBridge::new(&pending_store, &orchestrator);
    let authorizer = AllowRetrySendAuthorizer;

    let outcome = MatrixRetryExecutor::execute_due_retry(
        &metadata_store,
        &pending_store,
        &bridge,
        &authorizer,
        route.clone(),
        grant,
        after_lease,
    )
    .await
    .expect("expired retry claim should be reclaimable")
    .expect("expired claim should execute");

    assert_eq!(outcome.status, MatrixTerminalStatus::Delivered);
    let calls = port.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, ProtocolDeliveryIntent::Matrix(command));
}

#[tokio::test]
async fn retry_executor_skips_stale_schedule_after_terminal_status_without_port_call() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let pending_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let schedule = retry_schedule(&route);
    let due_at =
        schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            route.delivery_id.as_uuid(),
            command,
        )
        .await
        .expect("persist durable pending Matrix command");
    metadata_store
        .update_delivery_status(delivery_status_request(
            &route,
            OutboundDeliveryStatus::Delivered,
        ))
        .await
        .expect("persist terminal status");
    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist stale retry schedule after terminal status");

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = RecordingMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let bridge = MatrixProductionDeliveryBridge::new(&pending_store, &orchestrator);
    let authorizer = AllowRetrySendAuthorizer;

    let outcome = MatrixRetryExecutor::execute_due_retry(
        &metadata_store,
        &pending_store,
        &bridge,
        &authorizer,
        route.clone(),
        grant,
        due_at,
    )
    .await
    .expect("stale terminal retry schedule should be skipped");

    assert_eq!(outcome, None);
    assert!(port.calls().is_empty());
    assert_eq!(
        metadata_store
            .load_retry_schedule(route.scope().clone(), route.delivery_id)
            .await
            .expect("load retry schedule after stale terminal skip"),
        None
    );
}

#[tokio::test]
async fn retry_executor_terminalizes_exhausted_schedule_without_port_call() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let pending_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let mut schedule = retry_schedule(&route);
    schedule.attempt_number = retry_policy().max_attempts;
    let due_at =
        schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            route.delivery_id.as_uuid(),
            command,
        )
        .await
        .expect("persist durable pending Matrix command");
    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist exhausted retry schedule");

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = RecordingMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let bridge = MatrixProductionDeliveryBridge::new(&pending_store, &orchestrator);
    let authorizer = AllowRetrySendAuthorizer;

    let error = MatrixRetryExecutor::execute_due_retry(
        &metadata_store,
        &pending_store,
        &bridge,
        &authorizer,
        route.clone(),
        grant,
        due_at,
    )
    .await
    .expect_err("exhausted retry should terminalize without delivery");

    assert_eq!(error.reason, DeliveryReasonCode::MaxAttemptsExceeded);
    assert!(port.calls().is_empty());
    assert_eq!(
        metadata_store
            .load_delivery_status(route.scope().clone(), route.delivery_id)
            .await
            .expect("load terminalized status")
            .expect("status should be durable")
            .status,
        OutboundDeliveryStatus::Failed
    );
    assert_eq!(
        pending_store
            .load_pending_command(
                route.scope().clone(),
                route.delivery_id,
                route.delivery_id.as_uuid(),
            )
            .await
            .expect("load pending command after exhausted terminalization"),
        None
    );
}

#[tokio::test]
async fn retry_executor_errors_when_due_schedule_has_no_pending_command() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let pending_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let schedule = retry_schedule(&route);
    let due_at =
        schedule.recorded_at + chrono::Duration::from_std(schedule.retry_after).expect("due");

    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist retry schedule without pending command");

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = RecordingMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let bridge = MatrixProductionDeliveryBridge::new(&pending_store, &orchestrator);
    let authorizer = AllowRetrySendAuthorizer;

    let error = MatrixRetryExecutor::execute_due_retry(
        &metadata_store,
        &pending_store,
        &bridge,
        &authorizer,
        route,
        grant,
        due_at,
    )
    .await
    .expect_err("missing durable command should fail closed");

    assert_eq!(error.reason, DeliveryReasonCode::MissingMatrixRoute);
    assert!(port.calls().is_empty());
}

#[tokio::test]
async fn retry_executor_rejects_retry_duration_overflow_before_port_call() {
    let backend = Arc::new(InMemoryBackend::new());
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let pending_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let schedule = MatrixRetrySchedule {
        retry_after: Duration::MAX,
        ..retry_schedule(&route)
    };

    pending_store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            route.delivery_id.as_uuid(),
            command,
        )
        .await
        .expect("persist durable pending Matrix command");
    metadata_store
        .record_retry_scheduled(schedule, retry_context(&route))
        .await
        .expect("persist overflowing retry schedule");

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = RecordingMatrixDeliveryPort::default();
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let bridge = MatrixProductionDeliveryBridge::new(&pending_store, &orchestrator);
    let authorizer = AllowRetrySendAuthorizer;

    let error = MatrixRetryExecutor::execute_due_retry(
        &metadata_store,
        &pending_store,
        &bridge,
        &authorizer,
        route,
        grant,
        Utc::now(),
    )
    .await
    .expect_err("overflowing retry duration should fail before delivery");

    assert_eq!(error.reason, DeliveryReasonCode::MatrixMalformedResponse);
    assert!(port.calls().is_empty());
}

#[tokio::test]
async fn production_bridge_tombstones_pending_command_after_terminal_failure() {
    let backend = Arc::new(InMemoryBackend::new());
    let pending_writer =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let route = route();
    let command = command();
    let attempt_id = route.delivery_id.as_uuid();

    pending_writer
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            attempt_id,
            command.clone(),
        )
        .await
        .expect("persist pending Matrix command before adapter instance is dropped");

    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = FakeMatrixDeliveryPort::default();
    port.push_result(DeliveryPortResult::Rejected(DeliveryError::new(
        DeliveryReasonCode::MatrixTimeout,
    )));
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let retry_policy = retry_policy();
    let orchestrator = MatrixOutboundOrchestrator::new(
        &port,
        &credential_resolver,
        &metadata_store,
        &retry_policy,
    );
    let pending_reader =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(Arc::clone(&backend)));
    let bridge = MatrixProductionDeliveryBridge::new(&pending_reader, &orchestrator);

    let error = bridge
        .recover_pending_command(
            route.clone(),
            grant,
            DeliveryAttemptContext {
                delivery_id: route.delivery_id,
                attempt_number: retry_policy.max_attempts,
                transaction_id: command.transaction_id.clone(),
                started_at: Utc::now(),
            },
        )
        .await
        .expect_err("exhausted retryable delivery should return the terminal delivery error");

    assert_eq!(error.reason, DeliveryReasonCode::MatrixTimeout);
    assert_eq!(
        pending_reader
            .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
            .await
            .expect("load pending command after terminal failure"),
        None,
        "bridge must tombstone the pending command after terminal failure status is durable"
    );
    assert_eq!(
        metadata_store
            .load_delivery_status(route.scope().clone(), route.delivery_id)
            .await
            .expect("load terminal status")
            .expect("terminal status should be durable")
            .status,
        OutboundDeliveryStatus::Failed
    );
}

#[tokio::test]
async fn durable_matrix_pending_intent_consumed_record_cannot_be_resurrected_by_persist() {
    let backend = Arc::new(InMemoryBackend::new());
    let store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(backend));
    let route = route();
    let command = command();
    let attempt_id = route.delivery_id.as_uuid();

    store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            attempt_id,
            command.clone(),
        )
        .await
        .expect("persist pending Matrix command");

    let consumed = store
        .mark_pending_command_consumed(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect("mark pending Matrix command consumed");

    assert!(consumed, "pending command should be consumed once");

    let loaded_after_consumed = store
        .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect("load consumed Matrix command");

    assert_eq!(loaded_after_consumed, None);

    let _persist_after_consumed = store
        .persist_pending_command(
            route.scope().clone(),
            route.delivery_id,
            attempt_id,
            command,
        )
        .await;

    let loaded_after_repersist = store
        .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect("load consumed Matrix command after repersist attempt");

    assert_eq!(
        loaded_after_repersist, None,
        "persist_pending_command must not resurrect a consumed pending command"
    );
}

#[tokio::test]
async fn durable_matrix_pending_intent_absent_load_does_not_create_consumable_record() {
    let backend = Arc::new(InMemoryBackend::new());
    let store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(backend));
    let route = route();
    let attempt_id = route.delivery_id.as_uuid();

    let absent = store
        .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect("load absent pending Matrix command");

    assert_eq!(absent, None);

    let consumed = store
        .mark_pending_command_consumed(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect("consume absent pending Matrix command");

    assert!(
        !consumed,
        "loading an absent pending command must not create a durable record that can be consumed"
    );
}

#[tokio::test]
async fn durable_matrix_pending_intent_corrupt_json_and_identity_mismatch_error() {
    let corrupt_backend = Arc::new(InMemoryBackend::new());
    let corrupt_filesystem = matrix_metadata_filesystem(Arc::clone(&corrupt_backend));
    let corrupt_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(corrupt_backend));
    let corrupt_route = route();
    let corrupt_attempt_id = corrupt_route.delivery_id.as_uuid();

    put_pending_intent_bytes(
        corrupt_filesystem.as_ref(),
        corrupt_route.scope(),
        corrupt_route.delivery_id,
        corrupt_attempt_id,
        b"{ not valid matrix pending intent json".to_vec(),
    )
    .await;

    corrupt_store
        .load_pending_command(
            corrupt_route.scope().clone(),
            corrupt_route.delivery_id,
            corrupt_attempt_id,
        )
        .await
        .expect_err("corrupt pending intent JSON must error");

    let mismatch_backend = Arc::new(InMemoryBackend::new());
    let mismatch_filesystem = matrix_metadata_filesystem(Arc::clone(&mismatch_backend));
    let mismatch_store =
        FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(mismatch_backend));
    let mismatch_route = route();
    let mismatch_attempt_id = mismatch_route.delivery_id.as_uuid();
    let mismatched = StoredMatrixPendingIntentV1 {
        schema_version: MATRIX_PENDING_INTENT_SCHEMA_VERSION,
        delivery_id: OutboundDeliveryId::new(),
        scope: mismatch_route.scope().clone(),
        attempt_id: mismatch_attempt_id,
        command: Some(command()),
    };

    put_pending_intent_bytes(
        mismatch_filesystem.as_ref(),
        mismatch_route.scope(),
        mismatch_route.delivery_id,
        mismatch_attempt_id,
        serde_json::to_vec(&mismatched).expect("serialize mismatched pending intent"),
    )
    .await;

    mismatch_store
        .load_pending_command(
            mismatch_route.scope().clone(),
            mismatch_route.delivery_id,
            mismatch_attempt_id,
        )
        .await
        .expect_err("identity-mismatched pending intent must error");
}

#[tokio::test]
async fn durable_matrix_pending_intent_invalid_command_record_bypassing_constructors_errors() {
    let backend = Arc::new(InMemoryBackend::new());
    let filesystem = matrix_metadata_filesystem(Arc::clone(&backend));
    let store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(backend));
    let route = route();
    let attempt_id = route.delivery_id.as_uuid();
    let invalid_record = json!({
        "schema_version": MATRIX_PENDING_INTENT_SCHEMA_VERSION,
        "delivery_id": route.delivery_id,
        "scope": route.scope(),
        "attempt_id": attempt_id,
        "command": {
            "command_kind": "send_text",
            "transaction_id": "",
            "reply_target_binding_ref": binding(),
            "egress_target_index": 0,
            "room_id": "not-a-matrix-room",
            "body": {
                "msgtype": "m.text",
                "body": "hello matrix"
            }
        }
    });

    put_pending_intent_bytes(
        filesystem.as_ref(),
        route.scope(),
        route.delivery_id,
        attempt_id,
        serde_json::to_vec(&invalid_record).expect("serialize invalid pending intent"),
    )
    .await;

    store
        .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
        .await
        .expect_err("invalid pending command fields must error after deserialization");
}

#[tokio::test]
async fn durable_matrix_metadata_store_clears_retry_schedule_on_terminal_status() {
    for status in [
        OutboundDeliveryStatus::Delivered,
        OutboundDeliveryStatus::Failed,
        OutboundDeliveryStatus::DeadLettered,
    ] {
        let backend = Arc::new(InMemoryBackend::new());
        let writer = FilesystemMatrixOutboundMetadataStore::new(
            matrix_metadata_filesystem(Arc::clone(&backend)),
            outbound_state_store(),
        );
        let route = route();

        writer
            .record_retry_scheduled(retry_schedule(&route), retry_context(&route))
            .await
            .expect("persist retry schedule");
        writer
            .update_delivery_status(delivery_status_request(&route, status))
            .await
            .expect("persist terminal status");

        let reader = FilesystemMatrixOutboundMetadataStore::new(
            matrix_metadata_filesystem(backend),
            outbound_state_store(),
        );
        let loaded_schedule = reader
            .load_retry_schedule(route.scope().clone(), route.delivery_id)
            .await
            .expect("load retry schedule after terminal status");

        assert_eq!(
            loaded_schedule, None,
            "terminal status {status:?} must clear stale retry schedule"
        );
    }
}

#[tokio::test]
async fn durable_matrix_metadata_store_preserves_retry_schedule_on_pending_status() {
    let backend = Arc::new(InMemoryBackend::new());
    let writer = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(Arc::clone(&backend)),
        outbound_state_store(),
    );
    let route = route();
    let schedule = retry_schedule(&route);

    writer
        .record_retry_scheduled(schedule.clone(), retry_context(&route))
        .await
        .expect("persist retry schedule");
    writer
        .update_delivery_status(delivery_status_request(
            &route,
            OutboundDeliveryStatus::Pending,
        ))
        .await
        .expect("persist pending status");

    let reader = FilesystemMatrixOutboundMetadataStore::new(
        matrix_metadata_filesystem(backend),
        outbound_state_store(),
    );
    let loaded_schedule = reader
        .load_retry_schedule(route.scope().clone(), route.delivery_id)
        .await
        .expect("load retry schedule after pending status")
        .expect("pending status should preserve retry schedule");

    assert_eq!(loaded_schedule.delivery_id, schedule.delivery_id);
    assert_eq!(loaded_schedule.scope, schedule.scope);
    assert_eq!(loaded_schedule.attempt_number, schedule.attempt_number);
    assert_eq!(loaded_schedule.retry_after, schedule.retry_after);
    assert_eq!(loaded_schedule.reason, schedule.reason);
}

#[tokio::test]
async fn orchestrator_rejects_unverified_evidence_without_marking_delivered() {
    let command = command();
    let route = route();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let attempt_ctx = attempt(&route, &command);
    let mut evidence = accepted_evidence(&command, &route, &attempt_ctx);
    evidence.verified = false;
    let port = FakeMatrixDeliveryPort::default();
    port.push_result(DeliveryPortResult::Accepted(
        ProtocolDeliveryEvidence::Matrix(evidence),
    ));
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);

    let outcome = orchestrator
        .consume_pending_intent(command.clone(), route.clone(), grant, attempt_ctx)
        .await
        .expect("unverified evidence should schedule retry without marking delivery");

    assert_eq!(outcome.status, MatrixTerminalStatus::RetryScheduled);
    assert_eq!(
        outcome.retry,
        Some(MatrixRetryDecision::RetryAfter {
            after: Duration::from_secs(1),
            reason: DeliveryReasonCode::MatrixMalformedResponse
        })
    );
    assert!(store.statuses().is_empty());
    assert!(store.evidence().is_empty());
    let retry_schedules = store.retry_schedules();
    assert_eq!(retry_schedules.len(), 1);
    assert_eq!(retry_schedules[0].delivery_id, route.delivery_id);
    assert_eq!(
        retry_schedules[0].reason,
        DeliveryReasonCode::MatrixMalformedResponse
    );
}

#[tokio::test]
async fn orchestrator_rejects_evidence_bound_to_wrong_credential_without_marking_delivered() {
    let command = command();
    let route = route();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let attempt_ctx = attempt(&route, &command);
    let mut evidence = accepted_evidence(&command, &route, &attempt_ctx);
    evidence.installation_scoped_credential_ref = canonical_fingerprint("other-credential");
    let port = FakeMatrixDeliveryPort::default();
    port.push_result(DeliveryPortResult::Accepted(
        ProtocolDeliveryEvidence::Matrix(evidence),
    ));
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);

    let outcome = orchestrator
        .consume_pending_intent(command.clone(), route.clone(), grant, attempt_ctx)
        .await
        .expect("wrong credential evidence should schedule retry without marking delivery");

    assert_eq!(outcome.status, MatrixTerminalStatus::RetryScheduled);
    assert_eq!(
        outcome.retry,
        Some(MatrixRetryDecision::RetryAfter {
            after: Duration::from_secs(1),
            reason: DeliveryReasonCode::MatrixMalformedResponse
        })
    );
    assert!(store.statuses().is_empty());
    assert!(store.evidence().is_empty());
    let retry_schedules = store.retry_schedules();
    assert_eq!(retry_schedules.len(), 1);
    assert_eq!(retry_schedules[0].delivery_id, route.delivery_id);
    assert_eq!(
        retry_schedules[0].reason,
        DeliveryReasonCode::MatrixMalformedResponse
    );
}

#[tokio::test]
async fn orchestrator_terminalizes_invalid_accepted_evidence_after_retry_exhaustion() {
    let command = command();
    let route = route();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let mut exhausted_attempt = attempt(&route, &command);
    exhausted_attempt.attempt_number = 3;
    let mut evidence = accepted_evidence(&command, &route, &exhausted_attempt);
    evidence.verified = false;
    let port = FakeMatrixDeliveryPort::default();
    port.push_result(DeliveryPortResult::Accepted(
        ProtocolDeliveryEvidence::Matrix(evidence),
    ));
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);
    let capture = observability::test_capture::start();
    let error = orchestrator
        .consume_pending_intent(
            command.clone(),
            route.clone(),
            grant,
            exhausted_attempt.clone(),
        )
        .await
        .expect_err("invalid accepted evidence at max attempts must terminalize");

    assert_eq!(error.reason, DeliveryReasonCode::MatrixMalformedResponse);
    assert_eq!(store.statuses(), vec![OutboundDeliveryStatus::Failed]);
    assert_eq!(
        store.failure_kinds(),
        vec![Some(DeliveryFailureKind::TransportUnavailable)]
    );
    assert!(store.evidence().is_empty());
    assert!(store.retry_schedules().is_empty());
    let events = capture.finish();
    assert!(
        events.iter().any(|event| matches!(
            event,
            observability::MatrixObservabilityEvent::DeliveryStatusUpdated {
                delivery_id,
                status: MatrixTerminalStatus::FailedExhausted,
                reason: Some(DeliveryReasonCode::MatrixMalformedResponse),
            } if *delivery_id == exhausted_attempt.delivery_id
        )),
        "terminal failed status update should be recorded: {events:?}"
    );
    let debug = format!("{events:?}");
    assert!(!debug.contains("!room:matrix.example"));
    assert!(!debug.contains("event-1"));
    assert!(!debug.contains("credential-handle-1"));
}

#[tokio::test]
async fn orchestrator_terminalizes_wrong_credential_evidence_after_retry_exhaustion() {
    let command = command();
    let route = route();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let mut exhausted_attempt = attempt(&route, &command);
    exhausted_attempt.attempt_number = 3;
    let mut evidence = accepted_evidence(&command, &route, &exhausted_attempt);
    evidence.installation_scoped_credential_ref = canonical_fingerprint("other-credential");
    let port = FakeMatrixDeliveryPort::default();
    port.push_result(DeliveryPortResult::Accepted(
        ProtocolDeliveryEvidence::Matrix(evidence),
    ));
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);
    let error = orchestrator
        .consume_pending_intent(command.clone(), route.clone(), grant, exhausted_attempt)
        .await
        .expect_err("wrong credential evidence at max attempts must terminalize");

    assert_eq!(error.reason, DeliveryReasonCode::MatrixMalformedResponse);
    assert_eq!(store.statuses(), vec![OutboundDeliveryStatus::Failed]);
    assert_eq!(
        store.failure_kinds(),
        vec![Some(DeliveryFailureKind::TransportUnavailable)]
    );
    assert!(store.evidence().is_empty());
    assert!(store.retry_schedules().is_empty());
}

#[tokio::test]
async fn orchestrator_schedules_retry_without_terminal_status_for_retryable_error() {
    let command = command();
    let route = route();
    let owner = owner();
    let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
    let port = FakeMatrixDeliveryPort::default();
    port.push_result(DeliveryPortResult::Rejected(DeliveryError::new(
        DeliveryReasonCode::MatrixTimeout,
    )));
    let credential_resolver =
        FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
            credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
        });
    let store = FakeMatrixOutboundMetadataStore::default();
    let retry_policy = retry_policy();
    let orchestrator =
        MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);
    let capture = observability::test_capture::start();

    let outcome = orchestrator
        .consume_pending_intent(
            command.clone(),
            route.clone(),
            grant,
            attempt(&route, &command),
        )
        .await
        .expect("retryable error should schedule retry");

    assert_eq!(outcome.status, MatrixTerminalStatus::RetryScheduled);
    assert_eq!(
        outcome.retry,
        Some(MatrixRetryDecision::RetryAfter {
            after: Duration::from_secs(1),
            reason: DeliveryReasonCode::MatrixTimeout
        })
    );
    assert!(store.statuses().is_empty());
    assert!(store.evidence().is_empty());
    let retry_schedules = store.retry_schedules();
    assert_eq!(retry_schedules.len(), 1);
    assert_eq!(retry_schedules[0].delivery_id, route.delivery_id);
    assert_eq!(retry_schedules[0].attempt_number, 1);
    assert_eq!(retry_schedules[0].retry_after, Duration::from_secs(1));
    assert_eq!(retry_schedules[0].reason, DeliveryReasonCode::MatrixTimeout);
    let events = capture.finish();
    assert!(
        events.iter().any(|event| matches!(
            event,
            observability::MatrixObservabilityEvent::DeliveryStatusUpdated {
                delivery_id,
                status: MatrixTerminalStatus::RetryScheduled,
                reason: Some(DeliveryReasonCode::MatrixTimeout),
            } if *delivery_id == route.delivery_id
        )),
        "retry-scheduled status update should be recorded: {events:?}"
    );
}

#[test]
fn retry_policy_caps_untrusted_retry_hint_duration() {
    let policy = retry_policy();
    let error = DeliveryError {
        retry_hint: Some(RetryHint {
            after: Duration::from_secs(60 * 60 * 24),
        }),
        ..DeliveryError::new(DeliveryReasonCode::MatrixRateLimited)
    };

    assert_eq!(
        policy.classify(&error, 1),
        MatrixRetryDecision::RetryAfter {
            after: Duration::from_secs(60),
            reason: DeliveryReasonCode::MatrixRateLimited
        }
    );
}

#[test]
fn matrix_errcode_is_bounded_to_known_variants_or_other() {
    assert_eq!(
        MatrixErrcode::from_matrix_errcode("M_LIMIT_EXCEEDED"),
        MatrixErrcode::LimitExceeded
    );
    assert_eq!(
        MatrixErrcode::from_matrix_errcode("M_FORBIDDEN_WITH_UNBOUNDED_TEXT"),
        MatrixErrcode::Other
    );
}
