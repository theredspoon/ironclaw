use super::*;

// Executes one Matrix retry schedule. Production worker ticks use the
// rehydrating entrypoint so stored route/grant context is validated again by
// the shared orchestrator before every send.
pub struct MatrixRetryExecutor;

impl MatrixRetryExecutor {
    pub async fn execute_due_retry_from_store<F>(
        metadata_store: &FilesystemMatrixOutboundMetadataStore<F>,
        pending_store: &FilesystemMatrixPendingIntentStore<F>,
        bridge: &MatrixProductionDeliveryBridge<'_, F>,
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
        Self::execute_due_retry(metadata_store, pending_store, bridge, route, grant, now).await
    }

    pub async fn execute_due_retry<F>(
        metadata_store: &FilesystemMatrixOutboundMetadataStore<F>,
        pending_store: &FilesystemMatrixPendingIntentStore<F>,
        bridge: &MatrixProductionDeliveryBridge<'_, F>,
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
    ) -> Result<(), DeliveryError>;
}

#[async_trait]
pub trait MatrixRetryWorkPort: Send + Sync {
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
        if let Err(error) = self
            .retry_send_authorizer
            .authorize_retry_send(&context)
            .await
        {
            self.record_retry_failure(scope, delivery_id, error.reason)
                .await?;
            return Err(error);
        }
        let (route, grant) = context.into_parts();
        let orchestrator = MatrixOutboundOrchestrator::new(
            self.delivery_port.as_ref(),
            self.credential_resolver.as_ref(),
            self.metadata_store.as_ref(),
            self.retry_policy.as_ref(),
        );
        let bridge =
            MatrixProductionDeliveryBridge::new(self.pending_store.as_ref(), &orchestrator);
        MatrixRetryExecutor::execute_due_retry(
            self.metadata_store.as_ref(),
            self.pending_store.as_ref(),
            &bridge,
            route,
            grant,
            now,
        )
        .await
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
    pub scopes: Vec<TurnScope>,
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
    if deps.scopes.is_empty() {
        return Err(MatrixOutboundContractError::Backend(
            "matrix retry worker requires at least one scope".to_string(),
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
    let mut report = MatrixRetryWorkerTickReport {
        scopes_scanned: deps.scopes.len(),
        ..MatrixRetryWorkerTickReport::default()
    };
    for scope in &deps.scopes {
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
