use std::{error::Error, fmt, panic::AssertUnwindSafe, sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::Utc;
use futures_util::FutureExt;
use ironclaw_turns::{
    SanitizedFailure, TurnError, TurnRunWake, TurnRunWakeNotifier, TurnRunWakeNotifyError,
    TurnScope,
    runner::{
        ClaimRunRequest, ClaimedTurnRun, HeartbeatRequest, RecordRecoveryRequiredRequest,
        RecoverExpiredLeasesRequest, TurnRunTransitionPort,
    },
};
use tokio::{
    sync::{Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
    time::{MissedTickBehavior, interval, sleep},
};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct TurnRunSchedulerConfig {
    max_concurrent_runs: usize,
    poll_interval: Duration,
    lease_recovery_interval: Duration,
    runner_heartbeat_interval: Duration,
    claim_error_backoff: Duration,
    wake_channel_capacity: usize,
}

impl Default for TurnRunSchedulerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_runs: 4,
            poll_interval: Duration::from_secs(5),
            lease_recovery_interval: Duration::from_secs(10),
            runner_heartbeat_interval: Duration::from_secs(30),
            claim_error_backoff: Duration::from_secs(1),
            wake_channel_capacity: 128,
        }
    }
}

fn non_zero_duration(duration: Duration) -> Duration {
    if duration.is_zero() {
        Duration::from_millis(1)
    } else {
        duration
    }
}

impl TurnRunSchedulerConfig {
    pub fn max_concurrent_runs(&self) -> usize {
        self.max_concurrent_runs
    }

    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    pub fn lease_recovery_interval(&self) -> Duration {
        self.lease_recovery_interval
    }

    pub fn runner_heartbeat_interval(&self) -> Duration {
        self.runner_heartbeat_interval
    }

    pub fn claim_error_backoff(&self) -> Duration {
        self.claim_error_backoff
    }

    pub fn wake_channel_capacity(&self) -> usize {
        self.wake_channel_capacity
    }

    pub fn with_max_concurrent_runs(mut self, max_concurrent_runs: usize) -> Self {
        self.max_concurrent_runs = max_concurrent_runs.max(1);
        self
    }

    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = non_zero_duration(poll_interval);
        self
    }

    pub fn with_lease_recovery_interval(mut self, lease_recovery_interval: Duration) -> Self {
        self.lease_recovery_interval = non_zero_duration(lease_recovery_interval);
        self
    }

    pub fn with_runner_heartbeat_interval(mut self, runner_heartbeat_interval: Duration) -> Self {
        self.runner_heartbeat_interval = non_zero_duration(runner_heartbeat_interval);
        self
    }

    pub fn with_claim_error_backoff(mut self, claim_error_backoff: Duration) -> Self {
        self.claim_error_backoff = non_zero_duration(claim_error_backoff);
        self
    }

    pub fn with_wake_channel_capacity(mut self, wake_channel_capacity: usize) -> Self {
        self.wake_channel_capacity = wake_channel_capacity.max(1);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnRunExecutorError {
    failure_category: String,
}

impl TurnRunExecutorError {
    pub fn new(failure_category: impl Into<String>) -> Result<Self, String> {
        let failure_category = failure_category.into();
        SanitizedFailure::new(failure_category.clone())?;
        Ok(Self { failure_category })
    }

    pub fn failure_category(&self) -> &str {
        &self.failure_category
    }
}

impl fmt::Display for TurnRunExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "turn run executor failed: {}",
            self.failure_category
        )
    }
}

impl Error for TurnRunExecutorError {}

#[async_trait]
pub trait TurnRunExecutor: Send + Sync {
    async fn execute_claimed_run(
        &self,
        claimed: ClaimedTurnRun,
        transitions: Arc<dyn TurnRunTransitionPort>,
    ) -> Result<(), TurnRunExecutorError>;
}

pub struct TurnRunScheduler {
    transitions: Arc<dyn TurnRunTransitionPort>,
    executor: Arc<dyn TurnRunExecutor>,
    config: TurnRunSchedulerConfig,
}

impl TurnRunScheduler {
    pub fn new(
        transitions: Arc<dyn TurnRunTransitionPort>,
        executor: Arc<dyn TurnRunExecutor>,
        config: TurnRunSchedulerConfig,
    ) -> Self {
        Self {
            transitions,
            executor,
            config,
        }
    }

    pub fn start(self) -> TurnRunSchedulerHandle {
        let (command_tx, command_rx) = mpsc::channel(self.config.wake_channel_capacity());
        let notifier = Arc::new(SchedulerTurnRunWakeNotifier {
            command_tx: command_tx.clone(),
        });
        let supervisor = tokio::spawn(run_scheduler_loop(
            command_rx,
            command_tx.clone(),
            self.transitions,
            self.executor,
            self.config,
        ));
        TurnRunSchedulerHandle {
            notifier,
            command_tx,
            supervisor,
        }
    }
}

#[derive(Clone)]
pub struct SchedulerTurnRunWakeNotifier {
    command_tx: mpsc::Sender<SchedulerCommand>,
}

impl fmt::Debug for SchedulerTurnRunWakeNotifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SchedulerTurnRunWakeNotifier")
    }
}

impl TurnRunWakeNotifier for SchedulerTurnRunWakeNotifier {
    fn notify_queued_run(&self, wake: TurnRunWake) -> Result<(), TurnRunWakeNotifyError> {
        self.command_tx
            .try_send(SchedulerCommand::Wake(wake))
            .map_err(|_| TurnRunWakeNotifyError::DeliveryUnavailable)
    }
}

pub struct TurnRunSchedulerHandle {
    notifier: Arc<SchedulerTurnRunWakeNotifier>,
    command_tx: mpsc::Sender<SchedulerCommand>,
    supervisor: JoinHandle<()>,
}

impl TurnRunSchedulerHandle {
    pub fn wake_notifier(&self) -> Arc<SchedulerTurnRunWakeNotifier> {
        Arc::clone(&self.notifier)
    }

    pub async fn shutdown(self) {
        let _ = self.command_tx.send(SchedulerCommand::Shutdown).await;
        let _ = self.supervisor.await;
    }
}

#[derive(Debug)]
enum SchedulerCommand {
    Wake(TurnRunWake),
    Drain,
    Shutdown,
}

async fn run_scheduler_loop(
    mut command_rx: mpsc::Receiver<SchedulerCommand>,
    command_tx: mpsc::Sender<SchedulerCommand>,
    transitions: Arc<dyn TurnRunTransitionPort>,
    executor: Arc<dyn TurnRunExecutor>,
    config: TurnRunSchedulerConfig,
) {
    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_runs()));
    let mut executor_tasks = JoinSet::new();
    let mut poll_tick = interval(config.poll_interval());
    poll_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut recovery_tick = interval(config.lease_recovery_interval());
    recovery_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            Some(command) = command_rx.recv() => {
                match command {
                    SchedulerCommand::Wake(wake) => {
                        drain_queued_runs(
                            Arc::clone(&transitions),
                            Arc::clone(&executor),
                            Arc::clone(&semaphore),
                            command_tx.clone(),
                            &config,
                            Some(wake.scope),
                            &mut executor_tasks,
                        ).await;
                        drain_queued_runs(
                            Arc::clone(&transitions),
                            Arc::clone(&executor),
                            Arc::clone(&semaphore),
                            command_tx.clone(),
                            &config,
                            None,
                            &mut executor_tasks,
                        ).await;
                    }
                    SchedulerCommand::Drain => {
                        drain_queued_runs(
                            Arc::clone(&transitions),
                            Arc::clone(&executor),
                            Arc::clone(&semaphore),
                            command_tx.clone(),
                            &config,
                            None,
                            &mut executor_tasks,
                        ).await;
                    }
                    SchedulerCommand::Shutdown => {
                        executor_tasks.shutdown().await;
                        break;
                    },
                }
            }
            _ = poll_tick.tick() => {
                drain_queued_runs(
                    Arc::clone(&transitions),
                    Arc::clone(&executor),
                    Arc::clone(&semaphore),
                    command_tx.clone(),
                    &config,
                    None,
                    &mut executor_tasks,
                ).await;
            }
            Some(result) = executor_tasks.join_next(), if !executor_tasks.is_empty() => {
                if let Err(error) = result {
                    debug!(error = %error, "turn run scheduler executor supervisor task failed");
                }
            }
            _ = recovery_tick.tick() => {
                recover_expired_leases(Arc::clone(&transitions)).await;
            }
        }
    }
}

async fn drain_queued_runs(
    transitions: Arc<dyn TurnRunTransitionPort>,
    executor: Arc<dyn TurnRunExecutor>,
    semaphore: Arc<Semaphore>,
    command_tx: mpsc::Sender<SchedulerCommand>,
    config: &TurnRunSchedulerConfig,
    scope_filter: Option<TurnScope>,
    executor_tasks: &mut JoinSet<()>,
) {
    loop {
        let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
            break;
        };
        let claim = transitions
            .claim_next_run(ClaimRunRequest {
                runner_id: ironclaw_turns::TurnRunnerId::new(),
                lease_token: ironclaw_turns::TurnLeaseToken::new(),
                scope_filter: scope_filter.clone(),
            })
            .await;
        match claim {
            Ok(Some(claimed)) => {
                spawn_executor_task(
                    claimed,
                    Arc::clone(&transitions),
                    Arc::clone(&executor),
                    command_tx.clone(),
                    permit,
                    config.runner_heartbeat_interval(),
                    executor_tasks,
                );
            }
            Ok(None) => break,
            Err(error) => {
                debug!(error = %error, "turn run scheduler claim failed");
                schedule_drain_after(command_tx.clone(), config.claim_error_backoff());
                break;
            }
        }
    }
}

enum ExecutorTaskOutcome {
    Completed,
    RecoveryRequired(String),
}

fn spawn_executor_task(
    claimed: ClaimedTurnRun,
    transitions: Arc<dyn TurnRunTransitionPort>,
    executor: Arc<dyn TurnRunExecutor>,
    command_tx: mpsc::Sender<SchedulerCommand>,
    permit: tokio::sync::OwnedSemaphorePermit,
    runner_heartbeat_interval: Duration,
    executor_tasks: &mut JoinSet<()>,
) {
    executor_tasks.spawn(async move {
        let recovery_run_id = claimed.state.run_id;
        let recovery_runner_id = claimed.runner_id;
        let recovery_lease_token = claimed.lease_token;
        let mut heartbeat_tick = interval(runner_heartbeat_interval);
        heartbeat_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let executor_result =
            AssertUnwindSafe(executor.execute_claimed_run(claimed, Arc::clone(&transitions)))
                .catch_unwind();
        tokio::pin!(executor_result);
        let outcome = loop {
            tokio::select! {
                result = &mut executor_result => {
                    break match result {
                        Ok(Ok(())) => ExecutorTaskOutcome::Completed,
                        Ok(Err(error)) => ExecutorTaskOutcome::RecoveryRequired(
                            error.failure_category().to_string(),
                        ),
                        Err(_) => ExecutorTaskOutcome::RecoveryRequired(
                            "scheduler_executor_panic".to_string(),
                        ),
                    };
                }
                _ = heartbeat_tick.tick() => {
                    if !heartbeat_claimed_run(
                        Arc::clone(&transitions),
                        recovery_run_id,
                        recovery_runner_id,
                        recovery_lease_token,
                    ).await {
                        break ExecutorTaskOutcome::RecoveryRequired(
                            "scheduler_heartbeat_failed".to_string(),
                        );
                    }
                }
            }
        };

        match outcome {
            ExecutorTaskOutcome::Completed => {}
            ExecutorTaskOutcome::RecoveryRequired(category) => {
                record_recovery_required(
                    Arc::clone(&transitions),
                    recovery_run_id,
                    recovery_runner_id,
                    recovery_lease_token,
                    &category,
                )
                .await;
            }
        }

        drop(permit);
        let _ = command_tx.send(SchedulerCommand::Drain).await;
    });
}

async fn heartbeat_claimed_run(
    transitions: Arc<dyn TurnRunTransitionPort>,
    run_id: ironclaw_turns::TurnRunId,
    runner_id: ironclaw_turns::TurnRunnerId,
    lease_token: ironclaw_turns::TurnLeaseToken,
) -> bool {
    let result = transitions
        .heartbeat(HeartbeatRequest {
            run_id,
            runner_id,
            lease_token,
        })
        .await;
    if let Err(error) = result {
        debug!(error = %error, "turn run scheduler heartbeat failed");
        return false;
    }
    true
}

async fn record_recovery_required(
    transitions: Arc<dyn TurnRunTransitionPort>,
    run_id: ironclaw_turns::TurnRunId,
    runner_id: ironclaw_turns::TurnRunnerId,
    lease_token: ironclaw_turns::TurnLeaseToken,
    category: &str,
) {
    let Some(failure) = sanitized_failure(category) else {
        debug!(
            category,
            "turn run scheduler could not sanitize recovery category"
        );
        return;
    };
    let result = transitions
        .record_recovery_required(RecordRecoveryRequiredRequest {
            run_id,
            runner_id,
            lease_token,
            failure,
        })
        .await;
    if let Err(error) = result {
        debug!(error = %error, "turn run scheduler recovery transition failed");
    }
}

fn sanitized_failure(category: &str) -> Option<SanitizedFailure> {
    SanitizedFailure::new(category.to_string())
        .or_else(|_| SanitizedFailure::new("scheduler_executor_error"))
        .ok()
}

async fn recover_expired_leases(transitions: Arc<dyn TurnRunTransitionPort>) {
    let result: Result<_, TurnError> = transitions
        .recover_expired_leases(RecoverExpiredLeasesRequest {
            now: Utc::now(),
            scope_filter: None,
        })
        .await;
    if let Err(error) = result {
        debug!(error = %error, "turn run scheduler lease recovery failed");
    }
}

fn schedule_drain_after(command_tx: mpsc::Sender<SchedulerCommand>, delay: Duration) {
    tokio::spawn(async move {
        sleep(delay).await;
        let _ = command_tx.send(SchedulerCommand::Drain).await;
    });
}
