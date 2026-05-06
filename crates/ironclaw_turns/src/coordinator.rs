use async_trait::async_trait;
use std::sync::Arc;

use crate::{
    AdmissionRejection, CancelRunRequest, CancelRunResponse, GetRunStateRequest, ResumeTurnRequest,
    ResumeTurnResponse, SubmitTurnRequest, SubmitTurnResponse, TurnError, TurnRunId, TurnRunState,
    TurnScope, TurnStateStore, TurnStatus, events::EventCursor,
};

pub trait TurnAdmissionPolicy: Send + Sync {
    fn check_submit(&self, request: &SubmitTurnRequest) -> Result<(), AdmissionRejection>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnRunWake {
    pub scope: TurnScope,
    pub run_id: TurnRunId,
    pub status: TurnStatus,
    pub event_cursor: EventCursor,
}

pub trait TurnRunWakeNotifier: Send + Sync {
    fn notify_queued_run(&self, wake: TurnRunWake);
}

#[derive(Debug, Default)]
pub struct NoopTurnRunWakeNotifier;

impl TurnRunWakeNotifier for NoopTurnRunWakeNotifier {
    fn notify_queued_run(&self, _wake: TurnRunWake) {}
}

#[derive(Debug, Default)]
pub struct AllowAllTurnAdmissionPolicy;

impl TurnAdmissionPolicy for AllowAllTurnAdmissionPolicy {
    fn check_submit(&self, _request: &SubmitTurnRequest) -> Result<(), AdmissionRejection> {
        Ok(())
    }
}

#[async_trait]
pub trait TurnCoordinator: Send + Sync {
    async fn submit_turn(
        &self,
        request: SubmitTurnRequest,
    ) -> Result<SubmitTurnResponse, TurnError>;

    async fn resume_turn(
        &self,
        request: ResumeTurnRequest,
    ) -> Result<ResumeTurnResponse, TurnError>;

    async fn cancel_run(&self, request: CancelRunRequest) -> Result<CancelRunResponse, TurnError>;

    async fn get_run_state(&self, request: GetRunStateRequest) -> Result<TurnRunState, TurnError>;
}

pub struct DefaultTurnCoordinator<S> {
    store: Arc<S>,
    admission_policy: Arc<dyn TurnAdmissionPolicy>,
    wake_notifier: Arc<dyn TurnRunWakeNotifier>,
}

impl<S> DefaultTurnCoordinator<S>
where
    S: TurnStateStore,
{
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            admission_policy: Arc::new(AllowAllTurnAdmissionPolicy),
            wake_notifier: Arc::new(NoopTurnRunWakeNotifier),
        }
    }

    pub fn with_admission_policy(mut self, policy: Arc<dyn TurnAdmissionPolicy>) -> Self {
        self.admission_policy = policy;
        self
    }

    pub fn with_wake_notifier(mut self, notifier: Arc<dyn TurnRunWakeNotifier>) -> Self {
        self.wake_notifier = notifier;
        self
    }
}

fn submit_wake(scope: TurnScope, response: &SubmitTurnResponse) -> TurnRunWake {
    let SubmitTurnResponse::Accepted {
        run_id,
        status,
        event_cursor,
        ..
    } = response;
    TurnRunWake {
        scope,
        run_id: *run_id,
        status: *status,
        event_cursor: *event_cursor,
    }
}

fn resume_wake(scope: TurnScope, response: &ResumeTurnResponse) -> TurnRunWake {
    TurnRunWake {
        scope,
        run_id: response.run_id,
        status: response.status,
        event_cursor: response.event_cursor,
    }
}

#[async_trait]
impl<S> TurnCoordinator for DefaultTurnCoordinator<S>
where
    S: TurnStateStore + 'static,
{
    async fn submit_turn(
        &self,
        request: SubmitTurnRequest,
    ) -> Result<SubmitTurnResponse, TurnError> {
        let scope = request.scope.clone();
        let response = self
            .store
            .submit_turn(request, self.admission_policy.as_ref())
            .await?;
        self.wake_notifier
            .notify_queued_run(submit_wake(scope, &response));
        Ok(response)
    }

    async fn resume_turn(
        &self,
        request: ResumeTurnRequest,
    ) -> Result<ResumeTurnResponse, TurnError> {
        let scope = request.scope.clone();
        let response = self.store.resume_turn(request).await?;
        self.wake_notifier
            .notify_queued_run(resume_wake(scope, &response));
        Ok(response)
    }

    async fn cancel_run(&self, request: CancelRunRequest) -> Result<CancelRunResponse, TurnError> {
        self.store.request_cancel(request).await
    }

    async fn get_run_state(&self, request: GetRunStateRequest) -> Result<TurnRunState, TurnError> {
        self.store.get_run_state(request).await
    }
}
