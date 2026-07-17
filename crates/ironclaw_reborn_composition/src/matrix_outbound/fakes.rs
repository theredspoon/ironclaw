use std::collections::VecDeque;
use std::sync::Mutex;

use super::*;

#[derive(Debug, Default)]
pub struct FakeMatrixDeliveryPort {
    results: Mutex<VecDeque<DeliveryPortResult>>,
    calls: Mutex<Vec<ProtocolDeliveryIntent>>,
}

impl FakeMatrixDeliveryPort {
    pub fn push_result(&self, result: DeliveryPortResult) {
        self.results.lock().expect("result lock").push_back(result);
    }

    pub fn calls(&self) -> Vec<ProtocolDeliveryIntent> {
        self.calls.lock().expect("call lock").clone()
    }
}

#[async_trait]
impl MatrixDeliveryPort for FakeMatrixDeliveryPort {
    async fn deliver(
        &self,
        command: ProtocolDeliveryIntent,
        _route: ValidatedDeliveryRoute,
        _credential: ResolvedCredentialHandle,
        _attempt: DeliveryAttemptContext,
    ) -> DeliveryPortResult {
        self.calls.lock().expect("call lock").push(command);
        self.results
            .lock()
            .expect("result lock")
            .pop_front()
            .unwrap_or_else(|| {
                DeliveryPortResult::Rejected(DeliveryError::new(DeliveryReasonCode::MatrixTimeout))
            })
    }
}

#[derive(Debug, Clone)]
pub struct FakeMatrixCredentialResolver {
    credential: Option<ResolvedCredentialHandle>,
}

impl FakeMatrixCredentialResolver {
    pub fn with_credential(credential: ResolvedCredentialHandle) -> Self {
        Self {
            credential: Some(credential),
        }
    }
}

impl MatrixCredentialResolver for FakeMatrixCredentialResolver {
    fn resolve(&self, _route: &ValidatedDeliveryRoute) -> Option<ResolvedCredentialHandle> {
        self.credential.clone()
    }
}

#[derive(Debug, Default)]
pub struct FakeMatrixOutboundMetadataStore {
    statuses: Mutex<Vec<UpdateDeliveryStatusRequest>>,
    evidence: Mutex<Vec<(OutboundDeliveryId, MatrixDeliveryEvidenceV1)>>,
    retry_schedules: Mutex<Vec<MatrixRetrySchedule>>,
}

impl FakeMatrixOutboundMetadataStore {
    pub fn statuses(&self) -> Vec<OutboundDeliveryStatus> {
        self.statuses
            .lock()
            .expect("status lock")
            .iter()
            .map(|request| request.status)
            .collect()
    }

    pub fn status_requests(&self) -> Vec<UpdateDeliveryStatusRequest> {
        self.statuses.lock().expect("status lock").clone()
    }

    pub fn failure_kinds(&self) -> Vec<Option<DeliveryFailureKind>> {
        self.statuses
            .lock()
            .expect("status lock")
            .iter()
            .map(|request| request.failure_kind)
            .collect()
    }

    pub fn evidence(&self) -> Vec<(OutboundDeliveryId, MatrixDeliveryEvidenceV1)> {
        self.evidence.lock().expect("evidence lock").clone()
    }

    pub fn retry_schedules(&self) -> Vec<MatrixRetrySchedule> {
        self.retry_schedules
            .lock()
            .expect("retry schedule lock")
            .clone()
    }
}

#[async_trait]
impl MatrixOutboundMetadataStore for FakeMatrixOutboundMetadataStore {
    async fn load_delivery_status(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<UpdateDeliveryStatusRequest>, MatrixOutboundContractError> {
        Ok(self
            .statuses
            .lock()
            .expect("status lock")
            .iter()
            .rev()
            .find(|request| request.delivery_id == delivery_id && request.scope == scope)
            .cloned())
    }

    async fn update_delivery_status(
        &self,
        request: UpdateDeliveryStatusRequest,
    ) -> Result<(), MatrixOutboundContractError> {
        self.statuses.lock().expect("status lock").push(request);
        Ok(())
    }

    async fn persist_evidence(
        &self,
        delivery_id: OutboundDeliveryId,
        _scope: TurnScope,
        evidence: ValidatedMatrixDeliveryEvidence,
    ) -> Result<(), MatrixOutboundContractError> {
        self.evidence
            .lock()
            .expect("evidence lock")
            .push((delivery_id, evidence.into_inner()));
        Ok(())
    }

    async fn record_retry_scheduled(
        &self,
        schedule: MatrixRetrySchedule,
        _context: MatrixRetryExecutionContext,
    ) -> Result<(), MatrixOutboundContractError> {
        self.retry_schedules
            .lock()
            .expect("retry schedule lock")
            .push(schedule);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct RetryStateProbe {
    decisions: Mutex<Vec<MatrixRetryDecision>>,
}

impl RetryStateProbe {
    pub fn record(&self, decision: MatrixRetryDecision) {
        self.decisions
            .lock()
            .expect("retry probe lock")
            .push(decision);
    }

    pub fn decisions(&self) -> Vec<MatrixRetryDecision> {
        self.decisions.lock().expect("retry probe lock").clone()
    }
}

pub fn route_forgery_fixture(
    route: &FrozenProductDeliveryRoute,
    egress_target_index: u32,
) -> SealedDeliveryGrant {
    let owner = MatrixRoutePolicyOwnerToken::matrix_policy_owner();
    let mut grant = SealedDeliveryGrant::mint_for_matrix(&owner, route);
    grant.egress_target_index = egress_target_index;
    grant
}
