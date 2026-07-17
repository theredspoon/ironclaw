use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

use super::*;

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[derive(Debug, Default)]
pub struct FakeMatrixDeliveryPort {
    results: Mutex<VecDeque<DeliveryPortResult>>,
    calls: Mutex<Vec<ProtocolDeliveryIntent>>,
}

impl FakeMatrixDeliveryPort {
    pub fn push_result(&self, result: DeliveryPortResult) {
        lock_or_recover(&self.results).push_back(result);
    }

    pub fn calls(&self) -> Vec<ProtocolDeliveryIntent> {
        lock_or_recover(&self.calls).clone()
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
        lock_or_recover(&self.calls).push(command);
        lock_or_recover(&self.results)
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
        lock_or_recover(&self.statuses)
            .iter()
            .map(|request| request.status)
            .collect()
    }

    pub fn status_requests(&self) -> Vec<UpdateDeliveryStatusRequest> {
        lock_or_recover(&self.statuses).clone()
    }

    pub fn failure_kinds(&self) -> Vec<Option<DeliveryFailureKind>> {
        lock_or_recover(&self.statuses)
            .iter()
            .map(|request| request.failure_kind)
            .collect()
    }

    pub fn evidence(&self) -> Vec<(OutboundDeliveryId, MatrixDeliveryEvidenceV1)> {
        lock_or_recover(&self.evidence).clone()
    }

    pub fn retry_schedules(&self) -> Vec<MatrixRetrySchedule> {
        lock_or_recover(&self.retry_schedules).clone()
    }
}

#[async_trait]
impl MatrixOutboundMetadataStore for FakeMatrixOutboundMetadataStore {
    async fn load_delivery_status(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<UpdateDeliveryStatusRequest>, MatrixOutboundContractError> {
        Ok(lock_or_recover(&self.statuses)
            .iter()
            .rev()
            .find(|request| request.delivery_id == delivery_id && request.scope == scope)
            .cloned())
    }

    async fn update_delivery_status(
        &self,
        request: UpdateDeliveryStatusRequest,
    ) -> Result<(), MatrixOutboundContractError> {
        lock_or_recover(&self.statuses).push(request);
        Ok(())
    }

    async fn persist_evidence(
        &self,
        delivery_id: OutboundDeliveryId,
        _scope: TurnScope,
        evidence: ValidatedMatrixDeliveryEvidence,
    ) -> Result<(), MatrixOutboundContractError> {
        lock_or_recover(&self.evidence).push((delivery_id, evidence.into_inner()));
        Ok(())
    }

    async fn record_retry_scheduled(
        &self,
        schedule: MatrixRetrySchedule,
        _context: MatrixRetryExecutionContext,
    ) -> Result<(), MatrixOutboundContractError> {
        lock_or_recover(&self.retry_schedules).push(schedule);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct RetryStateProbe {
    decisions: Mutex<Vec<MatrixRetryDecision>>,
}

impl RetryStateProbe {
    pub fn record(&self, decision: MatrixRetryDecision) {
        lock_or_recover(&self.decisions).push(decision);
    }

    pub fn decisions(&self) -> Vec<MatrixRetryDecision> {
        lock_or_recover(&self.decisions).clone()
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
