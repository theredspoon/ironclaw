//! Matrix-local shared outbound handoff contracts.
//!
//! These types freeze the R003A/R003 boundary without changing global outbound
//! status, retry, or evidence schemas. ProductWorkflow keeps Matrix command
//! intent pending; this bridge records terminal status only after a delivery
//! port returns protocol evidence or a sanitized error.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ironclaw_outbound::OutboundDeliveryId;
use ironclaw_turns::ReplyTargetBindingRef;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolDeliveryIntent {
    Matrix(MatrixOutboundCommand),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixOutboundCommand {
    pub command_kind: MatrixCommandKind,
    pub transaction_id: MatrixTransactionId,
    pub reply_target_binding_ref: ReplyTargetBindingRef,
    pub egress_target_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixCommandKind {
    SendText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixTransactionId(String);

impl MatrixTransactionId {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixOutboundContractError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
            return Err(MatrixOutboundContractError::InvalidTransactionId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRouteMetadata {
    pub policy_revision: String,
    pub homeserver_origin_fingerprint: String,
    pub room_fingerprint: String,
    pub egress_target_index: u32,
    pub credential_handle_fingerprint: String,
    pub reply_target_binding_ref: ReplyTargetBindingRef,
    pub allowed_command_kinds: Vec<MatrixCommandKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenProductDeliveryRoute {
    delivery_id: OutboundDeliveryId,
    installation_id: String,
    adapter_id: String,
    metadata: MatrixRouteMetadata,
}

impl FrozenProductDeliveryRoute {
    pub fn mint_for_matrix(
        delivery_id: OutboundDeliveryId,
        installation_id: impl Into<String>,
        adapter_id: impl Into<String>,
        metadata: MatrixRouteMetadata,
    ) -> Self {
        Self {
            delivery_id,
            installation_id: installation_id.into(),
            adapter_id: adapter_id.into(),
            metadata,
        }
    }

    pub fn matrix_metadata(&self) -> &MatrixRouteMetadata {
        &self.metadata
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedDeliveryGrant {
    delivery_id: OutboundDeliveryId,
    installation_id: String,
    adapter_id: String,
    policy_revision: String,
    homeserver_origin_fingerprint: String,
    room_fingerprint: String,
    egress_target_index: u32,
    credential_handle_fingerprint: String,
    allowed_command_kinds: Vec<MatrixCommandKind>,
}

impl SealedDeliveryGrant {
    pub fn mint_for_matrix(route: &FrozenProductDeliveryRoute) -> Self {
        Self {
            delivery_id: route.delivery_id,
            installation_id: route.installation_id.clone(),
            adapter_id: route.adapter_id.clone(),
            policy_revision: route.metadata.policy_revision.clone(),
            homeserver_origin_fingerprint: route.metadata.homeserver_origin_fingerprint.clone(),
            room_fingerprint: route.metadata.room_fingerprint.clone(),
            egress_target_index: route.metadata.egress_target_index,
            credential_handle_fingerprint: route.metadata.credential_handle_fingerprint.clone(),
            allowed_command_kinds: route.metadata.allowed_command_kinds.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDeliveryRoute {
    route: FrozenProductDeliveryRoute,
}

impl ValidatedDeliveryRoute {
    pub fn matrix_metadata(&self) -> &MatrixRouteMetadata {
        self.route.matrix_metadata()
    }
}

pub fn validate_matrix_route_grant(
    command: &MatrixOutboundCommand,
    route: FrozenProductDeliveryRoute,
    grant: &SealedDeliveryGrant,
) -> Result<ValidatedDeliveryRoute, DeliveryError> {
    let metadata = route.matrix_metadata();
    let matches_route = grant.delivery_id == route.delivery_id
        && grant.installation_id == route.installation_id
        && grant.adapter_id == route.adapter_id
        && grant.policy_revision == metadata.policy_revision
        && grant.homeserver_origin_fingerprint == metadata.homeserver_origin_fingerprint
        && grant.room_fingerprint == metadata.room_fingerprint
        && grant.egress_target_index == metadata.egress_target_index
        && grant.credential_handle_fingerprint == metadata.credential_handle_fingerprint;
    let command_allowed = metadata
        .allowed_command_kinds
        .contains(&command.command_kind)
        && grant.allowed_command_kinds.contains(&command.command_kind)
        && metadata.reply_target_binding_ref == command.reply_target_binding_ref
        && metadata.egress_target_index == command.egress_target_index;

    if matches_route && command_allowed {
        Ok(ValidatedDeliveryRoute { route })
    } else {
        Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryAttemptContext {
    pub delivery_id: OutboundDeliveryId,
    pub attempt_number: u32,
    pub transaction_id: MatrixTransactionId,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryPortResult {
    Accepted(ProtocolDeliveryEvidence),
    Rejected(DeliveryError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolDeliveryEvidence {
    Matrix(MatrixDeliveryEvidenceV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixDeliveryEvidenceV1 {
    pub schema_version: u32,
    pub event_id_fingerprint: String,
    pub transaction_id: MatrixTransactionId,
    pub command_kind: MatrixCommandKind,
    pub delivered_at: DateTime<Utc>,
    pub verified: bool,
    pub homeserver_origin_fingerprint: String,
    pub room_fingerprint: String,
    pub installation_scoped_credential_ref: String,
    pub http_status: u16,
    pub latency_ms: u64,
}

impl MatrixDeliveryEvidenceV1 {
    pub fn validate_redacted(&self) -> Result<(), MatrixOutboundContractError> {
        let fields = [
            self.event_id_fingerprint.as_str(),
            self.homeserver_origin_fingerprint.as_str(),
            self.room_fingerprint.as_str(),
            self.installation_scoped_credential_ref.as_str(),
        ];
        if self.schema_version != 1 || fields.iter().any(|field| leaks_raw_matrix_value(field)) {
            return Err(MatrixOutboundContractError::UnsafeEvidence);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryError {
    pub reason: DeliveryReasonCode,
    pub retry_hint: Option<RetryHint>,
    pub status_family: Option<HttpStatusFamily>,
    pub matrix_errcode: Option<String>,
    pub operator_summary: SafeOperatorSummary,
}

impl DeliveryError {
    pub fn new(reason: DeliveryReasonCode) -> Self {
        Self {
            reason,
            retry_hint: None,
            status_family: None,
            matrix_errcode: None,
            operator_summary: SafeOperatorSummary::for_reason(reason),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryReasonCode {
    UnauthorizedTarget,
    MissingMatrixRoute,
    UnsupportedMatrixCommand,
    MatrixRateLimited,
    MatrixTimeout,
    MatrixServerError,
    MatrixMalformedResponse,
    MaxAttemptsExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpStatusFamily {
    Informational,
    Success,
    Redirect,
    ClientError,
    ServerError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryHint {
    pub after: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeOperatorSummary(String);

impl SafeOperatorSummary {
    pub fn for_reason(reason: DeliveryReasonCode) -> Self {
        let summary = match reason {
            DeliveryReasonCode::UnauthorizedTarget => "matrix delivery route is unauthorized",
            DeliveryReasonCode::MissingMatrixRoute => "matrix delivery route is missing",
            DeliveryReasonCode::UnsupportedMatrixCommand => "matrix command is unsupported",
            DeliveryReasonCode::MatrixRateLimited => "matrix homeserver rate limited delivery",
            DeliveryReasonCode::MatrixTimeout => "matrix delivery timed out",
            DeliveryReasonCode::MatrixServerError => "matrix homeserver returned a server error",
            DeliveryReasonCode::MatrixMalformedResponse => "matrix response was malformed",
            DeliveryReasonCode::MaxAttemptsExceeded => "matrix retry attempts were exhausted",
        };
        Self(summary.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixTerminalStatus {
    Delivered,
    FailedPermanent,
    FailedUnauthorized,
    FailedExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixRetryDecision {
    DoNotRetry {
        terminal_status: MatrixTerminalStatus,
    },
    RetryAfter {
        after: Duration,
        reason: DeliveryReasonCode,
    },
}

pub trait RetryPolicy: Send + Sync {
    fn classify(&self, err: &DeliveryError, attempt: u32) -> MatrixRetryDecision;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedMatrixRetryPolicy {
    pub max_attempts: u32,
    pub fallback_after: Duration,
}

impl RetryPolicy for BoundedMatrixRetryPolicy {
    fn classify(&self, err: &DeliveryError, attempt: u32) -> MatrixRetryDecision {
        let retryable = matches!(
            err.reason,
            DeliveryReasonCode::MatrixRateLimited
                | DeliveryReasonCode::MatrixTimeout
                | DeliveryReasonCode::MatrixServerError
                | DeliveryReasonCode::MatrixMalformedResponse
        );
        if !retryable {
            return MatrixRetryDecision::DoNotRetry {
                terminal_status: MatrixTerminalStatus::FailedPermanent,
            };
        }
        if attempt >= self.max_attempts {
            return MatrixRetryDecision::DoNotRetry {
                terminal_status: MatrixTerminalStatus::FailedExhausted,
            };
        }
        MatrixRetryDecision::RetryAfter {
            after: err
                .retry_hint
                .map_or(self.fallback_after, |hint| hint.after),
            reason: err.reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCredentialHandle {
    pub credential_handle_fingerprint: String,
}

pub trait MatrixCredentialResolver: Send + Sync {
    fn resolve(&self, route: &ValidatedDeliveryRoute) -> Option<ResolvedCredentialHandle>;
}

#[async_trait]
pub trait MatrixDeliveryPort: Send + Sync {
    async fn deliver(
        &self,
        command: ProtocolDeliveryIntent,
        route: ValidatedDeliveryRoute,
        credential: ResolvedCredentialHandle,
        attempt: DeliveryAttemptContext,
    ) -> DeliveryPortResult;
}

pub trait MatrixOutboundMetadataStore: Send + Sync {
    fn persist_evidence(
        &self,
        delivery_id: OutboundDeliveryId,
        evidence: MatrixDeliveryEvidenceV1,
    ) -> Result<(), MatrixOutboundContractError>;
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MatrixOutboundContractError {
    #[error("invalid matrix transaction id")]
    InvalidTransactionId,
    #[error("unsafe matrix evidence")]
    UnsafeEvidence,
}

fn leaks_raw_matrix_value(value: &str) -> bool {
    value.starts_with('$')
        || value.starts_with('!')
        || value.starts_with('@')
        || value.contains("://")
        || value.contains("access_token")
        || value.contains("Bearer ")
}

#[cfg(any(test, feature = "test-support"))]
pub mod fakes {
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
                    DeliveryPortResult::Rejected(DeliveryError::new(
                        DeliveryReasonCode::MatrixTimeout,
                    ))
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
        evidence: Mutex<Vec<(OutboundDeliveryId, MatrixDeliveryEvidenceV1)>>,
    }

    impl FakeMatrixOutboundMetadataStore {
        pub fn evidence(&self) -> Vec<(OutboundDeliveryId, MatrixDeliveryEvidenceV1)> {
            self.evidence.lock().expect("evidence lock").clone()
        }
    }

    impl MatrixOutboundMetadataStore for FakeMatrixOutboundMetadataStore {
        fn persist_evidence(
            &self,
            delivery_id: OutboundDeliveryId,
            evidence: MatrixDeliveryEvidenceV1,
        ) -> Result<(), MatrixOutboundContractError> {
            evidence.validate_redacted()?;
            self.evidence
                .lock()
                .expect("evidence lock")
                .push((delivery_id, evidence));
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
        let mut grant = SealedDeliveryGrant::mint_for_matrix(route);
        grant.egress_target_index = egress_target_index;
        grant
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix_outbound::fakes::route_forgery_fixture;

    fn binding() -> ReplyTargetBindingRef {
        ReplyTargetBindingRef::new("matrix-room-binding").expect("valid binding")
    }

    fn command() -> MatrixOutboundCommand {
        MatrixOutboundCommand {
            command_kind: MatrixCommandKind::SendText,
            transaction_id: MatrixTransactionId::new("txn-matrix-1").expect("valid txn"),
            reply_target_binding_ref: binding(),
            egress_target_index: 0,
        }
    }

    fn route() -> FrozenProductDeliveryRoute {
        FrozenProductDeliveryRoute::mint_for_matrix(
            OutboundDeliveryId::new(),
            "matrix-install",
            "matrix-adapter",
            MatrixRouteMetadata {
                policy_revision: "policy-rev-1".into(),
                homeserver_origin_fingerprint: "hs_fp_1".into(),
                room_fingerprint: "room_fp_1".into(),
                egress_target_index: 0,
                credential_handle_fingerprint: "cred_fp_1".into(),
                reply_target_binding_ref: binding(),
                allowed_command_kinds: vec![MatrixCommandKind::SendText],
            },
        )
    }

    #[test]
    fn forged_route_grant_fails_before_delivery_port() {
        let route = route();
        let forged_grant = route_forgery_fixture(&route, 9);

        let error = validate_matrix_route_grant(&command(), route, &forged_grant)
            .expect_err("forged grant must fail");

        assert_eq!(error.reason, DeliveryReasonCode::UnauthorizedTarget);
    }

    #[test]
    fn matrix_evidence_rejects_raw_identifiers() {
        let evidence = MatrixDeliveryEvidenceV1 {
            schema_version: 1,
            event_id_fingerprint: "$raw-event-id".into(),
            transaction_id: MatrixTransactionId::new("txn-matrix-1").expect("valid txn"),
            command_kind: MatrixCommandKind::SendText,
            delivered_at: Utc::now(),
            verified: false,
            homeserver_origin_fingerprint: "hs_fp_1".into(),
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
}
