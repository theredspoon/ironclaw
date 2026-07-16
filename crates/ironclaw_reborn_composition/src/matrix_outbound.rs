//! Matrix-local shared outbound handoff contracts.
//!
//! These types freeze the Matrix shared outbound boundary without changing
//! global outbound status, retry, or evidence schemas. ProductWorkflow keeps
//! Matrix command intent pending; this bridge records terminal status only
//! after a delivery port returns protocol evidence or a sanitized error.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ironclaw_outbound::{
    DeliveryFailureKind, OutboundDeliveryId, OutboundDeliveryStatus, UpdateDeliveryStatusRequest,
};
use ironclaw_turns::{ReplyTargetBindingRef, TurnScope};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    pub room_id: MatrixRoomId,
    pub body: MatrixMessageBody,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixRoomId(String);

impl MatrixRoomId {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixOutboundContractError> {
        let value = value.into();
        if !value.starts_with('!') || value.len() > 255 || value.chars().any(char::is_control) {
            return Err(MatrixOutboundContractError::InvalidRoomId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixMessageBody(Value);

impl MatrixMessageBody {
    pub fn new(value: Value) -> Result<Self, MatrixOutboundContractError> {
        if value.to_string().len() > 16 * 1024 {
            return Err(MatrixOutboundContractError::InvalidMessageBody);
        }
        Ok(Self(value))
    }

    pub fn as_json(&self) -> &Value {
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
    scope: TurnScope,
    installation_id: String,
    adapter_id: String,
    metadata: MatrixRouteMetadata,
}

#[derive(Debug, Clone, Copy)]
pub struct MatrixRoutePolicyOwnerToken {
    _private: (),
}

impl MatrixRoutePolicyOwnerToken {
    pub(crate) fn matrix_policy_owner() -> Self {
        Self { _private: () }
    }
}

impl FrozenProductDeliveryRoute {
    pub fn mint_for_matrix(
        _owner: &MatrixRoutePolicyOwnerToken,
        delivery_id: OutboundDeliveryId,
        scope: TurnScope,
        installation_id: impl Into<String>,
        adapter_id: impl Into<String>,
        metadata: MatrixRouteMetadata,
    ) -> Self {
        Self {
            delivery_id,
            scope,
            installation_id: installation_id.into(),
            adapter_id: adapter_id.into(),
            metadata,
        }
    }

    pub fn matrix_metadata(&self) -> &MatrixRouteMetadata {
        &self.metadata
    }

    pub fn scope(&self) -> &TurnScope {
        &self.scope
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
    pub fn mint_for_matrix(
        _owner: &MatrixRoutePolicyOwnerToken,
        route: &FrozenProductDeliveryRoute,
    ) -> Self {
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
    pub fn delivery_id(&self) -> OutboundDeliveryId {
        self.route.delivery_id
    }

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

    pub fn validate_for_delivery(
        &self,
        command: &MatrixOutboundCommand,
        metadata: &MatrixRouteMetadata,
    ) -> Result<(), MatrixOutboundContractError> {
        self.validate_redacted()?;
        if !self.verified
            || !(200..300).contains(&self.http_status)
            || self.transaction_id != command.transaction_id
            || self.command_kind != command.command_kind
            || self.homeserver_origin_fingerprint != metadata.homeserver_origin_fingerprint
            || self.room_fingerprint != metadata.room_fingerprint
        {
            return Err(MatrixOutboundContractError::UnverifiedEvidence);
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
    RetryScheduled,
    FailedPermanent,
    FailedUnauthorized,
    FailedExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixOrchestratorOutcome {
    pub status: MatrixTerminalStatus,
    pub retry: Option<MatrixRetryDecision>,
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
    fn update_delivery_status(
        &self,
        request: UpdateDeliveryStatusRequest,
    ) -> Result<(), MatrixOutboundContractError>;

    fn persist_evidence(
        &self,
        delivery_id: OutboundDeliveryId,
        evidence: MatrixDeliveryEvidenceV1,
    ) -> Result<(), MatrixOutboundContractError>;
}

pub struct MatrixOutboundOrchestrator<'a> {
    port: &'a dyn MatrixDeliveryPort,
    credential_resolver: &'a dyn MatrixCredentialResolver,
    metadata_store: &'a dyn MatrixOutboundMetadataStore,
    retry_policy: &'a dyn RetryPolicy,
}

impl<'a> MatrixOutboundOrchestrator<'a> {
    pub fn new(
        port: &'a dyn MatrixDeliveryPort,
        credential_resolver: &'a dyn MatrixCredentialResolver,
        metadata_store: &'a dyn MatrixOutboundMetadataStore,
        retry_policy: &'a dyn RetryPolicy,
    ) -> Self {
        Self {
            port,
            credential_resolver,
            metadata_store,
            retry_policy,
        }
    }

    pub async fn consume_pending_intent(
        &self,
        command: MatrixOutboundCommand,
        route: FrozenProductDeliveryRoute,
        grant: SealedDeliveryGrant,
        attempt: DeliveryAttemptContext,
    ) -> Result<MatrixOrchestratorOutcome, DeliveryError> {
        let route_scope = route.scope().clone();
        let validated = match validate_matrix_route_grant(&command, route, &grant) {
            Ok(validated) => validated,
            Err(error) => {
                self.persist_terminal_status(
                    attempt.delivery_id,
                    route_scope,
                    MatrixTerminalStatus::FailedUnauthorized,
                    Some(error.reason),
                )?;
                return Err(error);
            }
        };
        if attempt.delivery_id != validated.delivery_id() {
            let error = DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget);
            self.persist_terminal_status(
                attempt.delivery_id,
                validated.route.scope().clone(),
                MatrixTerminalStatus::FailedUnauthorized,
                Some(error.reason),
            )?;
            return Err(error);
        }
        let metadata = validated.matrix_metadata().clone();
        let Some(credential) = self.credential_resolver.resolve(&validated) else {
            let error = DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget);
            self.persist_terminal_status(
                attempt.delivery_id,
                validated.route.scope().clone(),
                MatrixTerminalStatus::FailedUnauthorized,
                Some(error.reason),
            )?;
            return Err(error);
        };
        if credential.credential_handle_fingerprint != metadata.credential_handle_fingerprint {
            let error = DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget);
            self.persist_terminal_status(
                attempt.delivery_id,
                validated.route.scope().clone(),
                MatrixTerminalStatus::FailedUnauthorized,
                Some(error.reason),
            )?;
            return Err(error);
        }
        let validated_scope = validated.route.scope().clone();

        match self
            .port
            .deliver(
                ProtocolDeliveryIntent::Matrix(command.clone()),
                validated,
                credential,
                attempt.clone(),
            )
            .await
        {
            DeliveryPortResult::Accepted(ProtocolDeliveryEvidence::Matrix(evidence)) => {
                evidence.validate_for_delivery(&command, &metadata)?;
                self.metadata_store
                    .persist_evidence(attempt.delivery_id, evidence)?;
                self.persist_terminal_status(
                    attempt.delivery_id,
                    validated_scope,
                    MatrixTerminalStatus::Delivered,
                    None,
                )?;
                Ok(MatrixOrchestratorOutcome {
                    status: MatrixTerminalStatus::Delivered,
                    retry: None,
                })
            }
            DeliveryPortResult::Rejected(error) => {
                let decision = self.retry_policy.classify(&error, attempt.attempt_number);
                match decision {
                    MatrixRetryDecision::RetryAfter { .. } => Ok(MatrixOrchestratorOutcome {
                        status: MatrixTerminalStatus::RetryScheduled,
                        retry: Some(decision),
                    }),
                    MatrixRetryDecision::DoNotRetry { terminal_status } => {
                        self.persist_terminal_status(
                            attempt.delivery_id,
                            validated_scope,
                            terminal_status,
                            Some(error.reason),
                        )?;
                        Err(error)
                    }
                }
            }
        }
    }

    fn persist_terminal_status(
        &self,
        delivery_id: OutboundDeliveryId,
        scope: TurnScope,
        status: MatrixTerminalStatus,
        reason: Option<DeliveryReasonCode>,
    ) -> Result<(), MatrixOutboundContractError> {
        self.metadata_store
            .update_delivery_status(UpdateDeliveryStatusRequest {
                delivery_id,
                scope,
                status: outbound_status_for_matrix_status(status),
                updated_at: Utc::now(),
                failure_kind: reason.map(delivery_failure_kind_for_reason),
            })
    }
}

fn outbound_status_for_matrix_status(status: MatrixTerminalStatus) -> OutboundDeliveryStatus {
    match status {
        MatrixTerminalStatus::Delivered => OutboundDeliveryStatus::Delivered,
        MatrixTerminalStatus::RetryScheduled => OutboundDeliveryStatus::Pending,
        MatrixTerminalStatus::FailedPermanent
        | MatrixTerminalStatus::FailedUnauthorized
        | MatrixTerminalStatus::FailedExhausted => OutboundDeliveryStatus::Failed,
    }
}

fn delivery_failure_kind_for_reason(reason: DeliveryReasonCode) -> DeliveryFailureKind {
    match reason {
        DeliveryReasonCode::UnauthorizedTarget => DeliveryFailureKind::AuthorizationRevoked,
        DeliveryReasonCode::MatrixRateLimited => DeliveryFailureKind::RateLimited,
        DeliveryReasonCode::MatrixTimeout
        | DeliveryReasonCode::MatrixServerError
        | DeliveryReasonCode::MatrixMalformedResponse => DeliveryFailureKind::TransportUnavailable,
        DeliveryReasonCode::MissingMatrixRoute
        | DeliveryReasonCode::UnsupportedMatrixCommand
        | DeliveryReasonCode::MaxAttemptsExceeded => DeliveryFailureKind::Rejected,
    }
}

impl From<MatrixOutboundContractError> for DeliveryError {
    fn from(_value: MatrixOutboundContractError) -> Self {
        Self::new(DeliveryReasonCode::MatrixMalformedResponse)
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MatrixOutboundContractError {
    #[error("invalid matrix transaction id")]
    InvalidTransactionId,
    #[error("invalid matrix room id")]
    InvalidRoomId,
    #[error("invalid matrix message body")]
    InvalidMessageBody,
    #[error("unsafe matrix evidence")]
    UnsafeEvidence,
    #[error("unverified matrix evidence")]
    UnverifiedEvidence,
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
        statuses: Mutex<Vec<UpdateDeliveryStatusRequest>>,
        evidence: Mutex<Vec<(OutboundDeliveryId, MatrixDeliveryEvidenceV1)>>,
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
    }

    impl MatrixOutboundMetadataStore for FakeMatrixOutboundMetadataStore {
        fn update_delivery_status(
            &self,
            request: UpdateDeliveryStatusRequest,
        ) -> Result<(), MatrixOutboundContractError> {
            self.statuses.lock().expect("status lock").push(request);
            Ok(())
        }

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
        let owner = MatrixRoutePolicyOwnerToken::matrix_policy_owner();
        let mut grant = SealedDeliveryGrant::mint_for_matrix(&owner, route);
        grant.egress_target_index = egress_target_index;
        grant
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix_outbound::fakes::{
        FakeMatrixCredentialResolver, FakeMatrixDeliveryPort, FakeMatrixOutboundMetadataStore,
        route_forgery_fixture,
    };
    use ironclaw_host_api::{AgentId, ProjectId, TenantId, ThreadId, UserId};
    use serde_json::json;

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
        }
    }

    fn route() -> FrozenProductDeliveryRoute {
        let owner = owner();
        FrozenProductDeliveryRoute::mint_for_matrix(
            &owner,
            OutboundDeliveryId::new(),
            scope(),
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

    fn accepted_evidence(command: &MatrixOutboundCommand) -> MatrixDeliveryEvidenceV1 {
        MatrixDeliveryEvidenceV1 {
            schema_version: 1,
            event_id_fingerprint: "event_fp_1".into(),
            transaction_id: command.transaction_id.clone(),
            command_kind: command.command_kind,
            delivered_at: Utc::now(),
            verified: true,
            homeserver_origin_fingerprint: "hs_fp_1".into(),
            room_fingerprint: "room_fp_1".into(),
            installation_scoped_credential_ref: "cred_ref_1".into(),
            http_status: 200,
            latency_ms: 12,
        }
    }

    #[tokio::test]
    async fn orchestrator_consumes_pending_matrix_intent_and_records_delivered_evidence() {
        let command = command();
        let route = route();
        let owner = owner();
        let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
        let port = FakeMatrixDeliveryPort::default();
        port.push_result(DeliveryPortResult::Accepted(
            ProtocolDeliveryEvidence::Matrix(accepted_evidence(&command)),
        ));
        let credential_resolver =
            FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
                credential_handle_fingerprint: "cred_fp_1".into(),
            });
        let store = FakeMatrixOutboundMetadataStore::default();
        let retry_policy = retry_policy();
        let orchestrator =
            MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);

        let outcome = orchestrator
            .consume_pending_intent(
                command.clone(),
                route.clone(),
                grant,
                attempt(&route, &command),
            )
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
        assert_eq!(store.evidence()[0].1.event_id_fingerprint, "event_fp_1");
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
                credential_handle_fingerprint: "wrong_cred_fp".into(),
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
                credential_handle_fingerprint: "cred_fp_1".into(),
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
        wrong_room_route.metadata.room_fingerprint = "room_fp_other".into();
        let owner = owner();
        let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &wrong_room_route);
        let port = FakeMatrixDeliveryPort::default();
        let credential_resolver =
            FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
                credential_handle_fingerprint: "cred_fp_1".into(),
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
            verified: true,
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

    #[tokio::test]
    async fn orchestrator_rejects_unverified_evidence_without_marking_delivered() {
        let command = command();
        let route = route();
        let owner = owner();
        let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
        let mut evidence = accepted_evidence(&command);
        evidence.verified = false;
        let port = FakeMatrixDeliveryPort::default();
        port.push_result(DeliveryPortResult::Accepted(
            ProtocolDeliveryEvidence::Matrix(evidence),
        ));
        let credential_resolver =
            FakeMatrixCredentialResolver::with_credential(ResolvedCredentialHandle {
                credential_handle_fingerprint: "cred_fp_1".into(),
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
            .expect_err("unverified evidence must not mark delivery");

        assert_eq!(error.reason, DeliveryReasonCode::MatrixMalformedResponse);
        assert!(store.statuses().is_empty());
        assert!(store.evidence().is_empty());
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
                credential_handle_fingerprint: "cred_fp_1".into(),
            });
        let store = FakeMatrixOutboundMetadataStore::default();
        let retry_policy = retry_policy();
        let orchestrator =
            MatrixOutboundOrchestrator::new(&port, &credential_resolver, &store, &retry_policy);

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
    }
}
