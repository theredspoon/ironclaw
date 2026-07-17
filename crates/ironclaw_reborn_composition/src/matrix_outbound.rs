//! Matrix-local shared outbound handoff contracts.
//!
//! These types freeze the Matrix shared outbound boundary without changing
//! global outbound status, retry, or evidence schemas. ProductWorkflow keeps
//! Matrix command intent pending; this bridge records terminal status only
//! after a delivery port returns protocol evidence or a sanitized error.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ironclaw_common::hashing::sha256_hex;
use ironclaw_filesystem::{
    CasApply, CasUpdateError, ContentType, Entry, FileType, FilesystemError, RootFilesystem,
    ScopedFilesystem, cas_update,
};
use ironclaw_host_api::{ResourceScope, ScopedPath};
use ironclaw_outbound::{
    DeliveryFailureKind, OutboundDeliveryId, OutboundDeliveryStatus, OutboundError,
    OutboundStateStore, UpdateDeliveryStatusRequest,
};
use ironclaw_turns::{ReplyTargetBindingRef, TurnScope};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

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

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixPendingIntentBridgeContext {
    pub reply_target_binding_ref: ReplyTargetBindingRef,
    pub egress_target_index: u32,
}

#[cfg(test)]
impl MatrixOutboundCommand {
    pub fn from_adapter_pending_intent(
        intent: ironclaw_matrix_adapter::MatrixOutboundCommand,
        context: MatrixPendingIntentBridgeContext,
    ) -> Result<Self, DeliveryError> {
        let ironclaw_matrix_adapter::MatrixOutboundCommand::SendMessage {
            room_id,
            txn_id,
            body,
        } = intent
        else {
            return Err(DeliveryError::new(
                DeliveryReasonCode::UnsupportedMatrixCommand,
            ));
        };

        Ok(Self {
            command_kind: MatrixCommandKind::SendText,
            transaction_id: MatrixTransactionId::new(txn_id)
                .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnsupportedMatrixCommand))?,
            reply_target_binding_ref: context.reply_target_binding_ref,
            egress_target_index: context.egress_target_index,
            room_id: MatrixRoomId::new(room_id)
                .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnsupportedMatrixCommand))?,
            body: MatrixMessageBody::new(body)
                .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnsupportedMatrixCommand))?,
        })
    }
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

fn matrix_room_fingerprint(room_id: &str) -> String {
    format!("sha256:{}", sha256_hex(room_id.as_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixRoomId(String);

impl MatrixRoomId {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixOutboundContractError> {
        let value = value.into();
        let has_required_shape = value
            .rsplit_once(':')
            .map(|(localpart, server_name)| {
                value.starts_with('!')
                    && localpart.len() > 1
                    && !server_name.is_empty()
                    && value.len() <= 255
                    && !value.chars().any(|c| c.is_control() || c.is_whitespace())
            })
            .unwrap_or(false);
        if !has_required_shape {
            return Err(MatrixOutboundContractError::InvalidRoomId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn fingerprint(&self) -> String {
        matrix_room_fingerprint(&self.0)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRetryExecutionContext {
    route: FrozenProductDeliveryRoute,
    grant: SealedDeliveryGrant,
}

impl MatrixRetryExecutionContext {
    fn new(
        route: FrozenProductDeliveryRoute,
        grant: SealedDeliveryGrant,
    ) -> Result<Self, MatrixOutboundContractError> {
        validate_retry_execution_context(&route, &grant)?;
        Ok(Self { route, grant })
    }

    pub fn into_parts(self) -> (FrozenProductDeliveryRoute, SealedDeliveryGrant) {
        (self.route, self.grant)
    }
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
        && metadata.egress_target_index == command.egress_target_index
        && metadata.room_fingerprint == command.room_id.fingerprint();

    if matches_route && command_allowed {
        Ok(ValidatedDeliveryRoute { route })
    } else {
        Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))
    }
}

fn validate_retry_execution_context(
    route: &FrozenProductDeliveryRoute,
    grant: &SealedDeliveryGrant,
) -> Result<(), MatrixOutboundContractError> {
    let metadata = route.matrix_metadata();
    let matches_route = grant.delivery_id == route.delivery_id
        && grant.installation_id == route.installation_id
        && grant.adapter_id == route.adapter_id
        && grant.policy_revision == metadata.policy_revision
        && grant.homeserver_origin_fingerprint == metadata.homeserver_origin_fingerprint
        && grant.room_fingerprint == metadata.room_fingerprint
        && grant.egress_target_index == metadata.egress_target_index
        && grant.credential_handle_fingerprint == metadata.credential_handle_fingerprint
        && grant.allowed_command_kinds == metadata.allowed_command_kinds;
    if matches_route {
        Ok(())
    } else {
        Err(MatrixOutboundContractError::Backend(
            "matrix retry execution context route/grant mismatch".to_string(),
        ))
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
        if self.schema_version != 1
            || fields
                .iter()
                .any(|field| !is_canonical_sha256_fingerprint(field))
            || fields.iter().any(|field| leaks_raw_matrix_value(field))
        {
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
            || self.installation_scoped_credential_ref != metadata.credential_handle_fingerprint
        {
            return Err(MatrixOutboundContractError::UnverifiedEvidence);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMatrixDeliveryEvidence(MatrixDeliveryEvidenceV1);

impl ValidatedMatrixDeliveryEvidence {
    pub fn new_redacted(
        evidence: MatrixDeliveryEvidenceV1,
    ) -> Result<Self, MatrixOutboundContractError> {
        evidence.validate_redacted()?;
        Ok(Self(evidence))
    }

    pub fn new_for_delivery(
        evidence: MatrixDeliveryEvidenceV1,
        command: &MatrixOutboundCommand,
        metadata: &MatrixRouteMetadata,
    ) -> Result<Self, MatrixOutboundContractError> {
        evidence.validate_for_delivery(command, metadata)?;
        Ok(Self(evidence))
    }

    pub fn as_inner(&self) -> &MatrixDeliveryEvidenceV1 {
        &self.0
    }

    pub fn into_inner(self) -> MatrixDeliveryEvidenceV1 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryError {
    pub reason: DeliveryReasonCode,
    pub retry_hint: Option<RetryHint>,
    pub status_family: Option<HttpStatusFamily>,
    pub matrix_errcode: Option<MatrixErrcode>,
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
pub enum MatrixErrcode {
    Forbidden,
    UnknownToken,
    UserDeactivated,
    LimitExceeded,
    NotFound,
    BadJson,
    TooLarge,
    UnsupportedRoomVersion,
    Other,
}

impl MatrixErrcode {
    pub fn from_matrix_errcode(value: &str) -> Self {
        match value {
            "M_FORBIDDEN" => Self::Forbidden,
            "M_UNKNOWN_TOKEN" => Self::UnknownToken,
            "M_USER_DEACTIVATED" => Self::UserDeactivated,
            "M_LIMIT_EXCEEDED" => Self::LimitExceeded,
            "M_NOT_FOUND" => Self::NotFound,
            "M_BAD_JSON" | "M_NOT_JSON" => Self::BadJson,
            "M_TOO_LARGE" => Self::TooLarge,
            "M_UNSUPPORTED_ROOM_VERSION" => Self::UnsupportedRoomVersion,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    pub max_retry_after: Duration,
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
            after: err.retry_hint.map_or(self.fallback_after, |hint| {
                hint.after.min(self.max_retry_after)
            }),
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

#[async_trait]
pub trait MatrixOutboundMetadataStore: Send + Sync {
    async fn load_delivery_status(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<UpdateDeliveryStatusRequest>, MatrixOutboundContractError>;

    async fn update_delivery_status(
        &self,
        request: UpdateDeliveryStatusRequest,
    ) -> Result<(), MatrixOutboundContractError>;

    async fn persist_evidence(
        &self,
        delivery_id: OutboundDeliveryId,
        scope: TurnScope,
        evidence: ValidatedMatrixDeliveryEvidence,
    ) -> Result<(), MatrixOutboundContractError>;

    async fn record_retry_scheduled(
        &self,
        schedule: MatrixRetrySchedule,
        context: MatrixRetryExecutionContext,
    ) -> Result<(), MatrixOutboundContractError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRetrySchedule {
    pub delivery_id: OutboundDeliveryId,
    pub scope: TurnScope,
    pub attempt_number: u32,
    pub retry_after: Duration,
    pub reason: DeliveryReasonCode,
    pub recorded_at: DateTime<Utc>,
}

const MATRIX_METADATA_SCHEMA_VERSION: u32 = 1;
const MATRIX_PENDING_INTENT_SCHEMA_VERSION: u32 = 1;
const MATRIX_RETRY_CLAIM_LEASE: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixOutboundMetadataV1 {
    schema_version: u32,
    delivery_id: OutboundDeliveryId,
    scope: TurnScope,
    evidence: Option<MatrixDeliveryEvidenceV1>,
    status: Option<StoredMatrixDeliveryStatusV1>,
    retry_schedule: Option<StoredMatrixRetryScheduleV1>,
    #[serde(default)]
    retry_execution_context: Option<StoredMatrixRetryExecutionContextV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixDeliveryStatusV1 {
    status: OutboundDeliveryStatus,
    updated_at: DateTime<Utc>,
    failure_kind: Option<DeliveryFailureKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixRetryScheduleV1 {
    attempt_number: u32,
    retry_after_millis: u64,
    reason: DeliveryReasonCode,
    recorded_at: DateTime<Utc>,
    #[serde(default)]
    claim_started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    claim_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixRetryExecutionContextV1 {
    route: StoredFrozenProductDeliveryRouteV1,
    grant: StoredSealedDeliveryGrantV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredFrozenProductDeliveryRouteV1 {
    delivery_id: OutboundDeliveryId,
    scope: TurnScope,
    installation_id: String,
    adapter_id: String,
    metadata: StoredMatrixRouteMetadataV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixRouteMetadataV1 {
    policy_revision: String,
    homeserver_origin_fingerprint: String,
    room_fingerprint: String,
    egress_target_index: u32,
    credential_handle_fingerprint: String,
    reply_target_binding_ref: ReplyTargetBindingRef,
    allowed_command_kinds: Vec<MatrixCommandKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredSealedDeliveryGrantV1 {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixPendingIntentV1 {
    schema_version: u32,
    delivery_id: OutboundDeliveryId,
    scope: TurnScope,
    attempt_id: Uuid,
    command: Option<MatrixOutboundCommand>,
}

impl StoredMatrixOutboundMetadataV1 {
    fn empty(delivery_id: OutboundDeliveryId, scope: TurnScope) -> Self {
        Self {
            schema_version: MATRIX_METADATA_SCHEMA_VERSION,
            delivery_id,
            scope,
            evidence: None,
            status: None,
            retry_schedule: None,
            retry_execution_context: None,
        }
    }
}

impl StoredMatrixPendingIntentV1 {
    fn pending(
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
        command: MatrixOutboundCommand,
    ) -> Self {
        Self {
            schema_version: MATRIX_PENDING_INTENT_SCHEMA_VERSION,
            delivery_id,
            scope,
            attempt_id,
            command: Some(command),
        }
    }

    fn consumed_tombstone(
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
    ) -> Self {
        Self {
            schema_version: MATRIX_PENDING_INTENT_SCHEMA_VERSION,
            delivery_id,
            scope,
            attempt_id,
            command: None,
        }
    }

    fn is_consumed_tombstone(&self) -> bool {
        self.command.is_none()
    }
}

impl From<&MatrixRetrySchedule> for StoredMatrixRetryScheduleV1 {
    fn from(schedule: &MatrixRetrySchedule) -> Self {
        Self {
            attempt_number: schedule.attempt_number,
            retry_after_millis: schedule.retry_after.as_millis().min(u128::from(u64::MAX)) as u64,
            reason: schedule.reason,
            recorded_at: schedule.recorded_at,
            claim_started_at: None,
            claim_expires_at: None,
        }
    }
}

impl StoredMatrixRetryScheduleV1 {
    fn into_schedule(
        self,
        delivery_id: OutboundDeliveryId,
        scope: TurnScope,
    ) -> MatrixRetrySchedule {
        MatrixRetrySchedule {
            delivery_id,
            scope,
            attempt_number: self.attempt_number,
            retry_after: Duration::from_millis(self.retry_after_millis),
            reason: self.reason,
            recorded_at: self.recorded_at,
        }
    }
}

impl From<&MatrixRouteMetadata> for StoredMatrixRouteMetadataV1 {
    fn from(metadata: &MatrixRouteMetadata) -> Self {
        Self {
            policy_revision: metadata.policy_revision.clone(),
            homeserver_origin_fingerprint: metadata.homeserver_origin_fingerprint.clone(),
            room_fingerprint: metadata.room_fingerprint.clone(),
            egress_target_index: metadata.egress_target_index,
            credential_handle_fingerprint: metadata.credential_handle_fingerprint.clone(),
            reply_target_binding_ref: metadata.reply_target_binding_ref.clone(),
            allowed_command_kinds: metadata.allowed_command_kinds.clone(),
        }
    }
}

impl From<StoredMatrixRouteMetadataV1> for MatrixRouteMetadata {
    fn from(metadata: StoredMatrixRouteMetadataV1) -> Self {
        Self {
            policy_revision: metadata.policy_revision,
            homeserver_origin_fingerprint: metadata.homeserver_origin_fingerprint,
            room_fingerprint: metadata.room_fingerprint,
            egress_target_index: metadata.egress_target_index,
            credential_handle_fingerprint: metadata.credential_handle_fingerprint,
            reply_target_binding_ref: metadata.reply_target_binding_ref,
            allowed_command_kinds: metadata.allowed_command_kinds,
        }
    }
}

impl From<&FrozenProductDeliveryRoute> for StoredFrozenProductDeliveryRouteV1 {
    fn from(route: &FrozenProductDeliveryRoute) -> Self {
        Self {
            delivery_id: route.delivery_id,
            scope: route.scope.clone(),
            installation_id: route.installation_id.clone(),
            adapter_id: route.adapter_id.clone(),
            metadata: StoredMatrixRouteMetadataV1::from(&route.metadata),
        }
    }
}

impl From<StoredFrozenProductDeliveryRouteV1> for FrozenProductDeliveryRoute {
    fn from(route: StoredFrozenProductDeliveryRouteV1) -> Self {
        Self {
            delivery_id: route.delivery_id,
            scope: route.scope,
            installation_id: route.installation_id,
            adapter_id: route.adapter_id,
            metadata: route.metadata.into(),
        }
    }
}

impl From<&SealedDeliveryGrant> for StoredSealedDeliveryGrantV1 {
    fn from(grant: &SealedDeliveryGrant) -> Self {
        Self {
            delivery_id: grant.delivery_id,
            installation_id: grant.installation_id.clone(),
            adapter_id: grant.adapter_id.clone(),
            policy_revision: grant.policy_revision.clone(),
            homeserver_origin_fingerprint: grant.homeserver_origin_fingerprint.clone(),
            room_fingerprint: grant.room_fingerprint.clone(),
            egress_target_index: grant.egress_target_index,
            credential_handle_fingerprint: grant.credential_handle_fingerprint.clone(),
            allowed_command_kinds: grant.allowed_command_kinds.clone(),
        }
    }
}

impl From<StoredSealedDeliveryGrantV1> for SealedDeliveryGrant {
    fn from(grant: StoredSealedDeliveryGrantV1) -> Self {
        Self {
            delivery_id: grant.delivery_id,
            installation_id: grant.installation_id,
            adapter_id: grant.adapter_id,
            policy_revision: grant.policy_revision,
            homeserver_origin_fingerprint: grant.homeserver_origin_fingerprint,
            room_fingerprint: grant.room_fingerprint,
            egress_target_index: grant.egress_target_index,
            credential_handle_fingerprint: grant.credential_handle_fingerprint,
            allowed_command_kinds: grant.allowed_command_kinds,
        }
    }
}

impl StoredMatrixRetryExecutionContextV1 {
    fn new(route: &FrozenProductDeliveryRoute, grant: &SealedDeliveryGrant) -> Self {
        Self {
            route: StoredFrozenProductDeliveryRouteV1::from(route),
            grant: StoredSealedDeliveryGrantV1::from(grant),
        }
    }

    fn into_context(self) -> Result<MatrixRetryExecutionContext, MatrixOutboundContractError> {
        let route = FrozenProductDeliveryRoute::from(self.route);
        let grant = SealedDeliveryGrant::from(self.grant);
        MatrixRetryExecutionContext::new(route, grant)
    }

    fn validate(&self) -> Result<(), MatrixOutboundContractError> {
        let matches_route = self.grant.delivery_id == self.route.delivery_id
            && self.grant.installation_id == self.route.installation_id
            && self.grant.adapter_id == self.route.adapter_id
            && self.grant.policy_revision == self.route.metadata.policy_revision
            && self.grant.homeserver_origin_fingerprint
                == self.route.metadata.homeserver_origin_fingerprint
            && self.grant.room_fingerprint == self.route.metadata.room_fingerprint
            && self.grant.egress_target_index == self.route.metadata.egress_target_index
            && self.grant.credential_handle_fingerprint
                == self.route.metadata.credential_handle_fingerprint
            && self.grant.allowed_command_kinds == self.route.metadata.allowed_command_kinds;
        if matches_route {
            Ok(())
        } else {
            Err(MatrixOutboundContractError::Backend(
                "matrix retry execution context route/grant mismatch".to_string(),
            ))
        }
    }
}

pub struct FilesystemMatrixPendingIntentStore<F>
where
    F: RootFilesystem + 'static,
{
    filesystem: Arc<ScopedFilesystem<F>>,
}

enum PendingRecordMutation<T> {
    Write {
        record: Box<StoredMatrixPendingIntentV1>,
        outcome: T,
    },
    NoOp {
        outcome: T,
    },
}

impl<F> FilesystemMatrixPendingIntentStore<F>
where
    F: RootFilesystem,
{
    pub fn new(filesystem: Arc<ScopedFilesystem<F>>) -> Self {
        Self { filesystem }
    }

    pub async fn persist_pending_command(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
        command: MatrixOutboundCommand,
    ) -> Result<(), MatrixOutboundContractError> {
        let record_scope = scope.clone();
        self.mutate_pending_record(scope, delivery_id, attempt_id, |current| {
            let record = match current {
                Some(mut record) => {
                    if record.is_consumed_tombstone() {
                        return Ok(PendingRecordMutation::Write {
                            record: Box::new(record),
                            outcome: (),
                        });
                    }
                    record.command = Some(command.clone());
                    record
                }
                None => StoredMatrixPendingIntentV1::pending(
                    record_scope.clone(),
                    delivery_id,
                    attempt_id,
                    command.clone(),
                ),
            };
            Ok(PendingRecordMutation::Write {
                record: Box::new(record),
                outcome: (),
            })
        })
        .await
    }

    pub async fn load_pending_command(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
    ) -> Result<Option<MatrixOutboundCommand>, MatrixOutboundContractError> {
        let resource_scope = scope.to_resource_scope();
        let path = matrix_pending_intent_path(&scope, delivery_id, attempt_id)?;
        let Some(versioned) = self.filesystem.get(&resource_scope, &path).await? else {
            return Ok(None);
        };
        let record = serde_json::from_slice::<StoredMatrixPendingIntentV1>(&versioned.entry.body)?;
        validate_stored_matrix_pending_intent(&record, &scope, delivery_id, attempt_id)?;
        Ok(record.command)
    }

    pub async fn mark_pending_command_consumed(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
    ) -> Result<bool, MatrixOutboundContractError> {
        self.mutate_pending_record(scope, delivery_id, attempt_id, |current| {
            let Some(mut record) = current else {
                return Ok(PendingRecordMutation::NoOp { outcome: false });
            };
            let consumed = record.command.take().is_some();
            Ok(PendingRecordMutation::Write {
                record: Box::new(record),
                outcome: consumed,
            })
        })
        .await
    }

    pub async fn take_pending_command(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
    ) -> Result<Option<MatrixOutboundCommand>, MatrixOutboundContractError> {
        self.mutate_pending_record(scope, delivery_id, attempt_id, |current| {
            let Some(mut record) = current else {
                return Ok(PendingRecordMutation::NoOp { outcome: None });
            };
            let command = record.command.take();
            Ok(PendingRecordMutation::Write {
                record: Box::new(record),
                outcome: command,
            })
        })
        .await
    }

    async fn mutate_pending_record<T>(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
        mutate: impl Fn(
            Option<StoredMatrixPendingIntentV1>,
        ) -> Result<PendingRecordMutation<T>, MatrixOutboundContractError>,
    ) -> Result<T, MatrixOutboundContractError> {
        let resource_scope = scope.to_resource_scope();
        let path = matrix_pending_intent_path(&scope, delivery_id, attempt_id)?;
        cas_update(
            self.filesystem.as_ref(),
            &resource_scope,
            &path,
            |bytes: &[u8]| {
                serde_json::from_slice::<StoredMatrixPendingIntentV1>(bytes).map_err(Into::into)
            },
            |record: &StoredMatrixPendingIntentV1| {
                Ok(
                    Entry::bytes(serde_json::to_vec(record)?)
                        .with_content_type(ContentType::json()),
                )
            },
            |current: Option<StoredMatrixPendingIntentV1>| {
                let outcome = (|| {
                    if let Some(record) = &current {
                        validate_stored_matrix_pending_intent(
                            record,
                            &scope,
                            delivery_id,
                            attempt_id,
                        )?;
                    }
                    match mutate(current)? {
                        PendingRecordMutation::Write { record, outcome } => {
                            validate_stored_matrix_pending_intent(
                                record.as_ref(),
                                &scope,
                                delivery_id,
                                attempt_id,
                            )?;
                            Ok(CasApply::new(*record, outcome))
                        }
                        PendingRecordMutation::NoOp { outcome } => Ok(CasApply::no_op(
                            StoredMatrixPendingIntentV1::consumed_tombstone(
                                scope.clone(),
                                delivery_id,
                                attempt_id,
                            ),
                            outcome,
                        )),
                    }
                })();
                async move { outcome }
            },
        )
        .await
        .map_err(map_matrix_pending_intent_cas_error)
    }
}

pub struct FilesystemMatrixOutboundMetadataStore<F>
where
    F: RootFilesystem,
{
    filesystem: Arc<ScopedFilesystem<F>>,
    outbound_state_store: Arc<dyn OutboundStateStore>,
}

impl<F> FilesystemMatrixOutboundMetadataStore<F>
where
    F: RootFilesystem,
{
    pub fn new(
        filesystem: Arc<ScopedFilesystem<F>>,
        outbound_state_store: Arc<dyn OutboundStateStore>,
    ) -> Self {
        Self {
            filesystem,
            outbound_state_store,
        }
    }

    pub async fn load_evidence(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<MatrixDeliveryEvidenceV1>, MatrixOutboundContractError> {
        Ok(self
            .load_record(&scope, delivery_id)
            .await?
            .and_then(|record| record.evidence))
    }

    pub async fn load_delivery_status(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<UpdateDeliveryStatusRequest>, MatrixOutboundContractError> {
        Ok(self
            .load_record(&scope, delivery_id)
            .await?
            .and_then(|record| {
                record.status.map(|status| UpdateDeliveryStatusRequest {
                    delivery_id,
                    scope,
                    status: status.status,
                    updated_at: status.updated_at,
                    failure_kind: status.failure_kind,
                })
            }))
    }

    pub async fn load_retry_schedule(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<MatrixRetrySchedule>, MatrixOutboundContractError> {
        Ok(self
            .load_record(&scope, delivery_id)
            .await?
            .and_then(|record| {
                record
                    .retry_schedule
                    .map(|schedule| schedule.into_schedule(delivery_id, scope))
            }))
    }

    pub async fn list_due_retry_schedules(
        &self,
        scope: TurnScope,
        now: DateTime<Utc>,
        max_entries: usize,
    ) -> Result<Vec<MatrixRetrySchedule>, MatrixOutboundContractError> {
        if max_entries == 0 {
            return Ok(Vec::new());
        }

        let resource_scope = scope.to_resource_scope();
        let metadata_dir = matrix_metadata_dir_path()?;
        let entries = match self
            .filesystem
            .list_dir(&resource_scope, &metadata_dir)
            .await
        {
            Ok(entries) => entries,
            Err(FilesystemError::NotFound { .. }) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let terminal_delivery_ids = self
            .outbound_state_store
            .list_delivery_attempts(scope.clone())
            .await?
            .into_iter()
            .filter(|attempt| is_terminal_delivery_status(attempt.status))
            .map(|attempt| attempt.delivery_id)
            .collect::<HashSet<_>>();
        let mut schedules = Vec::new();
        for entry in entries {
            if entry.file_type != FileType::File {
                continue;
            }
            let record_path = ScopedPath::new(format!("/outbound/matrix/metadata/{}", entry.name))
                .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))?;
            let Some(record) = self
                .load_record_at_path(&resource_scope, &record_path)
                .await?
            else {
                continue;
            };
            if record.scope != scope
                || terminal_delivery_ids.contains(&record.delivery_id)
                || record
                    .status
                    .as_ref()
                    .is_some_and(|status| is_terminal_delivery_status(status.status))
            {
                continue;
            }
            let Some(schedule) = record.retry_schedule else {
                continue;
            };
            if retry_schedule_due_and_unclaimed(&schedule, now)? {
                schedules.push(schedule.into_schedule(record.delivery_id, record.scope));
                if schedules.len() == max_entries {
                    break;
                }
            }
        }
        Ok(schedules)
    }

    pub async fn persist_retry_execution_context(
        &self,
        _owner: &MatrixRoutePolicyOwnerToken,
        route: &FrozenProductDeliveryRoute,
        grant: &SealedDeliveryGrant,
    ) -> Result<(), MatrixOutboundContractError> {
        validate_retry_execution_context(route, grant)?;
        self.mutate_record(route.scope().clone(), route.delivery_id, |mut record| {
            record.retry_execution_context =
                Some(StoredMatrixRetryExecutionContextV1::new(route, grant));
            record
        })
        .await
    }

    pub async fn load_retry_execution_context(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<MatrixRetryExecutionContext>, MatrixOutboundContractError> {
        let Some(record) = self.load_record(&scope, delivery_id).await? else {
            return Ok(None);
        };
        if record.retry_schedule.is_none() {
            return Ok(None);
        }
        if record
            .status
            .as_ref()
            .is_some_and(|status| is_terminal_delivery_status(status.status))
        {
            return Ok(None);
        }
        record
            .retry_execution_context
            .map(StoredMatrixRetryExecutionContextV1::into_context)
            .transpose()
    }

    pub async fn claim_due_retry_schedule(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        now: DateTime<Utc>,
        lease_duration: Duration,
    ) -> Result<Option<MatrixRetrySchedule>, MatrixOutboundContractError> {
        let resource_scope = scope.to_resource_scope();
        let path = matrix_metadata_path(&scope, delivery_id)?;
        cas_update(
            self.filesystem.as_ref(),
            &resource_scope,
            &path,
            |bytes: &[u8]| {
                serde_json::from_slice::<StoredMatrixOutboundMetadataV1>(bytes).map_err(Into::into)
            },
            |record: &StoredMatrixOutboundMetadataV1| {
                Ok(
                    Entry::bytes(serde_json::to_vec(record)?)
                        .with_content_type(ContentType::json()),
                )
            },
            |current: Option<StoredMatrixOutboundMetadataV1>| {
                let outcome = (|| {
                    let Some(mut record) = current else {
                        return Ok(CasApply::no_op(
                            StoredMatrixOutboundMetadataV1::empty(delivery_id, scope.clone()),
                            None,
                        ));
                    };
                    validate_stored_matrix_metadata(&record, &scope, delivery_id)?;

                    if record
                        .status
                        .as_ref()
                        .is_some_and(|status| is_terminal_delivery_status(status.status))
                    {
                        record.retry_schedule = None;
                        return Ok(CasApply::new(record, None));
                    }

                    let Some(schedule) = record.retry_schedule.as_mut() else {
                        return Ok(CasApply::no_op(record, None));
                    };
                    let due_at = retry_due_at(schedule.recorded_at, schedule.retry_after_millis)?;
                    if now < due_at
                        || schedule
                            .claim_expires_at
                            .is_some_and(|claim_expires_at| now < claim_expires_at)
                    {
                        return Ok(CasApply::no_op(record, None));
                    }

                    let claimed_schedule =
                        schedule.clone().into_schedule(delivery_id, scope.clone());
                    schedule.claim_started_at = Some(now);
                    schedule.claim_expires_at = Some(
                        now.checked_add_signed(chrono_duration_from_std(lease_duration)?)
                            .ok_or_else(|| {
                                MatrixOutboundContractError::Backend(
                                    "matrix retry claim lease overflow".to_string(),
                                )
                            })?,
                    );
                    Ok(CasApply::new(record, Some(claimed_schedule)))
                })();
                async move { outcome }
            },
        )
        .await
        .map_err(map_matrix_metadata_cas_error)
    }

    async fn load_record(
        &self,
        scope: &TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<StoredMatrixOutboundMetadataV1>, MatrixOutboundContractError> {
        let resource_scope = scope.to_resource_scope();
        let path = matrix_metadata_path(scope, delivery_id)?;
        let Some(versioned) = self.filesystem.get(&resource_scope, &path).await? else {
            return Ok(None);
        };
        let record: StoredMatrixOutboundMetadataV1 = serde_json::from_slice(&versioned.entry.body)?;
        validate_stored_matrix_metadata(&record, scope, delivery_id)?;
        Ok(Some(record))
    }

    async fn load_record_at_path(
        &self,
        resource_scope: &ResourceScope,
        path: &ScopedPath,
    ) -> Result<Option<StoredMatrixOutboundMetadataV1>, MatrixOutboundContractError> {
        let Some(versioned) = self.filesystem.get(resource_scope, path).await? else {
            return Ok(None);
        };
        let record: StoredMatrixOutboundMetadataV1 = serde_json::from_slice(&versioned.entry.body)?;
        validate_stored_matrix_metadata(&record, &record.scope, record.delivery_id)?;
        Ok(Some(record))
    }

    async fn mutate_record(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        mutate: impl Fn(StoredMatrixOutboundMetadataV1) -> StoredMatrixOutboundMetadataV1,
    ) -> Result<(), MatrixOutboundContractError> {
        let resource_scope = scope.to_resource_scope();
        let path = matrix_metadata_path(&scope, delivery_id)?;
        cas_update(
            self.filesystem.as_ref(),
            &resource_scope,
            &path,
            |bytes: &[u8]| {
                serde_json::from_slice::<StoredMatrixOutboundMetadataV1>(bytes).map_err(Into::into)
            },
            |record: &StoredMatrixOutboundMetadataV1| {
                Ok(
                    Entry::bytes(serde_json::to_vec(record)?)
                        .with_content_type(ContentType::json()),
                )
            },
            |current: Option<StoredMatrixOutboundMetadataV1>| {
                let outcome = (|| {
                    let record = current.unwrap_or_else(|| {
                        StoredMatrixOutboundMetadataV1::empty(delivery_id, scope.clone())
                    });
                    validate_stored_matrix_metadata(&record, &scope, delivery_id)?;
                    let record = mutate(record);
                    Ok(CasApply::new(record, ()))
                })();
                async move { outcome }
            },
        )
        .await
        .map_err(map_matrix_metadata_cas_error)
    }
}

#[async_trait]
impl<F> MatrixOutboundMetadataStore for FilesystemMatrixOutboundMetadataStore<F>
where
    F: RootFilesystem + 'static,
{
    async fn load_delivery_status(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<UpdateDeliveryStatusRequest>, MatrixOutboundContractError> {
        self.load_delivery_status(scope, delivery_id).await
    }

    async fn update_delivery_status(
        &self,
        request: UpdateDeliveryStatusRequest,
    ) -> Result<(), MatrixOutboundContractError> {
        self.outbound_state_store
            .update_delivery_status(request.clone())
            .await
            .map_err(MatrixOutboundContractError::from)?;
        self.mutate_record(request.scope.clone(), request.delivery_id, |mut record| {
            record.status = Some(StoredMatrixDeliveryStatusV1 {
                status: request.status,
                updated_at: request.updated_at,
                failure_kind: request.failure_kind,
            });
            if is_terminal_delivery_status(request.status) {
                record.retry_schedule = None;
                record.retry_execution_context = None;
            }
            record
        })
        .await
    }

    async fn persist_evidence(
        &self,
        delivery_id: OutboundDeliveryId,
        scope: TurnScope,
        evidence: ValidatedMatrixDeliveryEvidence,
    ) -> Result<(), MatrixOutboundContractError> {
        self.mutate_record(scope, delivery_id, |mut record| {
            record.evidence = Some(evidence.clone().into_inner());
            record
        })
        .await
    }

    async fn record_retry_scheduled(
        &self,
        schedule: MatrixRetrySchedule,
        context: MatrixRetryExecutionContext,
    ) -> Result<(), MatrixOutboundContractError> {
        let delivery_id = schedule.delivery_id;
        let scope = schedule.scope.clone();
        if context.route.delivery_id != delivery_id || context.route.scope != scope {
            return Err(MatrixOutboundContractError::Backend(
                "matrix retry schedule context identity mismatch".to_string(),
            ));
        }
        self.mutate_record(scope, delivery_id, |mut record| {
            record.retry_schedule = Some(StoredMatrixRetryScheduleV1::from(&schedule));
            record.retry_execution_context = Some(StoredMatrixRetryExecutionContextV1::new(
                &context.route,
                &context.grant,
            ));
            record
        })
        .await
    }
}

fn matrix_metadata_path(
    scope: &TurnScope,
    delivery_id: OutboundDeliveryId,
) -> Result<ScopedPath, MatrixOutboundContractError> {
    let scope_json = serde_json::to_vec(scope)?;
    let key = format!("{}:{}", sha256_hex(&scope_json), delivery_id);
    ScopedPath::new(format!(
        "/outbound/matrix/metadata/{}.json",
        sha256_hex(key.as_bytes())
    ))
    .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))
}

fn matrix_metadata_dir_path() -> Result<ScopedPath, MatrixOutboundContractError> {
    ScopedPath::new("/outbound/matrix/metadata")
        .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))
}

fn matrix_pending_intent_path(
    scope: &TurnScope,
    delivery_id: OutboundDeliveryId,
    attempt_id: Uuid,
) -> Result<ScopedPath, MatrixOutboundContractError> {
    let scope_json = serde_json::to_vec(scope)?;
    let key = format!("{}:{}:{}", sha256_hex(&scope_json), delivery_id, attempt_id);
    ScopedPath::new(format!(
        "/outbound/matrix/pending-intents/{}.json",
        sha256_hex(key.as_bytes())
    ))
    .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))
}

fn chrono_duration_from_std(
    duration: Duration,
) -> Result<chrono::Duration, MatrixOutboundContractError> {
    chrono::Duration::from_std(duration).map_err(|_| {
        MatrixOutboundContractError::Backend("matrix retry duration overflow".to_string())
    })
}

fn retry_due_at(
    recorded_at: DateTime<Utc>,
    retry_after_millis: u64,
) -> Result<DateTime<Utc>, MatrixOutboundContractError> {
    recorded_at
        .checked_add_signed(chrono_duration_from_std(Duration::from_millis(
            retry_after_millis,
        ))?)
        .ok_or_else(|| {
            MatrixOutboundContractError::Backend("matrix retry due timestamp overflow".to_string())
        })
}

fn retry_schedule_due_and_unclaimed(
    schedule: &StoredMatrixRetryScheduleV1,
    now: DateTime<Utc>,
) -> Result<bool, MatrixOutboundContractError> {
    Ok(
        now >= retry_due_at(schedule.recorded_at, schedule.retry_after_millis)?
            && schedule
                .claim_expires_at
                .is_none_or(|claim_expires_at| now >= claim_expires_at),
    )
}

fn validate_stored_matrix_metadata(
    record: &StoredMatrixOutboundMetadataV1,
    scope: &TurnScope,
    delivery_id: OutboundDeliveryId,
) -> Result<(), MatrixOutboundContractError> {
    if record.schema_version != MATRIX_METADATA_SCHEMA_VERSION
        || record.delivery_id != delivery_id
        || record.scope != *scope
    {
        return Err(MatrixOutboundContractError::Backend(
            "matrix metadata identity mismatch".to_string(),
        ));
    }
    if let Some(evidence) = &record.evidence {
        evidence.validate_redacted()?;
    }
    if let Some(context) = &record.retry_execution_context {
        if context.route.delivery_id != record.delivery_id || context.route.scope != record.scope {
            return Err(MatrixOutboundContractError::Backend(
                "matrix retry execution context identity mismatch".to_string(),
            ));
        }
        context.validate()?;
    }
    Ok(())
}

fn validate_stored_matrix_pending_intent(
    record: &StoredMatrixPendingIntentV1,
    scope: &TurnScope,
    delivery_id: OutboundDeliveryId,
    attempt_id: Uuid,
) -> Result<(), MatrixOutboundContractError> {
    if record.schema_version != MATRIX_PENDING_INTENT_SCHEMA_VERSION
        || record.delivery_id != delivery_id
        || record.scope != *scope
        || record.attempt_id != attempt_id
    {
        return Err(MatrixOutboundContractError::Backend(
            "matrix pending intent identity mismatch".to_string(),
        ));
    }
    if let Some(command) = &record.command {
        validate_stored_matrix_pending_command(command)?;
    }
    Ok(())
}

fn validate_stored_matrix_pending_command(
    command: &MatrixOutboundCommand,
) -> Result<(), MatrixOutboundContractError> {
    MatrixTransactionId::new(command.transaction_id.as_str().to_owned())?;
    MatrixRoomId::new(command.room_id.as_str().to_owned())?;
    MatrixMessageBody::new(command.body.as_json().clone())?;
    Ok(())
}

fn map_matrix_metadata_cas_error(
    error: CasUpdateError<MatrixOutboundContractError>,
) -> MatrixOutboundContractError {
    match error {
        CasUpdateError::Apply(error) => error,
        CasUpdateError::Backend(error) => error.into(),
        error @ (CasUpdateError::Timeout
        | CasUpdateError::RetriesExhausted
        | CasUpdateError::CasUnsupported) => {
            MatrixOutboundContractError::Backend(error.to_string())
        }
    }
}

fn map_matrix_pending_intent_cas_error(
    error: CasUpdateError<MatrixOutboundContractError>,
) -> MatrixOutboundContractError {
    match error {
        CasUpdateError::Apply(error) => error,
        CasUpdateError::Backend(error) => error.into(),
        error @ (CasUpdateError::Timeout
        | CasUpdateError::RetriesExhausted
        | CasUpdateError::CasUnsupported) => {
            MatrixOutboundContractError::Backend(error.to_string())
        }
    }
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
                )
                .await?;
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
            )
            .await?;
            return Err(error);
        }
        let retry_context =
            MatrixRetryExecutionContext::new(validated.route.clone(), grant.clone())
                .map_err(DeliveryError::from)?;
        let metadata = validated.matrix_metadata().clone();
        let Some(credential) = self.credential_resolver.resolve(&validated) else {
            let error = DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget);
            self.persist_terminal_status(
                attempt.delivery_id,
                validated.route.scope().clone(),
                MatrixTerminalStatus::FailedUnauthorized,
                Some(error.reason),
            )
            .await?;
            return Err(error);
        };
        if credential.credential_handle_fingerprint != metadata.credential_handle_fingerprint {
            let error = DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget);
            self.persist_terminal_status(
                attempt.delivery_id,
                validated.route.scope().clone(),
                MatrixTerminalStatus::FailedUnauthorized,
                Some(error.reason),
            )
            .await?;
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
                let evidence = match ValidatedMatrixDeliveryEvidence::new_for_delivery(
                    evidence, &command, &metadata,
                ) {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        return self
                            .apply_delivery_error(
                                DeliveryError::from(error),
                                &attempt,
                                validated_scope,
                                retry_context.clone(),
                            )
                            .await;
                    }
                };
                self.metadata_store
                    .persist_evidence(attempt.delivery_id, validated_scope.clone(), evidence)
                    .await?;
                self.persist_terminal_status(
                    attempt.delivery_id,
                    validated_scope,
                    MatrixTerminalStatus::Delivered,
                    None,
                )
                .await?;
                Ok(MatrixOrchestratorOutcome {
                    status: MatrixTerminalStatus::Delivered,
                    retry: None,
                })
            }
            DeliveryPortResult::Rejected(error) => {
                self.apply_delivery_error(error, &attempt, validated_scope, retry_context)
                    .await
            }
        }
    }

    async fn apply_delivery_error(
        &self,
        error: DeliveryError,
        attempt: &DeliveryAttemptContext,
        scope: TurnScope,
        retry_context: MatrixRetryExecutionContext,
    ) -> Result<MatrixOrchestratorOutcome, DeliveryError> {
        let decision = self.retry_policy.classify(&error, attempt.attempt_number);
        match decision {
            MatrixRetryDecision::RetryAfter { after, reason } => {
                self.metadata_store
                    .record_retry_scheduled(
                        MatrixRetrySchedule {
                            delivery_id: attempt.delivery_id,
                            scope,
                            attempt_number: attempt.attempt_number,
                            retry_after: after,
                            reason,
                            recorded_at: Utc::now(),
                        },
                        retry_context,
                    )
                    .await?;
                Ok(MatrixOrchestratorOutcome {
                    status: MatrixTerminalStatus::RetryScheduled,
                    retry: Some(decision),
                })
            }
            MatrixRetryDecision::DoNotRetry { terminal_status } => {
                self.persist_terminal_status(
                    attempt.delivery_id,
                    scope,
                    terminal_status,
                    Some(error.reason),
                )
                .await?;
                Err(error)
            }
        }
    }

    async fn persist_terminal_status(
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
            .await
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
    fn from(value: MatrixOutboundContractError) -> Self {
        tracing::debug!(
            target = "ironclaw::reborn::matrix_outbound",
            error = %value,
            "matrix outbound contract error mapped to sanitized delivery error"
        );
        Self::new(DeliveryReasonCode::MatrixMalformedResponse)
    }
}

pub struct MatrixProductionDeliveryBridge<'a, F>
where
    F: RootFilesystem + 'static,
{
    pending_store: &'a FilesystemMatrixPendingIntentStore<F>,
    orchestrator: &'a MatrixOutboundOrchestrator<'a>,
}

impl<'a, F> MatrixProductionDeliveryBridge<'a, F>
where
    F: RootFilesystem + 'static,
{
    pub fn new(
        pending_store: &'a FilesystemMatrixPendingIntentStore<F>,
        orchestrator: &'a MatrixOutboundOrchestrator<'a>,
    ) -> Self {
        Self {
            pending_store,
            orchestrator,
        }
    }

    pub async fn recover_pending_command(
        &self,
        route: FrozenProductDeliveryRoute,
        grant: SealedDeliveryGrant,
        attempt: DeliveryAttemptContext,
    ) -> Result<MatrixOrchestratorOutcome, DeliveryError> {
        let attempt_id = route.delivery_id.as_uuid();
        let tombstone_scope = route.scope().clone();
        let delivery_id = route.delivery_id;
        let durable_status = self
            .orchestrator
            .metadata_store
            .load_delivery_status(tombstone_scope.clone(), delivery_id)
            .await?;
        if durable_status
            .as_ref()
            .is_some_and(|request| is_terminal_delivery_status(request.status))
        {
            self.pending_store
                .mark_pending_command_consumed(tombstone_scope, delivery_id, attempt_id)
                .await?;
            return Err(DeliveryError::new(DeliveryReasonCode::MissingMatrixRoute));
        }
        let command = self
            .pending_store
            .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
            .await?
            .ok_or_else(|| DeliveryError::new(DeliveryReasonCode::MissingMatrixRoute))?;
        let attempt_number = attempt.attempt_number;
        let outcome = match self
            .orchestrator
            .consume_pending_intent(command, route, grant, attempt)
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                let durable_status = self
                    .orchestrator
                    .metadata_store
                    .load_delivery_status(tombstone_scope.clone(), delivery_id)
                    .await?;
                if durable_status
                    .as_ref()
                    .is_some_and(|request| is_terminal_delivery_status(request.status))
                    && matches!(
                        self.orchestrator
                            .retry_policy
                            .classify(&error, attempt_number),
                        MatrixRetryDecision::DoNotRetry { .. }
                    )
                {
                    self.pending_store
                        .mark_pending_command_consumed(
                            tombstone_scope.clone(),
                            delivery_id,
                            attempt_id,
                        )
                        .await?;
                }
                return Err(error);
            }
        };
        if outcome.status != MatrixTerminalStatus::RetryScheduled {
            self.pending_store
                .mark_pending_command_consumed(tombstone_scope, delivery_id, attempt_id)
                .await?;
        }
        Ok(outcome)
    }
}

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

pub struct MatrixRetryWorkerDeps<F>
where
    F: RootFilesystem + 'static,
{
    pub metadata_store: Arc<FilesystemMatrixOutboundMetadataStore<F>>,
    pub pending_store: Arc<FilesystemMatrixPendingIntentStore<F>>,
    pub delivery_port: Arc<dyn MatrixDeliveryPort>,
    pub credential_resolver: Arc<dyn MatrixCredentialResolver>,
    pub retry_policy: Arc<dyn RetryPolicy>,
    pub scopes: Vec<TurnScope>,
}

impl<F> Clone for MatrixRetryWorkerDeps<F>
where
    F: RootFilesystem + 'static,
{
    fn clone(&self) -> Self {
        Self {
            metadata_store: Arc::clone(&self.metadata_store),
            pending_store: Arc::clone(&self.pending_store),
            delivery_port: Arc::clone(&self.delivery_port),
            credential_resolver: Arc::clone(&self.credential_resolver),
            retry_policy: Arc::clone(&self.retry_policy),
            scopes: self.scopes.clone(),
        }
    }
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
    cancel: CancellationToken,
    handle: JoinHandle<()>,
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
                tracing::debug!(?error, "matrix retry worker task join failed");
            }
            Err(_) => {
                tracing::debug!(
                    ?timeout,
                    "matrix retry worker did not stop before shutdown timeout; aborting"
                );
                handle.abort();
                if let Err(error) = handle.await
                    && error.is_panic()
                {
                    tracing::debug!(?error, "aborted matrix retry worker task panicked");
                }
            }
        }
    }
}

pub fn spawn_matrix_retry_worker<F>(
    settings: MatrixRetryWorkerSettings,
    deps: MatrixRetryWorkerDeps<F>,
) -> Result<Option<MatrixRetryWorkerRuntimeHandle>, MatrixOutboundContractError>
where
    F: RootFilesystem + Send + Sync + 'static,
{
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

async fn run_matrix_retry_worker<F>(
    settings: MatrixRetryWorkerSettings,
    deps: MatrixRetryWorkerDeps<F>,
    cancel: CancellationToken,
) where
    F: RootFilesystem + Send + Sync + 'static,
{
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
                tracing::debug!(
                    scopes_scanned = report.scopes_scanned,
                    due_schedules = report.due_schedules,
                    attempted = report.attempted,
                    delivered = report.delivered,
                    retry_scheduled = report.retry_scheduled,
                    skipped = report.skipped,
                    failed = report.failed,
                    "matrix retry worker tick completed"
                );
            }
            Err(error) => {
                tracing::debug!(?error, "matrix retry worker tick failed");
            }
        }
        let delay = settings.poll_interval + matrix_retry_jitter_delay(settings.tick_jitter_max);
        if !matrix_retry_sleep_or_cancel(delay, &cancel).await {
            return;
        }
    }
}

pub async fn matrix_retry_worker_tick_once<F>(
    settings: &MatrixRetryWorkerSettings,
    deps: &MatrixRetryWorkerDeps<F>,
    now: DateTime<Utc>,
    cancel: &CancellationToken,
) -> Result<MatrixRetryWorkerTickReport, MatrixOutboundContractError>
where
    F: RootFilesystem + 'static,
{
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
            .metadata_store
            .list_due_retry_schedules(scope.clone(), now, settings.max_entries_per_scope)
            .await?;
        report.due_schedules += schedules.len();
        for schedule in schedules {
            if cancel.is_cancelled() {
                break;
            }
            report.attempted += 1;
            let orchestrator = MatrixOutboundOrchestrator::new(
                deps.delivery_port.as_ref(),
                deps.credential_resolver.as_ref(),
                deps.metadata_store.as_ref(),
                deps.retry_policy.as_ref(),
            );
            let bridge =
                MatrixProductionDeliveryBridge::new(deps.pending_store.as_ref(), &orchestrator);
            match MatrixRetryExecutor::execute_due_retry_from_store(
                deps.metadata_store.as_ref(),
                deps.pending_store.as_ref(),
                &bridge,
                schedule.scope,
                schedule.delivery_id,
                now,
            )
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
                    tracing::debug!(
                        delivery_id = %schedule.delivery_id,
                        reason = ?error.reason,
                        "matrix retry worker attempt failed"
                    );
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
    #[error("matrix metadata serialization failed: {0}")]
    Serialization(String),
    #[error("matrix metadata backend failed: {0}")]
    Backend(String),
}

impl From<serde_json::Error> for MatrixOutboundContractError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<FilesystemError> for MatrixOutboundContractError {
    fn from(value: FilesystemError) -> Self {
        Self::Backend(value.to_string())
    }
}

impl From<OutboundError> for MatrixOutboundContractError {
    fn from(value: OutboundError) -> Self {
        Self::Backend(value.to_string())
    }
}

fn leaks_raw_matrix_value(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    value.starts_with('$')
        || value.starts_with('!')
        || value.starts_with('@')
        || value.contains("://")
        || normalized.contains("access_token")
        || value.contains("Bearer ")
        || normalized.starts_with("secret:")
        || normalized.contains(".secret.")
}

fn is_canonical_sha256_fingerprint(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_terminal_delivery_status(status: OutboundDeliveryStatus) -> bool {
    matches!(
        status,
        OutboundDeliveryStatus::Delivered
            | OutboundDeliveryStatus::Failed
            | OutboundDeliveryStatus::DeadLettered
    )
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix_outbound::fakes::{
        FakeMatrixCredentialResolver, FakeMatrixDeliveryPort, FakeMatrixOutboundMetadataStore,
        route_forgery_fixture,
    };
    use async_trait::async_trait;
    use ironclaw_event_projections::ProjectionCursor;
    use ironclaw_filesystem::{CasExpectation, InMemoryBackend, ScopedFilesystem};
    use ironclaw_host_api::{
        AgentId, MountAlias, MountGrant, MountPermissions, MountView, ProjectId, TenantId,
        ThreadId, UserId, VirtualPath,
    };
    use ironclaw_matrix_adapter::{
        MatrixParsePolicy, MatrixProductAdapter, MatrixProductAdapterConfig,
    };
    use ironclaw_outbound::{
        AdvanceSubscriptionCursorRequest, CommunicationDeliveryIntent,
        CommunicationDeliveryResolutionRequest, CommunicationModality, CommunicationPreferenceKey,
        CommunicationPreferenceRecord, CommunicationPreferenceRepository,
        CommunicationPreferenceVersion, DeliveryDefaultScope, InMemoryOutboundStateStore,
        LoadSubscriptionCursorRequest, OutboundDeliveryAttempt, OutboundPolicyService,
        OutboundPushPlan, OutboundPushTargetRequest, ProjectionSubscriptionRecord,
        ReplyTargetBindingClaim, ReplyTargetBindingValidator, RequestedOutboundContext,
        RequestedOutboundKind, ThreadNotificationPolicy, ThreadProjectionAccessClaim,
        ThreadProjectionAccessPolicy, ThreadProjectionAccessRequest,
        VersionedCommunicationPreferenceRecord, WriteCommunicationPreferenceRequest,
    };
    use ironclaw_product_adapters::{
        AdapterInstallationId, AuthRequirement, ExternalConversationRef, FakeOutboundDeliverySink,
        FakeProtocolHttpEgress, FinalReplyView, ProductAdapterId, ProductOutboundPayload,
        ProductRenderOutcome, ProjectionCursor as ProductProjectionCursor,
    };
    use ironclaw_product_workflow::{
        ProductOutboundDeliveryOutcome, ProductOutboundDeliveryRequest,
        ProductOutboundTargetResolver, ProductWorkflowError, VerifiedProductOutboundTargetMetadata,
        prepare_and_render_product_outbound,
    };
    use ironclaw_turns::{TurnActor, TurnRunId};
    use serde_json::json;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::sync::Mutex;

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
            event_id_fingerprint: canonical_fingerprint("event-1"),
            transaction_id: command.transaction_id.clone(),
            command_kind: command.command_kind,
            delivered_at: Utc::now(),
            verified: true,
            homeserver_origin_fingerprint: canonical_fingerprint("homeserver-1"),
            room_fingerprint: command.room_id.fingerprint(),
            installation_scoped_credential_ref: canonical_fingerprint("credential-handle-1"),
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
            _route: ValidatedDeliveryRoute,
            _credential: ResolvedCredentialHandle,
            attempt: DeliveryAttemptContext,
        ) -> DeliveryPortResult {
            self.calls
                .lock()
                .expect("recorded call lock")
                .push((command.clone(), attempt));
            let ProtocolDeliveryIntent::Matrix(matrix_command) = command;
            DeliveryPortResult::Accepted(ProtocolDeliveryEvidence::Matrix(accepted_evidence(
                &matrix_command,
            )))
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

    async fn put_pending_intent_bytes(
        filesystem: &ScopedFilesystem<InMemoryBackend>,
        scope: &TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
        bytes: Vec<u8>,
    ) {
        let path = matrix_pending_intent_path(scope, delivery_id, attempt_id)
            .expect("pending intent path");
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
    }

    impl RecordingReplyTargetBindingValidator {
        fn allow(&self, target: ReplyTargetBindingRef) {
            self.allowed_targets
                .lock()
                .expect("validator lock")
                .insert(target);
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

    #[derive(Default)]
    struct RecordingProductOutboundTargetResolver;

    #[async_trait]
    impl ProductOutboundTargetResolver for RecordingProductOutboundTargetResolver {
        async fn resolve_product_outbound_target_metadata(
            &self,
            _target: &ironclaw_outbound::ValidatedReplyTargetBinding,
            _require_direct_message: bool,
        ) -> Result<VerifiedProductOutboundTargetMetadata, ProductWorkflowError> {
            Ok(VerifiedProductOutboundTargetMetadata {
                external_conversation_ref: ExternalConversationRef::new(
                    None,
                    "!room:example.org",
                    Some("$root:example.org"),
                    Some("$reply:example.org"),
                )
                .expect("valid Matrix conversation ref"),
                external_actor_ref: None,
            })
        }
    }

    fn matrix_product_adapter() -> MatrixProductAdapter {
        MatrixProductAdapter::new(MatrixProductAdapterConfig {
            adapter_id: ProductAdapterId::new("matrix").expect("valid adapter id"),
            installation_id: AdapterInstallationId::new("inst_matrix")
                .expect("valid installation id"),
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
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
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
        assert_eq!(
            store.evidence()[0].1.event_id_fingerprint,
            canonical_fingerprint("event-1")
        );
    }

    #[tokio::test]
    async fn adapter_pending_matrix_intent_can_join_composition_orchestrator_without_http() {
        let workflow_scope = scope();
        let outbound_store = InMemoryOutboundStateStore::default();
        let validator = RecordingReplyTargetBindingValidator::default();
        validator.allow(workflow_reply_target());
        let preferences = RecordingPreferenceRepository::default();
        preferences.seed(workflow_preference_record(&workflow_scope));
        let resolver = RecordingProductOutboundTargetResolver;
        let access_policy = AllowAllProjectionAccessPolicy;
        let outbound_policy =
            OutboundPolicyService::new(&outbound_store, &access_policy, &validator);
        let adapter = matrix_product_adapter();
        let egress = FakeProtocolHttpEgress::new(Vec::<String>::new());
        let delivery_sink = FakeOutboundDeliverySink::new();

        let outcome = prepare_and_render_product_outbound(
            &outbound_policy,
            &preferences,
            &resolver,
            ProductOutboundDeliveryRequest {
                delivery: requested_matrix_delivery(workflow_scope.clone()),
                payload: matrix_workflow_payload(),
                projection_cursor: ProductProjectionCursor::new("cursor:matrix:composition-bridge")
                    .expect("valid projection cursor"),
                adapter: &adapter,
                egress: &egress,
                delivery_sink: &delivery_sink,
                require_direct_message_target: false,
            },
        )
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

        let adapter_intent = adapter
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
                policy_revision: "policy-rev-1".into(),
                homeserver_origin_fingerprint: canonical_fingerprint("homeserver-1"),
                room_fingerprint: command.room_id.fingerprint(),
                egress_target_index: 0,
                credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
                reply_target_binding_ref: workflow_reply_target(),
                allowed_command_kinds: vec![MatrixCommandKind::SendText],
            },
        );
        let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
        let port = FakeMatrixDeliveryPort::default();
        port.push_result(DeliveryPortResult::Accepted(
            ProtocolDeliveryEvidence::Matrix(accepted_evidence(&command)),
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
            .consume_pending_intent(
                command.clone(),
                route.clone(),
                grant,
                DeliveryAttemptContext {
                    delivery_id: outbound_attempt.delivery_id,
                    attempt_number: 1,
                    transaction_id: command.transaction_id.clone(),
                    started_at: Utc::now(),
                },
            )
            .await
            .expect("converted pending intent should be delivered by fake port");

        assert_eq!(outcome.status, MatrixTerminalStatus::Delivered);
        assert_eq!(port.calls(), vec![ProtocolDeliveryIntent::Matrix(command)]);
        assert_eq!(store.statuses(), vec![OutboundDeliveryStatus::Delivered]);
        assert_eq!(store.failure_kinds(), vec![None]);
        assert_eq!(store.evidence().len(), 1);
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
            let mut evidence = accepted_evidence(&command());
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
    async fn durable_matrix_metadata_store_does_not_write_local_status_when_canonical_update_fails()
    {
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
        let evidence = ValidatedMatrixDeliveryEvidence::new_redacted(accepted_evidence(&command))
            .expect("fixture evidence is redacted");

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
        let writer = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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
        let writer = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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

        let first_reader = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
        let first_load = first_reader
            .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
            .await
            .expect("load pending Matrix command")
            .expect("pending command should load");

        assert_eq!(first_load, command);

        let fresh_reader =
            FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(backend));
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
        let pending_writer = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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
        port.push_result(DeliveryPortResult::Accepted(
            ProtocolDeliveryEvidence::Matrix(accepted_evidence(&command)),
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
        let pending_reader = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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
        let pending_writer = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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
        let pending_reader = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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
                    .claim_due_retry_schedule(
                        first_scope,
                        delivery_id,
                        now,
                        MATRIX_RETRY_CLAIM_LEASE,
                    )
                    .await
            },
            async move {
                second_store
                    .claim_due_retry_schedule(
                        second_scope,
                        delivery_id,
                        now,
                        MATRIX_RETRY_CLAIM_LEASE,
                    )
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
        let pending_store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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
        let pending_store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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

        let outcome = MatrixRetryExecutor::execute_due_retry(
            &metadata_store,
            &pending_store,
            &bridge,
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
        let pending_store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
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

        let outcome = MatrixRetryExecutor::execute_due_retry_from_store(
            &metadata_store,
            &pending_store,
            &bridge,
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
        let deps = MatrixRetryWorkerDeps {
            metadata_store: Arc::clone(&metadata_store),
            pending_store,
            delivery_port: Arc::clone(&port) as Arc<dyn MatrixDeliveryPort>,
            credential_resolver: Arc::new(FakeMatrixCredentialResolver::with_credential(
                ResolvedCredentialHandle {
                    credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
                },
            )),
            retry_policy: Arc::new(retry_policy()),
            scopes: vec![route.scope().clone()],
        };
        let settings = MatrixRetryWorkerSettings {
            enabled: true,
            max_entries_per_scope: 10,
            ..MatrixRetryWorkerSettings::default()
        };

        let report =
            matrix_retry_worker_tick_once(&settings, &deps, due_at, &CancellationToken::new())
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
        let deps = MatrixRetryWorkerDeps {
            metadata_store: Arc::clone(&metadata_store),
            pending_store,
            delivery_port: Arc::clone(&port) as Arc<dyn MatrixDeliveryPort>,
            credential_resolver: Arc::new(FakeMatrixCredentialResolver::with_credential(
                ResolvedCredentialHandle {
                    credential_handle_fingerprint: canonical_fingerprint("revoked-credential"),
                },
            )),
            retry_policy: Arc::new(retry_policy()),
            scopes: vec![route.scope().clone()],
        };
        let settings = MatrixRetryWorkerSettings {
            enabled: true,
            max_entries_per_scope: 10,
            ..MatrixRetryWorkerSettings::default()
        };

        let report =
            matrix_retry_worker_tick_once(&settings, &deps, due_at, &CancellationToken::new())
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
    async fn matrix_retry_worker_spawn_disabled_and_shutdown_paths_are_explicit() {
        let backend = Arc::new(InMemoryBackend::new());
        let metadata_store = Arc::new(FilesystemMatrixOutboundMetadataStore::new(
            matrix_metadata_filesystem(Arc::clone(&backend)),
            outbound_state_store(),
        ));
        let pending_store = Arc::new(FilesystemMatrixPendingIntentStore::new(
            matrix_metadata_filesystem(Arc::clone(&backend)),
        ));
        let deps = MatrixRetryWorkerDeps {
            metadata_store,
            pending_store,
            delivery_port: Arc::new(RecordingMatrixDeliveryPort::default()),
            credential_resolver: Arc::new(FakeMatrixCredentialResolver::with_credential(
                ResolvedCredentialHandle {
                    credential_handle_fingerprint: canonical_fingerprint("credential-handle-1"),
                },
            )),
            retry_policy: Arc::new(retry_policy()),
            scopes: vec![scope()],
        };

        let disabled =
            spawn_matrix_retry_worker(MatrixRetryWorkerSettings::default(), deps.clone())
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
        let pending_store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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

        let outcome = MatrixRetryExecutor::execute_due_retry(
            &metadata_store,
            &pending_store,
            &bridge,
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
        let pending_store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
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

        let outcome = MatrixRetryExecutor::execute_due_retry(
            &metadata_store,
            &pending_store,
            &bridge,
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
        let pending_store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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

        let outcome = MatrixRetryExecutor::execute_due_retry(
            &metadata_store,
            &pending_store,
            &bridge,
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
        let pending_store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
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

        let outcome = MatrixRetryExecutor::execute_due_retry(
            &metadata_store,
            &pending_store,
            &bridge,
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
        let pending_store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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

        let error = MatrixRetryExecutor::execute_due_retry(
            &metadata_store,
            &pending_store,
            &bridge,
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
        let pending_store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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

        let error = MatrixRetryExecutor::execute_due_retry(
            &metadata_store,
            &pending_store,
            &bridge,
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
        let pending_store = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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

        let error = MatrixRetryExecutor::execute_due_retry(
            &metadata_store,
            &pending_store,
            &bridge,
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
        let pending_writer = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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
        let pending_reader = FilesystemMatrixPendingIntentStore::new(matrix_metadata_filesystem(
            Arc::clone(&backend),
        ));
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
        let mut evidence = accepted_evidence(&command);
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
            .consume_pending_intent(
                command.clone(),
                route.clone(),
                grant,
                attempt(&route, &command),
            )
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
        let mut evidence = accepted_evidence(&command);
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
            .consume_pending_intent(
                command.clone(),
                route.clone(),
                grant,
                attempt(&route, &command),
            )
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
        let mut evidence = accepted_evidence(&command);
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
        let mut exhausted_attempt = attempt(&route, &command);
        exhausted_attempt.attempt_number = 3;

        let error = orchestrator
            .consume_pending_intent(command.clone(), route.clone(), grant, exhausted_attempt)
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
    }

    #[tokio::test]
    async fn orchestrator_terminalizes_wrong_credential_evidence_after_retry_exhaustion() {
        let command = command();
        let route = route();
        let owner = owner();
        let grant = SealedDeliveryGrant::mint_for_matrix(&owner, &route);
        let mut evidence = accepted_evidence(&command);
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
        let mut exhausted_attempt = attempt(&route, &command);
        exhausted_attempt.attempt_number = 3;

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
}
