//! Matrix-local shared outbound handoff contracts.
//!
//! These types freeze the Matrix shared outbound boundary without changing
//! global outbound status, retry, or evidence schemas. ProductWorkflow keeps
//! Matrix command intent pending; this bridge records terminal status only
//! after a delivery port returns protocol evidence or a sanitized error.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ironclaw_common::hashing::sha256_hex;
use ironclaw_filesystem::{
    CasApply, CasUpdateError, ContentType, Entry, FileType, FilesystemError, RootFilesystem,
    ScopedFilesystem, cas_update,
};
use ironclaw_host_api::{
    CapabilityId, ExtensionId, NetworkMethod, NetworkPolicy, NetworkScheme, NetworkTargetPattern,
    ResourceScope, RuntimeCredentialTarget, RuntimeHttpEgressError, RuntimeHttpEgressRequest,
    RuntimeHttpEgressResponse, RuntimeKind, ScopedPath, SecretHandle, TrustClass,
};
use ironclaw_host_runtime::{
    HostRuntimeCredentialMaterial, HostRuntimeHttpEgressPort, HostRuntimeHttpEgressRequest,
};
use ironclaw_outbound::{
    DeliveryFailureKind, OutboundDeliveryId, OutboundDeliveryStatus, OutboundError,
    OutboundStateStore, UpdateDeliveryStatusRequest,
};
use ironclaw_secrets::SecretMaterial;
use ironclaw_turns::{ReplyTargetBindingRef, TurnScope};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;
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

    pub fn route(&self) -> &FrozenProductDeliveryRoute {
        &self.route
    }

    pub fn grant(&self) -> &SealedDeliveryGrant {
        &self.grant
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
    pub delivery_id: OutboundDeliveryId,
    pub attempt_number: u32,
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
        attempt: &DeliveryAttemptContext,
    ) -> Result<(), MatrixOutboundContractError> {
        self.validate_redacted()?;
        if !self.verified
            || !(200..300).contains(&self.http_status)
            || self.delivery_id != attempt.delivery_id
            || self.attempt_number != attempt.attempt_number
            || self.transaction_id != command.transaction_id
            || self.transaction_id != attempt.transaction_id
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
    pub fn new_for_delivery(
        evidence: MatrixDeliveryEvidenceV1,
        command: &MatrixOutboundCommand,
        metadata: &MatrixRouteMetadata,
        attempt: &DeliveryAttemptContext,
    ) -> Result<Self, MatrixOutboundContractError> {
        evidence.validate_for_delivery(command, metadata, attempt)?;
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

    pub fn with_retry_hint(mut self, after: Duration) -> Self {
        self.retry_hint = Some(RetryHint { after });
        self
    }

    pub fn with_status_family(mut self, status_family: Option<HttpStatusFamily>) -> Self {
        self.status_family = status_family;
        self
    }

    pub fn with_matrix_errcode(mut self, matrix_errcode: MatrixErrcode) -> Self {
        self.matrix_errcode = Some(matrix_errcode);
        self
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
    MatrixBadRequest,
    MatrixNotFound,
    MatrixMessageTooLarge,
    MatrixUnsupportedRoomVersion,
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
            DeliveryReasonCode::MatrixBadRequest => "matrix homeserver rejected the request",
            DeliveryReasonCode::MatrixNotFound => "matrix homeserver could not find the target",
            DeliveryReasonCode::MatrixMessageTooLarge => "matrix message was too large",
            DeliveryReasonCode::MatrixUnsupportedRoomVersion => {
                "matrix room version is unsupported"
            }
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

#[derive(Debug, Clone)]
pub struct MatrixHttpDeliveryEndpoint {
    homeserver_origin: String,
    scheme: NetworkScheme,
    host: String,
    port: Option<u16>,
    credential_secret: SecretHandle,
    credential_material: SecretMaterial,
    credential_handle_fingerprint: String,
    capability_id: CapabilityId,
    response_body_limit: u64,
    timeout_ms: Option<u32>,
}

impl MatrixHttpDeliveryEndpoint {
    pub fn new(
        homeserver_origin: impl Into<String>,
        credential_secret: SecretHandle,
        credential_material: SecretMaterial,
        credential_handle_fingerprint: impl Into<String>,
        capability_id: CapabilityId,
    ) -> Result<Self, DeliveryError> {
        let homeserver_origin = homeserver_origin.into();
        let (scheme, host, port) = parse_matrix_homeserver_origin(&homeserver_origin)?;
        let credential_handle_fingerprint = credential_handle_fingerprint.into();
        if !is_canonical_sha256_fingerprint(&credential_handle_fingerprint) {
            return Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget));
        }
        Ok(Self {
            homeserver_origin: canonical_matrix_homeserver_origin(scheme, &host, port),
            scheme,
            host,
            port,
            credential_secret,
            credential_material,
            credential_handle_fingerprint,
            capability_id,
            response_body_limit: 4096,
            timeout_ms: Some(10_000),
        })
    }

    pub fn with_response_body_limit(
        mut self,
        response_body_limit: u64,
    ) -> Result<Self, DeliveryError> {
        if !(256..=16 * 1024 * 1024).contains(&response_body_limit) {
            return Err(DeliveryError::new(DeliveryReasonCode::MatrixBadRequest));
        }
        self.response_body_limit = response_body_limit;
        Ok(self)
    }

    pub fn with_timeout_ms(mut self, timeout_ms: Option<u32>) -> Result<Self, DeliveryError> {
        if let Some(timeout_ms) = timeout_ms
            && !(100..=120_000).contains(&timeout_ms)
        {
            return Err(DeliveryError::new(DeliveryReasonCode::MatrixBadRequest));
        }
        self.timeout_ms = timeout_ms;
        Ok(self)
    }
}

pub trait MatrixHttpDeliveryEndpointResolver: Send + Sync {
    fn resolve_endpoint(
        &self,
        route: &ValidatedDeliveryRoute,
        credential: &ResolvedCredentialHandle,
    ) -> Option<MatrixHttpDeliveryEndpoint>;
}

pub struct MatrixHttpDeliveryPort {
    egress: Arc<dyn MatrixHostHttpEgress>,
    endpoint_resolver: Arc<dyn MatrixHttpDeliveryEndpointResolver>,
}

impl MatrixHttpDeliveryPort {
    pub fn new(
        egress: Arc<dyn MatrixHostHttpEgress>,
        endpoint_resolver: Arc<dyn MatrixHttpDeliveryEndpointResolver>,
    ) -> Self {
        Self {
            egress,
            endpoint_resolver,
        }
    }
}

#[async_trait]
pub trait MatrixHostHttpEgress: Send + Sync {
    async fn execute_matrix_http(
        &self,
        request: HostRuntimeHttpEgressRequest,
    ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError>;
}

#[async_trait]
impl MatrixHostHttpEgress for HostRuntimeHttpEgressPort {
    async fn execute_matrix_http(
        &self,
        request: HostRuntimeHttpEgressRequest,
    ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
        self.execute(request).await
    }
}

#[async_trait]
impl MatrixDeliveryPort for MatrixHttpDeliveryPort {
    async fn deliver(
        &self,
        command: ProtocolDeliveryIntent,
        route: ValidatedDeliveryRoute,
        credential: ResolvedCredentialHandle,
        attempt: DeliveryAttemptContext,
    ) -> DeliveryPortResult {
        let ProtocolDeliveryIntent::Matrix(command) = command;
        let metadata = route.matrix_metadata().clone();
        let Some(endpoint) = self.endpoint_resolver.resolve_endpoint(&route, &credential) else {
            return DeliveryPortResult::Rejected(DeliveryError::new(
                DeliveryReasonCode::MissingMatrixRoute,
            ));
        };
        if endpoint.credential_handle_fingerprint != credential.credential_handle_fingerprint
            || endpoint.credential_handle_fingerprint != metadata.credential_handle_fingerprint
            || redacted_sha256_fingerprint(endpoint.homeserver_origin.as_bytes())
                != metadata.homeserver_origin_fingerprint
        {
            return DeliveryPortResult::Rejected(DeliveryError::new(
                DeliveryReasonCode::UnauthorizedTarget,
            ));
        }

        let request = matrix_send_request(&route, &command, &endpoint);
        let host_request = match matrix_host_http_request(request, &endpoint) {
            Ok(request) => request,
            Err(error) => return DeliveryPortResult::Rejected(error),
        };
        let started_at = Utc::now();
        match self.egress.execute_matrix_http(host_request).await {
            Ok(response) => classify_matrix_http_response(
                response, &command, &metadata, &endpoint, &attempt, started_at,
            ),
            Err(error) => DeliveryPortResult::Rejected(matrix_delivery_error_from_egress(error)),
        }
    }
}

fn matrix_send_request(
    route: &ValidatedDeliveryRoute,
    command: &MatrixOutboundCommand,
    endpoint: &MatrixHttpDeliveryEndpoint,
) -> RuntimeHttpEgressRequest {
    let room = encode_matrix_path_segment(command.room_id.as_str());
    let txn = encode_matrix_path_segment(command.transaction_id.as_str());
    RuntimeHttpEgressRequest {
        runtime: RuntimeKind::FirstParty,
        scope: route.route.scope().to_resource_scope(),
        capability_id: endpoint.capability_id.clone(),
        method: NetworkMethod::Put,
        url: format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            endpoint.homeserver_origin, room, txn
        ),
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: serde_json::to_vec(command.body.as_json()).unwrap_or_else(|_| b"{}".to_vec()),
        network_policy: NetworkPolicy {
            allowed_targets: vec![NetworkTargetPattern {
                scheme: Some(endpoint.scheme),
                host_pattern: endpoint.host.clone(),
                port: endpoint.port,
            }],
            deny_private_ip_ranges: true,
            max_egress_bytes: Some(endpoint.response_body_limit),
        },
        credential_injections: Vec::new(),
        response_body_limit: Some(endpoint.response_body_limit),
        save_body_to: None,
        timeout_ms: endpoint.timeout_ms,
    }
}

fn matrix_host_http_request(
    request: RuntimeHttpEgressRequest,
    endpoint: &MatrixHttpDeliveryEndpoint,
) -> Result<HostRuntimeHttpEgressRequest, DeliveryError> {
    Ok(HostRuntimeHttpEgressRequest {
        extension_id: matrix_extension_id()?,
        trust: TrustClass::System,
        request,
        credentials: vec![HostRuntimeCredentialMaterial {
            handle: endpoint.credential_secret.clone(),
            material: endpoint.credential_material.clone(),
            target: RuntimeCredentialTarget::Header {
                name: "authorization".to_string(),
                prefix: Some("Bearer ".to_string()),
            },
            required: true,
        }],
    })
}

fn matrix_extension_id() -> Result<ExtensionId, DeliveryError> {
    ExtensionId::new("ironclaw_matrix")
        .map_err(|_| DeliveryError::new(DeliveryReasonCode::MatrixBadRequest))
}

fn classify_matrix_http_response(
    response: RuntimeHttpEgressResponse,
    command: &MatrixOutboundCommand,
    metadata: &MatrixRouteMetadata,
    endpoint: &MatrixHttpDeliveryEndpoint,
    attempt: &DeliveryAttemptContext,
    started_at: DateTime<Utc>,
) -> DeliveryPortResult {
    let status_family = http_status_family(response.status);
    let body = serde_json::from_slice::<Value>(&response.body).ok();
    if (200..300).contains(&response.status) {
        let Some(event_id) = body
            .as_ref()
            .and_then(|body| body.get("event_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        else {
            return DeliveryPortResult::Rejected(
                DeliveryError::new(DeliveryReasonCode::MatrixMalformedResponse)
                    .with_status_family(status_family),
            );
        };
        return DeliveryPortResult::Accepted(ProtocolDeliveryEvidence::Matrix(
            MatrixDeliveryEvidenceV1 {
                schema_version: 1,
                delivery_id: attempt.delivery_id,
                attempt_number: attempt.attempt_number,
                event_id_fingerprint: redacted_sha256_fingerprint(event_id.as_bytes()),
                transaction_id: command.transaction_id.clone(),
                command_kind: command.command_kind,
                delivered_at: Utc::now(),
                verified: true,
                homeserver_origin_fingerprint: metadata.homeserver_origin_fingerprint.clone(),
                room_fingerprint: metadata.room_fingerprint.clone(),
                installation_scoped_credential_ref: endpoint.credential_handle_fingerprint.clone(),
                http_status: response.status,
                latency_ms: Utc::now()
                    .signed_duration_since(started_at)
                    .num_milliseconds()
                    .max(0) as u64,
            },
        ));
    }

    let matrix_errcode = body
        .as_ref()
        .and_then(|body| body.get("errcode"))
        .and_then(Value::as_str)
        .map(MatrixErrcode::from_matrix_errcode);
    let mut error = DeliveryError::new(reason_for_matrix_http_status(
        response.status,
        matrix_errcode,
    ))
    .with_status_family(status_family);
    if let Some(errcode) = matrix_errcode {
        error = error.with_matrix_errcode(errcode);
    }
    if matches!(error.reason, DeliveryReasonCode::MatrixRateLimited)
        && let Some(after) = matrix_retry_after(&response, body.as_ref())
    {
        error = error.with_retry_hint(after);
    }
    DeliveryPortResult::Rejected(error)
}

fn reason_for_matrix_http_status(
    status: u16,
    matrix_errcode: Option<MatrixErrcode>,
) -> DeliveryReasonCode {
    match (status, matrix_errcode) {
        (429, _) | (_, Some(MatrixErrcode::LimitExceeded)) => DeliveryReasonCode::MatrixRateLimited,
        (401 | 403, _)
        | (
            _,
            Some(
                MatrixErrcode::Forbidden
                | MatrixErrcode::UnknownToken
                | MatrixErrcode::UserDeactivated,
            ),
        ) => DeliveryReasonCode::UnauthorizedTarget,
        (_, Some(MatrixErrcode::TooLarge)) => DeliveryReasonCode::MatrixMessageTooLarge,
        (_, Some(MatrixErrcode::UnsupportedRoomVersion)) => {
            DeliveryReasonCode::MatrixUnsupportedRoomVersion
        }
        (_, Some(MatrixErrcode::NotFound)) => DeliveryReasonCode::MatrixNotFound,
        (_, Some(MatrixErrcode::BadJson)) => DeliveryReasonCode::MatrixBadRequest,
        (500..=599, _) => DeliveryReasonCode::MatrixServerError,
        (300..=399, _) => DeliveryReasonCode::UnauthorizedTarget,
        (400..=499, _) => DeliveryReasonCode::MatrixBadRequest,
        _ => DeliveryReasonCode::MatrixMalformedResponse,
    }
}

fn matrix_delivery_error_from_egress(error: RuntimeHttpEgressError) -> DeliveryError {
    match error.reason_code() {
        ironclaw_host_api::RuntimeHttpEgressReasonCode::CredentialUnavailable
        | ironclaw_host_api::RuntimeHttpEgressReasonCode::RequestDenied
        | ironclaw_host_api::RuntimeHttpEgressReasonCode::PolicyDenied => {
            DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget)
        }
        ironclaw_host_api::RuntimeHttpEgressReasonCode::NetworkError => {
            DeliveryError::new(DeliveryReasonCode::MatrixTimeout)
        }
        ironclaw_host_api::RuntimeHttpEgressReasonCode::ResponseError => {
            DeliveryError::new(DeliveryReasonCode::MatrixServerError)
        }
        ironclaw_host_api::RuntimeHttpEgressReasonCode::ResponseBodyLimitExceeded => {
            DeliveryError::new(DeliveryReasonCode::MatrixMalformedResponse)
        }
    }
}

fn matrix_retry_after(
    response: &RuntimeHttpEgressResponse,
    body: Option<&Value>,
) -> Option<Duration> {
    body.and_then(|body| body.get("retry_after_ms"))
        .and_then(Value::as_u64)
        .map(Duration::from_millis)
        .or_else(|| {
            response
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                .and_then(|(_, value)| value.trim().parse::<u64>().ok())
                .map(Duration::from_secs)
        })
}

fn http_status_family(status: u16) -> Option<HttpStatusFamily> {
    Some(match status {
        100..=199 => HttpStatusFamily::Informational,
        200..=299 => HttpStatusFamily::Success,
        300..=399 => HttpStatusFamily::Redirect,
        400..=499 => HttpStatusFamily::ClientError,
        500..=599 => HttpStatusFamily::ServerError,
        _ => return None,
    })
}

fn parse_matrix_homeserver_origin(
    origin: &str,
) -> Result<(NetworkScheme, String, Option<u16>), DeliveryError> {
    let parsed = Url::parse(origin)
        .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))?;
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.cannot_be_a_base()
        || parsed.path() != "/"
    {
        return Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget));
    }
    let scheme = match parsed.scheme() {
        "https" => NetworkScheme::Https,
        _ => return Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget)),
    };
    let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) else {
        return Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget));
    };
    if host_is_disallowed_matrix_origin(&host) {
        return Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget));
    }
    Ok((scheme, host, parsed.port()))
}

fn host_is_disallowed_matrix_origin(host: &str) -> bool {
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return disallowed_matrix_ip(ip);
    }
    host.chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
}

fn disallowed_matrix_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}

fn canonical_matrix_homeserver_origin(
    scheme: NetworkScheme,
    host: &str,
    port: Option<u16>,
) -> String {
    let scheme = match scheme {
        NetworkScheme::Http => "http",
        NetworkScheme::Https => "https",
    };
    match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    }
}

fn redacted_sha256_fingerprint(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn encode_matrix_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
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
                    evidence, &command, &metadata, &attempt,
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
        | DeliveryReasonCode::MatrixBadRequest
        | DeliveryReasonCode::MatrixNotFound
        | DeliveryReasonCode::MatrixMessageTooLarge
        | DeliveryReasonCode::MatrixUnsupportedRoomVersion
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
pub mod fakes;

#[cfg(test)]
mod tests;
