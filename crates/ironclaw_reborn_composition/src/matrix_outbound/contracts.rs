use super::*;
use ironclaw_host_api::{AgentId, ProjectId, TenantId};

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

pub(crate) const MATRIX_SEND_PATH_PREFIX: &str = "/_matrix/client/v3/rooms/";
pub(crate) const MATRIX_SEND_EVENT_PATH: &str = "/send/m.room.message/";

pub(crate) fn matrix_send_policy_path(room_id: &str, transaction_id: &str) -> String {
    // Policy authorization uses the logical Matrix path before HTTP delivery
    // applies percent-encoding. The adapter policy rejects '%' so encoded path
    // shapes cannot bypass room/transaction canonicalization checks.
    format!("{MATRIX_SEND_PATH_PREFIX}{room_id}{MATRIX_SEND_EVENT_PATH}{transaction_id}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixPendingIntentBridgeContext {
    pub reply_target_binding_ref: ReplyTargetBindingRef,
    pub egress_target_index: u32,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatrixRoomId(String);

impl MatrixRoomId {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixOutboundContractError> {
        let value = value.into();
        ruma_common::RoomId::parse(value.as_str())
            .map_err(|_| MatrixOutboundContractError::InvalidRoomId)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn fingerprint(&self) -> String {
        matrix_room_fingerprint(&self.0)
    }
}

impl<'de> Deserialize<'de> for MatrixRoomId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
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
pub struct MatrixPolicyProviderScope {
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub project_id: Option<ProjectId>,
}

impl MatrixPolicyProviderScope {
    pub(crate) fn to_policy_resource_scope(&self, base_scope: &ResourceScope) -> ResourceScope {
        ResourceScope {
            tenant_id: self.tenant_id.clone(),
            user_id: base_scope.user_id.clone(),
            agent_id: Some(self.agent_id.clone()),
            project_id: self.project_id.clone(),
            mission_id: None,
            thread_id: None,
            invocation_id: base_scope.invocation_id,
        }
        .tenant_shared_managed_scope()
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
    pub policy_provider_scope: Option<MatrixPolicyProviderScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenProductDeliveryRoute {
    pub(crate) delivery_id: OutboundDeliveryId,
    pub(crate) scope: TurnScope,
    pub(crate) installation_id: String,
    pub(crate) adapter_id: String,
    pub(crate) metadata: MatrixRouteMetadata,
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
    pub(crate) delivery_id: OutboundDeliveryId,
    pub(crate) installation_id: String,
    pub(crate) adapter_id: String,
    pub(crate) policy_revision: String,
    pub(crate) homeserver_origin_fingerprint: String,
    pub(crate) room_fingerprint: String,
    pub(crate) egress_target_index: u32,
    pub(crate) credential_handle_fingerprint: String,
    pub(crate) allowed_command_kinds: Vec<MatrixCommandKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRetryExecutionContext {
    pub(crate) route: FrozenProductDeliveryRoute,
    pub(crate) grant: SealedDeliveryGrant,
}

impl MatrixRetryExecutionContext {
    pub(crate) fn new(
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
    pub(crate) route: FrozenProductDeliveryRoute,
}

impl ValidatedDeliveryRoute {
    pub fn delivery_id(&self) -> OutboundDeliveryId {
        self.route.delivery_id
    }

    pub fn matrix_metadata(&self) -> &MatrixRouteMetadata {
        self.route.matrix_metadata()
    }

    pub fn scope(&self) -> &TurnScope {
        self.route.scope()
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

pub(crate) fn validate_retry_execution_context(
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
    InstallationInactive,
    StalePolicyRevision,
    CredentialMismatch,
    RoomNotAllowed,
    EgressTargetDenied,
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
            DeliveryReasonCode::InstallationInactive => "matrix installation is inactive",
            DeliveryReasonCode::StalePolicyRevision => "matrix policy revision is stale",
            DeliveryReasonCode::CredentialMismatch => {
                "matrix credential fingerprint no longer matches policy"
            }
            DeliveryReasonCode::RoomNotAllowed => "matrix room is not allowed by current policy",
            DeliveryReasonCode::EgressTargetDenied => {
                "matrix egress target is denied by current policy"
            }
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
