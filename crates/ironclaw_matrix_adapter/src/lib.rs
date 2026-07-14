//! Pure Matrix parse/render contracts for the Reborn Matrix channel.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

#[cfg(not(target_arch = "wasm32"))]
use async_trait::async_trait;
#[cfg(not(target_arch = "wasm32"))]
use ironclaw_product_adapters::redaction::RedactedString;
#[cfg(not(target_arch = "wasm32"))]
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, ExternalActorRef, ExternalConversationRef,
    ExternalEventId, OutboundDeliverySink, ParsedProductInbound, ProductAdapter,
    ProductAdapterCapabilities, ProductAdapterError, ProductAdapterId, ProductAttachmentDescriptor,
    ProductAttachmentKind, ProductInboundPayload, ProductOutboundEnvelope, ProductOutboundPayload,
    ProductRenderOutcome, ProductSurfaceKind, ProductSynchronousResponse, ProductTriggerReason,
    ProductWorkflowRejectionKind, ProtocolAuthEvidence, ProtocolAuthFailure, ProtocolHttpEgress,
    UserMessagePayload,
};
#[cfg(not(target_arch = "wasm32"))]
use pulldown_cmark::{Options, Parser, html};
use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use serde_json::json;
use serde_json::{Map, Value};

const DIAGNOSTIC_MESSAGE_MAX: usize = 100;
const MAX_EVENT_FIELD: usize = 512;
const MAX_FORMATTED_BODY: usize = 64 * 1024;
const MAX_HTML_NESTING: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixParseInput {
    pub raw_event: Value,
    pub installation_id: String,
    pub policy: MatrixParsePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MatrixParsePolicy {
    /// Empty allowlists fail open for local contract tests and pre-transport
    /// parsing; production hosts should pass explicit policy from operator
    /// configuration before emitting workflow input.
    pub allowed_rooms: Vec<String>,
    pub allowed_senders: Vec<String>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixProductAdapterConfig {
    pub adapter_id: ProductAdapterId,
    pub installation_id: AdapterInstallationId,
    pub parse_policy: MatrixParsePolicy,
    pub auth_requirement: AuthRequirement,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
pub struct MatrixProductAdapter {
    config: MatrixProductAdapterConfig,
    capabilities: ProductAdapterCapabilities,
}

#[cfg(not(target_arch = "wasm32"))]
impl MatrixProductAdapter {
    pub fn new(config: MatrixProductAdapterConfig) -> Self {
        Self {
            config,
            capabilities: ProductAdapterCapabilities::external_channel_default(),
        }
    }

    pub fn config(&self) -> &MatrixProductAdapterConfig {
        &self.config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(not(target_arch = "wasm32"))]
pub struct MatrixRenderInput {
    pub envelope: ProductOutboundEnvelope,
    pub context: MatrixRenderContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixRenderContext {
    pub installation_id: String,
    pub route_metadata: MatrixRouteMetadata,
    pub allowed_target_rooms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedMatrixInbound {
    pub facts: MatrixInboundEvent,
    pub metadata: MatrixMessageMetadata,
    #[cfg(not(target_arch = "wasm32"))]
    pub product: ParsedProductInbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixInboundEvent {
    pub event_id: String,
    pub room_id: String,
    pub sender: String,
    pub event_type: String,
    pub origin_server_ts: Option<i64>,
    pub transaction_id: Option<String>,
    pub deduplication_key: String,
    pub relation: Option<MatrixRelation>,
    pub content: Option<MatrixMessageContent>,
    pub encryption: EncryptionState,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixMessageMetadata {
    pub room_id: String,
    pub event_id: String,
    pub sender: String,
    pub origin_server_ts: Option<i64>,
    pub event_type: String,
    pub transaction_id: Option<String>,
    pub msgtype: Option<String>,
    pub formatted_body: Option<String>,
    pub reply_to_event_id: Option<String>,
    pub relation: Option<MatrixRelation>,
    pub media_url: Option<String>,
    pub encryption: EncryptionState,
    pub diagnostics: Vec<MatrixAdapterDiagnostic>,
}

impl std::fmt::Debug for MatrixMessageMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixMessageMetadata")
            .field("room_id", &safe_debug_identifier(&self.room_id))
            .field("event_id", &safe_debug_identifier(&self.event_id))
            .field("sender", &safe_debug_identifier(&self.sender))
            .field("origin_server_ts", &self.origin_server_ts)
            .field("event_type", &safe_debug_identifier(&self.event_type))
            .field(
                "transaction_id",
                &redacted_debug_option(self.transaction_id.as_deref()),
            )
            .field("msgtype", &redacted_debug_option(self.msgtype.as_deref()))
            .field("formatted_body", &"<redacted>")
            .field(
                "reply_to_event_id",
                &redacted_debug_option(self.reply_to_event_id.as_deref()),
            )
            .field("relation", &"<redacted>")
            .field("media_url", &"<redacted>")
            .field("encryption", &"<redacted>")
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

impl MatrixMessageMetadata {
    fn from_facts(facts: &MatrixInboundEvent) -> Self {
        Self {
            room_id: facts.room_id.clone(),
            event_id: facts.event_id.clone(),
            sender: facts.sender.clone(),
            origin_server_ts: facts.origin_server_ts,
            event_type: facts.event_type.clone(),
            transaction_id: facts.transaction_id.clone(),
            msgtype: None,
            formatted_body: None,
            reply_to_event_id: None,
            relation: None,
            media_url: None,
            encryption: EncryptionState::Unencrypted,
            diagnostics: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixRelation {
    pub kind: RelationKind,
    pub event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixMessageContent {
    pub msgtype: String,
    pub body: String,
    pub formatted_body: Option<String>,
    pub media: Option<MatrixMediaMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixMediaMetadata {
    pub msgtype: String,
    pub mxc_url: Option<String>,
    pub mime_type: Option<String>,
    pub filename: Option<String>,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Reply,
    Thread,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EncryptionState {
    Unencrypted,
    Undecryptable {
        algorithm: Option<String>,
        session_id: Option<String>,
        reason_code: MatrixReasonCode,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixRouteMetadata {
    pub room_id: String,
    pub reply_to_event_id: Option<String>,
    pub thread_root_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MatrixOutboundCommand {
    SendMessage {
        room_id: String,
        txn_id: String,
        body: Value,
    },
    TypingIntent {
        room_id: String,
    },
    ReadReceiptIntent {
        room_id: String,
        event_id: String,
    },
}

impl MatrixOutboundCommand {
    pub fn room_id(&self) -> &str {
        match self {
            Self::SendMessage { room_id, .. }
            | Self::TypingIntent { room_id }
            | Self::ReadReceiptIntent { room_id, .. } => room_id,
        }
    }

    pub fn body(&self) -> &Value {
        match self {
            Self::SendMessage { body, .. } => body,
            Self::TypingIntent { .. } | Self::ReadReceiptIntent { .. } => &Value::Null,
        }
    }
}

pub type MatrixEventFacts = MatrixInboundEvent;
pub type MatrixRelationMetadata = MatrixRelation;
pub type MatrixParseDiagnostic = MatrixAdapterDiagnostic;
pub type MatrixRenderDiagnostic = MatrixAdapterDiagnostic;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixReasonCode {
    UnsupportedEventType,
    MalformedMatrixEvent,
    UndecryptableEvent,
    UnsupportedOutboundPayload,
    UnsafeFormattedBody,
    UnsupportedMsgtype,
    UnauthorizedRoom,
    UnauthorizedSender,
    UnauthorizedTargetRoom,
    MissingRouteMetadata,
    UnsupportedMediaKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixAdapterDiagnostic {
    pub reason_code: MatrixReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<Box<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_id: Option<Box<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<Box<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<Box<str>>,
    pub message: Box<str>,
}

impl std::fmt::Display for MatrixAdapterDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.reason_code, self.message)
    }
}

impl std::error::Error for MatrixAdapterDiagnostic {}

impl MatrixAdapterDiagnostic {
    fn new(reason_code: MatrixReasonCode, facts: PartialFacts, message: impl Into<String>) -> Self {
        Self {
            reason_code,
            event_id: facts.event_id.and_then(sanitize_matrix_id),
            room_id: facts.room_id.and_then(sanitize_matrix_id),
            event_type: facts.event_type.and_then(sanitize_event_type),
            sender: facts.sender.and_then(sanitize_matrix_id),
            message: sanitize_message(message.into()).into_boxed_str(),
        }
    }
}

#[derive(Default)]
struct PartialFacts {
    event_id: Option<String>,
    room_id: Option<String>,
    event_type: Option<String>,
    sender: Option<String>,
}

pub fn parse_matrix_event(
    input: MatrixParseInput,
) -> Result<ParsedMatrixInbound, MatrixAdapterDiagnostic> {
    let object = input.raw_event.as_object().ok_or_else(|| {
        MatrixAdapterDiagnostic::new(
            MatrixReasonCode::MalformedMatrixEvent,
            PartialFacts::default(),
            "matrix event must be a JSON object",
        )
    })?;
    let partial = partial_facts(object);
    let mut facts = facts_from_object(object, partial)?;
    facts.deduplication_key = format!("matrix-{}-{}", input.installation_id, facts.event_id);

    if !input.policy.allowed_rooms.is_empty()
        && !input
            .policy
            .allowed_rooms
            .iter()
            .any(|room| room == &facts.room_id)
    {
        return Err(diagnostic_for_facts(
            MatrixReasonCode::UnauthorizedRoom,
            &facts,
            "matrix room is not allowlisted",
        ));
    }
    if !input.policy.allowed_senders.is_empty()
        && !input
            .policy
            .allowed_senders
            .iter()
            .any(|sender| sender == &facts.sender)
    {
        return Err(diagnostic_for_facts(
            MatrixReasonCode::UnauthorizedSender,
            &facts,
            "matrix sender is not allowlisted",
        ));
    }

    match facts.event_type.as_str() {
        "m.room.message" => parse_room_message(object, facts, &input.installation_id),
        "m.room.encrypted" => parse_encrypted_event(object, facts, &input.installation_id),
        _ => Err(diagnostic_for_facts(
            MatrixReasonCode::UnsupportedEventType,
            &facts,
            "matrix event type is not supported by the parse contract",
        )),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn render_matrix_outbound(
    input: MatrixRenderInput,
) -> Result<MatrixOutboundCommand, MatrixAdapterDiagnostic> {
    if input.context.route_metadata.room_id.is_empty() {
        return Err(MatrixAdapterDiagnostic::new(
            MatrixReasonCode::MissingRouteMetadata,
            PartialFacts::default(),
            "matrix route metadata must include a room id",
        ));
    }
    if !input.context.allowed_target_rooms.is_empty()
        && !input
            .context
            .allowed_target_rooms
            .iter()
            .any(|room| room == &input.context.route_metadata.room_id)
    {
        return Err(MatrixAdapterDiagnostic::new(
            MatrixReasonCode::UnauthorizedTargetRoom,
            PartialFacts {
                room_id: Some(input.context.route_metadata.room_id),
                ..PartialFacts::default()
            },
            "matrix target room is not allowlisted",
        ));
    }

    let ProductOutboundPayload::FinalReply(reply) = input.envelope.payload else {
        return Err(MatrixAdapterDiagnostic::new(
            MatrixReasonCode::UnsupportedOutboundPayload,
            PartialFacts {
                room_id: Some(input.context.route_metadata.room_id),
                ..PartialFacts::default()
            },
            "product outbound payload cannot be rendered as a Matrix message",
        ));
    };

    let mut body = Map::new();
    body.insert("msgtype".to_string(), json!("m.text"));
    body.insert(
        "body".to_string(),
        json!(markdown_to_plaintext(&reply.text)),
    );
    body.insert("format".to_string(), json!("org.matrix.custom.html"));
    body.insert(
        "formatted_body".to_string(),
        json!(markdown_to_sanitized_matrix_html(&reply.text)),
    );
    if input.context.route_metadata.reply_to_event_id.is_some()
        || input.context.route_metadata.thread_root_event_id.is_some()
    {
        body.insert(
            "m.relates_to".to_string(),
            render_relation(&input.context.route_metadata),
        );
    }

    Ok(MatrixOutboundCommand::SendMessage {
        room_id: input.context.route_metadata.room_id,
        txn_id: format!("ironclaw-{}", input.envelope.delivery_attempt_id),
        body: Value::Object(body),
    })
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl ProductAdapter for MatrixProductAdapter {
    fn adapter_id(&self) -> &ProductAdapterId {
        &self.config.adapter_id
    }

    fn installation_id(&self) -> &AdapterInstallationId {
        &self.config.installation_id
    }

    fn surface_kind(&self) -> ProductSurfaceKind {
        ProductSurfaceKind::ExternalChannel
    }

    fn capabilities(&self) -> &ProductAdapterCapabilities {
        &self.capabilities
    }

    fn auth_requirement(&self) -> &AuthRequirement {
        &self.config.auth_requirement
    }

    fn parse_inbound(
        &self,
        raw_payload: &[u8],
        auth_evidence: &ProtocolAuthEvidence,
    ) -> Result<ParsedProductInbound, ProductAdapterError> {
        if !auth_evidence.is_verified() {
            return Err(ProductAdapterError::Authentication(
                auth_evidence
                    .failure()
                    .cloned()
                    .unwrap_or(ProtocolAuthFailure::Missing),
            ));
        }

        let raw_event: Value = serde_json::from_slice(raw_payload).map_err(|err| {
            ProductAdapterError::MalformedInboundPayload {
                reason: RedactedString::new(format!("matrix webhook payload is not JSON: {err}")),
            }
        })?;

        parse_matrix_event(MatrixParseInput {
            raw_event,
            installation_id: self.config.installation_id.as_str().to_string(),
            policy: self.config.parse_policy.clone(),
        })
        .map(|parsed| parsed.product)
        .map_err(map_matrix_diagnostic_to_adapter_error)
    }

    async fn render_outbound(
        &self,
        envelope: ProductOutboundEnvelope,
        _egress: &dyn ProtocolHttpEgress,
        _delivery_sink: &dyn OutboundDeliverySink,
    ) -> Result<ProductRenderOutcome, ProductAdapterError> {
        if envelope.adapter_id != self.config.adapter_id {
            return Err(ProductAdapterError::InvalidIdentifier {
                kind: "envelope.adapter_id",
                reason: format!(
                    "envelope adapter_id `{}` does not match this adapter `{}`",
                    envelope.adapter_id.as_str(),
                    self.config.adapter_id.as_str(),
                ),
            });
        }
        if envelope.installation_id != self.config.installation_id {
            return Err(ProductAdapterError::InvalidIdentifier {
                kind: "envelope.installation_id",
                reason: format!(
                    "envelope installation_id `{}` does not match this installation `{}`",
                    envelope.installation_id.as_str(),
                    self.config.installation_id.as_str(),
                ),
            });
        }

        let route_metadata = MatrixRouteMetadata {
            room_id: envelope
                .target
                .external_conversation_ref
                .conversation_id()
                .to_string(),
            reply_to_event_id: envelope
                .target
                .external_conversation_ref
                .reply_target_message_id()
                .map(str::to_string),
            thread_root_event_id: envelope
                .target
                .external_conversation_ref
                .topic_id()
                .map(str::to_string),
        };
        let context = MatrixRenderContext {
            installation_id: self.config.installation_id.as_str().to_string(),
            route_metadata,
            allowed_target_rooms: self.config.parse_policy.allowed_rooms.clone(),
        };
        let command = render_matrix_outbound(MatrixRenderInput { envelope, context })
            .map_err(map_matrix_diagnostic_to_adapter_error)?;
        let body = serde_json::to_vec(&command).map_err(|err| ProductAdapterError::Internal {
            detail: RedactedString::new(format!(
                "matrix outbound command serialization failed: {err}"
            )),
        })?;

        Ok(ProductRenderOutcome::SynchronousResponse(
            ProductSynchronousResponse {
                content_type: "application/vnd.ironclaw.matrix-command+json".to_string(),
                body,
            },
        ))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn map_matrix_diagnostic_to_adapter_error(
    diagnostic: MatrixAdapterDiagnostic,
) -> ProductAdapterError {
    match diagnostic.reason_code {
        MatrixReasonCode::MalformedMatrixEvent => ProductAdapterError::MalformedInboundPayload {
            reason: RedactedString::new(diagnostic.to_string()),
        },
        MatrixReasonCode::UnauthorizedRoom
        | MatrixReasonCode::UnauthorizedSender
        | MatrixReasonCode::UnauthorizedTargetRoom => ProductAdapterError::WorkflowRejected {
            kind: ProductWorkflowRejectionKind::Unauthorized,
            status_code: 403,
            retryable: false,
            reason: RedactedString::new(diagnostic.to_string()),
        },
        MatrixReasonCode::UnsupportedEventType
        | MatrixReasonCode::UnsupportedMsgtype
        | MatrixReasonCode::UnsupportedOutboundPayload
        | MatrixReasonCode::MissingRouteMetadata
        | MatrixReasonCode::UnsupportedMediaKind
        | MatrixReasonCode::UnsafeFormattedBody
        | MatrixReasonCode::UndecryptableEvent => ProductAdapterError::WorkflowRejected {
            kind: ProductWorkflowRejectionKind::InvalidRequest,
            status_code: 400,
            retryable: false,
            reason: RedactedString::new(diagnostic.to_string()),
        },
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_room_message(
    object: &Map<String, Value>,
    facts: MatrixEventFacts,
    installation_id: &str,
) -> Result<ParsedMatrixInbound, MatrixAdapterDiagnostic> {
    let content = object
        .get("content")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            diagnostic_for_facts(
                MatrixReasonCode::MalformedMatrixEvent,
                &facts,
                "matrix room message content must be an object",
            )
        })?;
    let msgtype = required_string(content, "msgtype", &facts)?;

    let mut metadata = MatrixMessageMetadata::from_facts(&facts);
    metadata.msgtype = Some(msgtype.clone());
    let relation = parse_relation(content);
    metadata.reply_to_event_id = relation.reply_to_event_id.clone();
    metadata.relation = relation.relation.clone();
    metadata.formatted_body = sanitized_formatted_body(content, &facts, &mut metadata.diagnostics);

    let (payload, message_content) = match msgtype.as_str() {
        "m.text" | "m.notice" => {
            let body = required_string(content, "body", &facts)?;
            (
                ProductInboundPayload::UserMessage(
                    UserMessagePayload::new(
                        body.clone(),
                        Vec::new(),
                        ProductTriggerReason::DirectChat,
                    )
                    .map_err(|_| {
                        diagnostic_for_facts(
                            MatrixReasonCode::MalformedMatrixEvent,
                            &facts,
                            "matrix message body is not a valid product inbound text",
                        )
                    })?,
                ),
                MatrixMessageContent {
                    msgtype: msgtype.clone(),
                    body,
                    formatted_body: metadata.formatted_body.clone(),
                    media: None,
                },
            )
        }
        "m.image" | "m.file" | "m.audio" | "m.video" => {
            let attachment = attachment_from_content(&facts, content, &msgtype)?;
            let body = content
                .get("body")
                .and_then(Value::as_str)
                .and_then(sanitize_filename)
                .unwrap_or_default();
            let media = matrix_media_from_content(content, &msgtype);
            metadata.media_url = media.as_ref().and_then(|media| media.mxc_url.clone());
            (
                ProductInboundPayload::UserMessage(
                    UserMessagePayload::new(
                        body.clone(),
                        vec![attachment],
                        ProductTriggerReason::DirectChat,
                    )
                    .map_err(|_| {
                        diagnostic_for_facts(
                            MatrixReasonCode::MalformedMatrixEvent,
                            &facts,
                            "matrix media message is not a valid product inbound message",
                        )
                    })?,
                ),
                MatrixMessageContent {
                    msgtype: msgtype.clone(),
                    body,
                    formatted_body: metadata.formatted_body.clone(),
                    media,
                },
            )
        }
        _ => {
            return Err(diagnostic_for_facts(
                MatrixReasonCode::UnsupportedMsgtype,
                &facts,
                "matrix room message msgtype is not supported",
            ));
        }
    };
    let mut facts = facts;
    facts.relation = metadata.relation.clone();
    facts.content = Some(message_content);
    facts.encryption = EncryptionState::Unencrypted;

    product_result(facts, metadata, payload, installation_id)
}

#[cfg(target_arch = "wasm32")]
fn parse_room_message(
    object: &Map<String, Value>,
    facts: MatrixEventFacts,
    _installation_id: &str,
) -> Result<ParsedMatrixInbound, MatrixAdapterDiagnostic> {
    let content = object
        .get("content")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            diagnostic_for_facts(
                MatrixReasonCode::MalformedMatrixEvent,
                &facts,
                "matrix room message content must be an object",
            )
        })?;
    let msgtype = required_string(content, "msgtype", &facts)?;

    let mut metadata = MatrixMessageMetadata::from_facts(&facts);
    metadata.msgtype = Some(msgtype.clone());
    let relation = parse_relation(content);
    metadata.reply_to_event_id = relation.reply_to_event_id.clone();
    metadata.relation = relation.relation.clone();
    metadata.formatted_body = sanitized_formatted_body(content, &facts, &mut metadata.diagnostics);

    let message_content = match msgtype.as_str() {
        "m.text" | "m.notice" => {
            let body = required_string(content, "body", &facts)?;
            MatrixMessageContent {
                msgtype: msgtype.clone(),
                body,
                formatted_body: metadata.formatted_body.clone(),
                media: None,
            }
        }
        "m.image" | "m.file" | "m.audio" | "m.video" => {
            let body = content
                .get("body")
                .and_then(Value::as_str)
                .and_then(sanitize_filename)
                .unwrap_or_default();
            let media = matrix_media_from_content(content, &msgtype);
            metadata.media_url = media.as_ref().and_then(|media| media.mxc_url.clone());
            MatrixMessageContent {
                msgtype: msgtype.clone(),
                body,
                formatted_body: metadata.formatted_body.clone(),
                media,
            }
        }
        _ => {
            return Err(diagnostic_for_facts(
                MatrixReasonCode::UnsupportedMsgtype,
                &facts,
                "matrix room message msgtype is not supported",
            ));
        }
    };
    let mut facts = facts;
    facts.relation = metadata.relation.clone();
    facts.content = Some(message_content);
    facts.encryption = EncryptionState::Unencrypted;

    Ok(ParsedMatrixInbound { facts, metadata })
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_encrypted_event(
    object: &Map<String, Value>,
    facts: MatrixEventFacts,
    installation_id: &str,
) -> Result<ParsedMatrixInbound, MatrixAdapterDiagnostic> {
    let content = object.get("content").and_then(Value::as_object);
    let algorithm = content
        .and_then(|content| content.get("algorithm"))
        .and_then(Value::as_str)
        .and_then(sanitize_event_type)
        .map(|value| value.to_string());
    let session_id = content
        .and_then(|content| content.get("session_id"))
        .and_then(Value::as_str)
        .and_then(sanitize_matrix_id)
        .map(|value| value.to_string());
    let diagnostic = diagnostic_for_facts(
        MatrixReasonCode::UndecryptableEvent,
        &facts,
        "encrypted Matrix event cannot be decrypted in the parse/render adapter",
    );
    let encryption = EncryptionState::Undecryptable {
        algorithm: algorithm.clone(),
        session_id: session_id.clone(),
        reason_code: MatrixReasonCode::UndecryptableEvent,
    };
    let mut metadata = MatrixMessageMetadata::from_facts(&facts);
    metadata.encryption = encryption.clone();
    metadata.diagnostics = vec![diagnostic];
    let mut facts = facts;
    facts.encryption = encryption;
    product_result(
        facts,
        metadata,
        ProductInboundPayload::NoOp,
        installation_id,
    )
}

#[cfg(target_arch = "wasm32")]
fn parse_encrypted_event(
    object: &Map<String, Value>,
    facts: MatrixEventFacts,
    _installation_id: &str,
) -> Result<ParsedMatrixInbound, MatrixAdapterDiagnostic> {
    let content = object.get("content").and_then(Value::as_object);
    let algorithm = content
        .and_then(|content| content.get("algorithm"))
        .and_then(Value::as_str)
        .and_then(sanitize_event_type)
        .map(|value| value.to_string());
    let session_id = content
        .and_then(|content| content.get("session_id"))
        .and_then(Value::as_str)
        .and_then(sanitize_matrix_id)
        .map(|value| value.to_string());
    let diagnostic = diagnostic_for_facts(
        MatrixReasonCode::UndecryptableEvent,
        &facts,
        "encrypted Matrix event cannot be decrypted in the parse/render adapter",
    );
    let encryption = EncryptionState::Undecryptable {
        algorithm,
        session_id,
        reason_code: MatrixReasonCode::UndecryptableEvent,
    };
    let mut metadata = MatrixMessageMetadata::from_facts(&facts);
    metadata.encryption = encryption.clone();
    metadata.diagnostics = vec![diagnostic];
    let mut facts = facts;
    facts.encryption = encryption;
    Ok(ParsedMatrixInbound { facts, metadata })
}

#[cfg(not(target_arch = "wasm32"))]
fn product_result(
    facts: MatrixEventFacts,
    metadata: MatrixMessageMetadata,
    payload: ProductInboundPayload,
    installation_id: &str,
) -> Result<ParsedMatrixInbound, MatrixAdapterDiagnostic> {
    let external_event_id =
        ExternalEventId::new(format!("matrix-{installation_id}-{}", facts.event_id)).map_err(
            |_| {
                diagnostic_for_facts(
                    MatrixReasonCode::MalformedMatrixEvent,
                    &facts,
                    "matrix event id is not a valid product external event id",
                )
            },
        )?;
    let actor = ExternalActorRef::new("matrix_user", facts.sender.clone(), None::<String>)
        .map_err(|_| {
            diagnostic_for_facts(
                MatrixReasonCode::MalformedMatrixEvent,
                &facts,
                "matrix sender is not a valid product actor id",
            )
        })?;
    let conversation = ExternalConversationRef::new(
        None,
        facts.room_id.clone(),
        metadata
            .relation
            .as_ref()
            .filter(|relation| relation.kind == RelationKind::Thread)
            .map(|relation| relation.event_id.as_str()),
        metadata.reply_to_event_id.as_deref(),
    )
    .map_err(|_| {
        diagnostic_for_facts(
            MatrixReasonCode::MalformedMatrixEvent,
            &facts,
            "matrix room metadata is not a valid product conversation id",
        )
    })?;
    let product = ParsedProductInbound::new(external_event_id, actor, conversation, payload)
        .map_err(|_| {
            diagnostic_for_facts(
                MatrixReasonCode::MalformedMatrixEvent,
                &facts,
                "matrix event could not be converted to product inbound",
            )
        })?;
    Ok(ParsedMatrixInbound {
        facts,
        metadata,
        product,
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn attachment_from_content(
    facts: &MatrixEventFacts,
    content: &Map<String, Value>,
    msgtype: &str,
) -> Result<ProductAttachmentDescriptor, MatrixAdapterDiagnostic> {
    let kind = match msgtype {
        "m.image" => ProductAttachmentKind::Image,
        "m.audio" => ProductAttachmentKind::Audio,
        "m.video" => ProductAttachmentKind::Video,
        "m.file" => ProductAttachmentKind::Document,
        _ => {
            return Err(diagnostic_for_facts(
                MatrixReasonCode::UnsupportedMediaKind,
                facts,
                "matrix media msgtype is not supported",
            ));
        }
    };
    let info = content.get("info").and_then(Value::as_object);
    let mime_type = info
        .and_then(|info| info.get("mimetype"))
        .and_then(Value::as_str)
        .map(normalize_mime_type)
        .unwrap_or_else(|| default_mime_type(msgtype).to_string());
    let size_bytes = info
        .and_then(|info| info.get("size"))
        .and_then(Value::as_u64);
    let filename = content
        .get("body")
        .and_then(Value::as_str)
        .and_then(sanitize_filename);
    ProductAttachmentDescriptor::new(
        facts.event_id.clone(),
        mime_type,
        filename,
        size_bytes,
        kind,
    )
    .map_err(|_| {
        diagnostic_for_facts(
            MatrixReasonCode::MalformedMatrixEvent,
            facts,
            "matrix media metadata is not a valid product attachment descriptor",
        )
    })
}

fn matrix_media_from_content(
    content: &Map<String, Value>,
    msgtype: &str,
) -> Option<MatrixMediaMetadata> {
    let info = content.get("info").and_then(Value::as_object);
    Some(MatrixMediaMetadata {
        msgtype: msgtype.to_string(),
        mxc_url: content
            .get("url")
            .and_then(Value::as_str)
            .filter(|url| url.starts_with("mxc://"))
            .map(str::to_string),
        mime_type: info
            .and_then(|info| info.get("mimetype"))
            .and_then(Value::as_str)
            .map(normalize_mime_type),
        filename: content
            .get("body")
            .and_then(Value::as_str)
            .and_then(sanitize_filename),
        size_bytes: info
            .and_then(|info| info.get("size"))
            .and_then(Value::as_u64),
    })
}

fn facts_from_object(
    object: &Map<String, Value>,
    partial: PartialFacts,
) -> Result<MatrixEventFacts, MatrixAdapterDiagnostic> {
    let event_id = required_event_id(object, &partial)?;
    let room_id = required_top_string(object, "room_id", &partial)?;
    let sender = required_top_string(object, "sender", &partial)?;
    let event_type = required_top_string(object, "type", &partial)?;
    let origin_server_ts = object.get("origin_server_ts").and_then(Value::as_i64);
    let transaction_id = object
        .get("unsigned")
        .and_then(Value::as_object)
        .and_then(|unsigned| unsigned.get("transaction_id"))
        .and_then(Value::as_str)
        .map(sanitize_field_value)
        .map(|value| value.to_string());
    Ok(MatrixEventFacts {
        deduplication_key: event_id.clone(),
        event_id,
        room_id,
        sender,
        event_type,
        origin_server_ts,
        transaction_id,
        relation: None,
        content: None,
        encryption: EncryptionState::Unencrypted,
    })
}

fn partial_facts(object: &Map<String, Value>) -> PartialFacts {
    PartialFacts {
        event_id: object
            .get("event_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        room_id: object
            .get("room_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        event_type: object
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_string),
        sender: object
            .get("sender")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

fn required_event_id(
    object: &Map<String, Value>,
    partial: &PartialFacts,
) -> Result<String, MatrixAdapterDiagnostic> {
    let value = required_top_string(object, "event_id", partial)?;
    if is_valid_matrix_event_id(&value) {
        Ok(value)
    } else {
        Err(MatrixAdapterDiagnostic::new(
            MatrixReasonCode::MalformedMatrixEvent,
            PartialFacts {
                event_id: Some(value),
                room_id: partial.room_id.clone(),
                event_type: partial.event_type.clone(),
                sender: partial.sender.clone(),
            },
            "matrix event_id is not a valid Matrix event id",
        ))
    }
}

fn is_valid_matrix_event_id(value: &str) -> bool {
    value.starts_with('$')
        && value.len() <= 255
        && value.len() > 1
        && !value.chars().any(|c| c == '\0' || c.is_control())
}

fn required_top_string(
    object: &Map<String, Value>,
    field: &'static str,
    partial: &PartialFacts,
) -> Result<String, MatrixAdapterDiagnostic> {
    object
        .get(field)
        .and_then(Value::as_str)
        .and_then(|value| bounded_protocol_string(value).map(str::to_string))
        .ok_or_else(|| {
            MatrixAdapterDiagnostic::new(
                MatrixReasonCode::MalformedMatrixEvent,
                PartialFacts {
                    event_id: partial.event_id.clone(),
                    room_id: partial.room_id.clone(),
                    event_type: partial.event_type.clone(),
                    sender: partial.sender.clone(),
                },
                format!("matrix event field {field} is missing or invalid"),
            )
        })
}

fn required_string(
    object: &Map<String, Value>,
    field: &'static str,
    facts: &MatrixEventFacts,
) -> Result<String, MatrixAdapterDiagnostic> {
    object
        .get(field)
        .and_then(Value::as_str)
        .and_then(|value| bounded_payload_string(value).map(str::to_string))
        .ok_or_else(|| {
            diagnostic_for_facts(
                MatrixReasonCode::MalformedMatrixEvent,
                facts,
                format!("matrix content field {field} is missing or invalid"),
            )
        })
}

struct ParsedRelation {
    reply_to_event_id: Option<String>,
    relation: Option<MatrixRelationMetadata>,
}

fn parse_relation(content: &Map<String, Value>) -> ParsedRelation {
    let relates_to = content.get("m.relates_to").and_then(Value::as_object);
    let reply_to_event_id = relates_to
        .and_then(|relates_to| relates_to.get("m.in_reply_to"))
        .and_then(Value::as_object)
        .and_then(|reply| reply.get("event_id"))
        .and_then(Value::as_str)
        .and_then(sanitize_matrix_id)
        .map(|value| value.to_string());
    let relation = relates_to.and_then(|relates_to| {
        let event_id = relates_to
            .get("event_id")
            .and_then(Value::as_str)
            .and_then(sanitize_matrix_id)
            .map(|value| value.to_string())?;
        let kind = match relates_to.get("rel_type").and_then(Value::as_str) {
            Some("m.thread") => RelationKind::Thread,
            _ => RelationKind::Reply,
        };
        Some(MatrixRelationMetadata { kind, event_id })
    });
    ParsedRelation {
        reply_to_event_id,
        relation,
    }
}

fn sanitized_formatted_body(
    content: &Map<String, Value>,
    facts: &MatrixEventFacts,
    diagnostics: &mut Vec<MatrixAdapterDiagnostic>,
) -> Option<String> {
    if content.get("format").and_then(Value::as_str) != Some("org.matrix.custom.html") {
        return None;
    }
    let raw = content.get("formatted_body").and_then(Value::as_str)?;
    if raw.len() > MAX_FORMATTED_BODY {
        diagnostics.push(diagnostic_for_facts(
            MatrixReasonCode::UnsafeFormattedBody,
            facts,
            "matrix formatted body was unsafe and was downgraded to plaintext",
        ));
        return None;
    }
    if html_nesting_exceeds(raw, MAX_HTML_NESTING) {
        diagnostics.push(diagnostic_for_facts(
            MatrixReasonCode::UnsafeFormattedBody,
            facts,
            "matrix formatted body was too deeply nested and was downgraded to plaintext",
        ));
        return None;
    }
    let cleaned = sanitize_matrix_html(raw);
    if cleaned.trim().is_empty() && !raw.trim().is_empty() {
        diagnostics.push(diagnostic_for_facts(
            MatrixReasonCode::UnsafeFormattedBody,
            facts,
            "matrix formatted body sanitized to empty output",
        ));
        return None;
    }
    Some(cleaned)
}

fn sanitize_matrix_html(raw: &str) -> String {
    let tags: HashSet<&'static str> = [
        "a",
        "b",
        "blockquote",
        "br",
        "code",
        "em",
        "i",
        "li",
        "ol",
        "pre",
        "strong",
        "ul",
    ]
    .into_iter()
    .collect();
    let mut tag_attributes: HashMap<&'static str, HashSet<&'static str>> = HashMap::new();
    tag_attributes.insert("a", ["href"].into_iter().collect());
    let url_schemes: HashSet<&'static str> = ["http", "https"].into_iter().collect();
    let cleaned = ammonia::Builder::new()
        .tags(tags)
        .tag_attributes(tag_attributes)
        .url_schemes(url_schemes)
        .url_relative(ammonia::UrlRelative::Deny)
        .link_rel(None)
        .clean(raw)
        .to_string();
    sanitize_encoded_xss_text(&cleaned)
}

fn html_nesting_exceeds(raw: &str, limit: usize) -> bool {
    let mut depth = 0usize;
    let bytes = raw.as_bytes();
    let mut i = 0usize;
    while let Some(offset) = raw[i..].find('<') {
        i += offset + 1;
        let Some(&next) = bytes.get(i) else {
            break;
        };
        if next == b'!' || next == b'?' {
            continue;
        }
        if next == b'/' {
            depth = depth.saturating_sub(1);
            continue;
        }
        if next.is_ascii_alphabetic() {
            depth += 1;
            if depth > limit {
                return true;
            }
            if let Some(end) = raw[i..].find('>') {
                let tag = &raw[i..i + end];
                if tag.trim_end().ends_with('/') {
                    depth = depth.saturating_sub(1);
                }
                i += end + 1;
            }
        }
    }
    false
}

fn sanitize_encoded_xss_text(cleaned: &str) -> String {
    let mut value = cleaned.to_string();
    for pattern in [
        "onerror",
        "onload",
        "javascript:",
        "data:",
        "expression(",
        "&lt;script",
        "&lt;iframe",
        "&lt;object",
        "&lt;embed",
    ] {
        value = replace_ascii_case_insensitive(&value, pattern, "");
    }
    value
}

fn replace_ascii_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    let lower_input = input.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    let mut output = String::new();
    let mut cursor = 0usize;
    while let Some(offset) = lower_input[cursor..].find(&lower_needle) {
        let start = cursor + offset;
        output.push_str(&input[cursor..start]);
        output.push_str(replacement);
        cursor = start + needle.len();
    }
    output.push_str(&input[cursor..]);
    output
}

#[cfg(not(target_arch = "wasm32"))]
fn markdown_to_sanitized_matrix_html(markdown: &str) -> String {
    let mut unsafe_html = String::new();
    let parser = Parser::new_ext(markdown, Options::empty());
    html::push_html(&mut unsafe_html, parser);
    sanitize_matrix_html(&unsafe_html)
}

#[cfg(not(target_arch = "wasm32"))]
fn markdown_to_plaintext(markdown: &str) -> String {
    let parser = Parser::new_ext(markdown, Options::empty());
    let mut text = String::new();
    for event in parser {
        match event {
            pulldown_cmark::Event::Text(value) | pulldown_cmark::Event::Code(value) => {
                text.push_str(&value);
            }
            pulldown_cmark::Event::SoftBreak | pulldown_cmark::Event::HardBreak => {
                text.push('\n');
            }
            _ => {}
        }
    }
    if text.is_empty() {
        markdown.to_string()
    } else {
        text
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn render_relation(route: &MatrixRouteMetadata) -> Value {
    let mut relation = Map::new();
    if let Some(reply_to) = &route.reply_to_event_id {
        relation.insert("m.in_reply_to".to_string(), json!({ "event_id": reply_to }));
    }
    if let Some(thread_root) = &route.thread_root_event_id {
        relation.insert("rel_type".to_string(), json!("m.thread"));
        relation.insert("event_id".to_string(), json!(thread_root));
        relation.insert("is_falling_back".to_string(), json!(true));
    }
    Value::Object(relation)
}

fn diagnostic_for_facts(
    reason_code: MatrixReasonCode,
    facts: &MatrixEventFacts,
    message: impl Into<String>,
) -> MatrixAdapterDiagnostic {
    MatrixAdapterDiagnostic::new(
        reason_code,
        PartialFacts {
            event_id: Some(facts.event_id.clone()),
            room_id: Some(facts.room_id.clone()),
            event_type: Some(facts.event_type.clone()),
            sender: Some(facts.sender.clone()),
        },
        message,
    )
}

fn bounded_protocol_string(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= MAX_EVENT_FIELD
        && !value.chars().any(|c| c == '\0' || c.is_control()))
    .then_some(value)
}

fn bounded_payload_string(value: &str) -> Option<&str> {
    (value.len() <= MAX_FORMATTED_BODY
        && !value
            .chars()
            .any(|c| c == '\0' || c.is_control() && c != '\n' && c != '\t'))
    .then_some(value)
}

fn sanitize_matrix_id(value: impl AsRef<str>) -> Option<Box<str>> {
    let value = sanitize_field_value(value.as_ref());
    (!value.is_empty()).then(|| value.into_boxed_str())
}

fn sanitize_event_type(value: impl AsRef<str>) -> Option<Box<str>> {
    let value = value.as_ref();
    let sanitized = sanitize_field_value(value);
    (!sanitized.is_empty()
        && sanitized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
    .then(|| sanitized.into_boxed_str())
}

fn sanitize_message(message: String) -> String {
    sanitize_field_value(&message)
}

fn sanitize_field_value(value: &str) -> String {
    let mut escaped = String::new();
    for c in value.chars() {
        match c {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\0' => escaped.push_str("\\0"),
            c if c.is_control() => escaped.push(' '),
            c => escaped.push(c),
        }
    }
    let trimmed = escaped.trim();
    if looks_like_credential(trimmed) {
        return "[REDACTED-CREDENTIAL]".to_string();
    }
    trimmed.chars().take(DIAGNOSTIC_MESSAGE_MAX).collect()
}

fn looks_like_credential(value: &str) -> bool {
    value.contains("Bearer ")
        || value.contains("sk_")
        || value.contains("syt_")
        || value.contains("AKIA")
        || value.contains("ASIA")
        || value.contains("ghp_")
        || value.contains("gho_")
        || value.contains("ghs_")
        || value.contains("xoxb-")
        || value.contains("xoxp-")
        || value.contains("eyJ")
        || value.contains("AIza")
        || value
            .split(|c: char| c.is_whitespace() || matches!(c, ':' | ',' | ';' | '"' | '\''))
            .any(|token| {
                token.len() > 32
                    && token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            })
}

fn normalize_mime_type(value: &str) -> String {
    let normalized = value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '+' | '-' | '.'))
        .collect::<String>();
    if is_allowed_mime_type(&normalized) {
        normalized
    } else {
        "application/octet-stream".to_string()
    }
}

fn is_allowed_mime_type(value: &str) -> bool {
    value.starts_with("image/")
        || value.starts_with("audio/")
        || value.starts_with("video/")
        || value == "text/plain"
        || value == "application/pdf"
        || value == "application/octet-stream"
}

#[cfg(not(target_arch = "wasm32"))]
fn default_mime_type(msgtype: &str) -> &'static str {
    match msgtype {
        "m.image" | "m.audio" | "m.video" => "application/octet-stream",
        _ => "application/octet-stream",
    }
}

fn sanitize_filename(value: &str) -> Option<String> {
    let filename = value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .chars()
        .map(|c| {
            if c == '\0' || c.is_control() || matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect::<String>();
    let trimmed = filename.trim_matches(['.', ' ', '_']).trim();
    if trimmed.is_empty() {
        Some("untitled".to_string())
    } else {
        Some(truncate_utf8_bytes(trimmed, 255))
    }
}

fn truncate_utf8_bytes(value: &str, max_bytes: usize) -> String {
    let mut output = String::new();
    for c in value.chars() {
        if output.len() + c.len_utf8() > max_bytes {
            break;
        }
        output.push(c);
    }
    output
}

fn safe_debug_identifier(value: &str) -> String {
    sanitize_field_value(value)
}

fn redacted_debug_option(value: Option<&str>) -> String {
    value
        .map(sanitize_field_value)
        .unwrap_or_else(|| "<none>".to_string())
}
