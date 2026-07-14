//! Pure Matrix parse/render contracts for the Reborn Matrix channel.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use ironclaw_product_adapters::{
    ExternalActorRef, ExternalConversationRef, ExternalEventId, ParsedProductInbound,
    ProductAttachmentDescriptor, ProductAttachmentKind, ProductInboundPayload,
    ProductOutboundEnvelope, ProductOutboundPayload, ProductTriggerReason, UserMessagePayload,
};
use pulldown_cmark::{Options, Parser, html};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

const DIAGNOSTIC_MESSAGE_MAX: usize = 256;
const MAX_EVENT_FIELD: usize = 512;
const MAX_FORMATTED_BODY: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixParseInput {
    pub raw_event: Value,
    pub allowed_rooms: Vec<String>,
    pub allowed_senders: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRenderInput {
    pub envelope: ProductOutboundEnvelope,
    pub route_metadata: MatrixRouteMetadata,
    pub allowed_target_rooms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedMatrixInbound {
    pub facts: MatrixEventFacts,
    pub metadata: MatrixMessageMetadata,
    pub product: ParsedProductInbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixEventFacts {
    pub event_id: String,
    pub room_id: String,
    pub sender: String,
    pub event_type: String,
    pub origin_server_ts: Option<i64>,
    pub deduplication_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixMessageMetadata {
    pub msgtype: Option<String>,
    pub formatted_body: Option<String>,
    pub reply_to_event_id: Option<String>,
    pub relation: Option<MatrixRelationMetadata>,
    pub encryption: EncryptionState,
    pub diagnostics: Vec<MatrixAdapterDiagnostic>,
}

impl Default for MatrixMessageMetadata {
    fn default() -> Self {
        Self {
            msgtype: None,
            formatted_body: None,
            reply_to_event_id: None,
            relation: None,
            encryption: EncryptionState::Unencrypted,
            diagnostics: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixRelationMetadata {
    pub kind: RelationKind,
    pub event_id: String,
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
}

impl MatrixOutboundCommand {
    pub fn room_id(&self) -> &str {
        match self {
            Self::SendMessage { room_id, .. } => room_id,
        }
    }

    pub fn body(&self) -> &Value {
        match self {
            Self::SendMessage { body, .. } => body,
        }
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{reason_code:?}: {message}")]
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
    let facts = facts_from_object(object, partial)?;

    if !input.allowed_rooms.is_empty()
        && !input
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
    if !input.allowed_senders.is_empty()
        && !input
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
        "m.room.message" => parse_room_message(object, facts),
        "m.room.encrypted" => parse_encrypted_event(object, facts),
        _ => Err(diagnostic_for_facts(
            MatrixReasonCode::UnsupportedEventType,
            &facts,
            "matrix event type is not supported by the parse contract",
        )),
    }
}

pub fn render_matrix_outbound(
    input: MatrixRenderInput,
) -> Result<MatrixOutboundCommand, MatrixAdapterDiagnostic> {
    if input.route_metadata.room_id.is_empty() {
        return Err(MatrixAdapterDiagnostic::new(
            MatrixReasonCode::MissingRouteMetadata,
            PartialFacts::default(),
            "matrix route metadata must include a room id",
        ));
    }
    if !input.allowed_target_rooms.is_empty()
        && !input
            .allowed_target_rooms
            .iter()
            .any(|room| room == &input.route_metadata.room_id)
    {
        return Err(MatrixAdapterDiagnostic::new(
            MatrixReasonCode::UnauthorizedTargetRoom,
            PartialFacts {
                room_id: Some(input.route_metadata.room_id),
                ..PartialFacts::default()
            },
            "matrix target room is not allowlisted",
        ));
    }

    let ProductOutboundPayload::FinalReply(reply) = input.envelope.payload else {
        return Err(MatrixAdapterDiagnostic::new(
            MatrixReasonCode::UnsupportedOutboundPayload,
            PartialFacts {
                room_id: Some(input.route_metadata.room_id),
                ..PartialFacts::default()
            },
            "product outbound payload cannot be rendered as a Matrix message",
        ));
    };

    let mut body = Map::new();
    body.insert("msgtype".to_string(), json!("m.text"));
    body.insert("body".to_string(), json!(reply.text));
    body.insert("format".to_string(), json!("org.matrix.custom.html"));
    body.insert(
        "formatted_body".to_string(),
        json!(markdown_to_sanitized_matrix_html(
            body["body"].as_str().unwrap_or_default()
        )),
    );
    if input.route_metadata.reply_to_event_id.is_some()
        || input.route_metadata.thread_root_event_id.is_some()
    {
        body.insert(
            "m.relates_to".to_string(),
            render_relation(&input.route_metadata),
        );
    }

    Ok(MatrixOutboundCommand::SendMessage {
        room_id: input.route_metadata.room_id,
        txn_id: format!("ironclaw-{}", input.envelope.delivery_attempt_id),
        body: Value::Object(body),
    })
}

fn parse_room_message(
    object: &Map<String, Value>,
    facts: MatrixEventFacts,
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

    let mut metadata = MatrixMessageMetadata {
        msgtype: Some(msgtype.clone()),
        ..MatrixMessageMetadata::default()
    };
    let relation = parse_relation(content);
    metadata.reply_to_event_id = relation.reply_to_event_id.clone();
    metadata.relation = relation.relation;
    metadata.formatted_body = sanitized_formatted_body(content, &facts, &mut metadata.diagnostics);

    let payload = match msgtype.as_str() {
        "m.text" | "m.notice" => ProductInboundPayload::UserMessage(
            {
                let body = required_string(content, "body", &facts)?;
                UserMessagePayload::new(body, Vec::new(), ProductTriggerReason::DirectChat)
            }
            .map_err(|_| {
                diagnostic_for_facts(
                    MatrixReasonCode::MalformedMatrixEvent,
                    &facts,
                    "matrix message body is not a valid product inbound text",
                )
            })?,
        ),
        "m.image" | "m.file" | "m.audio" | "m.video" => {
            let attachment = attachment_from_content(&facts, content, &msgtype)?;
            let body = content
                .get("body")
                .and_then(Value::as_str)
                .and_then(sanitize_filename)
                .unwrap_or_default();
            ProductInboundPayload::UserMessage(
                UserMessagePayload::new(body, vec![attachment], ProductTriggerReason::DirectChat)
                    .map_err(|_| {
                    diagnostic_for_facts(
                        MatrixReasonCode::MalformedMatrixEvent,
                        &facts,
                        "matrix media message is not a valid product inbound message",
                    )
                })?,
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

    product_result(facts, metadata, payload)
}

fn parse_encrypted_event(
    object: &Map<String, Value>,
    facts: MatrixEventFacts,
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
    let metadata = MatrixMessageMetadata {
        encryption: EncryptionState::Undecryptable {
            algorithm,
            session_id,
            reason_code: MatrixReasonCode::UndecryptableEvent,
        },
        diagnostics: vec![diagnostic],
        ..MatrixMessageMetadata::default()
    };
    product_result(facts, metadata, ProductInboundPayload::NoOp)
}

fn product_result(
    facts: MatrixEventFacts,
    metadata: MatrixMessageMetadata,
    payload: ProductInboundPayload,
) -> Result<ParsedMatrixInbound, MatrixAdapterDiagnostic> {
    let external_event_id = ExternalEventId::new(facts.event_id.clone()).map_err(|_| {
        diagnostic_for_facts(
            MatrixReasonCode::MalformedMatrixEvent,
            &facts,
            "matrix event id is not a valid product external event id",
        )
    })?;
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

fn facts_from_object(
    object: &Map<String, Value>,
    partial: PartialFacts,
) -> Result<MatrixEventFacts, MatrixAdapterDiagnostic> {
    let event_id = required_top_string(object, "event_id", &partial)?;
    let room_id = required_top_string(object, "room_id", &partial)?;
    let sender = required_top_string(object, "sender", &partial)?;
    let event_type = required_top_string(object, "type", &partial)?;
    let origin_server_ts = object.get("origin_server_ts").and_then(Value::as_i64);
    Ok(MatrixEventFacts {
        deduplication_key: event_id.clone(),
        event_id,
        room_id,
        sender,
        event_type,
        origin_server_ts,
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
        "p",
        "pre",
        "s",
        "strong",
        "u",
        "ul",
    ]
    .into_iter()
    .collect();
    let mut tag_attributes: HashMap<&'static str, HashSet<&'static str>> = HashMap::new();
    tag_attributes.insert("a", ["href"].into_iter().collect());
    ammonia::Builder::new()
        .tags(tags)
        .tag_attributes(tag_attributes)
        .url_relative(ammonia::UrlRelative::Deny)
        .link_rel(None)
        .clean(raw)
        .to_string()
}

fn markdown_to_sanitized_matrix_html(markdown: &str) -> String {
    let mut unsafe_html = String::new();
    let parser = Parser::new_ext(markdown, Options::empty());
    html::push_html(&mut unsafe_html, parser);
    sanitize_matrix_html(&unsafe_html)
}

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
    bounded_protocol_string(value.as_ref()).map(|value| value.into())
}

fn sanitize_event_type(value: impl AsRef<str>) -> Option<Box<str>> {
    let value = value.as_ref();
    (value.len() <= MAX_EVENT_FIELD
        && !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
    .then(|| value.into())
}

fn sanitize_message(message: String) -> String {
    let mut safe = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>();
    if safe.len() > DIAGNOSTIC_MESSAGE_MAX {
        safe.truncate(DIAGNOSTIC_MESSAGE_MAX);
    }
    safe
}

fn normalize_mime_type(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '+' | '-' | '.'))
        .collect::<String>()
}

fn default_mime_type(msgtype: &str) -> &'static str {
    match msgtype {
        "m.image" => "image/jpeg",
        "m.audio" => "audio/ogg",
        "m.video" => "video/mp4",
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
    let trimmed = filename.trim_matches(['.', ' ']).trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(128).collect())
    }
}
