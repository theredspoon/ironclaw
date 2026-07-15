use ironclaw_matrix_adapter::{
    EncryptionState, MatrixParseInput, MatrixParsePolicy, MatrixReasonCode, RelationKind,
    parse_matrix_event,
};
use serde_json::Value;

use crate::auth::require_verified_evidence;
use crate::config::installation_config;
use crate::limits::{MAX_RAW_PAYLOAD_BYTES, ensure_input_size, ensure_json_depth};

pub(crate) fn parse_inbound(raw_payload: Vec<u8>, evidence_json: String) -> Result<String, String> {
    require_verified_evidence(&evidence_json)?;
    let config = installation_config()?;
    ensure_input_size("raw_payload", raw_payload.len(), MAX_RAW_PAYLOAD_BYTES)?;
    let raw_event: Value = serde_json::from_slice(&raw_payload)
        .map_err(|_| format!("{:?}", MatrixReasonCode::MalformedMatrixEvent))?;
    ensure_json_depth(&raw_event)?;
    let parsed = parse_matrix_event(MatrixParseInput {
        raw_event,
        installation_id: config.installation_id.clone(),
        policy: MatrixParsePolicy {
            allowed_rooms: config.matrix.allowed_rooms.clone(),
            allowed_senders: config.matrix.allowed_senders.clone(),
        },
    })
    .map_err(|diagnostic| format!("{:?}", diagnostic.reason_code))?;
    let payload = match parsed.facts.encryption {
        EncryptionState::Unencrypted => user_message_payload(&parsed),
        EncryptionState::Undecryptable { .. } => Value::String("no_op".to_string()),
    };
    let parsed_json = serde_json::json!({
        "external_event_id": format!("matrix-{}-{}", config.installation_id, parsed.facts.event_id),
        "external_actor_ref": {
            "kind": "matrix_user",
            "id": parsed.facts.sender,
            "display_name": null
        },
        "external_conversation_ref": {
            "space_id": null,
            "conversation_id": parsed.facts.room_id,
            "topic_id": parsed.metadata.relation.as_ref()
                .filter(|relation| relation.kind == RelationKind::Thread)
                .map(|relation| relation.event_id.clone()),
            "reply_target_message_id": parsed.metadata.reply_to_event_id
        },
        "payload": payload
    });
    Ok(parsed_json.to_string())
}

fn user_message_payload(parsed: &ironclaw_matrix_adapter::ParsedMatrixInbound) -> Value {
    let Some(content) = &parsed.facts.content else {
        return Value::String("no_op".to_string());
    };
    let attachments = content
        .media
        .as_ref()
        .map(|media| {
            vec![serde_json::json!({
                "external_file_id": parsed.facts.event_id,
                "mime_type": media.mime_type.as_deref().unwrap_or("application/octet-stream"),
                "filename": media.filename,
                "size_bytes": media.size_bytes,
                "kind": attachment_kind(&media.msgtype)
            })]
        })
        .unwrap_or_default();
    serde_json::json!({
        "user_message": {
            "text": content.body,
            "attachments": attachments,
            "trigger": "direct_chat",
            "requested_model": null
        }
    })
}

fn attachment_kind(msgtype: &str) -> &'static str {
    match msgtype {
        "m.image" => "image",
        "m.audio" => "audio",
        "m.video" => "video",
        "m.file" => "document",
        _ => "other",
    }
}
