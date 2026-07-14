use chrono::Utc;
use ironclaw_matrix_adapter::{
    EncryptionState, MatrixParseInput, MatrixParsePolicy, MatrixReasonCode, MatrixRenderContext,
    MatrixRenderInput, MatrixRouteMetadata, RelationKind, parse_matrix_event,
    render_matrix_outbound,
};
use ironclaw_product_adapters::{
    EncryptionStatus, ExternalActorRef, ExternalConversationRef, FinalReplyView,
    ProductAttachmentKind, ProductInboundPayload, ProductOutboundEnvelope, ProductOutboundPayload,
    ProductOutboundTarget, ProjectionCursor,
};
use ironclaw_turns::ReplyTargetBindingRef;
use serde_json::{Value, json};

fn text_event(content: Value) -> Value {
    json!({
        "type": "m.room.message",
        "event_id": "$event:example.org",
        "room_id": "!room:example.org",
        "sender": "@alice:example.org",
        "origin_server_ts": 1710000000000_i64,
        "content": content
    })
}

fn parse(value: Value) -> ironclaw_matrix_adapter::ParsedMatrixInbound {
    parse_matrix_event(MatrixParseInput {
        raw_event: value,
        installation_id: "inst_abc123".to_string(),
        policy: allow_policy(),
    })
    .expect("event should parse")
}

fn allow_policy() -> MatrixParsePolicy {
    MatrixParsePolicy {
        allowed_rooms: vec!["!room:example.org".to_string()],
        allowed_senders: vec!["@alice:example.org".to_string()],
    }
}

fn render_context(room_id: &str) -> MatrixRenderContext {
    MatrixRenderContext {
        installation_id: "inst_abc123".to_string(),
        route_metadata: MatrixRouteMetadata {
            room_id: room_id.to_string(),
            reply_to_event_id: None,
            thread_root_event_id: None,
        },
        allowed_target_rooms: vec!["!room:example.org".to_string()],
    }
}

#[test]
fn parses_plain_text_into_product_user_message() {
    let parsed = parse(text_event(
        json!({"msgtype": "m.text", "body": "hello matrix"}),
    ));

    assert_eq!(parsed.facts.event_id, "$event:example.org");
    assert_eq!(
        parsed.facts.deduplication_key,
        "matrix-inst_abc123-$event:example.org"
    );
    assert_eq!(
        parsed.product.external_event_id.as_str(),
        "matrix-inst_abc123-$event:example.org"
    );
    assert_eq!(
        parsed.product.encryption_status,
        Some(EncryptionStatus::Unencrypted)
    );
    assert_eq!(parsed.facts.room_id, "!room:example.org");
    assert_eq!(parsed.facts.sender, "@alice:example.org");
    match parsed.product.payload {
        ProductInboundPayload::UserMessage(payload) => assert_eq!(payload.text, "hello matrix"),
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[test]
fn sanitizes_formatted_html_and_keeps_plaintext_payload() {
    let parsed = parse(text_event(json!({
        "msgtype": "m.text",
        "body": "safe fallback",
        "format": "org.matrix.custom.html",
        "formatted_body": "<b>safe</b><script>alert(1)</script><a href=\"javascript:alert(1)\" onclick=\"x()\">bad</a>"
    })));

    assert_eq!(
        parsed.metadata.formatted_body.as_deref(),
        Some("<b>safe</b><a>bad</a>")
    );
    match parsed.product.payload {
        ProductInboundPayload::UserMessage(payload) => assert_eq!(payload.text, "safe fallback"),
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[test]
fn unsafe_formatted_html_downgrades_to_plaintext() {
    let parsed = parse(text_event(json!({
        "msgtype": "m.text",
        "body": "plain fallback",
        "format": "org.matrix.custom.html",
        "formatted_body": "<script>credential sk-live-abc</script>"
    })));

    assert!(parsed.metadata.formatted_body.is_none());
    assert_eq!(
        parsed.metadata.diagnostics[0].reason_code,
        MatrixReasonCode::UnsafeFormattedBody
    );
}

#[test]
fn preserves_reply_thread_and_dedup_metadata() {
    let parsed = parse(text_event(json!({
        "msgtype": "m.text",
        "body": "thread reply",
        "m.relates_to": {
            "rel_type": "m.thread",
            "event_id": "$root:example.org",
            "m.in_reply_to": {"event_id": "$reply:example.org"}
        }
    })));

    assert_eq!(
        parsed.facts.deduplication_key,
        "matrix-inst_abc123-$event:example.org"
    );
    assert_eq!(
        parsed.metadata.reply_to_event_id.as_deref(),
        Some("$reply:example.org")
    );
    assert_eq!(
        parsed.metadata.relation.as_ref().unwrap().kind,
        RelationKind::Thread
    );
    assert_eq!(
        parsed.product.external_conversation_ref.topic_id(),
        Some("$root:example.org")
    );
    assert_eq!(
        parsed
            .product
            .external_conversation_ref
            .reply_target_message_id(),
        Some("$reply:example.org")
    );
}

#[test]
fn parses_media_metadata_without_exposing_mxc_url() {
    let parsed = parse(text_event(json!({
        "msgtype": "m.image",
        "body": "../unsafe\u{0000}name.PNG",
        "url": "mxc://example.org/media-id",
        "info": {"mimetype": "IMAGE/PNG", "size": 4096}
    })));

    match parsed.product.payload {
        ProductInboundPayload::UserMessage(payload) => {
            let attachment = &payload.attachments[0];
            assert_eq!(attachment.external_file_id, "$event:example.org");
            assert_eq!(attachment.mime_type, "image/png");
            assert_eq!(attachment.filename.as_deref(), Some("unsafe_name.PNG"));
            assert_eq!(attachment.size_bytes, Some(4096));
            assert_eq!(attachment.kind, ProductAttachmentKind::Image);
            assert!(
                !serde_json::to_string(attachment)
                    .unwrap()
                    .contains("mxc://")
            );
        }
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[test]
fn undecryptable_encrypted_event_is_noop_with_safe_status() {
    let parsed = parse_matrix_event(MatrixParseInput {
        raw_event: json!({
            "type": "m.room.encrypted",
            "event_id": "$encrypted:example.org",
            "room_id": "!room:example.org",
            "sender": "@alice:example.org",
            "origin_server_ts": 1710000000000_i64,
            "content": {
                "algorithm": "m.megolm.v1.aes-sha2",
                "session_id": "opaque-session-id",
                "ciphertext": "must-not-leak"
            }
        }),
        installation_id: "inst_abc123".to_string(),
        policy: allow_policy(),
    })
    .expect("encrypted event should become noop");

    assert!(matches!(
        parsed.product.payload,
        ProductInboundPayload::NoOp
    ));
    assert_eq!(
        parsed.product.encryption_status,
        Some(EncryptionStatus::Undecryptable {
            algorithm: "m.megolm.v1.aes-sha2".to_string(),
            reason_code: "undecryptable_event".to_string(),
            session_id: Some("opaque-session-id".to_string()),
        })
    );
    assert_eq!(
        parsed.metadata.encryption,
        EncryptionState::Undecryptable {
            algorithm: Some("m.megolm.v1.aes-sha2".to_string()),
            session_id: Some("opaque-session-id".to_string()),
            reason_code: MatrixReasonCode::UndecryptableEvent,
        }
    );
    assert!(
        !serde_json::to_string(&parsed.metadata.diagnostics)
            .unwrap()
            .contains("ciphertext")
    );
}

#[test]
fn rejects_unsupported_and_unauthorized_events_with_sanitized_diagnostics() {
    let unsupported = parse_matrix_event(MatrixParseInput {
        raw_event: json!({
            "type": "m.room.member",
            "event_id": "$event:example.org",
            "room_id": "!room:example.org",
            "sender": "@alice:example.org",
            "content": {"body": "secret token sk-live-123"}
        }),
        installation_id: "inst_abc123".to_string(),
        policy: allow_policy(),
    })
    .expect_err("unsupported event should be diagnostic");
    assert_eq!(
        unsupported.reason_code,
        MatrixReasonCode::UnsupportedEventType
    );
    assert!(
        !serde_json::to_string(&unsupported)
            .unwrap()
            .contains("sk-live")
    );

    let unauthorized = parse_matrix_event(MatrixParseInput {
        raw_event: text_event(json!({"msgtype": "m.text", "body": "hello"})),
        installation_id: "inst_abc123".to_string(),
        policy: MatrixParsePolicy {
            allowed_rooms: vec!["!elsewhere:example.org".to_string()],
            allowed_senders: vec!["@alice:example.org".to_string()],
        },
    })
    .expect_err("unauthorized room should be diagnostic");
    assert_eq!(unauthorized.reason_code, MatrixReasonCode::UnauthorizedRoom);
}

#[test]
fn malformed_json_and_missing_required_fields_are_diagnostics() {
    let err = parse_matrix_event(MatrixParseInput {
        raw_event: json!({"type": "m.room.message", "content": {"body": "x"}}),
        installation_id: "inst_abc123".to_string(),
        policy: MatrixParsePolicy::default(),
    })
    .expect_err("missing Matrix identifiers must fail");

    assert_eq!(err.reason_code, MatrixReasonCode::MalformedMatrixEvent);
    assert!(err.message.len() <= 100);
}

#[test]
fn empty_policy_allows_local_contract_parsing_but_denied_sender_fails() {
    let parsed = parse_matrix_event(MatrixParseInput {
        raw_event: text_event(json!({"msgtype": "m.text", "body": "hello"})),
        installation_id: "inst_abc123".to_string(),
        policy: MatrixParsePolicy::default(),
    })
    .expect("empty policy is documented fail-open for local parsing");
    assert_eq!(parsed.metadata.room_id, "!room:example.org");

    let denied = parse_matrix_event(MatrixParseInput {
        raw_event: text_event(json!({"msgtype": "m.text", "body": "hello"})),
        installation_id: "inst_abc123".to_string(),
        policy: MatrixParsePolicy {
            allowed_rooms: vec!["!room:example.org".to_string()],
            allowed_senders: vec!["@elsewhere:example.org".to_string()],
        },
    })
    .expect_err("sender must be allowlisted when sender policy is present");
    assert_eq!(denied.reason_code, MatrixReasonCode::UnauthorizedSender);
}

#[test]
fn diagnostics_escape_truncate_and_redact_adversarial_fields() {
    let injected_sender = parse_matrix_event(MatrixParseInput {
        raw_event: json!({
            "type": "m.room.message",
            "event_id": "$event:example.org",
            "room_id": "!room:example.org",
            "sender": "@attacker\nERROR: injected message",
            "content": {"msgtype": "m.text", "body": "hello"}
        }),
        installation_id: "inst_abc123".to_string(),
        policy: allow_policy(),
    })
    .expect_err("control-character sender should fail validation");
    assert_eq!(
        injected_sender.sender.as_deref(),
        Some("@attacker\\nERROR: injected message")
    );

    let b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789";
    let redacted = parse_matrix_event(MatrixParseInput {
        raw_event: json!({
            "type": "m.room.member",
            "event_id": b64,
            "room_id": "!room:example.org",
            "sender": "@alice:example.org",
            "content": {"body": format!("Bearer sk_live_{}", "x".repeat(10_000))}
        }),
        installation_id: "inst_abc123".to_string(),
        policy: allow_policy(),
    })
    .expect_err("unsupported event should be diagnostic");
    let diagnostic_json = serde_json::to_string(&redacted).expect("diagnostic json");
    assert!(diagnostic_json.contains("[REDACTED-CREDENTIAL]"));
    assert!(!diagnostic_json.contains("Bearer"));
    assert!(!diagnostic_json.contains("sk_live"));
    assert!(redacted.message.len() <= 100);
}

#[test]
fn metadata_serializes_route_fields_without_logging_raw_metadata() {
    let parsed = parse(text_event(json!({
        "msgtype": "m.image",
        "body": "image.png",
        "url": "mxc://example.org/media-id",
        "info": {"mimetype": "image/png", "size": 12}
    })));
    let metadata_json = serde_json::to_string(&parsed.metadata).expect("metadata json");
    assert!(metadata_json.contains("!room:example.org"));
    assert!(metadata_json.contains("$event:example.org"));
    assert!(metadata_json.contains("mxc://example.org/media-id"));

    let diagnostic = parse_matrix_event(MatrixParseInput {
        raw_event: json!({
            "type": "m.room.member",
            "event_id": "$event:example.org",
            "room_id": "!room:example.org",
            "sender": "@alice:example.org",
            "content": {"url": "mxc://example.org/media-id"}
        }),
        installation_id: "inst_abc123".to_string(),
        policy: allow_policy(),
    })
    .expect_err("unsupported event should be diagnostic");
    assert!(
        !serde_json::to_string(&diagnostic)
            .expect("diagnostic json")
            .contains("mxc://")
    );
}

#[test]
fn renders_final_reply_to_matrix_command_with_markdown_html() {
    let command = render_matrix_outbound(MatrixRenderInput {
        envelope: outbound(ProductOutboundPayload::FinalReply(FinalReplyView {
            turn_run_id: ironclaw_turns::TurnRunId::new(),
            text: "**hello** [site](https://example.org)".to_string(),
            generated_at: Utc::now(),
        })),
        context: MatrixRenderContext {
            installation_id: "inst_abc123".to_string(),
            route_metadata: MatrixRouteMetadata {
                room_id: "!room:example.org".to_string(),
                reply_to_event_id: Some("$reply:example.org".to_string()),
                thread_root_event_id: Some("$root:example.org".to_string()),
            },
            allowed_target_rooms: vec!["!room:example.org".to_string()],
        },
    })
    .expect("reply should render");

    assert_eq!(command.room_id(), "!room:example.org");
    assert_eq!(command.body()["msgtype"], "m.text");
    assert_eq!(command.body()["body"], "hello site");
    assert_eq!(command.body()["format"], "org.matrix.custom.html");
    assert!(
        command.body()["formatted_body"]
            .as_str()
            .unwrap()
            .contains("<strong>hello</strong>")
    );
    assert_eq!(
        command.body()["m.relates_to"]["m.in_reply_to"]["event_id"],
        "$reply:example.org"
    );
    assert_eq!(command.body()["m.relates_to"]["rel_type"], "m.thread");
}

#[test]
fn render_rejects_unsupported_payloads_and_target_rooms() {
    let missing_route = render_matrix_outbound(MatrixRenderInput {
        envelope: outbound(ProductOutboundPayload::FinalReply(FinalReplyView {
            turn_run_id: ironclaw_turns::TurnRunId::new(),
            text: "hello".to_string(),
            generated_at: Utc::now(),
        })),
        context: render_context(""),
    })
    .expect_err("route metadata must include a room");
    assert_eq!(
        missing_route.reason_code,
        MatrixReasonCode::MissingRouteMetadata
    );

    let err = render_matrix_outbound(MatrixRenderInput {
        envelope: outbound(ProductOutboundPayload::KeepAlive),
        context: render_context("!room:example.org"),
    })
    .expect_err("keepalive is not a Matrix send command");
    assert_eq!(
        err.reason_code,
        MatrixReasonCode::UnsupportedOutboundPayload
    );

    let err = render_matrix_outbound(MatrixRenderInput {
        envelope: outbound(ProductOutboundPayload::FinalReply(FinalReplyView {
            turn_run_id: ironclaw_turns::TurnRunId::new(),
            text: "hello".to_string(),
            generated_at: Utc::now(),
        })),
        context: render_context("!evil:example.org"),
    })
    .expect_err("target room must be allowlisted");
    assert_eq!(err.reason_code, MatrixReasonCode::UnauthorizedTargetRoom);
}

fn outbound(payload: ProductOutboundPayload) -> ProductOutboundEnvelope {
    ProductOutboundEnvelope::new(
        ironclaw_product_adapters::ProductAdapterId::new("matrix").expect("adapter id"),
        ironclaw_product_adapters::AdapterInstallationId::new("matrix-installation")
            .expect("installation id"),
        ProductOutboundTarget::new(
            ReplyTargetBindingRef::new("binding").expect("binding"),
            ExternalConversationRef::new(None, "!room:example.org", None, None)
                .expect("conversation"),
            Some(
                ExternalActorRef::new("matrix_user", "@alice:example.org", None::<String>)
                    .expect("actor"),
            ),
        ),
        ProjectionCursor::new("cursor").expect("cursor"),
        payload,
    )
}
