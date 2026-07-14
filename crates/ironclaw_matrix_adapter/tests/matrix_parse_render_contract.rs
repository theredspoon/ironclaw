use chrono::Utc;
use ironclaw_matrix_adapter::{
    EncryptionState, MatrixParseInput, MatrixParsePolicy, MatrixProductAdapter,
    MatrixProductAdapterConfig, MatrixOutboundCommand, MatrixReasonCode, MatrixRenderContext,
    MatrixRenderInput, MatrixRouteMetadata, RelationKind, parse_matrix_event,
    render_matrix_outbound,
};
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, ExternalActorRef, ExternalConversationRef,
    FakeOutboundDeliverySink, FakeProtocolHttpEgress, FinalReplyView, ProductAdapter,
    ProductAdapterError, ProductAdapterId, ProductAttachmentKind, ProductInboundPayload,
    ProductOutboundEnvelope, ProductOutboundPayload, ProductOutboundTarget, ProductRenderOutcome,
    ProjectionCursor, ProtocolAuthEvidence, ProtocolAuthFailure,
};
use ironclaw_turns::ReplyTargetBindingRef;
use proptest::prelude::*;
use serde_json::{Value, json};
use std::panic;

const ADAPTER_SOURCE: &str = include_str!("../src/lib.rs");

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

fn text_event_with_id(event_id: &str, content: Value) -> Value {
    let mut event = text_event(content);
    event["event_id"] = json!(event_id);
    event
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

fn adapter() -> MatrixProductAdapter {
    MatrixProductAdapter::new(MatrixProductAdapterConfig {
        adapter_id: ProductAdapterId::new("matrix").expect("adapter id"),
        installation_id: AdapterInstallationId::new("inst_abc123").expect("installation id"),
        parse_policy: allow_policy(),
        auth_requirement: AuthRequirement::SharedSecretHeader {
            header_name: "x-matrix-webhook-secret".to_string(),
        },
    })
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
fn matrix_product_adapter_parses_authenticated_inbound_payload() {
    let adapter = adapter();
    let evidence =
        ProtocolAuthEvidence::test_verified(adapter.auth_requirement().clone(), "matrix-webhook");
    let raw = serde_json::to_vec(&text_event(json!({
        "msgtype": "m.text",
        "body": "hello through product adapter"
    })))
    .expect("event json");

    let parsed = adapter
        .parse_inbound(&raw, &evidence)
        .expect("product adapter parse should succeed");

    assert_eq!(
        parsed.external_event_id.as_str(),
        "matrix-inst_abc123-$event:example.org"
    );
    match parsed.payload {
        ProductInboundPayload::UserMessage(payload) => {
            assert_eq!(payload.text, "hello through product adapter");
        }
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[test]
fn matrix_product_adapter_rejects_unverified_inbound_payload() {
    let adapter = adapter();
    let raw = serde_json::to_vec(&text_event(json!({
        "msgtype": "m.text",
        "body": "hello"
    })))
    .expect("event json");

    let err = adapter
        .parse_inbound(
            &raw,
            &ProtocolAuthEvidence::failed(ProtocolAuthFailure::Missing),
        )
        .expect_err("host auth evidence must be verified");

    assert!(matches!(err, ProductAdapterError::Authentication(_)));
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
    assert_eq!(parsed.facts.room_id, "!room:example.org");
    assert_eq!(parsed.facts.sender, "@alice:example.org");
    match parsed.product.payload {
        ProductInboundPayload::UserMessage(payload) => assert_eq!(payload.text, "hello matrix"),
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[test]
fn wasm_path_does_not_define_shadow_product_contracts() {
    assert!(!ADAPTER_SOURCE.contains("mod wasm_product"));
    assert!(!ADAPTER_SOURCE.contains("pub struct ParsedProductInbound"));
    assert!(!ADAPTER_SOURCE.contains("pub struct ProductOutboundEnvelope"));
    assert!(!ADAPTER_SOURCE.contains("pub enum ProductInboundPayload"));
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
fn formatted_html_allowlist_matches_matrix_contract() {
    let parsed = parse(text_event(json!({
        "msgtype": "m.text",
        "body": "safe fallback",
        "format": "org.matrix.custom.html",
        "formatted_body": "<p><u>under</u><s>strike</s><a href=\"mailto:ops@example.org\">mail</a><a href=\"https://example.org\">site</a></p>"
    })));

    assert_eq!(
        parsed.metadata.formatted_body.as_deref(),
        Some("understrike<a>mail</a><a href=\"https://example.org\">site</a>")
    );
}

#[test]
fn xss_fixture_set_downgrades_or_sanitizes_to_safe_html() {
    let vectors = [
        r#"<img src=x onerror=alert(1)>"#,
        r#"<svg onload=alert(1)>"#,
        r#"<a href="data:text/html,<script>alert(1)</script>">x</a>"#,
        r#"<iframe src="javascript:alert(1)">x</iframe>"#,
        r#"<object data="javascript:alert(1)">x</object>"#,
        r#"<embed src="javascript:alert(1)">"#,
        r#"<div style="width: expression(alert(1))">x</div>"#,
        r#"&lt;img src=x onerror=alert(1)&gt;"#,
        r#"<A HREF="JaVaScRiPt:alert(1)" OnLoAd="alert(1)">x</A>"#,
    ];

    for vector in vectors {
        let parsed = parse(text_event(json!({
            "msgtype": "m.text",
            "body": "plain fallback",
            "format": "org.matrix.custom.html",
            "formatted_body": vector
        })));
        let rendered = parsed.metadata.formatted_body.unwrap_or_default();
        assert!(!rendered.contains("javascript:"), "{rendered}");
        assert!(!rendered.contains("data:"), "{rendered}");
        assert!(!rendered.to_ascii_lowercase().contains("onload"), "{rendered}");
        assert!(!rendered.to_ascii_lowercase().contains("onerror"), "{rendered}");
        assert!(!rendered.to_ascii_lowercase().contains("<script"), "{rendered}");
        assert!(!rendered.to_ascii_lowercase().contains("<iframe"), "{rendered}");
        assert!(!rendered.to_ascii_lowercase().contains("<object"), "{rendered}");
        assert!(!rendered.to_ascii_lowercase().contains("<embed"), "{rendered}");
        assert!(!rendered.to_ascii_lowercase().contains("expression("), "{rendered}");
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
fn oversized_or_deeply_nested_formatted_html_downgrades_to_plaintext() {
    let oversized = parse(text_event(json!({
        "msgtype": "m.text",
        "body": "plain fallback",
        "format": "org.matrix.custom.html",
        "formatted_body": "x".repeat(64 * 1024 + 1)
    })));
    assert!(oversized.metadata.formatted_body.is_none());
    assert_eq!(
        oversized.metadata.diagnostics[0].reason_code,
        MatrixReasonCode::UnsafeFormattedBody
    );

    let deeply_nested = format!("{}safe{}", "<b>".repeat(21), "</b>".repeat(21));
    let parsed = parse(text_event(json!({
        "msgtype": "m.text",
        "body": "plain fallback",
        "format": "org.matrix.custom.html",
        "formatted_body": deeply_nested
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
fn media_filename_and_mime_are_hardened() {
    let parsed = parse(text_event(json!({
        "msgtype": "m.file",
        "body": "../<script>\u{0000}unsafe?.bin",
        "url": "mxc://example.org/media-id",
        "info": {"mimetype": "Application/X Weird\u{0000}", "size": 4096}
    })));

    let ProductInboundPayload::UserMessage(payload) = parsed.product.payload else {
        panic!("expected media user message");
    };
    let attachment = &payload.attachments[0];
    assert_eq!(attachment.filename.as_deref(), Some("script__unsafe_.bin"));
    assert_eq!(attachment.mime_type, "application/octet-stream");

    let empty_name = parse(text_event(json!({
        "msgtype": "m.file",
        "body": "../..",
        "url": "mxc://example.org/media-id",
        "info": {}
    })));
    let ProductInboundPayload::UserMessage(payload) = empty_name.product.payload else {
        panic!("expected media user message");
    };
    assert_eq!(payload.attachments[0].filename.as_deref(), Some("untitled"));
    assert_eq!(payload.attachments[0].mime_type, "application/octet-stream");
}

#[test]
fn event_id_validation_accepts_current_and_legacy_matrix_forms() {
    let current = parse(text_event_with_id(
        "$opaqueBase64Hash",
        json!({"msgtype": "m.text", "body": "hello"}),
    ));
    assert_eq!(
        current.facts.deduplication_key,
        "matrix-inst_abc123-$opaqueBase64Hash"
    );

    let legacy = parse(text_event_with_id(
        "$opaque:example.org",
        json!({"msgtype": "m.text", "body": "hello"}),
    ));
    assert_eq!(
        legacy.facts.deduplication_key,
        "matrix-inst_abc123-$opaque:example.org"
    );

    let invalid = parse_matrix_event(MatrixParseInput {
        raw_event: text_event_with_id(
            "not-an-event-id",
            json!({"msgtype": "m.text", "body": "hello"}),
        ),
        installation_id: "inst_abc123".to_string(),
        policy: allow_policy(),
    })
    .expect_err("event ids must use Matrix event sigil");
    assert_eq!(invalid.reason_code, MatrixReasonCode::MalformedMatrixEvent);
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

    let embedded = parse_matrix_event(MatrixParseInput {
        raw_event: json!({
            "type": "m.room.member",
            "event_id": "$prefix Bearer tokenvalue:example.org",
            "room_id": "!room:example.org",
            "sender": "@alice:example.org",
            "content": {"body": "ignored"}
        }),
        installation_id: "inst_abc123".to_string(),
        policy: allow_policy(),
    })
    .expect_err("embedded credential pattern should be diagnostic-redacted");
    assert_eq!(embedded.event_id.as_deref(), Some("[REDACTED-CREDENTIAL]"));
}

#[test]
fn expanded_credential_patterns_are_redacted() {
    for token in [
        "AKIA1234567890ABCDEF",
        "ASIA1234567890ABCDEF",
        "ghp_abcdefghijklmnopqrstuvwxyz123456",
        "gho_abcdefghijklmnopqrstuvwxyz123456",
        "ghs_abcdefghijklmnopqrstuvwxyz123456",
        "xoxb-1234567890-secret",
        "xoxp-1234567890-secret",
        "eyJhbGciOiJIUzI1NiJ9.secret.signature",
        "AIzaSyDabcdefghijklmnopqrstuvwxyz",
    ] {
        let diagnostic = parse_matrix_event(MatrixParseInput {
            raw_event: json!({
                "type": "m.room.member",
                "event_id": format!("$event-{token}:example.org"),
                "room_id": "!room:example.org",
                "sender": "@alice:example.org",
                "content": {"body": "ignored"}
            }),
            installation_id: "inst_abc123".to_string(),
            policy: allow_policy(),
        })
        .expect_err("unsupported event should be diagnostic");
        let json = serde_json::to_string(&diagnostic).expect("diagnostic json");
        assert!(json.contains("[REDACTED-CREDENTIAL]"), "{json}");
        assert!(!json.contains(token), "{json}");
    }
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
fn metadata_debug_redacts_internal_and_adversarial_fields() {
    let parsed = parse(text_event(json!({
        "msgtype": "m.image",
        "body": "<b>body</b>",
        "format": "org.matrix.custom.html",
        "formatted_body": "<b>safe</b>",
        "url": "mxc://example.org/media-id",
        "info": {"mimetype": "image/png", "size": 12}
    })));
    let debug = format!("{:?}", parsed.metadata);
    assert!(!debug.contains("mxc://"));
    assert!(!debug.contains("<b>safe</b>"));
    assert!(!debug.contains("<b>body</b>"));
    assert!(!debug.contains("session_id"));

    let diagnostic = parse_matrix_event(MatrixParseInput {
        raw_event: json!({
            "type": "m.room.member",
            "event_id": "$event:example.org",
            "room_id": "!room\nERROR:example.org",
            "sender": "@attacker\nERROR:example.org",
            "content": {"body": "ignored"}
        }),
        installation_id: "inst_abc123".to_string(),
        policy: MatrixParsePolicy::default(),
    })
    .expect_err("control characters should become diagnostic");
    let debug = format!("{diagnostic:?}");
    assert!(!debug.contains('\n'));
    assert!(!debug.contains("ERROR:example.org\n"));
}

#[test]
fn parser_is_panic_safe_for_deeply_nested_json() {
    let handle = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let mut value = json!("leaf");
            for _ in 0..10_000 {
                value = json!({ "nested": value });
            }
            panic::catch_unwind(|| {
                parse_matrix_event(MatrixParseInput {
                    raw_event: value,
                    installation_id: "inst_abc123".to_string(),
                    policy: MatrixParsePolicy::default(),
                })
            })
        })
        .expect("deep-json test thread should spawn");
    let result = handle.join().expect("deep-json test thread should not panic");
    assert!(result.is_ok());
}

#[test]
fn parser_is_panic_safe_for_deeply_nested_arrays() {
    let handle = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let mut value = json!("leaf");
            for _ in 0..10_000 {
                value = json!([value]);
            }
            panic::catch_unwind(|| {
                parse_matrix_event(MatrixParseInput {
                    raw_event: value,
                    installation_id: "inst_abc123".to_string(),
                    policy: MatrixParsePolicy::default(),
                })
            })
        })
        .expect("deep-array test thread should spawn");
    let result = handle.join().expect("deep-array test thread should not panic");
    assert!(result.is_ok());
}

proptest! {
    #[test]
    fn parser_is_panic_safe_for_arbitrary_json(value in arbitrary_json()) {
        let result = panic::catch_unwind(|| {
            parse_matrix_event(MatrixParseInput {
                raw_event: value,
                installation_id: "inst_abc123".to_string(),
                policy: MatrixParsePolicy::default(),
            })
        });
        prop_assert!(result.is_ok());
    }
}

fn arbitrary_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|value| Value::Number(value.into())),
        ".*".prop_map(Value::String),
    ];
    leaf.prop_recursive(8, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::btree_map(".*", inner, 0..8)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
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

#[tokio::test]
async fn matrix_product_adapter_renders_outbound_at_product_boundary() {
    let adapter = adapter();
    let outcome = adapter
        .render_outbound(
            outbound(ProductOutboundPayload::FinalReply(FinalReplyView {
                turn_run_id: ironclaw_turns::TurnRunId::new(),
                text: "**hello** matrix".to_string(),
                generated_at: Utc::now(),
            })),
            &FakeProtocolHttpEgress::new(Vec::<String>::new()),
            &FakeOutboundDeliverySink::new(),
        )
        .await
        .expect("product adapter render should succeed");

    let ProductRenderOutcome::SynchronousResponse(response) = outcome else {
        panic!("expected synchronous Matrix command response");
    };
    assert_eq!(
        response.content_type,
        "application/vnd.ironclaw.matrix-command+json"
    );
    let command: ironclaw_matrix_adapter::MatrixOutboundCommand =
        serde_json::from_slice(&response.body).expect("matrix command json");
    assert_eq!(command.room_id(), "!room:example.org");
    assert_eq!(command.body()["body"], "hello matrix");
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

#[test]
fn test_parse_render_round_trip_preserves_semantics() {
    let parsed = parse(text_event(json!({
        "msgtype": "m.text",
        "body": "round trip",
        "m.relates_to": {
            "rel_type": "m.thread",
            "event_id": "$root:example.org",
            "m.in_reply_to": {"event_id": "$reply:example.org"}
        }
    })));

    let command = render_matrix_outbound(MatrixRenderInput {
        envelope: outbound(ProductOutboundPayload::FinalReply(FinalReplyView {
            turn_run_id: ironclaw_turns::TurnRunId::new(),
            text: "round trip".to_string(),
            generated_at: Utc::now(),
        })),
        context: MatrixRenderContext {
            installation_id: "inst_abc123".to_string(),
            route_metadata: MatrixRouteMetadata {
                room_id: parsed.metadata.room_id.clone(),
                reply_to_event_id: parsed.metadata.reply_to_event_id.clone(),
                thread_root_event_id: parsed
                    .metadata
                    .relation
                    .as_ref()
                    .map(|relation| relation.event_id.clone()),
            },
            allowed_target_rooms: vec![parsed.metadata.room_id.clone()],
        },
    })
    .expect("round-trip render");

    let MatrixOutboundCommand::SendMessage { room_id, body, .. } = command else {
        panic!("expected send message command");
    };
    assert_eq!(room_id, parsed.metadata.room_id);
    assert_eq!(body["body"], "round trip");
    assert_eq!(
        body["m.relates_to"]["m.in_reply_to"]["event_id"],
        "$reply:example.org"
    );
    assert_eq!(body["m.relates_to"]["event_id"], "$root:example.org");
    assert_eq!(body["m.relates_to"]["rel_type"], "m.thread");
    assert_eq!(
        parsed.facts.deduplication_key,
        "matrix-inst_abc123-$event:example.org"
    );
}

fn outbound(payload: ProductOutboundPayload) -> ProductOutboundEnvelope {
    ProductOutboundEnvelope::new(
        ironclaw_product_adapters::ProductAdapterId::new("matrix").expect("adapter id"),
        ironclaw_product_adapters::AdapterInstallationId::new("inst_abc123")
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
