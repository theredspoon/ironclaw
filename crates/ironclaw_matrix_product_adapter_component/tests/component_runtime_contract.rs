use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use chrono::Utc;
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, EgressRequest, ExternalActorRef,
    ExternalConversationRef, FinalReplyView, ParsedProductInbound, ProductAdapterCapabilities,
    ProductAdapterId, ProductAttachmentKind, ProductInboundPayload, ProductOutboundEnvelope,
    ProductOutboundPayload, ProductOutboundTarget, ProductTriggerReason, ProjectionCursor,
    ProtocolAuthEvidence, ProtocolAuthFailure, mark_bearer_token_verified,
};
use ironclaw_turns::ReplyTargetBindingRef;
use ironclaw_wasm_product_adapters::{
    ProductAdapterComponentRuntime, ProductAdapterComponentRuntimeConfig, RuntimeError,
};
use serde_json::{Value, json};

const ADAPTER_ID: &str = "matrix";
const INSTALLATION_ID: &str = "matrix-default";
const ROOM_ID: &str = "!room:example.org";
const SENDER_ID: &str = "@alice:example.org";
const MATRIX_HOST: &str = "matrix.org";
const MATRIX_CREDENTIAL_HANDLE: &str = "matrix-access-token";

static COMPONENT_ARTIFACT: OnceLock<PathBuf> = OnceLock::new();

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is under workspace/crates")
        .to_path_buf()
}

fn component_artifact() -> &'static PathBuf {
    COMPONENT_ARTIFACT.get_or_init(|| {
        let root = workspace_root();
        let status = Command::new("./scripts/build-product-adapter-components.sh")
            .current_dir(&root)
            .status()
            .expect("spawn component build");
        assert!(status.success(), "component build failed: {status}");
        root.join("target/wasm32-wasip2/release/ironclaw_matrix_product_adapter_component.wasm")
    })
}

fn prepared_component() -> (
    ProductAdapterComponentRuntime,
    ironclaw_wasm_product_adapters::PreparedProductAdapterComponent,
) {
    let mut testing_config = ProductAdapterComponentRuntimeConfig::for_testing();
    testing_config.default_limits = testing_config
        .default_limits
        .clone()
        .with_memory_bytes(4 * 1024 * 1024)
        .with_fuel(10_000_000);
    testing_config.max_component_bytes = 2 * 1024 * 1024;
    let runtime = ProductAdapterComponentRuntime::new(testing_config).expect("runtime");
    let bytes = std::fs::read(component_artifact()).expect("component artifact");
    let prepared = runtime
        .prepare("matrix", &bytes)
        .expect("prepare component");
    (runtime, prepared)
}

fn verified_evidence() -> ProtocolAuthEvidence {
    ProtocolAuthEvidence::test_verified(
        AuthRequirement::SharedSecretHeader {
            header_name: "x-matrix-webhook-secret".to_string(),
        },
        "matrix-webhook",
    )
}

fn text_event_for(room_id: &str, sender_id: &str, event_id: &str, body: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "type": "m.room.message",
        "event_id": event_id,
        "room_id": room_id,
        "sender": sender_id,
        "origin_server_ts": 1710000000000_i64,
        "content": {
            "msgtype": "m.text",
            "body": body,
            "m.relates_to": {
                "rel_type": "m.thread",
                "event_id": "$root:example.org",
                "m.in_reply_to": {"event_id": "$reply:example.org"}
            }
        }
    }))
    .expect("event json")
}

fn text_event(body: &str) -> Vec<u8> {
    text_event_for(ROOM_ID, SENDER_ID, "$event:example.org", body)
}

fn media_event() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "type": "m.room.message",
        "event_id": "$media:example.org",
        "room_id": ROOM_ID,
        "sender": SENDER_ID,
        "origin_server_ts": 1710000000000_i64,
        "content": {
            "msgtype": "m.image",
            "body": "../unsafe\u{0000}name.PNG",
            "url": "mxc://example.org/media-id",
            "info": {"mimetype": "IMAGE/PNG", "size": 4096}
        }
    }))
    .expect("event json")
}

fn encrypted_event() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "type": "m.room.encrypted",
        "event_id": "$encrypted:example.org",
        "room_id": ROOM_ID,
        "sender": SENDER_ID,
        "content": {"algorithm": "m.megolm.v1.aes-sha2", "session_id": "opaque"}
    }))
    .expect("event json")
}

fn outbound_for(
    adapter_id: &str,
    installation_id: &str,
    room_id: &str,
    payload: ProductOutboundPayload,
) -> ProductOutboundEnvelope {
    ProductOutboundEnvelope::new(
        ProductAdapterId::new(adapter_id).expect("adapter id"),
        AdapterInstallationId::new(installation_id).expect("installation id"),
        ProductOutboundTarget::new(
            ReplyTargetBindingRef::new("binding").expect("binding ref"),
            ExternalConversationRef::new(
                None,
                room_id,
                Some("$root:example.org"),
                Some("$reply:example.org"),
            )
            .expect("conversation"),
            Some(ExternalActorRef::new("matrix_user", SENDER_ID, None::<String>).expect("actor")),
        ),
        ProjectionCursor::new("cursor").expect("cursor"),
        payload,
    )
}

fn outbound(payload: ProductOutboundPayload) -> ProductOutboundEnvelope {
    outbound_for(ADAPTER_ID, INSTALLATION_ID, ROOM_ID, payload)
}

fn final_reply(text: &str) -> ProductOutboundPayload {
    ProductOutboundPayload::FinalReply(FinalReplyView {
        turn_run_id: ironclaw_turns::TurnRunId::new(),
        text: text.to_string(),
        generated_at: Utc::now(),
    })
}

#[test]
fn component_build_ignores_host_coverage_flags() {
    let root = workspace_root();
    let status = Command::new("./scripts/build-product-adapter-components.sh")
        .current_dir(&root)
        .status()
        .expect("spawn component build");
    assert!(
        status.success(),
        "component build inherited host compiler instrumentation: {status}"
    );
}

#[test]
fn matrix_component_manifest_loads_with_host_validated_contract() {
    let (_runtime, prepared) = prepared_component();
    let manifest = prepared.manifest();

    assert_eq!(manifest.adapter_id.as_str(), ADAPTER_ID);
    assert_eq!(manifest.installation_id.as_str(), INSTALLATION_ID);
    let caps: ProductAdapterCapabilities =
        serde_json::from_str(&manifest.capabilities_json).expect("capabilities JSON");
    assert!(caps.iter().any(|flag| {
        matches!(
            flag,
            ironclaw_product_adapters::ProductCapabilityFlag::InboundMessages
        )
    }));
    assert_eq!(manifest.declared_egress_targets.len(), 1);
    assert_eq!(
        manifest.declared_egress_targets[0].host.as_str(),
        MATRIX_HOST
    );
    assert_eq!(
        manifest.declared_egress_targets[0]
            .credential_handle
            .as_ref()
            .expect("credential")
            .as_str(),
        MATRIX_CREDENTIAL_HANDLE
    );
    assert_eq!(manifest.declared_auth_requirements.len(), 1);
}

#[test]
fn matrix_component_parses_inbound_into_canonical_product_json() {
    let (runtime, prepared) = prepared_component();

    let parsed = runtime
        .parse_inbound(
            &prepared,
            &text_event("hello from matrix"),
            &verified_evidence(),
        )
        .expect("parse inbound");
    let parsed: ParsedProductInbound =
        serde_json::from_str(&parsed.parsed_json).expect("canonical parsed inbound");

    assert_eq!(
        parsed.external_event_id.as_str(),
        "matrix-matrix-default-$event:example.org"
    );
    assert_eq!(parsed.external_actor_ref.id(), SENDER_ID);
    assert_eq!(parsed.external_conversation_ref.conversation_id(), ROOM_ID);
    assert_eq!(
        parsed.external_conversation_ref.topic_id(),
        Some("$root:example.org")
    );
    assert_eq!(
        parsed.external_conversation_ref.reply_target_message_id(),
        Some("$reply:example.org")
    );
    match parsed.payload {
        ProductInboundPayload::UserMessage(message) => {
            assert_eq!(message.text, "hello from matrix");
            assert_eq!(message.trigger, ProductTriggerReason::DirectChat);
            assert!(message.attachments.is_empty());
        }
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[test]
fn matrix_component_preserves_media_attachments() {
    let (runtime, prepared) = prepared_component();

    let parsed = runtime
        .parse_inbound(&prepared, &media_event(), &verified_evidence())
        .expect("parse media inbound");
    let parsed: ParsedProductInbound =
        serde_json::from_str(&parsed.parsed_json).expect("canonical parsed inbound");

    let ProductInboundPayload::UserMessage(message) = parsed.payload else {
        panic!("unexpected payload");
    };
    assert_eq!(message.attachments.len(), 1);
    assert_eq!(
        message.attachments[0].external_file_id,
        "$media:example.org"
    );
    assert_eq!(message.attachments[0].mime_type, "image/png");
    assert_eq!(
        message.attachments[0].filename.as_deref(),
        Some("unsafe_name.PNG")
    );
    assert_eq!(message.attachments[0].size_bytes, Some(4096));
    assert_eq!(message.attachments[0].kind, ProductAttachmentKind::Image);
}

#[test]
fn matrix_component_rejects_unverified_inbound_evidence() {
    let (runtime, prepared) = prepared_component();

    let err = runtime
        .parse_inbound(
            &prepared,
            &text_event("hello"),
            &ProtocolAuthEvidence::failed(ProtocolAuthFailure::Missing),
        )
        .expect_err("failed evidence must not parse");

    assert!(
        matches!(err, RuntimeError::AuthenticationFailed(_)),
        "{err:?}"
    );
}

#[test]
fn matrix_component_rejects_verified_evidence_for_wrong_auth_requirement() {
    let (runtime, prepared) = prepared_component();

    let err = runtime
        .parse_inbound(
            &prepared,
            &text_event("hello"),
            &mark_bearer_token_verified("alice"),
        )
        .expect_err("bearer evidence must not satisfy shared-secret manifest");

    assert!(
        matches!(err, RuntimeError::AuthenticationFailed(ref message)
            if message.contains("does not match")),
        "{err:?}"
    );
}

#[test]
fn matrix_component_renders_final_reply_as_policy_checked_egress() {
    let (runtime, prepared) = prepared_component();
    let envelope = outbound(final_reply("**hello** matrix"));
    let outbound_json = serde_json::to_string(&envelope).expect("outbound JSON");

    let rendered = runtime
        .render_outbound(&prepared, &outbound_json)
        .expect("render outbound");
    let request: EgressRequest =
        serde_json::from_slice(&serde_json::to_vec(&rendered.egress_request).unwrap())
            .expect("canonical egress request");

    assert_eq!(request.host().as_str(), MATRIX_HOST);
    assert_eq!(
        request.credential_handle().expect("credential").as_str(),
        MATRIX_CREDENTIAL_HANDLE
    );
    assert_eq!(request.method().as_str(), "PUT");
    assert!(request.path().as_str().starts_with(
        "/_matrix/client/v3/rooms/%21room%3Aexample.org/send/m.room.message/ironclaw-"
    ));
    let body: Value = serde_json::from_slice(request.body()).expect("matrix request body");
    assert_eq!(body["msgtype"], "m.text");
    assert_eq!(body["body"], "hello matrix");
    assert_eq!(body["format"], "org.matrix.custom.html");
    assert_eq!(
        body["m.relates_to"]["m.in_reply_to"]["event_id"],
        "$reply:example.org"
    );
    assert_eq!(body["m.relates_to"]["event_id"], "$root:example.org");
    assert_eq!(body["m.relates_to"]["rel_type"], "m.thread");
    assert!(
        body["formatted_body"]
            .as_str()
            .expect("formatted body")
            .contains("<strong>hello</strong>")
    );
}

#[test]
fn matrix_component_rejects_unsupported_or_unauthorized_outbound() {
    let (runtime, prepared) = prepared_component();
    let keepalive = serde_json::to_string(&outbound(ProductOutboundPayload::KeepAlive))
        .expect("keepalive outbound JSON");
    let err = runtime
        .render_outbound(&prepared, &keepalive)
        .expect_err("keepalive is unsupported");
    assert!(
        matches!(err, RuntimeError::ExecutionFailed { ref message, .. }
            if message.contains("unsupported_outbound_payload")),
        "{err:?}"
    );

    let envelope = outbound_for(
        "telegram",
        INSTALLATION_ID,
        ROOM_ID,
        final_reply("wrong adapter"),
    );
    let err = runtime
        .render_outbound(
            &prepared,
            &serde_json::to_string(&envelope).expect("outbound JSON"),
        )
        .expect_err("adapter id mismatch");
    assert!(
        matches!(err, RuntimeError::ExecutionFailed { ref message, .. }
            if message.contains("invalid_adapter_id")),
        "{err:?}"
    );

    let envelope = outbound_for(
        ADAPTER_ID,
        "other-install",
        ROOM_ID,
        final_reply("wrong install"),
    );
    let err = runtime
        .render_outbound(
            &prepared,
            &serde_json::to_string(&envelope).expect("outbound JSON"),
        )
        .expect_err("installation id mismatch");
    assert!(
        matches!(err, RuntimeError::ExecutionFailed { ref message, .. }
            if message.contains("invalid_installation_id")),
        "{err:?}"
    );
}

#[test]
fn matrix_component_rejects_malformed_inbound_but_does_not_own_policy() {
    let (runtime, prepared) = prepared_component();

    let err = runtime
        .parse_inbound(&prepared, br#"{"not": "matrix"}"#, &verified_evidence())
        .expect_err("malformed event");
    assert!(
        matches!(err, RuntimeError::ExecutionFailed { ref message, .. }
            if message.contains("MalformedMatrixEvent")),
        "{err:?}"
    );

    let parsed = runtime
        .parse_inbound(
            &prepared,
            &text_event_for(
                "!other:example.org",
                "@mallory:example.org",
                "$other:example.org",
                "pre-transport parse",
            ),
            &verified_evidence(),
        )
        .expect("guest parser is not the installation policy boundary");
    let parsed: ParsedProductInbound =
        serde_json::from_str(&parsed.parsed_json).expect("canonical parsed inbound");
    assert_eq!(
        parsed.external_conversation_ref.conversation_id(),
        "!other:example.org"
    );
}

#[test]
fn matrix_component_rejects_size_and_depth_limits() {
    let (runtime, prepared) = prepared_component();

    let oversized = vec![b' '; 256 * 1024 + 1];
    let err = runtime
        .parse_inbound(&prepared, &oversized, &verified_evidence())
        .expect_err("oversized inbound");
    assert!(
        matches!(err, RuntimeError::ExecutionFailed { ref message, .. }
            if message.contains("raw_payload_too_large")),
        "{err:?}"
    );

    let mut deep = json!(null);
    for _ in 0..65 {
        deep = json!([deep]);
    }
    let err = runtime
        .parse_inbound(
            &prepared,
            serde_json::to_string(&deep).expect("deep json").as_bytes(),
            &verified_evidence(),
        )
        .expect_err("deep inbound");
    assert!(
        matches!(err, RuntimeError::ExecutionFailed { ref message, .. }
            if message.contains("json_too_deep")),
        "{err:?}"
    );

    let huge_outbound =
        serde_json::to_string(&outbound(final_reply(&"x".repeat(256 * 1024)))).expect("outbound");
    let err = runtime
        .render_outbound(&prepared, &huge_outbound)
        .expect_err("oversized outbound");
    assert!(
        matches!(err, RuntimeError::ExecutionFailed { ref message, .. }
            if message.contains("outbound_json_too_large")),
        "{err:?}"
    );
}

#[test]
fn matrix_component_renders_sanitized_html_for_adversarial_markdown() {
    let (runtime, prepared) = prepared_component();
    let envelope = outbound(final_reply(
        "<script>alert(1)</script><img src=x onerror=alert(1)> [x](javascript:alert(1)) <a onclick=\"x\" href=\"https://example.org\">safe</a>",
    ));
    let rendered = runtime
        .render_outbound(
            &prepared,
            &serde_json::to_string(&envelope).expect("outbound JSON"),
        )
        .expect("render outbound");
    let body: Value = serde_json::from_slice(rendered.egress_request.body()).expect("body");
    let formatted = body["formatted_body"].as_str().expect("formatted body");
    let lower = formatted.to_ascii_lowercase();

    for forbidden in [
        "<script",
        "<img",
        "javascript:",
        "onerror",
        "onclick",
        "vbscript:",
    ] {
        assert!(
            !lower.contains(forbidden),
            "formatted body still contains {forbidden}: {formatted}"
        );
    }
}

#[test]
fn matrix_component_maps_encrypted_events_to_no_op() {
    let (runtime, prepared) = prepared_component();
    let parsed = runtime
        .parse_inbound(&prepared, &encrypted_event(), &verified_evidence())
        .expect("encrypted events parse as no-op");
    let parsed: ParsedProductInbound =
        serde_json::from_str(&parsed.parsed_json).expect("canonical parsed inbound");
    assert!(matches!(parsed.payload, ProductInboundPayload::NoOp));
}

#[test]
fn matrix_component_source_does_not_define_product_dto_shadows() {
    let source = [
        include_str!("../src/lib.rs"),
        include_str!("../src/inbound.rs"),
        include_str!("../src/outbound.rs"),
        include_str!("../src/egress.rs"),
        include_str!("../src/manifest.rs"),
    ]
    .join("\n");

    for forbidden in [
        "struct ParsedProductInbound",
        "struct ProductOutboundEnvelope",
        "struct EgressRequest",
        "enum ProductInboundPayload",
        "struct ProductAttachmentDescriptor",
    ] {
        assert!(
            !source.contains(forbidden),
            "component must not define product DTO shadow `{forbidden}`"
        );
    }
}

#[test]
fn group0_forbidden_config_boundary_changes_are_absent() {
    let source = [
        include_str!("../../ironclaw_wasm_product_adapters/wit/product_adapter.wit"),
        include_str!("../../ironclaw_wasm_product_adapters/src/config.rs"),
        include_str!("../../ironclaw_wasm_product_adapters/src/lib.rs"),
        include_str!("../../ironclaw_wasm_product_adapters/src/store.rs"),
        include_str!("../../ironclaw_wasm_product_adapters/src/component_runtime.rs"),
        include_str!("../src/lib.rs"),
        include_str!("../src/inbound.rs"),
        include_str!("../src/outbound.rs"),
        include_str!("../src/manifest.rs"),
    ]
    .join("\n");

    let forbidden = [
        ["installation", "-config-json"].concat(),
        ["matrix", "-config-json"].concat(),
        ["installation", "_config_json"].concat(),
        ["ProductAdapter", "InstallationConfig"].concat(),
        ["MatrixProductAdapter", "InstallationConfig"].concat(),
        ["ProductAdapter", "AuthConfig"].concat(),
        ["ProductAdapter", "EgressTargetConfig"].concat(),
        ["product_adapter_host::", "installation", "_config_json"].concat(),
        ["product_adapter_host::", "http_egress"].concat(),
    ];

    for forbidden in forbidden {
        assert!(
            !source.contains(&forbidden),
            "R002A must not expose forbidden Group 0 boundary `{forbidden}`"
        );
    }
}
