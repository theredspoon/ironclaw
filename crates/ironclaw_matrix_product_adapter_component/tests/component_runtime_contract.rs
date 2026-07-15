use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use chrono::Utc;
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, EgressRequest, ExternalActorRef,
    ExternalConversationRef, FinalReplyView, ParsedProductInbound, ProductAdapterCapabilities,
    ProductAdapterId, ProductInboundPayload, ProductOutboundEnvelope, ProductOutboundPayload,
    ProductOutboundTarget, ProductTriggerReason, ProjectionCursor, ProtocolAuthEvidence,
    ProtocolAuthFailure,
};
use ironclaw_turns::ReplyTargetBindingRef;
use ironclaw_wasm_product_adapters::{
    ProductAdapterComponentRuntime, ProductAdapterComponentRuntimeConfig, RuntimeError,
};
use serde_json::{Value, json};

const ADAPTER_ID: &str = "matrix";
const INSTALLATION_ID: &str = "inst_abc123";
const ROOM_ID: &str = "!room:example.org";
const SENDER_ID: &str = "@alice:example.org";
const MATRIX_HOST: &str = "matrix.example.org";
const MATRIX_CREDENTIAL_HANDLE: &str = "matrix_access_token";

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
        let status = Command::new(env!("CARGO"))
            .current_dir(&root)
            .args([
                "rustc",
                "-p",
                "ironclaw_matrix_product_adapter_component",
                "--release",
                "--target",
                "wasm32-wasip2",
                "--crate-type",
                "cdylib",
                "--",
                "-C",
                "opt-level=z",
                "-C",
                "strip=symbols",
            ])
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

fn text_event(body: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "type": "m.room.message",
        "event_id": "$event:example.org",
        "room_id": ROOM_ID,
        "sender": SENDER_ID,
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

fn outbound(payload: ProductOutboundPayload) -> ProductOutboundEnvelope {
    ProductOutboundEnvelope::new(
        ProductAdapterId::new(ADAPTER_ID).expect("adapter id"),
        AdapterInstallationId::new(INSTALLATION_ID).expect("installation id"),
        ProductOutboundTarget::new(
            ReplyTargetBindingRef::new("binding").expect("binding ref"),
            ExternalConversationRef::new(
                None,
                ROOM_ID,
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
        "matrix-inst_abc123-$event:example.org"
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
        matches!(err, RuntimeError::ExecutionFailed { ref message, .. }
            if message.contains("missing_auth_evidence")),
        "{err:?}"
    );
}

#[test]
fn matrix_component_renders_final_reply_as_policy_checked_egress() {
    let (runtime, prepared) = prepared_component();
    let envelope = outbound(ProductOutboundPayload::FinalReply(FinalReplyView {
        turn_run_id: ironclaw_turns::TurnRunId::new(),
        text: "**hello** matrix".to_string(),
        generated_at: Utc::now(),
    }));
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

    let mut envelope = outbound(ProductOutboundPayload::FinalReply(FinalReplyView {
        turn_run_id: ironclaw_turns::TurnRunId::new(),
        text: "wrong room".to_string(),
        generated_at: Utc::now(),
    }));
    envelope.target.external_conversation_ref =
        ExternalConversationRef::new(None, "!evil:example.org", None, None).expect("conversation");
    let err = runtime
        .render_outbound(
            &prepared,
            &serde_json::to_string(&envelope).expect("outbound JSON"),
        )
        .expect_err("target room is unauthorized");
    assert!(
        matches!(err, RuntimeError::ExecutionFailed { ref message, .. }
            if message.contains("unauthorized_target_room")),
        "{err:?}"
    );
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
