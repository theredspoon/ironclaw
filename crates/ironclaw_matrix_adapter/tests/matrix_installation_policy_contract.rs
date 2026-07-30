use std::collections::BTreeSet;
use std::sync::{Arc, Barrier, Mutex};

use chrono::Utc;
use ironclaw_extensions::{
    ExtensionActivationState, ExtensionCredentialBinding, ExtensionCredentialHandle,
    ExtensionInstallation, ExtensionInstallationId, ExtensionInstallationStore,
    ExtensionManifestRef, InMemoryExtensionInstallationStore, InstallationOwner,
    MANIFEST_SCHEMA_VERSION, ManifestSource,
};
use ironclaw_host_api::{ExtensionId, HostPortCatalog, SecretHandle, UserId};
use ironclaw_matrix_adapter::installation_policy::{
    ArtifactSha256, ComponentArtifactBinding, ComponentArtifactId, ComponentArtifactInspection,
    EgressTargetIndex, InstallationAuditMetadata, MatrixActivationState, MatrixCredentialState,
    MatrixExtensionLifecycleMutation, MatrixHomeserverOrigin, MatrixInboundRoutingContext,
    MatrixInstallationAuditEvent, MatrixInstallationMutation, MatrixInstallationMutationAuthority,
    MatrixInstallationMutationOperation, MatrixInstallationPolicy,
    MatrixInstallationPolicyRejection, MatrixInstallationProjectionCache,
    MatrixOutboundPolicyCheck, MatrixProductAdapterInstallation, MatrixRoomId,
    MatrixRuntimeArtifactEvidence, MatrixUserId, PolicyRevision, StaticManifestBinding,
    VerifiedMatrixAuthContext, WitPackageName, WitWorldName,
    apply_matrix_extension_lifecycle_mutation, authorize_matrix_outbound,
    authorize_matrix_outbound_with_extension_lifecycle,
    project_matrix_installation_from_runtime_entry, resolve_matrix_inbound_installation,
    validate_component_artifact, validate_matrix_credential_state,
};
use ironclaw_product_adapter_registry::{
    ManifestHash, list_enabled_product_adapter_entries, parse_product_adapter_manifest_record,
};
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, DeclaredEgressHost, DeclaredEgressTarget,
    EgressCredentialHandle, ProductAdapterId, ProtocolAuthEvidence, ProtocolAuthFailure,
};
use tempfile::tempdir;

fn adapter_id() -> ProductAdapterId {
    ProductAdapterId::new("matrix").expect("adapter id")
}

fn installation_id(value: &str) -> AdapterInstallationId {
    AdapterInstallationId::new(value).expect("installation id")
}

fn credential(value: &str) -> EgressCredentialHandle {
    EgressCredentialHandle::new(value).expect("credential handle")
}

fn room(value: &str) -> MatrixRoomId {
    MatrixRoomId::new(value).expect("room id")
}

fn user(value: &str) -> MatrixUserId {
    MatrixUserId::new(value).expect("user id")
}

fn homeserver(value: &str) -> MatrixHomeserverOrigin {
    MatrixHomeserverOrigin::parse(value).expect("homeserver")
}

fn auth_evidence() -> ProtocolAuthEvidence {
    ProtocolAuthEvidence::test_verified(
        AuthRequirement::SharedSecretHeader {
            header_name: "x-matrix-webhook-secret".to_string(),
        },
        "matrix-webhook",
    )
}

fn routing_context(
    homeserver: MatrixHomeserverOrigin,
    room_id: MatrixRoomId,
    sender: MatrixUserId,
) -> MatrixInboundRoutingContext {
    MatrixInboundRoutingContext::from_verified_auth(
        homeserver,
        room_id,
        sender,
        &auth_evidence(),
        1_710_000_000_001,
    )
    .expect("verified routing context")
}

fn set<T: Ord>(values: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    values.into_iter().collect()
}

fn artifact() -> ComponentArtifactBinding {
    ComponentArtifactBinding {
        artifact_id: ComponentArtifactId::new("matrix-component").expect("artifact id"),
        artifact_sha256: ArtifactSha256::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("sha"),
        wit_package: WitPackageName::new("near:product-adapter@0.1.0").expect("wit package"),
        wit_world: WitWorldName::new("product-adapter-component").expect("wit world"),
        manifest: StaticManifestBinding::new("manifest-hash-alpha").expect("manifest hash"),
        declared_egress_targets: vec![DeclaredEgressTarget::new(
            DeclaredEgressHost::new("matrix.example.org").expect("declared host"),
            Some(credential("matrix-access-token")),
        )],
    }
}

fn artifact_inspection() -> ComponentArtifactInspection {
    ComponentArtifactInspection {
        artifact_sha256: ArtifactSha256::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("sha"),
        wit_package: WitPackageName::new("near:product-adapter@0.1.0").expect("wit package"),
        wit_world: WitWorldName::new("product-adapter-component").expect("wit world"),
        manifest: StaticManifestBinding::new("manifest-hash-alpha").expect("manifest hash"),
        required_exports_present: true,
        unexpected_imports: Vec::new(),
        direct_http_egress_import: false,
        signature_valid: Some(true),
    }
}

fn runtime_artifact_evidence() -> MatrixRuntimeArtifactEvidence {
    MatrixRuntimeArtifactEvidence {
        artifact_id: ComponentArtifactId::new("matrix-component").expect("artifact id"),
        artifact_sha256: ArtifactSha256::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("sha"),
        wit_package: WitPackageName::new("near:product-adapter@0.1.0").expect("wit package"),
        wit_world: WitWorldName::new("product-adapter-component").expect("wit world"),
    }
}

fn audit() -> InstallationAuditMetadata {
    InstallationAuditMetadata::new("operator-alpha", 1_710_000_000_000).expect("audit metadata")
}

fn matrix_product_adapter_manifest_raw() -> String {
    format!(
        r#"
schema_version = "{schema}"
id = "matrix-product-adapter"
name = "Matrix"
version = "0.1.0"
description = "Matrix product adapter"
trust = "third_party"

[runtime]
kind = "wasm"
module = "adapters/matrix.wasm"

[[host_api]]
id = "ironclaw.product_adapter/v1"
section = "product_adapter.inbound"

[product_adapter.inbound]
surface_kind = "external_channel"

[product_adapter.inbound.auth]
kind = "shared_secret_header"
header_name = "x-matrix-webhook-secret"

[product_adapter.inbound.capabilities]
flags = ["inbound_messages", "external_final_reply_push"]

[[product_adapter.inbound.required_credentials]]
handle = "matrix-access-token"

[[product_adapter.inbound.egress]]
host = "matrix.example.org"
credential_handle = "matrix-access-token"
"#,
        schema = MANIFEST_SCHEMA_VERSION
    )
}

async fn matrix_extension_store_with_installation(
    activation: ExtensionActivationState,
    owner: InstallationOwner,
) -> (InMemoryExtensionInstallationStore, AdapterInstallationId) {
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let installation_id = ExtensionInstallationId::new("matrix-install-alpha").expect("install id");
    let adapter_installation_id =
        AdapterInstallationId::new(installation_id.as_str()).expect("adapter installation id");
    let manifest_hash = ManifestHash::new("sha256:matrix-manifest").expect("manifest hash");
    let manifest = parse_product_adapter_manifest_record(
        matrix_product_adapter_manifest_raw(),
        ManifestSource::InstalledLocal,
        &HostPortCatalog::empty(),
        Some(manifest_hash.clone()),
    )
    .expect("manifest");
    let installation = ExtensionInstallation::new(
        installation_id,
        extension_id.clone(),
        activation,
        ExtensionManifestRef::new(extension_id, Some(manifest_hash)),
        vec![ExtensionCredentialBinding::new(
            ExtensionCredentialHandle::new("matrix-access-token").expect("credential handle"),
            SecretHandle::new("secret_matrix_access_token").expect("secret handle"),
        )],
        Utc::now(),
        owner,
    )
    .expect("installation");
    let store = InMemoryExtensionInstallationStore::default();
    store
        .upsert_manifest_and_installation(manifest, installation)
        .await
        .expect("store");
    (store, adapter_installation_id)
}

fn policy() -> MatrixInstallationPolicy {
    MatrixInstallationPolicy::new(
        homeserver("https://matrix.example.org"),
        set([room("!room:example.org")]),
        set([user("@alice:example.org")]),
        EgressTargetIndex::new(0),
        credential("matrix-access-token"),
    )
    .expect("policy")
}

fn incomplete_policy() -> MatrixInstallationPolicy {
    MatrixInstallationPolicy::new(
        homeserver("https://matrix.example.org"),
        BTreeSet::new(),
        BTreeSet::new(),
        EgressTargetIndex::new(0),
        credential("matrix-access-token"),
    )
    .expect("draft policy")
}

fn installation(id: &str, activation: MatrixActivationState) -> MatrixProductAdapterInstallation {
    MatrixProductAdapterInstallation::new(
        adapter_id(),
        installation_id(id),
        artifact(),
        policy(),
        activation,
        PolicyRevision::new(7).expect("revision"),
        audit(),
    )
    .expect("installation")
}

#[test]
fn matrix_policy_rejects_ambiguous_or_disabled_inbound_before_guest_dispatch() {
    let allowed = installation("install-alpha", MatrixActivationState::Enabled);
    let disabled = installation("install-disabled", MatrixActivationState::Disabled);
    let ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
    );

    let err = resolve_matrix_inbound_installation(&[disabled], &ctx)
        .expect_err("disabled installation must reject before dispatch");
    assert_eq!(err, MatrixInstallationPolicyRejection::InstallationDisabled);

    let ambiguous = resolve_matrix_inbound_installation(&[allowed.clone(), allowed], &ctx)
        .expect_err("multiple matching installations must fail closed");
    assert_eq!(
        ambiguous,
        MatrixInstallationPolicyRejection::AmbiguousInstallation
    );
}

#[test]
fn matrix_policy_canonicalizes_identifiers_and_rejects_aliases_private_hosts() {
    assert!(MatrixRoomId::new("#alias:example.org").is_err());
    assert!(MatrixRoomId::new("!room:example.org").is_ok());
    assert!(MatrixUserId::new("@alice:example.org").is_ok());
    assert!(MatrixUserId::new("alice:example.org").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://matrix.example.org/").is_ok());
    assert!(MatrixHomeserverOrigin::parse("https://127.0.0.1").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://169.254.169.254").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://224.0.0.1").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://192.0.2.10").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://[::1]").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://[fe80::1]").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://[ff02::1]").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://[2001:db8::1]").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://[::ffff:169.254.169.254]").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://[::ffff:127.0.0.1]").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://[::ffff:224.0.0.1]").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://[]").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://[localhost]").is_err());
    assert!(MatrixHomeserverOrigin::parse("https://matrix.example.org/path").is_err());
}

#[test]
fn matrix_native_policy_accepts_server_name_less_v2_room_id_without_rewriting() {
    let room_id = "!opaquev2roomid";
    let parsed = MatrixRoomId::new(room_id).expect("v2 room id is valid");
    assert_eq!(parsed.as_str(), room_id);

    let encoded = serde_json::to_vec(&parsed).expect("serialize room id");
    let restored: MatrixRoomId = serde_json::from_slice(&encoded).expect("reload room id");
    assert_eq!(restored.as_str(), room_id);
}

#[test]
fn matrix_policy_snapshot_authorizes_outbound_and_rejects_credential_pair_mismatch() {
    let install = installation("install-alpha", MatrixActivationState::Enabled);
    let ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
    );
    let snapshot = resolve_matrix_inbound_installation(&[install], &ctx).expect("snapshot");

    authorize_matrix_outbound(
        &snapshot,
        &MatrixOutboundPolicyCheck {
            adapter_id: adapter_id(),
            installation_id: installation_id("install-alpha"),
            homeserver: homeserver("https://matrix.example.org"),
            room_id: room("!room:example.org"),
            egress_target_index: EgressTargetIndex::new(0),
            credential_handle: credential("matrix-access-token"),
            path: "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn".to_string(),
            guest_authorization_header_present: false,
            policy_revision: PolicyRevision::new(7).expect("revision"),
        },
    )
    .expect("allowed outbound");

    let err = authorize_matrix_outbound(
        &snapshot,
        &MatrixOutboundPolicyCheck {
            adapter_id: adapter_id(),
            installation_id: installation_id("install-alpha"),
            homeserver: homeserver("https://matrix.example.org"),
            room_id: room("!room:example.org"),
            egress_target_index: EgressTargetIndex::new(0),
            credential_handle: credential("other-token"),
            path: "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn".to_string(),
            guest_authorization_header_present: false,
            policy_revision: PolicyRevision::new(7).expect("revision"),
        },
    )
    .expect_err("wrong credential must fail closed");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::CredentialHandleMismatch
    );

    let err = authorize_matrix_outbound(
        &snapshot,
        &MatrixOutboundPolicyCheck {
            adapter_id: adapter_id(),
            installation_id: installation_id("install-alpha"),
            homeserver: homeserver("https://matrix.example.org"),
            room_id: room("!room:example.org"),
            egress_target_index: EgressTargetIndex::new(0),
            credential_handle: credential("matrix-access-token"),
            path: "/_matrix/client/v3/rooms/!other:example.org/send/m.room.message/txn".to_string(),
            guest_authorization_header_present: false,
            policy_revision: PolicyRevision::new(7).expect("revision"),
        },
    )
    .expect_err("path room must match the authorized room");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::UnsafeMatrixRequestShape
    );
}

#[test]
fn matrix_policy_rejects_installation_when_manifest_egress_binding_mismatches_policy() {
    let mut install = installation("install-alpha", MatrixActivationState::Enabled);
    install.component.declared_egress_targets[0] = DeclaredEgressTarget::new(
        DeclaredEgressHost::new("matrix.example.org").expect("declared host"),
        Some(credential("other-token")),
    );
    let ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
    );

    let err = resolve_matrix_inbound_installation(&[install], &ctx)
        .expect_err("manifest credential must match Matrix policy credential");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::CredentialHandleMismatch
    );

    let mut install = installation("install-alpha", MatrixActivationState::Enabled);
    install.component.declared_egress_targets.clear();
    let err = resolve_matrix_inbound_installation(&[install], &ctx)
        .expect_err("manifest must declare selected egress target");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::EgressTargetOutOfBounds
    );
}

#[tokio::test]
async fn matrix_policy_projects_from_enabled_product_adapter_registry_entry() {
    let raw = matrix_product_adapter_manifest_raw();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let installation_id = ExtensionInstallationId::new("matrix-install-alpha").expect("install id");
    let manifest_hash = ManifestHash::new("sha256:matrix-manifest").expect("manifest hash");
    let manifest = parse_product_adapter_manifest_record(
        raw,
        ManifestSource::InstalledLocal,
        &HostPortCatalog::empty(),
        Some(manifest_hash.clone()),
    )
    .expect("manifest");
    let installation = ExtensionInstallation::new(
        installation_id,
        extension_id.clone(),
        ExtensionActivationState::Enabled,
        ExtensionManifestRef::new(extension_id, Some(manifest_hash)),
        vec![ExtensionCredentialBinding::new(
            ExtensionCredentialHandle::new("matrix-access-token").expect("credential handle"),
            SecretHandle::new("secret_matrix_access_token").expect("secret handle"),
        )],
        Utc::now(),
        InstallationOwner::Tenant,
    )
    .expect("installation");
    let store = InMemoryExtensionInstallationStore::default();
    store
        .upsert_manifest_and_installation(manifest, installation)
        .await
        .expect("store");

    let entries = list_enabled_product_adapter_entries(&store)
        .await
        .expect("entries");
    assert_eq!(entries.len(), 1);

    let install = project_matrix_installation_from_runtime_entry(
        &entries[0],
        runtime_artifact_evidence(),
        policy(),
        audit(),
    )
    .expect("projected Matrix installation");
    assert_eq!(install.installation_id.as_str(), "matrix-install-alpha");
    assert_eq!(
        install.adapter_id.as_str(),
        "matrix-product-adapter/inbound"
    );
    assert_eq!(install.activation, MatrixActivationState::Enabled);
    assert_eq!(install.component.declared_egress_targets.len(), 1);
}

#[test]
fn matrix_policy_lifecycle_mutations_require_authority_and_emit_audit() {
    let mut install = MatrixProductAdapterInstallation::create_disabled(
        adapter_id(),
        installation_id("install-alpha"),
        artifact(),
        policy(),
        audit(),
    )
    .expect("disabled install");
    assert_eq!(install.activation, MatrixActivationState::Disabled);

    let unauthorized = MatrixInstallationMutationAuthority {
        can_manage_installations: false,
    };
    let err = install
        .apply_mutation(
            MatrixInstallationMutation::Enable {
                artifact_inspection: artifact_inspection(),
            },
            &unauthorized,
            "operator-beta",
            2,
        )
        .expect_err("mutation requires authority");
    assert_eq!(err, MatrixInstallationPolicyRejection::MutationUnauthorized);
    assert_eq!(install.activation, MatrixActivationState::Disabled);
    let rejected = MatrixInstallationAuditEvent::rejected(
        &install,
        MatrixInstallationMutationOperation::Enable,
        "operator-beta",
        err,
        2,
    )
    .expect("rejected audit event");
    assert_eq!(
        rejected.rejected_reason,
        Some(MatrixInstallationPolicyRejection::MutationUnauthorized)
    );
    assert_eq!(rejected.previous_activation, rejected.next_activation);

    let authorized = MatrixInstallationMutationAuthority {
        can_manage_installations: true,
    };
    let event = install
        .apply_mutation(
            MatrixInstallationMutation::Enable {
                artifact_inspection: artifact_inspection(),
            },
            &authorized,
            "operator-beta",
            2,
        )
        .expect("authorized enable");
    assert_eq!(event.operation, MatrixInstallationMutationOperation::Enable);
    assert_eq!(event.previous_activation, MatrixActivationState::Disabled);
    assert_eq!(event.next_activation, MatrixActivationState::Enabled);
    assert_eq!(
        install.audit.last_enable_actor.as_deref(),
        Some("operator-beta")
    );

    let previous_revision = install.policy_revision;
    let event = install
        .apply_mutation(
            MatrixInstallationMutation::Disable,
            &authorized,
            "operator-gamma",
            3,
        )
        .expect("authorized disable");
    assert_eq!(
        event.operation,
        MatrixInstallationMutationOperation::Disable
    );
    assert_eq!(event.previous_revision, previous_revision);
    assert_eq!(event.next_activation, MatrixActivationState::Disabled);
    assert_eq!(install.audit.updated_by, "operator-gamma");

    install
        .apply_mutation(
            MatrixInstallationMutation::Delete,
            &authorized,
            "operator-delta",
            4,
        )
        .expect("authorized delete");
    assert_eq!(install.activation, MatrixActivationState::Deleting);
}

#[test]
fn matrix_policy_revision_overflow_fails_closed_without_mutation() {
    let mut install = MatrixProductAdapterInstallation::new(
        adapter_id(),
        installation_id("install-alpha"),
        artifact(),
        policy(),
        MatrixActivationState::Disabled,
        PolicyRevision::new(u64::MAX).expect("max revision"),
        audit(),
    )
    .expect("installation");
    let original_revision = install.policy_revision;
    let original_policy = install.policy.clone();

    let err = install
        .apply_mutation(
            MatrixInstallationMutation::UpdatePolicy { policy: policy() },
            &MatrixInstallationMutationAuthority::tenant_operator(),
            "operator-alpha",
            2,
        )
        .expect_err("revision overflow must fail closed");

    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::PolicyRevisionOverflow
    );
    assert_eq!(install.policy_revision, original_revision);
    assert_eq!(install.policy, original_policy);
}

#[test]
fn matrix_policy_allows_disabled_incomplete_records_but_rejects_enablement() {
    let mut install = MatrixProductAdapterInstallation::create_disabled(
        adapter_id(),
        installation_id("install-draft"),
        artifact(),
        incomplete_policy(),
        audit(),
    )
    .expect("disabled draft installation");
    assert!(install.policy.allowed_rooms.is_empty());
    assert!(install.policy.allowed_senders.is_empty());

    let mut registry = MatrixInstallationProjectionCache::new();
    registry
        .insert_projection(install.clone(), "operator-alpha", 1)
        .expect("disabled draft can be persisted");
    let encoded = registry.to_json_string().expect("snapshot json");
    MatrixInstallationProjectionCache::from_json_str(&encoded)
        .expect("disabled draft can be reloaded");

    let err = MatrixProductAdapterInstallation::new(
        adapter_id(),
        installation_id("install-enabled-empty"),
        artifact(),
        incomplete_policy(),
        MatrixActivationState::Enabled,
        PolicyRevision::new(1).expect("revision"),
        audit(),
    )
    .expect_err("enabled installation requires explicit allowlists");
    assert_eq!(err, MatrixInstallationPolicyRejection::InvalidPolicyValue);

    let err = install
        .apply_mutation(
            MatrixInstallationMutation::Enable {
                artifact_inspection: artifact_inspection(),
            },
            &MatrixInstallationMutationAuthority::tenant_operator(),
            "operator-alpha",
            2,
        )
        .expect_err("enablement requires explicit allowlists");
    assert_eq!(err, MatrixInstallationPolicyRejection::InvalidPolicyValue);
    assert_eq!(install.activation, MatrixActivationState::Disabled);
}

#[test]
fn matrix_policy_projection_cache_rejects_overlapping_enabled_scopes() {
    let mut registry = MatrixInstallationProjectionCache::new();
    let alpha = installation("install-alpha", MatrixActivationState::Enabled);
    registry
        .insert_projection(alpha, "operator-alpha", 1)
        .expect("insert alpha");

    let overlapping = installation("install-overlap", MatrixActivationState::Enabled);
    let err = registry
        .insert_projection(overlapping, "operator-alpha", 2)
        .expect_err("overlapping enabled scope is ambiguous");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::AmbiguousInstallation
    );

    let mut disjoint_room = installation("install-disjoint-room", MatrixActivationState::Enabled);
    disjoint_room.policy.allowed_rooms = set([room("!other:example.org")]);
    registry
        .insert_projection(disjoint_room, "operator-alpha", 3)
        .expect("same homeserver with disjoint room is allowed");

    let mut disjoint_sender =
        installation("install-disjoint-sender", MatrixActivationState::Enabled);
    disjoint_sender.policy.allowed_senders = set([user("@bob:example.org")]);
    registry
        .insert_projection(disjoint_sender, "operator-alpha", 4)
        .expect("same homeserver and room with disjoint sender is allowed");

    let err = registry
        .apply_policy_mutation(
            &installation_id("install-disjoint-room"),
            MatrixInstallationMutation::UpdatePolicy { policy: policy() },
            &MatrixInstallationMutationAuthority::tenant_operator(),
            "operator-alpha",
            5,
        )
        .expect_err("policy update cannot create overlapping enabled scope");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::AmbiguousInstallation
    );

    let ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
    );
    let ambiguous = resolve_matrix_inbound_installation(
        &[
            installation("install-ambiguous-a", MatrixActivationState::Enabled),
            installation("install-ambiguous-b", MatrixActivationState::Enabled),
        ],
        &ctx,
    )
    .expect_err("inbound still fails closed if ambiguous state is encountered");
    assert_eq!(
        ambiguous,
        MatrixInstallationPolicyRejection::AmbiguousInstallation
    );
}

#[test]
fn matrix_policy_projection_cache_rejects_overlapping_enabled_scopes_on_reload() {
    let mut first = installation("install-alpha", MatrixActivationState::Enabled);
    let second = installation("install-beta", MatrixActivationState::Enabled);
    first.policy.allowed_rooms = set([room("!room:example.org"), room("!other:example.org")]);

    let raw = serde_json::json!({
        "installations": {
            first.installation_id.as_str(): first,
            second.installation_id.as_str(): second,
        },
        "audit_events": []
    })
    .to_string();

    let err = MatrixInstallationProjectionCache::from_json_str(&raw)
        .expect_err("persisted overlapping enabled scopes must fail closed");
    assert!(
        err.to_string().contains("AmbiguousInstallation"),
        "unexpected reload error: {err}"
    );
}

#[test]
fn matrix_policy_projection_cache_reloads_public_ipv6_homeserver_origins() {
    let origin = homeserver("https://[2606:4700:4700::1111]:8448");
    let encoded = serde_json::to_value(&origin).expect("serialize ipv6 homeserver");
    assert_eq!(encoded["host"], "2606:4700:4700::1111");

    let restored: MatrixHomeserverOrigin =
        serde_json::from_value(encoded).expect("reload ipv6 homeserver");
    assert_eq!(restored.host(), "2606:4700:4700::1111");
    assert_eq!(restored.port(), Some(8448));
}

#[test]
fn matrix_policy_projection_cache_records_policy_mutation_audits() {
    let installation = MatrixProductAdapterInstallation::create_disabled(
        ProductAdapterId::new("matrix").expect("adapter id"),
        AdapterInstallationId::new("matrix-install-alpha").expect("installation id"),
        artifact(),
        policy(),
        audit(),
    )
    .expect("disabled installation");
    let installation_id = installation.installation_id.clone();
    let unauthorized = MatrixInstallationMutationAuthority::deny();
    let authorized = MatrixInstallationMutationAuthority::tenant_operator();
    let mut registry = MatrixInstallationProjectionCache::new();

    registry
        .insert_projection(installation, "operator-alpha", 3)
        .expect("project installation");
    let err = registry
        .apply_policy_mutation(
            &installation_id,
            MatrixInstallationMutation::Enable {
                artifact_inspection: artifact_inspection(),
            },
            &authorized,
            "operator-alpha",
            4,
        )
        .expect_err("durable lifecycle mutation belongs to extension store");
    assert_eq!(err, MatrixInstallationPolicyRejection::MutationRejected);
    let err = registry
        .apply_policy_mutation(
            &installation_id,
            MatrixInstallationMutation::Disable,
            &authorized,
            "operator-alpha",
            5,
        )
        .expect_err("durable lifecycle mutation belongs to extension store");
    assert_eq!(err, MatrixInstallationPolicyRejection::MutationRejected);
    registry
        .apply_policy_mutation(
            &installation_id,
            MatrixInstallationMutation::UpdatePolicy { policy: policy() },
            &authorized,
            "operator-alpha",
            6,
        )
        .expect("durable cache owner updates policy");
    registry
        .apply_policy_mutation(
            &installation_id,
            MatrixInstallationMutation::RebindArtifact {
                component: artifact(),
                artifact_inspection: artifact_inspection(),
            },
            &authorized,
            "operator-alpha",
            7,
        )
        .expect("durable cache owner rebinds artifact");
    registry
        .apply_policy_mutation(
            &installation_id,
            MatrixInstallationMutation::RebindCredential {
                credential_handle: credential("matrix-access-token"),
            },
            &authorized,
            "operator-alpha",
            8,
        )
        .expect("durable cache owner rebinds credential");
    let err = registry
        .apply_policy_mutation(
            &installation_id,
            MatrixInstallationMutation::Delete,
            &authorized,
            "operator-alpha",
            9,
        )
        .expect_err("durable lifecycle mutation belongs to extension store");
    assert_eq!(err, MatrixInstallationPolicyRejection::MutationRejected);

    let err = registry
        .apply_policy_mutation(
            &installation_id,
            MatrixInstallationMutation::UpdatePolicy { policy: policy() },
            &unauthorized,
            "operator-beta",
            10,
        )
        .expect_err("policy update requires authority");
    assert_eq!(err, MatrixInstallationPolicyRejection::MutationUnauthorized);

    let stored = registry
        .installation(&installation_id)
        .expect("stored installation");
    assert_eq!(stored.activation, MatrixActivationState::Disabled);
    assert_eq!(
        registry
            .audit_events()
            .iter()
            .map(|event| event.operation)
            .collect::<Vec<_>>(),
        vec![
            MatrixInstallationMutationOperation::Create,
            MatrixInstallationMutationOperation::Enable,
            MatrixInstallationMutationOperation::Disable,
            MatrixInstallationMutationOperation::UpdatePolicy,
            MatrixInstallationMutationOperation::RebindArtifact,
            MatrixInstallationMutationOperation::RebindCredential,
            MatrixInstallationMutationOperation::Delete,
            MatrixInstallationMutationOperation::UpdatePolicy,
        ]
    );
    assert!(
        registry
            .audit_events()
            .iter()
            .take(7)
            .all(|event| event.actor == "operator-alpha")
    );
    assert_eq!(
        registry
            .audit_events()
            .iter()
            .map(|event| event.rejected_reason)
            .collect::<Vec<_>>(),
        vec![
            None,
            Some(MatrixInstallationPolicyRejection::MutationRejected),
            Some(MatrixInstallationPolicyRejection::MutationRejected),
            None,
            None,
            None,
            Some(MatrixInstallationPolicyRejection::MutationRejected),
            Some(MatrixInstallationPolicyRejection::MutationUnauthorized),
        ]
    );
    assert_eq!(
        registry
            .audit_events()
            .last()
            .and_then(|event| event.rejected_reason),
        Some(MatrixInstallationPolicyRejection::MutationUnauthorized)
    );
}

#[test]
fn matrix_policy_projection_cache_persists_and_reloads_durable_snapshot() {
    let installation = installation("install-alpha", MatrixActivationState::Enabled);
    let installation_id = installation.installation_id.clone();
    let mut registry = MatrixInstallationProjectionCache::new();
    registry
        .insert_projection(installation, "operator-alpha", 1)
        .expect("project installation");
    let durable_policy = MatrixInstallationPolicy::new(
        homeserver("https://matrix.example.org"),
        set([room("!opaquev2roomid")]),
        set([user("@alice:example.org")]),
        EgressTargetIndex::new(0),
        credential("matrix-access-token"),
    )
    .expect("durable policy");
    registry
        .apply_policy_mutation(
            &installation_id,
            MatrixInstallationMutation::UpdatePolicy {
                policy: durable_policy,
            },
            &MatrixInstallationMutationAuthority::tenant_operator(),
            "operator-alpha",
            2,
        )
        .expect("durable policy mutation");

    let encoded = registry.to_json_string().expect("durable snapshot json");
    let restored = MatrixInstallationProjectionCache::from_json_str(&encoded)
        .expect("reload durable snapshot");

    assert_eq!(
        restored
            .installation(&installation_id)
            .expect("restored installation")
            .activation,
        MatrixActivationState::Enabled
    );
    assert_eq!(
        restored
            .installation(&installation_id)
            .expect("restored installation")
            .policy
            .allowed_rooms
            .iter()
            .next()
            .expect("restored allowed room")
            .as_str(),
        "!opaquev2roomid",
        "durable policy cache reload must preserve the exact v2 room id"
    );
    assert_eq!(restored.audit_events(), registry.audit_events());
}

#[test]
fn matrix_policy_projection_cache_saves_and_loads_from_durable_path() {
    let installation = installation("install-alpha", MatrixActivationState::Enabled);
    let installation_id = installation.installation_id.clone();
    let mut registry = MatrixInstallationProjectionCache::new();
    registry
        .insert_projection(installation, "operator-alpha", 1)
        .expect("project installation");
    registry
        .apply_policy_mutation(
            &installation_id,
            MatrixInstallationMutation::UpdatePolicy { policy: policy() },
            &MatrixInstallationMutationAuthority::tenant_operator(),
            "operator-alpha",
            2,
        )
        .expect("durable policy mutation");

    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("nested/matrix-policy-cache.json");
    registry.save_to_path(&path).expect("save durable path");

    let restored =
        MatrixInstallationProjectionCache::load_from_path(&path).expect("load durable path");
    assert_eq!(
        restored
            .installation(&installation_id)
            .expect("restored installation")
            .activation,
        MatrixActivationState::Enabled
    );
    assert_eq!(restored.audit_events(), registry.audit_events());

    std::fs::write(&path, br#"{"installations":{"wrong-key":{"#).expect("corrupt snapshot");
    assert!(
        MatrixInstallationProjectionCache::load_from_path(&path).is_err(),
        "durable reload must fail closed on invalid persisted state"
    );
}

#[test]
fn matrix_policy_mutations_reject_invalid_component_policy_bindings_before_storing() {
    let authorized = MatrixInstallationMutationAuthority::tenant_operator();
    let mut install = installation("install-alpha", MatrixActivationState::Enabled);
    let original_policy = install.policy.clone();

    let mut wrong_homeserver_policy = policy();
    wrong_homeserver_policy.homeserver = homeserver("https://matrix-other.example.org");
    let err = install
        .apply_mutation(
            MatrixInstallationMutation::UpdatePolicy {
                policy: wrong_homeserver_policy,
            },
            &authorized,
            "operator-alpha",
            2,
        )
        .expect_err("policy update must not store mismatched homeserver");
    assert_eq!(err, MatrixInstallationPolicyRejection::HomeserverMismatch);
    assert_eq!(install.policy, original_policy);

    let err = install
        .apply_mutation(
            MatrixInstallationMutation::RebindCredential {
                credential_handle: credential("matrix-other-token"),
            },
            &authorized,
            "operator-alpha",
            3,
        )
        .expect_err("credential rebind must not store undeclared credential pair");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::CredentialHandleMismatch
    );
    assert_eq!(
        install.policy.credential_handle,
        credential("matrix-access-token")
    );

    let mut component = artifact();
    component.declared_egress_targets[0] = DeclaredEgressTarget::new(
        DeclaredEgressHost::new("matrix-other.example.org").expect("declared host"),
        Some(credential("matrix-access-token")),
    );
    let err = install
        .apply_mutation(
            MatrixInstallationMutation::RebindArtifact {
                component,
                artifact_inspection: artifact_inspection(),
            },
            &authorized,
            "operator-alpha",
            4,
        )
        .expect_err("artifact rebind must not store mismatched egress host");
    assert_eq!(err, MatrixInstallationPolicyRejection::HomeserverMismatch);
    assert_eq!(
        install.component.declared_egress_targets[0].host.as_str(),
        "matrix.example.org"
    );
}

#[test]
fn matrix_policy_mutation_authority_uses_extension_installation_owner() {
    let alice = UserId::new("alice").expect("alice");
    let bob = UserId::new("bob").expect("bob");
    let tenant_operator = UserId::new("operator-alpha").expect("operator");
    let owner = InstallationOwner::users(BTreeSet::from([alice.clone()])).expect("owner");

    assert!(
        MatrixInstallationMutationAuthority::from_installation_owner(
            &owner,
            &alice,
            &tenant_operator
        )
        .can_manage_installations
    );
    assert!(
        !MatrixInstallationMutationAuthority::from_installation_owner(
            &owner,
            &bob,
            &tenant_operator
        )
        .can_manage_installations
    );
    assert!(
        MatrixInstallationMutationAuthority::from_installation_owner(
            &InstallationOwner::Tenant,
            &tenant_operator,
            &tenant_operator,
        )
        .can_manage_installations
    );
    assert!(
        !MatrixInstallationMutationAuthority::from_installation_owner(
            &InstallationOwner::Tenant,
            &bob,
            &tenant_operator,
        )
        .can_manage_installations
    );
}

#[tokio::test]
async fn matrix_extension_store_owns_rollout_rollback_and_lifecycle_authorization() {
    let (store, installation_id) = matrix_extension_store_with_installation(
        ExtensionActivationState::Disabled,
        InstallationOwner::Tenant,
    )
    .await;
    let ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
    );
    assert!(
        list_enabled_product_adapter_entries(&store)
            .await
            .expect("entries")
            .is_empty(),
        "disabled-by-default extension installation is not projected for dispatch"
    );

    let operator = UserId::new("operator-alpha").expect("operator");
    let non_operator = UserId::new("alice").expect("alice");
    let err = apply_matrix_extension_lifecycle_mutation(
        &store,
        &installation_id,
        MatrixExtensionLifecycleMutation::Enable,
        &non_operator,
        &operator,
    )
    .await
    .expect_err("non-operator cannot mutate tenant-wide installation");
    assert_eq!(err, MatrixInstallationPolicyRejection::MutationUnauthorized);

    apply_matrix_extension_lifecycle_mutation(
        &store,
        &installation_id,
        MatrixExtensionLifecycleMutation::Enable,
        &operator,
        &operator,
    )
    .await
    .expect("enable through extension store");
    let entries = list_enabled_product_adapter_entries(&store)
        .await
        .expect("entries");
    assert_eq!(entries.len(), 1);
    let install = project_matrix_installation_from_runtime_entry(
        &entries[0],
        runtime_artifact_evidence(),
        policy(),
        audit(),
    )
    .expect("projected installation");
    let snapshot = resolve_matrix_inbound_installation(&[install], &ctx).expect("snapshot");

    apply_matrix_extension_lifecycle_mutation(
        &store,
        &installation_id,
        MatrixExtensionLifecycleMutation::Disable,
        &operator,
        &operator,
    )
    .await
    .expect("disable through extension store");
    let err = authorize_matrix_outbound_with_extension_lifecycle(
        &store,
        &snapshot,
        &MatrixOutboundPolicyCheck {
            adapter_id: adapter_id(),
            installation_id: installation_id.clone(),
            homeserver: homeserver("https://matrix.example.org"),
            room_id: room("!room:example.org"),
            egress_target_index: EgressTargetIndex::new(0),
            credential_handle: credential("matrix-access-token"),
            path: "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn".to_string(),
            guest_authorization_header_present: false,
            policy_revision: snapshot.policy_revision,
        },
    )
    .await
    .expect_err("disabled extension installation fails closed before egress");
    assert_eq!(err, MatrixInstallationPolicyRejection::InstallationDisabled);

    apply_matrix_extension_lifecycle_mutation(
        &store,
        &installation_id,
        MatrixExtensionLifecycleMutation::Delete,
        &operator,
        &operator,
    )
    .await
    .expect("delete through extension store");
    let err = authorize_matrix_outbound_with_extension_lifecycle(
        &store,
        &snapshot,
        &MatrixOutboundPolicyCheck {
            adapter_id: adapter_id(),
            installation_id: installation_id.clone(),
            homeserver: homeserver("https://matrix.example.org"),
            room_id: room("!room:example.org"),
            egress_target_index: EgressTargetIndex::new(0),
            credential_handle: credential("matrix-access-token"),
            path: "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn".to_string(),
            guest_authorization_header_present: false,
            policy_revision: snapshot.policy_revision,
        },
    )
    .await
    .expect_err("deleted extension installation fails closed before egress");
    assert_eq!(err, MatrixInstallationPolicyRejection::InstallationDeleting);

    let alice = UserId::new("alice").expect("alice");
    let bob = UserId::new("bob").expect("bob");
    let tenant_operator = UserId::new("operator-alpha").expect("operator");
    let (private_store, private_installation_id) = matrix_extension_store_with_installation(
        ExtensionActivationState::Disabled,
        InstallationOwner::users(BTreeSet::from([alice.clone()])).expect("owner"),
    )
    .await;
    let err = apply_matrix_extension_lifecycle_mutation(
        &private_store,
        &private_installation_id,
        MatrixExtensionLifecycleMutation::Enable,
        &bob,
        &tenant_operator,
    )
    .await
    .expect_err("non-owner cannot enable installation");
    assert_eq!(err, MatrixInstallationPolicyRejection::MutationUnauthorized);
    apply_matrix_extension_lifecycle_mutation(
        &private_store,
        &private_installation_id,
        MatrixExtensionLifecycleMutation::Enable,
        &alice,
        &tenant_operator,
    )
    .await
    .expect("member owner can enable private installation");
}

#[test]
fn matrix_policy_artifact_rebind_invalidates_prepared_snapshot() {
    let mut install = installation("install-alpha", MatrixActivationState::Enabled);
    let ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
    );
    let snapshot = resolve_matrix_inbound_installation(&[install.clone()], &ctx).expect("snapshot");
    let authorized = MatrixInstallationMutationAuthority::tenant_operator();
    let mut rebound = artifact();
    rebound.artifact_sha256 =
        ArtifactSha256::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("sha");
    let mut inspection = artifact_inspection();
    inspection.artifact_sha256 = rebound.artifact_sha256.clone();
    install
        .apply_mutation(
            MatrixInstallationMutation::RebindArtifact {
                component: rebound,
                artifact_inspection: inspection,
            },
            &authorized,
            "operator-beta",
            2,
        )
        .expect("artifact rebind");

    let err = authorize_matrix_outbound(
        &snapshot,
        &MatrixOutboundPolicyCheck {
            adapter_id: adapter_id(),
            installation_id: installation_id("install-alpha"),
            homeserver: homeserver("https://matrix.example.org"),
            room_id: room("!room:example.org"),
            egress_target_index: EgressTargetIndex::new(0),
            credential_handle: credential("matrix-access-token"),
            path: "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn".to_string(),
            guest_authorization_header_present: false,
            policy_revision: install.policy_revision,
        },
    )
    .expect_err("stale prepared component snapshot fails closed");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::PolicyRevisionMismatch
    );
}

#[test]
fn matrix_policy_concurrent_policy_mutations_serialize_with_monotonic_revisions() {
    let installation = MatrixProductAdapterInstallation::create_disabled(
        ProductAdapterId::new("matrix").expect("adapter id"),
        AdapterInstallationId::new("matrix-install-alpha").expect("installation id"),
        artifact(),
        policy(),
        audit(),
    )
    .expect("disabled installation");
    let installation_id = installation.installation_id.clone();
    let authorized = MatrixInstallationMutationAuthority::tenant_operator();
    let mut registry = MatrixInstallationProjectionCache::new();
    registry
        .insert_projection(installation, "operator-alpha", 1)
        .expect("insert projection");
    let registry = Arc::new(Mutex::new(registry));
    let barrier = Arc::new(Barrier::new(2));

    let policy_registry = Arc::clone(&registry);
    let policy_barrier = Arc::clone(&barrier);
    let policy_id = installation_id.clone();
    let policy_authority = authorized.clone();
    let update_policy = std::thread::spawn(move || {
        policy_barrier.wait();
        policy_registry
            .lock()
            .expect("registry lock")
            .apply_policy_mutation(
                &policy_id,
                MatrixInstallationMutation::UpdatePolicy { policy: policy() },
                &policy_authority,
                "operator-alpha",
                2,
            )
            .expect("policy update");
    });

    let artifact_registry = Arc::clone(&registry);
    let artifact_barrier = Arc::clone(&barrier);
    let artifact_id = installation_id.clone();
    let artifact_authority = authorized.clone();
    let update_artifact = std::thread::spawn(move || {
        artifact_barrier.wait();
        artifact_registry
            .lock()
            .expect("registry lock")
            .apply_policy_mutation(
                &artifact_id,
                MatrixInstallationMutation::RebindArtifact {
                    component: artifact(),
                    artifact_inspection: artifact_inspection(),
                },
                &artifact_authority,
                "operator-beta",
                3,
            )
            .expect("artifact rebind");
    });

    update_policy.join().expect("policy thread");
    update_artifact.join().expect("artifact thread");

    let registry = registry.lock().expect("registry lock");
    let install = registry
        .installation(&installation_id)
        .expect("stored installation");
    assert_eq!(
        install.policy_revision,
        PolicyRevision::new(3).expect("revision")
    );
    let mut operations = registry
        .audit_events()
        .iter()
        .map(|event| event.operation)
        .collect::<Vec<_>>();
    operations.sort_by_key(|operation| match operation {
        MatrixInstallationMutationOperation::Create => 0,
        MatrixInstallationMutationOperation::UpdatePolicy => 1,
        MatrixInstallationMutationOperation::RebindArtifact => 2,
        MatrixInstallationMutationOperation::Delete => 3,
        MatrixInstallationMutationOperation::Enable => 4,
        MatrixInstallationMutationOperation::Disable => 5,
        MatrixInstallationMutationOperation::RebindCredential => 6,
    });
    assert_eq!(
        operations,
        vec![
            MatrixInstallationMutationOperation::Create,
            MatrixInstallationMutationOperation::UpdatePolicy,
            MatrixInstallationMutationOperation::RebindArtifact,
        ]
    );
    assert!(
        registry
            .audit_events()
            .iter()
            .all(|event| event.rejected_reason.is_none())
    );
}

#[test]
fn matrix_policy_artifact_inspection_rejects_mismatch_and_direct_egress_imports() {
    validate_component_artifact(&artifact(), &artifact_inspection()).expect("valid artifact");

    let mut inspection = artifact_inspection();
    inspection.artifact_sha256 =
        ArtifactSha256::new("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .expect("sha");
    let err = validate_component_artifact(&artifact(), &inspection).expect_err("hash mismatch");
    assert_eq!(err, MatrixInstallationPolicyRejection::ArtifactHashMismatch);

    let mut inspection = artifact_inspection();
    inspection.direct_http_egress_import = true;
    let err = validate_component_artifact(&artifact(), &inspection)
        .expect_err("direct egress import must reject");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::UnexpectedGuestImport
    );

    let mut inspection = artifact_inspection();
    inspection.signature_valid = Some(false);
    let err = validate_component_artifact(&artifact(), &inspection)
        .expect_err("invalid signature must reject");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::ArtifactSignatureInvalid
    );

    let mut inspection = artifact_inspection();
    inspection.signature_valid = None;
    let err = validate_component_artifact(&artifact(), &inspection)
        .expect_err("missing signature verdict must reject");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::ArtifactSignatureInvalid
    );
}

#[test]
fn matrix_policy_snapshot_revision_fails_closed_after_policy_update() {
    let mut install = installation("install-alpha", MatrixActivationState::Enabled);
    install
        .component
        .declared_egress_targets
        .push(DeclaredEgressTarget::new(
            DeclaredEgressHost::new("matrix.example.org").expect("declared host"),
            Some(credential("matrix-rotated-token")),
        ));
    let ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
    );
    let snapshot = resolve_matrix_inbound_installation(&[install.clone()], &ctx).expect("snapshot");
    let authorized = MatrixInstallationMutationAuthority {
        can_manage_installations: true,
    };
    let mut rotated_policy = install.policy.clone();
    rotated_policy.egress_target_index = EgressTargetIndex::new(1);
    rotated_policy.credential_handle = credential("matrix-rotated-token");
    install
        .apply_mutation(
            MatrixInstallationMutation::UpdatePolicy {
                policy: rotated_policy,
            },
            &authorized,
            "operator-beta",
            2,
        )
        .expect("credential rotation policy update");

    let err = authorize_matrix_outbound(
        &snapshot,
        &MatrixOutboundPolicyCheck {
            adapter_id: adapter_id(),
            installation_id: installation_id("install-alpha"),
            homeserver: homeserver("https://matrix.example.org"),
            room_id: room("!room:example.org"),
            egress_target_index: EgressTargetIndex::new(0),
            credential_handle: credential("matrix-access-token"),
            path: "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn".to_string(),
            guest_authorization_header_present: false,
            policy_revision: install.policy_revision,
        },
    )
    .expect_err("stale snapshot must fail closed on revision mismatch");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::PolicyRevisionMismatch
    );
}

#[test]
fn matrix_policy_durable_cache_mutations_invalidate_prepared_snapshots() {
    let authorized = MatrixInstallationMutationAuthority::tenant_operator();
    let ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
    );

    let mut policy_install = installation("install-policy", MatrixActivationState::Enabled);
    policy_install
        .component
        .declared_egress_targets
        .push(DeclaredEgressTarget::new(
            DeclaredEgressHost::new("matrix.example.org").expect("declared host"),
            Some(credential("matrix-rotated-token")),
        ));
    let policy_id = policy_install.installation_id.clone();
    let mut policy_cache = MatrixInstallationProjectionCache::new();
    policy_cache
        .insert_projection(policy_install, "operator-alpha", 1)
        .expect("insert policy projection");
    let prepared = resolve_matrix_inbound_installation(
        &policy_cache.installations().cloned().collect::<Vec<_>>(),
        &ctx,
    )
    .expect("prepared policy snapshot");
    let mut rotated_policy = policy_cache
        .installation(&policy_id)
        .expect("stored installation")
        .policy
        .clone();
    rotated_policy.egress_target_index = EgressTargetIndex::new(1);
    rotated_policy.credential_handle = credential("matrix-rotated-token");
    policy_cache
        .apply_policy_mutation(
            &policy_id,
            MatrixInstallationMutation::UpdatePolicy {
                policy: rotated_policy,
            },
            &authorized,
            "operator-alpha",
            2,
        )
        .expect("durable policy update");
    let current_revision = policy_cache
        .installation(&policy_id)
        .expect("updated installation")
        .policy_revision;
    let err = authorize_matrix_outbound(
        &prepared,
        &MatrixOutboundPolicyCheck {
            adapter_id: adapter_id(),
            installation_id: policy_id.clone(),
            homeserver: homeserver("https://matrix.example.org"),
            room_id: room("!room:example.org"),
            egress_target_index: EgressTargetIndex::new(0),
            credential_handle: credential("matrix-access-token"),
            path: "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn".to_string(),
            guest_authorization_header_present: false,
            policy_revision: current_revision,
        },
    )
    .expect_err("stale prepared policy snapshot fails closed");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::PolicyRevisionMismatch
    );

    let artifact_id = installation_id("install-artifact");
    let mut artifact_cache = MatrixInstallationProjectionCache::new();
    artifact_cache
        .insert_projection(
            installation("install-artifact", MatrixActivationState::Enabled),
            "operator-alpha",
            3,
        )
        .expect("insert artifact projection");
    let prepared = resolve_matrix_inbound_installation(
        &artifact_cache.installations().cloned().collect::<Vec<_>>(),
        &ctx,
    )
    .expect("prepared artifact snapshot");
    let mut rebound = artifact();
    rebound.artifact_sha256 =
        ArtifactSha256::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("sha");
    let mut inspection = artifact_inspection();
    inspection.artifact_sha256 = rebound.artifact_sha256.clone();
    artifact_cache
        .apply_policy_mutation(
            &artifact_id,
            MatrixInstallationMutation::RebindArtifact {
                component: rebound,
                artifact_inspection: inspection,
            },
            &authorized,
            "operator-alpha",
            4,
        )
        .expect("durable artifact rebind");
    let current_revision = artifact_cache
        .installation(&artifact_id)
        .expect("updated installation")
        .policy_revision;
    let err = authorize_matrix_outbound(
        &prepared,
        &MatrixOutboundPolicyCheck {
            adapter_id: adapter_id(),
            installation_id: artifact_id.clone(),
            homeserver: homeserver("https://matrix.example.org"),
            room_id: room("!room:example.org"),
            egress_target_index: EgressTargetIndex::new(0),
            credential_handle: credential("matrix-access-token"),
            path: "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn".to_string(),
            guest_authorization_header_present: false,
            policy_revision: current_revision,
        },
    )
    .expect_err("stale prepared artifact snapshot fails closed");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::PolicyRevisionMismatch
    );

    let credential_id = installation_id("install-credential");
    let mut credential_cache = MatrixInstallationProjectionCache::new();
    credential_cache
        .insert_projection(
            installation("install-credential", MatrixActivationState::Enabled),
            "operator-alpha",
            5,
        )
        .expect("insert credential projection");
    let prepared = resolve_matrix_inbound_installation(
        &credential_cache
            .installations()
            .cloned()
            .collect::<Vec<_>>(),
        &ctx,
    )
    .expect("prepared credential snapshot");
    credential_cache
        .apply_policy_mutation(
            &credential_id,
            MatrixInstallationMutation::RebindCredential {
                credential_handle: credential("matrix-access-token"),
            },
            &authorized,
            "operator-alpha",
            6,
        )
        .expect("durable credential rebind");
    let current_revision = credential_cache
        .installation(&credential_id)
        .expect("updated installation")
        .policy_revision;
    let err = authorize_matrix_outbound(
        &prepared,
        &MatrixOutboundPolicyCheck {
            adapter_id: adapter_id(),
            installation_id: credential_id.clone(),
            homeserver: homeserver("https://matrix.example.org"),
            room_id: room("!room:example.org"),
            egress_target_index: EgressTargetIndex::new(0),
            credential_handle: credential("matrix-access-token"),
            path: "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn".to_string(),
            guest_authorization_header_present: false,
            policy_revision: current_revision,
        },
    )
    .expect_err("stale prepared credential snapshot fails closed");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::PolicyRevisionMismatch
    );
}

#[test]
fn matrix_policy_credential_lifecycle_states_fail_closed() {
    assert_eq!(
        validate_matrix_credential_state(MatrixCredentialState::Active),
        Ok(())
    );
    assert_eq!(
        validate_matrix_credential_state(MatrixCredentialState::Missing),
        Err(MatrixInstallationPolicyRejection::CredentialHandleMissing)
    );
    for state in [
        MatrixCredentialState::Stale,
        MatrixCredentialState::Revoked,
        MatrixCredentialState::Rotated,
    ] {
        assert_eq!(
            validate_matrix_credential_state(state),
            Err(MatrixInstallationPolicyRejection::CredentialHandleRevoked)
        );
    }
    assert_eq!(
        validate_matrix_credential_state(MatrixCredentialState::WrongHomeserver),
        Err(MatrixInstallationPolicyRejection::HomeserverMismatch)
    );
}

#[test]
fn matrix_policy_isolates_installations_and_rejection_diagnostics() {
    let alpha = installation("install-alpha", MatrixActivationState::Enabled);
    let mut beta = installation("install-beta", MatrixActivationState::Enabled);
    beta.policy.allowed_rooms = set([room("!beta:example.org")]);
    beta.policy.allowed_senders = set([user("@bob:example.org")]);
    beta.policy.credential_handle = credential("matrix-beta-token");
    beta.component.declared_egress_targets[0] = DeclaredEgressTarget::new(
        DeclaredEgressHost::new("matrix.example.org").expect("declared host"),
        Some(credential("matrix-beta-token")),
    );

    let alpha_ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
    );
    let snapshot = resolve_matrix_inbound_installation(&[alpha, beta.clone()], &alpha_ctx)
        .expect("alpha snapshot");
    assert_eq!(snapshot.installation_id, installation_id("install-alpha"));
    assert_eq!(
        snapshot.credential_handle,
        credential("matrix-access-token")
    );

    let beta_ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!beta:example.org"),
        user("@bob:example.org"),
    );
    let snapshot = resolve_matrix_inbound_installation(&[beta], &beta_ctx).expect("beta snapshot");
    assert_eq!(snapshot.installation_id, installation_id("install-beta"));
    assert_eq!(snapshot.credential_handle, credential("matrix-beta-token"));

    assert_eq!(
        MatrixInstallationPolicyRejection::CredentialHandleMismatch.external_response_shape(),
        MatrixInstallationPolicyRejection::RoomNotAllowed.external_response_shape()
    );
}

#[test]
fn matrix_policy_rejects_unverified_routing_context() {
    let err = MatrixInboundRoutingContext::from_verified_auth(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
        &ProtocolAuthEvidence::failed(ProtocolAuthFailure::Missing),
        1_710_000_000_001,
    )
    .expect_err("failed auth evidence must not create a routing context");

    assert_eq!(err, MatrixInstallationPolicyRejection::AuthInvalid);
}

#[test]
fn matrix_policy_auth_context_is_host_minted_from_protocol_evidence() {
    let ctx = MatrixInboundRoutingContext::from_verified_auth(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
        &auth_evidence(),
        1_710_000_000_001,
    )
    .expect("host-minted auth context");
    assert_eq!(ctx.auth.subject(), "matrix-webhook");

    let err = serde_json::from_str::<VerifiedMatrixAuthContext>(r#"{"subject":"guest-supplied"}"#)
        .expect_err("guest-visible JSON cannot mint verified auth context");
    assert!(
        err.to_string()
            .contains("host-minted from protocol auth evidence")
    );
}

#[test]
fn matrix_policy_audit_metadata_tracks_update_and_enable_actors() {
    let mut audit = InstallationAuditMetadata::new("operator-alpha", 1).expect("audit metadata");
    assert_eq!(audit.created_by, "operator-alpha");
    assert_eq!(audit.updated_by, "operator-alpha");
    assert_eq!(audit.last_enable_actor, None);

    audit
        .record_update("operator-beta", 2)
        .expect("update audit metadata");
    assert_eq!(audit.created_by, "operator-alpha");
    assert_eq!(audit.updated_by, "operator-beta");
    assert_eq!(audit.updated_at_ms, 2);

    audit
        .record_enable("operator-gamma", 3)
        .expect("enable audit metadata");
    assert_eq!(audit.updated_by, "operator-gamma");
    assert_eq!(audit.last_enable_actor.as_deref(), Some("operator-gamma"));
    assert_eq!(audit.last_enable_at_ms, Some(3));
}

#[test]
fn matrix_policy_rejects_guest_supplied_credentials_and_path_mutation() {
    let install = installation("install-alpha", MatrixActivationState::Enabled);
    let ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
    );
    let snapshot = resolve_matrix_inbound_installation(&[install], &ctx).expect("snapshot");

    let mut check = MatrixOutboundPolicyCheck {
        adapter_id: adapter_id(),
        installation_id: installation_id("install-alpha"),
        homeserver: homeserver("https://matrix.example.org"),
        room_id: room("!room:example.org"),
        egress_target_index: EgressTargetIndex::new(0),
        credential_handle: credential("matrix-access-token"),
        path: "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn".to_string(),
        guest_authorization_header_present: true,
        policy_revision: PolicyRevision::new(7).expect("revision"),
    };

    let err = authorize_matrix_outbound(&snapshot, &check)
        .expect_err("guest-supplied auth header must fail closed");
    assert_eq!(
        err,
        MatrixInstallationPolicyRejection::GuestCredentialMaterialRejected
    );

    check.guest_authorization_header_present = false;
    for path in [
        "https://matrix.example.org/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn",
        "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn?access_token=secret",
        "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn#fragment",
        "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/%2e%2e",
        "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/../txn",
        "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn\0",
        "//_matrix/client/v3/rooms/!room:example.org/send/m.room.message/txn",
        "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/file://token",
        "/_matrix/client/v3/rooms/!room:example.org/send/m.room.message/mxc://token",
    ] {
        check.path = path.to_string();
        let err = authorize_matrix_outbound(&snapshot, &check)
            .expect_err("unsafe Matrix request shape must fail closed");
        assert_eq!(
            err,
            MatrixInstallationPolicyRejection::UnsafeMatrixRequestShape
        );
    }
}

#[test]
fn matrix_policy_external_response_shape_does_not_enumerate_policy_state() {
    let expected =
        MatrixInstallationPolicyRejection::InstallationNotFound.external_response_shape();

    for reason in MatrixInstallationPolicyRejection::ALL {
        assert_eq!(
            reason.external_response_shape(),
            expected,
            "all policy denials must share one external shape: {reason:?}"
        );
    }
}
