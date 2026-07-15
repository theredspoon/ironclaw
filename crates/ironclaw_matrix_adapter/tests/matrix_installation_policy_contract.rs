use std::collections::BTreeSet;

use ironclaw_matrix_adapter::installation_policy::{
    ArtifactSha256, ComponentArtifactBinding, ComponentArtifactId, EgressTargetIndex,
    InstallationAuditMetadata, MatrixActivationState, MatrixHomeserverOrigin,
    MatrixInboundRoutingContext, MatrixInstallationPolicy, MatrixInstallationPolicyRejection,
    MatrixOutboundPolicyCheck, MatrixProductAdapterInstallation, MatrixRoomId, MatrixUserId,
    PolicyRevision, StaticManifestBinding, WitPackageName, WitWorldName, authorize_matrix_outbound,
    resolve_matrix_inbound_installation,
};
use ironclaw_product_adapters::{AdapterInstallationId, EgressCredentialHandle, ProductAdapterId};

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
    }
}

fn audit() -> InstallationAuditMetadata {
    InstallationAuditMetadata::new("operator-alpha", 1_710_000_000_000).expect("audit metadata")
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
    let ctx = MatrixInboundRoutingContext::verified_for_test(
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
    assert!(MatrixHomeserverOrigin::parse("https://matrix.example.org/path").is_err());
}

#[test]
fn matrix_policy_snapshot_authorizes_outbound_and_rejects_credential_pair_mismatch() {
    let install = installation("install-alpha", MatrixActivationState::Enabled);
    let ctx = MatrixInboundRoutingContext::verified_for_test(
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
fn matrix_policy_external_response_shape_does_not_enumerate_policy_state() {
    assert_eq!(
        MatrixInstallationPolicyRejection::InstallationNotFound.external_response_shape(),
        MatrixInstallationPolicyRejection::InstallationDisabled.external_response_shape()
    );
    assert_eq!(
        MatrixInstallationPolicyRejection::RoomNotAllowed.external_response_shape(),
        MatrixInstallationPolicyRejection::AmbiguousInstallation.external_response_shape()
    );
    assert_eq!(
        MatrixInstallationPolicyRejection::InstallationDisabled.external_response_shape(),
        MatrixInstallationPolicyRejection::MutationUnauthorized.external_response_shape()
    );
}
