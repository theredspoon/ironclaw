use std::collections::BTreeSet;

use ironclaw_matrix_adapter::installation_policy::{
    ArtifactSha256, ComponentArtifactBinding, ComponentArtifactId, ComponentArtifactInspection,
    EgressTargetIndex, InstallationAuditMetadata, MatrixActivationState, MatrixCredentialState,
    MatrixHomeserverOrigin, MatrixInboundRoutingContext, MatrixInstallationMutation,
    MatrixInstallationMutationAuthority, MatrixInstallationMutationOperation,
    MatrixInstallationPolicy, MatrixInstallationPolicyRejection, MatrixOutboundPolicyCheck,
    MatrixProductAdapterInstallation, MatrixRoomId, MatrixUserId, PolicyRevision,
    StaticManifestBinding, WitPackageName, WitWorldName, authorize_matrix_outbound,
    resolve_matrix_inbound_installation, validate_component_artifact,
    validate_matrix_credential_state,
};
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, DeclaredEgressHost, DeclaredEgressTarget,
    EgressCredentialHandle, ProductAdapterId, ProtocolAuthEvidence, ProtocolAuthFailure,
};

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
    let ctx = routing_context(
        homeserver("https://matrix.example.org"),
        room("!room:example.org"),
        user("@alice:example.org"),
    );
    let snapshot = resolve_matrix_inbound_installation(&[install.clone()], &ctx).expect("snapshot");
    let authorized = MatrixInstallationMutationAuthority {
        can_manage_installations: true,
    };
    install
        .apply_mutation(
            MatrixInstallationMutation::RebindCredential {
                credential_handle: credential("matrix-rotated-token"),
            },
            &authorized,
            "operator-beta",
            2,
        )
        .expect("credential rotation");

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
