use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use async_trait::async_trait;
use chrono::Utc;
use ironclaw_auth::{
    AuthChallenge, AuthContinuationRef, AuthFlowKind, AuthFlowManager, AuthInteractionService,
    AuthProductError, AuthProductScope, AuthProviderClient, AuthProviderId, AuthSurface,
    CredentialAccount, CredentialAccountChoiceRequest, CredentialAccountId, CredentialAccountLabel,
    CredentialAccountListPage, CredentialAccountListRequest, CredentialAccountLookupRequest,
    CredentialAccountMutation, CredentialAccountProjection, CredentialAccountSelectionRequest,
    CredentialAccountService, CredentialAccountStatus, CredentialAccountUpdateBinding,
    CredentialOwnership, CredentialRecoveryProjection, CredentialRecoveryRequest,
    CredentialRefreshReport, CredentialRefreshRequest, CredentialSetupService,
    InMemoryAuthProductServices, LifecyclePackageRef, NewAuthFlow, NewCredentialAccount,
    OAuthAuthorizationUrl, OAuthProviderCallbackRequest, OAuthProviderExchange,
    OAuthProviderExchangeContext, OAuthProviderRefresh, OAuthProviderRefreshRequest,
    OpaqueStateHash, SecretCleanupAction, SecretCleanupRequest, SecretCleanupService,
};
use ironclaw_events::{DurableAuditLog, EventStreamKey, InMemoryDurableAuditLog, ReadScope};
use ironclaw_extensions::{
    ExtensionActivationState, ExtensionInstallation, ExtensionInstallationId,
    ExtensionInstallationStore, ExtensionManifestRecord, ExtensionManifestRef,
    InMemoryExtensionInstallationStore, InstallationOwner, MANIFEST_SCHEMA_VERSION, ManifestHash,
    ManifestSource,
};
use ironclaw_filesystem::{
    BackendCapabilities, DirEntry, FileStat, FilesystemError, FilesystemOperation, InMemoryBackend,
    RecordVersion, RootFilesystem,
};
use ironclaw_host_api::{
    AgentId, ExtensionId, InvocationId, ProjectId, ResourceScope, SecretHandle, TenantId, UserId,
    VirtualPath,
};
use ironclaw_matrix_adapter::installation_policy::{
    ArtifactSha256, ComponentArtifactId, MatrixUserId, WitPackageName, WitWorldName,
};
use ironclaw_product_adapters::{AdapterInstallationId, EgressCredentialHandle, ProductAdapterId};
use ironclaw_product_workflow::{
    ExtensionCredentialSetupService, ExtensionCredentialSubmitRequest, RebornServicesError,
    RebornServicesErrorCode, RebornServicesErrorKind,
};
use ironclaw_secrets::InMemorySecretStore;
use secrecy::SecretString;

use super::*;
use crate::matrix_outbound_targets::{
    FilesystemMatrixRoomBindingStore, MatrixConfiguredRoomRoute,
    MatrixOutboundTargetProviderConfig, MatrixRoomBindingAuthority,
    MatrixRoomBindingMutationContext, MatrixRoomBindingRemovalOutcome,
    MatrixRoomBindingRemovalRequest, MatrixRoomBindingStore, MatrixRoomBindingUpdateOutcome,
    MatrixRoomBindingUpdateRequest, MatrixRoomBindingUpsertOutcome, MatrixRoomBindingUpsertRequest,
};

#[derive(Debug)]
struct FailingMatrixRoomBindingUpdateStore {
    inner: Arc<dyn MatrixRoomBindingStore>,
}

#[async_trait]
impl MatrixRoomBindingStore for FailingMatrixRoomBindingUpdateStore {
    async fn snapshot_provider_configs(
        &self,
    ) -> Result<Vec<MatrixOutboundTargetProviderConfig>, RebornServicesError> {
        self.inner.snapshot_provider_configs().await
    }

    async fn list_room_bindings(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        project_id: Option<&ProjectId>,
        subject_user_id: &UserId,
    ) -> Result<Vec<crate::matrix_outbound_targets::MatrixRoomBinding>, RebornServicesError> {
        self.inner
            .list_room_bindings(tenant_id, agent_id, project_id, subject_user_id)
            .await
    }

    async fn resolve_room_binding(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        project_id: Option<&ProjectId>,
        installation_id: &AdapterInstallationId,
        room_id: &crate::matrix_outbound::MatrixRoomId,
        subject_user_id: &UserId,
    ) -> Result<Option<crate::matrix_outbound_targets::MatrixRoomBinding>, RebornServicesError>
    {
        self.inner
            .resolve_room_binding(
                tenant_id,
                agent_id,
                project_id,
                installation_id,
                room_id,
                subject_user_id,
            )
            .await
    }

    async fn remove_room_binding(
        &self,
        request: MatrixRoomBindingRemovalRequest,
    ) -> Result<MatrixRoomBindingRemovalOutcome, RebornServicesError> {
        self.inner.remove_room_binding(request).await
    }

    async fn upsert_room_binding(
        &self,
        request: MatrixRoomBindingUpsertRequest,
    ) -> Result<MatrixRoomBindingUpsertOutcome, RebornServicesError> {
        self.inner.upsert_room_binding(request).await
    }

    async fn update_room_binding(
        &self,
        _request: MatrixRoomBindingUpdateRequest,
    ) -> Result<MatrixRoomBindingUpdateOutcome, RebornServicesError> {
        Err(matrix_room_binding_test_backend_error())
    }

    async fn provider_has_removed_room_binding(
        &self,
        provider: &MatrixOutboundTargetProviderConfig,
    ) -> Result<bool, RebornServicesError> {
        self.inner.provider_has_removed_room_binding(provider).await
    }
}

fn matrix_room_binding_test_backend_error() -> RebornServicesError {
    RebornServicesError {
        code: RebornServicesErrorCode::Unavailable,
        kind: RebornServicesErrorKind::ServiceUnavailable,
        status_code: 503,
        retryable: true,
        field: None,
        validation_code: None,
    }
}

#[tokio::test]
async fn matrix_lifecycle_refresher_projects_cache_from_runtime_sources_not_static_policy() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let source_room = "!source-backed-room:example.org";
    let source_sender = "@source-backed-user:example.org";
    let actor_user_id = "user:source-backed-agent";
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: source_room.to_string(),
            subject_user_id: UserId::new(actor_user_id).expect("actor user id"),
            matrix_sender_user_id: MatrixUserId::new(source_sender).expect("matrix sender"),
        }],
    };
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        root,
        store,
        vec![provider.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("refresher config");
    let scope = matrix_source_backed_scope();

    refresher
        .refresh_after_lifecycle_activation(
            &scope,
            &ExtensionId::new("matrix-product-adapter").expect("extension id"),
        )
        .await
        .expect("refresh projection cache");

    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
        matrix_policy_projection_cache_path_for_provider_key(
            &crate::matrix_outbound_targets::matrix_policy_provider_scope_key(
                &TenantId::new("matrix-source-backed-tenant").expect("tenant"),
                &AgentId::new("matrix-source-backed-agent").expect("agent"),
                Some(&ProjectId::new("matrix-source-backed-project").expect("project")),
                &installation_id,
            ),
        )
        .expect("cache path"),
    );
    let snapshot = source
        .resolve_matrix_policy_snapshot(
            &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter id"),
            &installation_id,
        )
        .await
        .expect("source-backed snapshot");
    assert_eq!(snapshot.installation_id, installation_id);
    assert_eq!(snapshot.homeserver.host(), "matrix.source.example.org");
    assert!(
        snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == source_room)
    );
    assert!(
        snapshot
            .allowed_senders
            .iter()
            .any(|sender| sender.as_str() == source_sender)
    );
    assert_eq!(snapshot.allowed_rooms.len(), 1);
    assert_eq!(snapshot.allowed_senders.len(), 1);
    assert!(
        !snapshot
            .allowed_senders
            .iter()
            .any(|sender| sender.as_str() == actor_user_id),
        "Matrix policy must not derive senders from IronClaw actor ids"
    );
}

#[tokio::test]
async fn matrix_lifecycle_refresher_rebuilds_shared_source_snapshot_after_room_binding_removal() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![
            MatrixConfiguredRoomRoute {
                room_id: "!fresh-shared-room-a:example.org".to_string(),
                subject_user_id: UserId::new("user:fresh-shared-room-a").expect("actor a"),
                matrix_sender_user_id: MatrixUserId::new("@fresh-shared-room-a:example.org")
                    .expect("matrix sender a"),
            },
            MatrixConfiguredRoomRoute {
                room_id: "!stale-shared-room-b:example.org".to_string(),
                subject_user_id: UserId::new("user:stale-shared-room-b").expect("actor b"),
                matrix_sender_user_id: MatrixUserId::new("@stale-shared-room-b:example.org")
                    .expect("matrix sender b"),
            },
        ],
    };
    let target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(
        Arc::clone(&root),
        [provider.tenant_id.clone()],
    ));
    target_source
        .seed_from_configs(std::slice::from_ref(&provider))
        .await
        .expect("seed filesystem Matrix target source");
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
        root,
        store.clone(),
        target_source.clone(),
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("shared-source refresher config");
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
    );
    refresher
        .refresh_after_lifecycle_activation(&scope, &extension_id)
        .await
        .expect("initial projection with rooms A and B");
    let initial_snapshot = source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");
    assert!(
        initial_snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!stale-shared-room-b:example.org")
    );

    let removal_request = MatrixRoomBindingRemovalRequest {
        tenant_id: provider.tenant_id.clone(),
        agent_id: provider.agent_id.clone(),
        project_id: provider.project_id.clone(),
        installation_id: provider.installation_id.clone(),
        room_id: crate::matrix_outbound::MatrixRoomId::new(
            "!stale-shared-room-b:example.org".to_string(),
        )
        .expect("room B"),
        subject_user_id: UserId::new("user:stale-shared-room-b").expect("actor b"),
    };
    refresher
        .invalidate_before_target_binding_removal(&scope, &extension_id, &removal_request)
        .await
        .expect("pre-invalidate projection before durable room binding removal");
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err("pre-invalidation must make the stale projection fail closed"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );

    let outcome = target_source
        .remove_room_binding(removal_request)
        .await
        .expect("remove room B from shared source");
    assert_eq!(outcome, MatrixRoomBindingRemovalOutcome::Removed);

    refresher
        .refresh_after_target_binding_mutation(&scope, &extension_id)
        .await
        .expect("projection refresh from mutated shared source");
    let refreshed_snapshot = source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("refreshed snapshot");
    assert!(
        refreshed_snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!fresh-shared-room-a:example.org")
    );
    assert!(
        !refreshed_snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!stale-shared-room-b:example.org"),
        "projection refresh must rebuild from the shared source after room B is removed"
    );
}

#[tokio::test]
async fn matrix_room_binding_authority_upsert_create_refreshes_provider_policy_projection() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(Arc::clone(&root), []));
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
        Arc::clone(&root),
        store.clone(),
        target_source.clone(),
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("shared-source refresher config");
    let audit_log = Arc::new(InMemoryDurableAuditLog::new());
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let authority =
        MatrixRoomBindingAuthority::new_with_audit_log(target_source, refresher, audit_log.clone());
    let request = MatrixRoomBindingUpsertRequest {
        tenant_id: scope.tenant_id.clone(),
        agent_id: scope.agent_id.clone().expect("agent"),
        project_id: scope.project_id.clone(),
        installation_id: AdapterInstallationId::new("matrix-source-backed-install")
            .expect("installation id"),
        room_id: crate::matrix_outbound::MatrixRoomId::new(
            "!authority-upsert-create:example.org".to_string(),
        )
        .expect("room"),
        subject_user_id: UserId::new("user:authority-upsert-create").expect("subject"),
        matrix_sender_user_id: MatrixUserId::new("@authority-upsert-create:example.org")
            .expect("matrix sender"),
    };

    let outcome = authority
        .upsert_room_binding(
            &MatrixRoomBindingMutationContext::for_host_owned_matrix_admin(
                scope.clone(),
                extension_id.clone(),
            ),
            request.clone(),
        )
        .await
        .expect("host-owned upsert creates binding and refreshes projection");
    assert_eq!(outcome, MatrixRoomBindingUpsertOutcome::Created);

    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: request.tenant_id.clone(),
        agent_id: request.agent_id.clone(),
        project_id: request.project_id.clone(),
        installation_id: request.installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: request.room_id.as_str().to_string(),
            subject_user_id: request.subject_user_id.clone(),
            matrix_sender_user_id: request.matrix_sender_user_id.clone(),
        }],
    };
    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
    );
    let snapshot = source
        .resolve_matrix_policy_snapshot(
            &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
            &request.installation_id,
        )
        .await
        .expect("upsert refresh publishes provider-scoped projection");
    assert!(
        snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == request.room_id.as_str())
    );

    let audit = audit_log
        .read_after_cursor(
            &EventStreamKey::new(
                scope.tenant_id.clone(),
                scope.user_id.clone(),
                scope.agent_id.clone(),
            ),
            &ReadScope::any(),
            None,
            10,
        )
        .await
        .expect("audit replay");
    assert_eq!(audit.entries.len(), 1);
    let record = &audit.entries[0].record;
    assert_eq!(record.action.kind, "matrix_room_binding_upsert");
    let target = record.action.target.as_ref().expect("audit target");
    assert!(target.contains("room_sha256="));
    assert!(!target.contains(request.room_id.as_str()));
    assert_eq!(
        record
            .result
            .as_ref()
            .and_then(|result| result.status.as_deref()),
        Some("Created")
    );
}

#[tokio::test]
async fn matrix_room_binding_authority_denies_cross_scope_upsert_context() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(Arc::clone(&root), []));
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
        root,
        store,
        target_source.clone(),
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("shared-source refresher config");
    let scope = matrix_source_backed_scope();
    let mut foreign_scope = scope.clone();
    foreign_scope.tenant_id = TenantId::new("matrix-foreign-tenant").expect("foreign tenant");
    let authority = MatrixRoomBindingAuthority::new(target_source.clone(), refresher);

    let error = authority
        .upsert_room_binding(
            &MatrixRoomBindingMutationContext::for_host_owned_matrix_admin(
                foreign_scope,
                ExtensionId::new("matrix-product-adapter").expect("extension id"),
            ),
            MatrixRoomBindingUpsertRequest {
                tenant_id: scope.tenant_id.clone(),
                agent_id: scope.agent_id.clone().expect("agent"),
                project_id: scope.project_id.clone(),
                installation_id: AdapterInstallationId::new("matrix-source-backed-install")
                    .expect("installation id"),
                room_id: crate::matrix_outbound::MatrixRoomId::new(
                    "!authority-denied:example.org".to_string(),
                )
                .expect("room"),
                subject_user_id: UserId::new("user:authority-denied").expect("subject"),
                matrix_sender_user_id: MatrixUserId::new("@authority-denied:example.org")
                    .expect("matrix sender"),
            },
        )
        .await
        .expect_err("foreign mutation context must not authorize request scope");

    assert!(matches!(error, ProductWorkflowError::BindingAccessDenied));
    assert!(
        target_source
            .snapshot_provider_configs()
            .await
            .expect("snapshot after denied request")
            .is_empty(),
        "denied requests must not mutate the store"
    );
}

#[tokio::test]
async fn matrix_room_binding_authority_remove_refreshes_projection_and_appends_redacted_audit() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let stale_room = crate::matrix_outbound::MatrixRoomId::new(
        "!authority-remove-stale:example.org".to_string(),
    )
    .expect("stale room");
    let fresh_room = crate::matrix_outbound::MatrixRoomId::new(
        "!authority-remove-fresh:example.org".to_string(),
    )
    .expect("fresh room");
    let stale_subject = UserId::new("user:authority-remove-stale").expect("stale subject");
    let fresh_subject = UserId::new("user:authority-remove-fresh").expect("fresh subject");
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![
            MatrixConfiguredRoomRoute {
                room_id: stale_room.as_str().to_string(),
                subject_user_id: stale_subject.clone(),
                matrix_sender_user_id: MatrixUserId::new("@authority-remove-stale:example.org")
                    .expect("stale matrix sender"),
            },
            MatrixConfiguredRoomRoute {
                room_id: fresh_room.as_str().to_string(),
                subject_user_id: fresh_subject,
                matrix_sender_user_id: MatrixUserId::new("@authority-remove-fresh:example.org")
                    .expect("fresh matrix sender"),
            },
        ],
    };
    let target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(
        Arc::clone(&root),
        [provider.tenant_id.clone()],
    ));
    target_source
        .seed_from_configs(std::slice::from_ref(&provider))
        .await
        .expect("seed target source");
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
        Arc::clone(&root),
        store,
        target_source.clone(),
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("shared-source refresher config");
    let audit_log = Arc::new(InMemoryDurableAuditLog::new());
    let authority = MatrixRoomBindingAuthority::new_with_audit_log(
        target_source.clone(),
        refresher,
        audit_log.clone(),
    );
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
    );

    let outcome = authority
        .remove_room_binding(
            &MatrixRoomBindingMutationContext::for_host_owned_matrix_admin(
                scope.clone(),
                extension_id,
            ),
            MatrixRoomBindingRemovalRequest {
                tenant_id: provider.tenant_id.clone(),
                agent_id: provider.agent_id.clone(),
                project_id: provider.project_id.clone(),
                installation_id: installation_id.clone(),
                room_id: stale_room.clone(),
                subject_user_id: stale_subject,
            },
        )
        .await
        .expect("authority removal refreshes projection");
    assert_eq!(outcome, MatrixRoomBindingRemovalOutcome::Removed);

    let snapshot = source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("refreshed snapshot after removal");
    assert!(
        snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == fresh_room.as_str())
    );
    assert!(
        !snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == stale_room.as_str())
    );

    let audit = audit_log
        .read_after_cursor(
            &EventStreamKey::new(
                scope.tenant_id.clone(),
                scope.user_id.clone(),
                scope.agent_id.clone(),
            ),
            &ReadScope::any(),
            None,
            10,
        )
        .await
        .expect("audit replay");
    assert_eq!(audit.entries.len(), 1);
    let record = &audit.entries[0].record;
    assert_eq!(record.action.kind, "matrix_room_binding_remove");
    let target = record.action.target.as_ref().expect("audit target");
    assert!(target.contains("room_sha256="));
    assert!(!target.contains(stale_room.as_str()));
    assert_eq!(
        record
            .result
            .as_ref()
            .and_then(|result| result.status.as_deref()),
        Some("Removed")
    );
}

#[tokio::test]
async fn matrix_room_binding_authority_update_refreshes_projection_and_deauthorizes_stale_room() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(Arc::clone(&root), []));
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
        Arc::clone(&root),
        store.clone(),
        target_source.clone(),
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("shared-source refresher config");
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let authority = MatrixRoomBindingAuthority::new(target_source, refresher);
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let subject_user_id = UserId::new("user:authority-update").expect("subject");

    authority
        .upsert_room_binding(
            &MatrixRoomBindingMutationContext::for_host_owned_matrix_admin(
                scope.clone(),
                extension_id.clone(),
            ),
            MatrixRoomBindingUpsertRequest {
                tenant_id: scope.tenant_id.clone(),
                agent_id: scope.agent_id.clone().expect("agent"),
                project_id: scope.project_id.clone(),
                installation_id: installation_id.clone(),
                room_id: crate::matrix_outbound::MatrixRoomId::new(
                    "!authority-update-stale:example.org".to_string(),
                )
                .expect("stale room"),
                subject_user_id: subject_user_id.clone(),
                matrix_sender_user_id: MatrixUserId::new("@authority-update:example.org")
                    .expect("matrix sender"),
            },
        )
        .await
        .expect("initial upsert");
    let update = MatrixRoomBindingUpdateRequest {
        tenant_id: scope.tenant_id.clone(),
        agent_id: scope.agent_id.clone().expect("agent"),
        project_id: scope.project_id.clone(),
        installation_id: installation_id.clone(),
        previous_room_id: crate::matrix_outbound::MatrixRoomId::new(
            "!authority-update-stale:example.org".to_string(),
        )
        .expect("stale room"),
        subject_user_id: subject_user_id.clone(),
        new_room_id: crate::matrix_outbound::MatrixRoomId::new(
            "!authority-update-fresh:example.org".to_string(),
        )
        .expect("fresh room"),
        new_matrix_sender_user_id: MatrixUserId::new("@authority-update:example.org")
            .expect("matrix sender"),
    };

    let outcome = authority
        .update_room_binding(
            &MatrixRoomBindingMutationContext::for_host_owned_matrix_admin(
                scope.clone(),
                extension_id,
            ),
            update,
        )
        .await
        .expect("host-owned update refreshes projection");
    assert_eq!(outcome, MatrixRoomBindingUpdateOutcome::Updated);

    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: scope.tenant_id.clone(),
        agent_id: scope.agent_id.clone().expect("agent"),
        project_id: scope.project_id.clone(),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!authority-update-fresh:example.org".to_string(),
            subject_user_id,
            matrix_sender_user_id: MatrixUserId::new("@authority-update:example.org")
                .expect("matrix sender"),
        }],
    };
    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
    );
    let snapshot = source
        .resolve_matrix_policy_snapshot(
            &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
            &installation_id,
        )
        .await
        .expect("updated projection");
    assert!(
        snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!authority-update-fresh:example.org")
    );
    assert!(
        !snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!authority-update-stale:example.org"),
        "host-owned update refresh must remove stale room authorization"
    );
}

#[tokio::test]
async fn matrix_room_binding_authority_upsert_update_refresh_failure_invalidates_stale_projection()
{
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(Arc::clone(&root), []));
    let initial_refresher =
        MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
            Arc::clone(&root),
            store.clone(),
            target_source.clone(),
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("initial shared-source refresher config");
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let room_id = crate::matrix_outbound::MatrixRoomId::new("!authority-upsert-update:example.org")
        .expect("room");
    let subject_user_id = UserId::new("user:authority-upsert-update").expect("subject");
    let initial_sender =
        MatrixUserId::new("@authority-upsert-update-old:example.org").expect("old sender");
    let updated_sender =
        MatrixUserId::new("@authority-upsert-update-new:example.org").expect("new sender");

    MatrixRoomBindingAuthority::new(target_source.clone(), initial_refresher)
        .upsert_room_binding(
            &MatrixRoomBindingMutationContext::for_host_owned_matrix_admin(
                scope.clone(),
                extension_id.clone(),
            ),
            MatrixRoomBindingUpsertRequest {
                tenant_id: scope.tenant_id.clone(),
                agent_id: scope.agent_id.clone().expect("agent"),
                project_id: scope.project_id.clone(),
                installation_id: installation_id.clone(),
                room_id: room_id.clone(),
                subject_user_id: subject_user_id.clone(),
                matrix_sender_user_id: initial_sender,
            },
        )
        .await
        .expect("initial upsert publishes stale projection");

    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: scope.tenant_id.clone(),
        agent_id: scope.agent_id.clone().expect("agent"),
        project_id: scope.project_id.clone(),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: room_id.as_str().to_string(),
            subject_user_id: subject_user_id.clone(),
            matrix_sender_user_id: updated_sender.clone(),
        }],
    };
    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend.clone()),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
    );
    source
        .resolve_matrix_policy_snapshot(
            &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
            &installation_id,
        )
        .await
        .expect("initial projection resolves before update");

    let failing_backend = Arc::new(FailOnNthPutFilesystem::new(backend, [2]));
    let failing_refresher =
        MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
            failing_backend,
            store,
            target_source.clone(),
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("failing shared-source refresher config");
    MatrixRoomBindingAuthority::new(target_source.clone(), failing_refresher)
        .upsert_room_binding(
            &MatrixRoomBindingMutationContext::for_host_owned_matrix_admin(
                scope.clone(),
                extension_id,
            ),
            MatrixRoomBindingUpsertRequest {
                tenant_id: scope.tenant_id.clone(),
                agent_id: scope.agent_id.clone().expect("agent"),
                project_id: scope.project_id.clone(),
                installation_id: installation_id.clone(),
                room_id: room_id.clone(),
                subject_user_id: subject_user_id.clone(),
                matrix_sender_user_id: updated_sender.clone(),
            },
        )
        .await
        .expect_err("refresh failure after upsert-as-update should surface");

    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(
                &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
                &installation_id,
            )
            .await
            .expect_err("pre-invalidation must hide stale projection after refresh failure"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );
    let stored = target_source
        .resolve_room_binding(
            &scope.tenant_id,
            scope.agent_id.as_ref().expect("agent"),
            scope.project_id.as_ref(),
            &installation_id,
            &room_id,
            &subject_user_id,
        )
        .await
        .expect("binding lookup after failed refresh")
        .expect("store mutation should have happened before refresh failed");
    assert_eq!(stored.matrix_sender_user_id, updated_sender);
}

#[tokio::test]
async fn matrix_room_binding_authority_update_failure_invalidates_stale_room_projection() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(Arc::clone(&root), []));
    let refresher = Arc::new(
        MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
            Arc::clone(&root),
            store.clone(),
            target_source.clone(),
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("shared-source refresher config"),
    );
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let subject_user_id = UserId::new("user:authority-update-failure").expect("subject");
    let stale_room_id = crate::matrix_outbound::MatrixRoomId::new(
        "!authority-update-failure-stale:example.org".to_string(),
    )
    .expect("stale room");
    let initial_authority =
        MatrixRoomBindingAuthority::new(target_source.clone(), Arc::clone(&refresher));

    initial_authority
        .upsert_room_binding(
            &MatrixRoomBindingMutationContext::for_host_owned_matrix_admin(
                scope.clone(),
                extension_id.clone(),
            ),
            MatrixRoomBindingUpsertRequest {
                tenant_id: scope.tenant_id.clone(),
                agent_id: scope.agent_id.clone().expect("agent"),
                project_id: scope.project_id.clone(),
                installation_id: installation_id.clone(),
                room_id: stale_room_id.clone(),
                subject_user_id: subject_user_id.clone(),
                matrix_sender_user_id: MatrixUserId::new("@authority-update-failure:example.org")
                    .expect("matrix sender"),
            },
        )
        .await
        .expect("initial upsert");

    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: scope.tenant_id.clone(),
        agent_id: scope.agent_id.clone().expect("agent"),
        project_id: scope.project_id.clone(),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: stale_room_id.as_str().to_string(),
            subject_user_id: subject_user_id.clone(),
            matrix_sender_user_id: MatrixUserId::new("@authority-update-failure:example.org")
                .expect("matrix sender"),
        }],
    };
    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
    );
    source
        .resolve_matrix_policy_snapshot(
            &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
            &installation_id,
        )
        .await
        .expect("initial stale projection resolves");

    let failing_source = Arc::new(FailingMatrixRoomBindingUpdateStore {
        inner: target_source,
    });
    let failing_authority = MatrixRoomBindingAuthority::new(failing_source, refresher);
    failing_authority
        .update_room_binding(
            &MatrixRoomBindingMutationContext::for_host_owned_matrix_admin(scope, extension_id),
            MatrixRoomBindingUpdateRequest {
                tenant_id: provider.tenant_id,
                agent_id: provider.agent_id,
                project_id: provider.project_id,
                installation_id: installation_id.clone(),
                previous_room_id: stale_room_id,
                subject_user_id,
                new_room_id: crate::matrix_outbound::MatrixRoomId::new(
                    "!authority-update-failure-fresh:example.org".to_string(),
                )
                .expect("fresh room"),
                new_matrix_sender_user_id: MatrixUserId::new(
                    "@authority-update-failure:example.org",
                )
                .expect("matrix sender"),
            },
        )
        .await
        .expect_err("update store failure should be returned");

    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(
                &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
                &installation_id,
            )
            .await
            .expect_err("pre-invalidation must fail closed before update errors"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );
}

#[tokio::test]
async fn matrix_room_binding_authority_discovers_durable_binding_after_restart_without_startup_provider_config()
 {
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend;
    let initial_source = Arc::new(FilesystemMatrixRoomBindingStore::new(Arc::clone(&root), []));
    let scope = matrix_source_backed_scope();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    initial_source
        .upsert_room_binding(MatrixRoomBindingUpsertRequest {
            tenant_id: scope.tenant_id.clone(),
            agent_id: scope.agent_id.clone().expect("agent"),
            project_id: scope.project_id.clone(),
            installation_id: installation_id.clone(),
            room_id: crate::matrix_outbound::MatrixRoomId::new(
                "!durable-discovery:example.org".to_string(),
            )
            .expect("room"),
            subject_user_id: UserId::new("user:durable-discovery").expect("subject"),
            matrix_sender_user_id: MatrixUserId::new("@durable-discovery:example.org")
                .expect("matrix sender"),
        })
        .await
        .expect("host-owned upsert writes durable binding and tenant index");

    let restarted_source = FilesystemMatrixRoomBindingStore::new(root, []);
    let configs = restarted_source
        .snapshot_provider_configs()
        .await
        .expect("restart discovery must use durable authority, not startup provider config");

    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].installation_id, installation_id);
    assert_eq!(configs[0].configured_room_routes.len(), 1);
    assert_eq!(
        configs[0].configured_room_routes[0].room_id,
        "!durable-discovery:example.org"
    );
}

#[tokio::test]
async fn matrix_room_binding_authority_discovers_mixed_startup_and_durable_only_tenants() {
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend;
    let durable_tenant_id = TenantId::new("matrix-durable-only-tenant").expect("tenant");
    let startup_tenant_id = TenantId::new("matrix-startup-tenant").expect("tenant");
    let agent_id = AgentId::new("matrix-source-backed-agent").expect("agent");
    let project_id = Some(ProjectId::new("matrix-source-backed-project").expect("project"));
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");

    let initial_source = FilesystemMatrixRoomBindingStore::new(Arc::clone(&root), []);
    initial_source
        .upsert_room_binding(MatrixRoomBindingUpsertRequest {
            tenant_id: durable_tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: project_id.clone(),
            installation_id: installation_id.clone(),
            room_id: crate::matrix_outbound::MatrixRoomId::new(
                "!durable-only-tenant:example.org".to_string(),
            )
            .expect("room"),
            subject_user_id: UserId::new("user:durable-only-tenant").expect("subject"),
            matrix_sender_user_id: MatrixUserId::new("@durable-only-tenant:example.org")
                .expect("matrix sender"),
        })
        .await
        .expect("write durable-only tenant binding");

    let restarted_source = FilesystemMatrixRoomBindingStore::new(root, [startup_tenant_id.clone()]);
    restarted_source
        .seed_from_configs(&[MatrixOutboundTargetProviderConfig {
            tenant_id: startup_tenant_id,
            agent_id,
            project_id,
            installation_id,
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!startup-tenant:example.org".to_string(),
                subject_user_id: UserId::new("user:startup-tenant").expect("subject"),
                matrix_sender_user_id: MatrixUserId::new("@startup-tenant:example.org")
                    .expect("matrix sender"),
            }],
        }])
        .await
        .expect("seed startup tenant binding");

    let mut room_ids = restarted_source
        .snapshot_provider_configs()
        .await
        .expect("snapshot should merge startup and durable tenant discovery")
        .into_iter()
        .flat_map(|provider| {
            provider
                .configured_room_routes
                .into_iter()
                .map(|route| route.room_id)
        })
        .collect::<Vec<_>>();
    room_ids.sort();

    assert_eq!(
        room_ids,
        vec![
            "!durable-only-tenant:example.org".to_string(),
            "!startup-tenant:example.org".to_string(),
        ]
    );
}

#[tokio::test]
async fn matrix_room_binding_authority_tombstone_blocks_bootstrap_resurrection_until_explicit_upsert_rebind()
 {
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend;
    let tenant_id = TenantId::new("matrix-source-backed-tenant").expect("tenant");
    let agent_id = AgentId::new("matrix-source-backed-agent").expect("agent");
    let project_id = Some(ProjectId::new("matrix-source-backed-project").expect("project"));
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let room_id =
        crate::matrix_outbound::MatrixRoomId::new("!tombstone-rebind:example.org".to_string())
            .expect("room");
    let subject_user_id = UserId::new("user:tombstone-rebind").expect("subject");
    let matrix_sender_user_id =
        MatrixUserId::new("@tombstone-rebind:example.org").expect("matrix sender");
    let bootstrap = MatrixOutboundTargetProviderConfig {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        project_id: project_id.clone(),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: room_id.as_str().to_string(),
            subject_user_id: subject_user_id.clone(),
            matrix_sender_user_id: matrix_sender_user_id.clone(),
        }],
    };

    let source = FilesystemMatrixRoomBindingStore::new(Arc::clone(&root), [tenant_id.clone()]);
    source
        .seed_from_configs(std::slice::from_ref(&bootstrap))
        .await
        .expect("initial bootstrap seed");
    source
        .remove_room_binding(MatrixRoomBindingRemovalRequest {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: project_id.clone(),
            installation_id: installation_id.clone(),
            room_id: room_id.clone(),
            subject_user_id: subject_user_id.clone(),
        })
        .await
        .expect("host-owned removal tombstones binding");

    let restarted_bootstrap_source =
        FilesystemMatrixRoomBindingStore::new(Arc::clone(&root), [tenant_id.clone()]);
    restarted_bootstrap_source
        .seed_from_configs(std::slice::from_ref(&bootstrap))
        .await
        .expect("bootstrap config cannot override tombstone");
    assert!(
        restarted_bootstrap_source
            .snapshot_provider_configs()
            .await
            .expect("snapshot after bootstrap")
            .is_empty(),
        "tombstoned binding must not be resurrected by startup config"
    );

    let outcome = restarted_bootstrap_source
        .upsert_room_binding(MatrixRoomBindingUpsertRequest {
            tenant_id,
            agent_id,
            project_id,
            installation_id,
            room_id,
            subject_user_id,
            matrix_sender_user_id,
        })
        .await
        .expect("explicit host-owned upsert rebind may clear tombstone");
    assert_eq!(outcome, MatrixRoomBindingUpsertOutcome::ReboundTombstone);
    assert_eq!(
        restarted_bootstrap_source
            .snapshot_provider_configs()
            .await
            .expect("snapshot after explicit rebind")
            .len(),
        1
    );
}

#[tokio::test]
async fn matrix_lifecycle_pre_invalidation_uses_removal_request_when_snapshot_is_empty() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!empty-snapshot-remove:example.org".to_string(),
            subject_user_id: UserId::new("user:empty-snapshot-remove").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@empty-snapshot-remove:example.org")
                .expect("matrix sender"),
        }],
    };
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let initial_refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        Arc::clone(&root),
        store.clone(),
        vec![provider.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("initial refresher");
    initial_refresher
        .refresh_after_lifecycle_activation(&scope, &extension_id)
        .await
        .expect("publish initial cache");

    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend.clone()),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
    );
    source
        .resolve_matrix_policy_snapshot(
            &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
            &installation_id,
        )
        .await
        .expect("initial snapshot resolves");

    let provider_scope = matrix_policy_projection_resource_scope_for_provider(&scope, &provider);
    let provider_cache_path =
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path");
    let scoped = crate::wrap_scoped(backend.clone());
    let initial_body = scoped
        .get(&provider_scope, &provider_cache_path)
        .await
        .expect("initial projection body lookup")
        .expect("initial projection body")
        .entry
        .body;
    assert_ne!(
        initial_body,
        MatrixInstallationProjectionCache::new()
            .to_json_bytes()
            .expect("empty projection bytes"),
        "initial projection body must contain the stale room before invalidation"
    );

    let empty_target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(
        Arc::clone(&root),
        [provider.tenant_id.clone()],
    ));
    let removal_refresher =
        MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
            root,
            store,
            empty_target_source,
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("removal refresher");
    removal_refresher
        .invalidate_before_target_binding_removal(
            &scope,
            &extension_id,
            &MatrixRoomBindingRemovalRequest {
                tenant_id: provider.tenant_id.clone(),
                agent_id: provider.agent_id.clone(),
                project_id: provider.project_id.clone(),
                installation_id: provider.installation_id.clone(),
                room_id: crate::matrix_outbound::MatrixRoomId::new(
                    "!empty-snapshot-remove:example.org".to_string(),
                )
                .expect("room"),
                subject_user_id: UserId::new("user:empty-snapshot-remove").expect("actor"),
            },
        )
        .await
        .expect("pre-invalidation must not need current target snapshot");

    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(
                &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
                &installation_id,
            )
            .await
            .expect_err("request-derived pre-invalidation tombstones the exact marker"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );
    assert_eq!(
        scoped
            .get(&provider_scope, &provider_cache_path)
            .await
            .expect("invalidated projection body lookup")
            .expect("invalidated projection body")
            .entry
            .body,
        MatrixInstallationProjectionCache::new()
            .to_json_bytes()
            .expect("empty projection bytes"),
        "request-derived pre-invalidation must clear the stale projection body"
    );
}

#[tokio::test]
async fn matrix_lifecycle_prepared_publish_refuses_stale_body_after_room_binding_tombstone() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![
            MatrixConfiguredRoomRoute {
                room_id: "!prepared-fresh-room:example.org".to_string(),
                subject_user_id: UserId::new("user:prepared-fresh-room").expect("actor a"),
                matrix_sender_user_id: MatrixUserId::new("@prepared-fresh-room:example.org")
                    .expect("matrix sender a"),
            },
            MatrixConfiguredRoomRoute {
                room_id: "!prepared-stale-room:example.org".to_string(),
                subject_user_id: UserId::new("user:prepared-stale-room").expect("actor b"),
                matrix_sender_user_id: MatrixUserId::new("@prepared-stale-room:example.org")
                    .expect("matrix sender b"),
            },
        ],
    };
    let target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(
        Arc::clone(&root),
        [provider.tenant_id.clone()],
    ));
    target_source
        .seed_from_configs(std::slice::from_ref(&provider))
        .await
        .expect("seed target source");
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
        root,
        store.clone(),
        target_source.clone(),
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("refresher");
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
    );
    refresher
        .prepare_lifecycle_activation_refresh(&scope, &extension_id)
        .await
        .expect("prepare stale body with both rooms");
    target_source
        .remove_room_binding(MatrixRoomBindingRemovalRequest {
            tenant_id: provider.tenant_id.clone(),
            agent_id: provider.agent_id.clone(),
            project_id: provider.project_id.clone(),
            installation_id: provider.installation_id.clone(),
            room_id: crate::matrix_outbound::MatrixRoomId::new(
                "!prepared-stale-room:example.org".to_string(),
            )
            .expect("room"),
            subject_user_id: UserId::new("user:prepared-stale-room").expect("actor b"),
        })
        .await
        .expect("remove stale room");
    refresher
        .publish_prepared_lifecycle_activation_refresh(&scope, &extension_id)
        .await
        .expect("stale prepared publish is ignored fail-closed");

    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(
                &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
                &installation_id,
            )
            .await
            .expect_err("stale prepared body must not get a valid commit marker"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );
    refresher
        .refresh_after_target_binding_mutation(&scope, &extension_id)
        .await
        .expect("fresh refresh after mutation");
    let snapshot = source
        .resolve_matrix_policy_snapshot(
            &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
            &installation_id,
        )
        .await
        .expect("fresh snapshot");
    assert!(
        snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!prepared-fresh-room:example.org")
    );
    assert!(
        !snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!prepared-stale-room:example.org")
    );
}

#[tokio::test]
async fn matrix_lifecycle_refresher_keeps_same_installation_providers_scope_isolated() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider_a = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!provider-a:example.org".to_string(),
            subject_user_id: UserId::new("user:provider-a").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@provider-a:example.org")
                .expect("matrix sender"),
        }],
    };
    let provider_b = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-other-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-other-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!provider-b:example.org".to_string(),
            subject_user_id: UserId::new("user:provider-b").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@provider-b:example.org")
                .expect("matrix sender"),
        }],
    };
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        root,
        store,
        vec![provider_a.clone(), provider_b.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("refresher config");
    let scope = matrix_source_backed_scope();

    refresher
        .refresh_after_lifecycle_activation(
            &scope,
            &ExtensionId::new("matrix-product-adapter").expect("extension id"),
        )
        .await
        .expect("refresh projection cache");

    let scoped = crate::wrap_scoped(backend);
    let source_a = FilesystemMatrixPolicySnapshotSource::new(
        Arc::clone(&scoped),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider_a),
        matrix_policy_projection_cache_path_for_provider(&provider_a).expect("path a"),
    );
    let source_b = FilesystemMatrixPolicySnapshotSource::new(
        scoped,
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider_b),
        matrix_policy_projection_cache_path_for_provider(&provider_b).expect("path b"),
    );
    let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
    let snapshot_a = source_a
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("snapshot a");
    let snapshot_b = source_b
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("snapshot b");

    assert!(
        snapshot_a
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!provider-a:example.org")
    );
    assert!(
        !snapshot_a
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!provider-b:example.org")
    );
    assert!(
        snapshot_b
            .allowed_senders
            .iter()
            .any(|sender| sender.as_str() == "@provider-b:example.org")
    );
    assert!(
        !snapshot_b
            .allowed_senders
            .iter()
            .any(|sender| sender.as_str() == "@provider-a:example.org")
    );
}

#[tokio::test]
async fn matrix_lifecycle_refresher_uses_provider_tenant_shared_scope_for_each_provider() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider_a = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-provider-tenant-a").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!provider-tenant-a:example.org".to_string(),
            subject_user_id: UserId::new("user:provider-tenant-a").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@provider-tenant-a:example.org")
                .expect("matrix sender"),
        }],
    };
    let provider_b = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-provider-tenant-b").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!provider-tenant-b:example.org".to_string(),
            subject_user_id: UserId::new("user:provider-tenant-b").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@provider-tenant-b:example.org")
                .expect("matrix sender"),
        }],
    };
    let lifecycle_scope = matrix_source_backed_scope();
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        root,
        store,
        vec![provider_a.clone(), provider_b.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("refresher config");

    refresher
        .refresh_after_lifecycle_activation(
            &lifecycle_scope,
            &ExtensionId::new("matrix-product-adapter").expect("extension id"),
        )
        .await
        .expect("refresh projection cache");

    let scoped = crate::wrap_scoped(backend);
    let lifecycle_tenant_scope = matrix_policy_projection_resource_scope(&lifecycle_scope);
    let provider_a_scope =
        matrix_policy_projection_resource_scope_for_provider(&lifecycle_scope, &provider_a);
    let provider_b_scope =
        matrix_policy_projection_resource_scope_for_provider(&lifecycle_scope, &provider_b);
    let provider_a_path = matrix_policy_projection_cache_path_for_provider(&provider_a)
        .expect("provider a cache path");
    let provider_b_path = matrix_policy_projection_cache_path_for_provider(&provider_b)
        .expect("provider b cache path");

    assert!(
        scoped
            .get(&provider_a_scope, &provider_a_path)
            .await
            .expect("provider a scoped cache lookup")
            .is_some(),
        "provider A cache must land in provider A tenant-shared scope"
    );
    assert!(
        scoped
            .get(&provider_b_scope, &provider_b_path)
            .await
            .expect("provider b scoped cache lookup")
            .is_some(),
        "provider B cache must land in provider B tenant-shared scope"
    );
    assert!(
        scoped
            .get(&lifecycle_tenant_scope, &provider_a_path)
            .await
            .expect("lifecycle scoped provider a cache lookup")
            .is_none(),
        "provider cache must not be written under the lifecycle caller tenant"
    );
    assert!(
        scoped
            .get(&lifecycle_tenant_scope, &provider_b_path)
            .await
            .expect("lifecycle scoped provider b cache lookup")
            .is_none(),
        "provider cache must not be written under the lifecycle caller tenant"
    );

    let source_a = FilesystemMatrixPolicySnapshotSource::new(
        Arc::clone(&scoped),
        provider_a_scope,
        provider_a_path,
    );
    let source_b =
        FilesystemMatrixPolicySnapshotSource::new(scoped, provider_b_scope, provider_b_path);
    let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
    let snapshot_a = source_a
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("provider a snapshot");
    let snapshot_b = source_b
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("provider b snapshot");

    assert!(
        snapshot_a
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!provider-tenant-a:example.org")
    );
    assert!(
        snapshot_b
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!provider-tenant-b:example.org")
    );
}

#[tokio::test]
async fn matrix_lifecycle_refresher_partial_write_failure_is_fail_closed_when_cleanup_fails() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let failing_backend = Arc::new(FailOnNthPutFilesystem::new(backend.clone(), [4, 5]));
    let root: Arc<dyn RootFilesystem> = failing_backend;
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider_a = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!partial-provider-a:example.org".to_string(),
            subject_user_id: UserId::new("user:partial-provider-a").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@partial-provider-a:example.org")
                .expect("matrix sender"),
        }],
    };
    let provider_b = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-partial-other-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-partial-other-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!partial-provider-b:example.org".to_string(),
            subject_user_id: UserId::new("user:partial-provider-b").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@partial-provider-b:example.org")
                .expect("matrix sender"),
        }],
    };
    let scope = matrix_source_backed_scope();
    let provider_a_scope =
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider_a);
    let provider_a_path = matrix_policy_projection_cache_path_for_provider(&provider_a)
        .expect("provider a cache path");
    let provider_b_scope =
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider_b);
    let provider_b_path = matrix_policy_projection_cache_path_for_provider(&provider_b)
        .expect("provider b cache path");
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        root,
        store,
        vec![provider_a, provider_b],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("refresher config");

    refresher
        .refresh_after_lifecycle_activation(
            &scope,
            &ExtensionId::new("matrix-product-adapter").expect("extension id"),
        )
        .await
        .expect_err("second provider write fails");

    let scoped = crate::wrap_scoped(backend);
    let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
    let provider_a_source = FilesystemMatrixPolicySnapshotSource::new(
        Arc::clone(&scoped),
        provider_a_scope,
        provider_a_path,
    );
    let provider_b_source =
        FilesystemMatrixPolicySnapshotSource::new(scoped, provider_b_scope, provider_b_path);

    assert!(matches!(
        provider_a_source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err("provider a cache must be invalidated after partial failure"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    ));
    assert!(matches!(
        provider_b_source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err("provider b cache must not become authoritative after write failure"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    ));
}

#[tokio::test]
async fn matrix_lifecycle_refresher_partial_marker_publish_failure_stays_post_publish_only() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let failing_backend = Arc::new(FailOnNthPutFilesystem::new(backend.clone(), [6, 7]));
    let root: Arc<dyn RootFilesystem> = failing_backend;
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider_a = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!marker-provider-a:example.org".to_string(),
            subject_user_id: UserId::new("user:marker-provider-a").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@marker-provider-a:example.org")
                .expect("matrix sender"),
        }],
    };
    let provider_b = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-marker-other-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-marker-other-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!marker-provider-b:example.org".to_string(),
            subject_user_id: UserId::new("user:marker-provider-b").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@marker-provider-b:example.org")
                .expect("matrix sender"),
        }],
    };
    let scope = matrix_source_backed_scope();
    let provider_a_scope =
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider_a);
    let provider_a_path = matrix_policy_projection_cache_path_for_provider(&provider_a)
        .expect("provider a cache path");
    let provider_b_scope =
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider_b);
    let provider_b_path = matrix_policy_projection_cache_path_for_provider(&provider_b)
        .expect("provider b cache path");
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        root,
        store,
        vec![provider_a, provider_b],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("refresher config");
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");

    refresher
        .prepare_lifecycle_activation_refresh(&scope, &extension_id)
        .await
        .expect("prepare writes staged bodies under tombstoned markers");
    let error = refresher
        .publish_prepared_lifecycle_activation_refresh(&scope, &extension_id)
        .await
        .expect_err("second provider marker publish fails");
    let ProductWorkflowError::Transient { reason } = error else {
        panic!("expected marker write failure, got {error}");
    };
    assert!(
        reason.contains("test projection cache write failed"),
        "unexpected marker write failure: {reason}"
    );

    let scoped = crate::wrap_scoped(backend);
    let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
    let provider_a_source = FilesystemMatrixPolicySnapshotSource::new(
        Arc::clone(&scoped),
        provider_a_scope,
        provider_a_path,
    );
    let provider_b_source =
        FilesystemMatrixPolicySnapshotSource::new(scoped, provider_b_scope, provider_b_path);

    provider_a_source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("provider a marker was published before cleanup failed");
    assert!(matches!(
        provider_b_source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err("provider b marker must not become authoritative after write failure"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    ));
}

#[tokio::test]
async fn matrix_lifecycle_refresher_room_removal_tombstone_failure_fails_closed_for_stale_room() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider_with_stale_room = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![
            MatrixConfiguredRoomRoute {
                room_id: "!fresh-room-a:example.org".to_string(),
                subject_user_id: UserId::new("user:fresh-room-a").expect("actor a"),
                matrix_sender_user_id: MatrixUserId::new("@fresh-room-a:example.org")
                    .expect("matrix sender a"),
            },
            MatrixConfiguredRoomRoute {
                room_id: "!stale-room-b:example.org".to_string(),
                subject_user_id: UserId::new("user:stale-room-b").expect("actor b"),
                matrix_sender_user_id: MatrixUserId::new("@stale-room-b:example.org")
                    .expect("matrix sender b"),
            },
        ],
    };
    let provider_after_room_removal = MatrixOutboundTargetProviderConfig {
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!fresh-room-a:example.org".to_string(),
            subject_user_id: UserId::new("user:fresh-room-a").expect("actor a"),
            matrix_sender_user_id: MatrixUserId::new("@fresh-room-a:example.org")
                .expect("matrix sender a"),
        }],
        ..provider_with_stale_room.clone()
    };
    let initial_refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        backend.clone(),
        store.clone(),
        vec![provider_with_stale_room.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("initial refresher config");
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let policy_scope =
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider_with_stale_room);
    let cache_path = matrix_policy_projection_cache_path_for_provider(&provider_with_stale_room)
        .expect("cache path");
    let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");

    initial_refresher
        .refresh_after_lifecycle_activation(&scope, &extension_id)
        .await
        .expect("initial projection with rooms A and B");

    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend.clone()),
        policy_scope,
        cache_path,
    );
    let initial_snapshot = source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");
    assert!(
        initial_snapshot
            .allowed_rooms
            .iter()
            .any(|room| room.as_str() == "!stale-room-b:example.org"),
        "setup must publish stale room B before the removal refresh"
    );

    let failing_backend = Arc::new(FailOnNthPutFilesystem::new(backend, [1]));
    let removal_refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        failing_backend,
        store,
        vec![provider_after_room_removal],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("removal refresher config");
    removal_refresher
        .refresh_after_lifecycle_activation(&scope, &extension_id)
        .await
        .expect_err("room removal refresh cannot publish the invalidation tombstone");

    let rejection = source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect_err("failed room removal refresh must fail closed instead of serving stale room B");
    assert!(matches!(
        rejection,
        MatrixInstallationPolicyRejection::InstallationNotFound
    ));
}

#[tokio::test]
async fn matrix_lifecycle_refresher_removal_invalidates_provider_cache_namespace() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!remove-cache:example.org".to_string(),
            subject_user_id: UserId::new("user:remove-cache").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@remove-cache:example.org")
                .expect("matrix sender"),
        }],
    };
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        root,
        store.clone(),
        vec![provider.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("refresher config");
    let scope = matrix_source_backed_scope();
    let cache_path = matrix_policy_projection_cache_path_for_provider(&provider).expect("path");
    let policy_scope = matrix_policy_projection_resource_scope_for_provider(&scope, &provider);

    refresher
        .refresh_after_lifecycle_activation(
            &scope,
            &ExtensionId::new("matrix-product-adapter").expect("extension id"),
        )
        .await
        .expect("activation refresh");
    store
        .set_activation_state(
            &ExtensionInstallationId::new("matrix-source-backed-install").expect("installation id"),
            ExtensionActivationState::Disabled,
        )
        .await
        .expect("disable matrix installation");
    refresher
        .refresh_after_lifecycle_removal(
            &scope,
            &ExtensionId::new("matrix-product-adapter").expect("extension id"),
        )
        .await
        .expect("removal refresh");

    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend),
        policy_scope,
        cache_path,
    );
    let error = source
        .resolve_matrix_policy_snapshot(
            &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
            &installation_id,
        )
        .await
        .expect_err("removal invalidates provider cache");
    assert!(matches!(
        error,
        MatrixInstallationPolicyRejection::InstallationNotFound
    ));
}

#[tokio::test]
async fn matrix_product_auth_setup_rebind_preinvalidates_before_durable_mutation_and_publishes_new_handle()
 {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let (scope, provider, source, refresher, adapter_id, installation_id) =
        matrix_product_auth_lifecycle_fixture(root, store.clone(), backend.clone()).await;
    refresher
        .refresh_after_lifecycle_activation(&scope.resource, &matrix_product_adapter_extension_id())
        .await
        .expect("initial Matrix projection");
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("initial snapshot")
            .credential_handle,
        EgressCredentialHandle::new("matrix-source-access-token").expect("old handle")
    );

    let setup = Arc::new(RebindingCredentialSetupService::new(
        store,
        source.clone(),
        adapter_id.clone(),
        installation_id.clone(),
        "matrix-source-rotated-token",
    ));
    let product_auth =
        product_auth_with_ports(setup.clone(), Arc::new(InMemoryAuthProductServices::new()));
    product_auth.set_policy_projection_cache_refresher(refresher);

    product_auth
        .credential_setup_service()
        .create_or_update_account(CredentialAccountMutation::Update(
            ironclaw_auth::CredentialAccountUpdate {
                account_id: CredentialAccountId::new(),
                account: new_lifecycle_account(
                    scope.clone(),
                    "matrix-oauth",
                    CredentialAccountStatus::Configured,
                    Some(matrix_product_adapter_extension_id()),
                    Some("matrix-source-rotated-token"),
                ),
            },
        ))
        .await
        .expect("source-owner credential rebind mutation");

    assert!(
        setup.saw_preinvalidated_projection(),
        "Matrix projection must be pre-invalidated before durable credential rebind"
    );
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("rebound snapshot")
            .credential_handle,
        EgressCredentialHandle::new("matrix-source-rotated-token").expect("new handle")
    );
    assert_eq!(provider.installation_id, installation_id);
}

#[tokio::test]
async fn matrix_product_auth_revocation_preinvalidates_and_leaves_policy_snapshot_failed_closed() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let (scope, _provider, source, refresher, adapter_id, installation_id) =
        matrix_product_auth_lifecycle_fixture(root, store, backend).await;
    refresher
        .refresh_after_lifecycle_activation(&scope.resource, &matrix_product_adapter_extension_id())
        .await
        .expect("initial Matrix projection");
    source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");

    let account_id = CredentialAccountId::new();
    let account = credential_account_from_new(
        account_id,
        new_lifecycle_account(
            scope.clone(),
            "matrix-oauth",
            CredentialAccountStatus::Configured,
            Some(matrix_product_adapter_extension_id()),
            Some("matrix-source-access-token"),
        ),
    );
    let accounts = Arc::new(RevokingCredentialAccountService::new(
        account,
        source.clone(),
        adapter_id.clone(),
        installation_id.clone(),
    ));
    let product_auth = product_auth_with_ports(
        Arc::new(InMemoryAuthProductServices::new()),
        accounts.clone(),
    );
    product_auth.set_policy_projection_cache_refresher(refresher);

    product_auth
        .credential_account_service()
        .update_status(&scope, account_id, CredentialAccountStatus::Revoked)
        .await
        .expect("source-owner credential revocation");

    assert!(
        accounts.saw_preinvalidated_projection(),
        "Matrix projection must be pre-invalidated before durable credential revocation"
    );
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err("revoked Matrix credential must leave policy snapshot failed closed"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );
}

#[tokio::test]
async fn matrix_product_auth_create_account_preinvalidates_and_publishes_configured_extension_account()
 {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let (scope, _provider, source, refresher, adapter_id, installation_id) =
        matrix_product_auth_lifecycle_fixture(root, store, backend).await;
    refresher
        .refresh_after_lifecycle_activation(&scope.resource, &matrix_product_adapter_extension_id())
        .await
        .expect("initial Matrix projection");
    source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");

    let product_auth = product_auth_with_ports(
        Arc::new(PassthroughCredentialSetupService),
        Arc::new(InMemoryAuthProductServices::new()),
    );
    let counting_refresher = Arc::new(CountingLifecyclePolicyProjectionCacheRefresher::new(
        refresher,
    ));
    product_auth.set_policy_projection_cache_refresher(counting_refresher.clone());

    let account = product_auth
        .credential_account_service()
        .create_account(new_lifecycle_account(
            scope,
            "matrix-oauth",
            CredentialAccountStatus::Configured,
            Some(matrix_product_adapter_extension_id()),
            Some("matrix-source-access-token"),
        ))
        .await
        .expect("create configured extension-owned Matrix account through exposed service");

    assert_eq!(account.status, CredentialAccountStatus::Configured);
    assert_eq!(
        counting_refresher.invalidate_count(),
        1,
        "create_account must pre-invalidate extension-owned lifecycle credentials"
    );
    assert_eq!(counting_refresher.prepare_count(), 1);
    assert_eq!(counting_refresher.publish_count(), 1);
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("create_account publish restores Matrix projection")
            .credential_handle,
        EgressCredentialHandle::new("matrix-source-access-token").expect("matrix handle")
    );
}

#[tokio::test]
async fn matrix_product_auth_oauth_callback_provider_denied_lifecycle_preinvalidates_and_fails_closed()
 {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let (scope, _provider, source, refresher, adapter_id, installation_id) =
        matrix_product_auth_lifecycle_fixture(root, store, backend).await;
    refresher
        .refresh_after_lifecycle_activation(&scope.resource, &matrix_product_adapter_extension_id())
        .await
        .expect("initial Matrix projection");
    source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");

    let shared = Arc::new(InMemoryAuthProductServices::new());
    let product_auth = crate::RebornProductAuthServices::from_shared(
        shared.clone(),
        Arc::new(NoopMatrixAuthContinuationDispatcher),
    );
    product_auth.set_policy_projection_cache_refresher(refresher);
    let opaque_state_hash = matrix_test_state_hash("provider-denied");
    let flow = shared
        .create_flow(NewAuthFlow {
            id: None,
            scope: scope.clone(),
            kind: AuthFlowKind::IntegrationCredential,
            provider: AuthProviderId::new("matrix-oauth").expect("provider"),
            challenge: AuthChallenge::OAuthUrl {
                authorization_url: OAuthAuthorizationUrl::new("https://provider.example/oauth")
                    .expect("authorization url"),
                expires_at: Utc::now() + chrono::Duration::minutes(5),
            },
            continuation: AuthContinuationRef::LifecycleActivation {
                package_ref: LifecyclePackageRef::new(
                    matrix_product_adapter_extension_id().as_str(),
                )
                .expect("package ref"),
            },
            update_binding: None,
            opaque_state_hash: Some(opaque_state_hash.clone()),
            pkce_verifier_hash: None,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        })
        .await
        .expect("create lifecycle OAuth flow");

    let error = product_auth
        .handle_oauth_callback(crate::RebornOAuthCallbackRequest {
            scope,
            flow_id: flow.id,
            opaque_state_hash,
            outcome: crate::RebornOAuthCallbackOutcome::ProviderDenied,
        })
        .await
        .expect_err("provider denied lifecycle callback should fail");

    assert_eq!(error.code, ironclaw_auth::AuthErrorCode::ProviderDenied);
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err("ProviderDenied lifecycle callback must leave Matrix failed closed"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );
}

#[tokio::test]
async fn matrix_webui_setup_only_manual_token_submit_rebind_preinvalidates_and_publishes() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let (scope, _provider, source, refresher, adapter_id, installation_id) =
        matrix_product_auth_lifecycle_fixture(root, store, backend).await;
    refresher
        .refresh_after_lifecycle_activation(&scope.resource, &matrix_product_adapter_extension_id())
        .await
        .expect("initial Matrix projection");
    source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");

    let shared = Arc::new(InMemoryAuthProductServices::new());
    let existing = shared
        .create_account(new_lifecycle_account(
            scope.clone(),
            "matrix-oauth",
            CredentialAccountStatus::Configured,
            Some(matrix_product_adapter_extension_id()),
            Some("matrix-source-access-token"),
        ))
        .await
        .expect("seed extension-owned Matrix credential");
    let product_auth = Arc::new(crate::RebornProductAuthServices::from_shared(
        shared.clone(),
        Arc::new(NoopMatrixAuthContinuationDispatcher),
    ));
    let counting_refresher = Arc::new(CountingLifecyclePolicyProjectionCacheRefresher::new(
        refresher,
    ));
    product_auth.set_policy_projection_cache_refresher(counting_refresher.clone());
    let service =
            crate::extension_host::webui_extension_credentials::ProductAuthExtensionCredentialSetup::new(
                product_auth,
            );

    let rebound_account_id = service
        .submit_manual_token(ExtensionCredentialSubmitRequest {
            scope: scope.clone(),
            provider: AuthProviderId::new("matrix-oauth").expect("provider"),
            label: "matrix oauth account".to_string(),
            requester_extension: matrix_product_adapter_extension_id(),
            existing_account: Some(CredentialAccountUpdateBinding::from_projection(
                &existing.projection(),
            )),
            secret: SecretString::from("matrix-rotated-manual-token".to_string()),
        })
        .await
        .expect("webui SetupOnly manual-token rebind");

    assert_eq!(rebound_account_id, existing.id);
    assert_eq!(
        counting_refresher.invalidate_count(),
        1,
        "SetupOnly installed-extension manual submit must pre-invalidate Matrix"
    );
    assert_eq!(counting_refresher.prepare_count(), 1);
    assert_eq!(counting_refresher.publish_count(), 1);
    let stored = shared
        .get_account(
            CredentialAccountLookupRequest::new(scope, existing.id)
                .for_extension(matrix_product_adapter_extension_id()),
        )
        .await
        .expect("lookup rebound account")
        .expect("rebound account");
    assert_eq!(stored.status, CredentialAccountStatus::Configured);
    assert_ne!(
        stored.access_secret.as_ref().map(SecretHandle::as_str),
        Some("matrix-source-access-token")
    );
    assert!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .is_ok(),
        "post-submit publish should restore the Matrix projection"
    );
}

#[tokio::test]
async fn matrix_product_auth_refresh_provider_success_preinvalidates_and_publishes_rotated_handle()
{
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let (scope, _provider, source, refresher, adapter_id, installation_id) =
        matrix_product_auth_lifecycle_fixture(root, store.clone(), backend).await;
    refresher
        .refresh_after_lifecycle_activation(&scope.resource, &matrix_product_adapter_extension_id())
        .await
        .expect("initial Matrix projection");
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("initial snapshot")
            .credential_handle,
        EgressCredentialHandle::new("matrix-source-access-token").expect("old handle")
    );

    let shared = Arc::new(InMemoryAuthProductServices::new());
    let mut account = new_lifecycle_account(
        scope.clone(),
        "matrix-oauth",
        CredentialAccountStatus::Expired,
        Some(matrix_product_adapter_extension_id()),
        Some("matrix-source-access-token"),
    );
    account.refresh_secret =
        Some(SecretHandle::new("matrix-source-refresh-token").expect("refresh handle"));
    let account = shared
        .create_account(account)
        .await
        .expect("create extension-owned Matrix credential");
    let setup = Arc::new(MatrixRefreshCredentialSetupService::new(
        shared.clone(),
        store,
        source.clone(),
        adapter_id.clone(),
        installation_id.clone(),
    ));
    let provider_client: Arc<dyn AuthProviderClient> =
        Arc::new(FakeRefreshProviderClient::success(
            "matrix-oauth",
            "matrix-source-rotated-token",
            Some("matrix-source-rotated-refresh-token"),
        ));
    let product_auth = product_auth_refresh_facade(shared.clone(), setup.clone(), provider_client);
    let counting_refresher = Arc::new(CountingLifecyclePolicyProjectionCacheRefresher::new(
        refresher,
    ));
    product_auth.set_policy_projection_cache_refresher(counting_refresher.clone());

    let report = product_auth
        .refresh_credential_account(
            CredentialRefreshRequest::new(
                scope.clone(),
                AuthProviderId::new("matrix-oauth").expect("provider"),
                account.id,
            )
            .for_extension(matrix_product_adapter_extension_id()),
        )
        .await
        .expect("provider refresh succeeds through product-auth facade");

    assert!(report.refreshed);
    assert_eq!(report.account.status, CredentialAccountStatus::Configured);
    assert!(
        setup.saw_preinvalidated_projection(),
        "Matrix projection must be pre-invalidated before provider refresh persists the rotated handle"
    );
    assert_eq!(
        counting_refresher.invalidate_count(),
        2,
        "extension-owned provider refresh pre-invalidates before provider egress and before durable handle mutation"
    );
    assert_eq!(
        counting_refresher.prepare_count(),
        1,
        "extension-owned provider refresh prepare is owned by the lifecycle-aware setup wrapper"
    );
    assert_eq!(
        counting_refresher.publish_count(),
        1,
        "extension-owned provider refresh publish is owned by the lifecycle-aware setup wrapper"
    );
    let stored = shared
        .get_account(
            CredentialAccountLookupRequest::new(scope.clone(), account.id)
                .for_extension(matrix_product_adapter_extension_id()),
        )
        .await
        .expect("lookup refreshed account")
        .expect("refreshed account");
    assert_eq!(
        stored.access_secret.as_ref().map(SecretHandle::as_str),
        Some("matrix-source-rotated-token")
    );
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("refreshed Matrix snapshot")
            .credential_handle,
        EgressCredentialHandle::new("matrix-source-rotated-token").expect("new handle")
    );
}

#[tokio::test]
async fn matrix_product_auth_refresh_provider_invalid_grant_preinvalidates_and_fails_closed() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let (scope, _provider, source, refresher, adapter_id, installation_id) =
        matrix_product_auth_lifecycle_fixture(root, store.clone(), backend).await;
    refresher
        .refresh_after_lifecycle_activation(&scope.resource, &matrix_product_adapter_extension_id())
        .await
        .expect("initial Matrix projection");
    source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");

    let shared = Arc::new(InMemoryAuthProductServices::new());
    let mut account = new_lifecycle_account(
        scope.clone(),
        "matrix-oauth",
        CredentialAccountStatus::Expired,
        Some(matrix_product_adapter_extension_id()),
        Some("matrix-source-access-token"),
    );
    account.refresh_secret =
        Some(SecretHandle::new("matrix-source-refresh-token").expect("refresh handle"));
    let account = shared
        .create_account(account)
        .await
        .expect("create extension-owned Matrix credential");
    let setup = Arc::new(MatrixRefreshCredentialSetupService::new(
        shared.clone(),
        store,
        source.clone(),
        adapter_id.clone(),
        installation_id.clone(),
    ));
    let provider_client: Arc<dyn AuthProviderClient> =
        Arc::new(FakeRefreshProviderClient::invalid_grant());
    let product_auth = product_auth_refresh_facade(shared.clone(), setup.clone(), provider_client);
    let counting_refresher = Arc::new(CountingLifecyclePolicyProjectionCacheRefresher::new(
        refresher,
    ));
    product_auth.set_policy_projection_cache_refresher(counting_refresher.clone());

    let report = product_auth
        .refresh_credential_account(
            CredentialRefreshRequest::new(
                scope.clone(),
                AuthProviderId::new("matrix-oauth").expect("provider"),
                account.id,
            )
            .for_extension(matrix_product_adapter_extension_id()),
        )
        .await
        .expect("invalid_grant terminalizes through product-auth facade");

    assert!(!report.refreshed);
    assert_eq!(report.account.status, CredentialAccountStatus::Revoked);
    assert!(
        setup.saw_preinvalidated_projection(),
        "Matrix projection must be pre-invalidated before invalid_grant revokes the credential"
    );
    assert_eq!(
        counting_refresher.invalidate_count(),
        2,
        "invalid_grant refresh pre-invalidates before provider egress and before durable revocation"
    );
    assert_eq!(
        counting_refresher.prepare_count(),
        0,
        "revoked invalid_grant refresh must not publish a configured lifecycle projection"
    );
    assert_eq!(
        counting_refresher.publish_count(),
        0,
        "revoked invalid_grant refresh must remain failed closed"
    );
    let stored = shared
        .get_account(
            CredentialAccountLookupRequest::new(scope, account.id)
                .for_extension(matrix_product_adapter_extension_id()),
        )
        .await
        .expect("lookup revoked account")
        .expect("revoked account");
    assert_eq!(stored.status, CredentialAccountStatus::Revoked);
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err("invalid_grant must leave Matrix policy snapshot failed closed"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );
}

#[tokio::test]
async fn matrix_product_auth_refresh_provider_backend_unavailable_preinvalidates_and_fails_closed()
{
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let (scope, _provider, source, refresher, adapter_id, installation_id) =
        matrix_product_auth_lifecycle_fixture(root, store.clone(), backend).await;
    refresher
        .refresh_after_lifecycle_activation(&scope.resource, &matrix_product_adapter_extension_id())
        .await
        .expect("initial Matrix projection");
    source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");

    let shared = Arc::new(InMemoryAuthProductServices::new());
    let mut account = new_lifecycle_account(
        scope.clone(),
        "matrix-oauth",
        CredentialAccountStatus::Expired,
        Some(matrix_product_adapter_extension_id()),
        Some("matrix-source-access-token"),
    );
    account.refresh_secret =
        Some(SecretHandle::new("matrix-source-refresh-token").expect("refresh handle"));
    let account = shared
        .create_account(account)
        .await
        .expect("create extension-owned Matrix credential");
    let setup = Arc::new(MatrixRefreshCredentialSetupService::new(
        shared.clone(),
        store,
        source.clone(),
        adapter_id.clone(),
        installation_id.clone(),
    ));
    let provider_client: Arc<dyn AuthProviderClient> =
        Arc::new(FakeRefreshProviderClient::backend_unavailable());
    let product_auth = product_auth_refresh_facade(shared.clone(), setup.clone(), provider_client);
    let counting_refresher = Arc::new(CountingLifecyclePolicyProjectionCacheRefresher::new(
        refresher,
    ));
    product_auth.set_policy_projection_cache_refresher(counting_refresher.clone());

    let error = product_auth
        .refresh_credential_account(
            CredentialRefreshRequest::new(
                scope,
                AuthProviderId::new("matrix-oauth").expect("provider"),
                account.id,
            )
            .for_extension(matrix_product_adapter_extension_id()),
        )
        .await
        .expect_err("backend outage must fail before durable refresh mutation");

    assert_eq!(error.code, ironclaw_auth::AuthErrorCode::BackendUnavailable);
    assert!(
        !setup.saw_preinvalidated_projection(),
        "provider outage must not reach the setup wrapper"
    );
    assert_eq!(
        counting_refresher.invalidate_count(),
        1,
        "extension-owned provider refresh must pre-invalidate before provider egress"
    );
    assert_eq!(counting_refresher.prepare_count(), 0);
    assert_eq!(counting_refresher.publish_count(), 0);
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err("provider outage must leave Matrix policy snapshot failed closed"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );
}

#[tokio::test]
async fn matrix_product_auth_cleanup_preinvalidates_and_leaves_policy_snapshot_failed_closed() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let (scope, _provider, source, refresher, adapter_id, installation_id) =
        matrix_product_auth_lifecycle_fixture(root, store, backend).await;
    refresher
        .refresh_after_lifecycle_activation(&scope.resource, &matrix_product_adapter_extension_id())
        .await
        .expect("initial Matrix projection");
    source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");

    let shared = Arc::new(InMemoryAuthProductServices::new());
    let account = shared
        .create_account(new_lifecycle_account(
            scope.clone(),
            "matrix-oauth",
            CredentialAccountStatus::Configured,
            Some(matrix_product_adapter_extension_id()),
            Some("matrix-source-access-token"),
        ))
        .await
        .expect("create Matrix lifecycle-owned credential");
    let product_auth = crate::RebornProductAuthServices::from_shared(
        shared.clone(),
        Arc::new(NoopMatrixAuthContinuationDispatcher),
    );
    product_auth.set_policy_projection_cache_refresher(refresher);

    let report = product_auth
        .cleanup_credentials_for_lifecycle(SecretCleanupRequest {
            scope: scope.clone(),
            extension_id: matrix_product_adapter_extension_id(),
            provider: None,
            action: SecretCleanupAction::Uninstall,
        })
        .await
        .expect("Matrix credential cleanup through product-auth facade");

    assert_eq!(report.revoked_accounts, vec![account.id]);
    let cleaned = shared
        .get_account(
            CredentialAccountLookupRequest::new(scope, account.id)
                .for_extension(matrix_product_adapter_extension_id()),
        )
        .await
        .expect("load cleaned account")
        .expect("cleaned account remains as revoked metadata");
    assert_eq!(cleaned.status, CredentialAccountStatus::Revoked);
    assert!(cleaned.access_secret.is_none());
    assert!(cleaned.refresh_secret.is_none());
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err("cleanup must leave Matrix policy snapshot failed closed"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );
}

#[tokio::test]
async fn non_matrix_product_auth_setup_mutation_leaves_matrix_projection_body_and_marker_unchanged()
{
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let (scope, provider, source, refresher, adapter_id, installation_id) =
        matrix_product_auth_lifecycle_fixture(root, store, backend.clone()).await;
    refresher
        .refresh_after_lifecycle_activation(&scope.resource, &matrix_product_adapter_extension_id())
        .await
        .expect("initial Matrix projection");
    let policy_scope =
        matrix_policy_projection_resource_scope_for_provider(&scope.resource, &provider);
    let cache_path = matrix_policy_projection_cache_path_for_provider(&provider).expect("path");
    let marker_path = matrix_policy_projection_commit_marker_path_for_cache_path(&cache_path)
        .expect("marker path");
    let scoped = crate::wrap_scoped(backend);
    let initial_body = scoped
        .get(&policy_scope, &cache_path)
        .await
        .expect("initial body lookup")
        .expect("initial body")
        .entry
        .body;
    let initial_marker = scoped
        .get(&policy_scope, &marker_path)
        .await
        .expect("initial marker lookup")
        .expect("initial marker")
        .entry
        .body;

    let product_auth = product_auth_with_ports(
        Arc::new(PassthroughCredentialSetupService),
        Arc::new(InMemoryAuthProductServices::new()),
    );
    product_auth.set_policy_projection_cache_refresher(refresher);
    product_auth
        .credential_setup_service()
        .create_or_update_account(CredentialAccountMutation::Update(
            ironclaw_auth::CredentialAccountUpdate {
                account_id: CredentialAccountId::new(),
                account: new_lifecycle_account(
                    scope.clone(),
                    "github",
                    CredentialAccountStatus::Configured,
                    Some(ExtensionId::new("github").expect("extension")),
                    Some("github-rotated-token"),
                ),
            },
        ))
        .await
        .expect("non-Matrix credential mutation");

    assert_eq!(
        scoped
            .get(&policy_scope, &cache_path)
            .await
            .expect("body lookup")
            .expect("body")
            .entry
            .body,
        initial_body
    );
    assert_eq!(
        scoped
            .get(&policy_scope, &marker_path)
            .await
            .expect("marker lookup")
            .expect("marker")
            .entry
            .body,
        initial_marker
    );
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("Matrix projection remains authoritative")
            .credential_handle,
        EgressCredentialHandle::new("matrix-source-access-token").expect("matrix handle")
    );
}

#[tokio::test]
async fn non_matrix_product_auth_cleanup_leaves_matrix_projection_body_and_marker_unchanged() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let (scope, provider, source, refresher, adapter_id, installation_id) =
        matrix_product_auth_lifecycle_fixture(root, store, backend.clone()).await;
    refresher
        .refresh_after_lifecycle_activation(&scope.resource, &matrix_product_adapter_extension_id())
        .await
        .expect("initial Matrix projection");
    let policy_scope =
        matrix_policy_projection_resource_scope_for_provider(&scope.resource, &provider);
    let cache_path = matrix_policy_projection_cache_path_for_provider(&provider).expect("path");
    let marker_path = matrix_policy_projection_commit_marker_path_for_cache_path(&cache_path)
        .expect("marker path");
    let scoped = crate::wrap_scoped(backend);
    let initial_body = scoped
        .get(&policy_scope, &cache_path)
        .await
        .expect("initial body lookup")
        .expect("initial body")
        .entry
        .body;
    let initial_marker = scoped
        .get(&policy_scope, &marker_path)
        .await
        .expect("initial marker lookup")
        .expect("initial marker")
        .entry
        .body;

    let shared = Arc::new(InMemoryAuthProductServices::new());
    let github_extension = ExtensionId::new("github").expect("extension");
    let account = shared
        .create_account(new_lifecycle_account(
            scope.clone(),
            "github",
            CredentialAccountStatus::Configured,
            Some(github_extension.clone()),
            Some("github-access-token"),
        ))
        .await
        .expect("create non-Matrix lifecycle-owned credential");
    let product_auth = crate::RebornProductAuthServices::from_shared(
        shared.clone(),
        Arc::new(NoopMatrixAuthContinuationDispatcher),
    );
    product_auth.set_policy_projection_cache_refresher(refresher);

    let report = product_auth
        .cleanup_credentials_for_lifecycle(SecretCleanupRequest {
            scope: scope.clone(),
            extension_id: github_extension,
            provider: None,
            action: SecretCleanupAction::Uninstall,
        })
        .await
        .expect("non-Matrix credential cleanup through product-auth facade");

    assert_eq!(report.revoked_accounts, vec![account.id]);
    assert_eq!(
        scoped
            .get(&policy_scope, &cache_path)
            .await
            .expect("body lookup")
            .expect("body")
            .entry
            .body,
        initial_body
    );
    assert_eq!(
        scoped
            .get(&policy_scope, &marker_path)
            .await
            .expect("marker lookup")
            .expect("marker")
            .entry
            .body,
        initial_marker
    );
    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("Matrix projection remains authoritative")
            .credential_handle,
        EgressCredentialHandle::new("matrix-source-access-token").expect("matrix handle")
    );
}

#[tokio::test]
async fn matrix_credential_handle_rebind_invalidates_provider_projection_before_refresh() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!credential-rebind:example.org".to_string(),
            subject_user_id: UserId::new("user:credential-rebind").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@credential-rebind:example.org")
                .expect("matrix sender"),
        }],
    };
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        Arc::clone(&root),
        store.clone(),
        vec![provider.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("refresher config");
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
    );

    refresher
        .refresh_after_lifecycle_activation(&scope, &extension_id)
        .await
        .expect("initial projection");
    let initial_snapshot = source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");
    assert_eq!(
        initial_snapshot.credential_handle,
        EgressCredentialHandle::new("matrix-source-access-token").expect("old handle")
    );

    refresher
        .invalidate_before_credential_lifecycle_mutation(&scope, &extension_id)
        .await
        .expect("pre-invalidate before source-owner credential handle rebind");
    store
        .upsert_manifest(matrix_runtime_manifest_record_with_credential(
            "matrix-source-rotated-token",
        ))
        .await
        .expect("source-owner credential handle rebind");

    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err("credential rebind must pre-invalidate the stale committed projection"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );

    refresher
        .refresh_after_lifecycle_activation(&scope, &extension_id)
        .await
        .expect("refresh after credential handle rebind");
    let rebound_snapshot = source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("refreshed rebound snapshot");
    assert_eq!(
        rebound_snapshot.credential_handle,
        EgressCredentialHandle::new("matrix-source-rotated-token").expect("new handle")
    );
}

#[tokio::test]
async fn matrix_credential_revocation_invalidates_provider_projection_and_retry_fails_closed() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!credential-revocation:example.org".to_string(),
            subject_user_id: UserId::new("user:credential-revocation").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@credential-revocation:example.org")
                .expect("matrix sender"),
        }],
    };
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        root,
        store.clone(),
        vec![provider.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("refresher config");
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend),
        matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
    );

    refresher
        .refresh_after_lifecycle_activation(&scope, &extension_id)
        .await
        .expect("initial projection");
    source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");

    refresher
        .invalidate_before_credential_lifecycle_mutation(&scope, &extension_id)
        .await
        .expect("pre-invalidate before source-owner credential revocation");
    store
        .set_activation_state(
            &ExtensionInstallationId::new("matrix-source-backed-install").expect("installation id"),
            ExtensionActivationState::Disabled,
        )
        .await
        .expect("source-owner credential revocation disables installation");

    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err(
                "source-owner revocation must invalidate the projection before retry delivery",
            ),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );
}

#[tokio::test]
async fn matrix_credential_refresh_body_write_failure_removes_stale_credential_body() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!credential-refresh-failure:example.org".to_string(),
            subject_user_id: UserId::new("user:credential-refresh-failure").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@credential-refresh-failure:example.org")
                .expect("matrix sender"),
        }],
    };
    let initial_refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        root,
        store.clone(),
        vec![provider.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("initial refresher config");
    let scope = matrix_source_backed_scope();
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
    let policy_scope = matrix_policy_projection_resource_scope_for_provider(&scope, &provider);
    let cache_path = matrix_policy_projection_cache_path_for_provider(&provider).expect("path");
    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend.clone()),
        policy_scope.clone(),
        cache_path.clone(),
    );

    initial_refresher
        .refresh_after_lifecycle_activation(&scope, &extension_id)
        .await
        .expect("initial projection");
    let initial_snapshot = source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("initial snapshot");
    assert_eq!(
        initial_snapshot.credential_handle,
        EgressCredentialHandle::new("matrix-source-access-token").expect("old handle")
    );

    initial_refresher
        .invalidate_before_credential_lifecycle_mutation(&scope, &extension_id)
        .await
        .expect("pre-invalidate before source-owner credential handle rebind");
    store
        .upsert_manifest(matrix_runtime_manifest_record_with_credential(
            "matrix-source-rotated-token",
        ))
        .await
        .expect("source-owner credential handle rebind");

    let failing_backend = Arc::new(FailOnNthPutFilesystem::new(backend.clone(), [2]));
    let failing_refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        failing_backend,
        store,
        vec![provider.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("failing refresher config");
    failing_refresher
        .refresh_after_lifecycle_activation(&scope, &extension_id)
        .await
        .expect_err("credential refresh body write fails");

    assert_eq!(
        source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err("failed credential refresh must fail closed"),
        MatrixInstallationPolicyRejection::InstallationNotFound
    );

    let scoped = crate::wrap_scoped(backend);
    let body = scoped
        .get(&policy_scope, &cache_path)
        .await
        .expect("cache body lookup")
        .expect("cache body entry")
        .entry
        .body;
    let body_text = String::from_utf8_lossy(&body);
    assert!(
        !body_text.contains("matrix-source-access-token"),
        "failed credential refresh must not leave the stale credential cache body"
    );
}

#[tokio::test]
async fn non_matrix_credential_installation_mutation_does_not_touch_matrix_projection_cache() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!non-matrix-mutation:example.org".to_string(),
            subject_user_id: UserId::new("user:non-matrix-mutation").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@non-matrix-mutation:example.org")
                .expect("matrix sender"),
        }],
    };
    let initial_refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        root,
        store.clone(),
        vec![provider.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("initial refresher config");
    let scope = matrix_source_backed_scope();
    let matrix_extension_id =
        ExtensionId::new("matrix-product-adapter").expect("matrix extension id");
    let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
    let policy_scope = matrix_policy_projection_resource_scope_for_provider(&scope, &provider);
    let cache_path = matrix_policy_projection_cache_path_for_provider(&provider).expect("path");
    let marker_path =
        matrix_policy_projection_commit_marker_path_for_cache_path(&cache_path).expect("marker");

    initial_refresher
        .refresh_after_lifecycle_activation(&scope, &matrix_extension_id)
        .await
        .expect("initial projection");
    let scoped = crate::wrap_scoped(backend.clone());
    let initial_body = scoped
        .get(&policy_scope, &cache_path)
        .await
        .expect("initial body lookup")
        .expect("initial body")
        .entry
        .body;
    let initial_marker = scoped
        .get(&policy_scope, &marker_path)
        .await
        .expect("initial marker lookup")
        .expect("initial marker")
        .entry
        .body;

    let non_matrix_extension_id = ExtensionId::new("github").expect("non-matrix extension id");
    store
        .upsert_manifest(non_matrix_runtime_manifest_record_with_credential(
            "github-access-token",
        ))
        .await
        .expect("upsert unrelated credential manifest");
    store
        .upsert_installation(
            ExtensionInstallation::new(
                ExtensionInstallationId::new("github-source-backed-install")
                    .expect("non-matrix installation id"),
                non_matrix_extension_id.clone(),
                ExtensionActivationState::Enabled,
                ExtensionManifestRef::new(
                    non_matrix_extension_id.clone(),
                    Some(ManifestHash::new("sha256:non-matrix-source-backed").expect("hash")),
                ),
                Vec::new(),
                chrono::Utc::now(),
                InstallationOwner::Tenant,
            )
            .expect("non-matrix installation"),
        )
        .await
        .expect("upsert unrelated installation");
    store
        .upsert_manifest(non_matrix_runtime_manifest_record_with_credential(
            "github-rotated-token",
        ))
        .await
        .expect("rotate unrelated credential manifest");

    let fail_on_write_backend = Arc::new(FailOnNthPutFilesystem::new(backend.clone(), [1]));
    let unrelated_refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        fail_on_write_backend,
        store,
        vec![provider.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("unrelated refresher config");
    unrelated_refresher
        .refresh_after_lifecycle_activation(&scope, &non_matrix_extension_id)
        .await
        .expect("unrelated lifecycle refresh must not write Matrix projection cache");

    assert_eq!(
        scoped
            .get(&policy_scope, &cache_path)
            .await
            .expect("body lookup after unrelated mutation")
            .expect("body after unrelated mutation")
            .entry
            .body,
        initial_body
    );
    assert_eq!(
        scoped
            .get(&policy_scope, &marker_path)
            .await
            .expect("marker lookup after unrelated mutation")
            .expect("marker after unrelated mutation")
            .entry
            .body,
        initial_marker
    );

    let source = FilesystemMatrixPolicySnapshotSource::new(scoped, policy_scope, cache_path);
    let snapshot = source
        .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
        .await
        .expect("Matrix projection remains readable after unrelated mutation");
    assert_eq!(
        snapshot.credential_handle,
        EgressCredentialHandle::new("matrix-source-access-token").expect("matrix handle")
    );
}

#[tokio::test]
async fn matrix_lifecycle_refresher_ignores_unrelated_extension_lifecycle() {
    let store = Arc::new(InMemoryExtensionInstallationStore::default());
    seed_enabled_matrix_runtime_entry(store.as_ref()).await;
    let backend = Arc::new(InMemoryBackend::default());
    let root: Arc<dyn RootFilesystem> = backend.clone();
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id,
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!unrelated:example.org".to_string(),
            subject_user_id: UserId::new("user:unrelated").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@unrelated:example.org")
                .expect("matrix sender"),
        }],
    };
    let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
        root,
        store,
        vec![provider.clone()],
        matrix_source_backed_artifact_evidence(),
        "matrix-source-backed-policy-owner".to_string(),
    )
    .expect("refresher config");
    let scope = matrix_source_backed_scope();

    refresher
        .refresh_after_lifecycle_activation(
            &scope,
            &ExtensionId::new("github").expect("extension id"),
        )
        .await
        .expect("unrelated extension refresh is ignored");

    let scoped = crate::wrap_scoped(backend);
    let missing = scoped
        .get(
            &matrix_policy_projection_resource_scope(&scope),
            &matrix_policy_projection_cache_path_for_provider(&provider).expect("path"),
        )
        .await
        .expect("cache lookup");
    assert!(missing.is_none());
}

async fn seed_enabled_matrix_runtime_entry(store: &InMemoryExtensionInstallationStore) {
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    store
        .upsert_manifest(matrix_runtime_manifest_record())
        .await
        .expect("upsert manifest");
    store
        .upsert_installation(
            ExtensionInstallation::new(
                ExtensionInstallationId::new("matrix-source-backed-install")
                    .expect("installation id"),
                extension_id.clone(),
                ExtensionActivationState::Enabled,
                ExtensionManifestRef::new(
                    extension_id,
                    Some(ManifestHash::new("sha256:matrix-source-backed").expect("hash")),
                ),
                Vec::new(),
                chrono::Utc::now(),
                InstallationOwner::Tenant,
            )
            .expect("installation"),
        )
        .await
        .expect("upsert installation");
}

type MatrixLifecycleFixture = (
    AuthProductScope,
    MatrixOutboundTargetProviderConfig,
    Arc<FilesystemMatrixPolicySnapshotSource<InMemoryBackend>>,
    Arc<MatrixLifecyclePolicyProjectionCacheRefresher>,
    ProductAdapterId,
    AdapterInstallationId,
);

async fn matrix_product_auth_lifecycle_fixture(
    root: Arc<dyn RootFilesystem>,
    store: Arc<InMemoryExtensionInstallationStore>,
    backend: Arc<InMemoryBackend>,
) -> MatrixLifecycleFixture {
    let installation_id =
        AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
    let provider = MatrixOutboundTargetProviderConfig {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        installation_id: installation_id.clone(),
        configured_room_routes: vec![MatrixConfiguredRoomRoute {
            room_id: "!product-auth-lifecycle:example.org".to_string(),
            subject_user_id: UserId::new("user:product-auth-lifecycle").expect("actor"),
            matrix_sender_user_id: MatrixUserId::new("@product-auth-lifecycle:example.org")
                .expect("matrix sender"),
        }],
    };
    let scope = AuthProductScope::new(matrix_source_backed_scope(), AuthSurface::Api);
    let source = Arc::new(FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(backend),
        matrix_policy_projection_resource_scope_for_provider(&scope.resource, &provider),
        matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
    ));
    let refresher = Arc::new(
        MatrixLifecyclePolicyProjectionCacheRefresher::new(
            root,
            store,
            vec![provider.clone()],
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("refresher config"),
    );
    (
        scope,
        provider,
        source,
        refresher,
        ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
        installation_id,
    )
}

fn product_auth_with_ports(
    setup: Arc<dyn CredentialSetupService>,
    accounts: Arc<dyn CredentialAccountService>,
) -> crate::RebornProductAuthServices {
    let shared = Arc::new(InMemoryAuthProductServices::new());
    crate::RebornProductAuthServices::new(
        shared.clone(),
        shared.clone(),
        setup,
        accounts,
        shared.clone(),
        shared,
        Arc::new(NoopMatrixAuthContinuationDispatcher),
    )
}

fn product_auth_refresh_facade(
    shared: Arc<InMemoryAuthProductServices>,
    setup: Arc<dyn CredentialSetupService>,
    provider_client: Arc<dyn AuthProviderClient>,
) -> crate::RebornProductAuthServices {
    let flow_manager: Arc<dyn AuthFlowManager> = shared.clone();
    let interaction_service: Arc<dyn AuthInteractionService> = shared.clone();
    let credential_account_service: Arc<dyn CredentialAccountService> = shared.clone();
    let cleanup_service: Arc<dyn SecretCleanupService> = shared;
    crate::RebornProductAuthServicePorts::new(
        flow_manager,
        interaction_service,
        setup,
        credential_account_service,
        provider_client.clone(),
        cleanup_service,
    )
    .into_services(
        Arc::new(NoopMatrixAuthContinuationDispatcher),
        Arc::new(InMemorySecretStore::new()),
    )
    .with_provider_client(provider_client)
}

struct CountingLifecyclePolicyProjectionCacheRefresher {
    inner: Arc<dyn LifecyclePolicyProjectionCacheRefresher>,
    invalidates: AtomicUsize,
    prepares: AtomicUsize,
    publishes: AtomicUsize,
    removals: AtomicUsize,
}

impl CountingLifecyclePolicyProjectionCacheRefresher {
    fn new(inner: Arc<dyn LifecyclePolicyProjectionCacheRefresher>) -> Self {
        Self {
            inner,
            invalidates: AtomicUsize::new(0),
            prepares: AtomicUsize::new(0),
            publishes: AtomicUsize::new(0),
            removals: AtomicUsize::new(0),
        }
    }

    fn invalidate_count(&self) -> usize {
        self.invalidates.load(Ordering::SeqCst)
    }

    fn prepare_count(&self) -> usize {
        self.prepares.load(Ordering::SeqCst)
    }

    fn publish_count(&self) -> usize {
        self.publishes.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl LifecyclePolicyProjectionCacheRefresher for CountingLifecyclePolicyProjectionCacheRefresher {
    async fn invalidate_before_credential_lifecycle_mutation(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ironclaw_product_workflow::ProductWorkflowError> {
        self.invalidates.fetch_add(1, Ordering::SeqCst);
        self.inner
            .invalidate_before_credential_lifecycle_mutation(scope, extension_id)
            .await
    }

    async fn invalidate_before_manifest_lifecycle_mutation(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ironclaw_product_workflow::ProductWorkflowError> {
        self.invalidates.fetch_add(1, Ordering::SeqCst);
        self.inner
            .invalidate_before_manifest_lifecycle_mutation(scope, extension_id)
            .await
    }

    async fn publish_after_manifest_lifecycle_mutation(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ironclaw_product_workflow::ProductWorkflowError> {
        self.publishes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .publish_after_manifest_lifecycle_mutation(scope, extension_id)
            .await
    }

    async fn prepare_lifecycle_activation_refresh(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ironclaw_product_workflow::ProductWorkflowError> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        self.inner
            .prepare_lifecycle_activation_refresh(scope, extension_id)
            .await
    }

    async fn publish_prepared_lifecycle_activation_refresh(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ironclaw_product_workflow::ProductWorkflowError> {
        self.publishes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .publish_prepared_lifecycle_activation_refresh(scope, extension_id)
            .await
    }

    async fn refresh_after_lifecycle_removal(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ironclaw_product_workflow::ProductWorkflowError> {
        self.removals.fetch_add(1, Ordering::SeqCst);
        self.inner
            .refresh_after_lifecycle_removal(scope, extension_id)
            .await
    }
}

struct NoopMatrixAuthContinuationDispatcher;

#[async_trait]
impl crate::RebornAuthContinuationDispatcher for NoopMatrixAuthContinuationDispatcher {
    async fn dispatch_auth_continuation(
        &self,
        _event: ironclaw_auth::AuthContinuationEvent,
    ) -> Result<(), AuthProductError> {
        Ok(())
    }

    async fn dispatch_canceled_auth_continuation(
        &self,
        _event: ironclaw_auth::AuthContinuationEvent,
    ) -> Result<(), AuthProductError> {
        Ok(())
    }
}

fn matrix_product_adapter_extension_id() -> ExtensionId {
    ExtensionId::new("matrix-product-adapter").expect("matrix extension")
}

fn matrix_test_state_hash(value: &str) -> OpaqueStateHash {
    OpaqueStateHash::new(format!(
        "{:064x}",
        value.bytes().fold(0_u64, |hash, byte| {
            hash.wrapping_mul(31).wrapping_add(u64::from(byte))
        })
    ))
    .expect("state hash")
}

fn new_lifecycle_account(
    scope: AuthProductScope,
    provider: &str,
    status: CredentialAccountStatus,
    owner_extension: Option<ExtensionId>,
    access_secret: Option<&str>,
) -> NewCredentialAccount {
    NewCredentialAccount {
        scope,
        provider: AuthProviderId::new(provider).expect("provider"),
        label: CredentialAccountLabel::new(format!("{provider} account")).expect("label"),
        status,
        ownership: if owner_extension.is_some() {
            CredentialOwnership::ExtensionOwned
        } else {
            CredentialOwnership::UserReusable
        },
        owner_extension,
        granted_extensions: Vec::new(),
        access_secret: access_secret
            .map(|handle| SecretHandle::new(handle).expect("secret handle")),
        refresh_secret: None,
        scopes: Vec::new(),
    }
}

fn credential_account_from_new(
    id: CredentialAccountId,
    account: NewCredentialAccount,
) -> CredentialAccount {
    let now = Utc::now();
    CredentialAccount {
        id,
        scope: account.scope,
        provider: account.provider,
        label: account.label,
        status: account.status,
        ownership: account.ownership,
        owner_extension: account.owner_extension,
        granted_extensions: account.granted_extensions,
        access_secret: account.access_secret,
        refresh_secret: account.refresh_secret,
        scopes: account.scopes,
        provider_identity: None,
        created_at: now,
        updated_at: now,
    }
}

struct RebindingCredentialSetupService {
    store: Arc<InMemoryExtensionInstallationStore>,
    source: Arc<dyn MatrixPolicySnapshotSource>,
    adapter_id: ProductAdapterId,
    installation_id: AdapterInstallationId,
    new_handle: String,
    saw_preinvalidated_projection: AtomicBool,
}

impl RebindingCredentialSetupService {
    fn new(
        store: Arc<InMemoryExtensionInstallationStore>,
        source: Arc<dyn MatrixPolicySnapshotSource>,
        adapter_id: ProductAdapterId,
        installation_id: AdapterInstallationId,
        new_handle: &str,
    ) -> Self {
        Self {
            store,
            source,
            adapter_id,
            installation_id,
            new_handle: new_handle.to_string(),
            saw_preinvalidated_projection: AtomicBool::new(false),
        }
    }

    fn saw_preinvalidated_projection(&self) -> bool {
        self.saw_preinvalidated_projection.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl CredentialSetupService for RebindingCredentialSetupService {
    async fn create_or_update_account(
        &self,
        request: CredentialAccountMutation,
    ) -> Result<CredentialAccount, AuthProductError> {
        if self
            .source
            .resolve_matrix_policy_snapshot(&self.adapter_id, &self.installation_id)
            .await
            .is_err()
        {
            self.saw_preinvalidated_projection
                .store(true, Ordering::SeqCst);
        }
        self.store
            .upsert_manifest(matrix_runtime_manifest_record_with_credential(
                &self.new_handle,
            ))
            .await
            .map_err(|_| AuthProductError::BackendUnavailable)?;
        let (account_id, account) = match request {
            CredentialAccountMutation::Create(account) => (CredentialAccountId::new(), account),
            CredentialAccountMutation::Update(update) => (update.account_id, update.account),
        };
        Ok(credential_account_from_new(account_id, account))
    }
}

struct MatrixRefreshCredentialSetupService {
    inner: Arc<InMemoryAuthProductServices>,
    store: Arc<InMemoryExtensionInstallationStore>,
    source: Arc<dyn MatrixPolicySnapshotSource>,
    adapter_id: ProductAdapterId,
    installation_id: AdapterInstallationId,
    saw_preinvalidated_projection: AtomicBool,
}

impl MatrixRefreshCredentialSetupService {
    fn new(
        inner: Arc<InMemoryAuthProductServices>,
        store: Arc<InMemoryExtensionInstallationStore>,
        source: Arc<dyn MatrixPolicySnapshotSource>,
        adapter_id: ProductAdapterId,
        installation_id: AdapterInstallationId,
    ) -> Self {
        Self {
            inner,
            store,
            source,
            adapter_id,
            installation_id,
            saw_preinvalidated_projection: AtomicBool::new(false),
        }
    }

    fn saw_preinvalidated_projection(&self) -> bool {
        self.saw_preinvalidated_projection.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl CredentialSetupService for MatrixRefreshCredentialSetupService {
    async fn create_or_update_account(
        &self,
        request: CredentialAccountMutation,
    ) -> Result<CredentialAccount, AuthProductError> {
        if self
            .source
            .resolve_matrix_policy_snapshot(&self.adapter_id, &self.installation_id)
            .await
            .is_err()
        {
            self.saw_preinvalidated_projection
                .store(true, Ordering::SeqCst);
        }
        let account = match &request {
            CredentialAccountMutation::Create(account) => account,
            CredentialAccountMutation::Update(update) => &update.account,
        };
        if account.status == CredentialAccountStatus::Configured
            && account
                .owner_extension
                .as_ref()
                .is_some_and(|extension_id| extension_id == &matrix_product_adapter_extension_id())
            && let Some(access_secret) = account.access_secret.as_ref()
        {
            self.store
                .upsert_manifest(matrix_runtime_manifest_record_with_credential(
                    access_secret.as_str(),
                ))
                .await
                .map_err(|_| AuthProductError::BackendUnavailable)?;
        }
        self.inner.create_or_update_account(request).await
    }
}

enum FakeRefreshProviderResult {
    Success {
        provider: AuthProviderId,
        access_secret: SecretHandle,
        refresh_secret: Option<SecretHandle>,
    },
    InvalidGrant,
    BackendUnavailable,
}

struct FakeRefreshProviderClient {
    result: FakeRefreshProviderResult,
}

impl FakeRefreshProviderClient {
    fn success(provider: &str, access_secret: &str, refresh_secret: Option<&str>) -> Self {
        Self {
            result: FakeRefreshProviderResult::Success {
                provider: AuthProviderId::new(provider).expect("provider"),
                access_secret: SecretHandle::new(access_secret).expect("access handle"),
                refresh_secret: refresh_secret
                    .map(|handle| SecretHandle::new(handle).expect("refresh handle")),
            },
        }
    }

    fn invalid_grant() -> Self {
        Self {
            result: FakeRefreshProviderResult::InvalidGrant,
        }
    }

    fn backend_unavailable() -> Self {
        Self {
            result: FakeRefreshProviderResult::BackendUnavailable,
        }
    }
}

#[async_trait]
impl AuthProviderClient for FakeRefreshProviderClient {
    async fn exchange_callback(
        &self,
        _context: OAuthProviderExchangeContext,
        _request: OAuthProviderCallbackRequest,
    ) -> Result<OAuthProviderExchange, AuthProductError> {
        Err(AuthProductError::BackendUnavailable)
    }

    async fn refresh_token(
        &self,
        request: OAuthProviderRefreshRequest,
    ) -> Result<OAuthProviderRefresh, AuthProductError> {
        match &self.result {
            FakeRefreshProviderResult::Success {
                provider,
                access_secret,
                refresh_secret,
            } => Ok(OAuthProviderRefresh {
                provider: provider.clone(),
                access_secret: access_secret.clone(),
                refresh_secret: refresh_secret.clone(),
                scopes: request.scopes,
            }),
            FakeRefreshProviderResult::InvalidGrant => Err(AuthProductError::InvalidGrant),
            FakeRefreshProviderResult::BackendUnavailable => {
                Err(AuthProductError::BackendUnavailable)
            }
        }
    }
}

struct PassthroughCredentialSetupService;

#[async_trait]
impl CredentialSetupService for PassthroughCredentialSetupService {
    async fn create_or_update_account(
        &self,
        request: CredentialAccountMutation,
    ) -> Result<CredentialAccount, AuthProductError> {
        let (account_id, account) = match request {
            CredentialAccountMutation::Create(account) => (CredentialAccountId::new(), account),
            CredentialAccountMutation::Update(update) => (update.account_id, update.account),
        };
        Ok(credential_account_from_new(account_id, account))
    }
}

struct RevokingCredentialAccountService {
    account: StdMutex<CredentialAccount>,
    source: Arc<dyn MatrixPolicySnapshotSource>,
    adapter_id: ProductAdapterId,
    installation_id: AdapterInstallationId,
    saw_preinvalidated_projection: AtomicBool,
}

impl RevokingCredentialAccountService {
    fn new(
        account: CredentialAccount,
        source: Arc<dyn MatrixPolicySnapshotSource>,
        adapter_id: ProductAdapterId,
        installation_id: AdapterInstallationId,
    ) -> Self {
        Self {
            account: StdMutex::new(account),
            source,
            adapter_id,
            installation_id,
            saw_preinvalidated_projection: AtomicBool::new(false),
        }
    }

    fn saw_preinvalidated_projection(&self) -> bool {
        self.saw_preinvalidated_projection.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl CredentialAccountService for RevokingCredentialAccountService {
    async fn create_account(
        &self,
        request: NewCredentialAccount,
    ) -> Result<CredentialAccount, AuthProductError> {
        Ok(credential_account_from_new(
            CredentialAccountId::new(),
            request,
        ))
    }

    async fn get_account(
        &self,
        _request: CredentialAccountLookupRequest,
    ) -> Result<Option<CredentialAccount>, AuthProductError> {
        Ok(Some(
            self.account
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        ))
    }

    async fn list_accounts(
        &self,
        _request: CredentialAccountListRequest,
    ) -> Result<CredentialAccountListPage, AuthProductError> {
        Ok(CredentialAccountListPage {
            accounts: vec![
                self.account
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .projection(),
            ],
            next_cursor: None,
        })
    }

    async fn update_status(
        &self,
        _scope: &AuthProductScope,
        _account_id: CredentialAccountId,
        status: CredentialAccountStatus,
    ) -> Result<CredentialAccount, AuthProductError> {
        if self
            .source
            .resolve_matrix_policy_snapshot(&self.adapter_id, &self.installation_id)
            .await
            .is_err()
        {
            self.saw_preinvalidated_projection
                .store(true, Ordering::SeqCst);
        }
        let mut account = self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        account.status = status;
        account.updated_at = Utc::now();
        Ok(account.clone())
    }

    async fn select_unique_configured_account(
        &self,
        _request: CredentialAccountSelectionRequest,
    ) -> Result<CredentialAccountProjection, AuthProductError> {
        Ok(self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .projection())
    }

    async fn project_credential_recovery(
        &self,
        _request: CredentialRecoveryRequest,
    ) -> Result<CredentialRecoveryProjection, AuthProductError> {
        Err(AuthProductError::BackendUnavailable)
    }

    async fn select_configured_account(
        &self,
        _request: CredentialAccountChoiceRequest,
    ) -> Result<CredentialAccountProjection, AuthProductError> {
        Ok(self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .projection())
    }

    async fn refresh_account(
        &self,
        _request: CredentialRefreshRequest,
    ) -> Result<CredentialRefreshReport, AuthProductError> {
        Err(AuthProductError::BackendUnavailable)
    }
}

fn matrix_runtime_manifest_record() -> ExtensionManifestRecord {
    matrix_runtime_manifest_record_with_credential("matrix-source-access-token")
}

fn matrix_runtime_manifest_record_with_credential(
    credential_handle: &str,
) -> ExtensionManifestRecord {
    matrix_runtime_manifest_record_with_egress_host(
        "matrix.source.example.org",
        "sha256:matrix-source-backed",
        credential_handle,
    )
}

fn matrix_runtime_manifest_record_with_egress_host(
    egress_host: &str,
    manifest_hash: &str,
    credential_handle: &str,
) -> ExtensionManifestRecord {
    product_adapter_manifest_record_with_credential(
        "matrix-product-adapter",
        "Matrix",
        "Matrix source-backed projection fixture",
        egress_host,
        manifest_hash,
        credential_handle,
    )
}

fn non_matrix_runtime_manifest_record_with_credential(
    credential_handle: &str,
) -> ExtensionManifestRecord {
    non_matrix_runtime_manifest_record_with_egress_host(
        "github.source.example.org",
        "sha256:non-matrix-source-backed",
        credential_handle,
    )
}

fn non_matrix_runtime_manifest_record_with_egress_host(
    egress_host: &str,
    manifest_hash: &str,
    credential_handle: &str,
) -> ExtensionManifestRecord {
    product_adapter_manifest_record_with_credential(
        "github",
        "GitHub",
        "Non-Matrix source-backed projection fixture",
        egress_host,
        manifest_hash,
        credential_handle,
    )
}

fn product_adapter_manifest_record_with_credential(
    extension_id: &str,
    name: &str,
    description: &str,
    egress_host: &str,
    manifest_hash: &str,
    credential_handle: &str,
) -> ExtensionManifestRecord {
    let host_ports =
        ironclaw_host_runtime::default_host_port_catalog().expect("default host port catalog");
    let contracts =
        crate::extension_host::host_api_contracts::product_extension_host_api_contract_registry()
            .expect("host API contracts");
    ExtensionManifestRecord::from_toml_with_contracts(
        format!(
            r#"
schema_version = "{schema}"
id = "{extension_id}"
name = "{name}"
version = "0.1.0"
description = "{description}"
trust = "first_party_requested"

[runtime]
kind = "wasm"
module = "wasm/matrix.wasm"

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
handle = "{credential_handle}"

[[product_adapter.inbound.egress]]
host = "{egress_host}"
credential_handle = "{credential_handle}"
"#,
            schema = MANIFEST_SCHEMA_VERSION,
            extension_id = extension_id,
            name = name,
            description = description,
            egress_host = egress_host,
            credential_handle = credential_handle,
        )
        .as_str(),
        ManifestSource::HostBundled,
        &host_ports,
        Some(ManifestHash::new(manifest_hash).expect("hash")),
        &contracts,
    )
    .expect("manifest")
}

fn matrix_source_backed_artifact_evidence() -> MatrixRuntimeArtifactEvidence {
    MatrixRuntimeArtifactEvidence {
        artifact_id: ComponentArtifactId::new("matrix-source-backed-component")
            .expect("artifact id"),
        artifact_sha256: ArtifactSha256::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("artifact sha"),
        wit_package: WitPackageName::new("near:source-backed-adapter@0.1.0").expect("wit package"),
        wit_world: WitWorldName::new("source-backed-product-adapter").expect("wit world"),
    }
}

fn matrix_source_backed_scope() -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
        user_id: UserId::new("matrix-source-backed-owner").expect("user"),
        agent_id: Some(AgentId::new("matrix-source-backed-agent").expect("agent")),
        project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

struct FailOnNthPutFilesystem {
    inner: Arc<InMemoryBackend>,
    fail_on_puts: Vec<usize>,
    put_count: Mutex<usize>,
}

impl FailOnNthPutFilesystem {
    fn new(inner: Arc<InMemoryBackend>, fail_on_puts: impl IntoIterator<Item = usize>) -> Self {
        Self {
            inner,
            fail_on_puts: fail_on_puts.into_iter().collect(),
            put_count: Mutex::new(0),
        }
    }
}

#[async_trait]
impl RootFilesystem for FailOnNthPutFilesystem {
    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    async fn put(
        &self,
        path: &VirtualPath,
        entry: Entry,
        cas: CasExpectation,
    ) -> Result<RecordVersion, FilesystemError> {
        {
            let mut put_count = self
                .put_count
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *put_count += 1;
            if self.fail_on_puts.contains(&*put_count) {
                return Err(FilesystemError::Backend {
                    path: path.clone(),
                    operation: FilesystemOperation::WriteFile,
                    reason: "test projection cache write failed".to_string(),
                });
            }
        }
        self.inner.put(path, entry, cas).await
    }

    async fn get(
        &self,
        path: &VirtualPath,
    ) -> Result<Option<ironclaw_filesystem::VersionedEntry>, FilesystemError> {
        self.inner.get(path).await
    }

    async fn list_dir(&self, path: &VirtualPath) -> Result<Vec<DirEntry>, FilesystemError> {
        self.inner.list_dir(path).await
    }

    async fn stat(&self, path: &VirtualPath) -> Result<FileStat, FilesystemError> {
        self.inner.stat(path).await
    }

    async fn delete(&self, path: &VirtualPath) -> Result<(), FilesystemError> {
        self.inner.delete(path).await
    }
}
