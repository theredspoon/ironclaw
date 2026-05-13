use chrono::Utc;
use ironclaw_host_api::SecretHandle;
use ironclaw_product_adapter_registry::{
    InMemoryProductAdapterRegistryStore, ManifestHash, ProductAdapterActivationState,
    ProductAdapterComponentRef, ProductAdapterCredentialBinding, ProductAdapterHealthSnapshot,
    ProductAdapterInstallation, ProductAdapterManifest, ProductAdapterManifestRef,
    ProductAdapterRegistryStore, RegistryError,
};
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, DeclaredEgressHost, DeclaredEgressTarget,
    EgressCredentialHandle, ProductAdapterCapabilities, ProductAdapterHealth, ProductAdapterId,
    ProductSurfaceKind, RedactedString,
};

fn adapter_id() -> ProductAdapterId {
    ProductAdapterId::new("telegram-v2").unwrap()
}

fn installation_id(value: &str) -> AdapterInstallationId {
    AdapterInstallationId::new(value).unwrap()
}

fn credential(value: &str) -> EgressCredentialHandle {
    EgressCredentialHandle::new(value).unwrap()
}

fn host(value: &str) -> DeclaredEgressHost {
    DeclaredEgressHost::new(value).unwrap()
}

fn secret(value: &str) -> SecretHandle {
    SecretHandle::new(value).unwrap()
}

fn manifest() -> ProductAdapterManifest {
    let telegram = credential("telegram_bot_token");
    ProductAdapterManifest::new(
        adapter_id(),
        semver::Version::new(0, 1, 0),
        ProductSurfaceKind::ExternalChannel,
        ProductAdapterComponentRef::new("file://adapters/telegram-v2.wasm").unwrap(),
        ProductAdapterCapabilities::external_channel_default(),
        AuthRequirement::SharedSecretHeader {
            header_name: "X-Telegram-Bot-Api-Secret-Token".to_string(),
        },
        vec![DeclaredEgressTarget::new(
            host("api.telegram.org"),
            Some(telegram.clone()),
        )],
        vec![telegram],
        Some(ManifestHash::new("sha256:abc123").unwrap()),
    )
    .unwrap()
}

fn installation(state: ProductAdapterActivationState) -> ProductAdapterInstallation {
    ProductAdapterInstallation::new(
        installation_id("acme-telegram-prod"),
        adapter_id(),
        state,
        ProductAdapterManifestRef::new(
            adapter_id(),
            Some(ManifestHash::new("sha256:abc123").unwrap()),
        ),
        vec![ProductAdapterCredentialBinding::new(
            credential("telegram_bot_token"),
            secret("telegram_bot_token"),
        )],
        Utc::now(),
    )
    .unwrap()
}

#[tokio::test]
async fn default_registry_has_no_enabled_installations() {
    let store = InMemoryProductAdapterRegistryStore::default();

    assert!(store.list_manifests().await.unwrap().is_empty());
    assert!(store.list_installations().await.unwrap().is_empty());
    assert!(store.list_enabled_installations().await.unwrap().is_empty());
}

#[tokio::test]
async fn installed_state_does_not_enable_runtime_traffic() {
    let store = InMemoryProductAdapterRegistryStore::default();
    store.upsert_manifest(manifest()).await.unwrap();
    store
        .upsert_installation(installation(ProductAdapterActivationState::Installed))
        .await
        .unwrap();

    assert!(store.list_enabled_installations().await.unwrap().is_empty());
}

#[tokio::test]
async fn explicit_activation_makes_installation_enabled() {
    let store = InMemoryProductAdapterRegistryStore::default();
    store.upsert_manifest(manifest()).await.unwrap();
    let id = installation_id("acme-telegram-prod");
    store
        .upsert_installation(installation(ProductAdapterActivationState::Installed))
        .await
        .unwrap();

    store
        .set_activation_state(&id, ProductAdapterActivationState::Enabled)
        .await
        .unwrap();

    let enabled = store.list_enabled_installations().await.unwrap();
    assert_eq!(enabled.len(), 1);
    assert_eq!(enabled[0].installation_id(), &id);
}

#[tokio::test]
async fn credential_binding_must_reference_declared_manifest_handle() {
    let store = InMemoryProductAdapterRegistryStore::default();
    store.upsert_manifest(manifest()).await.unwrap();
    let mut invalid = installation(ProductAdapterActivationState::Installed);
    invalid
        .set_credential_bindings(vec![ProductAdapterCredentialBinding::new(
            credential("slack_bot_token"),
            secret("slack_bot_token"),
        )])
        .unwrap();

    let err = store.upsert_installation(invalid).await.unwrap_err();
    assert!(matches!(
        err,
        RegistryError::UndeclaredCredentialHandle { .. }
    ));
}

#[test]
fn rejected_duplicate_credential_update_preserves_previous_bindings() {
    let mut installation = installation(ProductAdapterActivationState::Installed);
    let original = installation.credential_bindings().to_vec();

    let err = installation
        .set_credential_bindings(vec![
            ProductAdapterCredentialBinding::new(
                credential("telegram_bot_token"),
                secret("telegram_bot_token"),
            ),
            ProductAdapterCredentialBinding::new(
                credential("telegram_bot_token"),
                secret("telegram_bot_token_shadow"),
            ),
        ])
        .unwrap_err();

    assert!(matches!(
        err,
        RegistryError::DuplicateCredentialBinding { .. }
    ));
    assert_eq!(installation.credential_bindings(), original);
}

#[tokio::test]
async fn manifest_hash_mismatch_is_rejected() {
    let store = InMemoryProductAdapterRegistryStore::default();
    store.upsert_manifest(manifest()).await.unwrap();
    let invalid = ProductAdapterInstallation::new(
        installation_id("acme-telegram-prod"),
        adapter_id(),
        ProductAdapterActivationState::Installed,
        ProductAdapterManifestRef::new(
            adapter_id(),
            Some(ManifestHash::new("sha256:different").unwrap()),
        ),
        vec![ProductAdapterCredentialBinding::new(
            credential("telegram_bot_token"),
            secret("telegram_bot_token"),
        )],
        Utc::now(),
    )
    .unwrap();

    let err = store.upsert_installation(invalid).await.unwrap_err();
    assert!(matches!(err, RegistryError::ManifestHashMismatch { .. }));
}

#[tokio::test]
async fn egress_pairs_are_preserved_exactly() {
    let telegram_handle = credential("telegram_bot_token");
    let slack_handle = credential("slack_bot_token");
    let manifest = ProductAdapterManifest::new(
        adapter_id(),
        semver::Version::new(0, 1, 0),
        ProductSurfaceKind::ExternalChannel,
        ProductAdapterComponentRef::new("file://adapters/telegram-v2.wasm").unwrap(),
        ProductAdapterCapabilities::external_channel_default(),
        AuthRequirement::BearerToken,
        vec![
            DeclaredEgressTarget::new(host("api.telegram.org"), Some(telegram_handle.clone())),
            DeclaredEgressTarget::new(host("api.slack.com"), Some(slack_handle.clone())),
        ],
        vec![telegram_handle, slack_handle],
        None,
    )
    .unwrap();

    let pairs: Vec<(String, Option<String>)> = manifest
        .declared_egress()
        .iter()
        .map(|target| {
            (
                target.host.as_str().to_string(),
                target
                    .credential_handle
                    .as_ref()
                    .map(|handle| handle.as_str().to_string()),
            )
        })
        .collect();

    assert_eq!(
        pairs,
        vec![
            (
                "api.telegram.org".to_string(),
                Some("telegram_bot_token".to_string())
            ),
            (
                "api.slack.com".to_string(),
                Some("slack_bot_token".to_string())
            )
        ]
    );
}

#[tokio::test]
async fn health_update_redacts_message() {
    let store = InMemoryProductAdapterRegistryStore::default();
    store.upsert_manifest(manifest()).await.unwrap();
    let id = installation_id("acme-telegram-prod");
    store
        .upsert_installation(installation(ProductAdapterActivationState::Enabled))
        .await
        .unwrap();

    store
        .update_health(
            &id,
            ProductAdapterHealthSnapshot::new(
                ProductAdapterHealth::Degraded,
                Some(Utc::now()),
                Some(RedactedString::new("super-secret-token")),
            ),
        )
        .await
        .unwrap();

    let got = store.get_installation(&id).await.unwrap().unwrap();
    let rendered = format!("{:?}", got.health());
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("super-secret-token"));
}
