use chrono::Utc;
use ironclaw_extensions::{MANIFEST_SCHEMA_VERSION, ManifestSource};
use ironclaw_host_api::{ExtensionId, HostPortCatalog, SecretHandle};
use ironclaw_product_adapter_registry::{
    ExtensionActivationState, ExtensionCredentialBinding, ExtensionInstallation,
    ExtensionInstallationId, ExtensionInstallationStore, ExtensionManifestRecord,
    ExtensionManifestRef, InMemoryExtensionInstallationStore, ManifestHash, RegistryError,
    list_enabled_product_adapter_entries,
};
use ironclaw_product_adapters::EgressCredentialHandle;

fn extension_id() -> ExtensionId {
    ExtensionId::new("telegram-v2").unwrap()
}

fn installation_id() -> ExtensionInstallationId {
    ExtensionInstallationId::new("acme-telegram-prod").unwrap()
}

fn credential(value: &str) -> EgressCredentialHandle {
    EgressCredentialHandle::new(value).unwrap()
}

fn manifest_hash(value: &str) -> ManifestHash {
    ManifestHash::new(value).unwrap()
}

fn manifest(required_credential: &str, hash: &str) -> ExtensionManifestRecord {
    let raw = format!(
        r#"
schema_version = "{schema}"
id = "telegram-v2"
name = "Telegram"
version = "0.1.0"
description = "Telegram product adapter"
trust = "third_party"

[runtime]
kind = "wasm"
module = "adapters/telegram-v2.wasm"

[[host_api]]
id = "ironclaw.product_adapter/v1"
section = "product_adapter.inbound"

[product_adapter.inbound]
surface_kind = "external_channel"

[product_adapter.inbound.auth]
kind = "bearer_token"

[product_adapter.inbound.capabilities]
flags = ["inbound_messages"]

[[product_adapter.inbound.required_credentials]]
handle = "{required_credential}"
"#,
        schema = MANIFEST_SCHEMA_VERSION,
    );
    ExtensionManifestRecord::from_toml(
        raw,
        ManifestSource::InstalledLocal,
        &HostPortCatalog::empty(),
        Some(manifest_hash(hash)),
    )
    .unwrap()
}

fn installation(state: ExtensionActivationState) -> ExtensionInstallation {
    ExtensionInstallation::new(
        installation_id(),
        extension_id(),
        state,
        ExtensionManifestRef::new(extension_id(), Some(manifest_hash("sha256:abc123"))),
        vec![ExtensionCredentialBinding::new(
            credential("telegram_bot_token"),
            SecretHandle::new("secret_telegram_bot_token").unwrap(),
        )],
        Utc::now(),
    )
    .unwrap()
}

#[tokio::test]
async fn default_store_has_no_enabled_installations() {
    let store = InMemoryExtensionInstallationStore::default();

    assert!(store.list_manifests().await.unwrap().is_empty());
    assert!(store.list_enabled_installations().await.unwrap().is_empty());
}

#[tokio::test]
async fn explicit_activation_surfaces_in_product_adapter_runtime_entries() {
    let store = InMemoryExtensionInstallationStore::default();
    store
        .upsert_manifest(manifest("telegram_bot_token", "sha256:abc123"))
        .await
        .unwrap();
    store
        .upsert_installation(installation(ExtensionActivationState::Installed))
        .await
        .unwrap();

    store
        .set_activation_state(&installation_id(), ExtensionActivationState::Enabled)
        .await
        .unwrap();

    let enabled = store.list_enabled_installations().await.unwrap();
    assert_eq!(enabled.len(), 1);

    let entries = list_enabled_product_adapter_entries(&store).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].adapter().adapter_id().as_str(), "telegram-v2");
}

#[tokio::test]
async fn non_product_adapter_extension_is_skipped_in_product_adapter_projection() {
    let plain_raw = format!(
        r#"
schema_version = "{schema}"
id = "plain-tool"
name = "Plain Tool"
version = "0.1.0"
description = "No product adapter"
trust = "third_party"

[runtime]
kind = "wasm"
module = "wasm/plain.wasm"

[[capabilities]]
id = "plain-tool.do"
description = "Do something"
default_permission = "ask"
visibility = "model"
input_schema_ref = "schemas/in.json"
output_schema_ref = "schemas/out.json"
prompt_doc_ref = "prompts/do.md"
"#,
        schema = MANIFEST_SCHEMA_VERSION,
    );
    let plain_id = ExtensionId::new("plain-tool").unwrap();
    let plain_manifest = ExtensionManifestRecord::from_toml(
        plain_raw,
        ManifestSource::InstalledLocal,
        &ironclaw_host_api::HostPortCatalog::empty(),
        Some(manifest_hash("sha256:plain")),
    )
    .unwrap();
    let plain_install = ExtensionInstallation::new(
        ExtensionInstallationId::new("plain-install").unwrap(),
        plain_id.clone(),
        ExtensionActivationState::Enabled,
        ExtensionManifestRef::new(plain_id, Some(manifest_hash("sha256:plain"))),
        vec![],
        Utc::now(),
    )
    .unwrap();

    let store = InMemoryExtensionInstallationStore::default();
    store.upsert_manifest(plain_manifest).await.unwrap();
    store.upsert_installation(plain_install).await.unwrap();

    let pa_entries = list_enabled_product_adapter_entries(&store).await.unwrap();
    assert!(
        pa_entries.is_empty(),
        "plain extension should not appear in product adapter entries"
    );
}

#[tokio::test]
async fn credential_binding_must_reference_declared_manifest_handle() {
    let store = InMemoryExtensionInstallationStore::default();
    store
        .upsert_manifest(manifest("telegram_bot_token", "sha256:abc123"))
        .await
        .unwrap();

    let invalid = ExtensionInstallation::new(
        installation_id(),
        extension_id(),
        ExtensionActivationState::Installed,
        ExtensionManifestRef::new(extension_id(), Some(manifest_hash("sha256:abc123"))),
        vec![ExtensionCredentialBinding::new(
            credential("slack_bot_token"),
            SecretHandle::new("secret_slack_bot_token").unwrap(),
        )],
        Utc::now(),
    )
    .unwrap();

    let err = store.upsert_installation(invalid).await.unwrap_err();
    assert!(matches!(
        err,
        RegistryError::UndeclaredCredentialHandle { .. }
    ));
}

#[tokio::test]
async fn manifest_hash_mismatch_is_rejected() {
    let store = InMemoryExtensionInstallationStore::default();
    store
        .upsert_manifest(manifest("telegram_bot_token", "sha256:different"))
        .await
        .unwrap();

    let err = store
        .upsert_installation(installation(ExtensionActivationState::Installed))
        .await
        .unwrap_err();
    assert!(matches!(err, RegistryError::ManifestHashMismatch { .. }));
}

#[tokio::test]
async fn upsert_manifest_rejects_when_existing_installation_binding_revoked() {
    let store = InMemoryExtensionInstallationStore::default();
    store
        .upsert_manifest(manifest("telegram_bot_token", "sha256:abc123"))
        .await
        .unwrap();
    store
        .upsert_installation(installation(ExtensionActivationState::Enabled))
        .await
        .unwrap();

    let err = store
        .upsert_manifest(manifest("other_token", "sha256:abc123"))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RegistryError::UndeclaredCredentialHandle { .. }
    ));
}

#[test]
fn installation_deserialize_rejects_duplicate_bindings() {
    let json = r#"
{
  "installation_id": "acme-telegram-prod",
  "extension_id": "telegram-v2",
  "activation_state": "installed",
  "manifest_ref": { "extension_id": "telegram-v2", "manifest_hash": "sha256:abc123" },
  "credential_bindings": [
    { "credential_handle": "telegram_bot_token", "secret_handle": "secret_a" },
    { "credential_handle": "telegram_bot_token", "secret_handle": "secret_b" }
  ],
  "health": { "status": "healthy", "message": null, "checked_at": "2026-01-01T00:00:00Z" },
  "updated_at": "2026-01-01T00:00:00Z"
}
"#;
    let err = serde_json::from_str::<ExtensionInstallation>(json).unwrap_err();
    assert!(err.to_string().contains("duplicate credential binding"));
}
