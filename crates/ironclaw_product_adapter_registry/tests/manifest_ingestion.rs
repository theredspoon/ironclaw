use ironclaw_product_adapter_registry::{ProductAdapterManifestDocument, RegistryError};
use ironclaw_product_adapters::{AuthRequirement, ProductCapabilityFlag, ProductSurfaceKind};

const TELEGRAM_MANIFEST: &str = include_str!("fixtures/telegram-v2.product-adapter.toml");

#[test]
fn parses_telegram_v2_manifest_fixture() {
    let manifest = ProductAdapterManifestDocument::from_toml(TELEGRAM_MANIFEST)
        .unwrap()
        .into_manifest()
        .unwrap();

    assert_eq!(manifest.adapter_id().as_str(), "telegram-v2");
    assert_eq!(manifest.version().to_string(), "0.1.0");
    assert_eq!(manifest.surface_kind(), ProductSurfaceKind::ExternalChannel);
    assert_eq!(
        manifest.component_ref().as_str(),
        "file://adapters/telegram-v2.wasm"
    );
    assert!(matches!(
        manifest.auth_requirement(),
        AuthRequirement::SharedSecretHeader { header_name }
            if header_name == "X-Telegram-Bot-Api-Secret-Token"
    ));
    assert!(
        manifest
            .capabilities()
            .contains(ProductCapabilityFlag::ExternalFinalReplyPush)
    );
    assert_eq!(manifest.required_credentials().len(), 1);
    assert_eq!(
        manifest.required_credentials()[0].as_str(),
        "telegram_bot_token"
    );
    assert_eq!(manifest.declared_egress().len(), 1);
    assert_eq!(
        manifest.declared_egress()[0].host.as_str(),
        "api.telegram.org"
    );
    assert_eq!(
        manifest.declared_egress()[0]
            .credential_handle
            .as_ref()
            .unwrap()
            .as_str(),
        "telegram_bot_token"
    );
}

#[test]
fn rejects_unknown_manifest_fields() {
    let raw = r#"
api_version = "ironclaw.product_adapter_manifest/v1"
kind = "ProductAdapterManifest"
adapter_id = "bad-adapter"
version = "0.1.0"
surface_kind = "external_channel"
component_ref = "file://bad.wasm"
env_adapter_list = "telegram-v2"

[auth]
kind = "bearer_token"

[capabilities]
flags = ["inbound_messages"]
"#;

    let err = ProductAdapterManifestDocument::from_toml(raw).unwrap_err();
    assert!(matches!(err, RegistryError::ManifestParse { .. }));
}

#[test]
fn rejects_inline_secret_material_in_manifest() {
    let raw = r#"
api_version = "ironclaw.product_adapter_manifest/v1"
kind = "ProductAdapterManifest"
adapter_id = "bad-adapter"
version = "0.1.0"
surface_kind = "external_channel"
component_ref = "file://bad.wasm"

[auth]
kind = "bearer_token"

[capabilities]
flags = ["inbound_messages"]

[[required_credentials]]
handle = "bot_token"
secret_value = "123456789:AABBccDDeeFFgg"
"#;

    let err = ProductAdapterManifestDocument::from_toml(raw).unwrap_err();
    assert!(matches!(err, RegistryError::InlineSecretMaterial { .. }));
}

#[test]
fn rejects_secret_like_values_in_allowed_fields() {
    let raw = r#"
api_version = "ironclaw.product_adapter_manifest/v1"
kind = "ProductAdapterManifest"
adapter_id = "bad-adapter"
version = "0.1.0"
surface_kind = "external_channel"
component_ref = "https://bot:123456789:AABBccDDeeFFgg@example.com/adapter.wasm"

[auth]
kind = "bearer_token"

[capabilities]
flags = ["inbound_messages"]
"#;

    let err = ProductAdapterManifestDocument::from_toml(raw).unwrap_err();
    assert!(matches!(err, RegistryError::InlineSecretMaterial { .. }));
}

#[test]
fn rejects_egress_credential_not_declared_as_required() {
    let raw = r#"
api_version = "ironclaw.product_adapter_manifest/v1"
kind = "ProductAdapterManifest"
adapter_id = "bad-adapter"
version = "0.1.0"
surface_kind = "external_channel"
component_ref = "file://bad.wasm"

[auth]
kind = "bearer_token"

[capabilities]
flags = ["inbound_messages"]

[[egress]]
host = "api.example.com"
credential_handle = "undeclared_token"
"#;

    let err = ProductAdapterManifestDocument::from_toml(raw)
        .unwrap()
        .into_manifest()
        .unwrap_err();
    assert!(matches!(
        err,
        RegistryError::UndeclaredEgressCredentialHandle { .. }
    ));
}
