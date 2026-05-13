//! Extension Manifest v2 contract tests.

use ironclaw_extensions::{
    CapabilityVisibility, ExtensionManifestV2, ExtensionRuntimeV2, MANIFEST_SCHEMA_VERSION,
    ManifestSource, ManifestV2Error,
};
use ironclaw_host_api::{
    CapabilityProfileId, ExtensionId, HostPortCatalog, HostPortCatalogEntry, HostPortId,
    PermissionMode, RequestedTrustClass, RuntimeKind, TrustClass,
};

const TELEGRAM_TOKEN_PORT: &str = "host.secrets.telegram_bot_token";
const AUDIT_PORT: &str = "host.events.audit";
const SQL_TX_PORT: &str = "host.storage.sql_transaction.first_party";

fn catalog() -> HostPortCatalog {
    HostPortCatalog::new(vec![
        HostPortCatalogEntry::new(HostPortId::new(AUDIT_PORT).unwrap()),
        HostPortCatalogEntry::new(HostPortId::new(SQL_TX_PORT).unwrap()),
        HostPortCatalogEntry::new(HostPortId::new(TELEGRAM_TOKEN_PORT).unwrap()),
    ])
    .unwrap()
}

fn third_party_wasm_manifest(extension_id: &str, capability_id: &str) -> String {
    format!(
        r#"
schema_version = "{schema}"
id = "{ext}"
name = "Example Extension"
version = "0.1.0"
description = "test"
trust = "third_party"

[runtime]
kind = "wasm"
module = "wasm/example.wasm"

[[capabilities]]
id = "{cap}"
description = "Echoes input"
default_permission = "allow"
visibility = "model"
input_schema_ref = "schemas/example/echo.input.v1.json"
output_schema_ref = "schemas/example/echo.output.v1.json"
prompt_doc_ref = "prompt/example/echo.md"
"#,
        schema = MANIFEST_SCHEMA_VERSION,
        ext = extension_id,
        cap = capability_id,
    )
}

#[test]
fn parses_minimum_valid_v2_manifest_for_installed_third_party_extension() {
    let toml = third_party_wasm_manifest("acme-tools", "acme-tools.echo");
    let manifest =
        ExtensionManifestV2::parse(&toml, ManifestSource::InstalledLocal, &catalog()).unwrap();

    assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION);
    assert_eq!(manifest.id, ExtensionId::new("acme-tools").unwrap());
    assert_eq!(manifest.source, ManifestSource::InstalledLocal);
    assert_eq!(manifest.requested_trust, RequestedTrustClass::ThirdParty);
    assert_eq!(manifest.trust, TrustClass::UserTrusted);
    assert_eq!(manifest.runtime.kind(), RuntimeKind::Wasm);
    assert_eq!(manifest.capabilities.len(), 1);
    let cap = &manifest.capabilities[0];
    assert_eq!(cap.visibility, CapabilityVisibility::Model);
    assert_eq!(cap.default_permission, PermissionMode::Allow);
    assert!(cap.prompt_doc_ref.is_some());
}

#[test]
fn rejects_unknown_top_level_fields() {
    let toml = r#"
schema_version = "reborn.extension_manifest.v2"
id = "acme-tools"
name = "x"
version = "0.1"
description = "x"
trust = "third_party"
oops = true

[runtime]
kind = "wasm"
module = "wasm/echo.wasm"

[[capabilities]]
id = "acme-tools.echo"
description = "echo"
default_permission = "allow"
visibility = "host_internal"
input_schema_ref = "schemas/acme/echo.input.v1.json"
output_schema_ref = "schemas/acme/echo.output.v1.json"
"#;
    let err =
        ExtensionManifestV2::parse(toml, ManifestSource::InstalledLocal, &catalog()).unwrap_err();
    assert!(matches!(err, ManifestV2Error::Parse { .. }), "{err:?}");
}

#[test]
fn rejects_first_party_trust_for_installed_source() {
    let toml = format!(
        r#"
schema_version = "{schema}"
id = "acme-tools"
name = "x"
version = "0.1"
description = "x"
trust = "first_party_requested"

[runtime]
kind = "wasm"
module = "wasm/echo.wasm"

[[capabilities]]
id = "acme-tools.echo"
description = "echo"
default_permission = "allow"
visibility = "host_internal"
input_schema_ref = "schemas/acme/echo.input.v1.json"
output_schema_ref = "schemas/acme/echo.output.v1.json"
"#,
        schema = MANIFEST_SCHEMA_VERSION,
    );
    let err =
        ExtensionManifestV2::parse(&toml, ManifestSource::InstalledLocal, &catalog()).unwrap_err();
    assert!(
        matches!(
            err,
            ManifestV2Error::TrustForbiddenForSource {
                manifest_source: ManifestSource::InstalledLocal,
                requested: RequestedTrustClass::FirstPartyRequested,
            }
        ),
        "{err:?}"
    );
}

#[test]
fn rejects_first_party_runtime_for_installed_source() {
    let toml = format!(
        r#"
schema_version = "{schema}"
id = "acme-tools"
name = "x"
version = "0.1"
description = "x"
trust = "third_party"

[runtime]
kind = "first_party"
service = "native_memory_provider"

[[capabilities]]
id = "acme-tools.echo"
description = "echo"
default_permission = "allow"
visibility = "host_internal"
input_schema_ref = "schemas/acme/echo.input.v1.json"
output_schema_ref = "schemas/acme/echo.output.v1.json"
"#,
        schema = MANIFEST_SCHEMA_VERSION,
    );
    let err =
        ExtensionManifestV2::parse(&toml, ManifestSource::InstalledLocal, &catalog()).unwrap_err();
    assert!(
        matches!(
            err,
            ManifestV2Error::RuntimeForbiddenForSource {
                manifest_source: ManifestSource::InstalledLocal,
                kind: RuntimeKind::FirstParty,
            }
        ),
        "{err:?}"
    );
}

#[test]
fn host_bundled_source_may_assert_first_party_and_reserved_id() {
    let toml = format!(
        r#"
schema_version = "{schema}"
id = "ironclaw.memory.native"
name = "Reborn Native Memory"
version = "0.1.0"
description = "host-bundled"
trust = "first_party_requested"

[runtime]
kind = "first_party"
service = "native_memory_provider"

[[capabilities]]
id = "ironclaw.memory.native.context.retrieve"
implements = ["memory.context_retrieval.v1"]
description = "Retrieve bounded provider-neutral memory context."
default_permission = "allow"
visibility = "host_internal"
input_schema_ref = "schemas/memory/context-retrieve.input.v1.json"
output_schema_ref = "schemas/memory/context-retrieve.output.v1.json"
required_host_ports = [
  "host.storage.sql_transaction.first_party",
  "host.events.audit",
]
"#,
        schema = MANIFEST_SCHEMA_VERSION,
    );
    let manifest =
        ExtensionManifestV2::parse(&toml, ManifestSource::HostBundled, &catalog()).unwrap();
    assert_eq!(
        manifest.requested_trust,
        RequestedTrustClass::FirstPartyRequested
    );
    assert!(matches!(
        manifest.runtime,
        ExtensionRuntimeV2::FirstParty { .. }
    ));
    let cap = &manifest.capabilities[0];
    assert_eq!(
        cap.implements,
        vec![CapabilityProfileId::new("memory.context_retrieval.v1").unwrap()]
    );
    assert_eq!(cap.required_host_ports.len(), 2);
}

#[test]
fn rejects_reserved_id_prefix_for_installed_source() {
    let toml = third_party_wasm_manifest("ironclaw.fake", "ironclaw.fake.echo");
    let err = ExtensionManifestV2::parse(&toml, ManifestSource::RegistryInstalled, &catalog())
        .unwrap_err();
    assert!(
        matches!(err, ManifestV2Error::ReservedIdForInstalledSource { .. }),
        "{err:?}"
    );
}

#[test]
fn rejects_capability_id_without_provider_prefix() {
    let toml = third_party_wasm_manifest("acme-tools", "other.echo");
    let err =
        ExtensionManifestV2::parse(&toml, ManifestSource::InstalledLocal, &catalog()).unwrap_err();
    assert!(
        matches!(err, ManifestV2Error::CapabilityIdNotPrefixed { .. }),
        "{err:?}"
    );
}

#[test]
fn rejects_unknown_host_ports() {
    let toml = format!(
        r#"
schema_version = "{schema}"
id = "acme-tools"
name = "x"
version = "0.1"
description = "x"
trust = "third_party"

[runtime]
kind = "wasm"
module = "wasm/echo.wasm"

[[capabilities]]
id = "acme-tools.echo"
description = "echo"
default_permission = "allow"
visibility = "host_internal"
input_schema_ref = "schemas/acme/echo.input.v1.json"
output_schema_ref = "schemas/acme/echo.output.v1.json"
required_host_ports = ["host.does.not.exist"]
"#,
        schema = MANIFEST_SCHEMA_VERSION,
    );
    let err =
        ExtensionManifestV2::parse(&toml, ManifestSource::InstalledLocal, &catalog()).unwrap_err();
    assert!(
        matches!(err, ManifestV2Error::UnknownHostPort { .. }),
        "{err:?}"
    );
}

#[test]
fn rejects_model_visible_capability_without_prompt_doc_ref() {
    let toml = format!(
        r#"
schema_version = "{schema}"
id = "acme-tools"
name = "x"
version = "0.1"
description = "x"
trust = "third_party"

[runtime]
kind = "wasm"
module = "wasm/echo.wasm"

[[capabilities]]
id = "acme-tools.echo"
description = "echo"
default_permission = "allow"
visibility = "model"
input_schema_ref = "schemas/acme/echo.input.v1.json"
output_schema_ref = "schemas/acme/echo.output.v1.json"
"#,
        schema = MANIFEST_SCHEMA_VERSION,
    );
    let err =
        ExtensionManifestV2::parse(&toml, ManifestSource::InstalledLocal, &catalog()).unwrap_err();
    assert!(
        matches!(err, ManifestV2Error::MissingPromptDocRef { .. }),
        "{err:?}"
    );
}

#[test]
fn rejects_schema_ref_with_absolute_or_url_or_traversal_paths() {
    for bad_ref in [
        "/schemas/abs.json",
        "../escape.json",
        "https://example.com/schema.json",
        "schemas/with:colon.json",
    ] {
        let toml = format!(
            r#"
schema_version = "{schema}"
id = "acme-tools"
name = "x"
version = "0.1"
description = "x"
trust = "third_party"

[runtime]
kind = "wasm"
module = "wasm/echo.wasm"

[[capabilities]]
id = "acme-tools.echo"
description = "echo"
default_permission = "allow"
visibility = "host_internal"
input_schema_ref = "{bad}"
output_schema_ref = "schemas/acme/echo.output.v1.json"
"#,
            schema = MANIFEST_SCHEMA_VERSION,
            bad = bad_ref,
        );
        let err = ExtensionManifestV2::parse(&toml, ManifestSource::InstalledLocal, &catalog())
            .unwrap_err();
        assert!(
            matches!(err, ManifestV2Error::Contract(_)),
            "{bad_ref:?} should be rejected via contract error, got {err:?}"
        );
    }
}

#[test]
fn rejects_wrong_schema_version() {
    let toml = r#"
schema_version = "reborn.extension_manifest.v1"
id = "acme-tools"
name = "x"
version = "0.1"
description = "x"
trust = "third_party"

[runtime]
kind = "wasm"
module = "wasm/echo.wasm"

[[capabilities]]
id = "acme-tools.echo"
description = "echo"
default_permission = "allow"
visibility = "host_internal"
input_schema_ref = "schemas/acme/echo.input.v1.json"
output_schema_ref = "schemas/acme/echo.output.v1.json"
"#;
    let err =
        ExtensionManifestV2::parse(toml, ManifestSource::InstalledLocal, &catalog()).unwrap_err();
    assert!(
        matches!(err, ManifestV2Error::SchemaVersion { .. }),
        "{err:?}"
    );
}

#[test]
fn rejects_duplicate_capability_ids() {
    let toml = format!(
        r#"
schema_version = "{schema}"
id = "acme-tools"
name = "x"
version = "0.1"
description = "x"
trust = "third_party"

[runtime]
kind = "wasm"
module = "wasm/echo.wasm"

[[capabilities]]
id = "acme-tools.echo"
description = "echo"
default_permission = "allow"
visibility = "host_internal"
input_schema_ref = "schemas/acme/echo.input.v1.json"
output_schema_ref = "schemas/acme/echo.output.v1.json"

[[capabilities]]
id = "acme-tools.echo"
description = "echo (dup)"
default_permission = "allow"
visibility = "host_internal"
input_schema_ref = "schemas/acme/echo.input.v1.json"
output_schema_ref = "schemas/acme/echo.output.v1.json"
"#,
        schema = MANIFEST_SCHEMA_VERSION,
    );
    let err =
        ExtensionManifestV2::parse(&toml, ManifestSource::InstalledLocal, &catalog()).unwrap_err();
    assert!(
        matches!(err, ManifestV2Error::DuplicateCapability { .. }),
        "{err:?}"
    );
}
