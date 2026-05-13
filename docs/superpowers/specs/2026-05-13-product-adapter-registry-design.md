# ProductAdapter Registry Design

## Purpose

Create a narrow Reborn ProductAdapter registry foundation that mirrors the useful parts of v1 channel handling without carrying forward v1 `ChannelManager` coupling.

The first slice defines typed manifest and activation-state contracts for ProductAdapters. It does not implement the broader Blueprint/config-as-code system yet. Future Blueprint or harness apply flows can write into this registry, but runtime code should eventually read registry state rather than env-var adapter lists.

## Current v1 reference model

v1 WASM channels use three separate concepts:

1. **Discovery from filesystem**: channel WASM files and capability manifests are discovered under `WASM_CHANNELS_DIR`.
2. **Manifest metadata**: each channel ships a capabilities JSON, such as `channels-src/telegram/telegram.capabilities.json`, declaring auth, required secrets, HTTP allowlists, webhook settings, and defaults.
3. **Activation state**: runtime activation persists `activated_channels` in the settings store. Startup uses that persisted state when present; setup `wasm_channels` is only a first-run fallback.

Reborn should keep the same separation, but with typed ProductAdapter concepts and no legacy `ChannelsConfig` or `ExtensionManager` dependency.

## Architecture

Add a new workspace crate:

```text
crates/ironclaw_product_adapter_registry/
```

This crate owns ProductAdapter install/config registry contracts only. It does not load WASM, call ProductWorkflow, perform egress, read secrets, or register webhook routes.

### Core types

#### `ProductAdapterManifest`

Host-visible adapter declaration, typically loaded from a component bundle or future config apply flow.

Fields:

- `adapter_id: ProductAdapterId`
- `version: semver::Version`
- `surface_kind: ProductSurfaceKind`
- `component_ref: ProductAdapterComponentRef`
- `capabilities: ProductAdapterCapabilities`
- `auth_requirement: AuthRequirement`
- `declared_egress: Vec<DeclaredEgressTarget>`
- `required_credentials: Vec<EgressCredentialHandle>`
- `manifest_hash: Option<ManifestHash>`

#### `ProductAdapterInstallation`

Runtime installation state for one configured adapter instance.

Fields:

- `installation_id: AdapterInstallationId`
- `adapter_id: ProductAdapterId`
- `activation_state: ProductAdapterActivationState`
- `manifest_ref: ProductAdapterManifestRef`
- `credential_bindings: Vec<ProductAdapterCredentialBinding>`
- `health: ProductAdapterHealthSnapshot`
- `updated_at: DateTime<Utc>`

`ProductAdapterActivationState` is explicit:

- `Installed`
- `Enabled`
- `Disabled`

Default registry state is empty. Installing a manifest or installation does not implicitly enable runtime traffic unless activation state is `Enabled`.

#### `ProductAdapterCredentialBinding`

Binds adapter-declared credential handles to host secret handles without exposing secret material.

Fields:

- `credential_handle: EgressCredentialHandle`
- `secret_handle: SecretHandle`

The registry must never store raw secret material.

#### `ProductAdapterHealthSnapshot`

Redacted status view for operators and runtime readiness.

Fields:

- `status: ProductAdapterHealth`
- `checked_at: Option<DateTime<Utc>>`
- `message: Option<RedactedString>`

### Store trait

Define `ProductAdapterRegistryStore` as the first persistence boundary:

```rust
#[async_trait]
pub trait ProductAdapterRegistryStore: Send + Sync {
    async fn list_manifests(&self) -> Result<Vec<ProductAdapterManifest>, RegistryError>;
    async fn get_manifest(&self, adapter_id: &ProductAdapterId) -> Result<Option<ProductAdapterManifest>, RegistryError>;
    async fn upsert_manifest(&self, manifest: ProductAdapterManifest) -> Result<(), RegistryError>;

    async fn list_installations(&self) -> Result<Vec<ProductAdapterInstallation>, RegistryError>;
    async fn list_enabled_installations(&self) -> Result<Vec<ProductAdapterInstallation>, RegistryError>;
    async fn get_installation(&self, installation_id: &AdapterInstallationId) -> Result<Option<ProductAdapterInstallation>, RegistryError>;
    async fn upsert_installation(&self, installation: ProductAdapterInstallation) -> Result<(), RegistryError>;
    async fn set_activation_state(&self, installation_id: &AdapterInstallationId, state: ProductAdapterActivationState) -> Result<(), RegistryError>;
    async fn update_health(&self, installation_id: &AdapterInstallationId, health: ProductAdapterHealthSnapshot) -> Result<(), RegistryError>;
}
```

First implementation:

```text
InMemoryProductAdapterRegistryStore
```

DB-backed libSQL/Postgres stores are explicit follow-up work. The trait shape keeps that path open, but this slice is not production durable.

## Data flow

### First slice

```text
manifest value
  -> ProductAdapterRegistryStore::upsert_manifest
  -> ProductAdapterRegistryStore::upsert_installation
  -> explicit set_activation_state(..., Enabled)
  -> list_enabled_installations()
```

Runtime integration comes later. For now, tests drive the trait directly.

### Future runtime flow

```text
component bundle / Blueprint apply / operator command
  -> registry manifest + installation writes
  -> Reborn composition reads enabled installations
  -> WASM ProductAdapter loader loads component_ref
  -> host builds auth + egress policy from manifest declarations
  -> webhook/router layer selects enabled installation
```

## Boundaries and invariants

- No env-var adapter list such as `REBORN_PRODUCT_ADAPTERS` as the primary declaration path.
- No dependency on legacy `ChannelsConfig`, v1 WASM channel storage, or `ExtensionManager` activation internals.
- No raw secret material. Store secret handles and credential handles only.
- Preserve exact `(host, credential_handle)` egress pairs; do not flatten into independent host/credential sets.
- Empty registry means no ProductAdapters are active.
- Duplicate installation ids are rejected or overwrite only through explicit `upsert_installation` semantics on the same id; tests pin behavior.
- Manifest validation rejects malformed ids, duplicate egress pairs when useful for deterministic views, and credential bindings that reference undeclared credential handles.
- Health messages are redacted and must not include provider internals, raw payloads, host paths, or secrets.

## Error handling

`RegistryError` should include typed variants for:

- malformed manifest
- duplicate installation id conflict
- unknown manifest reference
- undeclared credential binding
- invalid activation transition
- store unavailable

Errors exposed outside the crate should use redacted messages.

## Tests

Minimum first-slice tests:

- default in-memory registry lists no enabled installations.
- manifest upsert + installation upsert with `Installed` state does not appear in enabled list.
- explicit activation to `Enabled` appears in enabled list.
- duplicate installation id behavior is deterministic.
- credential binding rejects undeclared credential handles.
- egress pairs are preserved exactly, including cross-pair leak regression shape.
- health update stores redacted health only.
- crate boundary test keeps registry out of WASM runtime, legacy channels, network, secrets material access, and ProductWorkflow execution.

## Follow-up work

- Load manifest metadata from ProductAdapter component bundles.
- Add libSQL and Postgres implementations of `ProductAdapterRegistryStore`.
- Wire Reborn composition/runtime to read enabled installations.
- Add operator CLI/admin UI to install, enable, disable, and inspect ProductAdapters.
- Add Blueprint/harness apply support that writes registry state declaratively.
- Remove legacy Reborn Telegram v2 coupling from `ChannelsConfig` and `ExtensionManager` once Reborn registry/runtime owns activation.
