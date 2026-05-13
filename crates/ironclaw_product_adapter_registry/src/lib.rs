//! ProductAdapter installation registry contracts for IronClaw Reborn.
//!
//! This crate models the Reborn equivalent of v1 channel manifests plus
//! activation state. It does not load WASM components, perform HTTP egress,
//! read secret material, or route webhooks.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ironclaw_host_api::SecretHandle;
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, DeclaredEgressHost, DeclaredEgressTarget,
    EgressCredentialHandle, ProductAdapterCapabilities, ProductAdapterHealth, ProductAdapterId,
    ProductCapabilityFlag, ProductSurfaceKind, RedactedString,
};
use semver::Version;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProductAdapterComponentRef(String);

impl ProductAdapterComponentRef {
    pub fn new(value: impl Into<String>) -> Result<Self, RegistryError> {
        let value = value.into();
        validate_nonempty_noncontrol("component_ref", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ProductAdapterComponentRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ManifestHash(String);

impl ManifestHash {
    pub fn new(value: impl Into<String>) -> Result<Self, RegistryError> {
        let value = value.into();
        validate_nonempty_noncontrol("manifest_hash", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ManifestHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductAdapterManifestRef {
    adapter_id: ProductAdapterId,
    manifest_hash: Option<ManifestHash>,
}

impl ProductAdapterManifestRef {
    pub fn new(adapter_id: ProductAdapterId, manifest_hash: Option<ManifestHash>) -> Self {
        Self {
            adapter_id,
            manifest_hash,
        }
    }

    pub fn adapter_id(&self) -> &ProductAdapterId {
        &self.adapter_id
    }

    pub fn manifest_hash(&self) -> Option<&ManifestHash> {
        self.manifest_hash.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductAdapterManifestDocument {
    api_version: String,
    kind: String,
    adapter_id: ProductAdapterId,
    version: Version,
    surface_kind: ProductSurfaceKind,
    component_ref: ProductAdapterComponentRef,
    manifest_hash: Option<ManifestHash>,
    auth: ProductAdapterManifestAuthDocument,
    capabilities: ProductAdapterManifestCapabilitiesDocument,
    #[serde(default)]
    required_credentials: Vec<ProductAdapterManifestCredentialDocument>,
    #[serde(default)]
    egress: Vec<ProductAdapterManifestEgressDocument>,
}

impl ProductAdapterManifestDocument {
    pub const API_VERSION: &'static str = "ironclaw.product_adapter_manifest/v1";
    pub const KIND: &'static str = "ProductAdapterManifest";

    pub fn from_toml(raw: &str) -> Result<Self, RegistryError> {
        let value: toml::Value =
            toml::from_str(raw).map_err(|error| RegistryError::ManifestParse {
                reason: error.to_string(),
            })?;
        reject_inline_secret_material_value("$", &value)?;
        let document: Self =
            value
                .try_into()
                .map_err(|error: toml::de::Error| RegistryError::ManifestParse {
                    reason: error.to_string(),
                })?;
        document.validate_header()?;
        Ok(document)
    }

    pub fn into_manifest(self) -> Result<ProductAdapterManifest, RegistryError> {
        let required_credentials: Vec<_> = self
            .required_credentials
            .into_iter()
            .map(|credential| credential.handle)
            .collect();
        let declared_egress: Vec<_> = self
            .egress
            .into_iter()
            .map(|target| DeclaredEgressTarget::new(target.host, target.credential_handle))
            .collect();
        let auth_requirement = self.auth.into_auth_requirement()?;
        ProductAdapterManifest::new(
            self.adapter_id,
            self.version,
            self.surface_kind,
            self.component_ref,
            ProductAdapterCapabilities::new(self.capabilities.flags),
            auth_requirement,
            declared_egress,
            required_credentials,
            self.manifest_hash,
        )
    }

    fn validate_header(&self) -> Result<(), RegistryError> {
        if self.api_version != Self::API_VERSION {
            return Err(RegistryError::UnsupportedManifestVersion {
                api_version: self.api_version.clone(),
            });
        }
        if self.kind != Self::KIND {
            return Err(RegistryError::InvalidValue {
                field: "kind",
                reason: format!("must be {}", Self::KIND),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProductAdapterManifestAuthDocument {
    RequestSignature {
        header_name: String,
        timestamp_header_name: Option<String>,
    },
    SharedSecretHeader {
        header_name: String,
    },
    SessionCookie {
        name: String,
    },
    BearerToken,
}

impl ProductAdapterManifestAuthDocument {
    fn into_auth_requirement(self) -> Result<AuthRequirement, RegistryError> {
        match self {
            Self::RequestSignature {
                header_name,
                timestamp_header_name,
            } => {
                validate_http_token("auth.header_name", &header_name)?;
                if let Some(timestamp_header) = timestamp_header_name.as_deref() {
                    validate_http_token("auth.timestamp_header_name", timestamp_header)?;
                }
                Ok(AuthRequirement::RequestSignature {
                    header_name,
                    timestamp_header_name,
                })
            }
            Self::SharedSecretHeader { header_name } => {
                validate_http_token("auth.header_name", &header_name)?;
                Ok(AuthRequirement::SharedSecretHeader { header_name })
            }
            Self::SessionCookie { name } => {
                validate_cookie_name("auth.name", &name)?;
                Ok(AuthRequirement::SessionCookie { name })
            }
            Self::BearerToken => Ok(AuthRequirement::BearerToken),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductAdapterManifestCapabilitiesDocument {
    flags: Vec<ProductCapabilityFlag>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductAdapterManifestCredentialDocument {
    handle: EgressCredentialHandle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductAdapterManifestEgressDocument {
    host: DeclaredEgressHost,
    credential_handle: Option<EgressCredentialHandle>,
}

/// Validated product-adapter manifest.
///
/// Construction always routes through [`ProductAdapterManifest::new`] or the
/// manual [`Deserialize`] impl below, so cross-field invariants
/// ([`Self::validate`]) are guaranteed for every value in scope — including
/// values reconstructed from a persisted serialized form. The `#[derive]`
/// intentionally excludes `Deserialize` to prevent direct-bypass paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductAdapterManifest {
    adapter_id: ProductAdapterId,
    version: Version,
    surface_kind: ProductSurfaceKind,
    component_ref: ProductAdapterComponentRef,
    capabilities: ProductAdapterCapabilities,
    auth_requirement: AuthRequirement,
    declared_egress: Vec<DeclaredEgressTarget>,
    required_credentials: Vec<EgressCredentialHandle>,
    manifest_hash: Option<ManifestHash>,
}

impl ProductAdapterManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        adapter_id: ProductAdapterId,
        version: Version,
        surface_kind: ProductSurfaceKind,
        component_ref: ProductAdapterComponentRef,
        capabilities: ProductAdapterCapabilities,
        auth_requirement: AuthRequirement,
        declared_egress: Vec<DeclaredEgressTarget>,
        required_credentials: Vec<EgressCredentialHandle>,
        manifest_hash: Option<ManifestHash>,
    ) -> Result<Self, RegistryError> {
        let manifest = Self {
            adapter_id,
            version,
            surface_kind,
            component_ref,
            capabilities,
            auth_requirement,
            declared_egress,
            required_credentials,
            manifest_hash,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn adapter_id(&self) -> &ProductAdapterId {
        &self.adapter_id
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn surface_kind(&self) -> ProductSurfaceKind {
        self.surface_kind
    }

    pub fn component_ref(&self) -> &ProductAdapterComponentRef {
        &self.component_ref
    }

    pub fn capabilities(&self) -> &ProductAdapterCapabilities {
        &self.capabilities
    }

    pub fn auth_requirement(&self) -> &AuthRequirement {
        &self.auth_requirement
    }

    pub fn declared_egress(&self) -> &[DeclaredEgressTarget] {
        &self.declared_egress
    }

    pub fn required_credentials(&self) -> &[EgressCredentialHandle] {
        &self.required_credentials
    }

    pub fn manifest_hash(&self) -> Option<&ManifestHash> {
        self.manifest_hash.as_ref()
    }

    fn validate(&self) -> Result<(), RegistryError> {
        validate_auth_requirement(&self.auth_requirement)?;
        let mut required = BTreeSet::new();
        for handle in &self.required_credentials {
            if !required.insert(handle.clone()) {
                return Err(RegistryError::DuplicateCredentialHandle {
                    handle: handle.clone(),
                });
            }
        }

        let mut pairs = BTreeSet::new();
        for target in &self.declared_egress {
            if let Some(handle) = target.credential_handle.as_ref()
                && !required.contains(handle)
            {
                return Err(RegistryError::UndeclaredEgressCredentialHandle {
                    handle: handle.clone(),
                });
            }
            let pair = (target.host.clone(), target.credential_handle.clone());
            if !pairs.insert(pair) {
                return Err(RegistryError::DuplicateEgressTarget);
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ProductAdapterManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            adapter_id: ProductAdapterId,
            version: Version,
            surface_kind: ProductSurfaceKind,
            component_ref: ProductAdapterComponentRef,
            capabilities: ProductAdapterCapabilities,
            auth_requirement: AuthRequirement,
            declared_egress: Vec<DeclaredEgressTarget>,
            required_credentials: Vec<EgressCredentialHandle>,
            manifest_hash: Option<ManifestHash>,
        }
        let wire = Wire::deserialize(deserializer)?;
        ProductAdapterManifest::new(
            wire.adapter_id,
            wire.version,
            wire.surface_kind,
            wire.component_ref,
            wire.capabilities,
            wire.auth_requirement,
            wire.declared_egress,
            wire.required_credentials,
            wire.manifest_hash,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductAdapterActivationState {
    Installed,
    Enabled,
    Disabled,
}

/// Host credential binding for an adapter-declared egress handle.
///
/// This stores an opaque [`SecretHandle`] only. It must never carry raw secret
/// material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductAdapterCredentialBinding {
    credential_handle: EgressCredentialHandle,
    secret_handle: SecretHandle,
}

impl ProductAdapterCredentialBinding {
    pub fn new(credential_handle: EgressCredentialHandle, secret_handle: SecretHandle) -> Self {
        Self {
            credential_handle,
            secret_handle,
        }
    }

    pub fn credential_handle(&self) -> &EgressCredentialHandle {
        &self.credential_handle
    }

    pub fn secret_handle(&self) -> &SecretHandle {
        &self.secret_handle
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductAdapterHealthSnapshot {
    status: ProductAdapterHealth,
    checked_at: Option<DateTime<Utc>>,
    message: Option<RedactedString>,
}

impl ProductAdapterHealthSnapshot {
    pub fn new(
        status: ProductAdapterHealth,
        checked_at: Option<DateTime<Utc>>,
        message: Option<RedactedString>,
    ) -> Self {
        Self {
            status,
            checked_at,
            message,
        }
    }

    pub fn healthy() -> Self {
        Self::new(ProductAdapterHealth::Healthy, None, None)
    }

    pub fn status(&self) -> ProductAdapterHealth {
        self.status
    }

    pub fn checked_at(&self) -> Option<DateTime<Utc>> {
        self.checked_at
    }

    pub fn message(&self) -> Option<&RedactedString> {
        self.message.as_ref()
    }
}

/// Validated installation snapshot.
///
/// Construction always routes through [`ProductAdapterInstallation::new`] or
/// the manual [`Deserialize`] impl below. The derive intentionally excludes
/// `Deserialize` so cross-field invariants (manifest-ref ↔ adapter-id parity,
/// duplicate-binding rejection) are guaranteed even for values reconstructed
/// from a persisted serialized form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductAdapterInstallation {
    installation_id: AdapterInstallationId,
    adapter_id: ProductAdapterId,
    activation_state: ProductAdapterActivationState,
    manifest_ref: ProductAdapterManifestRef,
    credential_bindings: Vec<ProductAdapterCredentialBinding>,
    health: ProductAdapterHealthSnapshot,
    updated_at: DateTime<Utc>,
}

impl ProductAdapterInstallation {
    pub fn new(
        installation_id: AdapterInstallationId,
        adapter_id: ProductAdapterId,
        activation_state: ProductAdapterActivationState,
        manifest_ref: ProductAdapterManifestRef,
        credential_bindings: Vec<ProductAdapterCredentialBinding>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, RegistryError> {
        if manifest_ref.adapter_id() != &adapter_id {
            return Err(RegistryError::ManifestAdapterMismatch {
                adapter_id,
                manifest_adapter_id: manifest_ref.adapter_id().clone(),
            });
        }
        let installation = Self {
            installation_id,
            adapter_id,
            activation_state,
            manifest_ref,
            credential_bindings,
            health: ProductAdapterHealthSnapshot::healthy(),
            updated_at,
        };
        installation.validate_bindings_unique()?;
        Ok(installation)
    }

    pub fn installation_id(&self) -> &AdapterInstallationId {
        &self.installation_id
    }

    pub fn adapter_id(&self) -> &ProductAdapterId {
        &self.adapter_id
    }

    pub fn activation_state(&self) -> ProductAdapterActivationState {
        self.activation_state
    }

    pub fn manifest_ref(&self) -> &ProductAdapterManifestRef {
        &self.manifest_ref
    }

    pub fn credential_bindings(&self) -> &[ProductAdapterCredentialBinding] {
        &self.credential_bindings
    }

    pub fn health(&self) -> &ProductAdapterHealthSnapshot {
        &self.health
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    fn set_activation_state(&mut self, state: ProductAdapterActivationState) {
        self.activation_state = state;
        self.updated_at = Utc::now();
    }

    fn set_health(&mut self, health: ProductAdapterHealthSnapshot) {
        self.health = health;
        self.updated_at = Utc::now();
    }

    fn validate_bindings_unique(&self) -> Result<(), RegistryError> {
        validate_bindings_unique(&self.credential_bindings)
    }
}

impl<'de> Deserialize<'de> for ProductAdapterInstallation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            installation_id: AdapterInstallationId,
            adapter_id: ProductAdapterId,
            activation_state: ProductAdapterActivationState,
            manifest_ref: ProductAdapterManifestRef,
            credential_bindings: Vec<ProductAdapterCredentialBinding>,
            health: ProductAdapterHealthSnapshot,
            updated_at: DateTime<Utc>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.manifest_ref.adapter_id() != &wire.adapter_id {
            return Err(serde::de::Error::custom(
                RegistryError::ManifestAdapterMismatch {
                    adapter_id: wire.adapter_id.clone(),
                    manifest_adapter_id: wire.manifest_ref.adapter_id().clone(),
                },
            ));
        }
        validate_bindings_unique(&wire.credential_bindings).map_err(serde::de::Error::custom)?;
        Ok(Self {
            installation_id: wire.installation_id,
            adapter_id: wire.adapter_id,
            activation_state: wire.activation_state,
            manifest_ref: wire.manifest_ref,
            credential_bindings: wire.credential_bindings,
            health: wire.health,
            updated_at: wire.updated_at,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RegistryError {
    #[error("invalid {field}: {reason}")]
    InvalidValue { field: &'static str, reason: String },
    #[error("duplicate credential handle {handle}")]
    DuplicateCredentialHandle { handle: EgressCredentialHandle },
    #[error("duplicate credential binding {handle}")]
    DuplicateCredentialBinding { handle: EgressCredentialHandle },
    #[error("duplicate egress target")]
    DuplicateEgressTarget,
    #[error("egress references undeclared credential handle {handle}")]
    UndeclaredEgressCredentialHandle { handle: EgressCredentialHandle },
    #[error("product adapter manifest parse failed: {reason}")]
    ManifestParse { reason: String },
    #[error("unsupported product adapter manifest api_version {api_version}")]
    UnsupportedManifestVersion { api_version: String },
    #[error("inline secret material is not allowed in manifest field {field}")]
    InlineSecretMaterial { field: String },
    #[error("installation references unknown adapter manifest {adapter_id}")]
    UnknownManifest { adapter_id: ProductAdapterId },
    #[error("installation binds undeclared credential handle {handle}")]
    UndeclaredCredentialHandle { handle: EgressCredentialHandle },
    #[error(
        "installation adapter {adapter_id} does not match manifest adapter {manifest_adapter_id}"
    )]
    ManifestAdapterMismatch {
        adapter_id: ProductAdapterId,
        manifest_adapter_id: ProductAdapterId,
    },
    #[error("installation manifest hash does not match registered manifest hash for {adapter_id}")]
    ManifestHashMismatch { adapter_id: ProductAdapterId },
    #[error("installation {installation_id} was not found")]
    InstallationNotFound {
        installation_id: AdapterInstallationId,
    },
}

#[async_trait]
pub trait ProductAdapterRegistryStore: Send + Sync {
    async fn list_manifests(&self) -> Result<Vec<ProductAdapterManifest>, RegistryError>;
    async fn get_manifest(
        &self,
        adapter_id: &ProductAdapterId,
    ) -> Result<Option<ProductAdapterManifest>, RegistryError>;
    async fn upsert_manifest(&self, manifest: ProductAdapterManifest) -> Result<(), RegistryError>;

    async fn list_installations(&self) -> Result<Vec<ProductAdapterInstallation>, RegistryError>;
    async fn list_enabled_installations(
        &self,
    ) -> Result<Vec<ProductAdapterInstallation>, RegistryError>;
    async fn get_installation(
        &self,
        installation_id: &AdapterInstallationId,
    ) -> Result<Option<ProductAdapterInstallation>, RegistryError>;
    async fn upsert_installation(
        &self,
        installation: ProductAdapterInstallation,
    ) -> Result<(), RegistryError>;
    async fn set_activation_state(
        &self,
        installation_id: &AdapterInstallationId,
        state: ProductAdapterActivationState,
    ) -> Result<(), RegistryError>;
    async fn update_health(
        &self,
        installation_id: &AdapterInstallationId,
        health: ProductAdapterHealthSnapshot,
    ) -> Result<(), RegistryError>;
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryProductAdapterRegistryStore {
    inner: Arc<RwLock<InMemoryRegistryState>>,
}

#[derive(Debug, Default)]
struct InMemoryRegistryState {
    manifests: HashMap<ProductAdapterId, ProductAdapterManifest>,
    installations: HashMap<AdapterInstallationId, ProductAdapterInstallation>,
}

#[async_trait]
impl ProductAdapterRegistryStore for InMemoryProductAdapterRegistryStore {
    async fn list_manifests(&self) -> Result<Vec<ProductAdapterManifest>, RegistryError> {
        let inner = self.inner.read().await;
        let mut manifests: Vec<_> = inner.manifests.values().cloned().collect();
        manifests.sort_by(|a, b| a.adapter_id().cmp(b.adapter_id()));
        Ok(manifests)
    }

    async fn get_manifest(
        &self,
        adapter_id: &ProductAdapterId,
    ) -> Result<Option<ProductAdapterManifest>, RegistryError> {
        Ok(self.inner.read().await.manifests.get(adapter_id).cloned())
    }

    async fn upsert_manifest(&self, manifest: ProductAdapterManifest) -> Result<(), RegistryError> {
        manifest.validate()?;
        let mut inner = self.inner.write().await;
        // Cross-write invariant: every stored installation must remain valid
        // against its registered manifest. Re-validate before replacing.
        for installation in inner.installations.values() {
            if installation.adapter_id() == manifest.adapter_id() {
                validate_installation_against_one_manifest(&manifest, installation)?;
            }
        }
        inner
            .manifests
            .insert(manifest.adapter_id().clone(), manifest);
        Ok(())
    }

    async fn list_installations(&self) -> Result<Vec<ProductAdapterInstallation>, RegistryError> {
        let inner = self.inner.read().await;
        let mut installations: Vec<_> = inner.installations.values().cloned().collect();
        installations.sort_by(|a, b| a.installation_id().cmp(b.installation_id()));
        Ok(installations)
    }

    async fn list_enabled_installations(
        &self,
    ) -> Result<Vec<ProductAdapterInstallation>, RegistryError> {
        let mut installations: Vec<_> = self
            .list_installations()
            .await?
            .into_iter()
            .filter(|installation| {
                installation.activation_state() == ProductAdapterActivationState::Enabled
            })
            .collect();
        installations.sort_by(|a, b| a.installation_id().cmp(b.installation_id()));
        Ok(installations)
    }

    async fn get_installation(
        &self,
        installation_id: &AdapterInstallationId,
    ) -> Result<Option<ProductAdapterInstallation>, RegistryError> {
        Ok(self
            .inner
            .read()
            .await
            .installations
            .get(installation_id)
            .cloned())
    }

    async fn upsert_installation(
        &self,
        installation: ProductAdapterInstallation,
    ) -> Result<(), RegistryError> {
        installation.validate_bindings_unique()?;
        let mut inner = self.inner.write().await;
        validate_installation_against_manifest(&inner.manifests, &installation)?;
        inner
            .installations
            .insert(installation.installation_id().clone(), installation);
        Ok(())
    }

    async fn set_activation_state(
        &self,
        installation_id: &AdapterInstallationId,
        state: ProductAdapterActivationState,
    ) -> Result<(), RegistryError> {
        let mut inner = self.inner.write().await;
        let installation = inner.installations.get(installation_id).ok_or_else(|| {
            RegistryError::InstallationNotFound {
                installation_id: installation_id.clone(),
            }
        })?;
        // Cross-write invariant: enabling an installation must re-check it
        // against the current manifest. Disabling/marking installed is
        // always allowed so operators can quarantine misconfigured state.
        if state == ProductAdapterActivationState::Enabled {
            validate_installation_against_manifest(&inner.manifests, installation)?;
        }
        // Re-borrow mutably now that the validation borrow has been released.
        let installation = inner
            .installations
            .get_mut(installation_id)
            .expect("installation was just looked up under the same write lock");
        installation.set_activation_state(state);
        Ok(())
    }

    async fn update_health(
        &self,
        installation_id: &AdapterInstallationId,
        health: ProductAdapterHealthSnapshot,
    ) -> Result<(), RegistryError> {
        let mut inner = self.inner.write().await;
        let installation = inner
            .installations
            .get_mut(installation_id)
            .ok_or_else(|| RegistryError::InstallationNotFound {
                installation_id: installation_id.clone(),
            })?;
        installation.set_health(health);
        Ok(())
    }
}

fn reject_inline_secret_material_value(
    path: &str,
    value: &toml::Value,
) -> Result<(), RegistryError> {
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                let child_path = format!("{path}.{key}");
                if is_secret_key_name(key) {
                    return Err(RegistryError::InlineSecretMaterial { field: child_path });
                }
                reject_inline_secret_material_value(&child_path, value)?;
            }
        }
        toml::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_inline_secret_material_value(&format!("{path}[{index}]"), value)?;
            }
        }
        toml::Value::String(value) => {
            if looks_like_inline_secret(value) {
                return Err(RegistryError::InlineSecretMaterial {
                    field: path.to_string(),
                });
            }
        }
        _ => {}
    }
    Ok(())
}

/// Best-effort tripwire matching table-key names that historically carry raw
/// secret material. Keys are normalised to lowercase and `-` -> `_` so both
/// `client-secret` and `Client_Secret` collapse to the same canonical token.
fn is_secret_key_name(key: &str) -> bool {
    let normalised: String = key
        .chars()
        .map(|c| {
            if c == '-' {
                '_'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    matches!(
        normalised.as_str(),
        "secret"
            | "secrets"
            | "secret_value"
            | "client_secret"
            | "webhook_secret"
            | "token"
            | "raw_token"
            | "access_token"
            | "refresh_token"
            | "bearer_token"
            | "oauth_token"
            | "auth_token"
            | "id_token"
            | "api_key"
            | "apikey"
            | "api_secret"
            | "private_key"
            | "password"
            | "passphrase"
    )
}

/// Best-effort string-shape tripwire for inline secret material. False
/// positives are acceptable: a hand-authored manifest can rename the field;
/// false negatives must not silently leak a real credential past the registry
/// boundary. The threat model is operator-authored TOML, not adversarial
/// input.
fn looks_like_inline_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("sha256:") {
        return false;
    }
    // Vendor-specific credential prefixes.
    const PREFIXES: &[&str] = &[
        "sk-",   // OpenAI / Anthropic
        "xoxb-", // Slack bot
        "xoxa-", // Slack legacy
        "xoxp-", // Slack user
        "xoxs-", // Slack session
        "xoxe-", // Slack ephemeral
        "ghp_",  // GitHub personal access token
        "gho_",  // GitHub OAuth
        "ghu_",  // GitHub user-to-server
        "ghs_",  // GitHub server-to-server
        "ghr_",  // GitHub refresh
        "akia",  // AWS access key (case-insensitive after lowercase)
        "asia",  // AWS short-term access key
    ];
    if PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return true;
    }
    if lower.contains("begin private key") || lower.contains("begin rsa private key") {
        return true;
    }
    // JWTs almost always start with the base64'd JSON header `{"alg":...`,
    // which encodes to `eyJ`. Require enough length to dampen false positives
    // from unrelated values that happen to share the prefix.
    if value.len() >= 30 && value.starts_with("eyJ") && value.contains('.') {
        return true;
    }
    if has_uri_userinfo(value) {
        return true;
    }
    looks_like_telegram_token(value)
}

fn has_uri_userinfo(value: &str) -> bool {
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    authority.contains('@')
}

fn looks_like_telegram_token(value: &str) -> bool {
    let Some((prefix, suffix)) = value.split_once(':') else {
        return false;
    };
    prefix.len() >= 6
        && prefix.chars().all(|c| c.is_ascii_digit())
        && suffix.len() >= 10
        && suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn validate_bindings_unique(
    credential_bindings: &[ProductAdapterCredentialBinding],
) -> Result<(), RegistryError> {
    let mut seen = BTreeSet::new();
    for binding in credential_bindings {
        if !seen.insert(binding.credential_handle.clone()) {
            return Err(RegistryError::DuplicateCredentialBinding {
                handle: binding.credential_handle.clone(),
            });
        }
    }
    Ok(())
}

fn validate_installation_against_manifest(
    manifests: &HashMap<ProductAdapterId, ProductAdapterManifest>,
    installation: &ProductAdapterInstallation,
) -> Result<(), RegistryError> {
    let manifest =
        manifests
            .get(installation.adapter_id())
            .ok_or_else(|| RegistryError::UnknownManifest {
                adapter_id: installation.adapter_id().clone(),
            })?;
    validate_installation_against_one_manifest(manifest, installation)
}

fn validate_installation_against_one_manifest(
    manifest: &ProductAdapterManifest,
    installation: &ProductAdapterInstallation,
) -> Result<(), RegistryError> {
    if manifest.adapter_id() != installation.manifest_ref().adapter_id() {
        return Err(RegistryError::ManifestAdapterMismatch {
            adapter_id: installation.adapter_id().clone(),
            manifest_adapter_id: installation.manifest_ref().adapter_id().clone(),
        });
    }
    // Manifest hash pinning is symmetric: if either side carries a hash,
    // both must carry the same hash. Otherwise an installation pinned to a
    // specific manifest revision could silently bind to an unstamped
    // manifest, defeating the only revision pin we have.
    match (
        manifest.manifest_hash(),
        installation.manifest_ref().manifest_hash(),
    ) {
        (Some(registered), Some(referenced)) if registered != referenced => {
            return Err(RegistryError::ManifestHashMismatch {
                adapter_id: installation.adapter_id().clone(),
            });
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(RegistryError::ManifestHashMismatch {
                adapter_id: installation.adapter_id().clone(),
            });
        }
        _ => {}
    }

    let declared: BTreeSet<_> = manifest.required_credentials().iter().cloned().collect();
    for binding in installation.credential_bindings() {
        if !declared.contains(binding.credential_handle()) {
            return Err(RegistryError::UndeclaredCredentialHandle {
                handle: binding.credential_handle().clone(),
            });
        }
    }
    Ok(())
}

fn validate_nonempty_noncontrol(field: &'static str, value: &str) -> Result<(), RegistryError> {
    if value.is_empty() {
        return Err(RegistryError::InvalidValue {
            field,
            reason: "must not be empty".to_string(),
        });
    }
    if value.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(RegistryError::InvalidValue {
            field,
            reason: "must not contain control characters".to_string(),
        });
    }
    Ok(())
}

fn validate_auth_requirement(requirement: &AuthRequirement) -> Result<(), RegistryError> {
    match requirement {
        AuthRequirement::RequestSignature {
            header_name,
            timestamp_header_name,
        } => {
            validate_http_token("auth.header_name", header_name)?;
            if let Some(timestamp_header) = timestamp_header_name.as_deref() {
                validate_http_token("auth.timestamp_header_name", timestamp_header)?;
            }
        }
        AuthRequirement::SharedSecretHeader { header_name } => {
            validate_http_token("auth.header_name", header_name)?;
        }
        AuthRequirement::SessionCookie { name } => {
            validate_cookie_name("auth.name", name)?;
        }
        AuthRequirement::BearerToken => {}
    }
    Ok(())
}

/// RFC 7230 §3.2.6 `token` = 1*tchar. Used to syntactically guard HTTP header
/// names against CRLF/whitespace/separator injection when adapter manifests
/// declare which header to read auth evidence from.
fn validate_http_token(field: &'static str, value: &str) -> Result<(), RegistryError> {
    if value.is_empty() {
        return Err(RegistryError::InvalidValue {
            field,
            reason: "must not be empty".to_string(),
        });
    }
    for c in value.chars() {
        if !is_http_tchar(c) {
            return Err(RegistryError::InvalidValue {
                field,
                reason: format!(
                    "must be an RFC 7230 token (no CTL, whitespace, or separators); got {value:?}"
                ),
            });
        }
    }
    Ok(())
}

fn is_http_tchar(c: char) -> bool {
    matches!(
        c,
        '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~'
    ) || c.is_ascii_alphanumeric()
}

/// RFC 6265 `cookie-name` is an HTTP `token`. Reuse the same predicate so a
/// declared cookie name can't smuggle CRLF, `=`, or `;` into downstream
/// `Set-Cookie`/`Cookie` interpolation.
fn validate_cookie_name(field: &'static str, value: &str) -> Result<(), RegistryError> {
    validate_http_token(field, value)
}
