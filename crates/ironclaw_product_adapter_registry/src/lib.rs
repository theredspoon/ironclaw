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
        ProductAdapterManifest::new(
            self.adapter_id,
            self.version,
            self.surface_kind,
            self.component_ref,
            ProductAdapterCapabilities::new(self.capabilities.flags),
            self.auth.into_auth_requirement(),
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
    fn into_auth_requirement(self) -> AuthRequirement {
        match self {
            Self::RequestSignature {
                header_name,
                timestamp_header_name,
            } => AuthRequirement::RequestSignature {
                header_name,
                timestamp_header_name,
            },
            Self::SharedSecretHeader { header_name } => {
                AuthRequirement::SharedSecretHeader { header_name }
            }
            Self::SessionCookie { name } => AuthRequirement::SessionCookie { name },
            Self::BearerToken => AuthRequirement::BearerToken,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    pub fn set_credential_bindings(
        &mut self,
        credential_bindings: Vec<ProductAdapterCredentialBinding>,
    ) -> Result<(), RegistryError> {
        validate_bindings_unique(&credential_bindings)?;
        self.credential_bindings = credential_bindings;
        Ok(())
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
        self.inner
            .write()
            .await
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
        let installation = inner
            .installations
            .get_mut(installation_id)
            .ok_or_else(|| RegistryError::InstallationNotFound {
                installation_id: installation_id.clone(),
            })?;
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
                let lower = key.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "secret" | "secret_value" | "token" | "raw_token" | "api_key" | "password"
                ) {
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

fn looks_like_inline_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("sha256:") {
        return false;
    }
    if value.starts_with("sk-")
        || value.starts_with("xoxb-")
        || value.starts_with("ghp_")
        || value.starts_with("AKIA")
        || value.contains("BEGIN PRIVATE KEY")
    {
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

    if manifest.adapter_id() != installation.manifest_ref().adapter_id() {
        return Err(RegistryError::ManifestAdapterMismatch {
            adapter_id: installation.adapter_id().clone(),
            manifest_adapter_id: installation.manifest_ref().adapter_id().clone(),
        });
    }
    if let (Some(registered), Some(referenced)) = (
        manifest.manifest_hash(),
        installation.manifest_ref().manifest_hash(),
    ) && registered != referenced
    {
        return Err(RegistryError::ManifestHashMismatch {
            adapter_id: installation.adapter_id().clone(),
        });
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
