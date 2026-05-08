//! Tenant-scoped secret service boundary for IronClaw Reborn.
//!
//! This crate stores and leases secret material behind opaque
//! [`SecretHandle`] values. It does not decide authorization, inject secrets into
//! runtimes, emit audit records, or expose raw values through metadata. Runtime
//! injection is not enforced until a higher-level obligation-handler/runtime
//! composition slice consumes these primitives.

mod crypto;
mod legacy_store;

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
pub use crypto::SecretsCrypto;
use ironclaw_host_api::{
    AgentId, CapabilityId, ExtensionId, InvocationId, MissionId, NetworkMethod, ProjectId,
    ResourceScope, SecretHandle, TenantId, ThreadId, Timestamp, UserId,
};
pub use legacy_store::{
    CreateSecretParams, DecryptedSecret, InMemorySecretsStore, Secret, SecretConsumeResult,
    SecretError, SecretRef, SecretsStore,
};
pub use secrecy::SecretString as SecretMaterial;
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

/// Opaque identifier for a one-shot secret lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretLeaseId(Uuid);

impl SecretLeaseId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SecretLeaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SecretLeaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Redacted metadata for a stored secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMetadata {
    pub scope: ResourceScope,
    pub handle: SecretHandle,
}

/// Lease lifecycle for one secret access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretLeaseStatus {
    Active,
    Consumed,
    Revoked,
}

/// Metadata for a scoped one-shot secret lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretLease {
    pub id: SecretLeaseId,
    pub scope: ResourceScope,
    pub handle: SecretHandle,
    pub status: SecretLeaseStatus,
}

/// Secret service failures. Variants intentionally avoid secret material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SecretStoreError {
    #[error("unknown secret {handle} for tenant/user scope")]
    UnknownSecret {
        scope: Box<ResourceScope>,
        handle: SecretHandle,
    },
    #[error("unknown secret lease {lease_id} for tenant/user scope")]
    UnknownLease {
        scope: Box<ResourceScope>,
        lease_id: SecretLeaseId,
    },
    #[error("secret lease {lease_id} was already consumed")]
    LeaseConsumed { lease_id: SecretLeaseId },
    #[error("secret lease {lease_id} was revoked")]
    LeaseRevoked { lease_id: SecretLeaseId },
    #[error("secret store state is unavailable: {reason}")]
    StoreUnavailable { reason: String },
}

impl SecretStoreError {
    pub fn stable_reason(&self) -> &'static str {
        match self {
            Self::UnknownSecret { .. } => "MissingCredential",
            Self::UnknownLease { .. } => "MissingCredential",
            Self::LeaseConsumed { .. } => "CredentialExpired",
            Self::LeaseRevoked { .. } => "CredentialRevoked",
            Self::StoreUnavailable { .. } => "BackendUnavailable",
        }
    }

    pub fn is_unknown_secret(&self) -> bool {
        matches!(self, Self::UnknownSecret { .. })
    }

    pub fn is_unknown_lease(&self) -> bool {
        matches!(self, Self::UnknownLease { .. })
    }

    pub fn is_consumed(&self) -> bool {
        matches!(self, Self::LeaseConsumed { .. })
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::LeaseRevoked { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialAccountId(String);

impl CredentialAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialBrokerError> {
        let value = value.into();
        validate_credential_id("credential_account", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialSessionId(Uuid);

impl CredentialSessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CredentialSessionId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialAccountStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialPathPolicy {
    Exact(String),
    Prefix(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialTargetPolicy {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: CredentialPathPolicy,
    pub methods: Vec<NetworkMethod>,
}

impl CredentialTargetPolicy {
    pub fn matches(&self, method: &NetworkMethod, url: &str) -> bool {
        let Ok(parsed) = url::Url::parse(url) else {
            return false;
        };
        if self.scheme != parsed.scheme() {
            return false;
        }
        if !parsed
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(&self.host))
        {
            return false;
        }
        if self
            .port
            .is_some_and(|port| Some(port) != parsed.port_or_known_default())
        {
            return false;
        }
        if !self.methods.iter().any(|allowed| allowed == method) {
            return false;
        }
        match &self.path {
            CredentialPathPolicy::Exact(path) => parsed.path() == path,
            CredentialPathPolicy::Prefix(prefix) => path_matches_prefix(parsed.path(), prefix),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CredentialAccount {
    pub scope: ResourceScope,
    pub id: CredentialAccountId,
    pub provider_or_extension_id: ExtensionId,
    pub label: String,
    pub status: CredentialAccountStatus,
    pub secret_handles: Vec<SecretHandle>,
    pub allowed_targets: Vec<CredentialTargetPolicy>,
    pub redacted_metadata: Value,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSession {
    pub scope: ResourceScope,
    pub invocation_id: InvocationId,
    pub capability_id: CapabilityId,
    pub extension_id: ExtensionId,
    pub account_id: CredentialAccountId,
    pub secret_handles: Vec<SecretHandle>,
    pub allowed_targets: Vec<CredentialTargetPolicy>,
    pub expires_at: Option<Timestamp>,
    pub max_uses: Option<u64>,
    pub correlation_id: CredentialSessionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CredentialBrokerError {
    #[error("invalid credential account id {value}: {reason}")]
    InvalidAccountId { value: String, reason: String },
    #[error("missing credential account {account_id} for tenant/user scope")]
    MissingCredential { account_id: CredentialAccountId },
    #[error("credential account {account_id} does not match caller scope")]
    CredentialScopeMismatch { account_id: CredentialAccountId },
    #[error("credential account {account_id} is expired")]
    CredentialExpired { account_id: CredentialAccountId },
    #[error("credential account {account_id} is revoked")]
    CredentialRevoked { account_id: CredentialAccountId },
    #[error("credential account {account_id} is not allowed for requested extension")]
    CredentialExtensionMismatch { account_id: CredentialAccountId },
    #[error("credential account {account_id} is not allowed for requested target")]
    CredentialPolicyMismatch { account_id: CredentialAccountId },
}

impl CredentialBrokerError {
    pub fn stable_reason(&self) -> &'static str {
        match self {
            Self::InvalidAccountId { .. } => "MissingCredential",
            Self::MissingCredential { .. } => "MissingCredential",
            Self::CredentialScopeMismatch { .. } => "CredentialScopeMismatch",
            Self::CredentialExpired { .. } => "CredentialExpired",
            Self::CredentialRevoked { .. } => "CredentialRevoked",
            Self::CredentialExtensionMismatch { .. } => "CredentialPolicyMismatch",
            Self::CredentialPolicyMismatch { .. } => "CredentialPolicyMismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSessionRequest {
    pub scope: ResourceScope,
    pub invocation_id: InvocationId,
    pub capability_id: CapabilityId,
    pub extension_id: ExtensionId,
    pub account_id: CredentialAccountId,
    pub method: NetworkMethod,
    pub url: String,
    pub expires_at: Option<Timestamp>,
    pub max_uses: Option<u64>,
}

#[derive(Debug, Default)]
pub struct InMemoryCredentialBroker {
    accounts: Mutex<HashMap<CredentialAccountKey, CredentialAccount>>,
}

impl InMemoryCredentialBroker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_account(&self, account: CredentialAccount) -> Result<(), CredentialBrokerError> {
        self.accounts
            .lock()
            .map_err(|_| CredentialBrokerError::MissingCredential {
                account_id: account.id.clone(),
            })?
            .insert(
                CredentialAccountKey::new(&account.scope, &account.id),
                account,
            );
        Ok(())
    }

    pub fn create_session(
        &self,
        request: CredentialSessionRequest,
    ) -> Result<CredentialSession, CredentialBrokerError> {
        let accounts =
            self.accounts
                .lock()
                .map_err(|_| CredentialBrokerError::MissingCredential {
                    account_id: request.account_id.clone(),
                })?;
        let account = accounts
            .get(&CredentialAccountKey::new(
                &request.scope,
                &request.account_id,
            ))
            .ok_or_else(|| CredentialBrokerError::MissingCredential {
                account_id: request.account_id.clone(),
            })?;
        if CredentialAccountKey::new(&account.scope, &account.id)
            != CredentialAccountKey::new(&request.scope, &request.account_id)
        {
            return Err(CredentialBrokerError::CredentialScopeMismatch {
                account_id: request.account_id,
            });
        }
        if account.provider_or_extension_id != request.extension_id {
            return Err(CredentialBrokerError::CredentialExtensionMismatch {
                account_id: request.account_id,
            });
        }
        match account.status {
            CredentialAccountStatus::Active => {}
            CredentialAccountStatus::Expired => {
                return Err(CredentialBrokerError::CredentialExpired {
                    account_id: request.account_id,
                });
            }
            CredentialAccountStatus::Revoked => {
                return Err(CredentialBrokerError::CredentialRevoked {
                    account_id: request.account_id,
                });
            }
        }
        if !account
            .allowed_targets
            .iter()
            .any(|target| target.matches(&request.method, &request.url))
        {
            return Err(CredentialBrokerError::CredentialPolicyMismatch {
                account_id: request.account_id,
            });
        }
        Ok(CredentialSession {
            scope: request.scope,
            invocation_id: request.invocation_id,
            capability_id: request.capability_id,
            extension_id: request.extension_id,
            account_id: account.id.clone(),
            secret_handles: account.secret_handles.clone(),
            allowed_targets: account.allowed_targets.clone(),
            expires_at: request.expires_at,
            max_uses: request.max_uses,
            correlation_id: CredentialSessionId::new(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CredentialAccountKey {
    tenant_id: TenantId,
    user_id: UserId,
    agent_id: Option<AgentId>,
    project_id: Option<ProjectId>,
    account_id: CredentialAccountId,
}

impl CredentialAccountKey {
    fn new(scope: &ResourceScope, account_id: &CredentialAccountId) -> Self {
        Self {
            tenant_id: scope.tenant_id.clone(),
            user_id: scope.user_id.clone(),
            agent_id: scope.agent_id.clone(),
            project_id: scope.project_id.clone(),
            account_id: account_id.clone(),
        }
    }
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    let path = path.strip_suffix('/').unwrap_or(path);
    let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
    if path == prefix {
        return true;
    }
    if path.len() > prefix.len() && path.starts_with(prefix) {
        let next_char = path.as_bytes()[prefix.len()];
        return next_char == b'/';
    }
    false
}

fn validate_credential_id(kind: &'static str, value: &str) -> Result<(), CredentialBrokerError> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(CredentialBrokerError::InvalidAccountId {
            value: value.to_string(),
            reason: format!("{kind} must contain only ASCII letters, digits, '-' or '_"),
        });
    }
    Ok(())
}

/// Scoped secret store contract.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Stores or replaces a secret under the caller's tenant/user/project scope and returns redacted metadata.
    ///
    /// Intended for trusted setup, composition, migration, or storage-code paths that are already
    /// allowed to manage secret material. This low-level primitive intentionally does not authorize
    /// arbitrary runtime/plugin callers.
    async fn put(
        &self,
        scope: ResourceScope,
        handle: SecretHandle,
        material: SecretMaterial,
    ) -> Result<SecretMetadata, SecretStoreError>;

    /// Returns redacted metadata for a secret without exposing material.
    async fn metadata(
        &self,
        scope: &ResourceScope,
        handle: &SecretHandle,
    ) -> Result<Option<SecretMetadata>, SecretStoreError>;

    /// Creates a one-shot lease for later secret consumption.
    async fn lease_once(
        &self,
        scope: &ResourceScope,
        handle: &SecretHandle,
    ) -> Result<SecretLease, SecretStoreError>;

    /// Consumes an active one-shot lease and returns secret material exactly once.
    async fn consume(
        &self,
        scope: &ResourceScope,
        lease_id: SecretLeaseId,
    ) -> Result<SecretMaterial, SecretStoreError>;

    /// Revokes an active one-shot lease without returning material.
    async fn revoke(
        &self,
        scope: &ResourceScope,
        lease_id: SecretLeaseId,
    ) -> Result<SecretLease, SecretStoreError>;

    /// Lists leases visible to the caller's tenant/user/project scope.
    async fn leases_for_scope(
        &self,
        scope: &ResourceScope,
    ) -> Result<Vec<SecretLease>, SecretStoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SecretLeaseKey {
    tenant_id: TenantId,
    user_id: UserId,
    agent_id: Option<AgentId>,
    project_id: Option<ProjectId>,
    mission_id: Option<MissionId>,
    thread_id: Option<ThreadId>,
    invocation_id: InvocationId,
    lease_id: SecretLeaseId,
}

impl SecretLeaseKey {
    fn new(scope: &ResourceScope, lease_id: SecretLeaseId) -> Self {
        Self {
            tenant_id: scope.tenant_id.clone(),
            user_id: scope.user_id.clone(),
            agent_id: scope.agent_id.clone(),
            project_id: scope.project_id.clone(),
            mission_id: scope.mission_id.clone(),
            thread_id: scope.thread_id.clone(),
            invocation_id: scope.invocation_id,
            lease_id,
        }
    }

    fn matches_scope(&self, scope: &ResourceScope) -> bool {
        self.tenant_id == scope.tenant_id
            && self.user_id == scope.user_id
            && self.agent_id == scope.agent_id
            && self.project_id == scope.project_id
            && self.mission_id == scope.mission_id
            && self.thread_id == scope.thread_id
            && self.invocation_id == scope.invocation_id
    }
}

#[derive(Debug, Clone)]
struct LeaseRecord {
    lease: SecretLease,
    material: Option<SecretMaterial>,
}

/// Adapter that exposes the battle-tested encrypted [`SecretsStore`] contract
/// through the scoped Reborn [`SecretStore`] lease boundary.
#[derive(Debug)]
pub struct ScopedSecretsStoreAdapter<S> {
    inner: Arc<S>,
    leases: Mutex<HashMap<SecretLeaseKey, LeaseRecord>>,
}

impl<S> ScopedSecretsStoreAdapter<S>
where
    S: SecretsStore + 'static,
{
    pub fn new(inner: Arc<S>) -> Self {
        Self {
            inner,
            leases: Mutex::new(HashMap::new()),
        }
    }

    fn lock_leases(
        &self,
    ) -> Result<MutexGuard<'_, HashMap<SecretLeaseKey, LeaseRecord>>, SecretStoreError> {
        self.leases
            .lock()
            .map_err(|error| SecretStoreError::StoreUnavailable {
                reason: error.to_string(),
            })
    }
}

fn scoped_legacy_user_id(scope: &ResourceScope) -> String {
    serde_json::json!({
        "tenant_id": scope.tenant_id.to_string(),
        "user_id": scope.user_id.to_string(),
        "agent_id": scope.agent_id.as_ref().map(ToString::to_string),
        "project_id": scope.project_id.as_ref().map(ToString::to_string),
    })
    .to_string()
}

#[async_trait]
impl<S> SecretStore for ScopedSecretsStoreAdapter<S>
where
    S: SecretsStore + 'static,
{
    async fn put(
        &self,
        scope: ResourceScope,
        handle: SecretHandle,
        material: SecretMaterial,
    ) -> Result<SecretMetadata, SecretStoreError> {
        self.inner
            .create(
                &scoped_legacy_user_id(&scope),
                CreateSecretParams::from_secret(handle.to_string(), material),
            )
            .await
            .map_err(map_legacy_secret_error)?;
        Ok(SecretMetadata { scope, handle })
    }

    async fn metadata(
        &self,
        scope: &ResourceScope,
        handle: &SecretHandle,
    ) -> Result<Option<SecretMetadata>, SecretStoreError> {
        match self
            .inner
            .get(&scoped_legacy_user_id(scope), handle.as_str())
            .await
        {
            Ok(_) => Ok(Some(SecretMetadata {
                scope: scope.clone(),
                handle: handle.clone(),
            })),
            Err(SecretError::NotFound(_)) => Ok(None),
            Err(error) => Err(map_legacy_secret_error(error)),
        }
    }

    async fn lease_once(
        &self,
        scope: &ResourceScope,
        handle: &SecretHandle,
    ) -> Result<SecretLease, SecretStoreError> {
        let material = self
            .inner
            .get_decrypted(&scoped_legacy_user_id(scope), handle.as_str())
            .await
            .map_err(|error| match error {
                SecretError::NotFound(_) => SecretStoreError::UnknownSecret {
                    scope: Box::new(scope.clone()),
                    handle: handle.clone(),
                },
                other => map_legacy_secret_error(other),
            })?;
        let lease = SecretLease {
            id: SecretLeaseId::new(),
            scope: scope.clone(),
            handle: handle.clone(),
            status: SecretLeaseStatus::Active,
        };
        self.lock_leases()?.insert(
            SecretLeaseKey::new(scope, lease.id),
            LeaseRecord {
                lease: lease.clone(),
                material: Some(SecretMaterial::from(material.expose().to_string())),
            },
        );
        Ok(lease)
    }

    async fn consume(
        &self,
        scope: &ResourceScope,
        lease_id: SecretLeaseId,
    ) -> Result<SecretMaterial, SecretStoreError> {
        let mut leases = self.lock_leases()?;
        let key = SecretLeaseKey::new(scope, lease_id);
        let record = leases
            .get_mut(&key)
            .ok_or_else(|| SecretStoreError::UnknownLease {
                scope: Box::new(scope.clone()),
                lease_id,
            })?;
        match record.lease.status {
            SecretLeaseStatus::Active => {
                let Some(material) = record.material.take() else {
                    record.lease.status = SecretLeaseStatus::Consumed;
                    return Err(SecretStoreError::StoreUnavailable {
                        reason: "active lease material unavailable".to_string(),
                    });
                };
                record.lease.status = SecretLeaseStatus::Consumed;
                Ok(material)
            }
            SecretLeaseStatus::Consumed => Err(SecretStoreError::LeaseConsumed { lease_id }),
            SecretLeaseStatus::Revoked => Err(SecretStoreError::LeaseRevoked { lease_id }),
        }
    }

    async fn revoke(
        &self,
        scope: &ResourceScope,
        lease_id: SecretLeaseId,
    ) -> Result<SecretLease, SecretStoreError> {
        let mut leases = self.lock_leases()?;
        let key = SecretLeaseKey::new(scope, lease_id);
        let record = leases
            .get_mut(&key)
            .ok_or_else(|| SecretStoreError::UnknownLease {
                scope: Box::new(scope.clone()),
                lease_id,
            })?;
        if record.lease.status == SecretLeaseStatus::Active {
            record.material = None;
            record.lease.status = SecretLeaseStatus::Revoked;
        }
        Ok(record.lease.clone())
    }

    async fn leases_for_scope(
        &self,
        scope: &ResourceScope,
    ) -> Result<Vec<SecretLease>, SecretStoreError> {
        Ok(self
            .lock_leases()?
            .iter()
            .filter(|(key, _)| key.matches_scope(scope))
            .map(|(_, record)| record.lease.clone())
            .collect())
    }
}

fn map_legacy_secret_error(error: SecretError) -> SecretStoreError {
    match error {
        SecretError::NotFound(name) => SecretStoreError::StoreUnavailable {
            reason: format!("legacy secret missing: {name}"),
        },
        SecretError::Expired => SecretStoreError::StoreUnavailable {
            reason: "legacy secret expired".to_string(),
        },
        SecretError::InvalidMasterKey => SecretStoreError::StoreUnavailable {
            reason: "legacy secrets master key unavailable".to_string(),
        },
        SecretError::AccessDenied => SecretStoreError::StoreUnavailable {
            reason: "legacy secret access denied".to_string(),
        },
        SecretError::InvalidUtf8
        | SecretError::Database(_)
        | SecretError::DecryptionFailed(_)
        | SecretError::EncryptionFailed(_)
        | SecretError::KeychainError(_) => SecretStoreError::StoreUnavailable {
            reason: error.to_string(),
        },
    }
}

/// In-memory secret store for contract tests and non-durable demos.
///
/// This is a thin encrypted adapter over the ported legacy [`InMemorySecretsStore`];
/// it intentionally does not keep a second raw-material store implementation.
#[derive(Debug)]
pub struct InMemorySecretStore {
    inner: ScopedSecretsStoreAdapter<InMemorySecretsStore>,
}

impl InMemorySecretStore {
    pub fn new() -> Self {
        let crypto = Arc::new(SecretsCrypto::from_valid_master_key_literal(
            "0123456789abcdef0123456789abcdef",
        ));
        Self {
            inner: ScopedSecretsStoreAdapter::new(Arc::new(InMemorySecretsStore::new(crypto))),
        }
    }
}

impl Default for InMemorySecretStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretStore for InMemorySecretStore {
    async fn put(
        &self,
        scope: ResourceScope,
        handle: SecretHandle,
        material: SecretMaterial,
    ) -> Result<SecretMetadata, SecretStoreError> {
        self.inner.put(scope, handle, material).await
    }

    async fn metadata(
        &self,
        scope: &ResourceScope,
        handle: &SecretHandle,
    ) -> Result<Option<SecretMetadata>, SecretStoreError> {
        self.inner.metadata(scope, handle).await
    }

    async fn lease_once(
        &self,
        scope: &ResourceScope,
        handle: &SecretHandle,
    ) -> Result<SecretLease, SecretStoreError> {
        self.inner.lease_once(scope, handle).await
    }

    async fn consume(
        &self,
        scope: &ResourceScope,
        lease_id: SecretLeaseId,
    ) -> Result<SecretMaterial, SecretStoreError> {
        self.inner.consume(scope, lease_id).await
    }

    async fn revoke(
        &self,
        scope: &ResourceScope,
        lease_id: SecretLeaseId,
    ) -> Result<SecretLease, SecretStoreError> {
        self.inner.revoke(scope, lease_id).await
    }

    async fn leases_for_scope(
        &self,
        scope: &ResourceScope,
    ) -> Result<Vec<SecretLease>, SecretStoreError> {
        self.inner.leases_for_scope(scope).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use ironclaw_host_api::{
        AgentId, CapabilityId, ExtensionId, InvocationId, MissionId, NetworkMethod, ProjectId,
        ResourceScope, SecretHandle, TenantId, ThreadId, UserId,
    };
    use secrecy::ExposeSecret;
    use serde_json::json;

    use crate::{
        CredentialAccount, CredentialAccountId, CredentialAccountStatus, CredentialBrokerError,
        CredentialPathPolicy, CredentialSessionRequest, CredentialTargetPolicy,
        InMemoryCredentialBroker, InMemorySecretStore, InMemorySecretsStore,
        ScopedSecretsStoreAdapter, SecretMaterial, SecretStore, SecretStoreError, SecretsCrypto,
        SecretsStore, scoped_legacy_user_id,
    };

    #[test]
    fn scoped_legacy_user_id_uses_unambiguous_json_encoding() {
        let none_agent = sample_scope("tenant-a", "user-a");
        let dash_agent = ResourceScope {
            agent_id: Some(AgentId::new("-").unwrap()),
            ..none_agent.clone()
        };
        let delimiter_scope = sample_scope("tenant=a;agent=-", "user=a;project=-");

        assert_ne!(
            scoped_legacy_user_id(&none_agent),
            scoped_legacy_user_id(&dash_agent)
        );
        assert_ne!(
            scoped_legacy_user_id(&none_agent),
            scoped_legacy_user_id(&delimiter_scope)
        );
        assert!(scoped_legacy_user_id(&none_agent).contains("\"agent_id\":null"));
    }

    #[test]
    fn credential_target_policy_matches_scheme_host_port_path_and_method() {
        let policy = CredentialTargetPolicy {
            scheme: "https".to_string(),
            host: "api.example.com".to_string(),
            port: Some(443),
            path: CredentialPathPolicy::Prefix("/v1/".to_string()),
            methods: vec![NetworkMethod::Get],
        };

        assert!(policy.matches(&NetworkMethod::Get, "https://api.example.com/v1/models"));
        assert!(policy.matches(&NetworkMethod::Get, "https://api.example.com:443/v1/models"));
        assert!(!policy.matches(
            &NetworkMethod::Get,
            "https://api.example.com:8443/v1/models"
        ));
        assert!(!policy.matches(&NetworkMethod::Post, "https://api.example.com/v1/models"));
        assert!(!policy.matches(&NetworkMethod::Get, "https://api.example.com/v2/models"));
        assert!(!policy.matches(
            &NetworkMethod::Get,
            "https://api.example.com/v1-evil/models"
        ));
        assert!(!policy.matches(&NetworkMethod::Get, "http://api.example.com/v1/models"));
        assert!(!policy.matches(&NetworkMethod::Get, "https://evil.example.com/v1/models"));

        let policy_without_port_constraint = CredentialTargetPolicy {
            port: None,
            ..policy
        };
        assert!(
            policy_without_port_constraint
                .matches(&NetworkMethod::Get, "https://api.example.com/v1/models")
        );
        assert!(policy_without_port_constraint.matches(
            &NetworkMethod::Get,
            "https://api.example.com:8443/v1/models"
        ));
    }

    #[test]
    fn credential_session_creation_requires_explicit_scoped_account_and_redacts_material() {
        let broker = InMemoryCredentialBroker::new();
        let scope = sample_scope("tenant-a", "user-a");
        let account_id = CredentialAccountId::new("openai_prod").unwrap();
        let secret_handle = SecretHandle::new("openai_key").unwrap();
        broker
            .put_account(sample_account(
                scope.clone(),
                account_id.clone(),
                secret_handle.clone(),
            ))
            .unwrap();

        let session = broker
            .create_session(CredentialSessionRequest {
                scope: scope.clone(),
                invocation_id: scope.invocation_id,
                capability_id: CapabilityId::new("openai.chat").unwrap(),
                extension_id: ExtensionId::new("openai").unwrap(),
                account_id,
                method: NetworkMethod::Get,
                url: "https://api.example.com/v1/models".to_string(),
                expires_at: None,
                max_uses: Some(1),
            })
            .unwrap();

        assert_eq!(session.scope, scope);
        assert_eq!(session.secret_handles, vec![secret_handle]);
        let debug = format!("{session:?}");
        assert!(!debug.contains("sk-live-sentinel"));
        assert!(!debug.contains("token"));
    }

    #[test]
    fn credential_session_creation_accepts_project_scoped_account_across_invocations() {
        let broker = InMemoryCredentialBroker::new();
        let account_scope = sample_scope("tenant-a", "user-a");
        let request_scope = ResourceScope {
            mission_id: Some(MissionId::new("mission-b").unwrap()),
            thread_id: Some(ThreadId::new("thread-b").unwrap()),
            invocation_id: InvocationId::new(),
            ..account_scope.clone()
        };
        let account_id = CredentialAccountId::new("openai_prod").unwrap();
        let secret_handle = SecretHandle::new("openai_key").unwrap();
        broker
            .put_account(sample_account(
                account_scope,
                account_id.clone(),
                secret_handle.clone(),
            ))
            .unwrap();

        let session = broker
            .create_session(session_request(
                request_scope.clone(),
                account_id,
                "https://api.example.com/v1/models",
            ))
            .unwrap();

        assert_eq!(session.scope, request_scope);
        assert_eq!(session.secret_handles, vec![secret_handle]);
    }

    #[test]
    fn credential_session_creation_denies_missing_cross_scope_revoked_and_policy_mismatch() {
        let broker = InMemoryCredentialBroker::new();
        let scope = sample_scope("tenant-a", "user-a");
        let other_scope = sample_scope("tenant-b", "user-b");
        let account_id = CredentialAccountId::new("github_prod").unwrap();
        let secret_handle = SecretHandle::new("github_key").unwrap();
        broker
            .put_account(sample_account(
                scope.clone(),
                account_id.clone(),
                secret_handle,
            ))
            .unwrap();

        let missing = broker.create_session(session_request(
            scope.clone(),
            CredentialAccountId::new("missing").unwrap(),
            "https://api.example.com/v1/models",
        ));
        assert!(matches!(
            missing,
            Err(CredentialBrokerError::MissingCredential { .. })
        ));

        let cross_scope = broker.create_session(session_request(
            other_scope,
            account_id.clone(),
            "https://api.example.com/v1/models",
        ));
        assert!(matches!(
            cross_scope,
            Err(CredentialBrokerError::MissingCredential { .. })
        ));

        let policy_mismatch = broker.create_session(session_request(
            scope.clone(),
            account_id.clone(),
            "https://api.example.com/v2/models",
        ));
        assert!(matches!(
            policy_mismatch,
            Err(CredentialBrokerError::CredentialPolicyMismatch { .. })
        ));

        let extension_mismatch = broker.create_session(CredentialSessionRequest {
            extension_id: ExtensionId::new("other_extension").unwrap(),
            ..session_request(
                scope.clone(),
                account_id.clone(),
                "https://api.example.com/v1/models",
            )
        });
        assert!(matches!(
            extension_mismatch,
            Err(CredentialBrokerError::CredentialExtensionMismatch { .. })
        ));

        let revoked_id = CredentialAccountId::new("github_revoked").unwrap();
        let mut revoked = sample_account(
            scope.clone(),
            revoked_id.clone(),
            SecretHandle::new("github_revoked_key").unwrap(),
        );
        revoked.status = CredentialAccountStatus::Revoked;
        broker.put_account(revoked).unwrap();
        let revoked_result = broker.create_session(session_request(
            scope,
            revoked_id,
            "https://api.example.com/v1/models",
        ));
        assert!(matches!(
            revoked_result,
            Err(CredentialBrokerError::CredentialRevoked { .. })
        ));
    }

    #[tokio::test]
    async fn scoped_adapter_reuses_encrypted_legacy_store_for_scoped_leases() {
        let crypto = Arc::new(
            SecretsCrypto::new(SecretMaterial::from(
                "0123456789abcdef0123456789abcdef".to_string(),
            ))
            .unwrap(),
        );
        let legacy = Arc::new(InMemorySecretsStore::new(crypto));
        let adapter = ScopedSecretsStoreAdapter::new(Arc::clone(&legacy));
        let scope = sample_scope("tenant-a", "user-a");
        let other_scope = sample_scope("tenant-b", "user-a");
        let handle = SecretHandle::new("api_key").unwrap();

        adapter
            .put(
                scope.clone(),
                handle.clone(),
                SecretMaterial::from("sk-live-sentinel".to_string()),
            )
            .await
            .unwrap();

        assert!(adapter.metadata(&scope, &handle).await.unwrap().is_some());
        assert!(
            adapter
                .metadata(&other_scope, &handle)
                .await
                .unwrap()
                .is_none()
        );
        let legacy_debug = format!(
            "{:?}",
            legacy
                .get(&scoped_legacy_user_id(&scope), handle.as_str())
                .await
                .unwrap()
        );
        assert!(!legacy_debug.contains("sk-live-sentinel"));

        let lease = adapter.lease_once(&scope, &handle).await.unwrap();
        let material = adapter.consume(&scope, lease.id).await.unwrap();
        assert_eq!(material.expose_secret(), "sk-live-sentinel");
        let second_consume = adapter.consume(&scope, lease.id).await;
        assert!(matches!(
            second_consume,
            Err(SecretStoreError::LeaseConsumed { .. })
        ));
    }

    #[tokio::test]
    async fn consumed_lease_record_drops_retained_material() {
        let store = InMemorySecretStore::new();
        let scope = sample_scope("tenant-a", "user-a");
        let handle = SecretHandle::new("api_key").unwrap();
        store
            .put(
                scope.clone(),
                handle.clone(),
                SecretMaterial::from("super-secret"),
            )
            .await
            .unwrap();

        let lease = store.lease_once(&scope, &handle).await.unwrap();
        store.consume(&scope, lease.id).await.unwrap();

        let leases_debug = format!("{store:?}");
        assert!(
            !leases_debug.contains("SecretBox"),
            "consumed lease records must not retain cloned secret material: {leases_debug}"
        );
    }

    #[tokio::test]
    async fn revoked_lease_record_drops_retained_material() {
        let store = InMemorySecretStore::new();
        let scope = sample_scope("tenant-a", "user-a");
        let handle = SecretHandle::new("api_key").unwrap();
        store
            .put(
                scope.clone(),
                handle.clone(),
                SecretMaterial::from("super-secret"),
            )
            .await
            .unwrap();

        let lease = store.lease_once(&scope, &handle).await.unwrap();
        store.revoke(&scope, lease.id).await.unwrap();

        let leases_debug = format!("{store:?}");
        assert!(
            !leases_debug.contains("SecretBox"),
            "revoked lease records must not retain cloned secret material: {leases_debug}"
        );
    }

    fn sample_account(
        scope: ResourceScope,
        id: CredentialAccountId,
        secret_handle: SecretHandle,
    ) -> CredentialAccount {
        CredentialAccount {
            scope,
            id,
            provider_or_extension_id: ExtensionId::new("openai").unwrap(),
            label: "Production".to_string(),
            status: CredentialAccountStatus::Active,
            secret_handles: vec![secret_handle],
            allowed_targets: vec![CredentialTargetPolicy {
                scheme: "https".to_string(),
                host: "api.example.com".to_string(),
                port: Some(443),
                path: CredentialPathPolicy::Prefix("/v1/".to_string()),
                methods: vec![NetworkMethod::Get],
            }],
            redacted_metadata: json!({ "last_four": "1234" }),
            updated_at: Utc::now(),
        }
    }

    fn session_request(
        scope: ResourceScope,
        account_id: CredentialAccountId,
        url: &str,
    ) -> CredentialSessionRequest {
        CredentialSessionRequest {
            invocation_id: scope.invocation_id,
            scope,
            capability_id: CapabilityId::new("openai.chat").unwrap(),
            extension_id: ExtensionId::new("openai").unwrap(),
            account_id,
            method: NetworkMethod::Get,
            url: url.to_string(),
            expires_at: None,
            max_uses: Some(1),
        }
    }

    fn sample_scope(tenant: &str, user: &str) -> ResourceScope {
        ResourceScope {
            tenant_id: TenantId::new(tenant).unwrap(),
            user_id: UserId::new(user).unwrap(),
            agent_id: None,
            project_id: Some(ProjectId::new("project-a").unwrap()),
            mission_id: Some(MissionId::new("mission-a").unwrap()),
            thread_id: Some(ThreadId::new("thread-a").unwrap()),
            invocation_id: InvocationId::new(),
        }
    }
}
