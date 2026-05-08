use std::{fmt, sync::Arc};

use ironclaw_secrets::{
    LibSqlSecretsStore, ScopedSecretsStoreAdapter, SecretError, SecretMaterial, SecretStore,
    SecretsCrypto,
};

/// Explicit standalone-Reborn secret store configuration.
///
/// Reborn does not auto-generate a durable master key. Production composition
/// must pass operator-controlled key material so encrypted rows remain
/// decryptable across restarts, matching v1's encrypted-at-rest invariant.
pub struct RebornLibSqlSecretStoreConfig {
    pub database: Arc<libsql::Database>,
    pub master_key: Option<SecretMaterial>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebornSecretStoreHealth {
    pub status: RebornSecretStoreHealthStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebornSecretStoreHealthStatus {
    Ready,
    MissingMasterKey,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebornSecretStoreError {
    MissingMasterKey,
    InvalidMasterKey,
    BackendUnavailable { reason: String },
}

impl fmt::Display for RebornSecretStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMasterKey => formatter
                .write_str("reborn secret store requires an explicit operator-provided master key"),
            Self::InvalidMasterKey => {
                formatter.write_str("reborn secret store master key is invalid")
            }
            Self::BackendUnavailable { reason } => {
                write!(
                    formatter,
                    "reborn secret store backend unavailable: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for RebornSecretStoreError {}

pub async fn check_libsql_reborn_secret_store_health(
    config: RebornLibSqlSecretStoreConfig,
) -> RebornSecretStoreHealth {
    match build_libsql_reborn_secret_store(config).await {
        Ok(_) => RebornSecretStoreHealth {
            status: RebornSecretStoreHealthStatus::Ready,
            reason: None,
        },
        Err(RebornSecretStoreError::MissingMasterKey) => RebornSecretStoreHealth {
            status: RebornSecretStoreHealthStatus::MissingMasterKey,
            reason: Some("explicit operator master key is required".to_string()),
        },
        Err(error) => RebornSecretStoreHealth {
            status: RebornSecretStoreHealthStatus::Unavailable,
            reason: Some(error.to_string()),
        },
    }
}

pub async fn build_libsql_reborn_secret_store(
    config: RebornLibSqlSecretStoreConfig,
) -> Result<Arc<dyn SecretStore>, RebornSecretStoreError> {
    let master_key = config
        .master_key
        .ok_or(RebornSecretStoreError::MissingMasterKey)?;
    let crypto = Arc::new(SecretsCrypto::new(master_key).map_err(|error| match error {
        SecretError::InvalidMasterKey => RebornSecretStoreError::InvalidMasterKey,
        other => RebornSecretStoreError::BackendUnavailable {
            reason: other.to_string(),
        },
    })?);
    let backend = Arc::new(LibSqlSecretsStore::new(config.database, crypto));
    backend
        .run_migrations()
        .await
        .map_err(map_secret_store_error)?;
    backend
        .verify_can_decrypt_existing_secrets()
        .await
        .map_err(map_secret_store_error)?;
    Ok(Arc::new(ScopedSecretsStoreAdapter::new(backend)))
}

fn map_secret_store_error(error: SecretError) -> RebornSecretStoreError {
    match error {
        SecretError::InvalidMasterKey => RebornSecretStoreError::InvalidMasterKey,
        other => RebornSecretStoreError::BackendUnavailable {
            reason: other.to_string(),
        },
    }
}
