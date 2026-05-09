#![cfg(any(feature = "libsql", feature = "postgres"))]

use std::sync::Arc;

#[cfg(feature = "libsql")]
use ironclaw_secrets::LibSqlSecretsStore;
#[cfg(feature = "postgres")]
use ironclaw_secrets::PostgresSecretsStore;
use ironclaw_secrets::{
    CreateSecretParams, SecretError, SecretMaterial, SecretsCrypto, SecretsStore,
};

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_secret_store_persists_encrypted_secret_material_across_reopen() {
    let dir = tempfile::tempdir().unwrap().keep();
    let db_path = dir.join("secrets.db");
    let crypto = test_crypto();
    let store = libsql_store(&db_path, Arc::clone(&crypto)).await;

    store
        .create(
            "reborn-user",
            CreateSecretParams::new("openai_key", "sk-live-reborn-secret-sentinel"),
        )
        .await
        .unwrap();
    drop(store);

    let raw_database = String::from_utf8_lossy(&std::fs::read(&db_path).unwrap()).to_string();
    assert!(
        !raw_database.contains("sk-live-reborn-secret-sentinel"),
        "raw secret material must be encrypted at rest"
    );

    let reopened = libsql_store(&db_path, crypto).await;
    let decrypted = reopened
        .get_decrypted("reborn-user", "openai_key")
        .await
        .unwrap();
    assert_eq!(decrypted.expose(), "sk-live-reborn-secret-sentinel");
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_secret_store_verify_can_decrypt_existing_secrets_rejects_wrong_key() {
    let dir = tempfile::tempdir().unwrap().keep();
    let db_path = dir.join("secrets.db");
    let store = libsql_store(&db_path, test_crypto()).await;

    store
        .create(
            "reborn-user",
            CreateSecretParams::new("openai_key", "sk-live-wrong-key-sentinel"),
        )
        .await
        .unwrap();
    drop(store);

    let wrong_crypto = Arc::new(
        SecretsCrypto::new(SecretMaterial::from(
            "abcdef0123456789abcdef0123456789".to_string(),
        ))
        .unwrap(),
    );
    let reopened = libsql_store(&db_path, wrong_crypto).await;
    let error = reopened
        .verify_can_decrypt_existing_secrets()
        .await
        .expect_err("wrong key must fail existing row decryptability check");
    assert!(matches!(error, SecretError::DecryptionFailed(_)));
    assert!(!format!("{error:?}").contains("sk-live-wrong-key-sentinel"));
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_secret_store_consume_if_matches_is_one_shot_and_durable() {
    let dir = tempfile::tempdir().unwrap().keep();
    let db_path = dir.join("secrets.db");
    let crypto = test_crypto();
    let store = libsql_store(&db_path, Arc::clone(&crypto)).await;

    store
        .create(
            "reborn-user",
            CreateSecretParams::new("oauth_state", "state-secret-sentinel"),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .consume_if_matches("reborn-user", "oauth_state", "wrong")
            .await
            .unwrap(),
        ironclaw_secrets::SecretConsumeResult::Mismatched
    );
    assert_eq!(
        store
            .consume_if_matches("reborn-user", "oauth_state", "state-secret-sentinel")
            .await
            .unwrap(),
        ironclaw_secrets::SecretConsumeResult::Matched
    );
    drop(store);

    let reopened = libsql_store(&db_path, crypto).await;
    assert!(!reopened.exists("reborn-user", "oauth_state").await.unwrap());
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_secret_store_persists_encrypted_secret_material_when_database_url_is_set() {
    let Some(store) = postgres_store().await else {
        return;
    };
    let suffix = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let user_id = format!("reborn-user-{suffix}");
    let secret_name = format!("openai_key_{suffix}");

    store
        .create(
            &user_id,
            CreateSecretParams::new(&secret_name, "sk-live-postgres-reborn-secret-sentinel"),
        )
        .await
        .unwrap();
    let decrypted = store.get_decrypted(&user_id, &secret_name).await.unwrap();
    assert_eq!(
        decrypted.expose(),
        "sk-live-postgres-reborn-secret-sentinel"
    );
}

#[cfg(feature = "libsql")]
async fn libsql_store(path: &std::path::Path, crypto: Arc<SecretsCrypto>) -> LibSqlSecretsStore {
    let db = Arc::new(libsql::Builder::new_local(path).build().await.unwrap());
    let store = LibSqlSecretsStore::new(db, crypto);
    store.run_migrations().await.unwrap();
    store
}

#[cfg(feature = "postgres")]
async fn postgres_store() -> Option<PostgresSecretsStore> {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping Postgres secret store contract: DATABASE_URL is not set");
        return None;
    };
    let config: tokio_postgres::Config = database_url
        .parse()
        .expect("DATABASE_URL must parse as a Postgres connection string");
    let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
    let pool = deadpool_postgres::Pool::builder(manager)
        .max_size(4)
        .build()
        .expect("Postgres pool must build");
    let store = PostgresSecretsStore::new(pool, test_crypto());
    store
        .run_migrations()
        .await
        .expect("DATABASE_URL must point at a reachable Postgres test database");
    Some(store)
}

fn test_crypto() -> Arc<SecretsCrypto> {
    Arc::new(
        SecretsCrypto::new(SecretMaterial::from(
            "0123456789abcdef0123456789abcdef".to_string(),
        ))
        .unwrap(),
    )
}
