//! Proof-of-concept tests for the security review of `ironclaw_secrets`.
//!
//! Each `#[test]` here is a failing test that demonstrates a real finding from
//! the 2026-05 review. They live together so the fixes can land alongside
//! green-on-red evidence. Once a finding is fixed, the matching PoC asserts
//! the new invariant rather than removing the test.
//!
//! Findings covered in this file:
//!
//! - **H3** — `reborn_secret_records` rows have no AAD/post-decrypt binding
//!   between ciphertext and `(user_id, name)`. A DB-write adversary can swap
//!   `(encrypted_value, key_salt)` between two rows and `get_decrypted` will
//!   silently return the wrong plaintext.
//! - **M1** — `CredentialSessionId` `Display` emits the raw UUID despite
//!   `Debug` being redacted, so `format!("{id}")` in a log line leaks the
//!   bearer-like value.
//! - **M2** — `SecretsCrypto::new` accepts low-entropy 32-byte master keys
//!   (e.g. 32 zero bytes), making captured ciphertext brute-forceable when
//!   an operator copy-pastes a weak key.

use ironclaw_secrets::{CredentialSessionId, SecretError, SecretMaterial, SecretsCrypto};

#[cfg(feature = "libsql")]
use std::sync::Arc;

#[cfg(feature = "libsql")]
use ironclaw_secrets::{CreateSecretParams, LibSqlSecretsStore, SecretsStore};

// ---------------------------------------------------------------------------
// H3 — row-swap returns the wrong plaintext
// ---------------------------------------------------------------------------

/// **Finding H3.** AES-GCM ciphertext in `reborn_secret_records` is not bound
/// to `(user_id, name)` via additional-authenticated-data or a post-decrypt
/// scope check. An attacker with DB write access (SQL injection elsewhere,
/// compromised replication, admin-with-DB-only-access, etc.) can swap the
/// `(encrypted_value, key_salt)` columns between two rows. The crypto layer
/// has no signal that anything is wrong, so `get_decrypted("low_priv_key")`
/// returns the plaintext that was originally stored under
/// `high_priv_admin_token`.
///
/// The same-user case shown here proves the bug with the minimum setup; the
/// cross-tenant variant (different `user_id` values) is structurally identical
/// because `scoped_legacy_user_id` is itself just another plaintext column.
///
/// Expected behavior after the fix (AES-GCM AAD = scope-key || handle, or an
/// embedded handle inside the encrypted payload that is verified post-decrypt):
/// the lookup either fails outright or returns the original plaintext bound
/// to the row, never the other row's value.
#[cfg(feature = "libsql")]
#[tokio::test]
async fn h3_libsql_secret_row_swap_must_not_return_other_rows_plaintext() {
    let dir = tempfile::tempdir().unwrap().keep();
    let db_path = dir.join("secrets.db");
    let crypto = h3_test_crypto();
    let database = Arc::new(libsql::Builder::new_local(&db_path).build().await.unwrap());
    let store = LibSqlSecretsStore::new(Arc::clone(&database), Arc::clone(&crypto));
    store.run_migrations().await.unwrap();

    let user_id = "tenant-A.user-A";
    let low_priv_plaintext = "PLAIN_A_low_privilege_read_only_token";
    let high_priv_plaintext = "PLAIN_B_admin_root_token";

    store
        .create(
            user_id,
            CreateSecretParams::new("low_priv_key", low_priv_plaintext),
        )
        .await
        .unwrap();
    store
        .create(
            user_id,
            CreateSecretParams::new("high_priv_admin_token", high_priv_plaintext),
        )
        .await
        .unwrap();

    // Simulate an attacker with DB write swapping the ciphertext columns
    // between the two rows. Note that `low_priv_key` keeps its row identity
    // (same user_id, same name, same id) — only the encrypted_value and
    // key_salt are taken from the other row.
    let conn = database.connect().unwrap();
    let mut rows = conn
        .query(
            "SELECT encrypted_value, key_salt FROM reborn_secret_records \
             WHERE user_id = ?1 AND name = ?2",
            libsql::params![user_id, "high_priv_admin_token"],
        )
        .await
        .unwrap();
    let row = rows.next().await.unwrap().expect("high-priv row exists");
    let admin_encrypted: Vec<u8> = row.get(0).unwrap();
    let admin_salt: Vec<u8> = row.get(1).unwrap();

    conn.execute(
        "UPDATE reborn_secret_records SET encrypted_value = ?1, key_salt = ?2 \
         WHERE user_id = ?3 AND name = ?4",
        libsql::params![admin_encrypted, admin_salt, user_id, "low_priv_key"],
    )
    .await
    .unwrap();

    // The fix must reject this lookup (DecryptionFailed / NotFound) or return
    // the original plaintext. Returning the *other* row's plaintext is the
    // bug.
    let lookup = store.get_decrypted(user_id, "low_priv_key").await;
    match lookup {
        Ok(material) => {
            assert_ne!(
                material.expose(),
                high_priv_plaintext,
                "H3: get_decrypted(low_priv_key) returned the high-priv plaintext after a \
                 ciphertext-column swap. AES-GCM has no AAD binding the ciphertext to \
                 (user_id, name), so cross-row swaps decrypt cleanly."
            );
            // Returning the original low-priv plaintext would be acceptable but
            // is not what happens today — the swap replaced the bytes.
            assert_eq!(
                material.expose(),
                low_priv_plaintext,
                "H3: get_decrypted returned an unexpected plaintext after row swap"
            );
        }
        Err(error) => {
            // Acceptable: the fix may reject the row at decrypt time once the
            // ciphertext is bound to (user_id, name).
            assert!(
                matches!(error, SecretError::DecryptionFailed(_)),
                "H3: post-fix, mismatched ciphertext must fail with DecryptionFailed, got {error:?}"
            );
        }
    }
}

#[cfg(feature = "libsql")]
fn h3_test_crypto() -> Arc<SecretsCrypto> {
    Arc::new(
        SecretsCrypto::new(SecretMaterial::from(
            "0123456789abcdef0123456789abcdef".to_string(),
        ))
        .unwrap(),
    )
}

// ---------------------------------------------------------------------------
// M1 — CredentialSessionId Display redaction
// ---------------------------------------------------------------------------

/// **Finding M1.** `CredentialSessionId` is documented as "bearer-like" and
/// "intentionally not `Serialize`"; `Debug` emits `[REDACTED]`. But `Display`
/// (used by `format!("{id}")`, `tracing::info!(%id, ...)`, and any
/// `error.to_string()` interpolation) emits the raw UUID. Any developer who
/// writes the idiomatic `session={session_id}` defeats the redaction.
///
/// Expected behavior after the fix: `Display` must not produce a parseable
/// UUID. A typical fix is to write a stable redacted form (`"[REDACTED]"`)
/// and provide a narrow `fn expose(&self) -> Uuid` for the small number of
/// call sites that genuinely need the value.
#[test]
fn m1_credential_session_id_display_must_not_emit_raw_uuid() {
    let id = CredentialSessionId::new();
    let displayed = format!("{id}");

    assert!(
        uuid::Uuid::parse_str(&displayed).is_err(),
        "M1: Display on CredentialSessionId must not emit a parseable UUID, \
         got {displayed:?}. Debug is redacted but Display leaks the bearer-like \
         value through every `{{}}`-style log/format call."
    );
}

// ---------------------------------------------------------------------------
// M2 — Master-key entropy is not validated
// ---------------------------------------------------------------------------

/// **Finding M2.** `SecretsCrypto::new` only checks that the master key is at
/// least 32 bytes long. An operator copy-pasting a weak key — 32 zero bytes,
/// `a` repeated 32 times, `01` repeated 16 times — passes the length check
/// and is then used as IKM for HKDF. Low-entropy IKM means captured
/// ciphertext is offline-brute-forceable, defeating the entire encrypted-at-
/// rest invariant.
///
/// Expected behavior after the fix: low-entropy master keys are rejected with
/// `SecretError::InvalidMasterKey`. A reasonable bar is "must be at least 32
/// bytes AND have at least N distinct bytes" or "must parse as 64 hex
/// characters / 32 base64-decoded bytes from a sufficiently random source".
/// The exact entropy heuristic is a design choice; the test here only asserts
/// that the three most-obvious weak keys are rejected.
#[test]
fn m2_secrets_crypto_must_reject_low_entropy_master_keys() {
    let weak_inputs = [
        // 32 bytes of '0' — passes length check today.
        "0".repeat(32),
        // 32 bytes of 'a' — same shape.
        "a".repeat(32),
        // 32 bytes of "01" repeated — only two distinct bytes.
        "01".repeat(16),
    ];

    for weak in weak_inputs {
        let result = SecretsCrypto::new(SecretMaterial::from(weak.clone()));
        assert!(
            matches!(result, Err(SecretError::InvalidMasterKey)),
            "M2: SecretsCrypto::new must reject low-entropy master key {weak:?}, \
             but it accepted it. A length-only check lets operators paste keys \
             with trivial entropy that are then used as HKDF input."
        );
    }
}
