//! Port of IronClaw's battle-tested secret crypto.
//!
//! Uses AES-256-GCM with per-secret HKDF-SHA256 key derivation, matching the
//! existing `src/secrets/crypto.rs` implementation so Reborn does not introduce
//! a parallel encryption scheme.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, AeadCore, OsRng},
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;

use crate::{DecryptedSecret, SecretError};

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 32;
const TAG_SIZE: usize = 16;
/// Minimum distinct-byte count for a master key.
///
/// HKDF accepts any IKM but its security degrades to brute-force when the IKM
/// has trivial entropy. A length-only check accepts 32 bytes of `0`, 32 bytes
/// of `a`, or short alphabet repeats — all of which an operator might paste
/// while bootstrapping. Requiring at least 8 distinct bytes rejects those
/// cases while leaving room for legitimate hex/base64 keys (typical 32-byte
/// hex strings use 16 distinct alphabet characters; random 32-byte keys have
/// ~30 distinct byte values on average).
const KEY_MIN_DISTINCT_BYTES: usize = 8;

pub struct SecretsCrypto {
    master_key: SecretString,
}

impl SecretsCrypto {
    pub fn new(master_key: SecretString) -> Result<Self, SecretError> {
        let bytes = master_key.expose_secret().as_bytes();
        if bytes.len() < KEY_SIZE {
            return Err(SecretError::InvalidMasterKey);
        }
        if distinct_byte_count(bytes) < KEY_MIN_DISTINCT_BYTES {
            return Err(SecretError::InvalidMasterKey);
        }
        Ok(Self { master_key })
    }

    pub(crate) fn from_valid_master_key(master_key: String) -> Self {
        // The caller is limited to crate-owned key generation whose byte length is reviewed.
        // This keeps infallible test/demo store construction out of production panic paths
        // while preserving `new` validation for externally supplied dynamic keys.
        Self {
            master_key: SecretString::from(master_key),
        }
    }

    pub fn generate_salt() -> Vec<u8> {
        let mut salt = vec![0u8; SALT_SIZE];
        rand::RngCore::fill_bytes(&mut OsRng, &mut salt);
        salt
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SecretError> {
        let salt = Self::generate_salt();
        let derived_key = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|error| SecretError::EncryptionFailed(error.to_string()))?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|error| SecretError::EncryptionFailed(error.to_string()))?;
        let mut encrypted = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        encrypted.extend_from_slice(&nonce);
        encrypted.extend_from_slice(&ciphertext);
        Ok((encrypted, salt))
    }

    pub fn decrypt(
        &self,
        encrypted_value: &[u8],
        salt: &[u8],
    ) -> Result<DecryptedSecret, SecretError> {
        if encrypted_value.len() < NONCE_SIZE + TAG_SIZE {
            return Err(SecretError::DecryptionFailed(
                "encrypted value too short".to_string(),
            ));
        }
        let derived_key = self.derive_key(salt)?;
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|error| SecretError::DecryptionFailed(error.to_string()))?;
        let (nonce_bytes, ciphertext) = encrypted_value.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|error| SecretError::DecryptionFailed(error.to_string()))?;
        DecryptedSecret::from_bytes(plaintext)
    }

    fn derive_key(&self, salt: &[u8]) -> Result<[u8; KEY_SIZE], SecretError> {
        let hk = Hkdf::<Sha256>::new(Some(salt), self.master_key.expose_secret().as_bytes());
        let mut derived = [0u8; KEY_SIZE];
        hk.expand(b"near-agent-secrets-v1", &mut derived)
            .map_err(|_| SecretError::EncryptionFailed("HKDF expansion failed".to_string()))?;
        Ok(derived)
    }
}

impl std::fmt::Debug for SecretsCrypto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretsCrypto")
            .field("master_key", &"[REDACTED]")
            .finish()
    }
}

/// Count of distinct byte values in the slice.
///
/// Used as a low-entropy heuristic in [`SecretsCrypto::new`]. A 32-bit bitmap
/// over the 256-byte alphabet (one bit per byte value) keeps this branch
/// constant-time-ish on key length, which matters because the input is a
/// secret.
fn distinct_byte_count(bytes: &[u8]) -> usize {
    let mut seen = [0u64; 4];
    for byte in bytes {
        let slot = (byte >> 6) as usize;
        let bit = byte & 0x3f;
        seen[slot] |= 1u64 << bit;
    }
    seen.iter().map(|word| word.count_ones() as usize).sum()
}
