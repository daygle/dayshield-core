//! Optional AES-256-GCM backup encryption.
//!
//! The on-disk format for an encrypted backup payload is:
//!
//! ```text
//! [16-byte salt][12-byte nonce][ciphertext + 16-byte GCM tag]
//! ```
//!
//! The 256-bit encryption key is derived from the passphrase and the random
//! salt using SHA-256 (two rounds: `SHA256(SHA256(passphrase) || salt)`).
//! This is intentionally simple to keep the dependency footprint small; a
//! production deployment should consider PBKDF2 or Argon2.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Encrypt `plaintext` with AES-256-GCM using a key derived from
/// `passphrase`.
///
/// Returns the concatenation `[salt(16) || nonce(12) || ciphertext+tag]`.
///
/// # Errors
///
/// Returns an [`anyhow::Error`] if the AEAD cipher fails.
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> anyhow::Result<Vec<u8>> {
    // Generate a random 16-byte salt and 12-byte nonce.
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt error: {e}"))?;

    let mut out = Vec::with_capacity(16 + 12 + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob previously produced by [`encrypt`].
///
/// # Errors
///
/// Returns an [`anyhow::Error`] when the blob is too short, the passphrase
/// is wrong, or the authentication tag is invalid.
pub fn decrypt(blob: &[u8], passphrase: &str) -> anyhow::Result<Vec<u8>> {
    if blob.len() < 28 {
        anyhow::bail!(
            "encrypted blob too short: expected at least 28 bytes, got {}",
            blob.len()
        );
    }

    let salt = &blob[..16];
    let nonce_bytes = &blob[16..28];
    let ciphertext = &blob[28..];

    let key = derive_key(passphrase, salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("AES-GCM decrypt failed: wrong passphrase or corrupted data"))?;

    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a 32-byte AES key from `passphrase` and `salt` using two rounds of
/// SHA-256: `key = SHA256(SHA256(passphrase) ‖ salt)`.
fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut h1 = Sha256::digest(passphrase.as_bytes());
    let mut combined = Vec::with_capacity(32 + salt.len());
    combined.extend_from_slice(&h1);
    combined.extend_from_slice(salt);
    let h2 = Sha256::digest(&combined);
    h1.copy_from_slice(&h2);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h1);
    out
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        let blob = encrypt(b"", "secret").unwrap();
        let plain = decrypt(&blob, "secret").unwrap();
        assert_eq!(plain, b"");
    }

    #[test]
    fn roundtrip_data() {
        let data = b"DayShield backup payload";
        let blob = encrypt(data, "hunter2").unwrap();
        let plain = decrypt(&blob, "hunter2").unwrap();
        assert_eq!(plain, data);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = encrypt(b"secret data", "correct").unwrap();
        assert!(decrypt(&blob, "wrong").is_err());
    }

    #[test]
    fn short_blob_returns_error() {
        assert!(decrypt(b"tooshort", "pass").is_err());
    }
}
