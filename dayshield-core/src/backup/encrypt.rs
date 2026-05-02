//! AES-256-GCM encryption and decryption for backup archives.
//!
//! # Scheme
//!
//! - **Key derivation**: SHA-256 of the UTF-8 passphrase → 32-byte AES key.
//! - **Cipher**: AES-256-GCM with a random 96-bit (12-byte) nonce.
//! - **Wire format**: `[12-byte nonce][ciphertext + 16-byte GCM auth tag]`.
//!
//! # Security note
//!
//! Key derivation via a single SHA-256 hash is intentionally simple.  For
//! high-value data consider using a proper KDF such as Argon2id or PBKDF2.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Length of the AES-GCM nonce in bytes.
const NONCE_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte AES-256 key from `passphrase` by hashing it with SHA-256.
fn derive_key(passphrase: &str) -> Key<Aes256Gcm> {
    let hash = Sha256::digest(passphrase.as_bytes());
    Key::<Aes256Gcm>::from(hash)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt `data` using AES-256-GCM with a passphrase-derived key.
///
/// Returns `[nonce (12 bytes)][ciphertext + auth tag]`.
pub fn encrypt(data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let key = derive_key(passphrase);
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `data` (produced by [`encrypt`]) using the same passphrase.
///
/// Returns the original plaintext, or an error when the passphrase is wrong
/// or the ciphertext is corrupt / tampered with.
pub fn decrypt(data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(
        data.len() > NONCE_LEN,
        "Encrypted data is too short to contain a valid nonce"
    );

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let key = derive_key(passphrase);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong passphrase or corrupt data"))
        .context("backup: decryption error")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"DayShield backup test data 1234";
        let passphrase = "super-secret-passphrase";

        let ciphertext = encrypt(plaintext, passphrase).unwrap();
        assert_ne!(ciphertext, plaintext);

        let recovered = decrypt(&ciphertext, passphrase).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_wrong_passphrase_fails() {
        let plaintext = b"some data";
        let ciphertext = encrypt(plaintext, "correct").unwrap();
        let result = decrypt(&ciphertext, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_truncated_ciphertext_fails() {
        let result = decrypt(&[0u8; 5], "pass");
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_output_starts_with_nonce_length() {
        let ct = encrypt(b"hello", "pass").unwrap();
        // nonce (12) + at least 1 byte of ciphertext + 16-byte tag
        assert!(ct.len() > NONCE_LEN + 16);
    }
}
