//! Argon2id password hashing and verification.
//!
//! # Algorithm
//!
//! Uses **Argon2id** (the hybrid variant recommended by RFC 9106) with the
//! following default parameters:
//!
//! | Parameter     | Value  |
//! |---------------|--------|
//! | Memory cost   | 65 536 KiB (64 MiB) |
//! | Iterations    | 3      |
//! | Parallelism   | 4      |
//!
//! These are conservative, production-suitable values.  The PHC string format
//! returned by [`hash_password`] embeds the parameters and salt, so all
//! information needed for verification is self-contained.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};

use crate::auth::model::AuthError;

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// Default memory cost in KiB (64 MiB).
pub const DEFAULT_MEMORY_KIB: u32 = 65_536;
/// Default number of hash iterations (time cost).
pub const DEFAULT_ITERATIONS: u32 = 3;
/// Default parallelism degree.
pub const DEFAULT_PARALLELISM: u32 = 4;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Hash `password` using Argon2id with the default parameters and a freshly
/// generated random salt.
///
/// Returns the PHC-format string, e.g.:
/// `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    hash_password_with_params(
        password,
        DEFAULT_MEMORY_KIB,
        DEFAULT_ITERATIONS,
        DEFAULT_PARALLELISM,
    )
}

/// Hash `password` using Argon2id with explicit parameters.
///
/// Useful for testing with reduced memory/iteration counts.
pub fn hash_password_with_params(
    password: &str,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<String, AuthError> {
    let params = Params::new(memory_kib, iterations, parallelism, None)
        .map_err(|e| AuthError::StorageError(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let salt = SaltString::generate(&mut OsRng);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::StorageError(e.to_string()))?;

    Ok(hash.to_string())
}

/// Verify that `password` matches the stored `hash` (PHC format).
///
/// Returns `Ok(())` on success or an [`AuthError::InvalidCredentials`] on
/// mismatch, and an [`AuthError::StorageError`] if the hash string is
/// malformed.
pub fn verify_password(password: &str, hash: &str) -> Result<(), AuthError> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AuthError::StorageError(format!("malformed hash: {e}")))?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| AuthError::InvalidCredentials)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Use reduced parameters in tests so they run quickly.
    fn fast_hash(password: &str) -> String {
        hash_password_with_params(password, 256, 1, 1).expect("hash should succeed")
    }

    #[test]
    fn hash_is_phc_format() {
        let h = fast_hash("secret");
        assert!(h.starts_with("$argon2id$"), "expected PHC prefix, got: {h}");
    }

    #[test]
    fn verify_correct_password() {
        let h = fast_hash("correct-horse-battery-staple");
        verify_password("correct-horse-battery-staple", &h).expect("correct password must verify");
    }

    #[test]
    fn verify_wrong_password_fails() {
        let h = fast_hash("correct-password");
        let result = verify_password("wrong-password", &h);
        assert!(
            matches!(result, Err(AuthError::InvalidCredentials)),
            "wrong password must return InvalidCredentials"
        );
    }

    #[test]
    fn two_hashes_of_same_password_differ() {
        // Each call uses a freshly generated salt.
        let h1 = fast_hash("same");
        let h2 = fast_hash("same");
        assert_ne!(h1, h2, "salted hashes must be unique");
    }

    #[test]
    fn malformed_hash_returns_storage_error() {
        let result = verify_password("pass", "not-a-valid-phc-string");
        assert!(matches!(result, Err(AuthError::StorageError(_))));
    }
}
