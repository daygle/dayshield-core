//! JWT session token creation and validation.
//!
//! # Key storage
//!
//! The HMAC-SHA256 signing secret is read from (or generated into)
//! `/etc/dayshield/session.key`.  The file holds the raw bytes of a 32-byte
//! random key; it is created with mode `0o600` if it does not exist.
//!
//! # Token format
//!
//! Tokens are standard JWTs signed with `HS256`.  Claims:
//!
//! | Claim | Type   | Description                         |
//! |-------|--------|-------------------------------------|
//! | `sub` | string | Username                            |
//! | `iat` | number | Unix timestamp — issued at          |
//! | `exp` | number | Unix timestamp — expires at (+8 h)  |

use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::auth::model::AuthError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default path to the session signing key.
pub const DEFAULT_KEY_PATH: &str = "/etc/dayshield/session.key";

/// Session lifetime in seconds (8 hours = 28 800 seconds).
pub const SESSION_DURATION_SECS: u64 = 8 * 3600;

/// Number of bytes in the signing key.
const KEY_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// JWT claims
// ---------------------------------------------------------------------------

/// JWT claims embedded in every session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Username (`sub` — subject).
    pub sub: String,
    /// Unix timestamp at which the token was issued.
    pub iat: u64,
    /// Unix timestamp at which the token expires.
    pub exp: u64,
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/// Load the signing key from `path`, generating and saving it if it does not
/// yet exist.
///
/// The key file is created with mode `0o600` (owner-read/write only).
pub fn load_or_create_key(path: &Path) -> Result<Vec<u8>, AuthError> {
    if path.exists() {
        let bytes = fs::read(path)
            .map_err(|e| AuthError::StorageError(format!("read key: {e}")))?;
        if bytes.len() < KEY_BYTES {
            return Err(AuthError::StorageError(
                "session key file is too short".into(),
            ));
        }
        return Ok(bytes);
    }

    // Generate a new random key.
    let mut key = vec![0u8; KEY_BYTES];
    rand::rng().fill(&mut key[..]);

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| AuthError::StorageError(format!("create key dir: {e}")))?;
    }

    // Write with restricted permissions.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| AuthError::StorageError(format!("create key file: {e}")))?;

    use std::io::Write;
    file.write_all(&key)
        .map_err(|e| AuthError::StorageError(format!("write key: {e}")))?;

    Ok(key)
}

// ---------------------------------------------------------------------------
// Token creation
// ---------------------------------------------------------------------------

/// Create a signed JWT for `username` using `key`.
///
/// The token is valid for [`SESSION_DURATION_SECS`] seconds from `now_secs`.
pub fn create_token(username: &str, key: &[u8], now_secs: u64) -> Result<String, AuthError> {
    let claims = SessionClaims {
        sub: username.to_string(),
        iat: now_secs,
        exp: now_secs + SESSION_DURATION_SECS,
    };

    encode(
        &Header::default(), // HS256
        &claims,
        &EncodingKey::from_secret(key),
    )
    .map_err(|e| AuthError::StorageError(format!("encode JWT: {e}")))
}

// ---------------------------------------------------------------------------
// Token validation
// ---------------------------------------------------------------------------

/// Validate `token` and return the embedded [`SessionClaims`].
///
/// Returns:
/// - [`AuthError::TokenExpired`] when the token has passed its `exp` claim.
/// - [`AuthError::TokenInvalid`] for any other decode/verification failure.
pub fn validate_token(token: &str, key: &[u8]) -> Result<SessionClaims, AuthError> {
    let mut validation = Validation::default(); // HS256
    validation.validate_exp = true;

    decode::<SessionClaims>(token, &DecodingKey::from_secret(key), &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                _ => AuthError::TokenInvalid,
            }
        })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        b"test-key-exactly-32-bytes-long!!".to_vec()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn create_and_validate_token() {
        let key = test_key();
        let token = create_token("admin", &key, now()).expect("token creation must succeed");
        let claims = validate_token(&token, &key).expect("token must be valid");
        assert_eq!(claims.sub, "admin");
    }

    #[test]
    fn expired_token_returns_token_expired() {
        let key = test_key();
        // Issue a token that expired well over 60 seconds ago (default leeway).
        let past = now().saturating_sub(SESSION_DURATION_SECS + 120);
        let token = create_token("admin", &key, past).expect("token creation must succeed");
        let result = validate_token(&token, &key);
        assert!(
            matches!(result, Err(AuthError::TokenExpired)),
            "expected TokenExpired, got: {result:?}"
        );
    }

    #[test]
    fn tampered_token_returns_token_invalid() {
        let key = test_key();
        let mut token = create_token("admin", &key, now()).expect("token creation must succeed");
        // Corrupt the signature portion.
        token.push_str("XXXX");
        let result = validate_token(&token, &key);
        assert!(
            matches!(result, Err(AuthError::TokenInvalid)),
            "expected TokenInvalid, got: {result:?}"
        );
    }

    #[test]
    fn wrong_key_returns_token_invalid() {
        let key1 = test_key();
        let key2 = b"different-key-32-bytes-exactly!!".to_vec();
        let token = create_token("admin", &key1, now()).expect("token creation must succeed");
        let result = validate_token(&token, &key2);
        assert!(
            matches!(result, Err(AuthError::TokenInvalid)),
            "expected TokenInvalid, got: {result:?}"
        );
    }

    #[test]
    fn load_or_create_key_generates_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("session.key");
        let key = load_or_create_key(&key_path).expect("key creation must succeed");
        assert_eq!(key.len(), KEY_BYTES);
        assert!(key_path.exists());
    }

    #[test]
    fn load_or_create_key_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("session.key");
        let k1 = load_or_create_key(&key_path).unwrap();
        let k2 = load_or_create_key(&key_path).unwrap();
        assert_eq!(k1, k2, "key must be stable across loads");
    }
}
