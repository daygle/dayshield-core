//! Authentication model types.
//!
//! Defines the [`User`] record that is persisted to disk, the
//! [`AuthenticatedUser`] extension injected into request extensions by the
//! auth middleware, and the [`AuthError`] error enum used throughout the
//! authentication subsystem.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// User model
// ---------------------------------------------------------------------------

/// A DayShield administrator account.
///
/// Only the `admin` account exists in v1.0. The struct is serialised to
/// `/etc/dayshield/admin.json` as the persistent user record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Login name — always `"admin"` in v1.0.
    pub username: String,
    /// Argon2id PHC hash string, e.g. `$argon2id$v=19$…`.
    pub password_hash: String,
    /// Unix timestamp (seconds since epoch) at which the account was created.
    pub created_at: u64,
}

impl User {
    /// Create a new user record with the given username and an already-hashed
    /// password.
    pub fn new(username: impl Into<String>, password_hash: impl Into<String>) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            username: username.into(),
            password_hash: password_hash.into(),
            created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Authenticated-user extension (injected by auth middleware)
// ---------------------------------------------------------------------------

/// Typed extension inserted into every authenticated request by the auth
/// middleware.  Handlers can extract it with `Extension<AuthenticatedUser>`.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub username: String,
}

// ---------------------------------------------------------------------------
// AuthError
// ---------------------------------------------------------------------------

/// Errors that can occur in the authentication subsystem.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("unauthorized")]
    Unauthorized,

    #[error("token expired")]
    TokenExpired,

    #[error("token invalid")]
    TokenInvalid,

    #[error("storage error: {0}")]
    StorageError(String),
}
