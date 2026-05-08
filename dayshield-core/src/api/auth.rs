//! Authentication REST API endpoints.
//!
//! | Method | Path                    | Description                         |
//! |--------|-------------------------|-------------------------------------|
//! | POST   | `/auth/login`           | Authenticate and receive a JWT      |
//! | POST   | `/auth/logout`          | Log out (client-side token drop)    |
//! | POST   | `/auth/change-password` | Change the admin password           |
//! | GET    | `/auth/status`          | Check authentication status         |

use std::path::Path;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::auth::{
    model::{AuthenticatedUser, AuthError},
    password::{hash_password, verify_password},
    session::{create_token, load_or_create_key, DEFAULT_KEY_PATH},
    storage::{load_user, update_password, DEFAULT_ADMIN_PATH},
};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum AuthApiError {
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

    #[error("bad request: {0}")]
    BadRequest(String),
}

impl From<AuthError> for AuthApiError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::InvalidCredentials => AuthApiError::InvalidCredentials,
            AuthError::Unauthorized => AuthApiError::Unauthorized,
            AuthError::TokenExpired => AuthApiError::TokenExpired,
            AuthError::TokenInvalid => AuthApiError::TokenInvalid,
            AuthError::StorageError(s) => AuthApiError::StorageError(s),
        }
    }
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            AuthApiError::InvalidCredentials
            | AuthApiError::Unauthorized
            | AuthApiError::TokenExpired
            | AuthApiError::TokenInvalid => StatusCode::UNAUTHORIZED,
            AuthApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AuthApiError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// POST /auth/login
// ---------------------------------------------------------------------------

/// Request body for `POST /auth/login`.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Inner data for the `POST /auth/login` response.
#[derive(Debug, Serialize)]
pub struct LoginData {
    pub authenticated: bool,
    pub username: String,
    pub token: String,
}

/// Response body for `POST /auth/login` — follows the standard ApiResponse envelope.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub data: LoginData,
}

/// Authenticate with username + password and receive a JWT.
pub async fn login(
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    login_with_paths(req, Path::new(DEFAULT_ADMIN_PATH), Path::new(DEFAULT_KEY_PATH)).await
}

/// Testable variant that accepts explicit file paths.
pub async fn login_with_paths(
    req: LoginRequest,
    admin_path: &Path,
    key_path: &Path,
) -> Result<impl IntoResponse, AuthApiError> {
    if req.username.is_empty() || req.password.is_empty() {
        return Err(AuthApiError::BadRequest("username and password are required".into()));
    }

    // Load user record.
    let user = load_user(admin_path)
        .map_err(AuthApiError::from)?
        .ok_or(AuthApiError::InvalidCredentials)?;

    // Username must match.
    if user.username != req.username {
        return Err(AuthApiError::InvalidCredentials);
    }

    // Verify password — argon2id is CPU + memory intensive; run on a blocking
    // thread so the Tokio async executor is not stalled.
    let password = req.password.clone();
    let hash = user.password_hash.clone();
    tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .map_err(|_| AuthApiError::StorageError("password verification task panicked".into()))?
        .map_err(|_| AuthApiError::InvalidCredentials)?;

    // Load (or create) the signing key.
    let key = load_or_create_key(key_path).map_err(AuthApiError::from)?;

    // Issue JWT — HMAC-SHA256 signing is CPU-intensive; run on a blocking thread.
    let username = user.username.clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let token = tokio::task::spawn_blocking(move || create_token(&username, &key, now))
        .await
        .map_err(|_| AuthApiError::StorageError("token creation task panicked".into()))?
        .map_err(AuthApiError::from)?;

    info!(username = %user.username, "login successful");

    Ok((
        StatusCode::OK,
        Json(LoginResponse {
            success: true,
            data: LoginData {
                authenticated: true,
                username: user.username,
                token,
            },
        }),
    ))
}

// ---------------------------------------------------------------------------
// POST /auth/logout
// ---------------------------------------------------------------------------

/// Log out.
///
/// DayShield uses stateless JWTs, so logout is a client-side operation (the
/// client discards the token).  This endpoint exists for completeness and
/// returns 200 OK with a confirmation message.
///
/// Future: maintain a server-side denylist here.
pub async fn logout(
    Extension(user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    info!(username = %user.username, "logout");
    Json(serde_json::json!({ "message": "logged out" }))
}

// ---------------------------------------------------------------------------
// POST /auth/change-password
// ---------------------------------------------------------------------------

/// Request body for `POST /auth/change-password`.
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(rename = "currentPassword")]
    pub old_password: String,
    #[serde(rename = "newPassword")]
    pub new_password: String,
}

/// Change the admin account password.
pub async fn change_password(
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    change_password_with_path(user, req, Path::new(DEFAULT_ADMIN_PATH)).await
}

/// Testable variant that accepts an explicit admin-file path.
pub async fn change_password_with_path(
    user: AuthenticatedUser,
    req: ChangePasswordRequest,
    admin_path: &Path,
) -> Result<impl IntoResponse, AuthApiError> {
    if req.new_password.is_empty() {
        return Err(AuthApiError::BadRequest("new_password must not be empty".into()));
    }
    if req.new_password.len() < 8 {
        return Err(AuthApiError::BadRequest("new_password must be at least 8 characters".into()));
    }

    // Load existing record and verify old password.
    let existing = load_user(admin_path)
        .map_err(AuthApiError::from)?
        .ok_or(AuthApiError::Unauthorized)?;

    if existing.username != user.username {
        return Err(AuthApiError::Unauthorized);
    }

    let old_password = req.old_password.clone();
    let existing_hash = existing.password_hash.clone();
    tokio::task::spawn_blocking(move || verify_password(&old_password, &existing_hash))
        .await
        .map_err(|_| AuthApiError::StorageError("password verification task panicked".into()))?
        .map_err(|_| AuthApiError::InvalidCredentials)?;

    // Hash and persist new password — also CPU intensive.
    let new_password = req.new_password.clone();
    let new_hash = tokio::task::spawn_blocking(move || hash_password(&new_password))
        .await
        .map_err(|_| AuthApiError::StorageError("password hashing task panicked".into()))?
        .map_err(AuthApiError::from)?;
    update_password(admin_path, &new_hash).map_err(AuthApiError::from)?;

    info!(username = %user.username, "password changed");

    Ok(Json(serde_json::json!({ "message": "password updated" })))
}

// ---------------------------------------------------------------------------
// GET /auth/status
// ---------------------------------------------------------------------------

/// Response body for `GET /auth/status`.
#[derive(Debug, Serialize)]
pub struct AuthStatusResponse {
    pub authenticated: bool,
    pub username: Option<String>,
}

/// Return the current authentication status.
///
/// If the middleware has injected an [`AuthenticatedUser`] extension, the
/// request is authenticated.
pub async fn status(
    user: Option<Extension<AuthenticatedUser>>,
) -> impl IntoResponse {
    match user {
        Some(Extension(u)) => Json(AuthStatusResponse {
            authenticated: true,
            username: Some(u.username),
        }),
        None => Json(AuthStatusResponse {
            authenticated: false,
            username: None,
        }),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{password::hash_password_with_params, storage::save_user, model::User};

    /// Write an admin record with a fast-hashed password to `path`.
    fn seed_admin(path: &Path, password: &str) {
        let hash = hash_password_with_params(password, 256, 1, 1).unwrap();
        let user = User::new("admin", hash);
        save_user(path, &user).unwrap();
    }

    #[tokio::test]
    async fn login_returns_token() {
        let dir = tempfile::tempdir().unwrap();
        let admin_path = dir.path().join("admin.json");
        let key_path = dir.path().join("session.key");
        seed_admin(&admin_path, "correct-password");

        let req = LoginRequest {
            username: "admin".into(),
            password: "correct-password".into(),
        };

        let resp = login_with_paths(req, &admin_path, &key_path)
            .await
            .expect("login must succeed");

        let resp = resp.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn login_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let admin_path = dir.path().join("admin.json");
        let key_path = dir.path().join("session.key");
        seed_admin(&admin_path, "correct-password");

        let req = LoginRequest {
            username: "admin".into(),
            password: "wrong-password".into(),
        };

        let result = login_with_paths(req, &admin_path, &key_path).await;
        assert!(
            matches!(result, Err(AuthApiError::InvalidCredentials)),
            "wrong password must be rejected"
        );
    }

    #[tokio::test]
    async fn login_unknown_user_fails() {
        let dir = tempfile::tempdir().unwrap();
        let admin_path = dir.path().join("admin.json"); // no file
        let key_path = dir.path().join("session.key");

        let req = LoginRequest {
            username: "ghost".into(),
            password: "any".into(),
        };

        let result = login_with_paths(req, &admin_path, &key_path).await;
        assert!(matches!(result, Err(AuthApiError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn change_password_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let admin_path = dir.path().join("admin.json");
        seed_admin(&admin_path, "old-password");

        let user = AuthenticatedUser { username: "admin".into() };
        let req = ChangePasswordRequest {
            old_password: "old-password".into(),
            new_password: "new-password-123".into(),
        };

        change_password_with_path(user, req, &admin_path)
            .await
            .expect("change password must succeed");

        // New password should now work.
        let loaded = load_user(&admin_path).unwrap().unwrap();
        verify_password("new-password-123", &loaded.password_hash).expect("new password must verify");
    }

    #[tokio::test]
    async fn change_password_wrong_old_fails() {
        let dir = tempfile::tempdir().unwrap();
        let admin_path = dir.path().join("admin.json");
        seed_admin(&admin_path, "correct-old-password");

        let user = AuthenticatedUser { username: "admin".into() };
        let req = ChangePasswordRequest {
            old_password: "wrong-old".into(),
            new_password: "new-password-123".into(),
        };

        let result = change_password_with_path(user, req, &admin_path).await;
        assert!(matches!(result, Err(AuthApiError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn change_password_too_short_fails() {
        let dir = tempfile::tempdir().unwrap();
        let admin_path = dir.path().join("admin.json");
        seed_admin(&admin_path, "old-password");

        let user = AuthenticatedUser { username: "admin".into() };
        let req = ChangePasswordRequest {
            old_password: "old-password".into(),
            new_password: "short".into(),
        };

        let result = change_password_with_path(user, req, &admin_path).await;
        assert!(matches!(result, Err(AuthApiError::BadRequest(_))));
    }
}
