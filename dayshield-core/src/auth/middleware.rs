//! Auth middleware — guards all routes that require authentication.
//!
//! # How it works
//!
//! The middleware inspects every incoming request.  If the path is on the
//! **public allow-list** (see below) it is forwarded unchanged.  For all other
//! paths the middleware:
//!
//! 1. Extracts the bearer token from the `Authorization` header
//!    (`Authorization: Bearer <token>`), from the `session` cookie, or from a
//!    `token` URL query parameter (used by browser WebSocket clients that
//!    cannot set custom headers).
//! 2. Validates the token signature and expiry using the HMAC-SHA256 session
//!    key stored in `/etc/dayshield/session.key`.
//! 3. On success, inserts an [`AuthenticatedUser`] extension into the request
//!    so downstream handlers can retrieve it with
//!    `Extension<AuthenticatedUser>`.
//! 4. On failure, returns `401 Unauthorized` immediately.
//!
//! # Public routes (no token required)
//!
//! - `POST /auth/login`
//! - `GET  /auth/status`
//! - `GET  /system/status`
//! - `GET  /installer/*`

use std::path::Path;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use tracing::debug;

use crate::auth::{
    model::AuthenticatedUser,
    session::validate_token,
};

// ---------------------------------------------------------------------------
// Public path list
// ---------------------------------------------------------------------------

/// Paths that do not require an authentication token.
///
/// Matching is prefix-based (a path matches if it *starts with* one of these
/// strings, after normalising to lowercase).
const PUBLIC_PATHS: &[&str] = &[
    "/auth/login",
    "/auth/status",
    "/system/status",
    "/installer/",
];

/// Returns `true` if `path` is on the public allow-list.
fn is_public_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    PUBLIC_PATHS.iter().any(|prefix| lower.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// Token extraction helpers
// ---------------------------------------------------------------------------

/// Try to extract a bearer token from the `Authorization` header.
fn token_from_header(req: &Request) -> Option<String> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    Some(token.to_string())
}

/// Try to extract a token from the `session` cookie.
fn token_from_cookie(req: &Request) -> Option<String> {
    let cookie_header = req.headers().get(header::COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("session=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Try to extract a token from the URL query string (`?token=<jwt>`).
fn token_from_query(req: &Request) -> Option<String> {
    let query = req.uri().query()?;
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let key = it.next()?.trim();
        if key != "token" {
            continue;
        }

        let value = it.next().unwrap_or("").trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// Extract a token from the request, preferring the `Authorization` header
/// over the `session` cookie, and then URL query parameter.
fn extract_token(req: &Request) -> Option<String> {
    token_from_header(req)
        .or_else(|| token_from_cookie(req))
        .or_else(|| token_from_query(req))
}

// ---------------------------------------------------------------------------
// Middleware function
// ---------------------------------------------------------------------------

/// Axum middleware that enforces authentication on all non-public routes.
///
/// # Usage
///
/// ```rust,ignore
/// use axum::middleware;
/// use crate::auth::middleware::auth_middleware;
///
/// let app = Router::new()
///     .route("/protected", get(handler))
///     .layer(middleware::from_fn_with_state(state, auth_middleware));
/// ```
pub async fn auth_middleware(
    req: Request,
    next: Next,
) -> Response {
    auth_middleware_with_key_path(req, next, Path::new(crate::auth::session::DEFAULT_KEY_PATH)).await
}

/// Testable variant that accepts an explicit key path.
pub async fn auth_middleware_with_key_path(
    mut req: Request,
    next: Next,
    key_path: &Path,
) -> Response {
    let path = req.uri().path().to_string();

    // Public routes bypass authentication.
    if is_public_path(&path) {
        return next.run(req).await;
    }

    // Load the signing key.
    let key = match crate::auth::session::load_or_create_key(key_path) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("failed to load session key: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "internal server error" })),
            )
                .into_response();
        }
    };

    // Extract token from request.
    let token = match extract_token(&req) {
        Some(t) => t,
        None => {
            debug!(path = %path, "auth: no token provided");
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "unauthorized" })),
            )
                .into_response();
        }
    };

    // Validate token.
    let claims = match validate_token(&token, &key) {
        Ok(c) => c,
        Err(e) => {
            debug!(path = %path, error = %e, "auth: invalid token");
            let (status, msg) = match e {
                crate::auth::model::AuthError::TokenExpired => {
                    (StatusCode::UNAUTHORIZED, "token expired")
                }
                _ => (StatusCode::UNAUTHORIZED, "invalid token"),
            };
            return (
                status,
                Json(serde_json::json!({ "error": msg })),
            )
                .into_response();
        }
    };

    // Inject authenticated user into request extensions.
    req.extensions_mut()
        .insert(AuthenticatedUser { username: claims.sub });

    next.run(req).await
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        response::IntoResponse,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn dummy_handler() -> impl IntoResponse {
        (StatusCode::OK, "ok")
    }

    fn build_app(key_path: &std::path::PathBuf) -> Router {
        let key_path = key_path.clone();
        Router::new()
            .route("/protected", get(dummy_handler))
            .route("/auth/login", get(dummy_handler))
            .route("/system/status", get(dummy_handler))
            .layer(middleware::from_fn(move |req, next| {
                let kp = key_path.clone();
                async move {
                    auth_middleware_with_key_path(req, next, &kp).await
                }
            }))
    }

    #[tokio::test]
    async fn public_route_passes_without_token() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("session.key");
        let app = build_app(&key_path);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/system/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn login_route_passes_without_token() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("session.key");
        let app = build_app(&key_path);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/auth/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_route_blocked_without_token() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("session.key");
        let app = build_app(&key_path);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn protected_route_accessible_with_valid_token() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("session.key");

        // Pre-create key so we can use it to sign a token.
        let key = crate::auth::session::load_or_create_key(&key_path).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = crate::auth::session::create_token("admin", &key, now).unwrap();

        let app = build_app(&key_path);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_route_accessible_with_query_token() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("session.key");

        // Pre-create key so we can use it to sign a token.
        let key = crate::auth::session::load_or_create_key(&key_path).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = crate::auth::session::create_token("admin", &key, now).unwrap();

        let app = build_app(&key_path);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/protected?token={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }
}
