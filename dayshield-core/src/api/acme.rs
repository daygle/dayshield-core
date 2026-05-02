//! ACME / TLS certificate endpoints.
//!
//! # Endpoints
//!
//! | Method | Path              | Description                                  |
//! |--------|-------------------|----------------------------------------------|
//! | GET    | `/acme/config`    | Return the current ACME configuration.       |
//! | POST   | `/acme/config`    | Update the ACME configuration.               |
//! | POST   | `/acme/issue`     | Trigger immediate certificate issuance.      |
//! | GET    | `/acme/status`    | Return certificate status / expiry info.     |
//! | GET    | `/.well-known/acme-challenge/{token}` | Serve an HTTP-01 challenge token. |

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    config::models::{
        is_valid_domain, validate_challenge_type, validate_directory_url, validate_email,
        AcmeChallengeType, AcmeConfig, AcmeProvider,
    },
    engine::acme::AcmeEngine,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the ACME API handlers.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The ACME engine returned an error.
    #[error("engine error: {0}")]
    EngineError(String),

    /// No ACME configuration has been saved yet.
    #[error("ACME is not configured")]
    NotConfigured,
}

impl IntoResponse for AcmeError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            AcmeError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AcmeError::NotConfigured => StatusCode::NOT_FOUND,
            AcmeError::StorageError(_) | AcmeError::EngineError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /acme/config`.
#[derive(Deserialize)]
pub struct UpdateAcmeConfigRequest {
    pub enabled: bool,
    pub provider: AcmeProvider,
    pub email: String,
    pub directory_url: Option<String>,
    pub domains: Vec<String>,
    pub cert_storage_path: String,
    pub challenge_type: AcmeChallengeType,
    pub renew_interval_hours: u64,
}

/// Response body for `GET /acme/status`.
#[derive(Serialize)]
pub struct AcmeStatusResponse {
    pub configured: bool,
    pub enabled: bool,
    pub domains: Vec<String>,
    /// Days until the stored certificate expires, or `null` if no cert exists.
    pub cert_expiry_days: Option<i64>,
    /// Whether the certificate is due for renewal (< 30 days remaining).
    pub needs_renewal: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: return the current ACME configuration.
///
/// Returns the persisted [`AcmeConfig`].  When no ACME configuration has been
/// saved yet, returns `404 Not Found`.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AcmeError> {
    let cfg = state
        .config_store
        .load_acme_config()
        .map_err(AcmeError::StorageError)?
        .ok_or(AcmeError::NotConfigured)?;

    info!(enabled = cfg.enabled, domains = ?cfg.domains, "acme: loaded config");
    Ok(Json(cfg))
}

/// Handler: update the ACME configuration.
///
/// Validates all fields, persists atomically, and returns the saved config
/// with `200 OK` on success.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateAcmeConfigRequest>,
) -> Result<impl IntoResponse, AcmeError> {
    // --- Validation --------------------------------------------------------

    if !validate_email(&req.email) {
        warn!(email = %req.email, "acme: invalid email");
        return Err(AcmeError::ValidationFailed(format!(
            "invalid email address {:?}",
            req.email
        )));
    }

    if req.domains.is_empty() {
        return Err(AcmeError::ValidationFailed(
            "at least one domain must be specified".into(),
        ));
    }

    for domain in &req.domains {
        if !is_valid_domain(domain) {
            warn!(domain = %domain, "acme: invalid domain");
            return Err(AcmeError::ValidationFailed(format!(
                "invalid domain name {:?}",
                domain
            )));
        }
    }

    if req.cert_storage_path.is_empty() {
        return Err(AcmeError::ValidationFailed(
            "cert_storage_path must not be empty".into(),
        ));
    }

    if req.renew_interval_hours == 0 {
        return Err(AcmeError::ValidationFailed(
            "renew_interval_hours must be > 0".into(),
        ));
    }

    if let Some(url) = &req.directory_url {
        if !validate_directory_url(url) {
            warn!(url = %url, "acme: invalid directory_url");
            return Err(AcmeError::ValidationFailed(format!(
                "invalid directory_url {:?}: must start with https://",
                url
            )));
        }
    }

    if !validate_challenge_type(&req.challenge_type) {
        return Err(AcmeError::ValidationFailed(
            "invalid challenge_type".into(),
        ));
    }

    // --- Build config -------------------------------------------------------

    let cfg = AcmeConfig {
        enabled: req.enabled,
        provider: req.provider,
        email: req.email,
        directory_url: req.directory_url,
        domains: req.domains,
        cert_storage_path: req.cert_storage_path,
        challenge_type: req.challenge_type,
        renew_interval_hours: req.renew_interval_hours,
    };

    info!(
        enabled = cfg.enabled,
        domains = ?cfg.domains,
        "acme: received update config request"
    );

    // --- Persist ------------------------------------------------------------

    state
        .config_store
        .save_acme_config(cfg.clone())
        .map_err(AcmeError::StorageError)?;

    info!("acme: config persisted");

    Ok(Json(cfg))
}

/// Handler: trigger immediate certificate issuance.
///
/// Loads the current ACME configuration and calls [`AcmeEngine::order_certificate`].
/// Returns `202 Accepted` with a message indicating that issuance has started.
pub async fn issue(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AcmeError> {
    let cfg = state
        .config_store
        .load_acme_config()
        .map_err(AcmeError::StorageError)?
        .ok_or(AcmeError::NotConfigured)?;

    if !cfg.enabled {
        return Err(AcmeError::ValidationFailed(
            "ACME is disabled in configuration".into(),
        ));
    }

    info!(domains = ?cfg.domains, "acme: manual issuance triggered via API");

    let engine = AcmeEngine::new(cfg);
    engine
        .order_certificate()
        .await
        .map_err(|e| AcmeError::EngineError(e.to_string()))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "message": "certificate issued successfully" })),
    ))
}

/// Handler: return certificate status and expiry information.
///
/// Loads the ACME config and inspects the on-disk certificate.
pub async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AcmeError> {
    let cfg = state
        .config_store
        .load_acme_config()
        .map_err(AcmeError::StorageError)?;

    let Some(cfg) = cfg else {
        return Ok(Json(AcmeStatusResponse {
            configured: false,
            enabled: false,
            domains: vec![],
            cert_expiry_days: None,
            needs_renewal: false,
        }));
    };

    let engine = AcmeEngine::new(cfg.clone());
    let needs_renewal = engine.renewal_check();

    // Try to read the certificate expiry.
    let cert_path = std::path::PathBuf::from(&cfg.cert_storage_path).join("cert.pem");
    let cert_expiry_days = if cert_path.exists() {
        engine.cert_expiry_days(&cert_path).ok()
    } else {
        None
    };

    Ok(Json(AcmeStatusResponse {
        configured: true,
        enabled: cfg.enabled,
        domains: cfg.domains,
        cert_expiry_days,
        needs_renewal,
    }))
}

/// Handler: serve an HTTP-01 ACME challenge token.
///
/// The ACME server calls `GET /.well-known/acme-challenge/{token}` during
/// HTTP-01 domain ownership verification.  This handler looks up the token in
/// the in-process [`ChallengeStore`] and returns the corresponding
/// key-authorisation string as `text/plain`.
///
/// Returns `404 Not Found` if the token is unknown (e.g. after the challenge
/// has been completed and cleaned up).
pub async fn serve_http01_challenge(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    let response = state.acme_challenge_store.get(&token).await;
    match response {
        Some(key_auth) => {
            info!(token = %token, "acme: serving HTTP-01 challenge token");
            (
                StatusCode::OK,
                [("content-type", "text/plain")],
                key_auth,
            )
                .into_response()
        }
        None => {
            warn!(token = %token, "acme: unknown HTTP-01 challenge token requested");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_email_valid() {
        assert!(validate_email("admin@example.com"));
        assert!(validate_email("user+tag@sub.domain.org"));
    }

    #[test]
    fn validate_email_invalid() {
        assert!(!validate_email(""));
        assert!(!validate_email("notanemail"));
        assert!(!validate_email("@example.com"));
        assert!(!validate_email("user@"));
        assert!(!validate_email("user@nodot"));
    }

    #[test]
    fn validate_directory_url_valid() {
        assert!(validate_directory_url(
            "https://acme-v02.api.letsencrypt.org/directory"
        ));
        assert!(validate_directory_url("https://acme.example.com/dir"));
    }

    #[test]
    fn validate_directory_url_invalid() {
        assert!(!validate_directory_url("http://insecure.example.com/dir"));
        assert!(!validate_directory_url("ftp://example.com"));
        assert!(!validate_directory_url("not-a-url"));
        assert!(!validate_directory_url(""));
        assert!(!validate_directory_url("https://"));
    }

    #[test]
    fn validate_domain_valid() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("my-host.internal"));
    }

    #[test]
    fn validate_domain_invalid() {
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("-bad.com"));
        assert!(!is_valid_domain("bad-.com"));
        assert!(!is_valid_domain("a".repeat(64).as_str()));
    }

    #[test]
    fn acme_challenge_type_serde_roundtrip() {
        let json = serde_json::to_string(&AcmeChallengeType::Http01).unwrap();
        assert_eq!(json, "\"http01\"");
        let rt: AcmeChallengeType = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, AcmeChallengeType::Http01);

        let json2 = serde_json::to_string(&AcmeChallengeType::Dns01).unwrap();
        assert_eq!(json2, "\"dns01\"");
    }
}
