//! ACME certificate management API endpoints.
//!
//! # GET /acme/config
//!
//! Returns the persisted [`AcmeConfig`].  When no configuration has been saved
//! yet, returns a default (disabled) configuration so clients always receive a
//! well-formed object.
//!
//! # POST /acme/config
//!
//! Accepts a full [`AcmeConfig`] JSON body, validates all fields, and
//! atomically persists the config.  Returns the saved config with `200 OK`.
//!
//! # POST /acme/issue
//!
//! Triggers certificate issuance (or renewal) for all domains in the current
//! configuration.  Calls [`AcmeEngine::order_certificate`] synchronously and
//! returns `200 OK` on success.
//!
//! # GET /acme/status
//!
//! Returns a JSON object describing whether a certificate file exists for the
//! primary domain and whether it appears to need renewal.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::{info, warn};

use crate::{
    config::models::{
        validate_acme_config, AcmeChallengeType, AcmeConfig, AcmeProvider,
    },
    engine::acme::AcmeEngine,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the ACME API handlers.
#[derive(Debug, thiserror::Error)]
pub enum AcmeApiError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The ACME engine returned an error.
    #[error("engine error: {0}")]
    EngineError(String),
}

impl IntoResponse for AcmeApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            AcmeApiError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AcmeApiError::StorageError(_) | AcmeApiError::EngineError(_) => {
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
#[derive(serde::Deserialize)]
pub struct UpdateAcmeConfigRequest {
    pub enabled: bool,
    pub directory_url: String,
    pub email: String,
    pub domains: Vec<String>,
    pub challenge_type: AcmeChallengeType,
    pub renew_interval_hours: u64,
    pub cert_storage_path: String,
}

/// Response body for `GET /acme/status`.
#[derive(serde::Serialize)]
pub struct AcmeCertStatus {
    /// Primary domain from configuration.
    pub domain: Option<String>,
    /// Whether a certificate file exists on disk for the primary domain.
    pub cert_exists: bool,
    /// Whether the engine considers the certificate due for renewal.
    pub needs_renewal: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: return the current ACME configuration.
///
/// Loads the ACME config from persistent storage.  Returns a sensible
/// default (disabled) when no configuration has been saved yet.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AcmeApiError> {
    let cfg = state
        .config_store
        .load_acme_config()
        .map_err(AcmeApiError::StorageError)?
        .unwrap_or_else(|| AcmeConfig {
            enabled: false,
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            email: String::new(),
            domains: vec![],
            challenge_type: AcmeChallengeType::Http01,
            renew_interval_hours: 24,
            provider: AcmeProvider::LetsEncrypt,
            cert_storage_path: "/etc/dayshield/certs".into(),
        });

    info!(enabled = cfg.enabled, "acme: loaded config");
    Ok(Json(cfg))
}

/// Handler: update the ACME configuration.
///
/// Validates all fields and persists atomically.  Returns the saved config
/// with `200 OK` on success.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateAcmeConfigRequest>,
) -> Result<impl IntoResponse, AcmeApiError> {
    // Build config from request so we can run our validators on it.
    let cfg = AcmeConfig {
        enabled: req.enabled,
        directory_url: req.directory_url,
        email: req.email,
        domains: req.domains,
        challenge_type: req.challenge_type,
        renew_interval_hours: req.renew_interval_hours,
        provider: AcmeProvider::Custom,
        cert_storage_path: req.cert_storage_path,
    };

    if cfg.enabled {
        if let Err(msg) = validate_acme_config(&cfg) {
            warn!("acme: config validation failed: {msg}");
            return Err(AcmeApiError::ValidationFailed(msg));
        }
        if cfg.renew_interval_hours == 0 {
            return Err(AcmeApiError::ValidationFailed(
                "renew_interval_hours must be greater than 0".into(),
            ));
        }
    }

    info!(
        enabled = cfg.enabled,
        domains = ?cfg.domains,
        "acme: received update config request"
    );

    state
        .config_store
        .save_acme_config(cfg.clone())
        .map_err(AcmeApiError::StorageError)?;

    info!("acme: config persisted");
    Ok(Json(cfg))
}

/// Handler: issue (or renew) certificates for all configured domains.
///
/// Loads the current ACME config, creates an [`AcmeEngine`], and calls
/// [`AcmeEngine::order_certificate`].  Returns `200 OK` with a success
/// message on completion, or an error response on failure.
pub async fn issue_certificates(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AcmeApiError> {
    let message = run_acme_renewal(&state).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": message
    })))
}

pub(crate) async fn run_acme_renewal(state: &Arc<AppState>) -> Result<String, AcmeApiError> {
    let cfg = state
        .config_store
        .load_acme_config()
        .map_err(AcmeApiError::StorageError)?
        .ok_or_else(|| AcmeApiError::EngineError("no ACME config saved".into()))?;

    if !cfg.enabled {
        return Err(AcmeApiError::ValidationFailed(
            "ACME is disabled - enable it in the config first".into(),
        ));
    }

    info!(domains = ?cfg.domains, "acme: starting certificate issuance / renewal");

    let engine = AcmeEngine::new(cfg.clone());
    if !engine.renewal_check().await.unwrap_or(true) {
        return Ok("certificate already valid; renewal not required".to_string());
    }

    engine
        .order_certificate()
        .await
        .map_err(|e| AcmeApiError::EngineError(e.to_string()))?;

    Ok("certificate issued successfully".to_string())
}

/// Handler: return certificate status for the primary domain.
///
/// Reports whether a certificate file exists on disk and whether the ACME
/// engine considers it due for renewal.
pub async fn get_certificate_status(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AcmeApiError> {
    let cfg = state
        .config_store
        .load_acme_config()
        .map_err(AcmeApiError::StorageError)?;

    let Some(cfg) = cfg else {
        return Ok(Json(AcmeCertStatus {
            domain: None,
            cert_exists: false,
            needs_renewal: false,
        }));
    };

    let primary_domain = cfg.domains.first().cloned();
    let engine = AcmeEngine::new(cfg);

    let (cert_exists, needs_renewal) = if let Some(domain) = &primary_domain {
        let exists = engine.cert_path(domain).exists();
        let renewal = engine.renewal_check().await.unwrap_or(true);
        (exists, renewal)
    } else {
        (false, false)
    };

    Ok(Json(AcmeCertStatus {
        domain: primary_domain,
        cert_exists,
        needs_renewal,
    }))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acme_api_error_validation_status_is_422() {
        use axum::response::IntoResponse;
        let err = AcmeApiError::ValidationFailed("bad email".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn acme_api_error_storage_status_is_500() {
        let err = AcmeApiError::StorageError(anyhow::anyhow!("disk error"));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn acme_api_error_engine_status_is_500() {
        let err = AcmeApiError::EngineError("protocol error".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
