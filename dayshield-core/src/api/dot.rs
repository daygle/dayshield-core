//! DNS-over-TLS (DoT) endpoints.
//!
//! | Method | Path              | Description                              |
//! |--------|-------------------|------------------------------------------|
//! | GET    | `/dns/dot/config` | Get current DoT configuration            |
//! | POST   | `/dns/dot/config` | Update DoT configuration and apply it    |
//!
//! When enabled, Unbound listens on the configured port (default 853) using
//! the provided TLS certificate and private key, accepting connections from
//! any client.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::info;

use crate::{
    config::models::{validate_dot_config, DotConfig},
    engine::dns::apply_config,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the DoT API handlers.
#[derive(Debug, thiserror::Error)]
pub enum DotError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The DNS engine failed to apply the configuration.
    #[error("engine error: {0}")]
    EngineError(String),
}

impl IntoResponse for DotError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            DotError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            DotError::StorageError(_) | DotError::EngineError(_) => {
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
// Request body
// ---------------------------------------------------------------------------

/// Request body for `POST /dns/dot/config`.
#[derive(serde::Deserialize)]
pub struct UpdateDotConfigRequest {
    /// Whether the DoT listener should be active.
    pub enabled: bool,
    /// TCP port to listen on (default 853).
    #[serde(default = "default_dot_port")]
    pub port: u16,
    /// Restrict DoT access to LAN clients only.
    #[serde(default = "default_dot_lan_only")]
    pub lan_only: bool,
    /// PEM-encoded TLS certificate chain.
    #[serde(default)]
    pub cert_pem: String,
    /// PEM-encoded private key matching the certificate.
    #[serde(default)]
    pub key_pem: String,
    /// ACME domain whose issued certificate should be used for DoT.
    #[serde(default)]
    pub acme_domain: Option<String>,
    /// Optional ACME certificate storage path to use for this DoT selection.
    #[serde(default)]
    pub acme_cert_storage_path: Option<String>,
}

fn default_dot_port() -> u16 {
    853
}

fn default_dot_lan_only() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: return the current DoT configuration.
///
/// When no DoT configuration has been saved yet, returns the default
/// (disabled) configuration.  The private key is included in the response;
/// this endpoint is protected by the application-level JWT auth middleware
/// applied to all registered API routes.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, DotError> {
    let cfg = state
        .config_store
        .load_dot_config()
        .map_err(DotError::StorageError)?
        .unwrap_or_default();

    info!(enabled = cfg.enabled, port = cfg.port, "dot: loaded config");

    Ok(Json(serde_json::json!({ "success": true, "data": cfg })))
}

/// Handler: update the DoT configuration.
///
/// Validates all fields, persists atomically, then re-applies the DNS engine
/// (which writes TLS files and regenerates `unbound.conf`).  Returns the
/// saved config with `200 OK` on success.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateDotConfigRequest>,
) -> Result<impl IntoResponse, DotError> {
    let acme_domain = req
        .acme_domain
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .cloned();

    let acme_cert_storage_path = if acme_domain.is_some() {
        state
            .config_store
            .load_acme_config()
            .map_err(DotError::StorageError)?
            .map(|cfg| cfg.cert_storage_path)
            .or_else(|| Some("/etc/dayshield/certs".to_string()))
    } else {
        None
    };

    let cfg = DotConfig {
        enabled: req.enabled,
        port: req.port,
        lan_only: req.lan_only,
        cert_pem: req.cert_pem.trim().is_empty().then(|| None).or(Some(req.cert_pem)),
        key_pem: req.key_pem.trim().is_empty().then(|| None).or(Some(req.key_pem)),
        acme_domain,
        acme_cert_storage_path: req
            .acme_cert_storage_path
            .filter(|s| !s.trim().is_empty())
            .or(acme_cert_storage_path),
    };

    // --- Validation --------------------------------------------------------

    if let Err(msg) = validate_dot_config(&cfg) {
        return Err(DotError::ValidationFailed(msg));
    }

    // --- Persist -----------------------------------------------------------

    state
        .config_store
        .save_dot_config(cfg.clone())
        .map_err(DotError::StorageError)?;

    info!(enabled = cfg.enabled, port = cfg.port, "dot: config persisted");

    // --- Apply -------------------------------------------------------------
    //
    // Re-apply the full DNS engine so that unbound.conf is regenerated with
    // the new (or removed) TLS stanzas and Unbound is reloaded.

    let dns_cfg = state
        .config_store
        .load_dns_config()
        .map_err(DotError::StorageError)?
        .unwrap_or_default();

    apply_config(&dns_cfg, Some(&cfg))
        .await
        .map_err(|e| DotError::EngineError(e.to_string()))?;

    info!("dot: engine apply complete");

    Ok(Json(serde_json::json!({ "success": true, "data": cfg })))
}
