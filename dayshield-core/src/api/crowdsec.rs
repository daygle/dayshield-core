//! CrowdSec API endpoints.
//!
//! # GET /crowdsec/config
//!
//! Returns the persisted [`CrowdSecConfig`].  When no configuration has been
//! saved yet, returns a default (disabled) configuration so clients always
//! receive a well-formed object.
//!
//! # POST /crowdsec/config
//!
//! Accepts a full [`CrowdSecConfig`] JSON body, validates all fields,
//! atomically persists the config, and immediately triggers
//! [`refresh_decisions`] so the nftables ban set is updated without waiting
//! for the next poll interval.  Returns the saved config with `200 OK`.
//!
//! # GET /crowdsec/decisions
//!
//! Returns the cached [`CrowdSecDecision`] list held in [`AppState`].  The
//! list is populated by the background polling loop (or by the immediate
//! refresh triggered after `POST /crowdsec/config`).

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::{info, warn};

use crate::{
    config::models::{validate_alias_name, validate_api_key, validate_url, CrowdSecConfig},
    engine::crowdsec::refresh_decisions,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the CrowdSec API handlers.
#[derive(Debug, thiserror::Error)]
pub enum CrowdSecError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The engine failed to refresh decisions.
    #[error("engine error: {0}")]
    EngineError(String),
}

impl IntoResponse for CrowdSecError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            CrowdSecError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            CrowdSecError::StorageError(_) | CrowdSecError::EngineError(_) => {
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

/// Request body for `POST /crowdsec/config`.
#[derive(serde::Deserialize)]
pub struct UpdateCrowdSecConfigRequest {
    pub enabled: bool,
    pub lapi_url: String,
    pub api_key: String,
    pub update_interval: u64,
    pub ban_alias_name: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: return the current CrowdSec configuration.
///
/// Loads the CrowdSec config from persistent storage.  Returns a sensible
/// default (disabled) when no configuration has been saved yet.  The
/// `api_key` field is always redacted in the response.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, CrowdSecError> {
    let mut cfg = state
        .config_store
        .load_crowdsec_config()
        .map_err(CrowdSecError::StorageError)?
        .unwrap_or_else(|| CrowdSecConfig {
            enabled: false,
            lapi_url: "http://127.0.0.1:8080".into(),
            api_key: String::new(),
            update_interval: 60,
            ban_alias_name: "crowdsec_bans".into(),
        });

    info!(enabled = cfg.enabled, "crowdsec: loaded config");
    cfg.api_key = String::new();
    Ok(Json(cfg))
}

/// Handler: update the CrowdSec configuration.
///
/// Validates all fields, persists atomically, then triggers an immediate
/// decision refresh so the nftables ban set reflects the new configuration
/// right away.  Returns the saved config with `200 OK` on success.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateCrowdSecConfigRequest>,
) -> Result<impl IntoResponse, CrowdSecError> {
    // --- Validation --------------------------------------------------------

    if !validate_url(&req.lapi_url) {
        warn!(lapi_url = %req.lapi_url, "crowdsec: invalid lapi_url");
        return Err(CrowdSecError::ValidationFailed(format!(
            "lapi_url {:?} is not a valid HTTP/HTTPS URL",
            req.lapi_url
        )));
    }

    if !validate_api_key(&req.api_key) {
        return Err(CrowdSecError::ValidationFailed(
            "api_key must not be empty".into(),
        ));
    }

    if req.update_interval == 0 {
        return Err(CrowdSecError::ValidationFailed(
            "update_interval must be greater than 0".into(),
        ));
    }

    if !validate_alias_name(&req.ban_alias_name) {
        return Err(CrowdSecError::ValidationFailed(format!(
            "ban_alias_name {:?} is invalid \
             (must be 1–63 chars, start with letter or _, contain only [A-Za-z0-9_])",
            req.ban_alias_name
        )));
    }

    // --- Build config ------------------------------------------------------

    let cfg = CrowdSecConfig {
        enabled: req.enabled,
        lapi_url: req.lapi_url,
        api_key: req.api_key,
        update_interval: req.update_interval,
        ban_alias_name: req.ban_alias_name,
    };

    info!(
        enabled = cfg.enabled,
        lapi_url = %cfg.lapi_url,
        "crowdsec: received update config request"
    );

    // --- Persist -----------------------------------------------------------

    state
        .config_store
        .save_crowdsec_config(cfg.clone())
        .map_err(CrowdSecError::StorageError)?;

    info!("crowdsec: config persisted");

    // --- Immediate refresh -------------------------------------------------

    // Trigger a decision refresh so the ban set is updated right away.
    // Only run when the integration is enabled; failures are soft-warned.
    if cfg.enabled {
        if let Err(e) = refresh_decisions(&cfg, &state).await {
            warn!(error = %e, "crowdsec: immediate decision refresh failed after config update");
        }
    }

    let mut resp = cfg;
    resp.api_key = String::new();
    Ok(Json(resp))
}

/// Handler: return the cached CrowdSec decision list.
///
/// Returns the in-memory decision cache populated by the most recent LAPI
/// poll.  The list may be empty if no decisions have been fetched yet (e.g.
/// the integration is disabled or no ban has been issued).
pub async fn get_decisions(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, CrowdSecError> {
    let decisions = state.crowdsec_decisions.read().await.clone();
    info!(count = decisions.len(), "crowdsec: returning cached decisions");
    Ok(Json(decisions))
}
