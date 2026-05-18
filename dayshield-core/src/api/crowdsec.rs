//! CrowdSec API endpoints.
//!
//! # GET /crowdsec/config
//!
//! Returns the persisted [`CrowdSecConfig`]. When no configuration has been
//! saved yet, returns a default disabled configuration so clients always
//! receive a well-formed object.
//!
//! # POST /crowdsec/config
//!
//! Accepts a partial [`CrowdSecConfig`] JSON body, validates the merged config,
//! atomically persists it, and immediately triggers [`refresh_decisions`] so
//! the nftables ban set is updated without waiting for the next poll interval.
//! Returns the saved config with `200 OK`.
//!
//! # GET /crowdsec/decisions
//!
//! Returns the cached [`CrowdSecDecision`] list held in [`AppState`]. The list
//! is populated by the background polling loop or by the immediate refresh
//! triggered after `POST /crowdsec/config`.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
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
}

impl IntoResponse for CrowdSecError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            CrowdSecError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            CrowdSecError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Response shape for CrowdSec configuration endpoints.
#[derive(Serialize)]
pub struct CrowdSecApiConfig {
    pub enabled: bool,
    pub lapi_url: String,
    /// Always redacted. Use `api_key_configured` to tell whether a key exists.
    pub api_key: String,
    pub api_key_configured: bool,
    pub update_interval: u64,
    pub ban_alias_name: String,
}

/// Request body for `POST /crowdsec/config`.
///
/// All fields are optional so dashboard toggles can update just the enabled
/// state. An empty `api_key` keeps the existing key, which avoids losing a
/// secret after the redacted config has been loaded by the UI.
#[derive(Deserialize)]
pub struct UpdateCrowdSecConfigRequest {
    pub enabled: Option<bool>,
    pub lapi_url: Option<String>,
    pub api_key: Option<String>,
    pub update_interval: Option<u64>,
    pub ban_alias_name: Option<String>,
}

fn default_crowdsec_cfg() -> CrowdSecConfig {
    CrowdSecConfig {
        enabled: false,
        lapi_url: "http://127.0.0.1:8080".into(),
        api_key: String::new(),
        update_interval: 60,
        ban_alias_name: "crowdsec_bans".into(),
    }
}

fn to_api_config(cfg: &CrowdSecConfig) -> CrowdSecApiConfig {
    CrowdSecApiConfig {
        enabled: cfg.enabled,
        lapi_url: cfg.lapi_url.clone(),
        api_key: String::new(),
        api_key_configured: validate_api_key(&cfg.api_key),
        update_interval: cfg.update_interval,
        ban_alias_name: cfg.ban_alias_name.clone(),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: return the current CrowdSec configuration.
///
/// Loads the CrowdSec config from persistent storage. Returns a sensible
/// default when no configuration has been saved yet. The `api_key` field is
/// always redacted in the response.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, CrowdSecError> {
    let cfg = state
        .config_store
        .load_crowdsec_config()
        .map_err(CrowdSecError::StorageError)?
        .unwrap_or_else(default_crowdsec_cfg);

    info!(enabled = cfg.enabled, "crowdsec: loaded config");
    Ok(Json(to_api_config(&cfg)))
}

/// Handler: update the CrowdSec configuration.
///
/// Merges supplied fields onto the saved config, validates, persists
/// atomically, then triggers an immediate decision refresh so the nftables ban
/// set reflects the new configuration right away. Returns the saved config
/// with `200 OK` on success.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateCrowdSecConfigRequest>,
) -> Result<impl IntoResponse, CrowdSecError> {
    let mut cfg = state
        .config_store
        .load_crowdsec_config()
        .map_err(CrowdSecError::StorageError)?
        .unwrap_or_else(default_crowdsec_cfg);

    if let Some(enabled) = req.enabled {
        cfg.enabled = enabled;
    }
    if let Some(lapi_url) = req.lapi_url {
        cfg.lapi_url = lapi_url.trim().to_string();
    }
    if let Some(api_key) = req.api_key {
        let trimmed = api_key.trim();
        if !trimmed.is_empty() {
            cfg.api_key = trimmed.to_string();
        }
    }
    if let Some(update_interval) = req.update_interval {
        cfg.update_interval = update_interval;
    }
    if let Some(ban_alias_name) = req.ban_alias_name {
        cfg.ban_alias_name = ban_alias_name.trim().to_string();
    }

    // --- Validation --------------------------------------------------------

    if !validate_url(&cfg.lapi_url) {
        warn!(lapi_url = %cfg.lapi_url, "crowdsec: invalid lapi_url");
        return Err(CrowdSecError::ValidationFailed(format!(
            "lapi_url {:?} is not a valid HTTP/HTTPS URL",
            cfg.lapi_url
        )));
    }

    if cfg.enabled && !validate_api_key(&cfg.api_key) {
        return Err(CrowdSecError::ValidationFailed(
            "api_key is required before enabling CrowdSec".into(),
        ));
    }

    if cfg.update_interval == 0 {
        return Err(CrowdSecError::ValidationFailed(
            "update_interval must be greater than 0".into(),
        ));
    }

    if !validate_alias_name(&cfg.ban_alias_name) {
        return Err(CrowdSecError::ValidationFailed(format!(
            "ban_alias_name {:?} is invalid \
             (must be 1-63 chars, start with letter or _, contain only [A-Za-z0-9_])",
            cfg.ban_alias_name
        )));
    }

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

    Ok(Json(to_api_config(&cfg)))
}

/// Handler: return the cached CrowdSec decision list.
///
/// Returns the in-memory decision cache populated by the most recent LAPI
/// poll. The list may be empty if no decisions have been fetched yet.
pub async fn get_decisions(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, CrowdSecError> {
    let decisions = state.crowdsec_decisions.read().await.clone();
    info!(
        count = decisions.len(),
        "crowdsec: returning cached decisions"
    );
    Ok(Json(decisions))
}
