//! Suricata IPS endpoints — `GET /ips/config` and `POST /ips/config`.
//!
//! # GET /ips/config
//!
//! Returns the persisted [`SuricataConfig`].  When no Suricata configuration
//! has been saved yet, returns a default (disabled) configuration.
//!
//! # POST /ips/config
//!
//! Accepts a full [`SuricataConfig`] JSON body, validates all fields,
//! atomically persists it, and triggers the Suricata engine to regenerate
//! and apply `suricata.yaml`.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::{info, warn};

use crate::{
    config::models::{is_valid_cidr, RuleSource, SuricataConfig},
    engine::suricata::apply_config,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the Suricata API handlers.
#[derive(Debug, thiserror::Error)]
pub enum SuricataError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The Suricata engine failed to apply the configuration.
    #[error("engine error: {0:#}")]
    EngineError(String),
}

impl IntoResponse for SuricataError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            SuricataError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            SuricataError::StorageError(_) | SuricataError::EngineError(_) => {
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

/// Request body for `POST /ips/config`.
#[derive(serde::Deserialize)]
pub struct UpdateSuricataConfigRequest {
    pub enabled: bool,
    pub home_nets: Vec<String>,
    pub external_nets: Vec<String>,
    pub rule_sources: Vec<RuleSource>,
    pub eve_log_enabled: bool,
    pub eve_log_path: String,
    pub stats_log_enabled: bool,
    pub stats_log_path: String,
    /// Stats flush interval in seconds; 0 uses Suricata's default (8s).
    #[serde(default)]
    pub stats_interval_seconds: u32,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: return the current Suricata IPS configuration.
///
/// Loads the Suricata config from persistent storage.  If no configuration
/// has been saved yet, returns a sensible default (disabled).
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SuricataError> {
    let cfg = state
        .config_store
        .load_suricata_config()
        .map_err(SuricataError::StorageError)?
        .unwrap_or_else(|| SuricataConfig {
            enabled: false,
            home_nets: vec![],
            external_nets: vec![],
            rule_sources: vec![],
            eve_log_enabled: false,
            eve_log_path: "/var/log/suricata/eve.json".into(),
            stats_log_enabled: false,
            stats_log_path: "/var/log/suricata/stats.log".into(),
            stats_interval_seconds: 0,
        });

    info!(enabled = cfg.enabled, "suricata: loaded config");

    Ok(Json(cfg))
}

/// Handler: update the Suricata IPS configuration.
///
/// Validates all fields, persists atomically, then triggers the Suricata
/// engine to regenerate and apply `suricata.yaml`.  Returns the saved config
/// with `200 OK` on success.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateSuricataConfigRequest>,
) -> Result<impl IntoResponse, SuricataError> {
    // --- Validation --------------------------------------------------------

    for cidr in req.home_nets.iter().chain(req.external_nets.iter()) {
        if !is_valid_cidr(cidr) {
            warn!(cidr = %cidr, "suricata: invalid CIDR");
            return Err(SuricataError::ValidationFailed(format!(
                "invalid CIDR: {cidr} (expected IPv4/IPv6 CIDR notation, e.g. 192.168.1.0/24)"
            )));
        }
    }

    if req.eve_log_enabled && req.eve_log_path.is_empty() {
        return Err(SuricataError::ValidationFailed(
            "eve_log_path must not be empty when eve_log_enabled is true".into(),
        ));
    }

    if req.stats_log_enabled && req.stats_log_path.is_empty() {
        return Err(SuricataError::ValidationFailed(
            "stats_log_path must not be empty when stats_log_enabled is true".into(),
        ));
    }

    // Each rule source must have at least one of url or path set.
    for src in &req.rule_sources {
        if src.url.is_none() && src.path.is_none() {
            return Err(SuricataError::ValidationFailed(format!(
                "rule source {:?} must have either a url or a path",
                src.name
            )));
        }
    }

    // --- Build config ------------------------------------------------------

    let cfg = SuricataConfig {
        enabled: req.enabled,
        home_nets: req.home_nets,
        external_nets: req.external_nets,
        rule_sources: req.rule_sources,
        eve_log_enabled: req.eve_log_enabled,
        eve_log_path: req.eve_log_path,
        stats_log_enabled: req.stats_log_enabled,
        stats_log_path: req.stats_log_path,
        stats_interval_seconds: req.stats_interval_seconds,
    };

    info!(
        enabled = cfg.enabled,
        home_nets = cfg.home_nets.len(),
        rule_sources = cfg.rule_sources.len(),
        "suricata: received update config request"
    );

    // --- Persist -----------------------------------------------------------

    state
        .config_store
        .save_suricata_config(cfg.clone())
        .map_err(SuricataError::StorageError)?;

    info!("suricata: config persisted");

    // --- Apply -------------------------------------------------------------

    apply_config(&cfg)
        .await
        .map_err(|e| SuricataError::EngineError(e.to_string()))?;

    info!("suricata: engine apply complete");

    Ok(Json(cfg))
}
