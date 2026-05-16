//! Managed Suricata ruleset API endpoints.
//!
//! | Method | Path                               | Description                          |
//! |--------|------------------------------------|--------------------------------------|
//! | GET    | `/rulesets/available`              | List curated ruleset sources         |
//! | GET    | `/rulesets`                        | List installed rulesets with status  |
//! | POST   | `/rulesets/:id/install`            | Install a curated ruleset            |
//! | POST   | `/rulesets/:id/check-update`       | Check for an available update        |
//! | POST   | `/rulesets/check-all-updates`      | Check updates for all installed      |
//! | POST   | `/rulesets/:id/update`             | Apply an available update            |
//! | POST   | `/rulesets/:id/enable`             | Enable an installed ruleset          |
//! | POST   | `/rulesets/:id/disable`            | Disable an installed ruleset         |
//! | DELETE | `/rulesets/:id`                    | Uninstall a ruleset                  |
//! | GET    | `/rulesets/:id/rules`              | List all rules in a ruleset          |
//! | POST   | `/rulesets/:id/disabled-rules`     | Update set of disabled rule IDs      |

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Serialize;

use crate::{
    rules::{
        manager::RulesetManager,
        models::{CuratedSource, InstalledRuleset, RulesetStatus},
        sources::curated_sources,
        storage::RulesetStore,
    },
    state::AppState,
};

/// Fallback config directory used when the config store path has no parent.
const DEFAULT_CONFIG_DIR: &str = "/etc/dayshield/config";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the rulesets API handlers.
#[derive(Debug, thiserror::Error)]
pub enum RulesetError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("validation error: {0}")]
    ValidationFailed(String),
    #[error("operation error: {0:#}")]
    OperationFailed(#[from] anyhow::Error),
}

impl IntoResponse for RulesetError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            RulesetError::NotFound(_) => StatusCode::NOT_FOUND,
            RulesetError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            RulesetError::OperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// API DTO types
// ---------------------------------------------------------------------------

/// Wire-format for a curated (available) ruleset source.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CuratedSourceResponse {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub url: String,
    pub license: String,
    pub vendor: String,
    /// Whether this source is currently installed.
    pub installed: bool,
}

/// Wire-format for an installed ruleset.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledRulesetResponse {
    pub id: String,
    pub display_name: String,
    pub source_url: String,
    pub installed_version: Option<String>,
    pub latest_version: Option<String>,
    pub enabled: bool,
    pub status: String,
    pub last_error: Option<String>,
    pub last_checked: Option<String>,
    pub last_updated: Option<String>,
    pub local_path: Option<String>,
    pub update_available: bool,
}

/// Wire-format for a single rule in a ruleset.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleResponse {
    pub id: String,
    pub action: String,
    pub signature: String,
    pub enabled: bool,
}

/// Request body for updating disabled rules.
#[derive(serde::Deserialize)]
pub struct UpdateDisabledRulesRequest {
    pub ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

fn to_status_str(s: &RulesetStatus) -> &'static str {
    match s {
        RulesetStatus::Installed => "installed",
        RulesetStatus::UpdateAvailable => "update_available",
        RulesetStatus::Failed => "failed",
    }
}

fn ruleset_to_response(r: &InstalledRuleset) -> InstalledRulesetResponse {
    InstalledRulesetResponse {
        id: r.id.clone(),
        display_name: r.display_name.clone(),
        source_url: r.source_url.clone(),
        installed_version: r.installed_version.clone(),
        latest_version: r.latest_version.clone(),
        enabled: r.enabled,
        status: to_status_str(&r.status).to_string(),
        last_error: r.last_error.clone(),
        last_checked: r.last_checked.map(|t| t.to_rfc3339()),
        last_updated: r.last_updated.map(|t| t.to_rfc3339()),
        local_path: r.local_path.clone(),
        update_available: r.status == RulesetStatus::UpdateAvailable,
    }
}

fn source_to_response(s: &CuratedSource, installed_ids: &[String]) -> CuratedSourceResponse {
    CuratedSourceResponse {
        id: s.id.clone(),
        display_name: s.display_name.clone(),
        description: s.description.clone(),
        url: s.url.clone(),
        license: s.license.clone(),
        vendor: s.vendor.clone(),
        installed: installed_ids.iter().any(|id| id == &s.id),
    }
}

fn make_manager(state: &Arc<AppState>) -> RulesetManager {
    let config_dir = state
        .config_store
        .config_path()
        .parent()
        .unwrap_or_else(|| std::path::Path::new(DEFAULT_CONFIG_DIR))
        .to_path_buf();
    RulesetManager::new(config_dir)
}

pub(crate) async fn run_scheduled_ruleset_updates(
    state: &Arc<AppState>,
) -> Result<(usize, usize), RulesetError> {
    let manager = make_manager(state);
    let checked = manager.check_all_updates().await?;

    let mut updated = 0usize;
    let mut failed = 0usize;

    for ruleset in checked
        .into_iter()
        .filter(|ruleset| ruleset.status == RulesetStatus::UpdateAvailable)
    {
        match manager.update(&ruleset.id).await {
            Ok(_) => updated += 1,
            Err(_) => failed += 1,
        }
    }

    Ok((updated, failed))
}

// ---------------------------------------------------------------------------
// GET /rulesets/available
// ---------------------------------------------------------------------------

/// List all curated ruleset sources, indicating which are already installed.
pub async fn list_available(
    State(_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let installed_ids: Vec<String> = RulesetStore::new()
        .load()
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.id)
        .collect();

    let sources = curated_sources();
    let response: Vec<CuratedSourceResponse> = sources
        .iter()
        .map(|s| source_to_response(s, &installed_ids))
        .collect();

    Ok(Json(serde_json::json!({
        "success": true,
        "data": response
    })))
}

// ---------------------------------------------------------------------------
// GET /rulesets
// ---------------------------------------------------------------------------

/// List all installed rulesets with their current status.
pub async fn list_installed(
    State(_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let rulesets = RulesetStore::new().load().unwrap_or_default();
    let response: Vec<InstalledRulesetResponse> = rulesets.iter().map(ruleset_to_response).collect();

    Ok(Json(serde_json::json!({
        "success": true,
        "data": response
    })))
}

// ---------------------------------------------------------------------------
// POST /rulesets/:id/install
// ---------------------------------------------------------------------------

/// Download and install a curated ruleset.
pub async fn install_ruleset(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let manager = make_manager(&state);
    let result = manager.install(&id).await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "data": ruleset_to_response(&result)
        })),
    ))
}

// ---------------------------------------------------------------------------
// POST /rulesets/:id/check-update
// ---------------------------------------------------------------------------

/// Check whether a newer version of a specific ruleset is available.
pub async fn check_update(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let manager = make_manager(&state);
    let result = manager.check_update(&id).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": ruleset_to_response(&result)
    })))
}

// ---------------------------------------------------------------------------
// POST /rulesets/check-all-updates
// ---------------------------------------------------------------------------

/// Check for updates on all installed rulesets.
pub async fn check_all_updates(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let manager = make_manager(&state);
    let results = manager.check_all_updates().await?;
    let response: Vec<InstalledRulesetResponse> = results.iter().map(ruleset_to_response).collect();

    Ok(Json(serde_json::json!({
        "success": true,
        "data": response
    })))
}

// ---------------------------------------------------------------------------
// POST /rulesets/:id/update
// ---------------------------------------------------------------------------

/// Apply an available update for an installed ruleset.
pub async fn update_ruleset(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let manager = make_manager(&state);
    let result = manager.update(&id).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": ruleset_to_response(&result)
    })))
}

// ---------------------------------------------------------------------------
// POST /rulesets/:id/enable
// ---------------------------------------------------------------------------

/// Enable an installed ruleset so Suricata includes it.
pub async fn enable_ruleset(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let manager = make_manager(&state);
    let result = manager.enable(&id).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": ruleset_to_response(&result)
    })))
}

// ---------------------------------------------------------------------------
// POST /rulesets/:id/disable
// ---------------------------------------------------------------------------

/// Disable an installed ruleset.
pub async fn disable_ruleset(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let manager = make_manager(&state);
    let result = manager.disable(&id).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": ruleset_to_response(&result)
    })))
}

// ---------------------------------------------------------------------------
// DELETE /rulesets/:id
// ---------------------------------------------------------------------------

/// Uninstall a ruleset and remove its files from disk.
pub async fn delete_ruleset(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let manager = make_manager(&state);
    manager.uninstall(&id).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Ruleset '{id}' uninstalled")
    })))
}

// ---------------------------------------------------------------------------
// GET /rulesets/:id/rules
// ---------------------------------------------------------------------------

/// List all rules in an installed ruleset with their enabled/disabled state.
pub async fn list_ruleset_rules(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let manager = make_manager(&state);
    let rules = manager.list_rules(&id)?;
    
    let response: Vec<RuleResponse> = rules.iter().map(|r| RuleResponse {
        id: r.id.clone(),
        action: r.action.clone(),
        signature: r.signature.clone(),
        enabled: r.enabled,
    }).collect();

    Ok(Json(serde_json::json!({
        "success": true,
        "data": response
    })))
}

// ---------------------------------------------------------------------------
// POST /rulesets/:id/disabled-rules
// ---------------------------------------------------------------------------

/// Update the set of disabled rule IDs for a ruleset.
pub async fn update_disabled_rules(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateDisabledRulesRequest>,
) -> Result<impl IntoResponse, RulesetError> {
    let manager = make_manager(&state);
    
    // Validate ruleset exists
    let rulesets = RulesetStore::new().load().unwrap_or_default();
    let _ruleset = rulesets.iter()
        .find(|r| r.id == id)
        .ok_or_else(|| RulesetError::NotFound(format!("Ruleset '{}' not found", id)))?;
    
    // Save disabled rules
    let disabled = crate::rules::models::DisabledRules { ids: req.ids };
    manager.save_disabled_rules(&id, &disabled)?;
    
    // Regenerate rules file to filter out disabled rules
    manager.regenerate_effective_rules(&id)?;
    
    // Regenerate Suricata config to apply changes
    manager.apply_suricata_config().await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Disabled rules updated for '{id}'")
    })))
}
