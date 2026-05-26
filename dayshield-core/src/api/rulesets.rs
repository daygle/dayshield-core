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

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    config::models::is_valid_interface_name,
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

#[derive(Debug, Deserialize, Default)]
pub struct RulesetScopeQuery {
    pub iface: Option<String>,
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

fn ruleset_to_response_scoped(
    r: &InstalledRuleset,
    scoped_enabled: Option<bool>,
) -> InstalledRulesetResponse {
    let mut response = ruleset_to_response(r);
    if let Some(enabled) = scoped_enabled {
        response.enabled = enabled;
    }
    response
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

fn normalize_scope_iface(raw: Option<String>) -> Result<Option<String>, RulesetError> {
    let Some(iface) = raw else {
        return Ok(None);
    };
    let iface = iface.trim().to_string();
    if iface.is_empty() {
        return Ok(None);
    }
    if !is_valid_interface_name(&iface) {
        return Err(RulesetError::ValidationFailed(format!(
            "interface '{iface}' is not a valid interface name"
        )));
    }
    Ok(Some(iface))
}

fn ensure_interface_seed(
    overrides: &mut HashMap<String, Vec<String>>,
    iface: &str,
    rulesets: &[InstalledRuleset],
) {
    if overrides.contains_key(iface) {
        return;
    }

    let mut ids = rulesets
        .iter()
        .filter(|ruleset| ruleset.enabled)
        .map(|ruleset| ruleset.id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    overrides.insert(iface.to_string(), ids);
}

fn ruleset_enabled_for_iface(
    ruleset: &InstalledRuleset,
    iface: Option<&str>,
    overrides: &HashMap<String, Vec<String>>,
) -> bool {
    match iface {
        Some(interface) => overrides
            .get(interface)
            .map(|ids| ids.iter().any(|id| id == &ruleset.id))
            .unwrap_or(ruleset.enabled),
        None => ruleset.enabled,
    }
}

fn set_iface_membership(ids: &mut Vec<String>, id: &str, enabled: bool) -> bool {
    if enabled {
        if ids.iter().any(|existing| existing == id) {
            return false;
        }
        ids.push(id.to_string());
        ids.sort();
        ids.dedup();
        return true;
    }

    let original_len = ids.len();
    ids.retain(|existing| existing != id);
    original_len != ids.len()
}

fn apply_interface_scoped_state_to_global_enabled(
    state: &Arc<AppState>,
    rulesets: &mut [InstalledRuleset],
    overrides: &HashMap<String, Vec<String>>,
) -> Result<bool, RulesetError> {
    let monitored_interfaces = state
        .config_store
        .load_suricata_config()?
        .map(|cfg| cfg.interfaces)
        .unwrap_or_default();

    if monitored_interfaces.is_empty() {
        return Ok(false);
    }

    let mut changed = false;
    for ruleset in rulesets.iter_mut() {
        let mut has_scoped_data = false;
        let mut next_enabled = false;

        for iface in &monitored_interfaces {
            if let Some(ids) = overrides.get(iface) {
                has_scoped_data = true;
                if ids.iter().any(|id| id == &ruleset.id) {
                    next_enabled = true;
                    break;
                }
            }
        }

        if !has_scoped_data {
            continue;
        }

        if ruleset.enabled != next_enabled {
            ruleset.enabled = next_enabled;
            changed = true;
        }
    }

    Ok(changed)
}

pub(crate) fn reconcile_interface_scoped_enablement(
    state: &Arc<AppState>,
) -> Result<bool, RulesetError> {
    let store = RulesetStore::new();
    let mut rulesets = store.load().unwrap_or_default();
    if rulesets.is_empty() {
        return Ok(false);
    }

    let overrides = store.load_interface_enabled().unwrap_or_default();
    if overrides.is_empty() {
        return Ok(false);
    }

    if !apply_interface_scoped_state_to_global_enabled(state, &mut rulesets, &overrides)? {
        return Ok(false);
    }

    store.save(&rulesets)?;
    Ok(true)
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
    Query(query): Query<RulesetScopeQuery>,
    State(_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let scoped_iface = normalize_scope_iface(query.iface)?;
    let rulesets = RulesetStore::new().load().unwrap_or_default();
    let overrides = RulesetStore::new()
        .load_interface_enabled()
        .unwrap_or_default();
    let response: Vec<InstalledRulesetResponse> = rulesets
        .iter()
        .map(|ruleset| {
            ruleset_to_response_scoped(
                ruleset,
                Some(ruleset_enabled_for_iface(
                    ruleset,
                    scoped_iface.as_deref(),
                    &overrides,
                )),
            )
        })
        .collect();

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
    Query(query): Query<RulesetScopeQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let scoped_iface = normalize_scope_iface(query.iface)?;
    let manager = make_manager(&state);

    if let Some(iface) = scoped_iface {
        let _ = manager.enable(&id).await.map_err(|err| {
            let message = err.to_string();
            if message.contains("has no local rules file") {
                RulesetError::ValidationFailed(message)
            } else {
                RulesetError::OperationFailed(err)
            }
        })?;

        let store = RulesetStore::new();
        let mut rulesets = store.load().unwrap_or_default();
        let idx = rulesets
            .iter()
            .position(|ruleset| ruleset.id == id)
            .ok_or_else(|| RulesetError::NotFound(format!("Ruleset '{id}' not found")))?;

        let mut overrides = store.load_interface_enabled().unwrap_or_default();
        ensure_interface_seed(&mut overrides, &iface, &rulesets);
        let ids = overrides.get_mut(&iface).ok_or_else(|| {
            RulesetError::OperationFailed(anyhow::anyhow!("failed to scope ruleset"))
        })?;
        let scoped_changed = set_iface_membership(ids, &id, true);
        if scoped_changed {
            store.save_interface_enabled(&overrides)?;
        }

        let global_changed =
            apply_interface_scoped_state_to_global_enabled(&state, &mut rulesets, &overrides)?;
        if global_changed {
            store.save(&rulesets)?;
            manager.apply_suricata_config().await?;
        }

        let scoped_enabled = overrides
            .get(&iface)
            .map(|items| items.iter().any(|item| item == &id))
            .unwrap_or(rulesets[idx].enabled);

        return Ok(Json(serde_json::json!({
            "success": true,
            "data": ruleset_to_response_scoped(&rulesets[idx], Some(scoped_enabled))
        })));
    }

    let result = manager.enable(&id).await.map_err(|err| {
        let message = err.to_string();
        if message.contains("has no local rules file") {
            RulesetError::ValidationFailed(message)
        } else {
            RulesetError::OperationFailed(err)
        }
    })?;

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
    Query(query): Query<RulesetScopeQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, RulesetError> {
    let scoped_iface = normalize_scope_iface(query.iface)?;
    let manager = make_manager(&state);

    if let Some(iface) = scoped_iface {
        let store = RulesetStore::new();
        let mut rulesets = store.load().unwrap_or_default();
        let idx = rulesets
            .iter()
            .position(|ruleset| ruleset.id == id)
            .ok_or_else(|| RulesetError::NotFound(format!("Ruleset '{id}' not found")))?;

        let mut overrides = store.load_interface_enabled().unwrap_or_default();
        ensure_interface_seed(&mut overrides, &iface, &rulesets);
        let ids = overrides.get_mut(&iface).ok_or_else(|| {
            RulesetError::OperationFailed(anyhow::anyhow!("failed to scope ruleset"))
        })?;
        let scoped_changed = set_iface_membership(ids, &id, false);
        if scoped_changed {
            store.save_interface_enabled(&overrides)?;
        }

        let global_changed =
            apply_interface_scoped_state_to_global_enabled(&state, &mut rulesets, &overrides)?;
        if global_changed {
            store.save(&rulesets)?;
            manager.apply_suricata_config().await?;
        }

        let scoped_enabled = overrides
            .get(&iface)
            .map(|items| items.iter().any(|item| item == &id))
            .unwrap_or(rulesets[idx].enabled);

        return Ok(Json(serde_json::json!({
            "success": true,
            "data": ruleset_to_response_scoped(&rulesets[idx], Some(scoped_enabled))
        })));
    }

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

    let response: Vec<RuleResponse> = rules
        .iter()
        .map(|r| RuleResponse {
            id: r.id.clone(),
            action: r.action.clone(),
            signature: r.signature.clone(),
            enabled: r.enabled,
        })
        .collect();

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
    let _ruleset = rulesets
        .iter()
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
