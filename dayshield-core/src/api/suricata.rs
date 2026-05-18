//! Suricata IPS/IDS endpoints.
//!
//! | Method | Path                              | Description                               |
//! |--------|-----------------------------------|-------------------------------------------|
//! | GET    | `/suricata/config`                | Get the current Suricata configuration    |
//! | POST   | `/suricata/config`                | Update + apply the Suricata configuration |
//! | GET    | `/suricata/rulesets`              | List configured rule sources              |
//! | PUT    | `/suricata/rulesets/{id}`         | Enable / disable a rule source by index  |
//! | GET    | `/suricata/alerts`                | Recent alerts from the EVE JSON log       |
//! | GET    | `/interfaces/{name}/suricata`     | Get Suricata config scoped to interface   |
//! | POST   | `/interfaces/{name}/suricata`     | Update Suricata config for interface      |

use std::{collections::VecDeque, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncBufReadExt;
use tracing::{info, warn};

use crate::{
    config::models::{
        ensure_ipv6_allowed, is_valid_cidr, is_valid_interface_name, validate_suricata_config,
        validate_url, SuricataConfig,
    },
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
// API DTO types (camelCase for UI compatibility)
// ---------------------------------------------------------------------------

/// Response shape for `GET /suricata/config` and `POST /suricata/config`.
///
/// Uses camelCase field names to match the TypeScript `SuricataConfig` type.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuricataApiConfig {
    pub enabled: bool,
    pub interfaces: Vec<String>,
    pub mode: String,
    /// Maps from storage `home_nets` → JSON key `homeNet`.
    pub home_net: Vec<String>,
    /// Maps from storage `external_nets` → JSON key `externalNet`.
    pub external_net: Vec<String>,
}

/// Request body for `POST /suricata/config`.
///
/// All fields are optional - only supplied fields are updated (partial update).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSuricataApiRequest {
    pub enabled: Option<bool>,
    pub interfaces: Option<Vec<String>>,
    pub mode: Option<String>,
    pub home_net: Option<Vec<String>>,
    pub external_net: Option<Vec<String>>,
}

/// Response shape for a single rule source (`GET /suricata/rulesets`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuricataRulesetResponse {
    pub id: usize,
    pub name: String,
    pub source: String,
    pub enabled: bool,
    pub last_updated: Option<String>,
}

/// Request body for `POST /suricata/rulesets` (create new rule source).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRulesetRequest {
    pub name: String,
    pub url: Option<String>,
    pub path: Option<String>,
    pub enabled: Option<bool>,
}

/// Request body for `PUT /suricata/rulesets/{id}`.
#[derive(Deserialize)]
pub struct UpdateRulesetRequest {
    pub enabled: bool,
}

/// A single alert entry from the EVE JSON log.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuricataAlertResponse {
    pub id: usize,
    pub timestamp: String,
    pub interface: Option<String>,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub signature: String,
    pub category: String,
    pub severity: String,
    pub action: String,
}

#[derive(Deserialize)]
pub struct ListAlertsQuery {
    pub limit: Option<usize>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_suricata_cfg() -> SuricataConfig {
    SuricataConfig {
        enabled: false,
        interfaces: vec![],
        mode: "ids".to_string(),
        home_nets: vec![],
        external_nets: vec![],
        rule_sources: vec![],
        eve_log_enabled: false,
        eve_log_path: "/var/log/suricata/eve.json".into(),
        stats_log_enabled: false,
        stats_log_path: "/var/log/suricata/stats.log".into(),
        stats_interval_seconds: 0,
    }
}

fn to_api_config(cfg: &SuricataConfig) -> SuricataApiConfig {
    SuricataApiConfig {
        enabled: cfg.enabled,
        interfaces: cfg.interfaces.clone(),
        mode: cfg.mode.clone(),
        home_net: cfg.home_nets.clone(),
        external_net: cfg.external_nets.clone(),
    }
}

fn map_severity(level: u64) -> &'static str {
    match level {
        1 => "high",
        2 => "medium",
        3 => "low",
        _ => "informational",
    }
}

fn is_blocked_suricata_ruleset_url(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    u.contains("suricata-7.0") || u.contains("/suricata-7/") || u.contains("suricata-7.")
}

const DEFAULT_ALERT_LIMIT: usize = 100;
const MAX_ALERT_LIMIT: usize = 1_000;

fn json_u16(value: &serde_json::Value, key: &str) -> u16 {
    value
        .get(key)
        .and_then(|p| p.as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(0)
}

fn parse_alert_line(line: &str) -> Option<SuricataAlertResponse> {
    if !line.contains("\"alert\"") {
        return None;
    }

    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v.get("event_type")?.as_str()? != "alert" {
        return None;
    }

    let alert = v.get("alert")?;
    let severity = map_severity(alert.get("severity").and_then(|s| s.as_u64()).unwrap_or(4));

    Some(SuricataAlertResponse {
        id: 0,
        timestamp: v
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string(),
        interface: v
            .get("in_iface")
            .or_else(|| v.get("interface"))
            .and_then(|i| i.as_str())
            .map(|s| s.to_string()),
        src_ip: v
            .get("src_ip")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        src_port: json_u16(&v, "src_port"),
        dst_ip: v
            .get("dest_ip")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        dst_port: json_u16(&v, "dest_port"),
        protocol: v
            .get("proto")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string(),
        signature: alert
            .get("signature")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        category: alert
            .get("category")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string(),
        severity: severity.to_string(),
        action: alert
            .get("action")
            .and_then(|a| a.as_str())
            .unwrap_or("alert")
            .to_string(),
    })
}

// ---------------------------------------------------------------------------
// GET /suricata/config
// ---------------------------------------------------------------------------

/// Return the current Suricata configuration in UI-compatible camelCase format.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SuricataError> {
    let cfg = state
        .config_store
        .load_suricata_config()
        .map_err(SuricataError::StorageError)?
        .unwrap_or_else(default_suricata_cfg);

    info!(enabled = cfg.enabled, "suricata: loaded config");

    Ok(Json(serde_json::json!({
        "success": true,
        "data": to_api_config(&cfg)
    })))
}

// ---------------------------------------------------------------------------
// POST /suricata/config
// ---------------------------------------------------------------------------

/// Update the Suricata configuration (partial update - only supplied fields
/// are changed).  Validates, persists, then applies via the engine.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateSuricataApiRequest>,
) -> Result<impl IntoResponse, SuricataError> {
    // Load existing config so we can merge.
    let mut cfg = state
        .config_store
        .load_suricata_config()
        .map_err(SuricataError::StorageError)?
        .unwrap_or_else(default_suricata_cfg);

    // Apply only the fields that were supplied.
    if let Some(v) = req.enabled {
        cfg.enabled = v;
    }
    if let Some(v) = req.interfaces {
        cfg.interfaces = v;
    }
    if let Some(v) = req.mode {
        cfg.mode = v.trim().to_ascii_lowercase();
    }
    if let Some(v) = req.home_net {
        cfg.home_nets = v;
    }
    if let Some(v) = req.external_net {
        cfg.external_nets = v;
    }

    cfg.interfaces = cfg
        .interfaces
        .into_iter()
        .map(|iface| iface.trim().to_string())
        .filter(|iface| !iface.is_empty())
        .collect();
    let mut seen_interfaces = std::collections::HashSet::new();
    cfg.interfaces
        .retain(|iface| seen_interfaces.insert(iface.clone()));
    cfg.home_nets = cfg
        .home_nets
        .into_iter()
        .map(|cidr| cidr.trim().to_string())
        .filter(|cidr| !cidr.is_empty())
        .collect();
    cfg.external_nets = cfg
        .external_nets
        .into_iter()
        .map(|cidr| cidr.trim().to_string())
        .filter(|cidr| !cidr.is_empty())
        .collect();

    // --- Validation --------------------------------------------------------

    if let Err(msg) = validate_suricata_config(&cfg) {
        warn!(error = %msg, "suricata: invalid config");
        return Err(SuricataError::ValidationFailed(msg));
    }

    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(SuricataError::StorageError)?
        .ipv6_enabled;

    for cidr in cfg.home_nets.iter().chain(cfg.external_nets.iter()) {
        if !is_valid_cidr(cidr) {
            warn!(cidr = %cidr, "suricata: invalid CIDR");
            return Err(SuricataError::ValidationFailed(format!(
                "invalid CIDR: {cidr} (expected IPv4/IPv6 CIDR notation, e.g. 192.168.1.0/24)"
            )));
        }
        if let Err(msg) = ensure_ipv6_allowed(cidr, ipv6_enabled, "Suricata network") {
            warn!(cidr = %cidr, "suricata: IPv6 CIDR rejected while disabled");
            return Err(SuricataError::ValidationFailed(msg));
        }
    }

    info!(
        enabled = cfg.enabled,
        interfaces = ?cfg.interfaces,
        mode = %cfg.mode,
        home_nets = cfg.home_nets.len(),
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

    Ok(Json(serde_json::json!({
        "success": true,
        "data": to_api_config(&cfg)
    })))
}

// ---------------------------------------------------------------------------
// GET /suricata/rulesets
// ---------------------------------------------------------------------------

/// List all configured rule sources as a flat array with sequential IDs.
pub async fn list_rulesets(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SuricataError> {
    let cfg = state
        .config_store
        .load_suricata_config()
        .map_err(SuricataError::StorageError)?
        .unwrap_or_else(default_suricata_cfg);

    let rulesets: Vec<SuricataRulesetResponse> = cfg
        .rule_sources
        .iter()
        .enumerate()
        .map(|(i, rs)| SuricataRulesetResponse {
            id: i,
            name: rs.name.clone(),
            source: rs
                .url
                .clone()
                .or_else(|| rs.path.clone())
                .unwrap_or_default(),
            enabled: rs.enabled,
            last_updated: None,
        })
        .collect();

    Ok(Json(serde_json::json!({
        "success": true,
        "data": rulesets
    })))
}

// ---------------------------------------------------------------------------
// POST /suricata/rulesets
// ---------------------------------------------------------------------------

/// Create a new rule source (URL-based or local file path).
pub async fn create_ruleset(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateRulesetRequest>,
) -> Result<impl IntoResponse, SuricataError> {
    let name = req.name.trim().to_string();
    let url = req
        .url
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty());
    let path = req
        .path
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty());

    // Validate inputs
    if name.is_empty() {
        return Err(SuricataError::ValidationFailed(
            "ruleset name must not be empty".into(),
        ));
    }
    if url.is_none() && path.is_none() {
        return Err(SuricataError::ValidationFailed(
            "either 'url' or 'path' must be provided".into(),
        ));
    }
    if url.is_some() && path.is_some() {
        return Err(SuricataError::ValidationFailed(
            "only one of 'url' or 'path' should be provided".into(),
        ));
    }
    if let Some(url) = url.as_deref() {
        if !validate_url(url) {
            return Err(SuricataError::ValidationFailed(format!(
                "ruleset URL {:?} is not a valid HTTP/HTTPS URL",
                url
            )));
        }
        if is_blocked_suricata_ruleset_url(url) {
            return Err(SuricataError::ValidationFailed(
                "Suricata 7.x ruleset feeds are not supported on this appliance (Suricata 6.x)"
                    .into(),
            ));
        }
    }

    let mut cfg = state
        .config_store
        .load_suricata_config()
        .map_err(SuricataError::StorageError)?
        .unwrap_or_else(default_suricata_cfg);

    let rule_source = crate::config::models::RuleSource {
        name,
        enabled: req.enabled.unwrap_or(true),
        url,
        path,
    };

    cfg.rule_sources.push(rule_source.clone());
    let rule_id = cfg.rule_sources.len() - 1;

    state
        .config_store
        .save_suricata_config(cfg)
        .map_err(SuricataError::StorageError)?;

    info!("suricata: ruleset created");

    let response = SuricataRulesetResponse {
        id: rule_id,
        name: rule_source.name,
        source: rule_source
            .url
            .clone()
            .or_else(|| rule_source.path.clone())
            .unwrap_or_default(),
        enabled: rule_source.enabled,
        last_updated: None,
    };

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "success": true,
            "data": response
        })),
    ))
}

// ---------------------------------------------------------------------------
// PUT /suricata/rulesets/{id}
// ---------------------------------------------------------------------------

/// Enable or disable the rule source at position `id` (0-based index).
pub async fn update_ruleset(
    Path(id): Path<usize>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateRulesetRequest>,
) -> Result<impl IntoResponse, SuricataError> {
    let mut cfg = state
        .config_store
        .load_suricata_config()
        .map_err(SuricataError::StorageError)?
        .unwrap_or_else(default_suricata_cfg);

    if id >= cfg.rule_sources.len() {
        return Err(SuricataError::ValidationFailed(format!(
            "rule source index {id} out of range (have {})",
            cfg.rule_sources.len()
        )));
    }

    cfg.rule_sources[id].enabled = req.enabled;

    state
        .config_store
        .save_suricata_config(cfg.clone())
        .map_err(SuricataError::StorageError)?;

    let rs = &cfg.rule_sources[id];
    let response = SuricataRulesetResponse {
        id,
        name: rs.name.clone(),
        source: rs
            .url
            .clone()
            .or_else(|| rs.path.clone())
            .unwrap_or_default(),
        enabled: rs.enabled,
        last_updated: None,
    };

    Ok(Json(serde_json::json!({
        "success": true,
        "data": response
    })))
}

// ---------------------------------------------------------------------------
// GET /suricata/alerts
// ---------------------------------------------------------------------------

/// Return recent alerts parsed from the EVE JSON log file.
///
/// Returns an empty array if the log file does not exist or Suricata is not
/// configured with EVE logging enabled.
pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListAlertsQuery>,
) -> Result<impl IntoResponse, SuricataError> {
    let cfg = state
        .config_store
        .load_suricata_config()
        .map_err(SuricataError::StorageError)?
        .unwrap_or_else(default_suricata_cfg);

    let log_path = if !cfg.eve_log_path.is_empty() {
        cfg.eve_log_path.clone()
    } else {
        "/var/log/suricata/eve.json".to_string()
    };

    let limit = query
        .limit
        .unwrap_or(DEFAULT_ALERT_LIMIT)
        .clamp(1, MAX_ALERT_LIMIT);

    let file = match tokio::fs::File::open(&log_path).await {
        Ok(file) => file,
        Err(_) => {
            return Ok(Json(serde_json::json!({
                "success": true,
                "data": serde_json::json!([])
            })));
        }
    };

    let mut lines = tokio::io::BufReader::new(file).lines();
    let mut alerts: VecDeque<SuricataAlertResponse> = VecDeque::with_capacity(limit);

    while let Some(line) = lines.next_line().await.map_err(|e| {
        SuricataError::StorageError(anyhow::anyhow!("failed to read {log_path}: {e}"))
    })? {
        if let Some(alert) = parse_alert_line(&line) {
            alerts.push_back(alert);
            if alerts.len() > limit {
                alerts.pop_front();
            }
        }
    }

    let mut result: Vec<SuricataAlertResponse> = alerts.into_iter().collect();
    for (i, a) in result.iter_mut().enumerate() {
        a.id = i;
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "data": result
    })))
}

// ---------------------------------------------------------------------------
// GET /interfaces/{name}/suricata
// ---------------------------------------------------------------------------

/// Get Suricata configuration with interface focus.
///
/// Shows whether the interface is being monitored by Suricata.
pub async fn get_interface_suricata_config(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
) -> Result<impl IntoResponse, SuricataError> {
    if !is_valid_interface_name(&interface_name) {
        return Err(SuricataError::ValidationFailed(format!(
            "interface {:?} is not a valid interface name",
            interface_name
        )));
    }

    let cfg = state
        .config_store
        .load_suricata_config()
        .map_err(SuricataError::StorageError)?
        .unwrap_or_else(default_suricata_cfg);

    let is_monitored = cfg.interfaces.contains(&interface_name);

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "interface": interface_name,
            "monitored": is_monitored,
            "enabled": cfg.enabled,
            "mode": cfg.mode,
            "interfaces": cfg.interfaces,
        }
    })))
}

// ---------------------------------------------------------------------------
// POST /interfaces/{name}/suricata
// ---------------------------------------------------------------------------

/// Enable or disable Suricata monitoring for a specific interface.
///
/// This adds or removes the interface from the list of interfaces being monitored
/// by Suricata, then applies the configuration.
#[derive(Deserialize)]
pub struct UpdateInterfaceSuricataRequest {
    /// Whether to enable monitoring on this interface
    pub monitored: bool,
}

pub async fn update_interface_suricata_config(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
    Json(req): Json<UpdateInterfaceSuricataRequest>,
) -> Result<impl IntoResponse, SuricataError> {
    if !is_valid_interface_name(&interface_name) {
        return Err(SuricataError::ValidationFailed(format!(
            "interface {:?} is not a valid interface name",
            interface_name
        )));
    }

    let mut cfg = state
        .config_store
        .load_suricata_config()
        .map_err(SuricataError::StorageError)?
        .unwrap_or_else(default_suricata_cfg);

    let currently_monitored = cfg.interfaces.contains(&interface_name);

    // Add or remove the interface from the monitoring list
    if req.monitored && !currently_monitored {
        // Add interface
        cfg.interfaces.push(interface_name.clone());
        info!(interface = %interface_name, "suricata: added interface to monitoring list");
    } else if !req.monitored && currently_monitored {
        // Remove interface
        cfg.interfaces.retain(|i| i != &interface_name);
        info!(interface = %interface_name, "suricata: removed interface from monitoring list");
    }

    state
        .config_store
        .save_suricata_config(cfg.clone())
        .map_err(SuricataError::StorageError)?;

    apply_config(&cfg)
        .await
        .map_err(|e| SuricataError::EngineError(e.to_string()))?;

    let is_monitored = cfg.interfaces.contains(&interface_name);

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "interface": interface_name,
            "monitored": is_monitored,
            "enabled": cfg.enabled,
            "mode": cfg.mode,
            "interfaces": cfg.interfaces,
        }
    })))
}
