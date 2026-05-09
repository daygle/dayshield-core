//! Firewall rule endpoints - `GET /firewall/rules`, `POST /firewall/rules`, and per-interface endpoints.
//!
//! # GET /firewall/rules
//!
//! Returns the persisted [`FirewallRule`] list, syncing the in-memory cache as
//! a side-effect.
//!
//! # POST /firewall/rules
//!
//! Accepts a new firewall rule, validates all fields, appends it to the
//! persisted list, and triggers the nftables engine to regenerate and apply
//! the full ruleset.
//!
//! # Per-interface endpoints
//!
//! - `GET /interfaces/{name}/firewall/rules` — get rules for a specific interface
//! - `POST /interfaces/{name}/firewall/rules` — create a rule for a specific interface
//! - `DELETE /interfaces/{name}/firewall/rules/{id}` — delete a rule from an interface

use std::sync::Arc;

use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, Json};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    config::models::{
        is_valid_cidr, is_valid_interface_name, is_valid_port, Action, FirewallRule,
        FirewallSchedule, FirewallSettings, Protocol,
    },
    engine::nftables::{apply_rules, get_rule_stats, NftError},
    state::AppState,
};

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: list all persisted firewall rules.
///
/// Loads the rule list from config storage, syncs the in-memory cache, and
/// returns the list as JSON.
pub async fn list_rules(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, NftError> {
    let rules = state
        .config_store
        .load_firewall_rules()
        .map_err(NftError::StorageError)?;

    info!(count = rules.len(), "firewall: loaded rules from storage");

    // Sync the in-memory cache.
    {
        let mut fw = state.firewall_rules.write().await;
        *fw = rules.clone();
    }

    Ok(Json(rules))
}

/// Handler: return current global firewall settings.
pub async fn get_settings(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, NftError> {
    let settings = state
        .config_store
        .load_firewall_settings()
        .map_err(NftError::StorageError)?;
    Ok(Json(settings))
}

/// Handler: replace global firewall settings and re-apply nftables.
pub async fn update_settings(
    State(state): State<Arc<AppState>>,
    Json(mut settings): Json<FirewallSettings>,
) -> Result<impl IntoResponse, NftError> {
    if settings.management_ports.is_empty() {
        return Err(NftError::ValidationFailed(
            "management_ports must contain at least one port".into(),
        ));
    }
    for p in &settings.management_ports {
        if !is_valid_port(*p) {
            return Err(NftError::ValidationFailed(format!(
                "invalid management port: {} (must be 1-65535)",
                p
            )));
        }
    }
    for src in &settings.management_allowed_sources {
        if !is_valid_cidr(src) {
            return Err(NftError::ValidationFailed(format!(
                "invalid management source CIDR: {}",
                src
            )));
        }
    }
    if let Some(iface) = settings.management_interface.as_ref() {
        if iface.is_empty() {
            settings.management_interface = None;
        } else if !is_valid_interface_name(iface) {
            return Err(NftError::ValidationFailed(format!(
                "invalid management interface name: {}",
                iface
            )));
        }
    }
    if settings.syn_flood_rate == 0 {
        return Err(NftError::ValidationFailed(
            "syn_flood_rate must be greater than 0".into(),
        ));
    }
    if settings.syn_flood_burst == 0 {
        return Err(NftError::ValidationFailed(
            "syn_flood_burst must be greater than 0".into(),
        ));
    }

    state
        .config_store
        .save_firewall_settings(settings.clone())
        .map_err(NftError::StorageError)?;

    let full_cfg = state
        .config_store
        .load()
        .map_err(NftError::StorageError)?;

    {
        let rules = state.firewall_rules.read().await;
        apply_rules(
            &rules,
            full_cfg.nat.as_ref(),
            &full_cfg.firewall_aliases,
            full_cfg.firewall_settings.as_ref(),
        )
        .await?;
    }

    Ok(Json(settings))
}

/// Request body for `POST /firewall/rules`.
#[derive(serde::Deserialize)]
pub struct CreateRuleRequest {
    pub description: Option<String>,
    pub priority: i32,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub protocol: Option<Protocol>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub action: Action,
    pub interface: Option<String>,
    pub log: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub schedule: Option<FirewallSchedule>,
}

fn default_true() -> bool { true }

/// Handler: create a new firewall rule.
///
/// Validates all fields, appends the rule to persistent storage, and
/// re-applies the full ruleset via the nftables engine.  Returns the
/// newly-created rule with a `201 Created` status on success.
pub async fn create_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<impl IntoResponse, NftError> {
    // --- Validation --------------------------------------------------------

    if let Some(src) = &req.source {
        if !is_valid_cidr(src) {
            warn!(src = %src, "firewall: invalid source CIDR");
            return Err(NftError::ValidationFailed(format!(
                "invalid source CIDR: {src}"
            )));
        }
    }

    if let Some(dst) = &req.destination {
        if !is_valid_cidr(dst) {
            warn!(dst = %dst, "firewall: invalid destination CIDR");
            return Err(NftError::ValidationFailed(format!(
                "invalid destination CIDR: {dst}"
            )));
        }
    }

    if let Some(sport) = req.source_port {
        if !is_valid_port(sport) {
            warn!(port = sport, "firewall: invalid source port");
            return Err(NftError::ValidationFailed(format!(
                "invalid source port: {sport} (must be 1–65535)"
            )));
        }
    }

    if let Some(dport) = req.destination_port {
        if !is_valid_port(dport) {
            warn!(port = dport, "firewall: invalid destination port");
            return Err(NftError::ValidationFailed(format!(
                "invalid destination port: {dport} (must be 1–65535)"
            )));
        }
    }

    if let Some(iface) = &req.interface {
        if !is_valid_interface_name(iface) {
            warn!(iface = %iface, "firewall: invalid interface name");
            return Err(NftError::ValidationFailed(format!(
                "invalid interface name: {iface}"
            )));
        }
    }

    // --- Build rule --------------------------------------------------------

    let rule = FirewallRule {
        id: uuid::Uuid::new_v4(),
        description: req.description,
        priority: req.priority,
        source: req.source,
        destination: req.destination,
        protocol: req.protocol,
        source_port: req.source_port,
        destination_port: req.destination_port,
        action: req.action,
        interface: req.interface,
        log: req.log,
        enabled: req.enabled,
        schedule: req.schedule,
    };

    info!(
        id = %rule.id,
        priority = rule.priority,
        action = ?rule.action,
        "firewall: received create rule request"
    );

    // --- Persist -----------------------------------------------------------

    // Append to in-memory cache and persist atomically.
    // Hold the write lock across the disk write so that no concurrent reader
    // can observe the new rule before it has been durably stored.
    {
        let mut rules = state.firewall_rules.write().await;
        rules.push(rule.clone());

        if let Err(e) = state.config_store.save_firewall_rules(rules.clone()) {
            // Roll back the in-memory change before returning the error.
            rules.pop();
            return Err(NftError::StorageError(e));
        }
    }

    info!(id = %rule.id, "firewall: rule persisted");

    // --- Apply -------------------------------------------------------------

    // Load current NAT rules and aliases so the full ruleset can be regenerated.
    let full_cfg = state
        .config_store
        .load()
        .map_err(NftError::StorageError)?;

    {
        let rules = state.firewall_rules.read().await;
        apply_rules(
            &rules,
            full_cfg.nat.as_ref(),
            &full_cfg.firewall_aliases,
            full_cfg.firewall_settings.as_ref(),
        )
        .await?;
    }

    info!(id = %rule.id, "firewall: nftables engine apply complete");

    Ok((StatusCode::CREATED, Json(rule)))
}

/// Handler: update an existing firewall rule by UUID.
///
/// Replaces all mutable fields of the rule identified by `id` with the values
/// supplied in the request body.  Returns the updated rule with `200 OK`, or
/// `404 Not Found` if no rule with that id exists.
pub async fn update_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<impl IntoResponse, NftError> {
    // --- Validation --------------------------------------------------------

    if let Some(src) = &req.source {
        if !is_valid_cidr(src) {
            warn!(src = %src, "firewall: invalid source CIDR");
            return Err(NftError::ValidationFailed(format!("invalid source CIDR: {src}")));
        }
    }
    if let Some(dst) = &req.destination {
        if !is_valid_cidr(dst) {
            warn!(dst = %dst, "firewall: invalid destination CIDR");
            return Err(NftError::ValidationFailed(format!("invalid destination CIDR: {dst}")));
        }
    }
    if let Some(sport) = req.source_port {
        if !is_valid_port(sport) {
            warn!(port = sport, "firewall: invalid source port");
            return Err(NftError::ValidationFailed(format!(
                "invalid source port: {sport} (must be 1\u{2013}65535)"
            )));
        }
    }
    if let Some(dport) = req.destination_port {
        if !is_valid_port(dport) {
            warn!(port = dport, "firewall: invalid destination port");
            return Err(NftError::ValidationFailed(format!(
                "invalid destination port: {dport} (must be 1\u{2013}65535)"
            )));
        }
    }
    if let Some(iface) = &req.interface {
        if !is_valid_interface_name(iface) {
            warn!(iface = %iface, "firewall: invalid interface name");
            return Err(NftError::ValidationFailed(format!("invalid interface name: {iface}")));
        }
    }

    // --- Build updated rule ------------------------------------------------

    let updated = FirewallRule {
        id,
        description: req.description,
        priority: req.priority,
        source: req.source,
        destination: req.destination,
        protocol: req.protocol,
        source_port: req.source_port,
        destination_port: req.destination_port,
        action: req.action,
        interface: req.interface,
        log: req.log,
        enabled: req.enabled,
        schedule: req.schedule,
    };

    info!(
        id = %id,
        priority = updated.priority,
        action = ?updated.action,
        "firewall: received update rule request"
    );

    // --- Persist -----------------------------------------------------------

    {
        let mut rules = state.firewall_rules.write().await;
        let pos = rules
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| NftError::NotFound(id.to_string()))?;
        rules[pos] = updated.clone();
        state
            .config_store
            .save_firewall_rules(rules.clone())
            .map_err(NftError::StorageError)?;
    }

    info!(id = %id, "firewall: rule updated");

    // --- Apply -------------------------------------------------------------

    let full_cfg = state
        .config_store
        .load()
        .map_err(NftError::StorageError)?;

    {
        let rules = state.firewall_rules.read().await;
        apply_rules(
            &rules,
            full_cfg.nat.as_ref(),
            &full_cfg.firewall_aliases,
            full_cfg.firewall_settings.as_ref(),
        )
        .await?;
    }

    info!(id = %id, "firewall: nftables engine apply complete after update");

    Ok(Json(updated))
}

/// Handler: return per-rule hit counters read from nftables.
pub async fn get_stats(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let stats = get_rule_stats().await;
    Json(stats)
}

// ---------------------------------------------------------------------------
// Per-interface firewall rules
// ---------------------------------------------------------------------------

/// Handler: list firewall rules for a specific interface.
///
/// Returns only rules that apply to the given interface (interface field matches
/// or is empty/None for global rules).
pub async fn list_interface_rules(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
) -> Result<impl IntoResponse, NftError> {
    let rules = state
        .config_store
        .load_firewall_rules()
        .map_err(NftError::StorageError)?;

    info!(
        interface = %interface_name,
        total_count = rules.len(),
        "firewall: loaded rules for interface"
    );

    // Filter rules by interface: include rules with no interface (global) or matching interface
    let interface_rules: Vec<FirewallRule> = rules
        .into_iter()
        .filter(|r| r.interface.is_none() || r.interface.as_deref() == Some(&interface_name))
        .collect();

    Ok(Json(interface_rules))
}

/// Handler: create a new firewall rule for a specific interface.
///
/// Automatically sets the interface field to the specified interface name,
/// validates all fields, appends the rule to persistent storage, and
/// re-applies the full ruleset via the nftables engine.
pub async fn create_interface_rule(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
    Json(mut req): Json<CreateRuleRequest>,
) -> Result<impl IntoResponse, NftError> {
    // Force the interface to be the URL parameter
    req.interface = Some(interface_name.clone());

    // --- Validation --------------------------------------------------------

    if let Some(src) = &req.source {
        if !is_valid_cidr(src) {
            warn!(src = %src, interface = %interface_name, "firewall: invalid source CIDR");
            return Err(NftError::ValidationFailed(format!(
                "invalid source CIDR: {src}"
            )));
        }
    }

    if let Some(dst) = &req.destination {
        if !is_valid_cidr(dst) {
            warn!(dst = %dst, interface = %interface_name, "firewall: invalid destination CIDR");
            return Err(NftError::ValidationFailed(format!(
                "invalid destination CIDR: {dst}"
            )));
        }
    }

    if let Some(sport) = req.source_port {
        if !is_valid_port(sport) {
            warn!(port = sport, interface = %interface_name, "firewall: invalid source port");
            return Err(NftError::ValidationFailed(format!(
                "invalid source port: {sport} (must be 1–65535)"
            )));
        }
    }

    if let Some(dport) = req.destination_port {
        if !is_valid_port(dport) {
            warn!(port = dport, interface = %interface_name, "firewall: invalid destination port");
            return Err(NftError::ValidationFailed(format!(
                "invalid destination port: {dport} (must be 1–65535)"
            )));
        }
    }

    // Interface is already validated (set from URL), but double-check anyway
    if let Some(iface) = &req.interface {
        if !is_valid_interface_name(iface) {
            warn!(iface = %iface, "firewall: invalid interface name");
            return Err(NftError::ValidationFailed(format!(
                "invalid interface name: {iface}"
            )));
        }
    }

    // --- Build rule --------------------------------------------------------

    let rule = FirewallRule {
        id: Uuid::new_v4(),
        description: req.description,
        priority: req.priority,
        source: req.source,
        destination: req.destination,
        protocol: req.protocol,
        source_port: req.source_port,
        destination_port: req.destination_port,
        action: req.action,
        interface: Some(interface_name.clone()),
        log: req.log,
        enabled: req.enabled,
        schedule: req.schedule,
    };

    info!(
        id = %rule.id,
        interface = %interface_name,
        priority = rule.priority,
        action = ?rule.action,
        "firewall: received create rule request for interface"
    );

    // --- Persist -----------------------------------------------------------

    {
        let mut rules = state.firewall_rules.write().await;
        rules.push(rule.clone());

        if let Err(e) = state.config_store.save_firewall_rules(rules.clone()) {
            rules.pop();
            return Err(NftError::StorageError(e));
        }
    }

    info!(id = %rule.id, interface = %interface_name, "firewall: rule persisted");

    // --- Apply -------------------------------------------------------------

    let full_cfg = state
        .config_store
        .load()
        .map_err(NftError::StorageError)?;

    {
        let rules = state.firewall_rules.read().await;
        apply_rules(
            &rules,
            full_cfg.nat.as_ref(),
            &full_cfg.firewall_aliases,
            full_cfg.firewall_settings.as_ref(),
        )
        .await?;
    }

    info!(
        id = %rule.id,
        interface = %interface_name,
        "firewall: nftables engine apply complete for interface"
    );

    Ok((StatusCode::CREATED, Json(rule)))
}

/// Handler: delete a firewall rule for a specific interface.
///
/// Removes the rule from the in-memory cache, verifies it belongs to the interface,
/// persists the updated list, and re-applies the full ruleset via the nftables engine.
/// Returns `204 No Content` on success or `404 Not Found` if no rule with that id
/// exists for the specified interface.
pub async fn delete_interface_rule(
    State(state): State<Arc<AppState>>,
    Path((interface_name, rule_id)): Path<(String, Uuid)>,
) -> Result<impl IntoResponse, NftError> {
    {
        let mut rules = state.firewall_rules.write().await;
        let pos = rules
            .iter()
            .position(|r| {
                r.id == rule_id
                    && (r.interface.is_none() || r.interface.as_deref() == Some(&interface_name))
            })
            .ok_or_else(|| NftError::NotFound(rule_id.to_string()))?;

        rules.remove(pos);
        state
            .config_store
            .save_firewall_rules(rules.clone())
            .map_err(NftError::StorageError)?;
    }

    info!(
        id = %rule_id,
        interface = %interface_name,
        "firewall: rule deleted"
    );

    let full_cfg = state
        .config_store
        .load()
        .map_err(NftError::StorageError)?;

    {
        let rules = state.firewall_rules.read().await;
        apply_rules(
            &rules,
            full_cfg.nat.as_ref(),
            &full_cfg.firewall_aliases,
            full_cfg.firewall_settings.as_ref(),
        )
        .await?;
    }

    info!(
        id = %rule_id,
        interface = %interface_name,
        "firewall: nftables engine apply complete after delete"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Handler: delete a firewall rule by UUID.
///
/// Removes the rule from the in-memory cache, persists the updated list, and
/// re-applies the full ruleset via the nftables engine.  Returns `204 No
/// Content` on success or `404 Not Found` if no rule with that id exists.
pub async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NftError> {
    {
        let mut rules = state.firewall_rules.write().await;
        let before = rules.len();
        rules.retain(|r| r.id != id);
        if rules.len() == before {
            return Err(NftError::NotFound(id.to_string()));
        }
        state
            .config_store
            .save_firewall_rules(rules.clone())
            .map_err(NftError::StorageError)?;
    }

    info!(id = %id, "firewall: rule deleted");

    let full_cfg = state
        .config_store
        .load()
        .map_err(NftError::StorageError)?;

    {
        let rules = state.firewall_rules.read().await;
        apply_rules(
            &rules,
            full_cfg.nat.as_ref(),
            &full_cfg.firewall_aliases,
            full_cfg.firewall_settings.as_ref(),
        )
        .await?;
    }

    info!(id = %id, "firewall: nftables engine apply complete after delete");

    Ok(StatusCode::NO_CONTENT)
}
