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
//! - `GET /interfaces/{name}/firewall/rules` - get rules for a physical interface
//! - `POST /interfaces/{name}/firewall/rules` - create a rule for a physical interface
//! - `DELETE /interfaces/{name}/firewall/rules/{id}` - delete a rule from an interface
//!
//! # Per-WireGuard-interface endpoints
//!
//! - `GET /wireguard/interfaces/{name}/firewall/rules` - get rules for a WireGuard interface
//! - `POST /wireguard/interfaces/{name}/firewall/rules` - create a rule for a WireGuard interface
//! - `DELETE /wireguard/interfaces/{name}/firewall/rules/{id}` - delete a rule from a WireGuard interface

use std::sync::Arc;

use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, Json};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    config::models::{
        ensure_ipv6_allowed, is_valid_cidr_or_addr, is_valid_interface_name, is_valid_port,
        validate_firewall_rule, validate_firewall_schedule, validate_firewall_settings, Action,
        FirewallAddressFamily, FirewallDirection, FirewallRule, FirewallSchedule,
        FirewallSettings, FirewallStateLimits, Protocol,
    },
    engine::nftables::{get_rule_stats, NftError},
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
    let cfg = state.config_store.load().map_err(NftError::StorageError)?;
    let ipv6_enabled = cfg
        .system_settings
        .as_ref()
        .map(|settings| settings.ipv6_enabled)
        .unwrap_or(false);
    let system_rules = crate::engine::nftables::system_firewall_rules(&cfg.interfaces, ipv6_enabled);

    info!(
        count = rules.len(),
        system_count = system_rules.len(),
        "firewall: loaded rules from storage"
    );

    // Sync the in-memory cache.
    {
        let mut fw = state.firewall_rules.write().await;
        *fw = rules.clone();
    }

    let mut response = Vec::with_capacity(system_rules.len() + rules.len());
    for rule in system_rules {
        let mut value = serde_json::to_value(rule)
            .map_err(|e| NftError::GenerateFailed(e.to_string()))?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("system".to_string(), serde_json::Value::Bool(true));
        }
        response.push(value);
    }
    for rule in rules {
        let mut value = serde_json::to_value(rule)
            .map_err(|e| NftError::GenerateFailed(e.to_string()))?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("system".to_string(), serde_json::Value::Bool(false));
        }
        response.push(value);
    }

    Ok(Json(response))
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
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(NftError::StorageError)?
        .ipv6_enabled;

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
        if !is_valid_cidr_or_addr(src) {
            return Err(NftError::ValidationFailed(format!(
                "invalid management source IP/CIDR: {}",
                src
            )));
        }
        if let Err(msg) = ensure_ipv6_allowed(src, ipv6_enabled, "management source IP/CIDR") {
            return Err(NftError::ValidationFailed(msg));
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
    validate_firewall_settings(&settings, ipv6_enabled).map_err(NftError::ValidationFailed)?;

    let previous_settings = state
        .config_store
        .load_firewall_settings()
        .map_err(NftError::StorageError)?;

    state
        .config_store
        .save_firewall_settings(settings.clone())
        .map_err(NftError::StorageError)?;

    if let Err(apply_err) = crate::captive_portal::apply_current_ruleset_nft(&state.config_store).await {
        warn!(
            error = %apply_err,
            "firewall: nftables apply failed after settings save; rolling back settings"
        );
        if let Err(rollback_err) = state
            .config_store
            .save_firewall_settings(previous_settings)
        {
            warn!(
                error = %rollback_err,
                "firewall: failed to restore previous firewall settings after apply failure"
            );
        } else if let Err(reapply_err) =
            crate::captive_portal::apply_current_ruleset_nft(&state.config_store).await
        {
            warn!(
                error = %reapply_err,
                "firewall: failed to reapply previous settings after rollback"
            );
        }
        return Err(apply_err);
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
    #[serde(default)]
    pub ip_family: FirewallAddressFamily,
    pub action: Action,
    #[serde(default = "default_direction")]
    pub direction: FirewallDirection, // Now supports Both
    pub interface: Option<String>,
    pub log: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub schedule: Option<FirewallSchedule>,
    #[serde(default)]
    pub state_limits: FirewallStateLimits,
}

fn default_true() -> bool { true }

fn default_direction() -> FirewallDirection { FirewallDirection::Forward }

fn validate_rule_request(req: &CreateRuleRequest, ipv6_enabled: bool) -> Result<(), NftError> {
    if req.priority < 0 {
        return Err(NftError::ValidationFailed(
            "priority must be greater than or equal to 0".into(),
        ));
    }

    if matches!(req.action, Action::Jump) {
        return Err(NftError::ValidationFailed(
            "jump action requires a target chain and is not supported yet".into(),
        ));
    }

    if matches!(req.ip_family, FirewallAddressFamily::Ipv6) && !ipv6_enabled {
        return Err(NftError::ValidationFailed(
            "IPv6 firewall rules require system ipv6Enabled".into(),
        ));
    }

    if matches!(req.protocol.as_ref(), Some(Protocol::Icmpv6)) && !ipv6_enabled {
        return Err(NftError::ValidationFailed(
            "ICMPv6 firewall rules require system ipv6Enabled".into(),
        ));
    }
    if matches!(req.protocol.as_ref(), Some(Protocol::Icmpv6))
        && matches!(req.ip_family, FirewallAddressFamily::Ipv4)
    {
        return Err(NftError::ValidationFailed(
            "ICMPv6 rules cannot use ipFamily=ipv4".into(),
        ));
    }
    if matches!(req.protocol.as_ref(), Some(Protocol::Icmp))
        && matches!(req.ip_family, FirewallAddressFamily::Ipv6)
    {
        return Err(NftError::ValidationFailed(
            "ICMP rules cannot use ipFamily=ipv6".into(),
        ));
    }

    if let Some(src) = &req.source {
        if !is_valid_cidr_or_addr(src) {
            warn!(src = %src, "firewall: invalid source IP/CIDR");
            return Err(NftError::ValidationFailed(format!("invalid source IP/CIDR: {src}")));
        }
        if let Err(msg) = ensure_ipv6_allowed(src, ipv6_enabled, "firewall source IP/CIDR") {
            return Err(NftError::ValidationFailed(msg));
        }
        if src.contains(':') && matches!(req.ip_family, FirewallAddressFamily::Ipv4) {
            return Err(NftError::ValidationFailed(
                "IPv6 source cannot use ipFamily=ipv4".into(),
            ));
        }
        if !src.contains(':') && matches!(req.ip_family, FirewallAddressFamily::Ipv6) {
            return Err(NftError::ValidationFailed(
                "IPv4 source cannot use ipFamily=ipv6".into(),
            ));
        }
    }

    if let Some(dst) = &req.destination {
        if !is_valid_cidr_or_addr(dst) {
            warn!(dst = %dst, "firewall: invalid destination IP/CIDR");
            return Err(NftError::ValidationFailed(format!("invalid destination IP/CIDR: {dst}")));
        }
        if let Err(msg) = ensure_ipv6_allowed(dst, ipv6_enabled, "firewall destination IP/CIDR") {
            return Err(NftError::ValidationFailed(msg));
        }
        if dst.contains(':') && matches!(req.ip_family, FirewallAddressFamily::Ipv4) {
            return Err(NftError::ValidationFailed(
                "IPv6 destination cannot use ipFamily=ipv4".into(),
            ));
        }
        if !dst.contains(':') && matches!(req.ip_family, FirewallAddressFamily::Ipv6) {
            return Err(NftError::ValidationFailed(
                "IPv4 destination cannot use ipFamily=ipv6".into(),
            ));
        }
    }

    let has_ports = req.source_port.is_some() || req.destination_port.is_some();
    if has_ports
        && !matches!(
            req.protocol.as_ref(),
            Some(Protocol::Tcp) | Some(Protocol::Udp)
        )
    {
        return Err(NftError::ValidationFailed(
            "source_port and destination_port require protocol tcp or udp".into(),
        ));
    }

    if let Some(sport) = req.source_port {
        if !is_valid_port(sport) {
            warn!(port = sport, "firewall: invalid source port");
            return Err(NftError::ValidationFailed(format!(
                "invalid source port: {sport} (must be 1-65535)"
            )));
        }
    }
    if let Some(dport) = req.destination_port {
        if !is_valid_port(dport) {
            warn!(port = dport, "firewall: invalid destination port");
            return Err(NftError::ValidationFailed(format!(
                "invalid destination port: {dport} (must be 1-65535)"
            )));
        }
    }
    if let Some(iface) = &req.interface {
        if !is_valid_interface_name(iface) {
            warn!(iface = %iface, "firewall: invalid interface name");
            return Err(NftError::ValidationFailed(format!("invalid interface name: {iface}")));
        }
    }

    if let Some(schedule) = &req.schedule {
        validate_firewall_schedule(schedule).map_err(NftError::ValidationFailed)?;
    }

    for (label, value) in [
        ("maxStates", req.state_limits.max_states),
        ("maxSourceNodes", req.state_limits.max_source_nodes),
        ("maxSourceStates", req.state_limits.max_source_states),
        ("maxSourceConnections", req.state_limits.max_source_connections),
        ("maxNewConnections", req.state_limits.max_new_connections),
        (
            "maxNewConnectionsSeconds",
            req.state_limits.max_new_connections_seconds,
        ),
        (
            "maxNewConnectionsPerSource",
            req.state_limits.max_new_connections_per_source,
        ),
        (
            "maxNewConnectionsPerSourceSeconds",
            req.state_limits.max_new_connections_per_source_seconds,
        ),
    ] {
        if value == Some(0) {
            return Err(NftError::ValidationFailed(format!(
                "{label} must be greater than 0"
            )));
        }
    }

    Ok(())
}

async fn save_rules_and_apply<F, T>(
    state: &Arc<AppState>,
    mutate: F,
) -> Result<T, NftError>
where
    F: FnOnce(&mut Vec<FirewallRule>) -> Result<T, NftError>,
{
    let mut cache = state.firewall_rules.write().await;
    let old_rules = state
        .config_store
        .load_firewall_rules()
        .map_err(NftError::StorageError)?;
    let mut new_rules = old_rules.clone();
    let result = mutate(&mut new_rules)?;

    state
        .config_store
        .save_firewall_rules(new_rules.clone())
        .map_err(NftError::StorageError)?;
    *cache = new_rules;

    if let Err(apply_err) = crate::captive_portal::apply_current_ruleset_nft(&state.config_store).await {
        warn!(
            error = %apply_err,
            "firewall: nftables apply failed after save; rolling back firewall rules"
        );
        match state.config_store.save_firewall_rules(old_rules.clone()) {
            Ok(()) => {
                *cache = old_rules;
                if let Err(reapply_err) =
                    crate::captive_portal::apply_current_ruleset_nft(&state.config_store).await
                {
                    warn!(
                        error = %reapply_err,
                        "firewall: failed to reapply previous rules after rollback"
                    );
                }
            }
            Err(rollback_err) => {
                warn!(
                    error = %rollback_err,
                    "firewall: failed to restore previous firewall rules after apply failure"
                );
            }
        }
        return Err(apply_err);
    }

    Ok(result)
}

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
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(NftError::StorageError)?
        .ipv6_enabled;
    validate_rule_request(&req, ipv6_enabled)?;

    if let Some(src) = &req.source {
        if !is_valid_cidr_or_addr(src) {
            warn!(src = %src, "firewall: invalid source CIDR");
            return Err(NftError::ValidationFailed(format!(
                "invalid source CIDR: {src}"
            )));
        }
        if let Err(msg) = ensure_ipv6_allowed(src, ipv6_enabled, "firewall source CIDR") {
            return Err(NftError::ValidationFailed(msg));
        }
    }

    if let Some(dst) = &req.destination {
        if !is_valid_cidr_or_addr(dst) {
            warn!(dst = %dst, "firewall: invalid destination CIDR");
            return Err(NftError::ValidationFailed(format!(
                "invalid destination CIDR: {dst}"
            )));
        }
        if let Err(msg) = ensure_ipv6_allowed(dst, ipv6_enabled, "firewall destination CIDR") {
            return Err(NftError::ValidationFailed(msg));
        }
    }

    if matches!(req.protocol.as_ref(), Some(Protocol::Icmpv6)) && !ipv6_enabled {
        return Err(NftError::ValidationFailed(
            "ICMPv6 firewall rules require system ipv6Enabled".into(),
        ));
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
        ip_family: req.ip_family,
        action: req.action,
        direction: req.direction,
        interface: req.interface,
        log: req.log,
        enabled: req.enabled,
        schedule: req.schedule,
        state_limits: req.state_limits,
    };
    validate_firewall_rule(&rule, ipv6_enabled).map_err(NftError::ValidationFailed)?;

    info!(
        id = %rule.id,
        priority = rule.priority,
        action = ?rule.action,
        "firewall: received create rule request"
    );

    let created = save_rules_and_apply(&state, |rules| {
        rules.push(rule.clone());
        Ok(rule.clone())
    })
    .await?;

    info!(id = %created.id, "firewall: rule persisted and nftables apply complete");

    Ok((StatusCode::CREATED, Json(created)))
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
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(NftError::StorageError)?
        .ipv6_enabled;
    validate_rule_request(&req, ipv6_enabled)?;

    if let Some(src) = &req.source {
        if !is_valid_cidr_or_addr(src) {
            warn!(src = %src, "firewall: invalid source CIDR");
            return Err(NftError::ValidationFailed(format!("invalid source CIDR: {src}")));
        }
        if let Err(msg) = ensure_ipv6_allowed(src, ipv6_enabled, "firewall source CIDR") {
            return Err(NftError::ValidationFailed(msg));
        }
    }
    if let Some(dst) = &req.destination {
        if !is_valid_cidr_or_addr(dst) {
            warn!(dst = %dst, "firewall: invalid destination CIDR");
            return Err(NftError::ValidationFailed(format!("invalid destination CIDR: {dst}")));
        }
        if let Err(msg) = ensure_ipv6_allowed(dst, ipv6_enabled, "firewall destination CIDR") {
            return Err(NftError::ValidationFailed(msg));
        }
    }
    if matches!(req.protocol.as_ref(), Some(Protocol::Icmpv6)) && !ipv6_enabled {
        return Err(NftError::ValidationFailed(
            "ICMPv6 firewall rules require system ipv6Enabled".into(),
        ));
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
        ip_family: req.ip_family,
        action: req.action,
        direction: req.direction,
        interface: req.interface,
        log: req.log,
        enabled: req.enabled,
        schedule: req.schedule,
        state_limits: req.state_limits,
    };
    validate_firewall_rule(&updated, ipv6_enabled).map_err(NftError::ValidationFailed)?;

    info!(
        id = %id,
        priority = updated.priority,
        action = ?updated.action,
        "firewall: received update rule request"
    );

    let updated = save_rules_and_apply(&state, |rules| {
        let pos = rules
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| NftError::NotFound(id.to_string()))?;
        rules[pos] = updated.clone();
        Ok(updated.clone())
    })
    .await?;

    info!(id = %id, "firewall: rule updated and nftables apply complete");

    Ok(Json(updated))
}

/// Handler: clone an existing firewall rule by UUID.
///
/// Copies all rule fields, assigns a fresh id, appends " (copy)" to the
/// description when present, persists, and re-applies the nftables ruleset.
pub async fn clone_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NftError> {
    let cloned = save_rules_and_apply(&state, |rules| {
        let original = rules
            .iter()
            .find(|rule| rule.id == id)
            .cloned()
            .ok_or_else(|| NftError::NotFound(id.to_string()))?;

        let mut cloned = original;
        cloned.id = Uuid::new_v4();
        cloned.description = cloned
            .description
            .map(|description| format!("{description} (copy)"));

        rules.push(cloned.clone());
        Ok(cloned)
    })
    .await?;

    info!(source_id = %id, cloned_id = %cloned.id, "firewall: rule cloned and nftables apply complete");

    Ok((StatusCode::CREATED, Json(cloned)))
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
    if !is_valid_interface_name(&interface_name) {
        return Err(NftError::ValidationFailed(format!(
            "invalid interface name: {interface_name}"
        )));
    }

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
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(NftError::StorageError)?
        .ipv6_enabled;
    validate_rule_request(&req, ipv6_enabled)?;

    if let Some(src) = &req.source {
        if !is_valid_cidr_or_addr(src) {
            warn!(src = %src, interface = %interface_name, "firewall: invalid source CIDR");
            return Err(NftError::ValidationFailed(format!(
                "invalid source CIDR: {src}"
            )));
        }
        if let Err(msg) = ensure_ipv6_allowed(src, ipv6_enabled, "firewall source CIDR") {
            return Err(NftError::ValidationFailed(msg));
        }
    }

    if let Some(dst) = &req.destination {
        if !is_valid_cidr_or_addr(dst) {
            warn!(dst = %dst, interface = %interface_name, "firewall: invalid destination CIDR");
            return Err(NftError::ValidationFailed(format!(
                "invalid destination CIDR: {dst}"
            )));
        }
        if let Err(msg) = ensure_ipv6_allowed(dst, ipv6_enabled, "firewall destination CIDR") {
            return Err(NftError::ValidationFailed(msg));
        }
    }

    if matches!(req.protocol.as_ref(), Some(Protocol::Icmpv6)) && !ipv6_enabled {
        return Err(NftError::ValidationFailed(
            "ICMPv6 firewall rules require system ipv6Enabled".into(),
        ));
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
        ip_family: req.ip_family,
        action: req.action,
        direction: req.direction,
        interface: Some(interface_name.clone()),
        log: req.log,
        enabled: req.enabled,
        schedule: req.schedule,
        state_limits: req.state_limits,
    };
    validate_firewall_rule(&rule, ipv6_enabled).map_err(NftError::ValidationFailed)?;

    info!(
        id = %rule.id,
        interface = %interface_name,
        priority = rule.priority,
        action = ?rule.action,
        "firewall: received create rule request for interface"
    );

    let created = save_rules_and_apply(&state, |rules| {
        rules.push(rule.clone());
        Ok(rule.clone())
    })
    .await?;

    info!(
        id = %created.id,
        interface = %interface_name,
        "firewall: interface rule persisted and nftables apply complete"
    );

    Ok((StatusCode::CREATED, Json(created)))
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
    if !is_valid_interface_name(&interface_name) {
        return Err(NftError::ValidationFailed(format!(
            "invalid interface name: {interface_name}"
        )));
    }

    save_rules_and_apply(&state, |rules| {
        let pos = rules
            .iter()
            .position(|r| r.id == rule_id && r.interface.as_deref() == Some(&interface_name))
            .ok_or_else(|| NftError::NotFound(rule_id.to_string()))?;

        rules.remove(pos);
        Ok(())
    })
    .await?;

    info!(
        id = %rule_id,
        interface = %interface_name,
        "firewall: rule deleted"
    );

    info!(
        id = %rule_id,
        interface = %interface_name,
        "firewall: nftables engine apply complete after interface delete"
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
    save_rules_and_apply(&state, |rules| {
        let before = rules.len();
        rules.retain(|r| r.id != id);
        if rules.len() == before {
            return Err(NftError::NotFound(id.to_string()));
        }
        Ok(())
    })
    .await?;

    info!(id = %id, "firewall: rule deleted");

    info!(id = %id, "firewall: nftables engine apply complete after delete");

    Ok(StatusCode::NO_CONTENT)
}
