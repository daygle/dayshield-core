//! DNS endpoints - `GET /dns/config` and `POST /dns/config`.
//!
//! # GET /dns/config
//!
//! Returns the persisted [`DnsConfig`].  When no DNS configuration has been
//! saved yet, returns a default (disabled) configuration.
//!
//! # POST /dns/config
//!
//! Accepts a full [`DnsConfig`] JSON body, validates all fields, atomically
//! persists it, and triggers the DNS engine to regenerate and apply the Unbound
//! configuration.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    config::models::{
        ensure_ipv6_allowed, is_valid_interface_name, is_valid_ip, validate_dns_local_record,
        validate_dot_config, DnsBlocklistEntry, DnsConfig, DnsInterfaceBlocklists, DnsLocalRecord,
        DotConfig,
    },
    engine::dns::apply_config_with_overrides,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the DNS API handlers.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The DNS engine failed to apply the configuration.
    #[error("engine error: {0:#}")]
    EngineError(String),
}

impl IntoResponse for DnsError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            DnsError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            DnsError::StorageError(_) | DnsError::EngineError(_) => {
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

/// Request body for `POST /dns/config`.
#[derive(serde::Deserialize)]
pub struct UpdateDnsConfigRequest {
    pub enabled: bool,
    pub listen_addresses: Vec<String>,
    pub port: u16,
    pub forwarders: Vec<String>,
    pub dnssec: bool,
    pub local_records: Vec<DnsLocalRecord>,
    #[serde(default)]
    pub interface_blocklists: Option<Vec<DnsInterfaceBlocklists>>,
    #[serde(default)]
    pub dot_enabled: Option<bool>,
    #[serde(default)]
    pub dot_port: Option<u16>,
    #[serde(default)]
    pub dot_lan_only: Option<bool>,
    #[serde(default)]
    pub dot_certificate: Option<String>,
    #[serde(default)]
    pub dot_private_key: Option<String>,
    #[serde(default)]
    pub dot_acme_domain: Option<String>,
    #[serde(default)]
    pub dot_acme_cert_storage_path: Option<String>,
    /// When true (default), the system automatically manages firewall rules
    /// to allow DNS traffic on the configured port from LAN clients.
    #[serde(default = "default_manage_firewall")]
    pub manage_firewall: bool,
}

fn default_manage_firewall() -> bool {
    true
}

/// Request body for creating a per-interface DNS blocklist URL.
#[derive(serde::Deserialize)]
pub struct CreateDnsBlocklistRequest {
    pub url: String,
    pub name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

fn ipv6_enabled(state: &AppState) -> Result<bool, DnsError> {
    Ok(state
        .config_store
        .load_system_settings()
        .map_err(DnsError::StorageError)?
        .ipv6_enabled)
}

fn is_valid_blocklist_url(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 2048 {
        return false;
    }
    (trimmed.starts_with("https://") || trimmed.starts_with("http://"))
        && !trimmed.chars().any(|c| c.is_ascii_whitespace())
}

fn is_wan_interface(state: &Arc<AppState>, interface_name: &str) -> Result<bool, DnsError> {
    let interfaces = state
        .config_store
        .load_interfaces()
        .map_err(DnsError::StorageError)?;

    Ok(interfaces.iter().any(|iface| {
        iface.name == interface_name && (iface.wan_mode.is_some() || iface.gateway.is_some())
    }))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: return the current DNS configuration.
///
/// Loads the DNS config from persistent storage.  If no configuration has been
/// saved yet, returns the clean-install default config.
pub async fn get_config(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, DnsError> {
    let cfg = state
        .config_store
        .load_dns_config()
        .map_err(DnsError::StorageError)?
        .unwrap_or_default();

    let dot_cfg = state
        .config_store
        .load_dot_config()
        .map_err(DnsError::StorageError)?
        .unwrap_or_default();

    info!(enabled = cfg.enabled, "dns: loaded config");

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "enabled": cfg.enabled,
            "listen_addresses": cfg.listen_addresses,
            "port": cfg.port,
            "forwarders": cfg.forwarders,
            "dnssec": cfg.dnssec,
            "local_records": cfg.local_records,
            "interface_blocklists": cfg.interface_blocklists,
            "dot_enabled": dot_cfg.enabled,
            "dot_port": dot_cfg.port,
            "dot_lan_only": dot_cfg.lan_only,
            "dot_certificate": dot_cfg.cert_pem,
            "dot_private_key": dot_cfg.key_pem,
            "dot_acme_domain": dot_cfg.acme_domain,
            "dot_acme_cert_storage_path": dot_cfg.acme_cert_storage_path,
        }
    })))
}

/// Handler: update the DNS configuration.
///
/// Validates all fields, persists atomically, then triggers the DNS engine to
/// regenerate and apply the Unbound configuration.  Returns the saved config
/// with `200 OK` on success.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateDnsConfigRequest>,
) -> Result<impl IntoResponse, DnsError> {
    let existing = state
        .config_store
        .load_dns_config()
        .map_err(DnsError::StorageError)?
        .unwrap_or_default();
    let ipv6_enabled = ipv6_enabled(&state)?;

    // --- Validation --------------------------------------------------------

    if req.port == 0 {
        return Err(DnsError::ValidationFailed(
            "DNS port must be non-zero".into(),
        ));
    }

    for addr in &req.listen_addresses {
        // Accept plain IPs or interface names (e.g. "eth0").
        if !is_valid_ip(addr) && !is_valid_interface_name(addr) {
            warn!(addr = %addr, "dns: invalid listen address");
            return Err(DnsError::ValidationFailed(format!(
                "invalid listen address: {addr} (expected IP address or interface name)"
            )));
        }
        if is_valid_ip(addr) {
            if let Err(msg) = ensure_ipv6_allowed(addr, ipv6_enabled, "DNS listen address") {
                return Err(DnsError::ValidationFailed(msg));
            }
        }
    }

    for fwd in &req.forwarders {
        if !is_valid_ip(fwd) {
            warn!(fwd = %fwd, "dns: invalid forwarder");
            return Err(DnsError::ValidationFailed(format!(
                "invalid forwarder: {fwd} (expected IPv4 or IPv6 address)"
            )));
        }
        if let Err(msg) = ensure_ipv6_allowed(fwd, ipv6_enabled, "DNS forwarder") {
            return Err(DnsError::ValidationFailed(msg));
        }
    }

    for rec in &req.local_records {
        if let Err(msg) = validate_dns_local_record(rec, ipv6_enabled) {
            return Err(DnsError::ValidationFailed(msg));
        }
    }

    if let Some(groups) = req.interface_blocklists.as_ref() {
        for group in groups {
            if !is_valid_interface_name(&group.interface) {
                return Err(DnsError::ValidationFailed(format!(
                    "invalid interface name in blocklists: {}",
                    group.interface
                )));
            }
            if is_wan_interface(&state, &group.interface)? {
                return Err(DnsError::ValidationFailed(format!(
                    "DNS blocklists are not allowed on WAN interface {}",
                    group.interface
                )));
            }
        }
    }

    // --- Build config ------------------------------------------------------

    let cfg = DnsConfig {
        enabled: req.enabled,
        listen_addresses: req.listen_addresses,
        port: req.port,
        forwarders: req.forwarders,
        dnssec: req.dnssec,
        local_records: req.local_records,
        interface_blocklists: req
            .interface_blocklists
            .unwrap_or(existing.interface_blocklists),
        manage_firewall: req.manage_firewall,
    };

    let dot_acme_domain = req.dot_acme_domain.filter(|s| !s.trim().is_empty());
    let dot_acme_cert_storage_path = if dot_acme_domain.is_some() {
        if let Some(path) = req
            .dot_acme_cert_storage_path
            .filter(|s| !s.trim().is_empty())
        {
            Some(path)
        } else {
            state
                .config_store
                .load_acme_config()
                .map_err(DnsError::StorageError)?
                .map(|cfg| cfg.cert_storage_path)
        }
    } else {
        None
    };

    let dot_cfg = DotConfig {
        enabled: req.dot_enabled.unwrap_or(false),
        port: req.dot_port.unwrap_or(853),
        lan_only: req.dot_lan_only.unwrap_or(true),
        cert_pem: req.dot_certificate.filter(|s| !s.trim().is_empty()),
        key_pem: req.dot_private_key.filter(|s| !s.trim().is_empty()),
        acme_domain: dot_acme_domain,
        acme_cert_storage_path: dot_acme_cert_storage_path,
    };

    if dot_cfg.enabled {
        if let Err(msg) = validate_dot_config(&dot_cfg) {
            return Err(DnsError::ValidationFailed(msg));
        }
    }

    info!(
        enabled = cfg.enabled,
        port = cfg.port,
        dnssec = cfg.dnssec,
        dot_enabled = dot_cfg.enabled,
        "dns: received update config request"
    );

    // --- Persist -----------------------------------------------------------

    state
        .config_store
        .save_dns_config(cfg.clone())
        .map_err(DnsError::StorageError)?;

    state
        .config_store
        .save_dot_config(dot_cfg.clone())
        .map_err(DnsError::StorageError)?;

    info!("dns: config persisted");

    // --- Apply -------------------------------------------------------------

    let dot = state
        .config_store
        .load_dot_config()
        .map_err(DnsError::StorageError)?;
    let (host_overrides, domain_overrides) = state
        .config_store
        .load_dns_overrides()
        .map_err(DnsError::StorageError)?;

    apply_config_with_overrides(
        &cfg,
        dot.as_ref(),
        ipv6_enabled,
        &host_overrides,
        &domain_overrides,
    )
    .await
    .map_err(|e| DnsError::EngineError(e.to_string()))?;

    info!("dns: engine apply complete");

    // Re-apply firewall so that any port or manage_firewall change takes
    // effect immediately (system LAN → DNS allow rules use the new port).
    if let Err(e) = crate::captive_portal::apply_current_ruleset_nft(&state.config_store).await {
        warn!(error = %e, "dns: firewall re-apply failed after config change");
    } else {
        info!("dns: firewall ruleset updated for new DNS port/manage_firewall setting");
    }

    Ok(Json(serde_json::json!({ "success": true, "data": cfg })))
}

/// Handler: list DNS blocklists for a specific interface.
pub async fn list_interface_blocklists(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
) -> Result<impl IntoResponse, DnsError> {
    if !is_valid_interface_name(&interface_name) {
        return Err(DnsError::ValidationFailed(format!(
            "invalid interface name: {interface_name}"
        )));
    }

    if is_wan_interface(&state, &interface_name)? {
        return Ok(Json(serde_json::json!({
            "success": true,
            "data": []
        })));
    }

    let cfg = state
        .config_store
        .load_dns_config()
        .map_err(DnsError::StorageError)?
        .unwrap_or_default();

    let blocklists = cfg
        .interface_blocklists
        .iter()
        .find(|b| b.interface == interface_name)
        .map(|b| b.blocklists.clone())
        .unwrap_or_default();

    Ok(Json(serde_json::json!({
        "success": true,
        "data": blocklists
    })))
}

/// Handler: create a DNS blocklist URL for a specific interface.
pub async fn create_interface_blocklist(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
    Json(req): Json<CreateDnsBlocklistRequest>,
) -> Result<impl IntoResponse, DnsError> {
    if !is_valid_interface_name(&interface_name) {
        return Err(DnsError::ValidationFailed(format!(
            "invalid interface name: {interface_name}"
        )));
    }

    if is_wan_interface(&state, &interface_name)? {
        return Err(DnsError::ValidationFailed(format!(
            "DNS blocklists are not allowed on WAN interface {interface_name}"
        )));
    }

    if !is_valid_blocklist_url(&req.url) {
        return Err(DnsError::ValidationFailed(format!(
            "invalid blocklist URL: {}",
            req.url
        )));
    }

    let mut cfg = state
        .config_store
        .load_dns_config()
        .map_err(DnsError::StorageError)?
        .unwrap_or_default();

    let entry = DnsBlocklistEntry {
        id: Uuid::new_v4(),
        name: req
            .name
            .as_ref()
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty()),
        url: req.url.trim().to_string(),
        enabled: req.enabled,
    };

    if let Some(group) = cfg
        .interface_blocklists
        .iter_mut()
        .find(|group| group.interface == interface_name)
    {
        group.blocklists.push(entry.clone());
    } else {
        cfg.interface_blocklists.push(DnsInterfaceBlocklists {
            interface: interface_name.clone(),
            blocklists: vec![entry.clone()],
        });
    }

    state
        .config_store
        .save_dns_config(cfg.clone())
        .map_err(DnsError::StorageError)?;

    let dot = state
        .config_store
        .load_dot_config()
        .map_err(DnsError::StorageError)?;
    let (host_overrides, domain_overrides) = state
        .config_store
        .load_dns_overrides()
        .map_err(DnsError::StorageError)?;

    apply_config_with_overrides(
        &cfg,
        dot.as_ref(),
        ipv6_enabled(&state)?,
        &host_overrides,
        &domain_overrides,
    )
    .await
    .map_err(|e| DnsError::EngineError(e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "success": true, "data": entry })),
    ))
}

/// Handler: delete a DNS blocklist URL from a specific interface.
pub async fn delete_interface_blocklist(
    State(state): State<Arc<AppState>>,
    Path((interface_name, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, DnsError> {
    if !is_valid_interface_name(&interface_name) {
        return Err(DnsError::ValidationFailed(format!(
            "invalid interface name: {interface_name}"
        )));
    }

    if is_wan_interface(&state, &interface_name)? {
        return Err(DnsError::ValidationFailed(format!(
            "DNS blocklists are not allowed on WAN interface {interface_name}"
        )));
    }

    let target = id
        .parse::<Uuid>()
        .map_err(|_| DnsError::ValidationFailed(format!("invalid blocklist ID: {id}")))?;

    let mut cfg = state
        .config_store
        .load_dns_config()
        .map_err(DnsError::StorageError)?
        .unwrap_or_default();

    let mut removed = false;
    if let Some(group) = cfg
        .interface_blocklists
        .iter_mut()
        .find(|group| group.interface == interface_name)
    {
        let before = group.blocklists.len();
        group.blocklists.retain(|entry| entry.id != target);
        removed = group.blocklists.len() < before;
    }

    if !removed {
        return Err(DnsError::ValidationFailed(format!(
            "blocklist {id} not found on interface {interface_name}"
        )));
    }

    cfg.interface_blocklists
        .retain(|group| !group.blocklists.is_empty());

    state
        .config_store
        .save_dns_config(cfg.clone())
        .map_err(DnsError::StorageError)?;

    let dot = state
        .config_store
        .load_dot_config()
        .map_err(DnsError::StorageError)?;
    let (host_overrides, domain_overrides) = state
        .config_store
        .load_dns_overrides()
        .map_err(DnsError::StorageError)?;

    apply_config_with_overrides(
        &cfg,
        dot.as_ref(),
        ipv6_enabled(&state)?,
        &host_overrides,
        &domain_overrides,
    )
    .await
    .map_err(|e| DnsError::EngineError(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}
