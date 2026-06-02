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

use std::{
    io::ErrorKind,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    config::models::{
        ensure_ipv6_allowed, is_valid_cidr, is_valid_interface_name, is_valid_ip,
        validate_dns_cache_config, validate_dns_local_record, validate_dot_config,
        DnsBlocklistEntry, DnsCacheConfig, DnsClientAclPreset, DnsConfig, DnsDomainOverride,
        DnsInterfaceBlocklists, DnsLocalRecord, DnsResolverMode, DotConfig,
    },
    engine::dns::{
        apply_config_with_overrides, generate_config_with_overrides, DNSSEC_ROOT_KEY_PATH,
    },
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
#[derive(Deserialize)]
pub struct UpdateDnsConfigRequest {
    pub enabled: bool,
    pub listen_addresses: Vec<String>,
    pub port: u16,
    #[serde(default)]
    pub resolver_mode: Option<DnsResolverMode>,
    pub forwarders: Vec<String>,
    pub dnssec: bool,
    #[serde(default)]
    pub client_acl_preset: Option<DnsClientAclPreset>,
    #[serde(default)]
    pub client_acl_custom_cidrs: Option<Vec<String>>,
    #[serde(default)]
    pub cache: Option<DnsCacheConfig>,
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

#[derive(Serialize)]
pub struct DnsStatusResponse {
    pub enabled: bool,
    pub resolver_mode: DnsResolverMode,
    pub forwarders: Vec<String>,
    pub domain_forwarding: Vec<DnsDomainOverride>,
    pub dnssec: DnssecStatus,
    pub client_acl_preset: DnsClientAclPreset,
    pub client_acl_custom_cidrs: Vec<String>,
    pub cache: DnsCacheConfig,
    pub plain_dns_firewall_managed: bool,
    pub dot: DotExposureStatus,
    pub unbound: UnboundServiceStatus,
    pub config_validation: UnboundConfigValidationStatus,
}

#[derive(Serialize)]
pub struct DnssecStatus {
    pub enabled: bool,
    pub root_anchor_path: String,
    pub root_anchor_present: bool,
    pub root_anchor_readable: bool,
    pub root_anchor_size_bytes: Option<u64>,
    pub health: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct DotExposureStatus {
    pub enabled: bool,
    pub port: u16,
    pub exposure: String,
    pub firewall_rule_expected: bool,
    pub firewall_scope: String,
}

#[derive(Serialize)]
pub struct UnboundServiceStatus {
    pub systemctl_available: bool,
    pub active: Option<bool>,
    pub enabled: Option<bool>,
    pub active_state: Option<String>,
    pub enabled_state: Option<String>,
    pub message: String,
}

#[derive(Serialize)]
pub struct UnboundConfigValidationStatus {
    pub checkconf_available: bool,
    pub valid: Option<bool>,
    pub status: String,
    pub message: String,
}

/// Request body for creating a per-interface DNS blocklist URL.
#[derive(Deserialize)]
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

fn dnssec_status(enabled: bool) -> DnssecStatus {
    if !enabled {
        return DnssecStatus {
            enabled,
            root_anchor_path: DNSSEC_ROOT_KEY_PATH.to_string(),
            root_anchor_present: false,
            root_anchor_readable: false,
            root_anchor_size_bytes: None,
            health: "disabled".to_string(),
            message: "DNSSEC validation is disabled".to_string(),
        };
    }

    match std::fs::metadata(DNSSEC_ROOT_KEY_PATH) {
        Ok(metadata) => {
            let size = metadata.len();
            DnssecStatus {
                enabled,
                root_anchor_path: DNSSEC_ROOT_KEY_PATH.to_string(),
                root_anchor_present: true,
                root_anchor_readable: true,
                root_anchor_size_bytes: Some(size),
                health: if size == 0 { "empty" } else { "ok" }.to_string(),
                message: if size == 0 {
                    "DNSSEC root anchor exists but is empty".to_string()
                } else {
                    "DNSSEC root anchor is present".to_string()
                },
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => DnssecStatus {
            enabled,
            root_anchor_path: DNSSEC_ROOT_KEY_PATH.to_string(),
            root_anchor_present: false,
            root_anchor_readable: false,
            root_anchor_size_bytes: None,
            health: "missing".to_string(),
            message: "DNSSEC root anchor is missing; apply DNS config to create it".to_string(),
        },
        Err(err) => DnssecStatus {
            enabled,
            root_anchor_path: DNSSEC_ROOT_KEY_PATH.to_string(),
            root_anchor_present: true,
            root_anchor_readable: false,
            root_anchor_size_bytes: None,
            health: "unreadable".to_string(),
            message: format!("DNSSEC root anchor could not be read: {err}"),
        },
    }
}

fn dot_exposure_status(dot: &DotConfig) -> DotExposureStatus {
    let (exposure, firewall_rule_expected, firewall_scope) = if !dot.enabled {
        ("disabled", false, "none")
    } else if dot.lan_only {
        ("lan", true, "LAN input allow rule")
    } else {
        ("public", true, "public TCP input allow rule")
    };

    DotExposureStatus {
        enabled: dot.enabled,
        port: dot.port,
        exposure: exposure.to_string(),
        firewall_rule_expected,
        firewall_scope: firewall_scope.to_string(),
    }
}

async fn unbound_service_status() -> UnboundServiceStatus {
    let active_probe = systemctl_probe(&["is-active", "unbound"]).await;
    let enabled_probe = systemctl_probe(&["is-enabled", "unbound"]).await;

    if !active_probe.available || !enabled_probe.available {
        return UnboundServiceStatus {
            systemctl_available: false,
            active: None,
            enabled: None,
            active_state: None,
            enabled_state: None,
            message: "systemctl is not available on this host".to_string(),
        };
    }

    let active_state = active_probe.output.trim().to_string();
    let enabled_state = enabled_probe.output.trim().to_string();
    UnboundServiceStatus {
        systemctl_available: true,
        active: Some(active_state == "active"),
        enabled: Some(enabled_state == "enabled"),
        active_state: Some(active_state),
        enabled_state: Some(enabled_state),
        message: "systemctl status probes completed".to_string(),
    }
}

struct CommandProbe {
    available: bool,
    output: String,
}

async fn systemctl_probe(args: &[&str]) -> CommandProbe {
    match Command::new("systemctl").args(args).output().await {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            CommandProbe {
                available: true,
                output: if stdout.is_empty() { stderr } else { stdout },
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => CommandProbe {
            available: false,
            output: String::new(),
        },
        Err(err) => CommandProbe {
            available: true,
            output: err.to_string(),
        },
    }
}

async fn validate_generated_unbound_config(config_text: &str) -> UnboundConfigValidationStatus {
    let temp_path = temporary_unbound_config_path();
    if let Err(err) = std::fs::write(&temp_path, config_text) {
        return UnboundConfigValidationStatus {
            checkconf_available: false,
            valid: None,
            status: "error".to_string(),
            message: format!(
                "failed to write temporary Unbound config {}: {err}",
                temp_path.display()
            ),
        };
    }

    let result = match Command::new("unbound-checkconf")
        .arg(&temp_path)
        .output()
        .await
    {
        Ok(out) if out.status.success() => UnboundConfigValidationStatus {
            checkconf_available: true,
            valid: Some(true),
            status: "valid".to_string(),
            message: "generated Unbound config passed validation".to_string(),
        },
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            UnboundConfigValidationStatus {
                checkconf_available: true,
                valid: Some(false),
                status: "invalid".to_string(),
                message: join_command_output(stdout, stderr),
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => UnboundConfigValidationStatus {
            checkconf_available: false,
            valid: None,
            status: "skipped".to_string(),
            message: "unbound-checkconf is not installed".to_string(),
        },
        Err(err) => UnboundConfigValidationStatus {
            checkconf_available: true,
            valid: None,
            status: "error".to_string(),
            message: format!("failed to run unbound-checkconf: {err}"),
        },
    };

    let _ = std::fs::remove_file(&temp_path);
    result
}

fn temporary_unbound_config_path() -> PathBuf {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "dayshield-unbound-check-{}-{since_epoch}.conf",
        std::process::id()
    ))
}

fn join_command_output(stdout: String, stderr: String) -> String {
    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => "unbound-checkconf failed without output".to_string(),
        (false, true) => stdout,
        (true, false) => stderr,
        (false, false) => format!("{stdout}\n{stderr}"),
    }
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
    let (_host_overrides, domain_overrides) = state
        .config_store
        .load_dns_overrides()
        .map_err(DnsError::StorageError)?;

    info!(enabled = cfg.enabled, "dns: loaded config");

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "enabled": cfg.enabled,
            "listen_addresses": cfg.listen_addresses,
            "port": cfg.port,
            "resolver_mode": cfg.resolver_mode,
            "forwarders": cfg.forwarders,
            "dnssec": cfg.dnssec,
            "client_acl_preset": cfg.client_acl_preset,
            "client_acl_custom_cidrs": cfg.client_acl_custom_cidrs,
            "cache": cfg.cache,
            "local_records": cfg.local_records,
            "interface_blocklists": cfg.interface_blocklists,
            "manage_firewall": cfg.manage_firewall,
            "domain_forwarding": domain_overrides,
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

/// Handler: return DNS runtime and validation status for a settings panel.
pub async fn get_status(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, DnsError> {
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
    let ipv6_enabled = ipv6_enabled(&state)?;
    let (host_overrides, domain_overrides) = state
        .config_store
        .load_dns_overrides()
        .map_err(DnsError::StorageError)?;

    let generated = generate_config_with_overrides(
        &cfg,
        Some(&dot_cfg),
        ipv6_enabled,
        &host_overrides,
        &domain_overrides,
    );

    let dnssec = dnssec_status(cfg.dnssec);
    let dot = dot_exposure_status(&dot_cfg);
    let unbound = unbound_service_status().await;
    let config_validation = validate_generated_unbound_config(&generated).await;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": DnsStatusResponse {
            enabled: cfg.enabled,
            resolver_mode: cfg.resolver_mode,
            forwarders: cfg.forwarders,
            domain_forwarding: domain_overrides,
            dnssec,
            client_acl_preset: cfg.client_acl_preset,
            client_acl_custom_cidrs: cfg.client_acl_custom_cidrs,
            cache: cfg.cache,
            plain_dns_firewall_managed: cfg.manage_firewall,
            dot,
            unbound,
            config_validation,
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

    let resolver_mode = req.resolver_mode.unwrap_or_else(|| {
        if req.forwarders == existing.forwarders {
            existing.resolver_mode
        } else if req.forwarders.is_empty() {
            DnsResolverMode::Recursive
        } else {
            DnsResolverMode::Forwarded
        }
    });
    let client_acl_preset = req.client_acl_preset.unwrap_or(existing.client_acl_preset);
    let client_acl_custom_cidrs = req
        .client_acl_custom_cidrs
        .clone()
        .unwrap_or_else(|| existing.client_acl_custom_cidrs.clone())
        .into_iter()
        .map(|cidr| cidr.trim().to_string())
        .filter(|cidr| !cidr.is_empty())
        .collect::<Vec<_>>();
    let cache = req.cache.clone().unwrap_or_else(|| existing.cache.clone());

    if matches!(resolver_mode, DnsResolverMode::Forwarded) && req.forwarders.is_empty() {
        return Err(DnsError::ValidationFailed(
            "forwarded resolver mode requires at least one forwarder".into(),
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

    if matches!(client_acl_preset, DnsClientAclPreset::Custom) && client_acl_custom_cidrs.is_empty()
    {
        return Err(DnsError::ValidationFailed(
            "custom client ACL requires at least one CIDR".into(),
        ));
    }
    for cidr in &client_acl_custom_cidrs {
        if !is_valid_cidr(cidr) {
            return Err(DnsError::ValidationFailed(format!(
                "invalid client ACL CIDR: {cidr}"
            )));
        }
        if let Err(msg) = ensure_ipv6_allowed(cidr, ipv6_enabled, "DNS client ACL CIDR") {
            return Err(DnsError::ValidationFailed(msg));
        }
    }

    if let Err(msg) = validate_dns_cache_config(&cache) {
        return Err(DnsError::ValidationFailed(msg));
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
        resolver_mode,
        forwarders: req.forwarders,
        dnssec: req.dnssec,
        client_acl_preset,
        client_acl_custom_cidrs,
        cache,
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
