//!
//! - `GET  /system/status`   - overall health and version
//! - `GET  /system/services` - list manageable service runtimes
//! - `GET  /system/services/{service}` - get one manageable service runtime
//! - `POST /system/services/{service}/{action}` - start/stop/restart a service
//! - `GET  /system/config`   - host-level settings (hostname, timezone, NTP…)
//! - `PUT  /system/config`   - update host-level settings
//! - `POST /system/reboot`   - schedule an immediate systemctl reboot
//! - `POST /system/shutdown` - schedule an immediate systemctl poweroff
//! - `GET  /system/rootfs/status`         - image-based rootfs update status for appliance UI
//! - `POST /system/rootfs/check`          - check for rootfs image updates
//! - `POST /system/rootfs/stage`          - pre-download and stage rootfs image artifact
//! - `POST /system/rootfs/apply`          - activate staged rootfs image (marks for initramfs)
//! - `GET  /system/rootfs/reboot-required`- report reboot-required state for rootfs updates
//! - `POST /system/rootfs/rollback`       - roll back to previous rootfs version
//! - `GET  /system/updates/status`   - get artifact update status for core/ui/rootfs
//! - `GET  /system/updates/settings` - get update settings
//! - `PUT  /system/updates/settings` - update settings (interval/reboot policy/registry)
//! - `POST /system/updates/check`    - force immediate update check
//! - `POST /system/updates/apply`    - apply updates from registry artifacts
//! - `POST /system/updates/rollback` - rollback latest applied update transaction
//! - `POST /system/updates/validate` - validate applied update state
//! - `POST /system/updates/appliance-rebuild-complete` - clear pending appliance rebuild status

use std::{collections::BTreeSet, fs, path::Path, sync::Arc};

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

use crate::{
    auth::model::AuthenticatedUser,
    config::models::SystemSettings,
    engine::{
        dns::apply_config_with_overrides as apply_dns_config,
        interfaces::refresh_router_advertisements, ipv6::apply_ipv6_setting, kea,
    },
    rootfs_update,
    state::{
        AppState, SVC_CADDY, SVC_CLOUDFLARED, SVC_CROWDSEC, SVC_DHCP, SVC_DNS, SVC_NFTABLES,
        SVC_SURICATA, SVC_VPN,
    },
    update::{self, UpdateComponent, UpdateSettings},
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SystemApiError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("validation error: {0}")]
    ValidationFailed(String),

    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    #[error("command error: {0}")]
    CommandError(String),
}

const SSHD_CONFIG_PATH: &str = "/etc/ssh/sshd_config";
const SSH_ROOT_DIR: &str = "/root/.ssh";
const SSH_AUTHORIZED_KEYS_PATH: &str = "/root/.ssh/authorized_keys";

impl IntoResponse for SystemApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            SystemApiError::NotFound(_) => StatusCode::NOT_FOUND,
            SystemApiError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            SystemApiError::StorageError(_) | SystemApiError::CommandError(_) => {
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
// GET /system/status
// ---------------------------------------------------------------------------

/// Response body returned by `GET /system/status`.
#[derive(Serialize)]
pub struct SystemStatusResponse {
    pub name: &'static str,
    pub version: &'static str,
    pub timestamp: String,
    pub services_healthy: bool,
    pub service_count: usize,
}

/// Handler: return the current system status.
pub async fn get_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let svc_state = state.services.read().await;
    let all_healthy = svc_state.values().all(|&h| h);
    let count = svc_state.len();
    drop(svc_state);

    Json(SystemStatusResponse {
        name: "DayShield Core",
        version: env!("CARGO_PKG_VERSION"),
        timestamp: Utc::now().to_rfc3339(),
        services_healthy: all_healthy,
        service_count: count,
    })
}

// ---------------------------------------------------------------------------
// GET /system/services
// GET /system/services/{service}
// POST /system/services/{service}/{action}
// ---------------------------------------------------------------------------

const SVC_NTP: &str = "ntp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceAction {
    Start,
    Stop,
    Restart,
}

impl ServiceAction {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            "restart" => Some(Self::Restart),
            _ => None,
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Start => "Start",
            Self::Stop => "Stop",
            Self::Restart => "Restart",
        }
    }

    fn systemctl_verb(self) -> &'static str {
        self.id()
    }

    fn variant(self) -> &'static str {
        match self {
            Self::Start => "primary",
            Self::Stop => "danger",
            Self::Restart => "neutral",
        }
    }

    fn requires_confirmation(self) -> bool {
        matches!(self, Self::Stop)
    }
}

#[derive(Debug, Clone, Copy)]
struct ServiceDefinition {
    id: &'static str,
    title: &'static str,
    category: &'static str,
    description: &'static str,
}

const SERVICE_DEFINITIONS: &[ServiceDefinition] = &[
    ServiceDefinition {
        id: SVC_NFTABLES,
        title: "Firewall",
        category: "security",
        description: "nftables packet filtering and NAT enforcement",
    },
    ServiceDefinition {
        id: SVC_DNS,
        title: "DNS",
        category: "services",
        description: "Unbound recursive DNS and DNS-over-TLS listener",
    },
    ServiceDefinition {
        id: SVC_DHCP,
        title: "DHCP",
        category: "services",
        description: "Kea DHCPv4 and DHCPv6 address assignment",
    },
    ServiceDefinition {
        id: SVC_SURICATA,
        title: "Suricata",
        category: "security",
        description: "Suricata intrusion detection and prevention engine",
    },
    ServiceDefinition {
        id: SVC_CROWDSEC,
        title: "CrowdSec",
        category: "security",
        description: "CrowdSec local agent used by DayShield decisions",
    },
    ServiceDefinition {
        id: SVC_CLOUDFLARED,
        title: "Cloudflared",
        category: "services",
        description: "Cloudflare Tunnel connector",
    },
    ServiceDefinition {
        id: SVC_CADDY,
        title: "Caddy",
        category: "services",
        description: "Caddy reverse proxy with automatic HTTPS",
    },
    ServiceDefinition {
        id: SVC_VPN,
        title: "VPN",
        category: "services",
        description: "WireGuard VPN tunnel management",
    },
    ServiceDefinition {
        id: SVC_NTP,
        title: "NTP",
        category: "services",
        description: "systemd-timesyncd or chrony time synchronisation",
    },
];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceListResponse {
    pub generated_at: String,
    pub services: Vec<ServiceRuntimeStatus>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRuntimeStatus {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub configured: bool,
    pub status: &'static str,
    pub status_label: String,
    pub configured_units: Vec<String>,
    pub units: Vec<ServiceUnitStatus>,
    pub actions: Vec<ServiceActionDescriptor>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceUnitStatus {
    pub unit: String,
    pub available: bool,
    pub running: bool,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: String,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceActionDescriptor {
    pub id: &'static str,
    pub label: &'static str,
    pub method: &'static str,
    pub href: String,
    pub variant: &'static str,
    pub requires_confirmation: bool,
    pub enabled: bool,
    pub disabled_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceActionResponse {
    pub action: &'static str,
    pub message: String,
    pub affected_units: Vec<String>,
    pub service: ServiceRuntimeStatus,
}

/// Handler: return all services that support direct runtime controls.
pub async fn list_services(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    let mut services = Vec::with_capacity(SERVICE_DEFINITIONS.len());
    for def in SERVICE_DEFINITIONS {
        services.push(build_service_status(&state, def).await?);
    }

    Ok(Json(ServiceListResponse {
        generated_at: Utc::now().to_rfc3339(),
        services,
    }))
}

/// Handler: return live runtime status for one manageable service.
pub async fn get_service(
    AxumPath(service): AxumPath<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    let def = find_service_definition(&service)?;
    Ok(Json(build_service_status(&state, def).await?))
}

/// Handler: run a whitelisted service action through systemctl.
pub async fn control_service(
    AxumPath((service, action)): AxumPath<(String, String)>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    let def = find_service_definition(&service)?;
    let action = ServiceAction::parse(&action).ok_or_else(|| {
        SystemApiError::ValidationFailed(
            "unsupported service action; expected start, stop, or restart".to_string(),
        )
    })?;
    let target_units = action_units(&state, def.id, action).await?;

    info!(
        service = def.id,
        action = action.id(),
        units = ?target_units,
        "system: service action requested"
    );

    for unit in &target_units {
        run_systemctl_unit(action, unit).await?;
    }

    let status = build_service_status(&state, def).await?;
    update_service_health(&state, def.id, &status).await;

    Ok(Json(ServiceActionResponse {
        action: action.id(),
        message: format!(
            "{} {} completed",
            def.title,
            action.label().to_ascii_lowercase()
        ),
        affected_units: target_units.into_iter().map(str::to_string).collect(),
        service: status,
    }))
}

fn find_service_definition(service: &str) -> Result<&'static ServiceDefinition, SystemApiError> {
    SERVICE_DEFINITIONS
        .iter()
        .find(|def| def.id.eq_ignore_ascii_case(service.trim()))
        .ok_or_else(|| SystemApiError::NotFound(format!("unknown manageable service: {service}")))
}

async fn build_service_status(
    state: &Arc<AppState>,
    def: &'static ServiceDefinition,
) -> Result<ServiceRuntimeStatus, SystemApiError> {
    let all_units = all_service_units(def.id);
    let configured_units = configured_service_units(state, def.id).await?;
    let mut units = Vec::with_capacity(all_units.len());
    for unit in all_units {
        units.push(read_unit_status(unit).await);
    }

    let configured = !configured_units.is_empty();
    let (status, status_label) = summarize_service_status(configured, &configured_units, &units);
    let actions = service_action_descriptors(def.id, configured, &units);

    Ok(ServiceRuntimeStatus {
        id: def.id,
        title: def.title,
        category: def.category,
        description: def.description,
        configured,
        status,
        status_label,
        configured_units: configured_units.into_iter().map(str::to_string).collect(),
        units,
        actions,
        updated_at: Utc::now().to_rfc3339(),
    })
}

fn all_service_units(service_id: &str) -> Vec<&'static str> {
    match service_id {
        SVC_NFTABLES => vec!["nftables.service"],
        SVC_DNS => vec!["unbound.service"],
        SVC_DHCP => kea::dhcp4_service_candidates()
            .iter()
            .chain(kea::dhcp6_service_candidates().iter())
            .copied()
            .collect(),
        SVC_SURICATA => vec!["suricata.service"],
        SVC_CROWDSEC => vec!["crowdsec.service"],
        SVC_CLOUDFLARED => vec!["cloudflared.service"],
        SVC_CADDY => vec!["caddy.service"],
        SVC_NTP => vec![
            "systemd-timesyncd.service",
            "chrony.service",
            "chronyd.service",
        ],
        _ => vec![],
    }
}

async fn configured_service_units(
    state: &Arc<AppState>,
    service_id: &str,
) -> Result<Vec<&'static str>, SystemApiError> {
    match service_id {
        SVC_NFTABLES => Ok(vec!["nftables.service"]),
        SVC_DNS => {
            let enabled = state
                .config_store
                .load_dns_config()
                .map_err(SystemApiError::StorageError)?
                .unwrap_or_default()
                .enabled;
            Ok(if enabled {
                vec!["unbound.service"]
            } else {
                vec![]
            })
        }
        SVC_DHCP => {
            let mut units = Vec::new();
            let dhcp_enabled = state
                .config_store
                .load_dhcp_config()
                .map_err(SystemApiError::StorageError)?
                .map(|cfg| cfg.enabled)
                .unwrap_or(false);
            if dhcp_enabled {
                units.push(
                    first_available_unit(kea::dhcp4_service_candidates())
                        .await
                        .unwrap_or(kea::dhcp4_service_candidates()[0]),
                );
            }

            let dhcp6_enabled = state
                .config_store
                .load_dhcp6_config()
                .map_err(SystemApiError::StorageError)?
                .map(|cfg| cfg.enabled)
                .unwrap_or(false);
            if dhcp6_enabled {
                units.push(
                    first_available_unit(kea::dhcp6_service_candidates())
                        .await
                        .unwrap_or(kea::dhcp6_service_candidates()[0]),
                );
            }
            Ok(units)
        }
        SVC_SURICATA => {
            let enabled = state
                .config_store
                .load_suricata_config()
                .map_err(SystemApiError::StorageError)?
                .map(|cfg| cfg.enabled)
                .unwrap_or(false);
            Ok(if enabled {
                vec!["suricata.service"]
            } else {
                vec![]
            })
        }
        SVC_CROWDSEC => {
            let enabled = state
                .config_store
                .load_crowdsec_config()
                .map_err(SystemApiError::StorageError)?
                .map(|cfg| cfg.enabled)
                .unwrap_or(false);
            Ok(if enabled {
                vec!["crowdsec.service"]
            } else {
                vec![]
            })
        }
        SVC_CLOUDFLARED => {
            let enabled = state
                .config_store
                .load_cloudflared_config()
                .map_err(SystemApiError::StorageError)?
                .unwrap_or_default()
                .enabled;
            Ok(if enabled {
                vec!["cloudflared.service"]
            } else {
                vec![]
            })
        }
        SVC_CADDY => {
            let enabled = state
                .config_store
                .load_caddy_config()
                .map_err(SystemApiError::StorageError)?
                .unwrap_or_default()
                .enabled;
            Ok(if enabled {
                vec!["caddy.service"]
            } else {
                vec![]
            })
        }
        SVC_NTP => {
            let cfg = crate::ntp::config::load(&state.config_store)
                .map_err(SystemApiError::StorageError)?;
            if !cfg.enabled {
                return Ok(vec![]);
            }
            if cfg.serve_clients {
                Ok(first_available_unit(&["chrony.service", "chronyd.service"])
                    .await
                    .into_iter()
                    .collect())
            } else if let Some(unit) = first_available_unit(&[
                "systemd-timesyncd.service",
                "chrony.service",
                "chronyd.service",
            ])
            .await
            {
                Ok(vec![unit])
            } else {
                Ok(vec![])
            }
        }
        _ => Ok(vec![]),
    }
}

async fn first_available_unit(candidates: &[&'static str]) -> Option<&'static str> {
    for unit in candidates {
        if read_unit_status(unit).await.available {
            return Some(*unit);
        }
    }
    None
}

async fn action_units(
    state: &Arc<AppState>,
    service_id: &str,
    action: ServiceAction,
) -> Result<Vec<&'static str>, SystemApiError> {
    if matches!(action, ServiceAction::Stop) {
        let mut units = Vec::new();
        for unit in all_service_units(service_id) {
            if read_unit_status(unit).await.available {
                units.push(unit);
            }
        }
        if units.is_empty() {
            return Err(SystemApiError::ValidationFailed(format!(
                "{service_id} has no available systemd units to stop"
            )));
        }
        return Ok(units);
    }

    let units = configured_service_units(state, service_id).await?;
    if units.is_empty() {
        return Err(SystemApiError::ValidationFailed(format!(
            "{service_id} is disabled or has no available configured service unit"
        )));
    }
    Ok(units)
}

async fn run_systemctl_unit(action: ServiceAction, unit: &str) -> Result<(), SystemApiError> {
    let output = tokio::process::Command::new("systemctl")
        .args([action.systemctl_verb(), unit])
        .output()
        .await
        .map_err(|err| SystemApiError::CommandError(format!("failed to spawn systemctl: {err}")))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    Err(SystemApiError::CommandError(if detail.is_empty() {
        format!("systemctl {} {unit} failed", action.systemctl_verb())
    } else {
        format!(
            "systemctl {} {unit} failed: {detail}",
            action.systemctl_verb()
        )
    }))
}

async fn read_unit_status(unit: &str) -> ServiceUnitStatus {
    let mut status = ServiceUnitStatus {
        unit: unit.to_string(),
        available: false,
        running: false,
        load_state: "unknown".to_string(),
        active_state: "unknown".to_string(),
        sub_state: "unknown".to_string(),
        unit_file_state: "unknown".to_string(),
        last_error: None,
    };

    match tokio::process::Command::new("systemctl")
        .args([
            "show",
            unit,
            "--property=LoadState,ActiveState,SubState,UnitFileState",
            "--no-pager",
        ])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(value) = line.strip_prefix("LoadState=") {
                    status.load_state = value.trim().to_string();
                } else if let Some(value) = line.strip_prefix("ActiveState=") {
                    status.active_state = value.trim().to_string();
                } else if let Some(value) = line.strip_prefix("SubState=") {
                    status.sub_state = value.trim().to_string();
                } else if let Some(value) = line.strip_prefix("UnitFileState=") {
                    status.unit_file_state = value.trim().to_string();
                }
            }
            status.available = status.load_state != "not-found";
            status.running = status.active_state == "active";
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            status.last_error = Some(if stderr.is_empty() {
                format!("systemctl show {unit} failed")
            } else {
                stderr
            });
        }
        Err(err) => {
            status.last_error = Some(format!("failed to query systemctl: {err}"));
        }
    }

    status
}

fn summarize_service_status(
    configured: bool,
    configured_units: &[&'static str],
    units: &[ServiceUnitStatus],
) -> (&'static str, String) {
    if !configured {
        return ("notConfigured", "Disabled".to_string());
    }

    let relevant = units
        .iter()
        .filter(|unit| configured_units.contains(&unit.unit.as_str()))
        .collect::<Vec<_>>();

    if relevant.is_empty() {
        return ("unknown", "Runtime unit could not be resolved".to_string());
    }

    if relevant.iter().any(|unit| !unit.available) {
        return ("missing", "Configured unit is not installed".to_string());
    }

    let running = relevant.iter().filter(|unit| unit.running).count();
    match running {
        0 => ("stopped", "Stopped".to_string()),
        n if n == relevant.len() => ("running", "Running".to_string()),
        n => (
            "degraded",
            format!("{n}/{} configured units running", relevant.len()),
        ),
    }
}

fn service_action_descriptors(
    service_id: &'static str,
    configured: bool,
    units: &[ServiceUnitStatus],
) -> Vec<ServiceActionDescriptor> {
    let has_available_unit = units.iter().any(|unit| unit.available);
    [
        ServiceAction::Start,
        ServiceAction::Stop,
        ServiceAction::Restart,
    ]
    .into_iter()
    .map(|action| {
        let disabled_reason = match action {
            ServiceAction::Start | ServiceAction::Restart if !configured => {
                Some("Enable this service in configuration before using this action".to_string())
            }
            ServiceAction::Stop if !has_available_unit => {
                Some("No systemd unit is available for this service".to_string())
            }
            _ => None,
        };
        ServiceActionDescriptor {
            id: action.id(),
            label: action.label(),
            method: "POST",
            href: format!("/system/services/{service_id}/{}", action.id()),
            variant: action.variant(),
            requires_confirmation: action.requires_confirmation(),
            enabled: disabled_reason.is_none(),
            disabled_reason,
        }
    })
    .collect()
}

async fn update_service_health(
    state: &Arc<AppState>,
    service_id: &str,
    status: &ServiceRuntimeStatus,
) {
    let healthy = status.status == "running";
    let mut map = state.services.write().await;
    map.insert(service_id.to_string(), healthy);
}

// ---------------------------------------------------------------------------
// GET /system/config
// ---------------------------------------------------------------------------

/// Handler: return the current system settings.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    let settings = state
        .config_store
        .load_system_settings()
        .map_err(SystemApiError::StorageError)?;
    Ok(Json(settings))
}

// ---------------------------------------------------------------------------
// POST /system/config
// ---------------------------------------------------------------------------

/// Handler: replace the system settings.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(settings): Json<SystemSettings>,
) -> Result<impl IntoResponse, SystemApiError> {
    validate_system_settings(&state, &settings)?;
    let previous = state
        .config_store
        .load_system_settings()
        .unwrap_or_default();

    state
        .config_store
        .save_system_settings(settings.clone())
        .map_err(SystemApiError::StorageError)?;

    apply_ssh_settings(&state, &previous, &settings).await?;

    if previous.ipv6_enabled != settings.ipv6_enabled {
        apply_ipv6_setting(settings.ipv6_enabled)
            .await
            .map_err(|e| {
                SystemApiError::CommandError(format!("failed to apply IPv6 setting: {e:#}"))
            })?;

        let full_cfg = state
            .config_store
            .load()
            .map_err(SystemApiError::StorageError)?;

        crate::captive_portal::apply_current_ruleset_nft(&state.config_store)
            .await
            .map_err(|e| {
                SystemApiError::CommandError(format!("failed to reapply firewall rules: {e}"))
            })?;

        if let Some(dns) = full_cfg.dns.as_ref() {
            apply_dns_config(
                dns,
                full_cfg.dot.as_ref(),
                settings.ipv6_enabled,
                &full_cfg.dns_host_overrides,
                &full_cfg.dns_domain_overrides,
            )
            .await
            .map_err(|e| {
                SystemApiError::CommandError(format!("failed to reapply DNS config: {e:#}"))
            })?;
        }

        refresh_router_advertisements(&full_cfg.interfaces, settings.ipv6_enabled).await;
    }

    if previous.web_port != settings.web_port {
        warn!(
            previous_web_port = previous.web_port,
            new_web_port = settings.web_port,
            "system: web port changed; restart required to apply"
        );
    }
    if previous.management_https_enabled != settings.management_https_enabled
        || previous.management_tls_acme_domain != settings.management_tls_acme_domain
    {
        warn!(
            https_enabled = settings.management_https_enabled,
            tls_domain = ?settings.management_tls_acme_domain,
            "system: management HTTPS setting changed; restart required to apply"
        );
    }

    info!(
        hostname = %settings.hostname,
        timezone = %settings.timezone,
        ssh_enabled = settings.ssh_enabled,
        ipv6_enabled = settings.ipv6_enabled,
        web_port = settings.web_port,
        "system: settings updated via API"
    );

    Ok(Json(settings))
}

fn validate_system_settings(
    state: &AppState,
    settings: &SystemSettings,
) -> Result<(), SystemApiError> {
    if settings.hostname.trim().is_empty() {
        return Err(SystemApiError::CommandError(
            "hostname must not be empty".into(),
        ));
    }
    if settings.ssh_port == 0 {
        return Err(SystemApiError::CommandError(
            "ssh_port must be between 1 and 65535".into(),
        ));
    }
    if settings.web_port == 0 {
        return Err(SystemApiError::CommandError(
            "web_port must be between 1 and 65535".into(),
        ));
    }
    if settings.ssh_port == settings.web_port {
        return Err(SystemApiError::CommandError(
            "ssh_port and web_port must be different".into(),
        ));
    }
    if settings.management_https_enabled && settings.management_tls_acme_domain.is_none() {
        return Err(SystemApiError::CommandError(
            "management_tls_acme_domain must be set when management_https_enabled is true".into(),
        ));
    }

    let cfg = state
        .config_store
        .load()
        .map_err(SystemApiError::StorageError)?;
    let known_interfaces = cfg
        .interfaces
        .iter()
        .filter(|iface| iface.enabled)
        .map(|iface| iface.name.as_str())
        .collect::<BTreeSet<_>>();
    for iface in &settings.ssh_listen_interfaces {
        if iface.trim().is_empty() {
            return Err(SystemApiError::CommandError(
                "ssh_listen_interfaces cannot contain empty interface names".into(),
            ));
        }
        if !known_interfaces.contains(iface.as_str()) {
            return Err(SystemApiError::CommandError(format!(
                "unknown SSH listen interface: {iface}"
            )));
        }
    }

    Ok(())
}

async fn apply_ssh_settings(
    state: &AppState,
    previous: &SystemSettings,
    settings: &SystemSettings,
) -> Result<(), SystemApiError> {
    let full_cfg = state
        .config_store
        .load()
        .map_err(SystemApiError::StorageError)?;
    let listen_addresses =
        resolve_ssh_listen_addresses(&settings.ssh_listen_interfaces, &full_cfg.interfaces).await;
    render_and_write_ssh_config(settings, &listen_addresses)?;
    if normalized_authorized_keys(&previous.ssh_authorized_keys)
        != normalized_authorized_keys(&settings.ssh_authorized_keys)
    {
        write_authorized_keys(&settings.ssh_authorized_keys)?;
    }

    if settings.ssh_enabled {
        run_systemctl(["enable", "--now", "ssh"]).await?;
        run_systemctl(["reload-or-restart", "ssh"]).await?;
    } else {
        run_systemctl(["disable", "--now", "ssh"]).await?;
    }

    Ok(())
}

fn render_and_write_ssh_config(
    settings: &SystemSettings,
    listen_addresses: &[String],
) -> Result<(), SystemApiError> {
    let mut rendered = String::new();
    rendered.push_str("# DayShield - managed sshd_config\n");
    rendered.push_str(&format!("Port {}\n", settings.ssh_port));
    rendered.push_str("AddressFamily any\n");
    for addr in listen_addresses {
        rendered.push_str(&format!("ListenAddress {}\n", addr));
    }
    rendered.push_str("\n# Authentication\n");
    rendered.push_str(&format!(
        "PermitRootLogin {}\n",
        if settings.ssh_permit_root_login {
            "yes"
        } else {
            "no"
        }
    ));
    rendered.push_str("PubkeyAuthentication yes\n");
    rendered.push_str("AuthorizedKeysFile .ssh/authorized_keys\n");
    rendered.push_str(&format!(
        "PasswordAuthentication {}\n",
        if settings.ssh_password_authentication {
            "yes"
        } else {
            "no"
        }
    ));
    rendered.push_str("PermitEmptyPasswords no\n");
    rendered.push_str("ChallengeResponseAuthentication no\n");
    rendered.push_str("KbdInteractiveAuthentication no\n");
    rendered.push_str("UsePAM yes\n");
    rendered.push_str("UseDNS no\n");
    rendered.push_str("PermitUserEnvironment no\n");
    rendered.push_str("LogLevel VERBOSE\n\n");
    rendered.push_str("# Forwarding\n");
    rendered.push_str("AllowAgentForwarding no\n");
    rendered.push_str("AllowTcpForwarding no\n");
    rendered.push_str("GatewayPorts no\n");
    rendered.push_str("X11Forwarding no\n");
    rendered.push_str("PermitTunnel no\n\n");
    rendered.push_str("# Session hardening\n");
    rendered.push_str("LoginGraceTime 30\n");
    rendered.push_str("MaxAuthTries 3\n");
    rendered.push_str("MaxStartups 10:30:60\n");
    rendered.push_str("MaxSessions 5\n");
    rendered.push_str("ClientAliveInterval 300\n");
    rendered.push_str("ClientAliveCountMax 2\n\n");
    rendered.push_str("Subsystem sftp /usr/lib/openssh/sftp-server\n");

    fs::write(SSHD_CONFIG_PATH, rendered)
        .map_err(|err| SystemApiError::CommandError(format!("failed to write sshd config: {err}")))
}

fn write_authorized_keys(keys: &[String]) -> Result<(), SystemApiError> {
    fs::create_dir_all(SSH_ROOT_DIR).map_err(|err| {
        SystemApiError::CommandError(format!("failed to create SSH directory: {err}"))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(SSH_ROOT_DIR, fs::Permissions::from_mode(0o700));
    }

    let contents = if keys.is_empty() {
        String::new()
    } else {
        let mut normalized = keys
            .iter()
            .map(|key| key.trim())
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        normalized.push('\n');
        normalized
    };

    fs::write(SSH_AUTHORIZED_KEYS_PATH, contents).map_err(|err| {
        SystemApiError::CommandError(format!("failed to write authorized_keys: {err}"))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(SSH_AUTHORIZED_KEYS_PATH, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn normalized_authorized_keys(keys: &[String]) -> String {
    let mut normalized = keys
        .iter()
        .map(|key| key.trim())
        .filter(|key| !key.is_empty())
        .collect::<Vec<_>>()
        .join("\n");

    if !normalized.is_empty() {
        normalized.push('\n');
    }

    normalized
}

async fn resolve_ssh_listen_addresses(
    selected_interfaces: &[String],
    interfaces: &[crate::config::models::Interface],
) -> Vec<String> {
    let mut addresses = BTreeSet::new();
    for iface_name in selected_interfaces {
        if let Ok(output) = tokio::process::Command::new("ip")
            .args(["-j", "addr", "show", "dev", iface_name])
            .output()
            .await
        {
            if output.status.success() {
                if let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) {
                    if let Some(items) = value.as_array() {
                        for item in items {
                            if let Some(addr_info) = item.get("addr_info").and_then(Value::as_array)
                            {
                                for addr in addr_info {
                                    if let Some(local) = addr.get("local").and_then(Value::as_str) {
                                        addresses.insert(local.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(iface) = interfaces.iter().find(|iface| iface.name == *iface_name) {
            for addr in &iface.addresses {
                if let Some(local) = addr.split('/').next().filter(|value| !value.is_empty()) {
                    addresses.insert(local.to_string());
                }
            }
        }
    }
    addresses.into_iter().collect()
}

async fn run_systemctl<const N: usize>(args: [&str; N]) -> Result<(), SystemApiError> {
    let output = tokio::process::Command::new("systemctl")
        .args(args)
        .output()
        .await
        .map_err(|err| SystemApiError::CommandError(format!("failed to spawn systemctl: {err}")))?;
    if output.status.success() {
        return Ok(());
    }
    if args.last() == Some(&"ssh") {
        let mut fallback = args
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        if let Some(last) = fallback.last_mut() {
            *last = "sshd".to_string();
        }
        let fallback_output = tokio::process::Command::new("systemctl")
            .args(&fallback)
            .output()
            .await
            .map_err(|err| {
                SystemApiError::CommandError(format!("failed to spawn systemctl fallback: {err}"))
            })?;
        if fallback_output.status.success() {
            return Ok(());
        }
    }
    Err(SystemApiError::CommandError(format!(
        "systemctl {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    )))
}

// ---------------------------------------------------------------------------
// POST /system/reboot
// ---------------------------------------------------------------------------

/// Handler: trigger an immediate system reboot via systemctl.
pub async fn reboot(
    State(_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    info!("system: reboot requested via API");
    tokio::process::Command::new("systemctl")
        .arg("--no-block")
        .arg("reboot")
        .spawn()
        .map_err(|e| {
            SystemApiError::CommandError(format!("failed to spawn systemctl reboot: {e}"))
        })?
        .wait()
        .await
        .map_err(|e| SystemApiError::CommandError(format!("systemctl reboot failed: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /system/shutdown
// ---------------------------------------------------------------------------

/// Handler: trigger an immediate system poweroff via systemctl.
pub async fn shutdown(
    State(_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    info!("system: shutdown requested via API");
    tokio::process::Command::new("systemctl")
        .arg("--no-block")
        .arg("poweroff")
        .spawn()
        .map_err(|e| {
            SystemApiError::CommandError(format!("failed to spawn systemctl poweroff: {e}"))
        })?
        .wait()
        .await
        .map_err(|e| SystemApiError::CommandError(format!("systemctl poweroff failed: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Rootfs image-based updates
// ---------------------------------------------------------------------------

/// Handler: return image-based rootfs update status for UI.
pub async fn get_rootfs_status() -> impl IntoResponse {
    Json(rootfs_update::status().await)
}

/// Handler: trigger an immediate check for a new rootfs image artifact.
pub async fn check_rootfs_updates(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let _ = update::check_for_updates(&state).await;
    Json(rootfs_update::status().await)
}


/// Handler: activate the staged rootfs image for boot.
///
/// Marks the staged image as ready for initramfs activation on the next boot.
/// Poll `/system/rootfs/status` to observe progress via `transaction_state`.
pub async fn apply_rootfs_update(
    Extension(user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    if let Err(reason) = authorize_sensitive_rootfs_operation("apply", &user) {
        return rootfs_authorization_error_response("apply", &user, &reason);
    }

    let user_clone = user.clone();
    crate::live_logs::ui::publish(crate::live_logs::LogEvent::UpdateEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        operation: "apply".to_string(),
        level: "info".to_string(),
        message: "Rootfs apply operation started".to_string(),
        component: Some("rootfs".to_string()),
    });
    tokio::spawn(async move {
        match rootfs_update::apply_update().await {
            Ok(result) => {
                audit_sensitive_rootfs_result(
                    "apply",
                    &user_clone,
                    result.success,
                    &result.message,
                );
                crate::live_logs::ui::publish(crate::live_logs::LogEvent::UpdateEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    operation: "apply".to_string(),
                    level: if result.success { "info" } else { "warning" }.to_string(),
                    message: result.message,
                    component: Some("rootfs".to_string()),
                });
            }
            Err(err) => {
                audit_sensitive_rootfs_error("apply", &user_clone, &err);
                crate::live_logs::ui::publish(crate::live_logs::LogEvent::UpdateEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    operation: "apply".to_string(),
                    level: "error".to_string(),
                    message: format!("Rootfs apply failed: {err}"),
                    component: Some("rootfs".to_string()),
                });
            }
        }
    });

    let current_status = rootfs_update::status().await;
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "operation": "apply",
            "success": true,
            "message": "Rootfs apply operation started. Poll /system/rootfs/status for progress.",
            "details": [],
            "status": current_status
        })),
    )
        .into_response()
}

/// Handler: return compact reboot-required state for rootfs update UX.
pub async fn get_rootfs_reboot_required() -> impl IntoResponse {
    Json(rootfs_update::reboot_state().await)
}

/// Handler: roll back the rootfs to the previous version.
pub async fn rollback_rootfs_update(
    Extension(user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    if let Err(reason) = authorize_sensitive_rootfs_operation("rollback", &user) {
        return rootfs_authorization_error_response("rollback", &user, &reason);
    }

    let user_clone = user.clone();
    crate::live_logs::ui::publish(crate::live_logs::LogEvent::UpdateEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        operation: "rollback".to_string(),
        level: "info".to_string(),
        message: "Rootfs rollback operation started".to_string(),
        component: Some("rootfs".to_string()),
    });
    tokio::spawn(async move {
        match rootfs_update::rollback().await {
            Ok(result) => {
                audit_sensitive_rootfs_result(
                    "rollback",
                    &user_clone,
                    result.success,
                    &result.message,
                );
                crate::live_logs::ui::publish(crate::live_logs::LogEvent::UpdateEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    operation: "rollback".to_string(),
                    level: if result.success { "info" } else { "warning" }.to_string(),
                    message: result.message,
                    component: Some("rootfs".to_string()),
                });
            }
            Err(err) => {
                audit_sensitive_rootfs_error("rollback", &user_clone, &err);
                crate::live_logs::ui::publish(crate::live_logs::LogEvent::UpdateEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    operation: "rollback".to_string(),
                    level: "error".to_string(),
                    message: format!("Rootfs rollback failed: {err}"),
                    component: Some("rootfs".to_string()),
                });
            }
        }
    });

    let current_status = rootfs_update::status().await;
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "operation": "rollback",
            "success": true,
            "message": "Rootfs rollback operation started. Poll /system/rootfs/status for progress.",
            "details": [],
            "status": current_status
        })),
    )
        .into_response()
}

/// Policy hook for rootfs operations that can mutate the boot image.
fn authorize_sensitive_rootfs_operation(
    operation: &str,
    user: &AuthenticatedUser,
) -> Result<(), String> {
    if user.username == "admin" {
        info!(
            target: "audit",
            username = %user.username,
            operation,
            "rootfs: sensitive operation authorized"
        );
        return Ok(());
    }

    let reason = format!(
        "user '{}' is not allowed to run rootfs {operation}; admin identity required",
        user.username
    );
    warn!(
        target: "audit",
        username = %user.username,
        operation,
        reason = %reason,
        "rootfs: sensitive operation denied"
    );
    Err(reason)
}

fn rootfs_authorization_error_response(
    operation: &str,
    user: &AuthenticatedUser,
    reason: &str,
) -> axum::response::Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "operation": operation,
            "success": false,
            "message": format!("not authorized to {operation} rootfs update"),
            "details": [reason],
            "user": user.username
        })),
    )
        .into_response()
}

fn audit_sensitive_rootfs_result(
    operation: &str,
    user: &AuthenticatedUser,
    success: bool,
    message: &str,
) {
    if success {
        info!(
            target: "audit",
            username = %user.username,
            operation,
            message,
            "rootfs: sensitive operation completed"
        );
    } else {
        warn!(
            target: "audit",
            username = %user.username,
            operation,
            message,
            "rootfs: sensitive operation completed unsuccessfully"
        );
    }
}

fn audit_sensitive_rootfs_error(operation: &str, user: &AuthenticatedUser, err: &anyhow::Error) {
    warn!(
        target: "audit",
        username = %user.username,
        operation,
        error = %err,
        "rootfs: sensitive operation failed"
    );
}

// ---------------------------------------------------------------------------
// Software updates
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateActionRequest {
    #[serde(default = "default_update_component")]
    pub component: UpdateComponent,
    /// If true, allows applying updates to only a subset of components even when multiple have available updates
    #[serde(default)]
    pub force_partial_apply: bool,
}

fn default_update_component() -> UpdateComponent {
    UpdateComponent::All
}

/// Handler: return software-update status for core and UI artifacts.
pub async fn get_updates_status(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    Ok(Json(update::get_status(&state).await))
}

/// Handler: return persisted software-update settings.
pub async fn get_update_settings(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    Ok(Json(update::load_settings(&state)))
}

/// Handler: update software-update settings.
pub async fn update_update_settings(
    State(state): State<Arc<AppState>>,
    Json(settings): Json<UpdateSettings>,
) -> Result<impl IntoResponse, SystemApiError> {
    update::save_settings(&state, &settings).map_err(SystemApiError::StorageError)?;
    Ok(Json(update::load_settings(&state)))
}

/// Handler: run an immediate check against configured update registry.
pub async fn check_updates(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    let status = update::check_for_updates(&state)
        .await
        .map_err(SystemApiError::StorageError)?;
    Ok(Json(status))
}

/// Handler: apply updates for selected component(s).
///
/// Spawns the update process in a background task and returns immediately with
/// 202 Accepted. The caller should poll `/system/updates/status` to monitor progress.
pub async fn apply_updates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<impl IntoResponse, SystemApiError> {
    let component = req.component;
    let force_partial = req.force_partial_apply;
    let state_clone = Arc::clone(&state);

    // Spawn update in background - don't wait for completion
    tokio::spawn(async move {
        match update::apply_updates(&state_clone, component, force_partial).await {
            Ok(result) => {
                info!(
                    "updates: background apply_updates completed successfully: {}",
                    result.message
                );
            }
            Err(e) => {
                warn!("updates: background apply_updates failed: {}", e);
            }
        }
    });

    // Get current status to return immediately
    let current_status = update::get_status(&state).await;

    // Return 202 Accepted immediately with current status to prevent timeout
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "operation": "apply",
            "success": true,
            "message": "Update process started. Progress is available in update status logs.",
            "details": [],
            "status": current_status
        })),
    ))
}

/// Handler: rollback selected component(s) to previous commit.
///
/// Spawns the rollback process in a background task and returns immediately.
/// The caller should poll `/system/updates/status` to monitor progress.
pub async fn rollback_updates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<impl IntoResponse, SystemApiError> {
    let component = req.component;
    if matches!(component, UpdateComponent::Rootfs) {
        // Rootfs rollback is handled by the dedicated /system/rootfs/rollback endpoint.
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "operation": "rollback",
                "success": false,
                "message": "Root filesystem rollbacks are managed through /system/rootfs/rollback.",
                "details": [],
                "status": update::get_status(&state).await
            })),
        ));
    }
    let force_partial = req.force_partial_apply;
    let state_clone = Arc::clone(&state);

    // Spawn rollback in background - don't wait for completion
    tokio::spawn(async move {
        match update::rollback_updates(&state_clone, component, force_partial).await {
            Ok(result) => {
                info!(
                    "updates: background rollback_updates completed successfully: {}",
                    result.message
                );
            }
            Err(e) => {
                warn!("updates: background rollback_updates failed: {}", e);
            }
        }
    });

    // Get current status to return immediately
    let current_status = update::get_status(&state).await;

    // Return 202 Accepted immediately with current status
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "operation": "rollback",
            "success": true,
            "message": "Rollback process started. Progress is available in update status logs.",
            "details": [],
            "status": current_status
        })),
    ))
}

/// Handler: validate selected component(s) are at expected commit.
pub async fn validate_updates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<impl IntoResponse, SystemApiError> {
    if matches!(req.component, UpdateComponent::Rootfs) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "operation": "validate",
                "success": false,
                "message": "Root filesystem deployment validation is available via /system/rootfs/status.",
                "details": [],
                "status": update::get_status(&state).await
            })),
        ));
    }

    let result = update::validate_updates(&state, req.component, req.force_partial_apply)
        .await
        .map_err(SystemApiError::StorageError)?;
    Ok((StatusCode::OK, Json(serde_json::json!(result))))
}

/// Handler: mark the appliance rebuild workflow as completed after rebuilding artifacts.
pub async fn mark_appliance_rebuild_complete(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    update::mark_appliance_rebuild_complete(&state).map_err(SystemApiError::StorageError)?;
    Ok(Json(update::get_status(&state).await))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit_status(unit: &str, available: bool, running: bool) -> ServiceUnitStatus {
        ServiceUnitStatus {
            unit: unit.to_string(),
            available,
            running,
            load_state: if available { "loaded" } else { "not-found" }.to_string(),
            active_state: if running { "active" } else { "inactive" }.to_string(),
            sub_state: if running { "running" } else { "dead" }.to_string(),
            unit_file_state: "enabled".to_string(),
            last_error: None,
        }
    }

    #[test]
    fn service_action_parser_accepts_supported_actions() {
        assert_eq!(ServiceAction::parse("start"), Some(ServiceAction::Start));
        assert_eq!(ServiceAction::parse("STOP"), Some(ServiceAction::Stop));
        assert_eq!(
            ServiceAction::parse("restart"),
            Some(ServiceAction::Restart)
        );
        assert_eq!(ServiceAction::parse("reload"), None);
    }

    #[test]
    fn service_action_descriptors_are_ui_ready() {
        let units = vec![unit_status("unbound.service", true, true)];
        let actions = service_action_descriptors(SVC_DNS, true, &units);

        let stop = actions
            .iter()
            .find(|action| action.id == "stop")
            .expect("stop action missing");
        assert_eq!(stop.href, "/system/services/dns/stop");
        assert_eq!(stop.variant, "danger");
        assert!(stop.requires_confirmation);
        assert!(stop.enabled);

        let disabled_actions = service_action_descriptors(SVC_DNS, false, &units);
        let start = disabled_actions
            .iter()
            .find(|action| action.id == "start")
            .expect("start action missing");
        assert!(!start.enabled);
        assert!(start.disabled_reason.is_some());
    }

    #[test]
    fn summarize_service_status_reports_degraded_multi_unit_services() {
        let units = vec![
            unit_status("kea-dhcp4-server.service", true, true),
            unit_status("kea-dhcp6-server.service", true, false),
        ];
        let (status, label) = summarize_service_status(
            true,
            &["kea-dhcp4-server.service", "kea-dhcp6-server.service"],
            &units,
        );

        assert_eq!(status, "degraded");
        assert_eq!(label, "1/2 configured units running");
    }

    #[test]
    fn summarize_service_status_distinguishes_disabled_and_missing() {
        let disabled = summarize_service_status(false, &[], &[]);
        assert_eq!(disabled.0, "notConfigured");

        let units = vec![unit_status("suricata.service", false, false)];
        let missing = summarize_service_status(true, &["suricata.service"], &units);
        assert_eq!(missing.0, "missing");
    }

    #[test]
    fn service_definitions_are_whitelisted() {
        assert_eq!(find_service_definition("DNS").unwrap().id, SVC_DNS);
        assert!(matches!(
            find_service_definition("anything-else"),
            Err(SystemApiError::NotFound(_))
        ));
    }

    #[test]
    fn rootfs_sensitive_operation_policy_requires_admin_identity() {
        let admin = AuthenticatedUser {
            username: "admin".to_string(),
        };
        let viewer = AuthenticatedUser {
            username: "viewer".to_string(),
        };

        assert!(authorize_sensitive_rootfs_operation("apply", &admin).is_ok());
        assert!(authorize_sensitive_rootfs_operation("apply", &viewer).is_err());
    }
}
