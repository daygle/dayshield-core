//! Dashboard summary endpoints.
//!
//! - `GET /dashboard/system`   - host resource usage (CPU, RAM, disk, uptime)
//! - `GET /dashboard/network`  - WAN/LAN interface overview
//! - `GET /dashboard/security` - recent Suricata alerts, CrowdSec decisions, firewall stats
//! - `GET /dashboard/acme`     - ACME certificate expiry summary

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, response::IntoResponse, Json};
use serde::Serialize;
use tracing::warn;

use crate::state::AppState;
use crate::engine::acme::AcmeEngine;
use crate::engine::interfaces::list_kernel_interfaces;

// ---------------------------------------------------------------------------
// GET /dashboard/system
// ---------------------------------------------------------------------------

/// Response for `GET /dashboard/system`.
#[derive(Serialize)]
pub struct DashboardSystemStatus {
    pub hostname: String,
    /// System uptime in seconds.
    pub uptime: u64,
    /// 1-minute, 5-minute, 15-minute load averages.
    pub loadavg: [f64; 3],
    /// CPU utilisation as a percentage (0–100).
    pub cpu_percent: f64,
    /// RAM utilisation as a percentage (0–100).
    pub ram_percent: f64,
    /// Root filesystem utilisation as a percentage (0–100).
    pub disk_percent: f64,
    /// CPU temperature in Celsius (`None` when unavailable).
    pub temperature: Option<f64>,
}

pub async fn get_system_status(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Pull the latest snapshot from the metrics buffer (non-blocking read).
    let snapshot = {
        let buf = state.metrics_buffer.read().await;
        buf.latest().cloned()
    };

    let (cpu_percent, ram_percent, loadavg, uptime, temperature) = match snapshot {
        Some(s) => (
            s.system.cpu_percent,
            s.system.ram_percent,
            [s.system.loadavg_1, s.system.loadavg_5, s.system.loadavg_15],
            s.system.uptime_seconds,
            if s.system.temperature_c > 0.0 {
                Some(s.system.temperature_c)
            } else {
                None
            },
        ),
        None => (0.0, 0.0, [0.0, 0.0, 0.0], 0, None),
    };

    let disk_percent = read_disk_percent("/").await;

    let hostname = state
        .config_store
        .load_system_settings()
        .map(|s| s.hostname)
        .unwrap_or_else(|_| "dayshield".into());

    Json(DashboardSystemStatus {
        hostname,
        uptime,
        loadavg,
        cpu_percent,
        ram_percent,
        disk_percent,
        temperature,
    })
}

/// Read root-filesystem usage percentage by calling `df -B1 <mount>`.
async fn read_disk_percent(mount: &str) -> f64 {
    // `df -B1 <path>` output line 2: Filesystem 1B-blocks Used Available Use% Mounted
    let output = tokio::process::Command::new("df")
        .args(["-B1", mount])
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            // Skip header line, parse second line.
            if let Some(line) = text.lines().nth(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Use% is at index 4 (e.g. "42%"), or compute from blocks.
                if parts.len() >= 5 {
                    return parts[4]
                        .trim_end_matches('%')
                        .parse::<f64>()
                        .unwrap_or(0.0);
                }
            }
            0.0
        }
        _ => 0.0,
    }
}

// ---------------------------------------------------------------------------
// GET /dashboard/network
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct LanIface {
    pub name: String,
    pub description: Option<String>,
    pub ip: Option<String>,
    pub ipv6: Option<String>,
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct NetworkStatus {
    pub wan_iface: String,
    pub wan_iface_description: Option<String>,
    pub wan_ip: Option<String>,
    pub wan_ipv6: Option<String>,
    /// `"up"`, `"down"`, or `"unknown"`
    pub gateway_status: &'static str,
    /// WAN receive throughput in bytes/second (from last metrics snapshot).
    pub wan_rx_bps: f64,
    /// WAN transmit throughput in bytes/second.
    pub wan_tx_bps: f64,
    pub lan_ifaces: Vec<LanIface>,
}

pub async fn get_network_status(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Gather configured interfaces.
    let configured = state.interfaces.read().await.clone();

    // Gather latest network throughput from metrics.
    let net_metrics = {
        let buf = state.metrics_buffer.read().await;
        buf.latest().map(|s| s.network.clone()).unwrap_or_default()
    };

    // Determine the WAN uplink using explicit WAN configuration when available.
    let wan = configured
        .iter()
        .find(|i| i.wan_mode.is_some() || i.gateway.is_some())
        .or_else(|| configured.iter().find(|i| i.enabled));
    let wan_name = wan.map(|i| i.name.clone()).unwrap_or_else(|| "eth0".into());
    let wan_description = wan.and_then(|i| i.description.clone());

    // Resolve live kernel addresses (needed for DHCP interfaces whose config
    // addresses vec is intentionally empty).
    let kernel_ifaces = list_kernel_interfaces().await.unwrap_or_default();
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map(|settings| settings.ipv6_enabled)
        .unwrap_or(false);
    let kernel_ip_for = |name: &str, ipv6: bool| -> Option<String> {
        kernel_ifaces
            .iter()
            .find(|ki| ki.name == name)
            .and_then(|ki| {
                ki.addresses.iter().find(|a| {
                    if ipv6 {
                        a.contains(':')
                    } else {
                        a.contains('.')
                    }
                })
            })
            // Strip the CIDR prefix length (e.g. "192.168.1.1/24" → "192.168.1.1").
            .map(|cidr| cidr.split('/').next().unwrap_or(cidr).to_string())
    };
    let wan_ip = wan
        .and_then(|i| i.addresses.iter().find(|cidr| cidr.contains('.')))
        .map(|cidr| cidr.split('/').next().unwrap_or(cidr).to_string())
        .or_else(|| kernel_ip_for(&wan_name, false));
    let wan_ipv6 = if ipv6_enabled {
        wan.and_then(|i| i.addresses.iter().find(|cidr| cidr.contains(':')))
            .map(|cidr| cidr.split('/').next().unwrap_or(cidr).to_string())
            .or_else(|| kernel_ip_for(&wan_name, true))
    } else {
        None
    };

    let wan_metrics = net_metrics.iter().find(|m| m.name == wan_name);
    let wan_rx_bps = wan_metrics.map(|m| m.rx_bps as f64).unwrap_or(0.0);
    let wan_tx_bps = wan_metrics.map(|m| m.tx_bps as f64).unwrap_or(0.0);

    // Gateway reachability: try to read the default route from /proc/net/route.
    let gateway_status = gateway_reachable().await;

    let lan_ifaces = configured
        .iter()
        .filter(|i| i.name != wan_name)
        .map(|i| LanIface {
            name: i.name.clone(),
            description: i.description.clone(),
            ip: i.addresses.iter().find(|cidr| cidr.contains('.'))
                .map(|cidr| cidr.split('/').next().unwrap_or(cidr).to_string())
                .or_else(|| kernel_ip_for(&i.name, false)),
            ipv6: if ipv6_enabled {
                i.addresses.iter().find(|cidr| cidr.contains(':'))
                    .map(|cidr| cidr.split('/').next().unwrap_or(cidr).to_string())
                    .or_else(|| kernel_ip_for(&i.name, true))
            } else {
                None
            },
            enabled: i.enabled,
        })
        .collect();

    Json(NetworkStatus {
        wan_iface: wan_name,
        wan_iface_description: wan_description,
        wan_ip,
        wan_ipv6,
        gateway_status,
        wan_rx_bps,
        wan_tx_bps,
        lan_ifaces,
    })
}

/// Returns `"up"` when a default route exists in `/proc/net/route`, else `"down"`.
async fn gateway_reachable() -> &'static str {
    match tokio::fs::read_to_string("/proc/net/route").await {
        Ok(content) => {
            // Each line after the header: Iface Destination Gateway ...
            // A destination of 00000000 is the default route.
            let has_default = content
                .lines()
                .skip(1)
                .any(|line| {
                    let mut cols = line.split_whitespace();
                    cols.next(); // iface
                    cols.next().map(|dest| dest == "00000000").unwrap_or(false)
                });
            if has_default { "up" } else { "down" }
        }
        Err(_) => "unknown",
    }
}

// ---------------------------------------------------------------------------
// GET /dashboard/security
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SecurityStatus {
    pub firewall_rule_count: usize,
    pub firewall_state_count: u64,
    pub suricata_alert_rate: f64,
    pub crowdsec_active_decisions: usize,
}

pub async fn get_security_status(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let firewall_rule_count = state.firewall_rules.read().await.len();
    let crowdsec_active_decisions = state.crowdsec_decisions.read().await.len();

    let (firewall_state_count, suricata_alert_rate) = {
        let buf = state.metrics_buffer.read().await;
        let snap = buf.latest();
        (
            snap.map(|s| s.firewall.state_count).unwrap_or(0),
            snap.map(|s| s.suricata.alerts_last_minute as f64 / 60.0).unwrap_or(0.0),
        )
    };

    Json(SecurityStatus {
        firewall_rule_count,
        firewall_state_count,
        suricata_alert_rate,
        crowdsec_active_decisions,
    })
}

// ---------------------------------------------------------------------------
// GET /dashboard/acme
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct AcmeStatus {
    pub domains: Vec<String>,
    pub cert_exists: bool,
    pub needs_renewal: bool,
    /// Days until primary certificate expires; `0` when no cert exists.
    pub expires_in_days: i64,
    pub next_renewal: Option<String>,
}

pub async fn get_acme_status(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let acme_cfg = state
        .config_store
        .load_acme_config()
        .ok()
        .flatten();

    let (domains, cert_exists, needs_renewal, expires_in_days, next_renewal) = match acme_cfg {
        Some(cfg) if cfg.enabled => {
            let domains = cfg.domains.clone();
            let primary = domains.first().cloned();
            let engine = AcmeEngine::new(cfg.clone());

            let (cert_exists, needs_renewal, expires_in_days) = if let Some(primary_domain) = &primary {
                let cert_path = engine.cert_path(primary_domain);
                let exists = cert_path.exists();
                let renewal_check = engine.renewal_check().await.unwrap_or(true);
                let days = if exists {
                    cert_expiry_days(cert_path.to_str().unwrap_or_default()).await.unwrap_or(0)
                } else {
                    0
                };
                (exists, !exists || renewal_check, days)
            } else {
                (false, false, 0)
            };

            let next = cfg
                .domains
                .first()
                .map(|_| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let next_secs = now + cfg.renew_interval_hours * 3600;
                    chrono::DateTime::from_timestamp(next_secs as i64, 0)
                        .map(|dt| dt.to_rfc3339())
                })
                .flatten();

            (domains, cert_exists, needs_renewal, expires_in_days, next)
        }
        _ => (vec![], false, false, 0, None),
    };

    Json(AcmeStatus {
        domains,
        cert_exists,
        needs_renewal,
        expires_in_days,
        next_renewal,
    })
}

/// Read the expiry of a PEM certificate file and return days remaining.
async fn cert_expiry_days(path: &str) -> Option<i64> {
    let output = tokio::process::Command::new("openssl")
        .args(["x509", "-noout", "-enddate", "-in", path])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // Output: "notAfter=May 28 12:00:00 2026 GMT"
    let text = String::from_utf8_lossy(&output.stdout);
    let date_str = text.trim().strip_prefix("notAfter=")?;

    // Parse with chrono; openssl uses a non-ISO format.
    let dt = chrono::DateTime::parse_from_str(
        &format!("{date_str} +0000"),
        "%b %e %H:%M:%S %Y %Z %z",
    )
    .ok()?;

    let now = chrono::Utc::now();
    Some(dt.signed_duration_since(now).num_days())
}
