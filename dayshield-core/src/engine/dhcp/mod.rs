//! DHCP engine — manages the dnsmasq DHCP/DNS server.
//!
//! # Overview
//!
//! This module translates a [`DhcpConfig`] into a complete `dnsmasq.conf` and
//! manages the dnsmasq process lifecycle (reload on config change).
//!
//! # Functions
//!
//! | Function            | Purpose                                              |
//! |---------------------|------------------------------------------------------|
//! | [`generate_config`] | Build a complete `dnsmasq.conf` string.             |
//! | [`apply_config`]    | Write `dnsmasq.conf` to disk and reload dnsmasq.    |

use std::path::Path;

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::models::DhcpConfig;

/// Path where the dnsmasq configuration file is written.
const DNSMASQ_CONF_PATH: &str = "/etc/dnsmasq.conf";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a complete dnsmasq configuration file as a `String`.
///
/// The generated file covers:
/// - Per-scope `dhcp-range` directives.
/// - `dhcp-option` directives for default gateway, DNS servers, and domain.
/// - `dhcp-host` entries for all static reservations.
pub fn generate_config(config: &DhcpConfig) -> String {
    let mut out = String::new();

    out.push_str("# DayShield — dnsmasq configuration (auto-generated; do not edit by hand)\n\n");

    // Global options.
    out.push_str("# Provide DNS forwarding as well as DHCP.\n");
    out.push_str("domain-needed\n");
    out.push_str("bogus-priv\n");
    out.push_str("no-resolv\n");
    out.push_str("no-hosts\n\n");

    for scope in &config.scopes {
        // Scope comment.
        out.push_str(&format!("# Scope: {} ({})\n", scope.id, scope.subnet));

        // dhcp-range: <start>,<end>,<lease-time>
        let lease = format_lease(scope.lease_seconds);
        out.push_str(&format!(
            "dhcp-range={},{},{}\n",
            scope.pool_start, scope.pool_end, lease
        ));

        // dhcp-option: router (option 3)
        if let Some(gw) = &scope.gateway {
            out.push_str(&format!("dhcp-option=option:router,{gw}\n"));
        }

        // dhcp-option: dns-server (option 6)
        if !scope.dns_servers.is_empty() {
            out.push_str(&format!(
                "dhcp-option=option:dns-server,{}\n",
                scope.dns_servers.join(",")
            ));
        }

        // Static host reservations within this scope.
        for res in &scope.reservations {
            // dhcp-host=<mac>[,<hostname>],<ip>
            match &res.hostname {
                Some(h) => out.push_str(&format!(
                    "dhcp-host={},{},{}\n",
                    res.mac_address, h, res.ip_address
                )),
                None => out.push_str(&format!(
                    "dhcp-host={},{}\n",
                    res.mac_address, res.ip_address
                )),
            }
        }

        out.push('\n');
    }

    out
}

/// Apply the provided DHCP configuration to the running dnsmasq instance.
///
/// Steps:
/// 1. Generate `dnsmasq.conf` via [`generate_config`].
/// 2. Write the file atomically to [`DNSMASQ_CONF_PATH`].
/// 3. If dnsmasq is running, send it `SIGHUP` via `systemctl reload`; otherwise
///    attempt to start it with `systemctl start dnsmasq`.
///
/// # Errors
///
/// Returns an error if the config file cannot be written or if the
/// reload / start command fails.
pub async fn apply_config(config: &DhcpConfig) -> Result<()> {
    info!(
        enabled = config.enabled,
        scopes = config.scopes.len(),
        "dhcp: applying config"
    );

    if !config.enabled {
        info!("dhcp: service disabled — stopping dnsmasq");
        let _ = Command::new("systemctl")
            .args(["stop", "dnsmasq"])
            .output()
            .await;
        return Ok(());
    }

    let conf_str = generate_config(config);
    write_config_atomic(DNSMASQ_CONF_PATH, &conf_str)
        .context("failed to write dnsmasq.conf")?;

    info!(path = DNSMASQ_CONF_PATH, "dhcp: dnsmasq.conf written");

    // Try a live reload first; fall back to a full service start.
    let reload = Command::new("systemctl")
        .args(["reload", "dnsmasq"])
        .output()
        .await;

    match reload {
        Ok(out) if out.status.success() => {
            info!("dhcp: dnsmasq reloaded via systemctl");
        }
        Ok(out) => {
            warn!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "dhcp: systemctl reload dnsmasq failed; attempting systemctl start"
            );
            start_dnsmasq().await?;
        }
        Err(e) => {
            warn!(error = %e, "dhcp: systemctl not available; attempting start");
            start_dnsmasq().await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Format a lease duration (in seconds) as a dnsmasq lease-time string.
///
/// dnsmasq accepts `<n>s`, `<n>m`, `<n>h`, or `infinite`.
fn format_lease(seconds: u32) -> String {
    if seconds == 0 {
        return "infinite".into();
    }
    if seconds % 3600 == 0 {
        return format!("{}h", seconds / 3600);
    }
    if seconds % 60 == 0 {
        return format!("{}m", seconds / 60);
    }
    format!("{seconds}s")
}

/// Write `content` to `path` using an atomic rename.
fn write_config_atomic(path: &str, content: &str) -> Result<()> {
    let tmp = format!("{path}.tmp");

    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    std::fs::write(&tmp, content)
        .with_context(|| format!("failed to write temporary file {tmp}"))?;

    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {tmp} to {path}"))?;

    Ok(())
}

/// Start the dnsmasq service via systemctl.
async fn start_dnsmasq() -> Result<()> {
    let out = Command::new("systemctl")
        .args(["start", "dnsmasq"])
        .output()
        .await
        .context("failed to spawn systemctl")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("systemctl start dnsmasq failed: {stderr}");
    }

    info!("dhcp: dnsmasq started via systemctl");
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{DhcpReservation, DhcpScope};
    use uuid::Uuid;

    fn base_scope() -> DhcpScope {
        DhcpScope {
            id: Uuid::new_v4(),
            subnet: "192.168.1.0/24".into(),
            pool_start: "192.168.1.100".into(),
            pool_end: "192.168.1.200".into(),
            gateway: Some("192.168.1.1".into()),
            dns_servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            lease_seconds: 86400,
            reservations: vec![],
        }
    }

    fn base_config() -> DhcpConfig {
        DhcpConfig {
            enabled: true,
            scopes: vec![base_scope()],
        }
    }

    #[test]
    fn generate_config_contains_dhcp_range() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("dhcp-range=192.168.1.100,192.168.1.200,24h"));
    }

    #[test]
    fn generate_config_contains_router_option() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("dhcp-option=option:router,192.168.1.1"));
    }

    #[test]
    fn generate_config_contains_dns_option() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("dhcp-option=option:dns-server,1.1.1.1,8.8.8.8"));
    }

    #[test]
    fn generate_config_static_reservation_with_hostname() {
        let mut cfg = base_config();
        cfg.scopes[0].reservations.push(DhcpReservation {
            id: Uuid::new_v4(),
            hostname: Some("myhost".into()),
            mac_address: "aa:bb:cc:dd:ee:ff".into(),
            ip_address: "192.168.1.50".into(),
        });
        let out = generate_config(&cfg);
        assert!(out.contains("dhcp-host=aa:bb:cc:dd:ee:ff,myhost,192.168.1.50"));
    }

    #[test]
    fn generate_config_static_reservation_no_hostname() {
        let mut cfg = base_config();
        cfg.scopes[0].reservations.push(DhcpReservation {
            id: Uuid::new_v4(),
            hostname: None,
            mac_address: "11:22:33:44:55:66".into(),
            ip_address: "192.168.1.51".into(),
        });
        let out = generate_config(&cfg);
        assert!(out.contains("dhcp-host=11:22:33:44:55:66,192.168.1.51"));
    }

    #[test]
    fn format_lease_hours() {
        assert_eq!(format_lease(86400), "24h");
        assert_eq!(format_lease(3600), "1h");
    }

    #[test]
    fn format_lease_minutes() {
        assert_eq!(format_lease(600), "10m");
    }

    #[test]
    fn format_lease_seconds() {
        assert_eq!(format_lease(90), "90s");
    }

    #[test]
    fn format_lease_infinite() {
        assert_eq!(format_lease(0), "infinite");
    }

    #[test]
    fn generate_config_multiple_scopes() {
        let mut cfg = base_config();
        let mut s2 = base_scope();
        s2.pool_start = "10.0.0.50".into();
        s2.pool_end = "10.0.0.150".into();
        cfg.scopes.push(s2);
        let out = generate_config(&cfg);
        assert!(out.contains("dhcp-range=192.168.1.100,192.168.1.200"));
        assert!(out.contains("dhcp-range=10.0.0.50,10.0.0.150"));
    }
}

