//! DHCP engine — manages the Kea DHCPv4 server.
//!
//! # Overview
//!
//! This module translates a [`DhcpConfig`] into a Kea DHCPv4 JSON configuration
//! and manages the kea-dhcp4-server process lifecycle (restart on config change).
//!
//! # Functions
//!
//! | Function            | Purpose                                              |
//! |---------------------|------------------------------------------------------|
//! | [`generate_config`] | Build a complete Kea DHCPv4 JSON config string.      |
//! | [`apply_config`]    | Write config to disk and restart kea-dhcp4-server.   |

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;
use tokio::process::Command;
use tracing::info;

use crate::config::models::DhcpConfig;

/// Path where the Kea DHCPv4 configuration file is written.
const KEA_CONF_PATH: &str = "/etc/kea/kea-dhcp4.conf";

/// Path to the Kea memfile lease database.
pub const KEA_LEASES_PATH: &str = "/var/lib/kea/kea-leases4.csv";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a complete Kea DHCPv4 JSON configuration as a `String`.
///
/// Each [`DhcpScope`] becomes a `subnet4` entry.  Static reservations use
/// `hw-address` + `ip-address` entries within the subnet.
pub fn generate_config(config: &DhcpConfig) -> String {
    let mut subnets = Vec::new();

    for (i, scope) in config.scopes.iter().enumerate() {
        let pool_str = format!("{}-{}", scope.pool_start, scope.pool_end);

        let mut option_data = Vec::new();
        if let Some(gw) = &scope.gateway {
            if !gw.is_empty() {
                option_data.push(json!({ "name": "routers", "data": gw }));
            }
        }
        if !scope.dns_servers.is_empty() {
            option_data.push(json!({
                "name": "domain-name-servers",
                "data": scope.dns_servers.join(", ")
            }));
        }
        if let Some(dn) = &scope.domain_name {
            if !dn.is_empty() {
                option_data.push(json!({ "name": "domain-name", "data": dn }));
                option_data.push(json!({ "name": "domain-search", "data": dn }));
            }
        }

        let reservations: Vec<_> = scope
            .reservations
            .iter()
            .map(|r| {
                let mut entry = json!({
                    "hw-address": r.mac_address,
                    "ip-address": r.ip_address,
                });
                if let Some(h) = &r.hostname {
                    entry["hostname"] = json!(h);
                }
                entry
            })
            .collect();

        subnets.push(json!({
            "id": (i as u32) + 1,
            "subnet": scope.subnet,
            "pools": [{ "pool": pool_str }],
            "valid-lifetime": scope.lease_seconds,
            "option-data": option_data,
            "reservations": reservations,
        }));
    }

    let interfaces = if config.interface.is_empty() {
        vec![]
    } else {
        vec![config.interface.clone()]
    };

    let kea_conf = json!({
        "Dhcp4": {
            "interfaces-config": {
                "interfaces": interfaces,
                "dhcp-socket-type": "raw"
            },
            "lease-database": {
                "type": "memfile",
                "persist": true,
                "name": KEA_LEASES_PATH,
                "lfc-interval": 3600
            },
            "expired-leases-processing": {
                "reclaim-timer-wait-time": 10,
                "hold-reclaimed-time": 3600,
                "flush-reclaimed-timer-wait-time": 25
            },
            "renew-timer": 900,
            "rebind-timer": 1800,
            "valid-lifetime": 86400,
            "subnet4": subnets,
            "loggers": [{
                "name": "kea-dhcp4",
                "output_options": [{
                    "output": "/var/log/kea/kea-dhcp4.log",
                    "maxsize": 1048576,
                    "maxver": 3
                }],
                "severity": "INFO",
                "debuglevel": 0
            }]
        }
    });

    serde_json::to_string_pretty(&kea_conf).unwrap_or_else(|_| "{}".to_string())
}

/// Apply the provided DHCP configuration to the running Kea DHCPv4 instance.
///
/// Steps:
/// 1. Generate `kea-dhcp4.conf` via [`generate_config`].
/// 2. Write the file atomically to [`KEA_CONF_PATH`].
/// 3. Restart `kea-dhcp4-server` via systemctl (Kea does not support SIGHUP).
///
/// # Errors
///
/// Returns an error if the config file cannot be written or if the
/// restart command fails.
pub async fn apply_config(config: &DhcpConfig) -> Result<()> {
    info!(
        enabled = config.enabled,
        scopes = config.scopes.len(),
        "dhcp: applying config"
    );

    if !config.enabled {
        info!("dhcp: service disabled — stopping kea-dhcp4-server");
        let _ = Command::new("systemctl")
            .args(["stop", "kea-dhcp4-server"])
            .output()
            .await;
        return Ok(());
    }

    std::fs::create_dir_all("/etc/kea").context("failed to create /etc/kea")?;
    std::fs::create_dir_all("/var/log/kea").context("failed to create /var/log/kea")?;

    let conf_str = generate_config(config);
    write_config_atomic(KEA_CONF_PATH, &conf_str)
        .context("failed to write kea-dhcp4.conf")?;

    info!(path = KEA_CONF_PATH, "dhcp: kea-dhcp4.conf written");

    restart_kea().await
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

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

/// Restart the kea-dhcp4-server service via systemctl.
async fn restart_kea() -> Result<()> {
    let out = Command::new("systemctl")
        .args(["restart", "kea-dhcp4-server"])
        .output()
        .await
        .context("failed to spawn systemctl")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("systemctl restart kea-dhcp4-server failed: {stderr}");
    }

    info!("dhcp: kea-dhcp4-server restarted");
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
            interface: "eth1".into(),
            scopes: vec![base_scope()],
        }
    }

    #[test]
    fn generate_config_contains_pool() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("192.168.1.100-192.168.1.200"));
    }

    #[test]
    fn generate_config_contains_subnet() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("192.168.1.0/24"));
    }

    #[test]
    fn generate_config_contains_router_option() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("routers"));
        assert!(out.contains("192.168.1.1"));
    }

    #[test]
    fn generate_config_contains_dns_option() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("domain-name-servers"));
        assert!(out.contains("1.1.1.1"));
    }

    #[test]
    fn generate_config_static_reservation_with_hostname() {
        let mut cfg = base_config();
        cfg.scopes[0].reservations.push(DhcpReservation {
            id: Uuid::new_v4(),
            hostname: Some("myhost".into()),
            mac_address: "aa:bb:cc:dd:ee:ff".into(),
            ip_address: "192.168.1.50".into(),
            description: String::new(),
        });
        let out = generate_config(&cfg);
        assert!(out.contains("aa:bb:cc:dd:ee:ff"));
        assert!(out.contains("192.168.1.50"));
        assert!(out.contains("myhost"));
    }

    #[test]
    fn generate_config_static_reservation_no_hostname() {
        let mut cfg = base_config();
        cfg.scopes[0].reservations.push(DhcpReservation {
            id: Uuid::new_v4(),
            hostname: None,
            mac_address: "11:22:33:44:55:66".into(),
            ip_address: "192.168.1.51".into(),
            description: String::new(),
        });
        let out = generate_config(&cfg);
        assert!(out.contains("11:22:33:44:55:66"));
        assert!(out.contains("192.168.1.51"));
    }

    #[test]
    fn generate_config_interface() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("eth1"));
    }

    #[test]
    fn generate_config_multiple_scopes() {
        let mut cfg = base_config();
        let mut s2 = base_scope();
        s2.subnet = "10.0.0.0/24".into();
        s2.pool_start = "10.0.0.50".into();
        s2.pool_end = "10.0.0.150".into();
        cfg.scopes.push(s2);
        let out = generate_config(&cfg);
        assert!(out.contains("192.168.1.100-192.168.1.200"));
        assert!(out.contains("10.0.0.50-10.0.0.150"));
    }

    #[test]
    fn generate_config_valid_lifetime() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("86400"));
    }
}

