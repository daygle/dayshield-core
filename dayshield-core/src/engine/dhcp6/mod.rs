//! DHCPv6 engine - manages the Kea DHCPv6 server.
//!
//! This module translates a [`Dhcp6Config`] into a Kea DHCPv6 JSON
//! configuration and manages kea-dhcp6-server lifecycle.

use std::{io::ErrorKind, path::Path};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};
use serde_json::json;
use tokio::process::Command;
use tracing::info;

use crate::config::models::Dhcp6Config;

/// Path where the Kea DHCPv6 configuration file is written.
const KEA6_CONF_PATH: &str = "/etc/dayshield/kea-dhcp6.conf";

/// Compatibility path expected by the distro kea-dhcp6-server unit.
const KEA6_SYSTEM_CONF_PATH: &str = "/etc/kea/kea-dhcp6.conf";

/// Path to the Kea DHCPv6 memfile lease database.
pub const KEA6_LEASES_PATH: &str = "/var/lib/kea/kea-leases6.csv";

/// Generate a complete Kea DHCPv6 JSON configuration as a `String`.
pub fn generate_config(config: &Dhcp6Config) -> String {
    let mut subnets = Vec::new();

    for (i, scope) in config.scopes.iter().enumerate() {
        let pool_str = format!("{}-{}", scope.pool_start, scope.pool_end);

        let mut option_data = Vec::new();
        if !scope.dns_servers.is_empty() {
            option_data.push(json!({
                "name": "dns-servers",
                "data": scope.dns_servers.join(", ")
            }));
        }
        if let Some(dn) = &scope.domain_name {
            if !dn.is_empty() {
                option_data.push(json!({ "name": "domain-search", "data": dn }));
            }
        }

        let reservations: Vec<serde_json::Value> = scope
            .reservations
            .iter()
            .map(|r| {
                let mut entry = json!({
                    "duid": r.duid,
                    "ip-addresses": [r.ip_address],
                });
                if let Some(hn) = &r.hostname {
                    if !hn.is_empty() {
                        entry["hostname"] = json!(hn);
                    }
                }
                entry
            })
            .collect();

        subnets.push(json!({
            "id": (i as u32) + 1,
            "subnet": scope.subnet,
            "pools": [{ "pool": pool_str }],
            "preferred-lifetime": scope.lease_seconds,
            "valid-lifetime": scope.lease_seconds,
            "renew-timer": scope.lease_seconds / 2,
            "rebind-timer": (scope.lease_seconds * 3) / 4,
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
        "Dhcp6": {
            "interfaces-config": {
                "interfaces": interfaces,
                "dhcp-socket-type": "raw"
            },
            "lease-database": {
                "type": "memfile",
                "persist": true,
                "name": KEA6_LEASES_PATH,
                "lfc-interval": 3600
            },
            "expired-leases-processing": {
                "reclaim-timer-wait-time": 10,
                "hold-reclaimed-time": 3600,
                "flush-reclaimed-timer-wait-time": 25
            },
            "subnet6": subnets,
            "loggers": [{
                "name": "kea-dhcp6",
                "output_options": [{
                    "output": "/var/log/kea/kea-dhcp6.log",
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

/// Apply the provided DHCPv6 configuration to the running Kea DHCPv6 instance.
pub async fn apply_config(config: &Dhcp6Config) -> Result<()> {
    info!(
        enabled = config.enabled,
        scopes = config.scopes.len(),
        "dhcp6: applying config"
    );

    if !config.enabled {
        info!("dhcp6: service disabled - stopping kea-dhcp6-server");
        let _ = Command::new("systemctl")
            .args(["disable", "--now", "kea-dhcp6-server"])
            .output()
            .await;
        remove_config_if_exists(KEA6_CONF_PATH)?;
        remove_config_if_exists(KEA6_SYSTEM_CONF_PATH)?;
        return Ok(());
    }

    std::fs::create_dir_all("/etc/kea").context("failed to create /etc/kea")?;
    #[cfg(unix)]
    std::fs::set_permissions("/etc/kea", std::fs::Permissions::from_mode(0o755))
        .context("failed to chmod /etc/kea")?;
    std::fs::create_dir_all("/var/log/kea").context("failed to create /var/log/kea")?;

    let conf_str = generate_config(config);
    write_config_atomic(KEA6_CONF_PATH, &conf_str)
        .context("failed to write kea-dhcp6.conf")?;
    #[cfg(unix)]
    std::fs::set_permissions(KEA6_CONF_PATH, std::fs::Permissions::from_mode(0o644))
        .context("failed to chmod kea-dhcp6.conf")?;

    write_config_atomic(KEA6_SYSTEM_CONF_PATH, &conf_str).context(
        "failed to mirror kea-dhcp6.conf to system path \
         (check dayshield.service sandbox: ReadWritePaths should include /etc/kea)",
    )?;
    #[cfg(unix)]
    std::fs::set_permissions(KEA6_SYSTEM_CONF_PATH, std::fs::Permissions::from_mode(0o644))
        .context("failed to chmod system kea-dhcp6.conf")?;

    info!(
        path = KEA6_CONF_PATH,
        system_path = KEA6_SYSTEM_CONF_PATH,
        "dhcp6: kea-dhcp6.conf written"
    );

    let enable_out = Command::new("systemctl")
        .args(["enable", "kea-dhcp6-server"])
        .output()
        .await
        .context("failed to enable kea-dhcp6-server")?;

    if !enable_out.status.success() {
        let stderr = String::from_utf8_lossy(&enable_out.stderr);
        anyhow::bail!("systemctl enable kea-dhcp6-server failed: {stderr}");
    }

    restart_kea6().await
}

fn write_config_atomic(path: &str, content: &str) -> Result<()> {
    let tmp = format!("{path}.tmp");

    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory for {path}"))?;
    }

    std::fs::write(&tmp, content).with_context(|| format!("write temp config {tmp}"))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename {tmp} -> {path}"))?;

    Ok(())
}

fn remove_config_if_exists(path: &str) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            info!(path, "dhcp6: removed stale kea-dhcp6.conf");
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove stale config {path}")),
    }
}

async fn restart_kea6() -> Result<()> {
    let out = Command::new("systemctl")
        .args(["restart", "kea-dhcp6-server"])
        .output()
        .await
        .context("failed to spawn systemctl restart kea-dhcp6-server")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("systemctl restart kea-dhcp6-server failed: {stderr}");
    }

    info!("dhcp6: kea-dhcp6-server restarted");
    Ok(())
}
