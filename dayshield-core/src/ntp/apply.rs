//! NTP engine - write daemon config files and restart system services.
//!
//! # Service strategy
//!
//! | `serve_clients` | NTP daemon used      | Config file written                    |
//! |-----------------|----------------------|----------------------------------------|
//! | `false`         | `systemd-timesyncd`  | `/etc/systemd/timesyncd.conf`          |
//! | `true`          | `chrony`             | `/etc/chrony/chrony.conf`              |
//!
//! When `enabled` is `false`, both daemons are stopped and their config files
//! are left untouched (only the service unit is stopped).

use std::path::Path;

use tokio::process::Command;
use tracing::{info, warn};

use crate::ntp::model::NtpConfig;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur while applying an NTP configuration.
#[derive(Debug, thiserror::Error)]
pub enum NtpError {
    /// A file system operation failed.
    #[error("I/O error writing NTP config: {0}")]
    Io(#[from] std::io::Error),

    /// A `systemctl` or `chronyc` invocation returned a non-zero exit code.
    #[error("service command failed ({service}): {message}")]
    ServiceCommand { service: String, message: String },
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply an [`NtpConfig`] to the running system.
///
/// Steps performed:
/// 1. If `cfg.enabled` is `false`, stop the relevant daemon(s) and return.
/// 2. Choose the daemon based on `cfg.serve_clients`.
/// 3. Write the daemon's configuration file.
/// 4. Enable and restart the daemon via `systemctl`.
pub async fn apply_ntp_config(cfg: &NtpConfig) -> Result<(), NtpError> {
    if !cfg.enabled {
        info!("NTP disabled - stopping daemons");
        stop_service("systemd-timesyncd").await;
        stop_chrony_services().await;
        return Ok(());
    }

    if cfg.serve_clients {
        let chrony_unit = detect_chrony_unit().ok_or_else(|| NtpError::ServiceCommand {
            service: "chrony".into(),
            message:
                "serve_clients requires chrony to be installed (missing chrony.service/chronyd.service)"
                    .into(),
        })?;
        apply_chrony(cfg, chrony_unit).await
    } else {
        apply_timesyncd(cfg).await
    }
}

// ---------------------------------------------------------------------------
// systemd-timesyncd path
// ---------------------------------------------------------------------------

const TIMESYNCD_CONF: &str = "/etc/systemd/timesyncd.conf";

async fn apply_timesyncd(cfg: &NtpConfig) -> Result<(), NtpError> {
    let servers = cfg.upstream_servers.join(" ");
    let content = format!(
        "# Managed by DayShield - do not edit manually\n\
         [Time]\n\
         NTP={servers}\n\
         FallbackNTP=\n"
    );

    info!(path = TIMESYNCD_CONF, "Writing systemd-timesyncd config");
    tokio::fs::write(TIMESYNCD_CONF, content)
        .await
        .map_err(|e| {
            NtpError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "{} (check dayshield.service ReadWritePaths for /etc/systemd)",
                    e
                ),
            ))
        })?;

    // Stop chrony if it was previously running.
    stop_chrony_services().await;

    restart_service("systemd-timesyncd").await?;
    info!("systemd-timesyncd restarted");
    Ok(())
}

// ---------------------------------------------------------------------------
// chrony path
// ---------------------------------------------------------------------------

const CHRONY_CONF: &str = "/etc/chrony/chrony.conf";

async fn apply_chrony(cfg: &NtpConfig, chrony_unit: &'static str) -> Result<(), NtpError> {
    let mut lines: Vec<String> = vec![
        "# Managed by DayShield - do not edit manually".into(),
        String::new(),
        "# Upstream servers".into(),
    ];

    for server in &cfg.upstream_servers {
        lines.push(format!("server {server} iburst"));
    }

    lines.push(String::new());
    lines.push("# Clock management".into());
    lines.push("driftfile /var/lib/chrony/drift".into());
    lines.push("makestep 1 3".into());
    lines.push("rtcsync".into());
    lines.push(String::new());

    if !cfg.listen_interfaces.is_empty() {
        lines.push("# Listen interfaces for LAN clients".into());
        for iface in &cfg.listen_interfaces {
            lines.push(format!("binddevice {iface}"));
        }
        lines.push(String::new());
    }

    lines.push("# Allow NTP queries from all LAN clients".into());
    lines.push("allow 0/0".into());
    lines.push(String::new());
    lines.push("# Logging".into());
    lines.push("logdir /var/log/chrony".into());

    let content = lines.join("\n") + "\n";

    info!(path = CHRONY_CONF, "Writing chrony config");
    // Ensure the parent directory exists.
    if let Some(parent) = std::path::Path::new(CHRONY_CONF).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(CHRONY_CONF, content)
        .await
        .map_err(|e| {
            NtpError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "{} (check dayshield.service ReadWritePaths for /etc/chrony)",
                    e
                ),
            ))
        })?;

    // Stop timesyncd if it was previously running.
    stop_service("systemd-timesyncd").await;

    restart_service(chrony_unit).await?;
    info!(unit = chrony_unit, "chrony restarted");
    Ok(())
}

fn detect_chrony_unit() -> Option<&'static str> {
    const CANDIDATES: [&str; 2] = ["chrony", "chronyd"];
    const UNIT_DIRS: [&str; 3] = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"];

    for unit in CANDIDATES {
        let service_name = format!("{unit}.service");
        for dir in UNIT_DIRS {
            if Path::new(dir).join(&service_name).exists() {
                return Some(unit);
            }
        }
    }
    None
}

async fn stop_chrony_services() {
    stop_service("chrony").await;
    stop_service("chronyd").await;
}

// ---------------------------------------------------------------------------
// systemctl helpers
// ---------------------------------------------------------------------------

/// Attempt to stop a service unit, logging a warning on failure.
async fn stop_service(unit: &str) {
    let status = Command::new("systemctl")
        .args(["stop", unit])
        .status()
        .await;
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => warn!(unit, exit_code = ?s.code(), "systemctl stop returned non-zero"),
        Err(e) => warn!(unit, error = %e, "Failed to invoke systemctl stop"),
    }
}

/// Enable and restart a service unit, returning an error on failure.
async fn restart_service(unit: &str) -> Result<(), NtpError> {
    // Enable
    let enable = Command::new("systemctl")
        .args(["enable", unit])
        .output()
        .await?;
    if !enable.status.success() {
        let msg = String::from_utf8_lossy(&enable.stderr).into_owned();
        return Err(NtpError::ServiceCommand {
            service: unit.into(),
            message: format!("enable failed: {msg}"),
        });
    }

    // Restart
    let restart = Command::new("systemctl")
        .args(["restart", unit])
        .output()
        .await?;
    if !restart.status.success() {
        let msg = String::from_utf8_lossy(&restart.stderr).into_owned();
        return Err(NtpError::ServiceCommand {
            service: unit.into(),
            message: format!("restart failed: {msg}"),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timesyncd_conf_format() {
        let cfg = NtpConfig {
            enabled: true,
            upstream_servers: vec!["0.pool.ntp.org".into(), "1.pool.ntp.org".into()],
            serve_clients: false,
            listen_interfaces: vec![],
        };
        let servers = cfg.upstream_servers.join(" ");
        let content = format!(
            "# Managed by DayShield - do not edit manually\n\
             [Time]\n\
             NTP={servers}\n\
             FallbackNTP=\n"
        );
        assert!(content.contains("NTP=0.pool.ntp.org 1.pool.ntp.org"));
    }

    #[test]
    fn chrony_conf_contains_servers() {
        let cfg = NtpConfig {
            enabled: true,
            upstream_servers: vec!["192.0.2.1".into()],
            serve_clients: true,
            listen_interfaces: vec!["eth1".into()],
        };
        let mut lines: Vec<String> = vec!["# header".into()];
        for s in &cfg.upstream_servers {
            lines.push(format!("server {s} iburst"));
        }
        for iface in &cfg.listen_interfaces {
            lines.push(format!("binddevice {iface}"));
        }
        let content = lines.join("\n");
        assert!(content.contains("server 192.0.2.1 iburst"));
        assert!(content.contains("binddevice eth1"));
    }
}
