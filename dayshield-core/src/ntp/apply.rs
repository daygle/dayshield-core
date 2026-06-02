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
//!
//! # Serving NTP to LAN clients
//!
//! chrony cannot bind its server socket to more than one named device, so the
//! set of interfaces a client may reach is controlled with source-subnet
//! `allow` rules instead. For every selected interface DayShield resolves the
//! live IP networks (via [`crate::engine::interfaces`]) and emits one
//! `allow <network>` line each. chrony denies all clients by default, so this
//! serves time only to the selected LAN subnets and never to the WAN.

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
        return apply_chrony(cfg, chrony_unit, true).await;
    }

    if has_timesyncd_unit() {
        apply_timesyncd(cfg).await
    } else if let Some(chrony_unit) = detect_chrony_unit() {
        // Some images intentionally install chrony as the only time daemon.
        // In that case, run chrony in client-only mode for upstream sync.
        apply_chrony(cfg, chrony_unit, false).await
    } else {
        Err(NtpError::ServiceCommand {
            service: "ntp".into(),
            message: "no supported NTP daemon installed (expected systemd-timesyncd or chrony)"
                .into(),
        })
    }
}

// ---------------------------------------------------------------------------
// systemd-timesyncd path
// ---------------------------------------------------------------------------

const TIMESYNCD_CONF: &str = "/etc/systemd/timesyncd.conf";

/// Render the contents of `/etc/systemd/timesyncd.conf` for `cfg`.
fn render_timesyncd_conf(cfg: &NtpConfig) -> String {
    let servers = cfg.upstream_servers.join(" ");
    format!(
        "# Managed by DayShield - do not edit manually\n\
         [Time]\n\
         NTP={servers}\n\
         FallbackNTP=\n"
    )
}

async fn apply_timesyncd(cfg: &NtpConfig) -> Result<(), NtpError> {
    let content = render_timesyncd_conf(cfg);

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

/// Render the contents of `/etc/chrony/chrony.conf`.
///
/// When `serve_clients` is `true`, one `allow <subnet>` line is emitted for
/// each entry in `allow_subnets`, restricting served clients to those source
/// networks. When `serve_clients` is `false` (or no subnets could be
/// resolved), chrony runs client-only with the server port disabled.
fn render_chrony_conf(cfg: &NtpConfig, serve_clients: bool, allow_subnets: &[String]) -> String {
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

    if serve_clients && !allow_subnets.is_empty() {
        // chrony denies all clients by default; only the listed source subnets
        // (derived from the selected LAN interfaces) are served. The WAN is
        // never included, so no `allow 0/0` is ever written.
        lines.push("# Serve NTP only to the selected LAN subnets".into());
        for subnet in allow_subnets {
            lines.push(format!("allow {subnet}"));
        }
        lines.push(String::new());
    } else {
        lines.push("# Client-only mode (do not serve NTP to network clients)".into());
        lines.push("port 0".into());
        lines.push(String::new());
    }
    lines.push("# Logging".into());
    lines.push("logdir /var/log/chrony".into());

    lines.join("\n") + "\n"
}

/// Compute the chrony `allow` network for a CIDR address from the kernel.
///
/// Masks the host bits so that `192.168.1.10/24` becomes `192.168.1.0/24`.
/// Returns `None` for malformed input.
fn chrony_allow_subnet(cidr: &str) -> Option<String> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    let prefix: u8 = prefix_str.parse().ok()?;
    match addr_str.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => {
            if prefix > 32 {
                return None;
            }
            let bits = u32::from(v4);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Some(format!("{}/{}", std::net::Ipv4Addr::from(bits & mask), prefix))
        }
        std::net::IpAddr::V6(v6) => {
            if prefix > 128 {
                return None;
            }
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            Some(format!("{}/{}", std::net::Ipv6Addr::from(bits & mask), prefix))
        }
    }
}

/// Resolve the live IP networks behind a set of interface names so chrony can
/// be told exactly which LAN subnets to serve.
async fn resolve_listen_subnets(interfaces: &[String]) -> Vec<String> {
    let kernel = match crate::engine::interfaces::list_kernel_interfaces().await {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "NTP: failed to query interface addresses for chrony allow rules");
            return Vec::new();
        }
    };

    let mut subnets: Vec<String> = Vec::new();
    for name in interfaces {
        let Some(iface) = kernel.iter().find(|k| &k.name == name) else {
            warn!(interface = %name, "NTP: selected interface not found in kernel; skipping");
            continue;
        };
        for cidr in &iface.addresses {
            if let Some(subnet) = chrony_allow_subnet(cidr) {
                if !subnets.contains(&subnet) {
                    subnets.push(subnet);
                }
            }
        }
    }
    subnets
}

async fn apply_chrony(
    cfg: &NtpConfig,
    chrony_unit: &'static str,
    serve_clients: bool,
) -> Result<(), NtpError> {
    let allow_subnets = if serve_clients {
        let subnets = resolve_listen_subnets(&cfg.listen_interfaces).await;
        if subnets.is_empty() {
            warn!(
                "NTP: serve_clients requested but no LAN subnets could be resolved \
                 from the selected interfaces; chrony will run client-only"
            );
        }
        subnets
    } else {
        Vec::new()
    };

    let content = render_chrony_conf(cfg, serve_clients, &allow_subnets);

    info!(path = CHRONY_CONF, "Writing chrony config");
    // Ensure the parent directory exists.
    if let Some(parent) = std::path::Path::new(CHRONY_CONF).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(CHRONY_CONF, content).await.map_err(|e| {
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
    const UNIT_DIRS: [&str; 3] = [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ];

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

fn has_timesyncd_unit() -> bool {
    const UNIT_DIRS: [&str; 3] = [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ];
    for dir in UNIT_DIRS {
        if Path::new(dir).join("systemd-timesyncd.service").exists() {
            return true;
        }
    }
    false
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
        let content = render_timesyncd_conf(&cfg);
        assert!(content.contains("NTP=0.pool.ntp.org 1.pool.ntp.org"));
        assert!(content.contains("FallbackNTP="));
    }

    #[test]
    fn chrony_conf_contains_servers_and_allow_subnets() {
        let cfg = NtpConfig {
            enabled: true,
            upstream_servers: vec!["192.0.2.1".into()],
            serve_clients: true,
            listen_interfaces: vec!["eth1".into(), "eth2".into()],
        };
        // Two interfaces -> two distinct allow lines (the old single-binddevice
        // behaviour silently dropped all but the last interface).
        let content = render_chrony_conf(
            &cfg,
            true,
            &["192.168.1.0/24".into(), "10.0.0.0/8".into()],
        );
        assert!(content.contains("server 192.0.2.1 iburst"));
        assert!(content.contains("allow 192.168.1.0/24"));
        assert!(content.contains("allow 10.0.0.0/8"));
        // The WAN-exposing wildcard must never be emitted.
        assert!(!content.contains("allow 0/0"));
        assert!(!content.contains("binddevice"));
    }

    #[test]
    fn chrony_conf_client_only_when_no_subnets() {
        let cfg = NtpConfig {
            enabled: true,
            upstream_servers: vec!["192.0.2.1".into()],
            serve_clients: true,
            listen_interfaces: vec!["eth1".into()],
        };
        // serve_clients requested but no resolvable subnets -> fail safe to
        // client-only rather than opening the server to everyone.
        let content = render_chrony_conf(&cfg, true, &[]);
        assert!(content.contains("port 0"));
        assert!(!content.contains("allow"));
    }

    #[test]
    fn chrony_conf_client_only_mode() {
        let cfg = NtpConfig {
            enabled: true,
            upstream_servers: vec!["192.0.2.1".into()],
            serve_clients: false,
            listen_interfaces: vec![],
        };
        let content = render_chrony_conf(&cfg, false, &[]);
        assert!(content.contains("port 0"));
        assert!(!content.contains("allow"));
    }

    #[test]
    fn allow_subnet_masks_host_bits() {
        assert_eq!(
            chrony_allow_subnet("192.168.1.10/24").as_deref(),
            Some("192.168.1.0/24")
        );
        assert_eq!(
            chrony_allow_subnet("10.20.30.40/8").as_deref(),
            Some("10.0.0.0/8")
        );
        assert_eq!(
            chrony_allow_subnet("2001:db8:abcd:1::5/64").as_deref(),
            Some("2001:db8:abcd:1::/64")
        );
    }

    #[test]
    fn allow_subnet_rejects_malformed() {
        assert_eq!(chrony_allow_subnet("not-a-cidr"), None);
        assert_eq!(chrony_allow_subnet("192.168.1.0"), None);
        assert_eq!(chrony_allow_subnet("192.168.1.0/33"), None);
        assert_eq!(chrony_allow_subnet("2001:db8::/129"), None);
    }
}
