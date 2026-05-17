//! Router Advertisement daemon (radvd) configuration manager.
//!
//! # Overview
//!
//! This module generates `/etc/radvd.conf` from the set of LAN interfaces
//! that have been assigned a prefix via DHCPv6-PD tracking, and manages the
//! `radvd` process lifecycle.
//!
//! When LAN hosts connect to a DayShield-managed segment, radvd broadcasts
//! Router Advertisement (RA) messages that carry the delegated /64 prefix.
//! Hosts use SLAAC to auto-configure their own global IPv6 addresses from
//! that advertisement.
//!
//! # radvd.conf format
//!
//! ```text
//! interface eth1 {
//!     AdvSendAdvert on;
//!     AdvManagedFlag off;
//!     AdvOtherConfigFlag off;
//!     MinRtrAdvInterval 3;
//!     MaxRtrAdvInterval 10;
//!
//!     prefix 2001:db8:0:3::/64 {
//!         AdvOnLink on;
//!         AdvAutonomous on;
//!         AdvRouterAddr on;
//!         AdvPreferredLifetime 3600;
//!         AdvValidLifetime 7200;
//!     };
//! };
//! ```

use std::net::Ipv6Addr;

use tokio::process::Command;
use tracing::{debug, info, warn};

const RADVD_CONF_PATH: &str = "/etc/radvd.conf";
const RADVD_PID_PATH: &str = "/run/radvd.pid";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A prefix assignment for a LAN interface to be advertised via RA.
pub struct PrefixAssignment {
    /// OS interface name, e.g. `"eth1"`.
    pub iface: String,
    /// Assigned address CIDR on that interface, e.g. `"2001:db8:0:3::1/64"`.
    /// The host bits will be stripped when building the RA prefix block.
    pub prefix: String,
    /// `AdvManagedFlag` — set `true` for interfaces running a DHCPv6 server so
    /// hosts request addresses via DHCPv6 rather than configuring via SLAAC.
    pub managed: bool,
    /// `AdvOtherConfigFlag` — set `true` alongside `managed` so hosts also
    /// fetch DNS servers and other config via DHCPv6.
    pub other: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply radvd configuration for the given set of prefix assignments.
///
/// * If `assignments` is non-empty, writes `/etc/radvd.conf` and
///   starts/reloads radvd.
/// * If `assignments` is empty, stops radvd and removes the config.
pub async fn apply_radvd(assignments: &[PrefixAssignment]) -> anyhow::Result<()> {
    if assignments.is_empty() {
        return stop_radvd().await;
    }

    let conf = generate_radvd_conf(assignments);
    tokio::fs::write(RADVD_CONF_PATH, &conf)
        .await
        .map_err(|e| anyhow::anyhow!("write radvd.conf: {e}"))?;

    debug!(
        interfaces = assignments.len(),
        "radvd: wrote configuration"
    );

    reload_or_start_radvd().await
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

fn generate_radvd_conf(assignments: &[PrefixAssignment]) -> String {
    let mut conf = String::from(
        "# Managed by dayshield-core - do not edit manually\n\n",
    );

    for a in assignments {
        let network = network_from_cidr(&a.prefix);
        let managed_flag = if a.managed { "on" } else { "off" };
        let other_flag = if a.other { "on" } else { "off" };
        // When managed-mode is on, hosts use DHCPv6 for addresses — SLAAC is disabled.
        let autonomous = if a.managed { "off" } else { "on" };
        conf.push_str(&format!(
            r#"interface {iface} {{
    AdvSendAdvert on;
    AdvManagedFlag {managed};
    AdvOtherConfigFlag {other};
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 10;

    prefix {prefix} {{
        AdvOnLink on;
        AdvAutonomous {autonomous};
        AdvRouterAddr on;
        AdvPreferredLifetime 3600;
        AdvValidLifetime 7200;
    }};
}};

"#,
            iface = a.iface,
            prefix = network,
            managed = managed_flag,
            other = other_flag,
            autonomous = autonomous,
        ));
    }

    conf
}

/// Strip host bits from a CIDR to produce the pure network prefix.
///
/// e.g. `"2001:db8:0:3::1/64"` → `"2001:db8:0:3::/64"`
fn network_from_cidr(cidr: &str) -> String {
    let mut parts = cidr.splitn(2, '/');
    let addr_str = match parts.next() {
        Some(s) => s,
        None => return cidr.to_string(),
    };
    let len_str = match parts.next() {
        Some(s) => s,
        None => return cidr.to_string(),
    };
    let addr: Ipv6Addr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return cidr.to_string(),
    };
    let prefix_len: u8 = match len_str.parse() {
        Ok(l) => l,
        Err(_) => return cidr.to_string(),
    };

    let addr_u128 = u128::from(addr);
    let mask: u128 = if prefix_len == 0 {
        0
    } else {
        !0u128 << (128 - prefix_len as u32)
    };
    let network = Ipv6Addr::from(addr_u128 & mask);
    format!("{network}/{prefix_len}")
}

// ---------------------------------------------------------------------------
// Process management
// ---------------------------------------------------------------------------

async fn reload_or_start_radvd() -> anyhow::Result<()> {
    // Try SIGHUP reload if already running.
    if let Ok(pid_str) = std::fs::read_to_string(RADVD_PID_PATH) {
        let pid = pid_str.trim();
        if !pid.is_empty() {
            let result = Command::new("kill").args(["-HUP", pid]).output().await;
            if let Ok(out) = result {
                if out.status.success() {
                    info!("radvd: reloaded via SIGHUP (pid {})", pid);
                    return Ok(());
                }
            }
        }
    }

    // Not running or reload failed — start fresh.
    stop_radvd().await.ok();

    // Validate config before starting.
    let test = Command::new("radvd")
        .args(["-C", RADVD_CONF_PATH, "-n", "-d", "1"])
        .output()
        .await;

    match test {
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("radvd config test failed: {stderr}");
        }
        Err(e) => {
            // radvd not installed — log warning but do not fail the apply.
            warn!(error = %e, "radvd: binary not found; skipping RA advertisements");
            return Ok(());
        }
        _ => {}
    }

    let result = Command::new("radvd")
        .args(["-C", RADVD_CONF_PATH, "-p", RADVD_PID_PATH])
        .spawn();

    match result {
        Ok(_) => {
            info!("radvd: started");
            Ok(())
        }
        Err(e) => {
            warn!(error = %e, "radvd: failed to start; RA advertisements will be unavailable");
            Ok(()) // non-fatal — prefix is still assigned, hosts can use DHCPv6
        }
    }
}

async fn stop_radvd() -> anyhow::Result<()> {
    // Try graceful kill by PID file.
    if let Ok(pid_str) = std::fs::read_to_string(RADVD_PID_PATH) {
        let pid = pid_str.trim();
        if !pid.is_empty() {
            let _ = Command::new("kill").args([pid]).output().await;
        }
    }
    let _ = std::fs::remove_file(RADVD_PID_PATH);

    // pkill fallback.
    let _ = Command::new("pkill").args(["radvd"]).output().await;

    info!("radvd: stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_strips_host_bits() {
        assert_eq!(
            network_from_cidr("2001:db8:0:3::1/64"),
            "2001:db8:0:3::/64"
        );
        assert_eq!(
            network_from_cidr("2001:db8:0:3::/64"),
            "2001:db8:0:3::/64"
        );
    }

    #[test]
    fn generate_conf_single_interface() {
        let assignments = vec![PrefixAssignment {
            iface: "eth1".to_string(),
            prefix: "2001:db8:0:3::1/64".to_string(),
        }];
        let conf = generate_radvd_conf(&assignments);
        assert!(conf.contains("interface eth1"));
        assert!(conf.contains("prefix 2001:db8:0:3::/64"));
        assert!(conf.contains("AdvSendAdvert on"));
        assert!(conf.contains("AdvAutonomous on"));
    }

    #[test]
    fn generate_conf_multiple_interfaces() {
        let assignments = vec![
            PrefixAssignment {
                iface: "eth1".to_string(),
                prefix: "2001:db8:0:1::1/64".to_string(),
            },
            PrefixAssignment {
                iface: "eth2".to_string(),
                prefix: "2001:db8:0:2::1/64".to_string(),
            },
        ];
        let conf = generate_radvd_conf(&assignments);
        assert!(conf.contains("interface eth1"));
        assert!(conf.contains("interface eth2"));
        assert!(conf.contains("2001:db8:0:1::/64"));
        assert!(conf.contains("2001:db8:0:2::/64"));
    }
}
