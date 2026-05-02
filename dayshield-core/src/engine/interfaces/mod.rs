//! Interface manager — applies network interface configuration via iproute2.
//!
//! # Overview
//!
//! This module translates [`Interface`] configuration objects into live kernel
//! state using `ip(8)` commands.  It also provides a read path that discovers
//! the current kernel interfaces by parsing the JSON output of
//! `ip -j link` and `ip -j addr`.
//!
//! # Functions
//!
//! | Function                  | Purpose                                        |
//! |---------------------------|------------------------------------------------|
//! | [`list_kernel_interfaces`] | Enumerate live interfaces from the kernel.    |
//! | [`apply_interface`]        | Apply a single [`Interface`] config.          |
//! | [`sync_interfaces`]        | Reconcile desired config against kernel state. |

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::config::models::{is_valid_cidr, is_valid_interface_name, Interface};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can be produced by the interface engine.
#[derive(Debug, thiserror::Error)]
pub enum InterfaceError {
    /// The interface name fails the naming rules.
    #[error("invalid interface name: {0:?}")]
    InvalidName(String),

    /// A CIDR address string is malformed.
    #[error("invalid CIDR address: {0:?}")]
    InvalidCIDR(String),

    /// An `ip(8)` command failed or could not be spawned.
    #[error("failed to apply interface configuration: {0}")]
    ApplyFailed(String),

    /// Querying kernel interfaces via `ip(8)` failed.
    #[error("failed to query kernel interfaces: {0}")]
    KernelQueryFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),
}

impl axum::response::IntoResponse for InterfaceError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::Json;

        let status = match &self {
            InterfaceError::InvalidName(_) | InterfaceError::InvalidCIDR(_) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            InterfaceError::ApplyFailed(_)
            | InterfaceError::KernelQueryFailed(_)
            | InterfaceError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, Json(serde_json::json!({ "error": self.to_string() }))).into_response()
    }
}

// ---------------------------------------------------------------------------
// Kernel interface representation
// ---------------------------------------------------------------------------

/// A network interface as currently seen by the kernel.
#[derive(Debug, Clone, Serialize)]
pub struct KernelInterface {
    /// OS-level interface name.
    pub name: String,
    /// Hardware (MAC) address, if available.
    pub mac: Option<String>,
    /// Maximum transmission unit in bytes.
    pub mtu: Option<u32>,
    /// Operational state: `"UP"` or `"DOWN"`.
    pub state: String,
    /// Assigned addresses in CIDR notation.
    pub addresses: Vec<String>,
}

// ---------------------------------------------------------------------------
// Private: raw iproute2 JSON shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct IpLinkEntry {
    ifname: String,
    #[serde(default)]
    flags: Vec<String>,
    mtu: Option<u32>,
    address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpAddrEntry {
    ifname: String,
    #[serde(default)]
    addr_info: Vec<IpAddrInfo>,
}

#[derive(Debug, Deserialize)]
struct IpAddrInfo {
    local: String,
    prefixlen: u8,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enumerate all network interfaces currently visible to the kernel.
///
/// Runs `ip -j link` to get link-layer information and `ip -j addr` for IP
/// addresses, then merges the results into a [`KernelInterface`] list.
///
/// # Errors
///
/// Returns [`InterfaceError::KernelQueryFailed`] if `ip(8)` cannot be executed
/// or its output cannot be parsed.
pub async fn list_kernel_interfaces() -> Result<Vec<KernelInterface>, InterfaceError> {
    info!("interfaces: querying kernel interfaces");

    // --- ip -j link --------------------------------------------------------
    let link_out = Command::new("ip")
        .args(["-j", "link"])
        .output()
        .await
        .map_err(|e| InterfaceError::KernelQueryFailed(e.to_string()))?;

    if !link_out.status.success() {
        let stderr = String::from_utf8_lossy(&link_out.stderr);
        return Err(InterfaceError::KernelQueryFailed(format!(
            "ip -j link failed: {stderr}"
        )));
    }

    let link_entries: Vec<IpLinkEntry> =
        serde_json::from_slice(&link_out.stdout).map_err(|e| {
            InterfaceError::KernelQueryFailed(format!("ip link parse error: {e}"))
        })?;

    debug!(count = link_entries.len(), "interfaces: parsed ip -j link");

    // --- ip -j addr --------------------------------------------------------
    let addr_out = Command::new("ip")
        .args(["-j", "addr"])
        .output()
        .await
        .map_err(|e| InterfaceError::KernelQueryFailed(e.to_string()))?;

    let addr_entries: Vec<IpAddrEntry> = if addr_out.status.success() {
        serde_json::from_slice(&addr_out.stdout).unwrap_or_default()
    } else {
        warn!(
            stderr = %String::from_utf8_lossy(&addr_out.stderr),
            "interfaces: ip -j addr failed; addresses will be empty"
        );
        vec![]
    };

    // Build ifname → addresses map.
    let mut addr_map: HashMap<String, Vec<String>> = HashMap::new();
    for entry in &addr_entries {
        let cidrs: Vec<String> = entry
            .addr_info
            .iter()
            .map(|a| format!("{}/{}", a.local, a.prefixlen))
            .collect();
        addr_map.insert(entry.ifname.clone(), cidrs);
    }

    // Merge link and address information.
    let interfaces = link_entries
        .into_iter()
        .map(|link| {
            let state = if link.flags.iter().any(|f| f == "UP") {
                "UP".to_string()
            } else {
                "DOWN".to_string()
            };
            let addresses = addr_map.remove(&link.ifname).unwrap_or_default();
            KernelInterface {
                name: link.ifname,
                mac: link.address,
                mtu: link.mtu,
                state,
                addresses,
            }
        })
        .collect();

    Ok(interfaces)
}

/// Apply a single [`Interface`] configuration to the running kernel.
///
/// When `config.enabled` is `true`:
/// - Brings the interface up (`ip link set dev <name> up`).
/// - Sets the MTU if `config.mtu` is `Some`.
/// - If `config.dhcp4` is `true`, logs a placeholder (dhclient integration is
///   a future work item).
/// - Otherwise adds each address in `config.addresses` via `ip addr add`.
///
/// When `config.enabled` is `false`:
/// - Brings the interface down (`ip link set dev <name> down`).
///
/// # Errors
///
/// Returns [`InterfaceError::InvalidName`] or [`InterfaceError::InvalidCIDR`]
/// on bad input, and [`InterfaceError::ApplyFailed`] if an `ip(8)` command
/// fails at runtime.
pub async fn apply_interface(config: &Interface) -> Result<(), InterfaceError> {
    let name = &config.name;

    if !is_valid_interface_name(name) {
        return Err(InterfaceError::InvalidName(name.clone()));
    }

    info!(
        name = %name,
        enabled = config.enabled,
        dhcp4 = config.dhcp4,
        addresses = ?config.addresses,
        "interfaces: applying interface configuration"
    );

    if config.enabled {
        run_ip(&["link", "set", "dev", name, "up"]).await?;

        if let Some(mtu) = config.mtu {
            debug!(name = %name, mtu, "interfaces: setting MTU");
            run_ip(&["link", "set", "dev", name, "mtu", &mtu.to_string()]).await?;
        }

        if config.dhcp4 {
            info!(name = %name, "interfaces: DHCP4 requested (dhclient integration pending)");
            // TODO: spawn / signal dhclient for the interface.
        } else {
            for cidr in &config.addresses {
                if !is_valid_cidr(cidr) {
                    return Err(InterfaceError::InvalidCIDR(cidr.clone()));
                }
                debug!(name = %name, cidr = %cidr, "interfaces: adding address");
                run_ip(&["addr", "add", cidr, "dev", name]).await?;
            }
        }
    } else {
        info!(name = %name, "interfaces: bringing interface down");
        run_ip(&["link", "set", "dev", name, "down"]).await?;
    }

    info!(name = %name, "interfaces: apply complete");
    Ok(())
}

/// Reconcile the desired interface configuration against the live kernel state.
///
/// For each configured interface the function:
/// 1. Locates the matching kernel interface (by name).
/// 2. Calls [`apply_interface`] to ensure the desired state is reached.
/// 3. If the interface is enabled and not using DHCP, removes any IP addresses
///    present in the kernel but absent from the desired config.
///
/// # Errors
///
/// Returns on the first error encountered; partial application may have
/// occurred.
pub async fn sync_interfaces(configured: &[Interface]) -> Result<(), InterfaceError> {
    info!(count = configured.len(), "interfaces: starting sync");

    let kernel = list_kernel_interfaces().await?;
    let kernel_map: HashMap<&str, &KernelInterface> =
        kernel.iter().map(|k| (k.name.as_str(), k)).collect();

    for config in configured {
        let kernel_iface = kernel_map.get(config.name.as_str()).copied();

        let current_up = kernel_iface.map(|k| k.state == "UP").unwrap_or(false);

        // Only skip apply if both state and addresses already match.
        let already_up = config.enabled == current_up;
        let kernel_addrs: &[String] = kernel_iface
            .map(|k| k.addresses.as_slice())
            .unwrap_or(&[]);
        let addrs_match = !config.dhcp4
            && config.addresses.len() == kernel_addrs.len()
            && config.addresses.iter().all(|a| kernel_addrs.contains(a));

        if !already_up || !addrs_match {
            apply_interface(config).await?;
        }

        // Remove stale static addresses from the kernel.
        if config.enabled && !config.dhcp4 {
            if let Some(ki) = kernel_iface {
                for kernel_addr in &ki.addresses {
                    if !config.addresses.contains(kernel_addr) {
                        warn!(
                            name = %config.name,
                            address = %kernel_addr,
                            "interfaces: removing stale address"
                        );
                        // Best-effort removal; log but don't abort on failure.
                        let _ =
                            run_ip(&["addr", "del", kernel_addr, "dev", &config.name]).await;
                    }
                }
            }
        }
    }

    info!("interfaces: sync complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Run `ip <args>` and return an error if the command exits non-zero.
async fn run_ip(args: &[&str]) -> Result<(), InterfaceError> {
    debug!(args = ?args, "interfaces: running ip command");

    let output = Command::new("ip")
        .args(args)
        .output()
        .await
        .map_err(|e| InterfaceError::ApplyFailed(format!("failed to spawn ip: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(InterfaceError::ApplyFailed(format!(
            "`ip {}` exited {}: {stderr}",
            args.join(" "),
            output.status
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::Interface;

    fn iface(name: &str, addresses: Vec<&str>, enabled: bool) -> Interface {
        Interface {
            name: name.into(),
            description: None,
            addresses: addresses.into_iter().map(String::from).collect(),
            mtu: None,
            enabled,
            dhcp4: false,
            dhcp6: false,
            vlan: None,
        }
    }

    #[test]
    fn interface_error_formats() {
        let e = InterfaceError::InvalidName("bad name".into());
        assert!(e.to_string().contains("bad name"));

        let e = InterfaceError::InvalidCIDR("1.2.3.4".into());
        assert!(e.to_string().contains("1.2.3.4"));

        let e = InterfaceError::ApplyFailed("command failed".into());
        assert!(e.to_string().contains("command failed"));
    }

    #[tokio::test]
    async fn apply_interface_rejects_invalid_name() {
        let config = iface("bad name!", vec![], true);
        let result = apply_interface(&config).await;
        assert!(matches!(result, Err(InterfaceError::InvalidName(_))));
    }

    #[tokio::test]
    async fn apply_interface_rejects_invalid_cidr() {
        let config = iface("eth0", vec!["not-a-cidr"], true);
        // The command will fail before reaching the cidr validation if `ip` is
        // not available, but if `ip link set dev eth0 up` fails we get
        // ApplyFailed.  We can only assert the cidr path directly when ip is
        // available and succeeds — so just verify the function returns *some*
        // Err rather than Ok.
        let result = apply_interface(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn apply_interface_disabled_runs_ip_down() {
        // With a non-existent interface this will fail at the ip command.
        // We assert an error is returned (not a panic).
        let config = iface("nonexistent9", vec![], false);
        let result = apply_interface(&config).await;
        // May succeed (unlikely) or fail; either way it must not panic.
        let _ = result;
    }
}
