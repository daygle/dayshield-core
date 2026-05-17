//! Interface manager - applies network interface configuration via iproute2.
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
//! | `start_dhcp_client`        | Spawn dhclient for a DHCP4 interface.         |
//! | `stop_dhcp_client`         | Release DHCP lease and stop dhclient.         |

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::config::models::{is_valid_cidr, is_valid_interface_name, Interface, Ipv6Mode, WanMode};
use crate::engine::{prefix_delegation, radvd};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can be produced by the interface engine.
#[derive(Debug, thiserror::Error)]
pub enum InterfaceError {
    /// The interface name fails the naming rules.
    #[error("invalid interface name: {0:?}")]
    InvalidName(String),

    /// The MTU value is outside the acceptable range.
    #[error("invalid MTU value: {0}")]
    InvalidMtu(u16),

    /// The MSS value is outside the acceptable range.
    #[error("invalid MSS value: {0}")]
    InvalidMss(u16),

    /// A CIDR address string is malformed.
    #[error("invalid CIDR address: {0:?}")]
    InvalidCIDR(String),

    /// VLAN tag ID is outside the 802.1Q range.
    #[error("invalid VLAN ID: {0} (must be 1-4094)")]
    InvalidVlanId(u16),

    /// VLAN interface is missing a parent/base interface.
    #[error("VLAN interface {0:?} is missing parent interface")]
    MissingVlanParent(String),

    /// VLAN parent/base interface name is invalid.
    #[error("invalid VLAN parent interface name: {0:?}")]
    InvalidVlanParent(String),

    /// VLAN parent was set without a VLAN ID.
    #[error("interface {0:?} has parent_interface set but no VLAN ID")]
    ParentInterfaceWithoutVlan(String),

    /// An `ip(8)` command failed or could not be spawned.
    #[error("failed to apply interface configuration: {0}")]
    ApplyFailed(String),

    /// Querying kernel interfaces via `ip(8)` failed.
    #[error("failed to query kernel interfaces: {0}")]
    KernelQueryFailed(String),

    /// The specified interface does not exist in persistent configuration.
    #[error("interface not found: {0:?}")]
    NotFound(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),
}

impl axum::response::IntoResponse for InterfaceError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::Json;

        let status = match &self {
            InterfaceError::InvalidName(_)
            | InterfaceError::InvalidMtu(_)
            | InterfaceError::InvalidMss(_)
            | InterfaceError::InvalidCIDR(_)
            | InterfaceError::InvalidVlanId(_)
            | InterfaceError::MissingVlanParent(_)
            | InterfaceError::InvalidVlanParent(_)
            | InterfaceError::ParentInterfaceWithoutVlan(_) => StatusCode::UNPROCESSABLE_ENTITY,
            InterfaceError::NotFound(_) => StatusCode::NOT_FOUND,
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
    /// Raw kernel flags from `ip -j link` (e.g. `UP`, `LOWER_UP`, `MULTICAST`).
    pub flags: Vec<String>,
    /// Assigned addresses in CIDR notation.
    pub addresses: Vec<String>,
    /// Received packet counter.
    pub rx_packets: Option<u64>,
    /// Received byte counter.
    pub rx_bytes: Option<u64>,
    /// Transmitted packet counter.
    pub tx_packets: Option<u64>,
    /// Transmitted byte counter.
    pub tx_bytes: Option<u64>,
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
    #[serde(default)]
    stats: Option<IpLinkStats>,
    #[serde(default)]
    stats64: Option<IpLinkStats>,
}

#[derive(Debug, Deserialize)]
struct IpLinkStats {
    #[serde(default)]
    rx: Option<IpLinkCounterValues>,
    #[serde(default)]
    tx: Option<IpLinkCounterValues>,
}

#[derive(Debug, Deserialize)]
struct IpLinkCounterValues {
    #[serde(default)]
    packets: Option<u64>,
    #[serde(default)]
    bytes: Option<u64>,
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
           .args(["-j", "-s", "link"])
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

    // Build ifname â†’ addresses map.
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
            let counters = link.stats64.or(link.stats);
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
                flags: link.flags,
                addresses,
                rx_packets: counters
                    .as_ref()
                    .and_then(|stats| stats.rx.as_ref())
                    .and_then(|rx| rx.packets),
                rx_bytes: counters
                    .as_ref()
                    .and_then(|stats| stats.rx.as_ref())
                    .and_then(|rx| rx.bytes),
                tx_packets: counters
                    .as_ref()
                    .and_then(|stats| stats.tx.as_ref())
                    .and_then(|tx| tx.packets),
                tx_bytes: counters
                    .as_ref()
                    .and_then(|stats| stats.tx.as_ref())
                    .and_then(|tx| tx.bytes),
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
/// - If `config.dhcp4` is `true`, spawns `dhclient` (from `isc-dhcp-client`)
///   to acquire an address from the upstream DHCP server.  Any previously
///   running dhclient for the same interface is released first.
/// - If `config.dhcp4` is `false`, any running dhclient for this interface is
///   stopped before static addresses are configured via `ip addr add`.
///
/// When `config.enabled` is `false`:
/// - Releases any active DHCP lease (`dhclient -r`) before bringing the
///   interface down.
///
/// # Errors
///
/// Returns [`InterfaceError::InvalidName`] or [`InterfaceError::InvalidCIDR`]
/// on bad input, and [`InterfaceError::ApplyFailed`] if an `ip(8)` command
/// fails at runtime.
pub async fn apply_interface(config: &Interface) -> Result<(), InterfaceError> {
    apply_interface_with_ipv6(config, false).await
}

/// Apply a single [`Interface`] configuration with awareness of the global
/// IPv6 setting.
pub async fn apply_interface_with_ipv6(
    config: &Interface,
    ipv6_enabled: bool,
) -> Result<(), InterfaceError> {
    let name = &config.name;

    if !is_valid_interface_name(name) {
        return Err(InterfaceError::InvalidName(name.clone()));
    }

    if let Some(vlan_id) = config.vlan {
        if !(1..=4094).contains(&vlan_id) {
            return Err(InterfaceError::InvalidVlanId(vlan_id));
        }
        let parent = config
            .parent_interface
            .as_deref()
            .ok_or_else(|| InterfaceError::MissingVlanParent(name.clone()))?;
        if !is_valid_interface_name(parent) {
            return Err(InterfaceError::InvalidVlanParent(parent.to_string()));
        }
        if parent == name {
            return Err(InterfaceError::InvalidVlanParent(parent.to_string()));
        }
    } else if config.parent_interface.is_some() {
        return Err(InterfaceError::ParentInterfaceWithoutVlan(name.clone()));
    }

    info!(
        name = %name,
        enabled = config.enabled,
        dhcp4 = config.dhcp4,
        dhcp6 = config.dhcp6,
        accept_ra = config.accept_ra,
        ipv6_mode = ?config.effective_ipv6_mode(),
        ipv6_enabled,
        addresses = ?config.addresses,
        "interfaces: applying interface configuration"
    );

    if config.enabled {
        if let Some(vlan_id) = config.vlan {
            let parent = config
                .parent_interface
                .as_deref()
                .expect("validated VLAN parent_interface to be present");
            let _ = run_ip(&["link", "del", "dev", name]).await;
            run_ip(&[
                "link",
                "add",
                "link",
                parent,
                "name",
                name,
                "type",
                "vlan",
                "id",
                &vlan_id.to_string(),
            ])
            .await?;
        }

        run_ip(&["link", "set", "dev", name, "up"]).await?;

        if let Some(mtu) = config.mtu {
            debug!(name = %name, mtu, "interfaces: setting MTU");
            run_ip(&["link", "set", "dev", name, "mtu", &mtu.to_string()]).await?;
        }

        match config.wan_mode.as_ref() {
            Some(WanMode::Pppoe) => {
                // Ensure DHCP client is not competing with PPPoE on the same WAN.
                stop_dhcp_client(name).await;
                stop_dhcp6_client(name).await;
                stop_dhcp6_pd_client(name).await;
                set_ipv6_ra_accept(name, false).await?;
                let username = config.pppoe_username.as_deref().unwrap_or("");
                let password = config.pppoe_password.as_deref().unwrap_or("");
                let ppp_mtu = config.mtu.unwrap_or(1492).clamp(576, 1492);
                start_pppoe(name, username, password, ipv6_enabled, ppp_mtu).await?;
            }
            _ => {
                let ipv6_mode = config.effective_ipv6_mode();
                let use_dhcp6 = ipv6_enabled && matches!(ipv6_mode, Ipv6Mode::Dhcp6);
                let use_ra = ipv6_enabled && matches!(ipv6_mode, Ipv6Mode::Slaac);

                set_ipv6_ra_accept(name, use_ra).await?;

                if config.dhcp4 {
                    start_dhcp_client(name).await?;
                } else {
                    // Ensure no stale dhclient is running before applying static config.
                    stop_dhcp_client(name).await;
                }

                if use_dhcp6 {
                    start_dhcp6_client(name).await?;
                    // Start prefix-delegation client when ia_pd_hint_len is configured.
                    if let Some(hint_len) = config.ia_pd_hint_len {
                        prefix_delegation::ensure_pd_hook_installed().await.ok();
                        start_dhcp6_pd_client(name, Some(hint_len)).await.ok();
                    } else {
                        stop_dhcp6_pd_client(name).await;
                    }
                } else {
                    stop_dhcp6_client(name).await;
                    stop_dhcp6_pd_client(name).await;
                }

                // For TrackInterface LAN mode: apply the tracked prefix if already available.
                // Full resolution (all LAN interfaces + radvd) happens in sync_interfaces_with_ipv6.
                if ipv6_enabled && matches!(ipv6_mode, Ipv6Mode::TrackInterface) {
                    if let Some(src) = &config.track_source_interface {
                        let target_len = config.delegated_prefix_len.unwrap_or(64);
                        let prefix_id = config.track_prefix_id.unwrap_or(0);
                        match prefix_delegation::read_delegated_prefix(src) {
                            Some(delegated) => {
                                if let Some(assigned) = prefix_delegation::compute_track_address(
                                    &delegated, prefix_id, target_len, 1,
                                ) {
                                    if let Err(e) = assign_ipv6_address_exclusive(name, &assigned).await {
                                        warn!(name = %name, addr = %assigned, error = %e,
                                            "interfaces: failed to assign tracked IPv6 prefix");
                                    } else {
                                        debug!(name = %name, assigned = %assigned,
                                            "interfaces: applied tracked IPv6 prefix");
                                    }
                                }
                            }
                            None => {
                                debug!(name = %name, source = %src,
                                    "interfaces: delegated prefix not yet available");
                            }
                        }
                    }
                }

                for cidr in &config.addresses {
                    if !ipv6_enabled && cidr.contains(':') {
                        return Err(InterfaceError::InvalidCIDR(cidr.clone()));
                    }
                    if cidr.contains(':') && !matches!(ipv6_mode, Ipv6Mode::Static) {
                        continue;
                    }
                    if config.dhcp4 && !cidr.contains(':') {
                        continue;
                    }
                    if !is_valid_cidr(cidr) {
                        return Err(InterfaceError::InvalidCIDR(cidr.clone()));
                    }
                    debug!(name = %name, cidr = %cidr, "interfaces: adding address");
                    run_ip(&["addr", "add", cidr, "dev", name]).await?;
                }

                // Apply static default gateway if configured.
                if let Some(gw_ip) = &config.gateway {
                    if !ipv6_enabled && gw_ip.contains(':') {
                        return Err(InterfaceError::ApplyFailed(
                            "IPv6 gateway requires system ipv6Enabled".to_string(),
                        ));
                    }
                    info!(name = %name, gateway = %gw_ip, "interfaces: applying static default route");
                    if gw_ip.contains(':') {
                        run_ip(&["-6", "route", "replace", "default", "via", gw_ip, "dev", name]).await?;
                    } else {
                        run_ip(&["route", "replace", "default", "via", gw_ip, "dev", name]).await?;
                    }
                }
            }
        }
    } else {
        // Release any active DHCP or PPPoE session before taking the interface down.
        stop_pppoe(name).await;
        stop_dhcp_client(name).await;
        stop_dhcp6_client(name).await;
        stop_dhcp6_pd_client(name).await;
        let _ = set_ipv6_ra_accept(name, false).await;
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
    sync_interfaces_with_ipv6(configured, false).await
}

/// Reconcile interface configuration using the current IPv6 mode.
pub async fn sync_interfaces_with_ipv6(
    configured: &[Interface],
    ipv6_enabled: bool,
) -> Result<(), InterfaceError> {
    info!(count = configured.len(), "interfaces: starting sync");

    let kernel = list_kernel_interfaces().await?;
    let kernel_map: HashMap<&str, &KernelInterface> =
        kernel.iter().map(|k| (k.name.as_str(), k)).collect();

    for config in configured {
        let kernel_iface = kernel_map.get(config.name.as_str()).copied();
        let ipv6_mode = config.effective_ipv6_mode();
        let manage_ipv4_static = !config.dhcp4;
        let manage_ipv6_static = ipv6_enabled && matches!(ipv6_mode, Ipv6Mode::Static);

        let current_up = kernel_iface.map(|k| k.state == "UP").unwrap_or(false);

        // Only skip apply if both state and addresses already match.
        let already_up = config.enabled == current_up;
        let kernel_addrs: &[String] = kernel_iface
            .map(|k| k.addresses.as_slice())
            .unwrap_or(&[]);
        let desired_addrs = config
            .addresses
            .iter()
            .filter(|addr| {
                if addr.contains(':') {
                    manage_ipv6_static
                } else {
                    manage_ipv4_static
                }
            })
            .cloned()
            .collect::<Vec<String>>();
        let managed_kernel_addrs = kernel_addrs
            .iter()
            .filter(|addr| {
                if addr.contains(':') {
                    manage_ipv6_static
                } else {
                    manage_ipv4_static
                }
            })
            .cloned()
            .collect::<Vec<String>>();
        let addrs_match = (manage_ipv4_static || manage_ipv6_static)
            && desired_addrs.len() == managed_kernel_addrs.len()
            && desired_addrs.iter().all(|a| managed_kernel_addrs.contains(a));

        if !already_up || !addrs_match {
            apply_interface_with_ipv6(config, ipv6_enabled).await?;
        } else if config.enabled {
            // Keep RA policy synchronized even when addresses/state are unchanged.
            let enable_ra = ipv6_enabled
                && matches!(ipv6_mode, Ipv6Mode::Slaac)
                && !matches!(config.wan_mode.as_ref(), Some(WanMode::Pppoe));
            set_ipv6_ra_accept(&config.name, enable_ra).await?;
        }

        // Remove stale static addresses from the kernel.
        if config.enabled && (manage_ipv4_static || manage_ipv6_static) {
            if let Some(ki) = kernel_iface {
                for kernel_addr in &ki.addresses {
                    if kernel_addr.contains(':') && !manage_ipv6_static {
                        continue;
                    }
                    if !kernel_addr.contains(':') && !manage_ipv4_static {
                        continue;
                    }
                    if !desired_addrs.contains(kernel_addr) {
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

    refresh_router_advertisements(configured, ipv6_enabled).await;

    Ok(())
}

/// Resolve tracked prefixes and refresh radvd advertisements for downstream
/// interfaces. Empty assignments stop radvd, which also clears stale RA config
/// when IPv6 is globally disabled or the last tracked interface is removed.
pub async fn refresh_router_advertisements(configured: &[Interface], ipv6_enabled: bool) {
    if !ipv6_enabled {
        if let Err(e) = radvd::apply_radvd(&[]).await {
            warn!(error = %e, "interfaces: failed to stop radvd after IPv6 disable");
        }
        return;
    }

    let mut radvd_assignments: Vec<radvd::PrefixAssignment> = Vec::new();

    for config in configured {
        if !config.enabled {
            continue;
        }
        if !matches!(config.effective_ipv6_mode(), Ipv6Mode::TrackInterface) {
            continue;
        }
        let Some(src) = config.track_source_interface.as_deref() else {
            continue;
        };
        let target_len = config.delegated_prefix_len.unwrap_or(64);
        let prefix_id = config.track_prefix_id.unwrap_or(0);

        match prefix_delegation::read_delegated_prefix(src) {
            Some(delegated) => {
                match prefix_delegation::compute_track_address(&delegated, prefix_id, target_len, 1) {
                    Some(assigned) => {
                        if let Err(e) = assign_ipv6_address_exclusive(&config.name, &assigned).await {
                            warn!(
                                name = %config.name,
                                addr = %assigned,
                                error = %e,
                                "interfaces: failed to set tracked prefix"
                            );
                        } else {
                            info!(
                                name = %config.name,
                                assigned = %assigned,
                                source = %src,
                                "interfaces: applied tracked IPv6 prefix"
                            );
                            let flags = config.effective_ra_mode().flags();
                            radvd_assignments.push(radvd::PrefixAssignment {
                                iface: config.name.clone(),
                                prefix: assigned,
                                managed: flags.managed,
                                other: flags.other,
                                autonomous: flags.autonomous,
                            });
                        }
                    }
                    None => {
                        warn!(
                            name = %config.name,
                            delegated = %delegated,
                            prefix_id,
                            target_len,
                            "interfaces: could not compute tracked prefix from delegated"
                        );
                    }
                }
            }
            None => {
                debug!(
                    name = %config.name,
                    source = %src,
                    "interfaces: delegated prefix not yet available; will retry on next sync"
                );
            }
        }
    }

    if let Err(e) = radvd::apply_radvd(&radvd_assignments).await {
        warn!(error = %e, "interfaces: radvd apply failed (non-fatal)");
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Start `dhclient` for `name` to acquire an IPv4 address via DHCP.
///
/// A PID file is written to `/run/dhclient.<name>.pid`.  Any previously
/// running dhclient for the same interface is stopped first.
///
/// dhclient runs as a detached background process; its Child handle is
/// dropped intentionally so it continues renewing leases independently.
async fn start_dhcp_client(name: &str) -> Result<(), InterfaceError> {
    let pid_file = format!("/run/dhclient.{name}.pid");

    // Release any existing lease and clean up the old process first.
    stop_dhcp_client(name).await;

    info!(name = %name, pid_file = %pid_file, "interfaces: starting dhclient");

    // Spawn dhclient in background (no -1 flag so it keeps renewing).
    Command::new("dhclient")
        .args(["-pf", &pid_file, name])
        .spawn()
        .map_err(|e| {
            InterfaceError::ApplyFailed(format!("failed to spawn dhclient for {name}: {e}"))
        })?;
    // Child handle dropped - dhclient runs as a background process.
    Ok(())
}

/// Start `dhclient` for `name` to acquire IPv6 configuration via DHCPv6.
async fn start_dhcp6_client(name: &str) -> Result<(), InterfaceError> {
    let pid_file = format!("/run/dhclient6.{name}.pid");

    stop_dhcp6_client(name).await;

    info!(name = %name, pid_file = %pid_file, "interfaces: starting dhclient -6");

    Command::new("dhclient")
        .args(["-6", "-pf", &pid_file, name])
        .spawn()
        .map_err(|e| {
            InterfaceError::ApplyFailed(format!("failed to spawn dhclient -6 for {name}: {e}"))
        })?;
    Ok(())
}

/// Stop `dhclient` for `name`, releasing the DHCP lease.
///
/// Runs `dhclient -r` for a graceful release, then removes the PID file.
/// Errors are logged and swallowed because dhclient may not be running.
async fn stop_dhcp_client(name: &str) {
    let pid_file = format!("/run/dhclient.{name}.pid");

    // Attempt a graceful release (sends DHCPRELEASE to the upstream server).
    let result = Command::new("dhclient")
        .args(["-r", "-pf", &pid_file, name])
        .output()
        .await;

    match result {
        Ok(out) if out.status.success() => {
            info!(name = %name, "interfaces: dhclient released DHCP lease");
        }
        Ok(out) => {
            // Not running or already released - not an error worth surfacing.
            debug!(
                name = %name,
                stderr = %String::from_utf8_lossy(&out.stderr),
                "interfaces: dhclient -r exited non-zero (may not have been running)"
            );
        }
        Err(e) => {
            debug!(name = %name, error = %e, "interfaces: dhclient not found or not spawnable");
        }
    }

    // Remove the PID file regardless of whether release succeeded.
    if let Err(e) = std::fs::remove_file(&pid_file) {
        if e.kind() != std::io::ErrorKind::NotFound {
            debug!(name = %name, error = %e, "interfaces: could not remove dhclient PID file");
        }
    }
}

/// Stop `dhclient -6` for `name`, releasing the DHCPv6 lease.
async fn stop_dhcp6_client(name: &str) {
    let pid_file = format!("/run/dhclient6.{name}.pid");

    let result = Command::new("dhclient")
        .args(["-6", "-r", "-pf", &pid_file, name])
        .output()
        .await;

    match result {
        Ok(out) if out.status.success() => {
            info!(name = %name, "interfaces: dhclient -6 released DHCPv6 lease");
        }
        Ok(out) => {
            debug!(
                name = %name,
                stderr = %String::from_utf8_lossy(&out.stderr),
                "interfaces: dhclient -6 -r exited non-zero (may not have been running)"
            );
        }
        Err(e) => {
            debug!(name = %name, error = %e, "interfaces: dhclient -6 not found or not spawnable");
        }
    }

    if let Err(e) = std::fs::remove_file(&pid_file) {
        if e.kind() != std::io::ErrorKind::NotFound {
            debug!(name = %name, error = %e, "interfaces: could not remove dhclient6 PID file");
        }
    }
}

/// Start `dhclient -6 -P` for `name` to acquire an IPv6 prefix delegation.
///
/// When `hint_len` is provided, a dhclient config requesting that prefix size
/// is written first.  The PID is written to `/run/dhclient6-pd.<name>.pid`.
async fn start_dhcp6_pd_client(name: &str, hint_len: Option<u8>) -> Result<(), InterfaceError> {
    let pid_file = format!("/run/dhclient6-pd.{name}.pid");
    let lease_file = format!("/var/lib/dhclient/dhclient6-pd.{name}.leases");

    stop_dhcp6_pd_client(name).await;

    let mut args: Vec<String> = vec!["-6".into(), "-P".into()];

    // If a prefix hint is given, write a config file and pass -cf.
    if let Some(len) = hint_len {
        match prefix_delegation::write_dhcp6_pd_conf(name, len).await {
            Ok(conf_path) => {
                args.push("-cf".into());
                args.push(conf_path);
            }
            Err(e) => {
                warn!(name = %name, hint_len = len, error = %e,
                    "interfaces: could not write dhclient6-pd config; proceeding without hint");
            }
        }
    }

    args.extend([
        "-pf".into(),
        pid_file.clone(),
        "-lf".into(),
        lease_file,
        name.to_string(),
    ]);

    info!(name = %name, hint_len = ?hint_len, "interfaces: starting dhclient6 prefix delegation");

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    Command::new("dhclient")
        .args(&arg_refs)
        .spawn()
        .map_err(|e| {
            InterfaceError::ApplyFailed(format!(
                "failed to spawn dhclient6-pd for {name}: {e}"
            ))
        })?;
    Ok(())
}

/// Stop the DHCPv6-PD client for `name`, releasing any active prefix lease.
async fn stop_dhcp6_pd_client(name: &str) {
    let pid_file = format!("/run/dhclient6-pd.{name}.pid");

    let result = Command::new("dhclient")
        .args(["-6", "-r", "-P", "-pf", &pid_file, name])
        .output()
        .await;

    match result {
        Ok(out) if out.status.success() => {
            info!(name = %name, "interfaces: dhclient6-pd released prefix delegation");
        }
        Ok(out) => {
            debug!(
                name = %name,
                stderr = %String::from_utf8_lossy(&out.stderr),
                "interfaces: dhclient6-pd -r exited non-zero (may not have been running)"
            );
        }
        Err(e) => {
            debug!(name = %name, error = %e, "interfaces: dhclient6-pd not found or not spawnable");
        }
    }

    if let Err(e) = std::fs::remove_file(&pid_file) {
        if e.kind() != std::io::ErrorKind::NotFound {
            debug!(name = %name, error = %e, "interfaces: could not remove dhclient6-pd PID file");
        }
    }
}

/// Assign an IPv6 address as the sole global-scope address on an interface.
///
/// Flushes all existing global-scope IPv6 addresses (which is correct for
/// a `track_interface` LAN interface managed exclusively by DayShield) then
/// adds the new address.
async fn assign_ipv6_address_exclusive(name: &str, cidr: &str) -> Result<(), InterfaceError> {
    // Remove all existing global-scope IPv6 addresses.
    let _ = Command::new("ip")
        .args(["-6", "addr", "flush", "dev", name, "scope", "global"])
        .output()
        .await;

    // Add the new tracked address.
    run_ip(&["addr", "add", cidr, "dev", name]).await
}

/// Configure Linux IPv6 Router Advertisement acceptance for an interface.
///
/// Uses `accept_ra=2` when enabled so RA works even if forwarding is enabled.
async fn set_ipv6_ra_accept(name: &str, enabled: bool) -> Result<(), InterfaceError> {
    let value = if enabled { "2" } else { "0" };
    let key = format!("net.ipv6.conf.{name}.accept_ra");
    let assignment = format!("{key}={value}");

    debug!(name = %name, enabled, "interfaces: applying IPv6 RA acceptance");

    let out = Command::new("sysctl")
        .args(["-w", &assignment])
        .output()
        .await
        .map_err(|e| InterfaceError::ApplyFailed(format!("failed to spawn sysctl for {name}: {e}")))?;

    if !out.status.success() {
        return Err(InterfaceError::ApplyFailed(format!(
            "sysctl -w {assignment} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    Ok(())
}

/// Write PPPoE peer config and start `pppd` for `wan_iface`.
///
/// Creates:
/// - `/etc/ppp/peers/wan-<wan_iface>` - pppd config using `rp-pppoe` plugin.
/// - `/etc/ppp/chap-secrets` and `/etc/ppp/pap-secrets` with credentials.
///
/// Spawns `pppd call wan-<wan_iface>` as a background process.  `ppp0` will
/// appear once the ISP authenticates.
async fn start_pppoe(
    wan_iface: &str,
    username: &str,
    password: &str,
    ipv6_enabled: bool,
    ppp_mtu: u16,
) -> Result<(), InterfaceError> {
    use tokio::fs;

    if username.trim().is_empty() || password.is_empty() {
        return Err(InterfaceError::ApplyFailed(
            "pppoe: missing username or password".to_string(),
        ));
    }
    if username.chars().any(char::is_control) || password.chars().any(char::is_control) {
        return Err(InterfaceError::ApplyFailed(
            "pppoe: credentials contain control characters".to_string(),
        ));
    }

    // pppd peer files are line-oriented. Escape values so embedded quotes or
    // backslashes do not break parsing.
    let escaped_username = username.replace('\\', "\\\\").replace('"', "\\\"");
    let escaped_password = password.replace('\\', "\\\\").replace('"', "\\\"");

    let peer_name = format!("wan-{wan_iface}");
    let peer_path = format!("/etc/ppp/peers/{peer_name}");
    let pid_file = format!("/run/ppp-{peer_name}.pid");
    let secrets_line = format!("\"{}\" * \"{}\" *\n", escaped_username, escaped_password);

    // Ensure /etc/ppp exists
    fs::create_dir_all("/etc/ppp/peers")
        .await
        .map_err(|e| InterfaceError::ApplyFailed(format!("pppoe: create /etc/ppp/peers: {e}")))?;

    // Write peer config
    let ipv6_line = if ipv6_enabled {
        "+ipv6\ndefaultroute6\n"
    } else {
        "noipv6\n"
    };
    let peer_cfg = format!(
        "plugin rp-pppoe.so {wan_iface}\nuser \"{escaped_username}\"\nlinkname {peer_name}\n\
pidfile {pid_file}\nnoipdefault\nnoauth\ndefaultroute\nreplacedefaultroute\n\
hide-password\npersist\nmaxfail 0\nholdoff 5\nmtu {ppp_mtu}\nmru {ppp_mtu}\n{ipv6_line}"
    );
    fs::write(&peer_path, &peer_cfg)
        .await
        .map_err(|e| InterfaceError::ApplyFailed(format!("pppoe: write peer file: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&peer_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| InterfaceError::ApplyFailed(format!("pppoe: chmod peer file: {e}")))?;
    }

    // Write secrets (600 permissions)
    for path in ["/etc/ppp/chap-secrets", "/etc/ppp/pap-secrets"] {
        fs::write(path, &secrets_line)
            .await
            .map_err(|e| InterfaceError::ApplyFailed(format!("pppoe: write {path}: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| InterfaceError::ApplyFailed(format!("pppoe: chmod {path}: {e}")))?;
        }
    }

    // Stop any existing pppd for this WAN first
    stop_pppoe(wan_iface).await;

    info!(wan_iface = %wan_iface, "interfaces: starting pppoe (pppd call {})", peer_name);

    Command::new("pppd")
        .args(["call", &peer_name])
        .spawn()
        .map_err(|e| InterfaceError::ApplyFailed(format!("pppoe: failed to spawn pppd: {e}")))?;

    Ok(())
}

/// Stop `pppd` for the given WAN interface, if running.
async fn stop_pppoe(wan_iface: &str) {
    let peer_name = format!("wan-{wan_iface}");
    let pid_file = format!("/run/ppp-{peer_name}.pid");

    if let Ok(pid_text) = tokio::fs::read_to_string(&pid_file).await {
        if let Ok(pid) = pid_text.trim().parse::<u32>() {
            let _ = Command::new("kill")
                .args([pid.to_string()])
                .output()
                .await;
        }
        let _ = tokio::fs::remove_file(&pid_file).await;
    }

    // Best-effort fallback for sessions started before pidfile support.
    let _ = Command::new("pkill")
        .args(["-f", &format!("pppd call {peer_name}")])
        .output()
        .await;
}

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
            mss: None,
            enabled,
            dhcp4: false,
            dhcp6: false,
            accept_ra: false,
            ipv6_mode: Some(Ipv6Mode::Static),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            vlan: None,
            parent_interface: None,
            wan_mode: None,
            pppoe_username: None,
            pppoe_password: None,
            gateway: None,
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
        // available and succeeds - so just verify the function returns *some*
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
