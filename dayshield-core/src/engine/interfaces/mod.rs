//! Interface manager — applies network interface configuration via iproute2.
//!
//! TODO: implement interface creation (VLAN, bridge, bond, WireGuard) using
//!       `ip link add`.
//! TODO: implement IP address assignment using `ip addr add / del`.
//! TODO: implement interface up/down lifecycle using `ip link set`.
//! TODO: implement MTU configuration using `ip link set mtu`.
//! TODO: read the live interface table from the kernel (via netlink or
//!       `/sys/class/net`) and populate [`AppState::interfaces`].
//! TODO: emit interface state-change events to the logging layer.

use anyhow::Result;
use tracing::info;

use crate::config::models::Interface;

/// Apply the given interface configuration to the running kernel.
///
/// TODO: diff the desired state against the current kernel state and issue
///       `ip` commands only for changed attributes.
pub async fn apply_interface(iface: &Interface) -> Result<()> {
    info!(
        name = %iface.name,
        enabled = iface.enabled,
        "interfaces: apply_interface called (stub)"
    );
    Ok(())
}

/// Read the current network interfaces from the kernel.
///
/// TODO: parse `/sys/class/net` or use the `rtnetlink` crate to enumerate
///       all live interfaces and their addresses.
pub async fn list_kernel_interfaces() -> Result<Vec<Interface>> {
    info!("interfaces: list_kernel_interfaces called (stub)");
    Ok(vec![])
}
