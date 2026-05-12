//! Gateway engine - manages default routes and monitors upstream gateways.
//!
//! # Overview
//!
//! This module translates [`Gateway`] configuration into live kernel routing
//! state and provides health-check probing for each configured gateway.
//!
//! | Function                | Purpose                                              |
//! |-------------------------|------------------------------------------------------|
//! | [`list_kernel_gateways`] | Read default routes from the kernel routing table.  |
//! | [`apply_gateway`]        | Write or remove a static default route.             |
//! | [`probe_gateway`]        | Single ICMP ping health check for one IP.           |
//! | [`probe_all_gateways`]   | Probe every configured gateway and return results.  |
//!
//! DHCP and PPPoE gateways are **not** written by this module - their default
//! routes are managed by `dhclient` / `pppd` respectively.  This engine only
//! writes routes for gateways that have an explicit `gateway_ip`.

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::config::models::Gateway;

// ---------------------------------------------------------------------------
// Status type
// ---------------------------------------------------------------------------

/// Live health state of a gateway.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum GatewayState {
    /// Gateway responded to the most recent ICMP probe.
    Online,
    /// Gateway did not respond to the most recent ICMP probe.
    Offline,
    /// No probe has been attempted yet or probing is not configured.
    Unknown,
}

/// A default route entry as currently seen in the kernel routing table.
#[derive(Debug, Clone, Serialize)]
pub struct KernelGateway {
    /// Interface the default route is via.
    pub interface: String,
    /// Current gateway IP from the routing table (`None` for on-link routes).
    pub gateway_ip: Option<String>,
    /// Live health state (populated by [`probe_gateway`]).
    pub state: GatewayState,
}

// Raw shape of one entry in `ip -j route show default`.
#[derive(Debug, Deserialize)]
struct IpRouteEntry {
    #[serde(default)]
    gateway: Option<String>,
    dev: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Read the live default route(s) from the kernel routing table.
///
/// Runs `ip -j route show default` and returns one [`KernelGateway`] per
/// default route entry.  Returns an empty list on any error.
pub async fn list_kernel_gateways() -> Vec<KernelGateway> {
    let out = Command::new("ip")
        .args(["-j", "route", "show", "default"])
        .output()
        .await;

    let out = match out {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, "gateway: failed to run ip route");
            return vec![];
        }
    };

    if !out.status.success() {
        warn!(
            stderr = %String::from_utf8_lossy(&out.stderr),
            "gateway: ip route show default failed"
        );
        return vec![];
    }

    let entries: Vec<IpRouteEntry> = serde_json::from_slice(&out.stdout).unwrap_or_default();

    entries
        .into_iter()
        .map(|e| KernelGateway {
            interface: e.dev,
            gateway_ip: e.gateway,
            state: GatewayState::Unknown,
        })
        .collect()
}

/// Apply a static gateway route to the kernel.
///
/// Runs `ip route replace default via <ip> dev <iface>` for gateways with a
/// configured `gateway_ip`.  If the gateway is disabled, the route is removed
/// instead.  Gateways without a `gateway_ip` (DHCP / PPPoE) are skipped.
///
/// # Errors
///
/// Returns an error string if the `ip route` command cannot be spawned or
/// exits with a non-zero status.
pub async fn apply_gateway(gw: &Gateway) -> Result<(), String> {
    let ip = match &gw.gateway_ip {
        Some(ip) => ip,
        None => {
            debug!(
                name = %gw.name,
                "gateway: skipping auto-discovered gateway (DHCP/PPPoE)"
            );
            return Ok(());
        }
    };

    if !gw.enabled {
        info!(name = %gw.name, ip = %ip, "gateway: removing disabled gateway route");
        let _ = Command::new("ip")
            .args(["route", "del", "default", "via", ip, "dev", &gw.interface])
            .output()
            .await;
        return Ok(());
    }

    info!(
        name  = %gw.name,
        ip    = %ip,
        iface = %gw.interface,
        "gateway: applying default route"
    );

    let out = Command::new("ip")
        .args(["route", "replace", "default", "via", ip, "dev", &gw.interface])
        .output()
        .await
        .map_err(|e| format!("failed to run ip route replace: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "ip route replace default via {ip} dev {} failed: {stderr}",
            gw.interface
        ));
    }

    Ok(())
}

/// Probe a single IP address with one ICMP ping (2-second timeout).
///
/// Returns [`GatewayState::Online`] if the ping succeeds,
/// [`GatewayState::Offline`] otherwise.
pub async fn probe_gateway(ip: &str) -> GatewayState {
    match Command::new("ping")
        .args(["-c", "1", "-W", "2", ip])
        .output()
        .await
    {
        Ok(o) if o.status.success() => GatewayState::Online,
        _ => GatewayState::Offline,
    }
}

/// Probe every configured gateway and return `(gateway, state)` pairs.
///
/// The probe IP is chosen as:
/// 1. `gw.monitor_ip` if set.
/// 2. `gw.gateway_ip` if set.
/// 3. `GatewayState::Unknown` if neither is available (e.g. DHCP gateway with
///    no `monitor_ip` configured).
///
/// Disabled gateways are returned with `GatewayState::Unknown` without
/// probing.
pub async fn probe_all_gateways(gateways: &[Gateway]) -> Vec<(&Gateway, GatewayState)> {
    let mut results = Vec::with_capacity(gateways.len());

    for gw in gateways {
        if !gw.enabled {
            results.push((gw, GatewayState::Unknown));
            continue;
        }

        let probe_ip = gw
            .monitor_ip
            .as_deref()
            .or(gw.gateway_ip.as_deref());

        let state = match probe_ip {
            Some(ip) => probe_gateway(ip).await,
            None => GatewayState::Unknown,
        };

        results.push((gw, state));
    }

    results
}
