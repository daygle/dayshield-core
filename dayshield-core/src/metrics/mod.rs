//! Metrics module — system and service metrics structs.
//!
//! TODO: implement Prometheus-compatible metrics export via a `/metrics`
//!       endpoint using the `prometheus` or `metrics` crate.
//! TODO: track per-rule packet/byte counters from nftables.
//! TODO: track DHCP lease statistics.
//! TODO: track VPN peer handshake ages.
//! TODO: track DNS query rate and NXDOMAIN rate.
//! TODO: expose CrowdSec active-decision count.

use serde::Serialize;

/// Point-in-time snapshot of system metrics.
///
/// TODO: populate all fields from live data sources instead of defaults.
#[derive(Debug, Clone, Serialize, Default)]
pub struct SystemMetrics {
    /// Total number of packets processed by the firewall since last reset.
    pub packets_total: u64,
    /// Total number of packets dropped by the firewall since last reset.
    pub packets_dropped: u64,
    /// Number of active DHCP leases.
    pub dhcp_leases_active: u32,
    /// Number of active WireGuard peers.
    pub vpn_peers_active: u32,
    /// Number of IPs currently banned by CrowdSec.
    pub crowdsec_bans_active: u32,
    /// DNS queries per second (rolling 60-second average).
    pub dns_qps: f64,
    /// System uptime in seconds.
    pub uptime_seconds: u64,
}

impl SystemMetrics {
    /// Create a new zeroed-out metrics snapshot.
    pub fn new() -> Self {
        Self::default()
    }
}
