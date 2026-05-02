//! Metrics module — real-time system and service metrics.
//!
//! Provides data models, a background collector, an in-memory ring buffer,
//! REST API handlers, and a WebSocket streaming endpoint.

pub mod buffer;
pub mod collector;
pub mod crowdsec;
pub mod firewall;
pub mod network;
pub mod suricata;
pub mod system;
pub mod websocket;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data models
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of all system and service metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsSnapshot {
    /// Unix timestamp (seconds since epoch) when the snapshot was taken.
    pub timestamp: u64,
    /// CPU, RAM, load, temperature and uptime metrics.
    pub system: SystemMetrics,
    /// Per-network-interface throughput metrics.
    pub network: Vec<InterfaceMetrics>,
    /// Firewall connection-state count and per-rule hit counters.
    pub firewall: FirewallMetrics,
    /// Suricata IDS/IPS alert-rate metrics.
    pub suricata: SuricataMetrics,
    /// CrowdSec decision-rate metrics.
    pub crowdsec: CrowdSecMetrics,
}

/// Host system resource metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemMetrics {
    /// CPU utilisation as a percentage (0–100).
    pub cpu_percent: f64,
    /// RAM utilisation as a percentage (0–100).
    pub ram_percent: f64,
    /// 1-minute load average.
    pub loadavg_1: f64,
    /// 5-minute load average.
    pub loadavg_5: f64,
    /// 15-minute load average.
    pub loadavg_15: f64,
    /// CPU temperature in degrees Celsius (0.0 when unavailable).
    pub temperature_c: f64,
    /// System uptime in seconds.
    pub uptime_seconds: u64,
}

/// Throughput metrics for a single network interface.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InterfaceMetrics {
    /// Interface name (e.g. `"eth0"`).
    pub name: String,
    /// Receive throughput in bits per second.
    pub rx_bps: u64,
    /// Transmit throughput in bits per second.
    pub tx_bps: u64,
    /// Total received packet count since boot.
    pub rx_packets: u64,
    /// Total transmitted packet count since boot.
    pub tx_packets: u64,
}

/// Firewall connection-state and rule-hit metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallMetrics {
    /// Number of active connection-tracking state entries.
    pub state_count: u64,
    /// Per-rule hit counters `(rule_handle, packet_count)`.
    pub rule_hit_counts: Vec<RuleHitCount>,
}

/// Packet hit count for a single nftables rule.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleHitCount {
    /// nftables rule handle number.
    pub handle: u64,
    /// Number of packets matched by this rule.
    pub packets: u64,
}

/// Suricata IDS/IPS alert-rate metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuricataMetrics {
    /// Number of alerts in the last 60 seconds.
    pub alerts_last_minute: u64,
    /// Number of alerts in the last 5 minutes (300 seconds).
    pub alerts_last_5min: u64,
}

/// CrowdSec decision-rate metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CrowdSecMetrics {
    /// Number of new decisions in the last 60 seconds.
    pub decisions_last_minute: u64,
    /// Number of new decisions in the last 5 minutes (300 seconds).
    pub decisions_last_5min: u64,
}
