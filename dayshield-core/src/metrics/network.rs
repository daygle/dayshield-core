//! Network metrics collector: per-interface throughput (rx/tx bps, packets).
//!
//! Reads `/proc/net/dev` on two successive ticks and computes the per-second
//! byte-rate delta for each interface.  Loopback (`lo`) is excluded.

use std::collections::HashMap;

use tokio::fs;
use tracing::warn;

use crate::metrics::InterfaceMetrics;

// ---------------------------------------------------------------------------
// /proc/net/dev parser
// ---------------------------------------------------------------------------

/// Counters parsed from a single `/proc/net/dev` line for one interface.
#[derive(Clone, Copy, Default, Debug)]
pub struct IfaceCounters {
    /// Total bytes received since boot.
    pub rx_bytes: u64,
    /// Total bytes transmitted since boot.
    pub tx_bytes: u64,
    /// Total packets received since boot.
    pub rx_packets: u64,
    /// Total packets transmitted since boot.
    pub tx_packets: u64,
}

/// Parse the full text of `/proc/net/dev` and return a map of
/// `interface_name → IfaceCounters`.
///
/// Lines that cannot be parsed are silently skipped.
pub fn parse_proc_net_dev(content: &str) -> HashMap<String, IfaceCounters> {
    let mut map = HashMap::new();

    for line in content.lines().skip(2) {
        // Format: `  eth0: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes ...`
        // The first column ends with a colon.
        let line = line.trim();
        let colon = match line.find(':') {
            Some(i) => i,
            None => continue,
        };
        let name = line[..colon].trim().to_string();

        let mut nums = line[colon + 1..].split_whitespace();
        let rx_bytes: u64 = nums.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let rx_packets: u64 = nums.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        // Skip rx_errs, rx_drop, rx_fifo, rx_frame, rx_compressed, rx_multicast (6 fields)
        for _ in 0..6 {
            nums.next();
        }
        let tx_bytes: u64 = nums.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let tx_packets: u64 = nums.next().and_then(|v| v.parse().ok()).unwrap_or(0);

        map.insert(name, IfaceCounters { rx_bytes, tx_bytes, rx_packets, tx_packets });
    }

    map
}

// ---------------------------------------------------------------------------
// Throughput delta calculation
// ---------------------------------------------------------------------------

/// Compute per-interface throughput metrics from two consecutive readings
/// taken `elapsed_secs` seconds apart.
///
/// `lo` (loopback) is excluded from the output.
pub fn compute_throughput(
    prev: &HashMap<String, IfaceCounters>,
    curr: &HashMap<String, IfaceCounters>,
    elapsed_secs: f64,
) -> Vec<InterfaceMetrics> {
    let divisor = elapsed_secs.max(0.001);
    let mut result = Vec::new();

    for (name, curr_c) in curr {
        if name == "lo" {
            continue;
        }
        let prev_c = prev.get(name).copied().unwrap_or_default();

        let rx_bytes_delta = curr_c.rx_bytes.saturating_sub(prev_c.rx_bytes);
        let tx_bytes_delta = curr_c.tx_bytes.saturating_sub(prev_c.tx_bytes);

        result.push(InterfaceMetrics {
            name: name.clone(),
            rx_bps: (rx_bytes_delta as f64 * 8.0 / divisor) as u64,
            tx_bps: (tx_bytes_delta as f64 * 8.0 / divisor) as u64,
            rx_packets: curr_c.rx_packets,
            tx_packets: curr_c.tx_packets,
        });
    }

    // Deterministic ordering.
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

// ---------------------------------------------------------------------------
// Top-level collector
// ---------------------------------------------------------------------------

/// Read current `/proc/net/dev` counters.
pub async fn read_iface_counters() -> HashMap<String, IfaceCounters> {
    match fs::read_to_string("/proc/net/dev").await {
        Ok(content) => parse_proc_net_dev(&content),
        Err(e) => {
            warn!(error = %e, "metrics/network: failed to read /proc/net/dev");
            HashMap::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    1024      16    0    0    0     0          0         0     1024      16    0    0    0     0       0          0
  eth0: 1000000    8000    0    0    0     0          0         0   500000    4000    0    0    0     0       0          0
  eth1:  200000    1500    0    0    0     0          0         0   100000     800    0    0    0     0       0          0
"#;

    #[test]
    fn test_parse_proc_net_dev() {
        let map = parse_proc_net_dev(SAMPLE);
        // lo should be present in raw parsing
        assert!(map.contains_key("lo"));
        let eth0 = map["eth0"];
        assert_eq!(eth0.rx_bytes, 1_000_000);
        assert_eq!(eth0.tx_bytes, 500_000);
        assert_eq!(eth0.rx_packets, 8_000);
        assert_eq!(eth0.tx_packets, 4_000);
    }

    #[test]
    fn test_compute_throughput_basic() {
        let mut prev = HashMap::new();
        prev.insert("eth0".to_string(), IfaceCounters { rx_bytes: 0, tx_bytes: 0, rx_packets: 0, tx_packets: 0 });

        let mut curr = HashMap::new();
        curr.insert("eth0".to_string(), IfaceCounters { rx_bytes: 1000, tx_bytes: 500, rx_packets: 10, tx_packets: 5 });

        let metrics = compute_throughput(&prev, &curr, 1.0);
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].name, "eth0");
        // 1000 bytes / 1s * 8 = 8000 bps
        assert_eq!(metrics[0].rx_bps, 8000);
        assert_eq!(metrics[0].tx_bps, 4000);
        assert_eq!(metrics[0].rx_packets, 10);
        assert_eq!(metrics[0].tx_packets, 5);
    }

    #[test]
    fn test_compute_throughput_excludes_loopback() {
        let mut prev = HashMap::new();
        prev.insert("lo".to_string(), IfaceCounters::default());

        let mut curr = HashMap::new();
        curr.insert("lo".to_string(), IfaceCounters { rx_bytes: 9999, tx_bytes: 9999, rx_packets: 100, tx_packets: 100 });

        let metrics = compute_throughput(&prev, &curr, 1.0);
        assert!(metrics.is_empty(), "loopback should be excluded");
    }

    #[test]
    fn test_compute_throughput_counter_wrap_saturation() {
        // Simulates a counter reset (e.g., interface down/up).
        let mut prev = HashMap::new();
        prev.insert("eth0".to_string(), IfaceCounters { rx_bytes: 5000, tx_bytes: 3000, rx_packets: 50, tx_packets: 30 });

        let mut curr = HashMap::new();
        curr.insert("eth0".to_string(), IfaceCounters { rx_bytes: 100, tx_bytes: 100, rx_packets: 10, tx_packets: 5 });

        let metrics = compute_throughput(&prev, &curr, 1.0);
        // saturating_sub → 0 bytes delta
        assert_eq!(metrics[0].rx_bps, 0);
        assert_eq!(metrics[0].tx_bps, 0);
    }

    #[test]
    fn test_compute_throughput_sorted() {
        let mut prev = HashMap::new();
        let mut curr = HashMap::new();
        for name in ["eth2", "eth0", "eth1"] {
            prev.insert(name.to_string(), IfaceCounters::default());
            curr.insert(name.to_string(), IfaceCounters::default());
        }
        let metrics = compute_throughput(&prev, &curr, 1.0);
        let names: Vec<&str> = metrics.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["eth0", "eth1", "eth2"]);
    }
}
