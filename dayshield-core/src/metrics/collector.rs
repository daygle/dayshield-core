//! Background metrics collector task.
//!
//! [`start_metrics_collector`] spawns a Tokio task that wakes every second,
//! collects a fresh [`MetricsSnapshot`] from all subsystem collectors, and
//! pushes the result into the shared [`MetricsBuffer`].

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::time::{interval, Duration};
use tracing::{info, warn};

use crate::{
    metrics::{
        crowdsec::collect_crowdsec_default,
        firewall::collect_firewall,
        network::{compute_throughput, read_iface_counters, IfaceCounters},
        suricata::collect_suricata,
        system::{collect_system, CpuStat},
        MetricsSnapshot,
    },
    state::AppState,
};

/// Collection interval.
const COLLECTION_INTERVAL: Duration = Duration::from_secs(1);

/// Return the current time as seconds since the Unix epoch.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Spawn the background metrics collector.
///
/// This function returns immediately; the collection loop runs in a detached
/// Tokio task for the lifetime of the process.
pub async fn start_metrics_collector(state: Arc<AppState>) {
    tokio::spawn(async move {
        run_collector(state).await;
    });
}

/// Inner collection loop - runs forever.
async fn run_collector(state: Arc<AppState>) {
    info!("metrics/collector: starting");

    let mut ticker = interval(COLLECTION_INTERVAL);
    let mut prev_cpu: Option<CpuStat> = None;
    let mut prev_iface: std::collections::HashMap<String, IfaceCounters> =
        std::collections::HashMap::new();
    let mut last_tick = std::time::Instant::now();

    loop {
        ticker.tick().await;

        let elapsed = last_tick.elapsed().as_secs_f64().max(0.001);
        last_tick = std::time::Instant::now();

        let now = now_unix_secs();

        // --- System metrics ---
        let (system, curr_cpu) = collect_system(prev_cpu.as_ref()).await;
        prev_cpu = Some(curr_cpu);

        // --- Network metrics ---
        let curr_iface = read_iface_counters().await;
        let network = compute_throughput(&prev_iface, &curr_iface, elapsed);
        prev_iface = curr_iface;

        // --- Firewall metrics ---
        let firewall = match tokio::time::timeout(
            Duration::from_secs(5),
            collect_firewall(),
        )
        .await
        {
            Ok(fm) => fm,
            Err(_) => {
                warn!("metrics/collector: firewall collection timed out");
                crate::metrics::FirewallMetrics::default()
            }
        };

        // --- Suricata metrics ---
        let suricata = collect_suricata(now).await;

        // --- CrowdSec metrics ---
        let crowdsec = collect_crowdsec_default(now).await;

        let snapshot = MetricsSnapshot {
            timestamp: now,
            system,
            network,
            firewall,
            suricata,
            crowdsec,
        };

        // Push into the buffer.
        let mut buf = state.metrics_buffer.write().await;
        buf.push(snapshot);
    }
}
