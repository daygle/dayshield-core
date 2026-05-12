//! State module - shared application state and service health tracking.
//!
//! [`AppState`] is the single source of truth for in-memory runtime data.
//! It is created once at startup, wrapped in an [`Arc`], and injected into
//! every Axum handler via Axum's `State` extractor.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;

use crate::{
    config::{
        models::{CrowdSecDecision, FirewallRule, Interface},
        ConfigStore,
    },
    metrics::buffer::MetricsBuffer,
    notify::queue::NotifyQueue,
};

/// Known DayShield service names used as health-map keys.
pub const SVC_NFTABLES: &str = "nftables";
pub const SVC_SURICATA: &str = "suricata";
pub const SVC_DNS: &str = "dns";
pub const SVC_DHCP: &str = "dhcp";
pub const SVC_VPN: &str = "vpn";
pub const SVC_CROWDSEC: &str = "crowdsec";
pub const SVC_ACME: &str = "acme";
pub const SVC_CLOUDFLARED: &str = "cloudflared";

/// Shared application state.
///
/// All mutable fields are wrapped in [`RwLock`] so that handlers can hold read
/// locks concurrently and only serialise on writes.
pub struct AppState {
    /// Health map: `service_name -> is_healthy`.
    pub services: RwLock<HashMap<String, bool>>,
    /// In-memory list of configured network interfaces.
    pub interfaces: RwLock<Vec<Interface>>,
    /// In-memory list of active firewall rules.
    pub firewall_rules: RwLock<Vec<FirewallRule>>,
    /// Cached CrowdSec decisions fetched from the LAPI.
    pub crowdsec_decisions: RwLock<Vec<CrowdSecDecision>>,
    /// Persistent configuration store.
    pub config_store: ConfigStore,
    /// In-memory time-series buffer for metrics snapshots.
    pub metrics_buffer: RwLock<MetricsBuffer>,
    /// Sender side of the notification queue.
    pub notify_queue: NotifyQueue,
    /// Login attempt tracker: username → (consecutive_failures, lockout_until_unix_secs).
    ///
    /// Reset to zero on successful login.  The inner `Option<u64>` holds the
    /// Unix timestamp at which the lockout expires; `None` means not locked.
    pub login_attempts: RwLock<HashMap<String, (u32, Option<u64>)>>,
}

impl AppState {
    /// Create a new [`AppState`] with sensible defaults.
    ///
    /// All known services are initially marked as unhealthy until the
    /// corresponding engine confirms it is running.
    ///
    /// Returns `(AppState, notify_rx)` where `notify_rx` must be passed to
    /// [`crate::notify::worker::start_notify_worker`].
    pub fn new() -> (Self, tokio::sync::mpsc::Receiver<crate::notify::model::NotifyEvent>) {
        let mut services = HashMap::new();
        for name in [
            SVC_NFTABLES,
            SVC_SURICATA,
            SVC_DNS,
            SVC_DHCP,
            SVC_VPN,
            SVC_CROWDSEC,
            SVC_ACME,
            SVC_CLOUDFLARED,
        ] {
            services.insert(name.to_string(), false);
        }

        let (notify_queue, notify_rx) = NotifyQueue::new();

        let state = Self {
            services: RwLock::new(services),
            interfaces: RwLock::new(vec![]),
            firewall_rules: RwLock::new(vec![]),
            crowdsec_decisions: RwLock::new(vec![]),
            config_store: ConfigStore::new(),
            metrics_buffer: RwLock::new(MetricsBuffer::default()),
            notify_queue,
            login_attempts: RwLock::new(HashMap::new()),
        };
        (state, notify_rx)
    }

    /// Create a new [`AppState`] using a custom config directory (useful for
    /// tests that must not touch `/etc/dayshield`).
    pub fn with_config_dir(dir: impl AsRef<std::path::Path>) -> (Self, tokio::sync::mpsc::Receiver<crate::notify::model::NotifyEvent>) {
        let (mut state, rx) = Self::new();
        state.config_store = ConfigStore::with_dir(dir);
        (state, rx)
    }

    /// Mark a service as healthy.
    pub async fn set_healthy(self: &Arc<Self>, service: &str) {
        let mut map = self.services.write().await;
        map.insert(service.to_string(), true);
    }

    /// Mark a service as unhealthy.
    pub async fn set_unhealthy(self: &Arc<Self>, service: &str) {
        let mut map = self.services.write().await;
        map.insert(service.to_string(), false);
    }
}

impl Default for AppState {
    fn default() -> Self {
        // Drop the receiver; useful for tests that don't need the worker.
        let (state, _rx) = Self::new();
        state
    }
}
