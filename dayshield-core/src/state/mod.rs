//! State module — shared application state and service health tracking.
//!
//! [`AppState`] is the single source of truth for in-memory runtime data.
//! It is created once at startup, wrapped in an [`Arc`], and injected into
//! every Axum handler via Axum's `State` extractor.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;

use crate::config::{
    models::{FirewallRule, Interface},
    ConfigStore,
};

/// Known DayShield service names used as health-map keys.
pub const SVC_NFTABLES: &str = "nftables";
pub const SVC_SURICATA: &str = "suricata";
pub const SVC_DNS: &str = "dns";
pub const SVC_DHCP: &str = "dhcp";
pub const SVC_VPN: &str = "vpn";
pub const SVC_CROWDSEC: &str = "crowdsec";

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
    /// Persistent configuration store.
    pub config_store: ConfigStore,
}

impl AppState {
    /// Create a new [`AppState`] with sensible defaults.
    ///
    /// All known services are initially marked as unhealthy until the
    /// corresponding engine confirms it is running.
    pub fn new() -> Self {
        let mut services = HashMap::new();
        for name in [
            SVC_NFTABLES,
            SVC_SURICATA,
            SVC_DNS,
            SVC_DHCP,
            SVC_VPN,
            SVC_CROWDSEC,
        ] {
            services.insert(name.to_string(), false);
        }

        Self {
            services: RwLock::new(services),
            interfaces: RwLock::new(vec![]),
            firewall_rules: RwLock::new(vec![]),
            config_store: ConfigStore::new(),
        }
    }

    /// Create a new [`AppState`] using a custom config directory (useful for
    /// tests that must not touch `/etc/dayshield`).
    pub fn with_config_dir(dir: impl AsRef<std::path::Path>) -> Self {
        let mut state = Self::new();
        state.config_store = ConfigStore::with_dir(dir);
        state
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
        Self::new()
    }
}
