//! DHCP engine — manages the Kea or dnsmasq DHCP server.
//!
//! TODO: select backend (Kea vs dnsmasq) based on system config.
//! TODO: generate `kea-dhcp4.conf` / `dnsmasq.conf` from [`DhcpConfig`].
//! TODO: implement process lifecycle management (start / stop / reload).
//! TODO: implement static host reservation management.
//! TODO: expose active lease table via the REST API.
//! TODO: emit lease events to the metrics / logging layer.

use anyhow::Result;
use tracing::info;

use crate::config::models::DhcpConfig;

/// Apply the provided DHCP configuration to the running DHCP daemon.
///
/// TODO: choose between Kea and dnsmasq, generate the appropriate config file,
///       write it to disk, and reload the daemon.
pub async fn apply_config(config: &DhcpConfig) -> Result<()> {
    info!(
        enabled = config.enabled,
        scopes = config.scopes.len(),
        "dhcp: apply_config called (stub)"
    );
    Ok(())
}

/// Generate the DHCP server configuration file contents as a `String`.
///
/// TODO: implement full config generation for the selected backend.
pub fn generate_config(config: &DhcpConfig) -> String {
    // TODO: build complete DHCP config from `config`.
    format!(
        "# DayShield DHCP config (stub)\n\
         # enabled={}, scopes={}\n",
        config.enabled,
        config.scopes.len()
    )
}
