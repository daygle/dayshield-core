//! DNS engine — manages the Unbound recursive resolver.
//!
//! TODO: generate `unbound.conf` from [`DnsConfig`].
//! TODO: implement process lifecycle management (start / stop / reload).
//! TODO: implement local-zone and local-data record generation.
//! TODO: implement DNSSEC key-tag verification and trust-anchor management.
//! TODO: implement RPZ (Response Policy Zone) integration for ad/malware blocking.
//! TODO: expose DNS query statistics to the metrics layer.

use anyhow::Result;
use tracing::info;

use crate::config::models::DnsConfig;

/// Apply the provided DNS configuration to the running Unbound instance.
///
/// TODO: generate `unbound.conf`, write it to disk, and signal Unbound to
///       reload.
pub async fn apply_config(config: &DnsConfig) -> Result<()> {
    info!(
        enabled = config.enabled,
        forwarders = config.forwarders.len(),
        "dns: apply_config called (stub)"
    );
    Ok(())
}

/// Generate the Unbound configuration file contents as a `String`.
///
/// TODO: implement full `unbound.conf` template generation.
pub fn generate_config(config: &DnsConfig) -> String {
    // TODO: build complete unbound.conf from `config`.
    format!(
        "# DayShield Unbound config (stub)\n\
         # enabled={}, forwarders={}\n",
        config.enabled,
        config.forwarders.join(", ")
    )
}
