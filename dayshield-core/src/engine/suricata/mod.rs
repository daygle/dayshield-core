//! Suricata engine — manages the Suricata IPS/IDS process and rule sets.
//!
//! TODO: implement Suricata process lifecycle management (start/stop/reload).
//! TODO: generate `suricata.yaml` from `SystemConfig`.
//! TODO: implement rule-set download and update via suricata-update.
//! TODO: expose per-interface capture configuration (AF_PACKET / nfqueue).
//! TODO: parse EVE JSON logs and forward alerts to the metrics layer.
//! TODO: integrate CrowdSec bouncer for automatic IP bans on IPS alerts.

use anyhow::Result;
use tracing::info;

/// Ensure Suricata is running with an up-to-date configuration.
///
/// TODO: diff the current running config against the new one and reload only
///       if a change is detected.
pub async fn apply_config() -> Result<()> {
    info!("suricata: apply_config called (stub)");
    Ok(())
}

/// Download and install the latest Suricata rule sets.
///
/// TODO: shell out to `suricata-update` and reload the rule engine.
pub async fn update_rules() -> Result<()> {
    info!("suricata: update_rules called (stub)");
    Ok(())
}

/// Reload the Suricata process without dropping network packets.
///
/// TODO: send SIGUSR2 to the Suricata process.
pub async fn reload() -> Result<()> {
    info!("suricata: reload called (stub)");
    Ok(())
}
