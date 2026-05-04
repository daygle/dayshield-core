//! DNS engine — manages the Unbound recursive resolver.
//!
//! # Overview
//!
//! This module translates a [`DnsConfig`] into a full `unbound.conf` file and
//! manages the Unbound process lifecycle (reload on config change).
//!
//! # Functions
//!
//! | Function            | Purpose                                              |
//! |---------------------|------------------------------------------------------|
//! | [`generate_config`] | Build a complete `unbound.conf` string.             |
//! | [`apply_config`]    | Write `unbound.conf` to disk and reload Unbound.    |

use std::path::Path;

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::models::{DnsConfig, DnsLocalRecord};

/// Path where Unbound's configuration file is written.
const UNBOUND_CONF_PATH: &str = "/etc/unbound/unbound.conf";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a complete Unbound configuration file as a `String`.
///
/// The generated file covers:
/// - `server:` block with listen interfaces/addresses, port, DNSSEC, and
///   privacy/hardening settings.
/// - `local-data:` entries for every [`DnsLocalRecord`] in `config`.
/// - `forward-zone:` block for each forwarder IP when `config.forwarders` is
///   non-empty (falls back to full recursion when the list is empty).
pub fn generate_config(config: &DnsConfig) -> String {
    let mut out = String::new();

    out.push_str("# DayShield — Unbound configuration (auto-generated; do not edit by hand)\n\n");

    out.push_str("server:\n");
    out.push_str("    verbosity: 1\n");
    out.push_str("    statistics-interval: 0\n");
    out.push_str("    statistics-cumulative: no\n");
    out.push_str("    num-threads: 1\n");

    // Listen addresses.
    if config.listen_addresses.is_empty() {
        out.push_str("    interface: 0.0.0.0\n");
    } else {
        for addr in &config.listen_addresses {
            out.push_str(&format!("    interface: {addr}\n"));
        }
    }

    out.push_str(&format!("    port: {}\n", config.port));
    out.push_str("    do-ip4: yes\n");
    out.push_str("    do-ip6: no\n");
    out.push_str("    do-udp: yes\n");
    out.push_str("    do-tcp: yes\n");

    // Privacy / hardening.
    out.push_str("    hide-identity: yes\n");
    out.push_str("    hide-version: yes\n");
    out.push_str("    harden-glue: yes\n");
    out.push_str("    harden-dnssec-stripped: yes\n");
    out.push_str("    use-caps-for-id: no\n");
    out.push_str("    cache-min-ttl: 3600\n");
    out.push_str("    cache-max-ttl: 86400\n");
    out.push_str("    prefetch: yes\n");

    // DNSSEC.
    if config.dnssec {
        out.push_str("    auto-trust-anchor-file: \"/var/lib/unbound/root.key\"\n");
        out.push_str("    val-clean-additional: yes\n");
    } else {
        out.push_str("    # DNSSEC disabled\n");
    }

    out.push('\n');

    // Local records (static A / AAAA overrides).
    for rec in &config.local_records {
        let line = build_local_data_line(rec);
        if let Some(l) = line {
            out.push_str(&format!("    local-data: \"{l}\"\n"));
        }
    }

    if !config.local_records.is_empty() {
        out.push('\n');
    }

    // Forward zone — use the forwarder list when non-empty.
    if !config.forwarders.is_empty() {
        out.push_str("forward-zone:\n");
        out.push_str("    name: \".\"\n");
        for fwd in &config.forwarders {
            out.push_str(&format!("    forward-addr: {fwd}\n"));
        }
        out.push('\n');
    }

    out
}

/// Apply the provided DNS configuration to the running Unbound instance.
///
/// Steps:
/// 1. Generate `unbound.conf` via [`generate_config`].
/// 2. Write the file atomically to [`UNBOUND_CONF_PATH`].
/// 3. If Unbound is running, send it `unbound-control reload`; otherwise
///    attempt to start it with `systemctl start unbound`.
///
/// # Errors
///
/// Returns an error if the configuration file cannot be written or if the
/// reload / start command fails.
pub async fn apply_config(config: &DnsConfig) -> Result<()> {
    info!(
        enabled = config.enabled,
        forwarders = config.forwarders.len(),
        dnssec = config.dnssec,
        "dns: applying config"
    );

    if !config.enabled {
        info!("dns: service disabled — stopping Unbound");
        let _ = Command::new("systemctl")
            .args(["stop", "unbound"])
            .output()
            .await;
        return Ok(());
    }

    let conf_str = generate_config(config);
    write_config_atomic(UNBOUND_CONF_PATH, &conf_str)
        .context("failed to write unbound.conf")?;

    info!(path = UNBOUND_CONF_PATH, "dns: unbound.conf written");

    // Try a live reload first; fall back to a full service start.
    let reload = Command::new("unbound-control")
        .arg("reload")
        .output()
        .await;

    match reload {
        Ok(out) if out.status.success() => {
            info!("dns: unbound-control reload succeeded");
        }
        Ok(out) => {
            warn!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "dns: unbound-control reload failed; attempting systemctl start unbound"
            );
            start_unbound().await?;
        }
        Err(e) => {
            warn!(error = %e, "dns: unbound-control not available; attempting systemctl start unbound");
            start_unbound().await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Format a [`DnsLocalRecord`] as a single Unbound `local-data` value.
///
/// Returns `None` for unrecognised record types.
fn build_local_data_line(rec: &DnsLocalRecord) -> Option<String> {
    let rtype = rec.record_type.to_uppercase();
    match rtype.as_str() {
        "A" | "AAAA" | "CNAME" | "PTR" | "MX" | "TXT" => {
            Some(format!("{} IN {} {}", rec.name, rtype, rec.value))
        }
        _ => {
            warn!(
                name = %rec.name,
                record_type = %rec.record_type,
                "dns: unsupported record type; skipping"
            );
            None
        }
    }
}

/// Write `content` to `path` using an atomic rename.
fn write_config_atomic(path: &str, content: &str) -> Result<()> {
    let tmp = format!("{path}.tmp");

    // Ensure the parent directory exists.
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    std::fs::write(&tmp, content)
        .with_context(|| format!("failed to write temporary file {tmp}"))?;

    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {tmp} to {path}"))?;

    Ok(())
}

/// Start the Unbound service via systemctl.
async fn start_unbound() -> Result<()> {
    let out = Command::new("systemctl")
        .args(["start", "unbound"])
        .output()
        .await
        .context("failed to spawn systemctl")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("systemctl start unbound failed: {stderr}");
    }

    info!("dns: unbound started via systemctl");
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{DnsLocalRecord};

    fn base_config() -> DnsConfig {
        DnsConfig {
            enabled: true,
            listen_addresses: vec!["127.0.0.1".into()],
            port: 53,
            forwarders: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            dnssec: false,
            local_records: vec![],
        }
    }

    #[test]
    fn generate_config_contains_listen_address() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("interface: 127.0.0.1"), "should contain listen address");
    }

    #[test]
    fn generate_config_contains_port() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("port: 53"));
    }

    #[test]
    fn generate_config_forward_zone() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("forward-zone:"));
        assert!(out.contains("forward-addr: 1.1.1.1"));
        assert!(out.contains("forward-addr: 8.8.8.8"));
    }

    #[test]
    fn generate_config_no_forward_zone_when_empty() {
        let mut cfg = base_config();
        cfg.forwarders.clear();
        let out = generate_config(&cfg);
        assert!(!out.contains("forward-zone:"), "full recursion: no forward-zone expected");
    }

    #[test]
    fn generate_config_dnssec_enabled() {
        let mut cfg = base_config();
        cfg.dnssec = true;
        let out = generate_config(&cfg);
        assert!(out.contains("auto-trust-anchor-file"));
    }

    #[test]
    fn generate_config_local_records() {
        let mut cfg = base_config();
        cfg.local_records.push(DnsLocalRecord {
            name: "host.local.".into(),
            record_type: "A".into(),
            value: "192.168.1.10".into(),
        });
        let out = generate_config(&cfg);
        assert!(out.contains("local-data: \"host.local. IN A 192.168.1.10\""));
    }

    #[test]
    fn generate_config_skips_unknown_record_type() {
        let mut cfg = base_config();
        cfg.local_records.push(DnsLocalRecord {
            name: "host.local.".into(),
            record_type: "UNKNOWN".into(),
            value: "value".into(),
        });
        let out = generate_config(&cfg);
        assert!(!out.contains("UNKNOWN"));
    }

    #[test]
    fn generate_config_default_listen_when_empty() {
        let mut cfg = base_config();
        cfg.listen_addresses.clear();
        let out = generate_config(&cfg);
        assert!(out.contains("interface: 0.0.0.0"));
        assert!(out.contains("interface: ::"));
    }
}

