//! DNS engine - manages the Unbound recursive resolver.
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

use crate::config::models::{
    AcmeConfig,
    AcmeChallengeType,
    AcmeProvider,
    DnsConfig,
    DnsLocalRecord,
    DotConfig,
};

/// Path where Unbound's configuration file is written.
const UNBOUND_CONF_PATH: &str = "/etc/dayshield/unbound.conf";

/// Directory where DoT TLS certificate and key are stored.
const DOT_CERTS_DIR: &str = "/etc/dayshield/certs";
/// Path to the DoT TLS certificate file.
pub const DOT_CERT_PATH: &str = "/etc/dayshield/certs/dot.crt";
/// Path to the DoT TLS private key file.
pub const DOT_KEY_PATH: &str = "/etc/dayshield/certs/dot.key";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a complete Unbound configuration file as a `String`.
///
/// The generated file covers:
/// - `server:` block with listen interfaces/addresses, port, DNSSEC, and
///   privacy/hardening settings.
/// - Optional DoT TLS settings when `dot` is `Some` and `dot.enabled` is
///   `true`: `ssl-port`, `ssl-service-key`, `ssl-service-pem`, and an
///   additional `interface: 0.0.0.0@<port>` stanza so Unbound accepts both
///   plain DNS (port 53) and DoT (port 853) connections.
/// - `local-data:` entries for every [`DnsLocalRecord`] in `config`.
/// - `forward-zone:` block for each forwarder IP when `config.forwarders` is
///   non-empty (falls back to full recursion when the list is empty).
pub fn generate_config(config: &DnsConfig, dot: Option<&DotConfig>) -> String {
    let mut out = String::new();

    out.push_str("# DayShield - Unbound configuration (auto-generated; do not edit by hand)\n\n");

    out.push_str("server:\n");
    out.push_str("    verbosity: 1\n");
    out.push_str("    statistics-interval: 0\n");
    out.push_str("    statistics-cumulative: no\n");
    out.push_str("    num-threads: 1\n");

    // Listen addresses for plain DNS.
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
    out.push_str("    use-caps-for-id: yes\n");
    out.push_str("    module-config: \"validator iterator\"\n");
    out.push_str("    cache-min-ttl: 3600\n");
    out.push_str("    cache-max-ttl: 86400\n");
    out.push_str("    prefetch: yes\n");

    // DNSSEC.
    if config.dnssec {
        out.push_str("    auto-trust-anchor-file: \"/var/lib/unbound/root.key\"\n");
    } else {
        out.push_str("    # DNSSEC disabled\n");
    }

    // DNS-over-TLS settings.
    if let Some(dot) = dot {
        if dot.enabled {
            out.push_str(&format!("\n    # DNS-over-TLS (DoT)\n"));
            out.push_str(&format!("    ssl-port: {}\n", dot.port));
            out.push_str(&format!("    ssl-service-key: \"{DOT_KEY_PATH}\"\n"));
            out.push_str(&format!("    ssl-service-pem: \"{DOT_CERT_PATH}\"\n"));
            // Bind the DoT port on all interfaces so that both LAN and external
            // clients can connect.  Restrict access at the firewall layer if
            // finer-grained control is needed.
            out.push_str(&format!("    interface: 0.0.0.0@{}\n", dot.port));
        }
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

    // Forward zone - use the forwarder list when non-empty.
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
/// 1. If `dot` is `Some` and `dot.enabled`, write the TLS certificate and key
///    to [`DOT_CERT_PATH`] / [`DOT_KEY_PATH`] before generating the config.
/// 2. Generate `unbound.conf` via [`generate_config`].
/// 3. Write the file atomically to [`UNBOUND_CONF_PATH`].
/// 4. If Unbound is running, send it `unbound-control reload`; otherwise
///    attempt to start it with `systemctl start unbound`.
///
/// # Errors
///
/// Returns an error if the certificate/key files cannot be written, if the
/// configuration file cannot be written, or if the reload / start command
/// fails.
pub async fn apply_config(config: &DnsConfig, dot: Option<&DotConfig>) -> Result<()> {
    info!(
        enabled = config.enabled,
        forwarders = config.forwarders.len(),
        dnssec = config.dnssec,
        "dns: applying config"
    );

    if !config.enabled {
        info!("dns: service disabled - stopping Unbound");
        let _ = Command::new("systemctl")
            .args(["stop", "unbound"])
            .output()
            .await;
        return Ok(());
    }

    // Write DoT TLS files before generating the config so Unbound can find them.
    if let Some(dot) = dot {
        if dot.enabled {
            write_dot_tls_files(dot)?;
        }
    }

    let conf_str = generate_config(config, dot);
    write_config_atomic(UNBOUND_CONF_PATH, &conf_str)
        .with_context(|| {
            format!(
                "failed to write {} (check dayshield.service sandbox: ReadWritePaths should include /etc/unbound)",
                UNBOUND_CONF_PATH
            )
        })?;

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

/// Write the DoT TLS certificate and private key to their well-known paths.
///
/// The private key is written with mode `0o600` on Unix systems so it cannot
/// be read by unprivileged processes.  The certificate is written with mode
/// `0o644` (world-readable) since it is not secret.
fn write_dot_tls_files(dot: &DotConfig) -> Result<()> {
    // Ensure the certificates directory exists.
    std::fs::create_dir_all(DOT_CERTS_DIR)
        .with_context(|| format!("failed to create directory {DOT_CERTS_DIR}"))?;

    if let Some(acme_domain) = dot.acme_domain.as_ref().filter(|s| !s.trim().is_empty()) {
        let storage_path = dot
            .acme_cert_storage_path
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("Acme certificate storage path is required for ACME-based DoT certs"))?;

        let acme_cfg = AcmeConfig {
            enabled: false,
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            email: String::new(),
            domains: vec![acme_domain.clone()],
            challenge_type: AcmeChallengeType::Http01,
            renew_interval_hours: 24,
            provider: AcmeProvider::Custom,
            cert_storage_path: storage_path.clone(),
        };
        let acme_engine = crate::engine::acme::AcmeEngine::new(acme_cfg);
        let cert_path = acme_engine.cert_path(acme_domain);
        let key_path = acme_engine.key_path(acme_domain);

        let cert_bytes = std::fs::read(&cert_path)
            .with_context(|| format!("failed to read ACME cert from {cert_path:?}"))?;
        let key_bytes = std::fs::read(&key_path)
            .with_context(|| format!("failed to read ACME private key from {key_path:?}"))?;

        write_cert_file(DOT_CERT_PATH, &cert_bytes)?;
        write_key_restricted(DOT_KEY_PATH, &key_bytes)?;
    } else {
        let cert_pem = dot
            .cert_pem
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("DoT cert_pem is missing"))?;
        let key_pem = dot
            .key_pem
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("DoT key_pem is missing"))?;

        write_cert_file(DOT_CERT_PATH, cert_pem.as_bytes())?;
        write_key_restricted(DOT_KEY_PATH, key_pem.as_bytes())?;
    }

    info!(cert = DOT_CERT_PATH, key = DOT_KEY_PATH, "dot: TLS files written");
    Ok(())
}

/// Write `data` to `path` with mode `0o644`.
///
/// Uses a write-then-rename for atomicity on the same filesystem.  This is
/// the standard pattern used throughout the DayShield config layer.
#[cfg(unix)]
fn write_cert_file(path: &str, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = format!("{path}.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&tmp)
            .with_context(|| format!("failed to open temp cert file {tmp}"))?;
        f.write_all(data)
            .with_context(|| format!("failed to write temp cert file {tmp}"))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {tmp} to {path}"))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_cert_file(path: &str, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)
        .with_context(|| format!("failed to write cert file {path}"))?;
    Ok(())
}

/// Write `data` to `path` with mode `0o600` on Unix, or a plain write on
/// other platforms.
///
/// Uses a write-then-rename for atomicity on the same filesystem.  Each call
/// operates on a uniquely suffixed `.tmp` file so concurrent callers do not
/// interfere with each other's temporary files.
#[cfg(unix)]
fn write_key_restricted(path: &str, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = format!("{path}.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("failed to open temp key file {tmp}"))?;
        f.write_all(data)
            .with_context(|| format!("failed to write temp key file {tmp}"))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {tmp} to {path}"))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key_restricted(path: &str, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)
        .with_context(|| format!("failed to write key file {path}"))?;
    Ok(())
}

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
            interface_blocklists: vec![],
        }
    }

    fn dot_config() -> DotConfig {
        DotConfig {
            enabled: true,
            port: 853,
            cert_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n".into(),
        }
    }

    #[test]
    fn generate_config_contains_listen_address() {
        let cfg = base_config();
        let out = generate_config(&cfg, None);
        assert!(out.contains("interface: 127.0.0.1"), "should contain listen address");
    }

    #[test]
    fn generate_config_contains_port() {
        let cfg = base_config();
        let out = generate_config(&cfg, None);
        assert!(out.contains("port: 53"));
    }

    #[test]
    fn generate_config_forward_zone() {
        let cfg = base_config();
        let out = generate_config(&cfg, None);
        assert!(out.contains("forward-zone:"));
        assert!(out.contains("forward-addr: 1.1.1.1"));
        assert!(out.contains("forward-addr: 8.8.8.8"));
    }

    #[test]
    fn generate_config_no_forward_zone_when_empty() {
        let mut cfg = base_config();
        cfg.forwarders.clear();
        let out = generate_config(&cfg, None);
        assert!(!out.contains("forward-zone:"), "full recursion: no forward-zone expected");
    }

    #[test]
    fn generate_config_dnssec_enabled() {
        let mut cfg = base_config();
        cfg.dnssec = true;
        let out = generate_config(&cfg, None);
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
        let out = generate_config(&cfg, None);
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
        let out = generate_config(&cfg, None);
        assert!(!out.contains("UNKNOWN"));
    }

    #[test]
    fn generate_config_default_listen_when_empty() {
        let mut cfg = base_config();
        cfg.listen_addresses.clear();
        let out = generate_config(&cfg, None);
        assert!(out.contains("interface: 0.0.0.0"));
        assert!(!out.contains("interface: ::"));
    }

    #[test]
    fn generate_config_dot_enabled() {
        let cfg = base_config();
        let dot = dot_config();
        let out = generate_config(&cfg, Some(&dot));
        assert!(out.contains("ssl-port: 853"), "should contain ssl-port");
        assert!(out.contains(DOT_KEY_PATH), "should reference key path");
        assert!(out.contains(DOT_CERT_PATH), "should reference cert path");
        assert!(out.contains("interface: 0.0.0.0@853"), "should add DoT interface stanza");
    }

    #[test]
    fn generate_config_dot_disabled() {
        let cfg = base_config();
        let mut dot = dot_config();
        dot.enabled = false;
        let out = generate_config(&cfg, Some(&dot));
        assert!(!out.contains("ssl-port:"), "disabled DoT should not add ssl-port");
    }

    #[test]
    fn generate_config_dot_none() {
        let cfg = base_config();
        let out = generate_config(&cfg, None);
        assert!(!out.contains("ssl-port:"), "no DoT config should not add ssl-port");
    }

    #[test]
    fn generate_config_dot_custom_port() {
        let cfg = base_config();
        let mut dot = dot_config();
        dot.port = 8853;
        let out = generate_config(&cfg, Some(&dot));
        assert!(out.contains("ssl-port: 8853"));
        assert!(out.contains("interface: 0.0.0.0@8853"));
    }
}

