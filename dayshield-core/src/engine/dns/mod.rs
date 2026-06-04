//! DNS engine - manages the Unbound recursive resolver.
//!
//! # Overview
//!
//! This module translates a [`DnsConfig`] into a full `unbound.conf` file and
//! manages the Unbound process lifecycle (reload on config change).
//!
//! # Functions
//!
//! | Function                       | Purpose                                   |
//! |--------------------------------|-------------------------------------------|
//! | [`generate_config`]            | Build a complete `unbound.conf` string.   |
//! | [`apply_config_with_overrides`]| Write `unbound.conf` to disk, reload Unbound. |

use std::{io::ErrorKind, net::IpAddr, path::Path};

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::models::{
    AcmeChallengeType, AcmeConfig, AcmeDnsProvider, DnsClientAclPreset, DnsConfig,
    DnsDomainOverride, DnsHostOverride, DnsLocalRecord, DnsResolverMode, DotConfig,
};

/// Path where Unbound's configuration file is written.  Persisted under
/// `/var/lib` so DNS settings survive rootfs A/B updates.  The base
/// /etc/unbound/unbound.conf includes from this path.
const UNBOUND_CONF_PATH: &str = "/var/lib/dayshield/unbound/dayshield.conf";
pub const DNSSEC_ROOT_KEY_PATH: &str = "/var/lib/unbound/root.key";

/// Directory where DoT TLS certificate and key are stored.
const DOT_CERTS_DIR: &str = "/var/lib/dayshield/certs";
/// Path to the DoT TLS certificate file.
pub const DOT_CERT_PATH: &str = "/var/lib/dayshield/certs/dot.crt";
/// Path to the DoT TLS private key file.
pub const DOT_KEY_PATH: &str = "/var/lib/dayshield/certs/dot.key";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate the DayShield-managed Unbound include fragment as a `String`.
///
/// The generated file covers:
/// - `server:` block contents with listen interfaces/addresses, port, DNSSEC,
///   and privacy/hardening settings.
/// - Optional DoT TLS settings when `dot` is `Some` and `dot.enabled` is
///   `true`: `tls-port`, `tls-service-key`, `tls-service-pem`, and an
///   additional `interface: 0.0.0.0@<port>` stanza so Unbound accepts both
///   plain DNS (port 53) and DoT (port 853) connections.
/// - `local-data:` entries for every [`DnsLocalRecord`] in `config`.
/// - `forward-zone:` block for each forwarder IP when resolver mode is
///   `forwarded` and `config.forwarders` is non-empty.
///
/// The base DayShield rootfs includes this file from inside the primary
/// `server:` block, so the fragment must not declare another top-level
/// `server:` stanza.
pub fn generate_config(config: &DnsConfig, dot: Option<&DotConfig>) -> String {
    generate_config_with_overrides(config, dot, false, &[], &[])
}

/// Generate the DayShield-managed Unbound include fragment for the current IPv6 mode.
pub fn generate_config_with_ipv6(
    config: &DnsConfig,
    dot: Option<&DotConfig>,
    ipv6_enabled: bool,
) -> String {
    generate_config_with_overrides(config, dot, ipv6_enabled, &[], &[])
}

/// Generate the DayShield-managed Unbound include fragment for the full DNS runtime.
pub fn generate_config_with_overrides(
    config: &DnsConfig,
    dot: Option<&DotConfig>,
    ipv6_enabled: bool,
    host_overrides: &[DnsHostOverride],
    domain_overrides: &[DnsDomainOverride],
) -> String {
    let mut out = String::new();

    out.push_str("# DayShield - Unbound configuration fragment (auto-generated; do not edit by hand)\n\n");

    out.push_str("    verbosity: 1\n");
    out.push_str("    statistics-interval: 0\n");
    out.push_str("    statistics-cumulative: no\n");
    out.push_str("    num-threads: 1\n");

    // Listen addresses for plain DNS.
    if config.listen_addresses.is_empty() {
        out.push_str("    interface: 0.0.0.0\n");
        if ipv6_enabled {
            out.push_str("    interface: ::0\n");
        }
    } else {
        for addr in &config.listen_addresses {
            out.push_str(&format!("    interface: {addr}\n"));
        }
    }

    out.push_str(&format!("    port: {}\n", config.port));
    out.push_str("    do-ip4: yes\n");
    out.push_str(&format!(
        "    do-ip6: {}\n",
        if ipv6_enabled { "yes" } else { "no" }
    ));
    out.push_str("    do-udp: yes\n");
    out.push_str("    do-tcp: yes\n");
    append_access_controls(&mut out, config, dot, ipv6_enabled);

    // Privacy / hardening.
    out.push_str("    hide-identity: yes\n");
    out.push_str("    hide-version: yes\n");
    out.push_str("    harden-glue: yes\n");
    out.push_str("    use-caps-for-id: yes\n");
    if config.dnssec {
        out.push_str("    harden-dnssec-stripped: yes\n");
        out.push_str("    module-config: \"validator iterator\"\n");
    } else {
        out.push_str("    harden-dnssec-stripped: no\n");
        out.push_str("    module-config: \"iterator\"\n");
    }
    out.push_str(&format!(
        "    cache-min-ttl: {}\n",
        config.cache.min_ttl_seconds
    ));
    out.push_str(&format!(
        "    cache-max-ttl: {}\n",
        config.cache.max_ttl_seconds
    ));
    out.push_str(&format!(
        "    prefetch: {}\n",
        yes_no(config.cache.prefetch)
    ));
    out.push_str(&format!(
        "    serve-expired: {}\n",
        yes_no(config.cache.serve_expired)
    ));
    if config.cache.serve_expired {
        out.push_str(&format!(
            "    serve-expired-ttl: {}\n",
            config.cache.serve_expired_ttl_seconds
        ));
    }

    // DNSSEC.
    if config.dnssec {
        out.push_str(&format!(
            "    auto-trust-anchor-file: \"{DNSSEC_ROOT_KEY_PATH}\"\n"
        ));
    } else {
        out.push_str("    # DNSSEC disabled\n");
    }

    // DNS-over-TLS settings.
    if let Some(dot) = dot {
        if dot.enabled {
            out.push_str("\n    # DNS-over-TLS (DoT)\n");
            out.push_str(&format!("    tls-port: {}\n", dot.port));
            out.push_str(&format!("    tls-service-key: \"{DOT_KEY_PATH}\"\n"));
            out.push_str(&format!("    tls-service-pem: \"{DOT_CERT_PATH}\"\n"));
            // Bind the DoT port on all interfaces so that both LAN and external
            // clients can connect.  Restrict access at the firewall layer if
            // finer-grained control is needed.
            out.push_str(&format!("    interface: 0.0.0.0@{}\n", dot.port));
            if ipv6_enabled {
                out.push_str(&format!("    interface: ::0@{}\n", dot.port));
            }
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
    for ov in host_overrides {
        let record_type = match ov.address.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => "A",
            Ok(IpAddr::V6(_)) => "AAAA",
            Err(_) => {
                warn!(
                    hostname = %ov.hostname,
                    address = %ov.address,
                    "dns: invalid host override address; skipping"
                );
                continue;
            }
        };
        out.push_str(&format!(
            "    local-data: \"{} IN {} {}\"\n",
            ov.hostname, record_type, ov.address
        ));
    }

    if !config.local_records.is_empty() || !host_overrides.is_empty() {
        out.push('\n');
    }

    for ov in domain_overrides {
        out.push_str("forward-zone:\n");
        out.push_str(&format!("    name: \"{}\"\n", ov.domain));
        out.push_str(&format!("    forward-addr: {}\n\n", ov.forward_to));
    }

    // Forward zone - use the forwarder list only in forwarded mode.
    if matches!(config.resolver_mode, DnsResolverMode::Forwarded) && !config.forwarders.is_empty() {
        out.push_str("forward-zone:\n");
        out.push_str("    name: \".\"\n");
        for fwd in &config.forwarders {
            out.push_str(&format!("    forward-addr: {fwd}\n"));
        }
        out.push('\n');
    }

    out
}

/// Apply the provided DNS configuration, including persisted host/domain overrides.
///
/// Steps:
/// 1. If `dot` is `Some` and `dot.enabled`, write the TLS certificate and key
///    to [`DOT_CERT_PATH`] / [`DOT_KEY_PATH`] before generating the config.
/// 2. Generate `unbound.conf` via [`generate_config_with_overrides`].
/// 3. Write the file atomically to [`UNBOUND_CONF_PATH`].
/// 4. Validate the generated config with `unbound-checkconf` when available.
/// 5. Apply the change with `systemctl reload-or-restart unbound`, or with a
///    full restart when the requested change cannot be safely reloaded.
///
/// # Errors
///
/// Returns an error if the certificate/key files cannot be written, if the
/// configuration file cannot be written, or if the reload / start command
/// fails.
pub async fn apply_config_with_overrides(
    config: &DnsConfig,
    dot: Option<&DotConfig>,
    ipv6_enabled: bool,
    host_overrides: &[DnsHostOverride],
    domain_overrides: &[DnsDomainOverride],
) -> Result<()> {
    info!(
        enabled = config.enabled,
        forwarders = config.forwarders.len(),
        dnssec = config.dnssec,
        ipv6_enabled,
        host_overrides = host_overrides.len(),
        domain_overrides = domain_overrides.len(),
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

    // /var/lib/unbound is outside dayshield's ReadWritePaths sandbox; anchor
    // bootstrapping belongs to unbound.service ExecStartPre. We only check
    // readiness here so we can skip unbound-checkconf (which fails hard on a
    // missing anchor) and let unbound bootstrap the file on its next start.
    let anchor_ready = !config.dnssec || dnssec_root_anchor_ready();
    if config.dnssec && !anchor_ready {
        warn!(
            path = DNSSEC_ROOT_KEY_PATH,
            "dns: DNSSEC root anchor not yet present; unbound will bootstrap it on next start"
        );
    }

    let conf_str =
        generate_config_with_overrides(config, dot, ipv6_enabled, host_overrides, domain_overrides);
    write_config_atomic(UNBOUND_CONF_PATH, &conf_str)
        .with_context(|| {
            format!(
                "failed to write {} (check dayshield.service sandbox: ReadWritePaths should include /var/lib/dayshield/unbound)",
                UNBOUND_CONF_PATH
            )
        })?;

    info!(path = UNBOUND_CONF_PATH, "dns: unbound.conf written");

    if anchor_ready {
        check_unbound_config().await?;
    } else {
        warn!("dns: skipping config validation: DNSSEC anchor missing; will validate on next apply");
    }
    apply_unbound_runtime(needs_unbound_restart(config, dot)).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn append_access_controls(
    out: &mut String,
    config: &DnsConfig,
    dot: Option<&DotConfig>,
    ipv6_enabled: bool,
) {
    let public_dot = dot
        .filter(|dot| dot.enabled)
        .map(|dot| !dot.lan_only)
        .unwrap_or(false);

    if public_dot || matches!(config.client_acl_preset, DnsClientAclPreset::AllowAll) {
        out.push_str("    access-control: 0.0.0.0/0 allow\n");
        if ipv6_enabled {
            out.push_str("    access-control: ::0/0 allow\n");
        }
        return;
    }

    out.push_str("    access-control: 0.0.0.0/0 refuse\n");
    out.push_str("    access-control: 127.0.0.0/8 allow\n");

    match config.client_acl_preset {
        DnsClientAclPreset::PrivateRanges => {
            out.push_str("    access-control: 10.0.0.0/8 allow\n");
            out.push_str("    access-control: 172.16.0.0/12 allow\n");
            out.push_str("    access-control: 192.168.0.0/16 allow\n");
            out.push_str("    access-control: 100.64.0.0/10 allow\n");
            out.push_str("    access-control: 169.254.0.0/16 allow\n");
        }
        DnsClientAclPreset::Custom => {
            for cidr in &config.client_acl_custom_cidrs {
                if !cidr.contains(':') {
                    out.push_str(&format!("    access-control: {} allow\n", cidr.trim()));
                }
            }
        }
        DnsClientAclPreset::LocalhostOnly | DnsClientAclPreset::AllowAll => {}
    }

    if ipv6_enabled {
        out.push_str("    access-control: ::0/0 refuse\n");
        out.push_str("    access-control: ::1/128 allow\n");
        match config.client_acl_preset {
            DnsClientAclPreset::PrivateRanges => {
                out.push_str("    access-control: fc00::/7 allow\n");
                out.push_str("    access-control: fe80::/10 allow\n");
            }
            DnsClientAclPreset::Custom => {
                for cidr in &config.client_acl_custom_cidrs {
                    if cidr.contains(':') {
                        out.push_str(&format!("    access-control: {} allow\n", cidr.trim()));
                    }
                }
            }
            DnsClientAclPreset::LocalhostOnly | DnsClientAclPreset::AllowAll => {}
        }
    }
}

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
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Acme certificate storage path is required for ACME-based DoT certs"
                )
            })?;

        let acme_cfg = AcmeConfig {
            enabled: false,
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            email: String::new(),
            domains: vec![acme_domain.clone()],
            challenge_type: AcmeChallengeType::Http01,
            renew_interval_hours: 24,
            dns_provider: AcmeDnsProvider::Manual,
            cloudflare_zone_id: None,
            cloudflare_api_token: None,
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

    info!(
        cert = DOT_CERT_PATH,
        key = DOT_KEY_PATH,
        "dot: TLS files written"
    );
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
    std::fs::rename(&tmp, path).with_context(|| format!("failed to rename {tmp} to {path}"))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_cert_file(path: &str, data: &[u8]) -> Result<()> {
    std::fs::write(path, data).with_context(|| format!("failed to write cert file {path}"))?;
    Ok(())
}

/// Write `data` to `path` with mode `0o600` on Unix, or a plain write on
/// other platforms.
///
/// Uses a write-then-rename for atomicity on the same filesystem.
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
    std::fs::rename(&tmp, path).with_context(|| format!("failed to rename {tmp} to {path}"))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key_restricted(path: &str, data: &[u8]) -> Result<()> {
    std::fs::write(path, data).with_context(|| format!("failed to write key file {path}"))?;
    Ok(())
}

/// Format a [`DnsLocalRecord`] as a single Unbound `local-data` value.
///
/// Returns `None` for unrecognised record types.
fn build_local_data_line(rec: &DnsLocalRecord) -> Option<String> {
    let rtype = rec.record_type.to_uppercase();
    match rtype.as_str() {
        "A" | "AAAA" | "CNAME" | "PTR" | "MX" | "TXT" => {
            let value = if rtype == "TXT" {
                format!("\\\"{}\\\"", escape_unbound_txt(&rec.value))
            } else {
                rec.value.clone()
            };
            Some(format!("{} IN {} {}", rec.name, rtype, value))
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

fn escape_unbound_txt(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
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

    std::fs::rename(&tmp, path).with_context(|| format!("failed to rename {tmp} to {path}"))?;

    Ok(())
}

/// Check that a usable DNSSEC trust anchor exists at [`DNSSEC_ROOT_KEY_PATH`].
///
/// `/var/lib/unbound` is owned by the unbound service and is outside the
/// dayshield.service `ReadWritePaths` sandbox, so we cannot write there.
/// Bootstrapping the anchor is the responsibility of `unbound.service`'s
/// `ExecStartPre` (`unbound-anchor-prepare.sh`). This function only signals
/// whether the anchor is ready so the caller can decide to skip
/// `unbound-checkconf` — which fails hard on a missing anchor file — and
/// let unbound bootstrap it on its next start.
fn dnssec_root_anchor_ready() -> bool {
    let path = Path::new(DNSSEC_ROOT_KEY_PATH);
    path.exists() && std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) > 0
}

async fn check_unbound_config() -> Result<()> {
    run_unbound_checkconf_fragment(UNBOUND_CONF_PATH).await?;
    run_unbound_checkconf(None).await
}

async fn run_unbound_checkconf(config_path: Option<&str>) -> Result<()> {
    let mut cmd = Command::new("unbound-checkconf");
    if let Some(config_path) = config_path {
        cmd.arg(config_path);
    }

    let out = match cmd.output().await {
        Ok(out) => out,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            warn!("dns: unbound-checkconf not found; skipping preflight config validation");
            return Ok(());
        }
        Err(err) => return Err(err).context("failed to spawn unbound-checkconf"),
    };

    if !out.status.success() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let target = config_path.unwrap_or("system default config");
        anyhow::bail!(
            "unbound-checkconf failed for {target}: {}{}{}",
            stdout.trim(),
            if stdout.trim().is_empty() || stderr.trim().is_empty() {
                ""
            } else {
                "\n"
            },
            stderr.trim()
        );
    }

    Ok(())
}

async fn run_unbound_checkconf_fragment(fragment_path: &str) -> Result<()> {
    let wrapper_path = format!("{fragment_path}.checkconf");
    let wrapper = format!(
        "server:\n    include: \"{fragment_path}\"\n"
    );

    std::fs::write(&wrapper_path, wrapper)
        .with_context(|| format!("failed to write temporary file {wrapper_path}"))?;

    let result = run_unbound_checkconf(Some(&wrapper_path)).await;
    let _ = std::fs::remove_file(&wrapper_path);
    result
}

fn needs_unbound_restart(config: &DnsConfig, dot: Option<&DotConfig>) -> bool {
    dot.is_some()
        || config
            .listen_addresses
            .iter()
            .any(|addr| addr.parse::<IpAddr>().is_err())
}

/// Apply the Unbound service change.
///
/// Plain DNS config can be reloaded to preserve cache. TLS listener changes
/// and interface-name listener changes require a full restart in Unbound.
async fn apply_unbound_runtime(restart: bool) -> Result<()> {
    let action = if restart {
        "restart"
    } else {
        "reload-or-restart"
    };
    let out = Command::new("systemctl")
        .args([action, "unbound"])
        .output()
        .await
        .context("failed to spawn systemctl")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("systemctl {action} unbound failed: {stderr}");
    }

    info!(action, "dns: unbound reconciled via systemctl");
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{DnsCacheConfig, DnsLocalRecord};

    fn base_config() -> DnsConfig {
        DnsConfig {
            enabled: true,
            listen_addresses: vec!["127.0.0.1".into()],
            port: 53,
            resolver_mode: DnsResolverMode::Forwarded,
            forwarders: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            dnssec: false,
            client_acl_preset: DnsClientAclPreset::PrivateRanges,
            client_acl_custom_cidrs: vec![],
            cache: DnsCacheConfig::default(),
            local_records: vec![],
            interface_blocklists: vec![],
            manage_firewall: true,
        }
    }

    fn dot_config() -> DotConfig {
        DotConfig {
            enabled: true,
            port: 853,
            lan_only: true,
            cert_pem: Some(
                "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n".to_string(),
            ),
            key_pem: Some(
                "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n".to_string(),
            ),
            acme_domain: None,
            acme_cert_storage_path: None,
        }
    }

    #[test]
    fn generate_config_contains_listen_address() {
        let cfg = base_config();
        let out = generate_config(&cfg, None);
        assert!(
            out.contains("interface: 127.0.0.1"),
            "should contain listen address"
        );
        assert!(
            !out.contains("\nserver:\n"),
            "managed include should not add a nested server block"
        );
    }

    #[test]
    fn generate_config_contains_port() {
        let cfg = base_config();
        let out = generate_config(&cfg, None);
        assert!(out.contains("port: 53"));
    }

    #[test]
    fn generate_config_contains_resolver_access_controls() {
        let cfg = base_config();
        let out = generate_config(&cfg, None);
        assert!(out.contains("access-control: 0.0.0.0/0 refuse"));
        assert!(out.contains("access-control: 127.0.0.0/8 allow"));
        assert!(out.contains("access-control: 192.168.0.0/16 allow"));
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
        assert!(
            !out.contains("forward-zone:"),
            "full recursion: no forward-zone expected"
        );
    }

    #[test]
    fn generate_config_recursive_mode_ignores_saved_forwarders() {
        let mut cfg = base_config();
        cfg.resolver_mode = DnsResolverMode::Recursive;
        let out = generate_config(&cfg, None);
        assert!(
            !out.contains("forward-zone:"),
            "recursive mode should not render global forwarders"
        );
    }

    #[test]
    fn generate_config_custom_client_acl() {
        let mut cfg = base_config();
        cfg.client_acl_preset = DnsClientAclPreset::Custom;
        cfg.client_acl_custom_cidrs = vec!["192.0.2.0/24".into(), "fd00:1234::/64".into()];
        let out = generate_config_with_ipv6(&cfg, None, true);
        assert!(out.contains("access-control: 0.0.0.0/0 refuse"));
        assert!(out.contains("access-control: 192.0.2.0/24 allow"));
        assert!(out.contains("access-control: fd00:1234::/64 allow"));
        assert!(!out.contains("access-control: 10.0.0.0/8 allow"));
    }

    #[test]
    fn generate_config_renders_cache_controls() {
        let mut cfg = base_config();
        cfg.cache = DnsCacheConfig {
            min_ttl_seconds: 60,
            max_ttl_seconds: 7200,
            prefetch: false,
            serve_expired: true,
            serve_expired_ttl_seconds: 900,
        };
        let out = generate_config(&cfg, None);
        assert!(out.contains("cache-min-ttl: 60"));
        assert!(out.contains("cache-max-ttl: 7200"));
        assert!(out.contains("prefetch: no"));
        assert!(out.contains("serve-expired: yes"));
        assert!(out.contains("serve-expired-ttl: 900"));
    }

    #[test]
    fn generate_config_dnssec_enabled() {
        let mut cfg = base_config();
        cfg.dnssec = true;
        let out = generate_config(&cfg, None);
        assert!(out.contains("auto-trust-anchor-file"));
        assert!(out.contains("module-config: \"validator iterator\""));
    }

    #[test]
    fn generate_config_dnssec_disabled_uses_iterator_only() {
        let cfg = base_config();
        let out = generate_config(&cfg, None);
        assert!(out.contains("harden-dnssec-stripped: no"));
        assert!(out.contains("module-config: \"iterator\""));
        assert!(!out.contains("auto-trust-anchor-file"));
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
    fn generate_config_quotes_txt_records() {
        let mut cfg = base_config();
        cfg.local_records.push(DnsLocalRecord {
            name: "txt.local.".into(),
            record_type: "TXT".into(),
            value: "hello \"day\" shield".into(),
        });
        let out = generate_config(&cfg, None);
        assert!(out.contains(r#"local-data: "txt.local. IN TXT \"hello \"day\" shield\"""#));
    }

    #[test]
    fn generate_config_renders_dns_overrides() {
        let cfg = base_config();
        let host_overrides = vec![
            DnsHostOverride {
                hostname: "host.local.".into(),
                address: "192.168.1.20".into(),
            },
            DnsHostOverride {
                hostname: "v6.local.".into(),
                address: "fd00::20".into(),
            },
        ];
        let domain_overrides = vec![DnsDomainOverride {
            domain: "corp.local.".into(),
            forward_to: "10.0.0.53".into(),
        }];
        let out =
            generate_config_with_overrides(&cfg, None, true, &host_overrides, &domain_overrides);
        assert!(out.contains("local-data: \"host.local. IN A 192.168.1.20\""));
        assert!(out.contains("local-data: \"v6.local. IN AAAA fd00::20\""));
        assert!(out.contains("name: \"corp.local.\""));
        assert!(out.contains("forward-addr: 10.0.0.53"));
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
    fn generate_config_with_ipv6_includes_default_ipv6_listen() {
        let mut cfg = base_config();
        cfg.listen_addresses.clear();
        let out = generate_config_with_ipv6(&cfg, None, true);
        assert!(out.contains("interface: 0.0.0.0"));
        assert!(out.contains("interface: ::0"));
        assert!(out.contains("do-ip6: yes"));
    }

    #[test]
    fn generate_config_dot_enabled() {
        let cfg = base_config();
        let dot = dot_config();
        let out = generate_config(&cfg, Some(&dot));
        assert!(out.contains("tls-port: 853"), "should contain tls-port");
        assert!(out.contains(DOT_KEY_PATH), "should reference key path");
        assert!(out.contains(DOT_CERT_PATH), "should reference cert path");
        assert!(
            out.contains("interface: 0.0.0.0@853"),
            "should add DoT interface stanza"
        );
    }

    #[test]
    fn generate_config_public_dot_allows_public_clients() {
        let cfg = base_config();
        let mut dot = dot_config();
        dot.lan_only = false;
        let out = generate_config_with_ipv6(&cfg, Some(&dot), true);
        assert!(out.contains("access-control: 0.0.0.0/0 allow"));
        assert!(out.contains("access-control: ::0/0 allow"));
        assert!(!out.contains("access-control: 0.0.0.0/0 refuse"));
    }

    #[test]
    fn generate_config_dot_disabled() {
        let cfg = base_config();
        let mut dot = dot_config();
        dot.enabled = false;
        let out = generate_config(&cfg, Some(&dot));
        assert!(
            !out.contains("tls-port:"),
            "disabled DoT should not add tls-port"
        );
    }

    #[test]
    fn generate_config_dot_none() {
        let cfg = base_config();
        let out = generate_config(&cfg, None);
        assert!(
            !out.contains("tls-port:"),
            "no DoT config should not add tls-port"
        );
    }

    #[test]
    fn generate_config_dot_custom_port() {
        let cfg = base_config();
        let mut dot = dot_config();
        dot.port = 8853;
        let out = generate_config(&cfg, Some(&dot));
        assert!(out.contains("tls-port: 8853"));
        assert!(out.contains("interface: 0.0.0.0@8853"));
    }

    #[test]
    fn generate_config_dot_adds_ipv6_listener_when_ipv6_enabled() {
        let cfg = base_config();
        let dot = dot_config();
        let out = generate_config_with_ipv6(&cfg, Some(&dot), true);
        assert!(out.contains("tls-port: 853"));
        assert!(out.contains("interface: 0.0.0.0@853"));
        assert!(out.contains("interface: ::0@853"));
    }

    #[test]
    fn unbound_restart_needed_for_dot_or_interface_names() {
        let cfg = base_config();
        assert!(!needs_unbound_restart(&cfg, None));

        let dot = dot_config();
        assert!(needs_unbound_restart(&cfg, Some(&dot)));

        let mut iface_cfg = base_config();
        iface_cfg.listen_addresses = vec!["eth1".into()];
        assert!(needs_unbound_restart(&iface_cfg, None));
    }
}
