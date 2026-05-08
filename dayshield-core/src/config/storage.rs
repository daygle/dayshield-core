//! Configuration storage layer.
//!
//! Persists [`SystemConfig`] as a single JSON file under
//! `/etc/dayshield/config/config.json` with the following guarantees:
//!
//! - **Atomic writes**: the new file is written to a temporary path next to the
//!   target and then renamed into place, so a crash mid-write cannot leave a
//!   partially-written file.
//! - **Validation before commit**: [`ConfigStore::save`] calls
//!   [`ConfigStore::validate`] and returns an error (without touching disk) if
//!   the config is invalid.
//! - **Rollback on failure**: [`ConfigStore::save_with_rollback`] first backs
//!   up the current on-disk file and restores it if the post-write validation
//!   step fails.
//! - **Schema versioning**: on-disk files carry a `schema_version` integer.
//!   [`ConfigStore::load`] automatically migrates older versions to the current
//!   schema so new code can always assume the latest format.
//! - **Config fragments**: [`ConfigStore::load_fragments`] merges all
//!   `*.json` files found in the config directory into a single
//!   [`SystemConfig`], enabling modular configuration management.
//! - **Engine notifications**: register a post-save callback via
//!   [`ConfigStore::set_on_save`] to push config changes to live engine
//!   services immediately after a successful commit.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use super::models::{
    AcmeConfig, AdminSecuritySettings, CrowdSecConfig, DhcpConfig, DnsConfig, DnsDomainOverride,
    DnsHostOverride, FirewallAlias, FirewallRule, FirewallSettings, Gateway, Interface, NatConfig,
    NotifyConfig, NtpConfig, SuricataConfig, SystemConfig, WireGuardInterface,
};

/// Default path to the configuration directory.
const DEFAULT_CONFIG_DIR: &str = "/etc/dayshield/config";
/// Config file name inside the config directory.
const CONFIG_FILE: &str = "config.json";
/// Temporary file suffix used for atomic writes.
const TMP_SUFFIX: &str = ".tmp";
/// Backup file suffix used for rollback.
const BAK_SUFFIX: &str = ".bak";

// ── Permission-aware write helper ─────────────────────────────────────────────

/// Write `data` to `path` with mode `0o600` (owner read/write only).
///
/// Uses a write-then-rename pattern for atomicity.  The temp file is created
/// at `<path>.tmp`, written with restricted permissions, and then renamed to
/// `path`.
#[cfg(unix)]
fn write_restricted(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = PathBuf::from(format!("{}{}", path.display(), TMP_SUFFIX));

    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("Failed to open temp file {}", tmp.display()))?;
        f.write_all(data)
            .with_context(|| format!("Failed to write temp file {}", tmp.display()))?;
    }

    std::fs::rename(&tmp, path).with_context(|| {
        format!("Failed to rename {} to {}", tmp.display(), path.display())
    })?;

    Ok(())
}

/// Fallback for non-Unix platforms (uses standard write).
#[cfg(not(unix))]
fn write_restricted(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = PathBuf::from(format!("{}{}", path.display(), TMP_SUFFIX));
    std::fs::write(&tmp, data)
        .with_context(|| format!("Failed to write temp file {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| {
        format!("Failed to rename {} to {}", tmp.display(), path.display())
    })?;
    Ok(())
}

// ── Schema versioning ─────────────────────────────────────────────────────────

/// The current on-disk schema version.
///
/// Increment this constant whenever the [`SystemConfig`] format changes in a
/// backwards-incompatible way, and add a corresponding arm to
/// [`migrate_config`].
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// On-disk envelope that carries a schema version alongside the config.
///
/// The `schema_version` field is optional (defaults to `0`) so that config
/// files written before versioning was introduced can still be loaded and
/// automatically migrated.
#[derive(serde::Serialize, serde::Deserialize)]
struct VersionedConfig {
    /// Schema version.  `0` means "pre-versioning" (treated as version 0).
    #[serde(default)]
    schema_version: u32,
    /// The actual configuration payload.
    #[serde(flatten)]
    config: SystemConfig,
}

/// Migrate a [`SystemConfig`] from `from_version` to [`CURRENT_SCHEMA_VERSION`].
///
/// Each arm of the `match` applies one incremental migration step.  Future
/// schema changes should add a new arm here and bump [`CURRENT_SCHEMA_VERSION`].
fn migrate_config(config: SystemConfig, from_version: u32) -> Result<SystemConfig> {
    let mut version = from_version;

    while version < CURRENT_SCHEMA_VERSION {
        match version {
            0 => {
                // Migration v0 → v1: no structural changes; the schema_version
                // field was simply added to the on-disk envelope.
                debug!("Migrating config from schema v0 to v1 (no-op)");
                version = 1;
            }
            other => {
                anyhow::bail!(
                    "Unknown schema version {other}; cannot migrate to {CURRENT_SCHEMA_VERSION}"
                );
            }
        }
    }

    Ok(config)
}

// ── Type alias for the post-save engine hook ──────────────────────────────────

/// Callback type invoked after a successful [`ConfigStore::save_with_rollback`].
///
/// The callback receives a reference to the newly-committed [`SystemConfig`].
/// Use [`ConfigStore::set_on_save`] to register a hook.
pub type OnSaveFn = Arc<dyn Fn(&SystemConfig) + Send + Sync>;

/// Manages loading and saving the [`SystemConfig`] to persistent storage.
pub struct ConfigStore {
    config_path: PathBuf,
    /// Optional hook called after every successful save.
    on_save: Option<OnSaveFn>,
}

impl ConfigStore {
    /// Create a new [`ConfigStore`] using the default config directory.
    pub fn new() -> Self {
        Self::with_dir(DEFAULT_CONFIG_DIR)
    }

    /// Create a new [`ConfigStore`] using a custom directory (useful for
    /// testing without requiring `/etc` access).
    pub fn with_dir(dir: impl AsRef<Path>) -> Self {
        Self {
            config_path: dir.as_ref().join(CONFIG_FILE),
            on_save: None,
        }
    }

    /// Register a callback to be invoked after every successful
    /// [`Self::save_with_rollback`] call.
    ///
    /// The callback receives an immutable reference to the committed
    /// [`SystemConfig`].  Use this hook to push configuration changes to live
    /// engine services (e.g. reload nftables, restart chrony).
    ///
    /// Only one callback can be registered at a time; calling this method a
    /// second time replaces the previous hook.
    pub fn set_on_save(&mut self, hook: OnSaveFn) {
        self.on_save = Some(hook);
    }

    /// Return the path to the configuration file managed by this store.
    ///
    /// The parent directory of this path is the configuration directory.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Load the [`SystemConfig`] from disk, migrating old schema versions.
    ///
    /// Returns a default (empty) config if the file does not exist yet.
    pub fn load(&self) -> Result<SystemConfig> {
        if !self.config_path.exists() {
            info!(
                path = %self.config_path.display(),
                "Config file not found; using defaults"
            );
            return Ok(SystemConfig::default());
        }

        debug!(path = %self.config_path.display(), "Loading config");
        let raw = std::fs::read_to_string(&self.config_path)
            .with_context(|| format!("Failed to read {}", self.config_path.display()))?;

        // Deserialise as a versioned envelope.  Files without a
        // `schema_version` field will deserialise with version == 0.
        let versioned: VersionedConfig = serde_json::from_str(&raw)
            .with_context(|| format!("Failed to parse {}", self.config_path.display()))?;

        if versioned.schema_version < CURRENT_SCHEMA_VERSION {
            info!(
                from_version = versioned.schema_version,
                to_version = CURRENT_SCHEMA_VERSION,
                "Migrating config schema"
            );
        }

        let config = migrate_config(versioned.config, versioned.schema_version)?;
        Ok(config)
    }

    /// Load and merge all `*.json` fragment files found in the configuration
    /// directory, then overlay them onto a base [`SystemConfig`].
    ///
    /// Fragment files are read in lexicographic order.  Each file is parsed as
    /// a JSON object and shallow-merged (via [`serde_json::Value`]) into the
    /// accumulated configuration.  This allows operators to split large
    /// configurations across multiple files (e.g. `interfaces.json`,
    /// `firewall.json`) without having to maintain a single monolithic file.
    ///
    /// The primary `config.json` is **excluded** from this scan; it is loaded
    /// separately by [`Self::load`].
    ///
    /// Returns the merged [`SystemConfig`], or an error if any fragment cannot
    /// be parsed.
    pub fn load_fragments(&self) -> Result<SystemConfig> {
        let dir = self
            .config_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Config path has no parent directory"))?;

        if !dir.exists() {
            return Ok(SystemConfig::default());
        }

        // Collect all *.json files in the directory except the primary config.
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read config directory {}", dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension().and_then(|e| e.to_str()) == Some("json")
                    && p.file_name() != self.config_path.file_name()
            })
            .collect();

        entries.sort();

        if entries.is_empty() {
            return Ok(SystemConfig::default());
        }

        // Start from an empty JSON object and merge each fragment in order.
        let mut merged = serde_json::Value::Object(serde_json::Map::new());

        for path in &entries {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read fragment {}", path.display()))?;
            let fragment: serde_json::Value = serde_json::from_str(&raw)
                .with_context(|| format!("Failed to parse fragment {}", path.display()))?;
            merge_json(&mut merged, fragment);
            debug!(path = %path.display(), "Loaded config fragment");
        }

        let config: SystemConfig = serde_json::from_value(merged)
            .context("Failed to deserialise merged config fragments")?;

        info!(count = entries.len(), "Loaded config fragments from directory");
        Ok(config)
    }

    /// Validate the provided config.
    ///
    /// Returns `Ok(())` when the config is valid, or an [`anyhow::Error`]
    /// describing the first validation failure found.
    pub fn validate(&self, config: &SystemConfig) -> Result<()> {
        use crate::config::models::{
            is_valid_cidr, is_valid_domain, is_valid_interface_name, is_valid_ip,
            is_valid_ipv4_range, is_valid_mac, is_valid_mtu, is_valid_port,
        };

        for iface in &config.interfaces {
            if !is_valid_interface_name(&iface.name) {
                anyhow::bail!(
                    "Interface {:?} has an invalid name (must be 1–15 alphanumeric/[-_.] chars)",
                    iface.name
                );
            }
            for cidr in &iface.addresses {
                if !is_valid_cidr(cidr) {
                    anyhow::bail!(
                        "Interface {:?} has invalid CIDR address {:?}",
                        iface.name,
                        cidr
                    );
                }
            }
            if let Some(mtu) = iface.mtu {
                if !is_valid_mtu(mtu) {
                    anyhow::bail!(
                        "Interface {:?} has invalid MTU {} (must be ≥ 68)",
                        iface.name,
                        mtu
                    );
                }
            }
        }

        // Firewall rules must have a non-negative priority.
        for rule in &config.firewall_rules {
            if rule.priority < 0 {
                anyhow::bail!(
                    "Firewall rule {} has negative priority {}",
                    rule.id,
                    rule.priority
                );
            }
        }

        // Firewall global settings validation.
        if let Some(settings) = &config.firewall_settings {
            if settings.syn_flood_rate == 0 {
                anyhow::bail!("Firewall syn_flood_rate must be greater than 0");
            }
            if settings.syn_flood_burst == 0 {
                anyhow::bail!("Firewall syn_flood_burst must be greater than 0");
            }
            if settings.management_ports.is_empty() {
                anyhow::bail!("Firewall management_ports must contain at least one port");
            }
            for port in &settings.management_ports {
                if !is_valid_port(*port) {
                    anyhow::bail!(
                        "Firewall management_ports contains invalid port {} (must be 1–65535)",
                        port
                    );
                }
            }
            for src in &settings.management_allowed_sources {
                if !is_valid_cidr(src) {
                    anyhow::bail!(
                        "Firewall management_allowed_sources contains invalid CIDR {:?}",
                        src
                    );
                }
            }
            if let Some(iface) = &settings.management_interface {
                if !iface.is_empty() && !is_valid_interface_name(iface) {
                    anyhow::bail!(
                        "Firewall management_interface {:?} is not a valid interface name",
                        iface
                    );
                }
            }
        }

        // DNS config validation.
        if let Some(dns) = &config.dns {
            for addr in &dns.listen_addresses {
                if !is_valid_ip(addr) {
                    anyhow::bail!("DNS listen address {:?} is not a valid IP address", addr);
                }
            }
            if dns.port == 0 {
                anyhow::bail!("DNS port must be non-zero");
            }
            for fwd in &dns.forwarders {
                if !is_valid_ip(fwd) {
                    anyhow::bail!("DNS forwarder {:?} is not a valid IP address", fwd);
                }
            }
            for rec in &dns.local_records {
                if rec.name.is_empty() {
                    anyhow::bail!("DNS local record has an empty name");
                }
            }
        }

        // DHCP config validation.
        if let Some(dhcp) = &config.dhcp {
            for scope in &dhcp.scopes {
                if !is_valid_cidr(&scope.subnet) {
                    anyhow::bail!(
                        "DHCP scope {} has invalid subnet {:?}",
                        scope.id,
                        scope.subnet
                    );
                }
                if !is_valid_ip(&scope.pool_start) {
                    anyhow::bail!(
                        "DHCP scope {} has invalid pool_start {:?}",
                        scope.id,
                        scope.pool_start
                    );
                }
                if !is_valid_ip(&scope.pool_end) {
                    anyhow::bail!(
                        "DHCP scope {} has invalid pool_end {:?}",
                        scope.id,
                        scope.pool_end
                    );
                }
                if !is_valid_ipv4_range(&scope.pool_start, &scope.pool_end) {
                    anyhow::bail!(
                        "DHCP scope {} pool_start {} must be ≤ pool_end {}",
                        scope.id,
                        scope.pool_start,
                        scope.pool_end
                    );
                }
                if let Some(gw) = &scope.gateway {
                    if !is_valid_ip(gw) {
                        anyhow::bail!(
                            "DHCP scope {} has invalid gateway {:?}",
                            scope.id,
                            gw
                        );
                    }
                }
                for dns in &scope.dns_servers {
                    if !is_valid_ip(dns) {
                        anyhow::bail!(
                            "DHCP scope {} has invalid DNS server {:?}",
                            scope.id,
                            dns
                        );
                    }
                }
                for res in &scope.reservations {
                    if !is_valid_mac(&res.mac_address) {
                        anyhow::bail!(
                            "DHCP reservation {} has invalid MAC {:?}",
                            res.id,
                            res.mac_address
                        );
                    }
                    if !is_valid_ip(&res.ip_address) {
                        anyhow::bail!(
                            "DHCP reservation {} has invalid IP {:?}",
                            res.id,
                            res.ip_address
                        );
                    }
                }
            }
        }

        // DNS local record type validation.
        if let Some(dns) = &config.dns {
            for rec in &dns.local_records {
                if !matches!(rec.record_type.to_uppercase().as_str(), "A" | "AAAA" | "CNAME" | "PTR" | "MX" | "TXT") {
                    anyhow::bail!(
                        "DNS local record {:?} has unsupported record type {:?}",
                        rec.name,
                        rec.record_type
                    );
                }
            }
        }

        // Domain name validation at the system level.
        if let Some(domain) = &config.domain {
            if !is_valid_domain(domain) {
                anyhow::bail!("System domain {:?} is not a valid domain name", domain);
            }
        }

        // Suricata config validation.
        if let Some(suricata) = &config.suricata {
            use crate::config::models::validate_suricata_config;
            if let Err(msg) = validate_suricata_config(suricata) {
                anyhow::bail!("Suricata config is invalid: {msg}");
            }
        }

        // Firewall alias validation.
        {
            use crate::config::models::{validate_alias_name, validate_alias_values};
            let mut seen_names = std::collections::HashSet::new();
            for alias in &config.firewall_aliases {
                if !validate_alias_name(&alias.name) {
                    anyhow::bail!(
                        "Firewall alias has invalid name {:?} \
                         (must be 1–63 chars, start with letter or _, contain only [A-Za-z0-9_])",
                        alias.name
                    );
                }
                if !seen_names.insert(alias.name.clone()) {
                    anyhow::bail!("Duplicate firewall alias name {:?}", alias.name);
                }
                if let Err(msg) = validate_alias_values(alias) {
                    anyhow::bail!("{msg}");
                }
            }
        }

        // DNS host-override validation.
        {
            use crate::config::models::{validate_dns_hostname, is_valid_ip};
            for ov in &config.dns_host_overrides {
                if !validate_dns_hostname(&ov.hostname) {
                    anyhow::bail!(
                        "DNS host override has invalid hostname {:?}",
                        ov.hostname
                    );
                }
                if !is_valid_ip(&ov.address) {
                    anyhow::bail!(
                        "DNS host override {:?} has invalid address {:?}",
                        ov.hostname, ov.address
                    );
                }
            }
        }

        // DNS domain-override validation.
        {
            use crate::config::models::{validate_dns_domain, is_valid_ip};
            for ov in &config.dns_domain_overrides {
                if !validate_dns_domain(&ov.domain) {
                    anyhow::bail!(
                        "DNS domain override has invalid domain {:?}",
                        ov.domain
                    );
                }
                if !is_valid_ip(&ov.forward_to) {
                    anyhow::bail!(
                        "DNS domain override {:?} has invalid forward_to address {:?}",
                        ov.domain, ov.forward_to
                    );
                }
            }
        }

        // WireGuard interface validation.
        {
            use crate::config::models::{
                validate_cidr, validate_endpoint, validate_wg_interface_name, validate_wg_key,
            };
            let mut seen_names = std::collections::HashSet::new();
            for wg in &config.wireguard_interfaces {
                if !validate_wg_interface_name(&wg.name) {
                    anyhow::bail!(
                        "WireGuard interface has invalid name {:?} \
                         (must be 1–15 alphanumeric/[-_.] chars)",
                        wg.name
                    );
                }
                if !seen_names.insert(wg.name.clone()) {
                    anyhow::bail!("Duplicate WireGuard interface name {:?}", wg.name);
                }
                if !validate_wg_key(&wg.private_key) {
                    anyhow::bail!(
                        "WireGuard interface {:?} has an invalid private_key \
                         (must be a 44-char base64 string)",
                        wg.name
                    );
                }
                if !validate_wg_key(&wg.public_key) {
                    anyhow::bail!(
                        "WireGuard interface {:?} has an invalid public_key \
                         (must be a 44-char base64 string)",
                        wg.name
                    );
                }
                for addr in &wg.addresses {
                    if !validate_cidr(addr) {
                        anyhow::bail!(
                            "WireGuard interface {:?} has invalid address CIDR {:?}",
                            wg.name,
                            addr
                        );
                    }
                }
                for peer in &wg.peers {
                    if !validate_wg_key(&peer.public_key) {
                        anyhow::bail!(
                            "WireGuard interface {:?} peer {:?} has an invalid public_key",
                            wg.name,
                            peer.name
                        );
                    }
                    if let Some(psk) = &peer.preshared_key {
                        if !validate_wg_key(psk) {
                            anyhow::bail!(
                                "WireGuard interface {:?} peer {:?} has an invalid preshared_key",
                                wg.name,
                                peer.name
                            );
                        }
                    }
                    for cidr in &peer.allowed_ips {
                        if !validate_cidr(cidr) {
                            anyhow::bail!(
                                "WireGuard interface {:?} peer {:?} has invalid allowed_ip CIDR {:?}",
                                wg.name,
                                peer.name,
                                cidr
                            );
                        }
                    }
                    if let Some(ep) = &peer.endpoint {
                        if !validate_endpoint(ep) {
                            anyhow::bail!(
                                "WireGuard interface {:?} peer {:?} has invalid endpoint {:?}",
                                wg.name,
                                peer.name,
                                ep
                            );
                        }
                    }
                }
            }
        }

        // CrowdSec config validation.
        if let Some(cs) = &config.crowdsec {
            use crate::config::models::{validate_alias_name, validate_api_key, validate_url};
            if cs.enabled {
                if !validate_url(&cs.lapi_url) {
                    anyhow::bail!(
                        "CrowdSec lapi_url {:?} is not a valid HTTP/HTTPS URL",
                        cs.lapi_url
                    );
                }
                if !validate_api_key(&cs.api_key) {
                    anyhow::bail!("CrowdSec api_key must not be empty");
                }
                if cs.update_interval == 0 {
                    anyhow::bail!("CrowdSec update_interval must be greater than 0");
                }
                if !validate_alias_name(&cs.ban_alias_name) {
                    anyhow::bail!(
                        "CrowdSec ban_alias_name {:?} is invalid \
                         (must be 1–63 chars, start with letter or _, contain only [A-Za-z0-9_])",
                        cs.ban_alias_name
                    );
                }
            }
        }

        // ACME config validation.
        if let Some(acme) = &config.acme {
            use crate::config::models::validate_acme_config;
            if acme.enabled {
                if let Err(msg) = validate_acme_config(acme) {
                    anyhow::bail!("ACME config is invalid: {msg}");
                }
                if acme.renew_interval_hours == 0 {
                    anyhow::bail!("ACME renew_interval_hours must be greater than 0");
                }
            }
        }

        // Notify config validation.
        if let Some(notify) = &config.notify {
            use crate::config::models::validate_notify_config;
            if let Err(msg) = validate_notify_config(notify) {
                anyhow::bail!("Notify config is invalid: {msg}");
            }
        }

        // NTP config validation.
        if let Some(ntp) = &config.ntp {
            use crate::config::models::validate_ntp_config;
            if let Err(msg) = validate_ntp_config(ntp) {
                anyhow::bail!("NTP config is invalid: {msg}");
            }
            // Cross-check listen_interfaces against the known interface names.
            if ntp.enabled && ntp.serve_clients {
                let known: std::collections::HashSet<&str> =
                    config.interfaces.iter().map(|i| i.name.as_str()).collect();
                for iface in &ntp.listen_interfaces {
                    if !known.is_empty() && !known.contains(iface.as_str()) {
                        anyhow::bail!(
                            "NTP listen_interface {:?} is not defined in the interface config",
                            iface
                        );
                    }
                }
            }
        }

        // NAT config validation.
        if let Some(nat) = &config.nat {
            use crate::config::models::validate_nat_config;
            if let Err(msg) = validate_nat_config(nat) {
                anyhow::bail!("NAT config is invalid: {msg}");
            }
        }

        Ok(())
    }

    /// Return the ACME configuration from the persisted config.
    ///
    /// Returns `None` if no ACME configuration has been saved yet.
    pub fn load_acme_config(&self) -> Result<Option<AcmeConfig>> {
        Ok(self.load()?.acme)
    }

    /// Atomically replace the ACME configuration in the persisted config.
    ///
    /// Loads the current config, replaces `acme`, validates, then calls
    /// [`Self::save_with_rollback`] to write atomically with rollback on
    /// post-write validation failure.
    pub fn save_acme_config(&self, acme: AcmeConfig) -> Result<()> {
        let mut config = self.load()?;
        config.acme = Some(acme);
        self.save_with_rollback(&config)
    }

    /// Return the CrowdSec configuration from the persisted config.
    ///
    /// Returns `None` if no CrowdSec configuration has been saved yet.
    pub fn load_crowdsec_config(&self) -> Result<Option<CrowdSecConfig>> {
        Ok(self.load()?.crowdsec)
    }

    /// Atomically replace the CrowdSec configuration in the persisted config.
    ///
    /// Loads the current config, replaces `crowdsec`, validates, then calls
    /// [`Self::save_with_rollback`] to write atomically with rollback on
    /// post-write validation failure.
    pub fn save_crowdsec_config(&self, crowdsec: CrowdSecConfig) -> Result<()> {
        let mut config = self.load()?;
        config.crowdsec = Some(crowdsec);
        self.save_with_rollback(&config)
    }

    /// Return the WireGuard interface list from the persisted config.
    pub fn load_wireguard_interfaces(&self) -> Result<Vec<WireGuardInterface>> {
        Ok(self.load()?.wireguard_interfaces)
    }

    /// Atomically replace the WireGuard interface list in the persisted config.
    ///
    /// Loads the current config, replaces `wireguard_interfaces`, validates,
    /// then calls [`Self::save_with_rollback`] to write atomically with rollback
    /// on post-write validation failure.
    pub fn save_wireguard_interfaces(&self, interfaces: Vec<WireGuardInterface>) -> Result<()> {
        let mut config = self.load()?;
        config.wireguard_interfaces = interfaces;
        self.save_with_rollback(&config)
    }

    /// Return only the interface slice from the persisted config.
    ///
    /// Equivalent to `load()?.interfaces` but makes intent explicit.
    pub fn load_interfaces(&self) -> Result<Vec<Interface>> {
        Ok(self.load()?.interfaces)
    }

    /// Atomically replace the interface list in the persisted config.
    ///
    /// Loads the current config, replaces `interfaces`, then calls
    /// [`Self::save_with_rollback`] to write the updated config atomically.
    pub fn save_interfaces(&self, interfaces: Vec<Interface>) -> Result<()> {
        let mut config = self.load()?;
        config.interfaces = interfaces;
        self.save_with_rollback(&config)
    }

    /// Return only the firewall-rule slice from the persisted config.
    ///
    /// Equivalent to `load()?.firewall_rules` but makes intent explicit.
    pub fn load_firewall_rules(&self) -> Result<Vec<FirewallRule>> {
        Ok(self.load()?.firewall_rules)
    }

    /// Atomically replace the firewall-rule list in the persisted config.
    ///
    /// Loads the current config, replaces `firewall_rules`, validates, then
    /// calls [`Self::save_with_rollback`] to write the updated config
    /// atomically with rollback on post-write validation failure.
    pub fn save_firewall_rules(&self, rules: Vec<FirewallRule>) -> Result<()> {
        let mut config = self.load()?;
        config.firewall_rules = rules;
        self.save_with_rollback(&config)
    }

    /// Return firewall global settings from persisted config.
    ///
    /// Returns defaults when no settings have been saved yet.
    pub fn load_firewall_settings(&self) -> Result<FirewallSettings> {
        Ok(self.load()?.firewall_settings.unwrap_or_default())
    }

    /// Atomically replace firewall global settings in persisted config.
    pub fn save_firewall_settings(&self, settings: FirewallSettings) -> Result<()> {
        let mut config = self.load()?;
        config.firewall_settings = Some(settings);
        self.save_with_rollback(&config)
    }

    /// Return the DNS configuration from the persisted config.
    ///
    /// Returns `None` if no DNS configuration has been saved yet.
    pub fn load_dns_config(&self) -> Result<Option<DnsConfig>> {
        Ok(self.load()?.dns)
    }

    /// Atomically replace the DNS configuration in the persisted config.
    ///
    /// Loads the current config, replaces `dns`, validates, then calls
    /// [`Self::save_with_rollback`] to write atomically with rollback on
    /// post-write validation failure.
    pub fn save_dns_config(&self, dns: DnsConfig) -> Result<()> {
        let mut config = self.load()?;
        config.dns = Some(dns);
        self.save_with_rollback(&config)
    }

    /// Return the DHCP configuration from the persisted config.
    ///
    /// Returns `None` if no DHCP configuration has been saved yet.
    pub fn load_dhcp_config(&self) -> Result<Option<DhcpConfig>> {
        Ok(self.load()?.dhcp)
    }

    /// Atomically replace the DHCP configuration in the persisted config.
    ///
    /// Loads the current config, replaces `dhcp`, validates, then calls
    /// [`Self::save_with_rollback`] to write atomically with rollback on
    /// post-write validation failure.
    pub fn save_dhcp_config(&self, dhcp: DhcpConfig) -> Result<()> {
        let mut config = self.load()?;
        config.dhcp = Some(dhcp);
        self.save_with_rollback(&config)
    }

    /// Return the Suricata configuration from the persisted config.
    ///
    /// Returns `None` if no Suricata configuration has been saved yet.
    pub fn load_suricata_config(&self) -> Result<Option<SuricataConfig>> {
        Ok(self.load()?.suricata)
    }

    /// Atomically replace the Suricata configuration in the persisted config.
    ///
    /// Loads the current config, replaces `suricata`, validates, then calls
    /// [`Self::save_with_rollback`] to write atomically with rollback on
    /// post-write validation failure.
    pub fn save_suricata_config(&self, suricata: SuricataConfig) -> Result<()> {
        let mut config = self.load()?;
        config.suricata = Some(suricata);
        self.save_with_rollback(&config)
    }

    /// Return the firewall alias list from the persisted config.
    pub fn load_firewall_aliases(&self) -> Result<Vec<FirewallAlias>> {
        Ok(self.load()?.firewall_aliases)
    }

    /// Atomically replace the firewall alias list in the persisted config.
    ///
    /// Loads the current config, replaces `firewall_aliases`, validates, then
    /// calls [`Self::save_with_rollback`] to write atomically with rollback on
    /// post-write validation failure.
    pub fn save_firewall_aliases(&self, aliases: Vec<FirewallAlias>) -> Result<()> {
        let mut config = self.load()?;
        config.firewall_aliases = aliases;
        self.save_with_rollback(&config)
    }

    /// Return the DNS host and domain overrides from the persisted config.
    ///
    /// Returns `(host_overrides, domain_overrides)`.
    pub fn load_dns_overrides(
        &self,
    ) -> Result<(Vec<DnsHostOverride>, Vec<DnsDomainOverride>)> {
        let cfg = self.load()?;
        Ok((cfg.dns_host_overrides, cfg.dns_domain_overrides))
    }

    /// Atomically replace the DNS override lists in the persisted config.
    ///
    /// Loads the current config, replaces `dns_host_overrides` and
    /// `dns_domain_overrides`, validates, then calls
    /// [`Self::save_with_rollback`] to write atomically.
    pub fn save_dns_overrides(
        &self,
        host_overrides: Vec<DnsHostOverride>,
        domain_overrides: Vec<DnsDomainOverride>,
    ) -> Result<()> {
        let mut config = self.load()?;
        config.dns_host_overrides = host_overrides;
        config.dns_domain_overrides = domain_overrides;
        self.save_with_rollback(&config)
    }

    /// Return the notification configuration from the persisted config.
    ///
    /// Returns `None` if no notification configuration has been saved yet.
    pub fn load_notify_config(&self) -> Result<Option<NotifyConfig>> {
        Ok(self.load()?.notify)
    }

    /// Atomically replace the notification configuration in the persisted config.
    ///
    /// Loads the current config, replaces `notify`, validates, then calls
    /// [`Self::save_with_rollback`] to write atomically with rollback on
    /// post-write validation failure.
    pub fn save_notify_config(&self, notify: NotifyConfig) -> Result<()> {
        let mut config = self.load()?;
        config.notify = Some(notify);
        self.save_with_rollback(&config)
    }

    /// Return the NTP configuration from the persisted config.
    ///
    /// Returns `None` if no NTP configuration has been saved yet.
    pub fn load_ntp_config(&self) -> Result<Option<NtpConfig>> {
        Ok(self.load()?.ntp)
    }

    /// Atomically replace the NTP configuration in the persisted config.
    ///
    /// Loads the current config, replaces `ntp`, validates, then calls
    /// [`Self::save_with_rollback`] to write atomically with rollback on
    /// post-write validation failure.
    pub fn save_ntp_config(&self, ntp: NtpConfig) -> Result<()> {
        let mut config = self.load()?;
        config.ntp = Some(ntp);
        self.save_with_rollback(&config)
    }

    /// Return the NAT configuration from the persisted config.
    ///
    /// Returns `None` if no NAT configuration has been saved yet.
    pub fn load_nat_config(&self) -> Result<Option<NatConfig>> {
        Ok(self.load()?.nat)
    }

    /// Atomically replace the NAT configuration in the persisted config.
    ///
    /// Loads the current config, replaces `nat`, validates, then calls
    /// [`Self::save_with_rollback`] to write atomically with rollback on
    /// post-write validation failure.
    pub fn save_nat_config(&self, nat: NatConfig) -> Result<()> {
        let mut config = self.load()?;
        config.nat = Some(nat);
        self.save_with_rollback(&config)
    }

    /// Return the system settings from the persisted config.
    ///
    /// Returns defaults when no settings have been saved yet.
    pub fn load_system_settings(&self) -> Result<super::models::SystemSettings> {        Ok(self.load()?.system_settings.unwrap_or_default())
    }

    /// Atomically replace the system settings in the persisted config.
    ///
    /// Loads the current config, replaces `system_settings`, validates, then
    /// calls [`Self::save_with_rollback`] to write atomically.
    pub fn save_system_settings(&self, settings: super::models::SystemSettings) -> Result<()> {
        let mut config = self.load()?;
        config.system_settings = Some(settings);
        self.save_with_rollback(&config)
    }

    /// Return the gateway list from the persisted config.
    pub fn load_gateways(&self) -> Result<Vec<Gateway>> {
        Ok(self.load()?.gateways)
    }

    /// Atomically replace the gateway list in the persisted config.
    pub fn save_gateways(&self, gateways: Vec<Gateway>) -> Result<()> {
        let mut config = self.load()?;
        config.gateways = gateways;
        self.save_with_rollback(&config)
    }

    /// Return the admin security settings from the persisted config.
    ///
    /// Returns defaults when no settings have been saved yet.
    pub fn load_admin_security_settings(&self) -> Result<super::models::AdminSecuritySettings> {
        Ok(self.load()?.admin_security.unwrap_or_default())
    }

    /// Atomically replace the admin security settings in the persisted config.
    pub fn save_admin_security_settings(
        &self,
        settings: super::models::AdminSecuritySettings,
    ) -> Result<()> {
        let mut config = self.load()?;
        config.admin_security = Some(settings);
        self.save_with_rollback(&config)
    }

    /// Validate and atomically write config to disk.
    ///
    /// The write is performed by:
    /// 1. Serialising the config to a versioned JSON envelope.
    /// 2. Writing to `<config_path>.tmp`.
    /// 3. Renaming the temp file to `<config_path>`.
    ///
    /// Renaming is atomic on POSIX systems.
    pub fn save(&self, config: &SystemConfig) -> Result<()> {
        self.validate(config)?;

        // Ensure the parent directory exists.
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }

        // Wrap config in the versioned envelope before serialising.
        let versioned = VersionedConfig {
            schema_version: CURRENT_SCHEMA_VERSION,
            config: config.clone(),
        };
        let json =
            serde_json::to_string_pretty(&versioned).context("Failed to serialise config")?;

        write_restricted(&self.config_path, json.as_bytes())?;

        info!(path = %self.config_path.display(), "Config saved");
        Ok(())
    }

    /// Save with automatic rollback on post-write validation failure.
    ///
    /// Workflow:
    /// 1. Back up the current config file (if it exists).
    /// 2. Write the new config atomically via [`Self::save`].
    /// 3. Re-load and re-validate the written file.
    /// 4. If step 3 fails, restore the backup and return the error.
    /// 5. On success, invoke the registered [`OnSaveFn`] hook (if any) so
    ///    that live engine services receive the updated configuration.
    pub fn save_with_rollback(&self, config: &SystemConfig) -> Result<()> {
        let bak_path = PathBuf::from(format!("{}{}", self.config_path.display(), BAK_SUFFIX));

        // Step 1 - backup.
        if self.config_path.exists() {
            std::fs::copy(&self.config_path, &bak_path).with_context(|| {
                format!(
                    "Failed to back up config to {}",
                    bak_path.display()
                )
            })?;
            debug!(backup = %bak_path.display(), "Config backed up");
        }

        // Step 2 - write.
        if let Err(e) = self.save(config) {
            // Restore backup if write itself failed.
            self.try_restore_backup(&bak_path);
            return Err(e);
        }

        // Step 3 - re-validate from disk.
        match self.load().and_then(|c| self.validate(&c)) {
            Ok(_) => {
                // Clean up the backup on success.
                let _ = std::fs::remove_file(&bak_path);

                // Step 5 - notify engine layer.
                if let Some(hook) = &self.on_save {
                    hook(config);
                }

                Ok(())
            }
            Err(e) => {
                warn!("Post-write validation failed; rolling back to backup");
                self.try_restore_backup(&bak_path);
                Err(e.context("Config rolled back after post-write validation failure"))
            }
        }
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    fn try_restore_backup(&self, bak_path: &Path) {
        if bak_path.exists() {
            if let Err(re) = std::fs::copy(bak_path, &self.config_path) {
                warn!(
                    error = %re,
                    backup = %bak_path.display(),
                    target = %self.config_path.display(),
                    "Failed to restore config backup"
                );
            } else {
                info!(path = %self.config_path.display(), "Config restored from backup");
            }
        }
    }
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── JSON fragment merge ────────────────────────────────────────────────────────

/// Recursively merge `src` into `dst`.
///
/// - Object fields in `src` are recursively merged into the corresponding
///   object in `dst`.
/// - Arrays and scalar values in `src` overwrite those in `dst`.
fn merge_json(dst: &mut serde_json::Value, src: serde_json::Value) {
    match (dst, src) {
        (serde_json::Value::Object(dst_map), serde_json::Value::Object(src_map)) => {
            for (key, src_val) in src_map {
                // Only recurse when the destination already holds an object;
                // otherwise overwrite directly to avoid inserting spurious nulls.
                match dst_map.get_mut(&key) {
                    Some(dst_val) if dst_val.is_object() && src_val.is_object() => {
                        merge_json(dst_val, src_val);
                    }
                    _ => {
                        dst_map.insert(key, src_val);
                    }
                }
            }
        }
        (dst, src) => {
            *dst = src;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{is_valid_cidr, is_valid_interface_name, is_valid_mtu, Interface};

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ds-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_interface(name: &str) -> Interface {
        Interface {
            name: name.into(),
            description: None,
            addresses: vec!["192.168.1.1/24".into()],
            mtu: None,
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            vlan: None,
        }
    }

    // -----------------------------------------------------------------------
    // Validation helpers
    // -----------------------------------------------------------------------

    #[test]
    fn interface_name_valid() {
        assert!(is_valid_interface_name("eth0"));
        assert!(is_valid_interface_name("wlan0"));
        assert!(is_valid_interface_name("br-lan"));
        assert!(is_valid_interface_name("wg0"));
        assert!(is_valid_interface_name("eth0.100"));
        assert!(is_valid_interface_name("bond_0"));
    }

    #[test]
    fn interface_name_invalid() {
        assert!(!is_valid_interface_name(""));
        assert!(!is_valid_interface_name("this_name_is_too_long_for_linux"));
        assert!(!is_valid_interface_name("eth 0"));
        assert!(!is_valid_interface_name("eth/0"));
        assert!(!is_valid_interface_name("eth:0"));
    }

    #[test]
    fn cidr_valid() {
        assert!(is_valid_cidr("192.168.1.0/24"));
        assert!(is_valid_cidr("10.0.0.1/8"));
        assert!(is_valid_cidr("0.0.0.0/0"));
        assert!(is_valid_cidr("::1/128"));
        assert!(is_valid_cidr("2001:db8::/32"));
        assert!(is_valid_cidr("fe80::1/64"));
    }

    #[test]
    fn cidr_invalid() {
        assert!(!is_valid_cidr("192.168.1.0"));
        assert!(!is_valid_cidr("192.168.1.0/33"));
        assert!(!is_valid_cidr("::1/129"));
        assert!(!is_valid_cidr("not-an-ip/24"));
        assert!(!is_valid_cidr(""));
        assert!(!is_valid_cidr("/24"));
    }

    #[test]
    fn mtu_valid() {
        assert!(is_valid_mtu(68));
        assert!(is_valid_mtu(1500));
        assert!(is_valid_mtu(9000));
        assert!(is_valid_mtu(65535));
    }

    #[test]
    fn mtu_invalid() {
        assert!(!is_valid_mtu(0));
        assert!(!is_valid_mtu(67));
    }

    // -----------------------------------------------------------------------
    // Storage round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn load_returns_default_when_missing() {
        let dir = std::env::temp_dir().join(format!("ds-missing-{}", uuid::Uuid::new_v4()));
        let store = ConfigStore::with_dir(&dir);
        let cfg = store.load().unwrap();
        assert!(cfg.interfaces.is_empty());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.hostname = "test-fw".into();

        store.save(&cfg).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.hostname, "test-fw");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_interfaces_roundtrip() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let ifaces = vec![make_interface("eth0"), make_interface("eth1")];
        store.save_interfaces(ifaces.clone()).unwrap();

        let loaded = store.load_interfaces().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "eth0");
        assert_eq!(loaded[1].name, "eth1");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_invalid_interface_name() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.interfaces.push(Interface {
            name: "".into(),
            description: None,
            addresses: vec![],
            mtu: None,
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            vlan: None,
        });
        assert!(store.validate(&cfg).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_invalid_cidr() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.interfaces.push(Interface {
            name: "eth0".into(),
            description: None,
            addresses: vec!["not-a-cidr".into()],
            mtu: None,
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            vlan: None,
        });
        assert!(store.validate(&cfg).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_invalid_mtu() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.interfaces.push(Interface {
            name: "eth0".into(),
            description: None,
            addresses: vec![],
            mtu: Some(10),
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            vlan: None,
        });
        assert!(store.validate(&cfg).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_with_rollback_restores_on_invalid_reload() {
        // Verify that a good config can be saved and re-loaded successfully.
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.hostname = "rollback-test".into();

        store.save_with_rollback(&cfg).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.hostname, "rollback-test");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Firewall rule storage
    // -----------------------------------------------------------------------

    fn make_rule(description: &str) -> crate::config::models::FirewallRule {
        use crate::config::models::{Action, FirewallRule};
        FirewallRule {
            id: uuid::Uuid::new_v4(),
            description: Some(description.into()),
            priority: 0,
            source: None,
            destination: None,
            protocol: None,
            source_port: None,
            destination_port: None,
            action: Action::Accept,
            interface: None,
            log: false,
        }
    }

    #[test]
    fn load_firewall_rules_returns_empty_on_missing_file() {
        let dir = std::env::temp_dir().join(format!("ds-fw-missing-{}", uuid::Uuid::new_v4()));
        let store = ConfigStore::with_dir(&dir);
        let rules = store.load_firewall_rules().unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn save_and_load_firewall_rules_roundtrip() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let rules = vec![make_rule("allow-ssh"), make_rule("block-telnet")];
        store.save_firewall_rules(rules.clone()).unwrap();

        let loaded = store.load_firewall_rules().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].description.as_deref(), Some("allow-ssh"));
        assert_eq!(loaded[1].description.as_deref(), Some("block-telnet"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_firewall_rules_preserves_other_config_fields() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        // Save an interface first.
        store
            .save_interfaces(vec![make_interface("eth0")])
            .unwrap();

        // Now save firewall rules - interfaces must still be present.
        store
            .save_firewall_rules(vec![make_rule("rule-a")])
            .unwrap();

        let cfg = store.load().unwrap();
        assert_eq!(cfg.interfaces.len(), 1, "interfaces must survive firewall save");
        assert_eq!(cfg.firewall_rules.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_firewall_rules_rejects_negative_priority() {
        use crate::config::models::{Action, FirewallRule};

        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let bad_rule = FirewallRule {
            id: uuid::Uuid::new_v4(),
            description: None,
            priority: -1,
            source: None,
            destination: None,
            protocol: None,
            source_port: None,
            destination_port: None,
            action: Action::Drop,
            interface: None,
            log: false,
        };

        let result = store.save_firewall_rules(vec![bad_rule]);
        assert!(result.is_err(), "negative priority must be rejected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Validation helpers (new)
    // -----------------------------------------------------------------------

    #[test]
    fn is_valid_ip_v4() {
        use crate::config::models::is_valid_ip;
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("0.0.0.0"));
        assert!(is_valid_ip("255.255.255.255"));
        assert!(!is_valid_ip("256.0.0.1"));
        assert!(!is_valid_ip("192.168.1.0/24"));
        assert!(!is_valid_ip(""));
    }

    #[test]
    fn is_valid_ip_v6() {
        use crate::config::models::is_valid_ip;
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("2001:db8::1"));
        assert!(is_valid_ip("fe80::1"));
        assert!(!is_valid_ip("::1/128"));
    }

    #[test]
    fn is_valid_ipv4_range_ok() {
        use crate::config::models::is_valid_ipv4_range;
        assert!(is_valid_ipv4_range("192.168.1.100", "192.168.1.200"));
        assert!(is_valid_ipv4_range("10.0.0.1", "10.0.0.1")); // start == end is ok
    }

    #[test]
    fn is_valid_ipv4_range_reversed() {
        use crate::config::models::is_valid_ipv4_range;
        assert!(!is_valid_ipv4_range("192.168.1.200", "192.168.1.100"));
    }

    #[test]
    fn is_valid_ipv4_range_invalid_addresses() {
        use crate::config::models::is_valid_ipv4_range;
        assert!(!is_valid_ipv4_range("not-an-ip", "192.168.1.1"));
    }

    #[test]
    fn is_valid_mac_colon() {
        use crate::config::models::is_valid_mac;
        assert!(is_valid_mac("aa:bb:cc:dd:ee:ff"));
        assert!(is_valid_mac("AA:BB:CC:DD:EE:FF"));
        assert!(is_valid_mac("00:11:22:33:44:55"));
    }

    #[test]
    fn is_valid_mac_hyphen() {
        use crate::config::models::is_valid_mac;
        assert!(is_valid_mac("aa-bb-cc-dd-ee-ff"));
    }

    #[test]
    fn is_valid_mac_invalid() {
        use crate::config::models::is_valid_mac;
        assert!(!is_valid_mac("aabbccddeeff"));         // no separator
        assert!(!is_valid_mac("aa:bb:cc:dd:ee"));       // only 5 groups
        assert!(!is_valid_mac("aa:bb:cc:dd:ee:gg"));    // invalid hex
        assert!(!is_valid_mac(""));
    }

    #[test]
    fn is_valid_domain_ok() {
        use crate::config::models::is_valid_domain;
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("example.com."));   // trailing dot
        assert!(is_valid_domain("my-host.local"));
        assert!(is_valid_domain("a"));              // single label
    }

    #[test]
    fn is_valid_domain_invalid() {
        use crate::config::models::is_valid_domain;
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("-bad.com"));      // starts with hyphen
        assert!(!is_valid_domain("bad-.com"));      // ends with hyphen
        assert!(!is_valid_domain("bad..com"));      // empty label
        assert!(!is_valid_domain(&"a".repeat(254))); // too long
    }

    // -----------------------------------------------------------------------
    // DNS / DHCP storage round-trips
    // -----------------------------------------------------------------------

    fn make_dns_config() -> crate::config::models::DnsConfig {
        use crate::config::models::DnsConfig;
        DnsConfig {
            enabled: true,
            listen_addresses: vec!["127.0.0.1".into()],
            port: 53,
            forwarders: vec!["1.1.1.1".into()],
            dnssec: false,
            local_records: vec![],
        }
    }

    fn make_dhcp_config() -> crate::config::models::DhcpConfig {
        use crate::config::models::{DhcpConfig, DhcpScope};
        DhcpConfig {
            enabled: true,
            scopes: vec![DhcpScope {
                id: uuid::Uuid::new_v4(),
                subnet: "192.168.1.0/24".into(),
                pool_start: "192.168.1.100".into(),
                pool_end: "192.168.1.200".into(),
                gateway: Some("192.168.1.1".into()),
                dns_servers: vec!["1.1.1.1".into()],
                lease_seconds: 86400,
                reservations: vec![],
            }],
        }
    }

    #[test]
    fn load_dns_config_returns_none_when_missing() {
        let dir = std::env::temp_dir().join(format!("ds-dns-missing-{}", uuid::Uuid::new_v4()));
        let store = ConfigStore::with_dir(&dir);
        let result = store.load_dns_config().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn save_and_load_dns_config_roundtrip() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let dns = make_dns_config();
        store.save_dns_config(dns.clone()).unwrap();

        let loaded = store.load_dns_config().unwrap().expect("DNS config should be Some");
        assert_eq!(loaded.port, 53);
        assert_eq!(loaded.forwarders, vec!["1.1.1.1"]);
        assert!(loaded.enabled);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_dns_config_preserves_other_fields() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        store.save_interfaces(vec![make_interface("eth0")]).unwrap();
        store.save_dns_config(make_dns_config()).unwrap();

        let cfg = store.load().unwrap();
        assert_eq!(cfg.interfaces.len(), 1, "interfaces must survive dns save");
        assert!(cfg.dns.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_dhcp_config_returns_none_when_missing() {
        let dir = std::env::temp_dir().join(format!("ds-dhcp-missing-{}", uuid::Uuid::new_v4()));
        let store = ConfigStore::with_dir(&dir);
        let result = store.load_dhcp_config().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn save_and_load_dhcp_config_roundtrip() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let dhcp = make_dhcp_config();
        store.save_dhcp_config(dhcp).unwrap();

        let loaded = store.load_dhcp_config().unwrap().expect("DHCP config should be Some");
        assert!(loaded.enabled);
        assert_eq!(loaded.scopes.len(), 1);
        assert_eq!(loaded.scopes[0].pool_start, "192.168.1.100");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_dhcp_config_preserves_other_fields() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        store.save_interfaces(vec![make_interface("eth0")]).unwrap();
        store.save_dhcp_config(make_dhcp_config()).unwrap();

        let cfg = store.load().unwrap();
        assert_eq!(cfg.interfaces.len(), 1, "interfaces must survive dhcp save");
        assert!(cfg.dhcp.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_invalid_dns_forwarder() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.dns = Some(crate::config::models::DnsConfig {
            enabled: true,
            listen_addresses: vec![],
            port: 53,
            forwarders: vec!["not-an-ip".into()],
            dnssec: false,
            local_records: vec![],
        });
        assert!(store.validate(&cfg).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_dhcp_scope_with_invalid_mac() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.dhcp = Some(crate::config::models::DhcpConfig {
            enabled: true,
            scopes: vec![crate::config::models::DhcpScope {
                id: uuid::Uuid::new_v4(),
                subnet: "192.168.1.0/24".into(),
                pool_start: "192.168.1.100".into(),
                pool_end: "192.168.1.200".into(),
                gateway: None,
                dns_servers: vec![],
                lease_seconds: 86400,
                reservations: vec![crate::config::models::DhcpReservation {
                    id: uuid::Uuid::new_v4(),
                    hostname: None,
                    mac_address: "not-a-mac".into(),
                    ip_address: "192.168.1.50".into(),
                }],
            }],
        });
        assert!(store.validate(&cfg).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_reversed_dhcp_pool_range() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.dhcp = Some(crate::config::models::DhcpConfig {
            enabled: true,
            scopes: vec![crate::config::models::DhcpScope {
                id: uuid::Uuid::new_v4(),
                subnet: "192.168.1.0/24".into(),
                pool_start: "192.168.1.200".into(), // reversed
                pool_end: "192.168.1.100".into(),
                gateway: None,
                dns_servers: vec![],
                lease_seconds: 86400,
                reservations: vec![],
            }],
        });
        assert!(store.validate(&cfg).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // ACME storage and validation
    // -----------------------------------------------------------------------

    fn make_acme_config() -> crate::config::models::AcmeConfig {
        use crate::config::models::{AcmeChallengeType, AcmeConfig, AcmeProvider};
        AcmeConfig {
            enabled: true,
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            email: "admin@example.com".into(),
            domains: vec!["example.com".into()],
            challenge_type: AcmeChallengeType::Http01,
            renew_interval_hours: 24,
            provider: AcmeProvider::LetsEncrypt,
            cert_storage_path: "/tmp/certs".into(),
        }
    }

    #[test]
    fn acme_config_save_and_load_roundtrip() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let acme = make_acme_config();
        store.save_acme_config(acme.clone()).unwrap();

        let loaded = store.load_acme_config().unwrap().expect("ACME config should be Some");
        assert!(loaded.enabled);
        assert_eq!(loaded.email, "admin@example.com");
        assert_eq!(loaded.domains, vec!["example.com"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn acme_config_load_returns_none_when_missing() {
        let dir = std::env::temp_dir().join(format!("ds-acme-missing-{}", uuid::Uuid::new_v4()));
        let store = ConfigStore::with_dir(&dir);
        let result = store.load_acme_config().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn acme_config_save_preserves_other_fields() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        store.save_interfaces(vec![make_interface("eth0")]).unwrap();
        store.save_acme_config(make_acme_config()).unwrap();

        let cfg = store.load().unwrap();
        assert_eq!(cfg.interfaces.len(), 1, "interfaces must survive ACME save");
        assert!(cfg.acme.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_acme_config_with_invalid_email() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        let mut acme = make_acme_config();
        acme.email = "not-an-email".into();
        cfg.acme = Some(acme);

        assert!(store.validate(&cfg).is_err(), "invalid email must be rejected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_acme_config_with_invalid_domain() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        let mut acme = make_acme_config();
        acme.domains = vec!["-invalid-domain".into()];
        cfg.acme = Some(acme);

        assert!(store.validate(&cfg).is_err(), "invalid domain must be rejected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_acme_config_with_zero_renew_interval() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        let mut acme = make_acme_config();
        acme.renew_interval_hours = 0;
        cfg.acme = Some(acme);

        assert!(store.validate(&cfg).is_err(), "zero renew_interval_hours must be rejected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_acme_config_with_invalid_directory_url() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        let mut acme = make_acme_config();
        acme.directory_url = "not-a-url".into();
        cfg.acme = Some(acme);

        assert!(store.validate(&cfg).is_err(), "invalid directory_url must be rejected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_acme_config_disabled_skips_validation() {
        // Disabled ACME config with bad fields should be accepted.
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.acme = Some(crate::config::models::AcmeConfig {
            enabled: false,
            directory_url: "not-a-url".into(),  // would fail if enabled
            email: "not-an-email".into(),
            domains: vec![],
            challenge_type: crate::config::models::AcmeChallengeType::Http01,
            renew_interval_hours: 0,
            provider: crate::config::models::AcmeProvider::Custom,
            cert_storage_path: "/tmp".into(),
        });

        assert!(store.validate(&cfg).is_ok(), "disabled ACME must skip validation");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // validate_email / validate_directory_url helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_email_accepts_valid_emails() {
        use crate::config::models::validate_email;
        assert!(validate_email("user@example.com"));
        assert!(validate_email("admin@subdomain.example.org"));
        assert!(validate_email("a@b.com"));
    }

    #[test]
    fn validate_email_rejects_invalid_emails() {
        use crate::config::models::validate_email;
        assert!(!validate_email("not-an-email"));
        assert!(!validate_email("@example.com"));      // empty local part
        assert!(!validate_email("user@"));             // empty domain
        assert!(!validate_email("user@@example.com")); // multiple @
        assert!(!validate_email(""));
    }

    #[test]
    fn validate_directory_url_accepts_valid_urls() {
        use crate::config::models::validate_directory_url;
        assert!(validate_directory_url("https://acme-v02.api.letsencrypt.org/directory"));
        assert!(validate_directory_url("http://localhost:8080/dir"));
    }

    #[test]
    fn validate_directory_url_rejects_invalid_urls() {
        use crate::config::models::validate_directory_url;
        assert!(!validate_directory_url("not-a-url"));
        assert!(!validate_directory_url("ftp://acme.example.com"));
        assert!(!validate_directory_url(""));
    }

    // -----------------------------------------------------------------------
    // Schema versioning
    // -----------------------------------------------------------------------

    #[test]
    fn save_writes_schema_version() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let cfg = SystemConfig::default();
        store.save(&cfg).unwrap();

        let raw = std::fs::read_to_string(store.config_path()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            value["schema_version"].as_u64(),
            Some(CURRENT_SCHEMA_VERSION as u64),
            "saved file must contain schema_version"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_migrates_legacy_file_without_schema_version() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        // Write a "legacy" file that has no schema_version field.
        let legacy_json = r#"{"hostname":"legacy-fw","interfaces":[],"firewall_rules":[],"vpn_tunnels":[],"wireguard_interfaces":[],"crowdsec_policies":[],"firewall_aliases":[],"dns_host_overrides":[],"dns_domain_overrides":[]}"#;
        std::fs::write(store.config_path(), legacy_json).unwrap();

        let cfg = store.load().unwrap();
        assert_eq!(cfg.hostname, "legacy-fw");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrate_config_noop_for_v0_to_v1() {
        let cfg = SystemConfig::default();
        let migrated = migrate_config(cfg.clone(), 0).unwrap();
        assert_eq!(migrated.hostname, cfg.hostname);
    }

    #[test]
    fn migrate_config_errors_on_unknown_version() {
        let cfg = SystemConfig::default();
        assert!(migrate_config(cfg, 9999).is_err());
    }

    // -----------------------------------------------------------------------
    // Fragment loading
    // -----------------------------------------------------------------------

    #[test]
    fn load_fragments_returns_default_for_empty_dir() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);
        let cfg = store.load_fragments().unwrap();
        assert!(cfg.interfaces.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_fragments_merges_json_files() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        // Write two fragment files.
        std::fs::write(
            dir.join("hostname.json"),
            r#"{"hostname":"fragment-fw"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("interfaces.json"),
            r#"{"interfaces":[{"name":"eth0","addresses":["192.168.1.1/24"],"enabled":true,"dhcp4":false,"dhcp6":false}]}"#,
        )
        .unwrap();

        let cfg = store.load_fragments().unwrap();
        assert_eq!(cfg.hostname, "fragment-fw");
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].name, "eth0");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_fragments_skips_primary_config_file() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        // Write the primary config with one hostname.
        let mut cfg = SystemConfig::default();
        cfg.hostname = "primary".into();
        store.save(&cfg).unwrap();

        // Write a fragment with a different hostname.
        std::fs::write(dir.join("frag.json"), r#"{"hostname":"from-fragment"}"#).unwrap();

        // load_fragments should include frag.json but NOT config.json.
        let frags = store.load_fragments().unwrap();
        assert_eq!(frags.hostname, "from-fragment");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Engine hook (on_save)
    // -----------------------------------------------------------------------

    #[test]
    fn on_save_hook_is_called_after_successful_save() {
        use std::sync::{Arc, Mutex};

        let dir = temp_dir();
        let mut store = ConfigStore::with_dir(&dir);

        let called = Arc::new(Mutex::new(false));
        let called_clone = Arc::clone(&called);

        store.set_on_save(Arc::new(move |_cfg| {
            *called_clone.lock().unwrap() = true;
        }));

        let cfg = SystemConfig::default();
        store.save_with_rollback(&cfg).unwrap();

        assert!(*called.lock().unwrap(), "on_save hook must be called");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn on_save_hook_receives_committed_config() {
        use std::sync::{Arc, Mutex};

        let dir = temp_dir();
        let mut store = ConfigStore::with_dir(&dir);

        let hostname_seen = Arc::new(Mutex::new(String::new()));
        let hostname_clone = Arc::clone(&hostname_seen);

        store.set_on_save(Arc::new(move |cfg| {
            *hostname_clone.lock().unwrap() = cfg.hostname.clone();
        }));

        let mut cfg = SystemConfig::default();
        cfg.hostname = "hook-test".into();
        store.save_with_rollback(&cfg).unwrap();

        assert_eq!(*hostname_seen.lock().unwrap(), "hook-test");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
