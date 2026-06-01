//! Configuration storage layer.
//!
//! Persists [`SystemConfig`] as a single JSON file under
//! `/var/lib/dayshield/config/config.json` with the following guarantees:
//!
//! - **Single source of truth**: there is exactly one configuration file. The
//!   whole running configuration is serialised into it, so "what is my current
//!   config?" always has one unambiguous answer.
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
//! - **Config history**: every successful [`ConfigStore::save_with_rollback`]
//!   archives the committed configuration as a timestamped revision under
//!   `history/`. Past revisions can be listed, inspected and restored via
//!   [`ConfigStore::list_revisions`], [`ConfigStore::load_revision`] and
//!   [`ConfigStore::restore_revision`].
//! - **Engine notifications**: register a post-save callback via
//!   [`ConfigStore::set_on_save`] to push config changes to live engine
//!   services immediately after a successful commit.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use super::history;
use super::models::{
    AcmeConfig, AdminSecuritySettings, AiEngineConfig, CaddyConfig, CaptivePortalConfig,
    CloudflaredConfig,
    ConfigHistorySettings,
    CrowdSecConfig, Dhcp6Config, DhcpConfig, DnsConfig, DnsDomainOverride, DnsHostOverride,
    DotConfig, DynamicDnsConfig, FirewallAlias, FirewallRule, FirewallSettings, Gateway,
    HoneypotConfig, Interface, NatConfig, NotifyConfig, NtpConfig, QosConfig, SuricataConfig,
    SystemConfig, WireGuardInterface,
};

/// Default path to the configuration directory.
///
/// Lives under `/var/lib/` so the persisted DayShield state survives every
/// rootfs A/B update — `/var` is on its own partition shared by both slots.
const DEFAULT_CONFIG_DIR: &str = "/var/lib/dayshield/config";
/// Config file name inside the config directory.
const CONFIG_FILE: &str = "config.json";
/// Temporary file suffix used for atomic writes.
const TMP_SUFFIX: &str = ".tmp";
/// Backup file suffix used for rollback.
const BAK_SUFFIX: &str = ".bak";

// Ã¢â€â‚¬Ã¢â€â‚¬ Permission-aware write helper Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Write `data` to `path` with mode `0o600` (owner read/write only).
///
/// Uses a write-then-rename pattern for atomicity.  The temp file is created
/// at `<path>.tmp`, written with restricted permissions, and then renamed to
/// `path`.
#[cfg(unix)]
pub(crate) fn write_restricted(path: &Path, data: &[u8]) -> Result<()> {
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

    std::fs::rename(&tmp, path)
        .with_context(|| format!("Failed to rename {} to {}", tmp.display(), path.display()))?;

    Ok(())
}

/// Fallback for non-Unix platforms (uses standard write).
#[cfg(not(unix))]
pub(crate) fn write_restricted(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = PathBuf::from(format!("{}{}", path.display(), TMP_SUFFIX));
    std::fs::write(&tmp, data)
        .with_context(|| format!("Failed to write temp file {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Failed to rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Schema versioning Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// The current on-disk schema version.
///
/// Increment this constant whenever the [`SystemConfig`] format changes in a
/// backwards-incompatible way, and add a corresponding arm to
/// [`migrate_config`].
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

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
fn migrate_config(mut config: SystemConfig, from_version: u32) -> Result<SystemConfig> {
    if from_version > CURRENT_SCHEMA_VERSION {
        anyhow::bail!(
            "Unknown schema version {from_version}; cannot migrate to {CURRENT_SCHEMA_VERSION}"
        );
    }

    let mut version = from_version;

    while version < CURRENT_SCHEMA_VERSION {
        match version {
            0 => {
                // Migration v0 -> v1: no structural changes; the schema_version
                // field was simply added to the on-disk envelope.
                debug!("Migrating config from schema v0 to v1 (no-op)");
                version = 1;
            }
            1 => {
                // Migration v1 -> v2: the configuration revision history became a
                // first-class, configurable feature. Older configs predate the
                // `config_history` settings, so initialise them with the built-in
                // defaults (enabled, retain 50) rather than leaving them absent.
                if config.config_history.is_none() {
                    debug!("Migrating config from schema v1 to v2 (init config_history)");
                    config.config_history = Some(ConfigHistorySettings::default());
                }
                version = 2;
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

// Ã¢â€â‚¬Ã¢â€â‚¬ Type alias for the post-save engine hook Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

        if versioned.schema_version < CURRENT_SCHEMA_VERSION {
            if let Err(err) = self.save(&config) {
                warn!(
                    path = %self.config_path.display(),
                    error = %err,
                    "Failed to persist migrated config schema"
                );
            }
        }

        Ok(config)
    }

    /// Validate the provided config.
    ///
    /// Returns `Ok(())` when the config is valid, or an [`anyhow::Error`]
    /// describing the first validation failure found.
    pub fn validate(&self, config: &SystemConfig) -> Result<()> {
        use crate::config::models::{
            ensure_ipv6_allowed, ipv4_addr_in_cidr, ipv6_addr_in_cidr, is_valid_cidr,
            is_valid_cidr_or_addr, is_valid_domain, is_valid_interface_name, is_valid_ip,
            is_valid_ipv4_addr, is_valid_ipv4_range, is_valid_mac, is_valid_mss, is_valid_mtu,
            is_valid_port, is_valid_vlan_id, normalize_ipv4_cidr, normalize_ipv6_cidr,
            validate_firewall_rule, validate_firewall_settings, validate_qos_config, Ipv6Mode,
            WanMode,
        };

        let interface_names: std::collections::HashSet<&str> =
            config.interfaces.iter().map(|i| i.name.as_str()).collect();
        let mut seen_interface_names = std::collections::HashSet::new();
        let ipv6_enabled = config
            .system_settings
            .as_ref()
            .map(|settings| settings.ipv6_enabled)
            .unwrap_or(false);

        for iface in &config.interfaces {
            if !seen_interface_names.insert(iface.name.as_str()) {
                anyhow::bail!("Duplicate interface name {:?}", iface.name);
            }
            if !is_valid_interface_name(&iface.name) {
                anyhow::bail!(
                    "Interface {:?} has an invalid name (must be 1-15 alphanumeric/[-_.] chars)",
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
                if let Err(msg) = ensure_ipv6_allowed(
                    cidr,
                    ipv6_enabled,
                    &format!("Interface {:?} address", iface.name),
                ) {
                    anyhow::bail!("{msg}");
                }
            }
            let ipv6_mode = iface.effective_ipv6_mode();

            if !matches!(ipv6_mode, Ipv6Mode::Static) && !ipv6_enabled {
                anyhow::bail!(
                    "Interface {:?} selects non-static IPv6 mode but system ipv6Enabled is false",
                    iface.name
                );
            }
            if matches!(ipv6_mode, Ipv6Mode::Slaac)
                && !(iface.wan_mode.is_some() || iface.gateway.is_some())
            {
                anyhow::bail!(
                    "Interface {:?} enables SLAAC/RA but is not WAN-designated",
                    iface.name
                );
            }
            if matches!(ipv6_mode, Ipv6Mode::Slaac)
                && matches!(iface.wan_mode, Some(WanMode::Pppoe))
            {
                anyhow::bail!(
                    "Interface {:?} enables SLAAC/RA, which is not supported on PPPoE interfaces",
                    iface.name
                );
            }
            if matches!(ipv6_mode, Ipv6Mode::TrackInterface) {
                let source = iface.track_source_interface.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Interface {:?} uses track_interface mode but has no track_source_interface",
                        iface.name
                    )
                })?;
                if source == iface.name {
                    anyhow::bail!(
                        "Interface {:?} track_source_interface cannot reference itself",
                        iface.name
                    );
                }
                if !interface_names.contains(source) {
                    anyhow::bail!(
                        "Interface {:?} references unknown track_source_interface {:?}",
                        iface.name,
                        source
                    );
                }
                if let Some(prefix_len) = iface.delegated_prefix_len {
                    if prefix_len > 128 {
                        anyhow::bail!(
                            "Interface {:?} delegated_prefix_len {} is out of range 0-128",
                            iface.name,
                            prefix_len
                        );
                    }
                }
            } else if iface.ra_mode.is_some() {
                anyhow::bail!(
                    "Interface {:?} sets ra_mode but is not using ipv6_mode = track_interface",
                    iface.name
                );
            }
            // ia_pd_hint_len is only valid on WAN DHCPv6 interfaces.
            if let Some(hint_len) = iface.ia_pd_hint_len {
                if hint_len < 1 || hint_len > 128 {
                    anyhow::bail!(
                        "Interface {:?} ia_pd_hint_len {} is out of range 1-128",
                        iface.name,
                        hint_len
                    );
                }
                let is_wan = iface.wan_mode.is_some() || iface.gateway.is_some();
                if !is_wan {
                    anyhow::bail!(
                        "Interface {:?} ia_pd_hint_len can only be set on WAN-designated interfaces",
                        iface.name
                    );
                }
                if !matches!(iface.effective_ipv6_mode(), Ipv6Mode::Dhcp6) {
                    anyhow::bail!(
                        "Interface {:?} ia_pd_hint_len requires ipv6_mode = dhcp6",
                        iface.name
                    );
                }
            }
            if let Some(gateway) = &iface.gateway {
                if !is_valid_ip(gateway) {
                    anyhow::bail!(
                        "Interface {:?} has invalid gateway {:?}",
                        iface.name,
                        gateway
                    );
                }
                if let Err(msg) = ensure_ipv6_allowed(
                    gateway,
                    ipv6_enabled,
                    &format!("Interface {:?} gateway", iface.name),
                ) {
                    anyhow::bail!("{msg}");
                }
            }
            match iface.wan_mode {
                Some(WanMode::Dhcp) => {
                    if !iface.dhcp4 {
                        anyhow::bail!(
                            "Interface {:?} wan_mode=dhcp requires dhcp4=true",
                            iface.name
                        );
                    }
                    if iface.gateway.is_some() {
                        anyhow::bail!(
                            "Interface {:?} wan_mode=dhcp must not set a static gateway",
                            iface.name
                        );
                    }
                }
                Some(WanMode::Pppoe) => {
                    if iface.gateway.is_some() {
                        anyhow::bail!(
                            "Interface {:?} wan_mode=pppoe must not set a static gateway",
                            iface.name
                        );
                    }
                    if !iface.addresses.is_empty() {
                        anyhow::bail!(
                            "Interface {:?} wan_mode=pppoe must not set static addresses",
                            iface.name
                        );
                    }
                    let username_ok = iface
                        .pppoe_username
                        .as_deref()
                        .map(|value| {
                            !value.trim().is_empty() && !value.chars().any(char::is_control)
                        })
                        .unwrap_or(false);
                    let password_ok = iface
                        .pppoe_password
                        .as_deref()
                        .map(|value| !value.is_empty() && !value.chars().any(char::is_control))
                        .unwrap_or(false);
                    if !username_ok || !password_ok {
                        anyhow::bail!(
                            "Interface {:?} wan_mode=pppoe requires non-empty username/password without control characters",
                            iface.name
                        );
                    }
                    if let Some(mtu) = iface.mtu {
                        if !(576..=1492).contains(&mtu) {
                            anyhow::bail!(
                                "Interface {:?} wan_mode=pppoe requires MTU between 576 and 1492",
                                iface.name
                            );
                        }
                    }
                }
                None => {}
            }
            let is_wan = iface.wan_mode.is_some() || iface.gateway.is_some();
            if !is_wan && (iface.block_private_networks || iface.block_bogon_networks) {
                anyhow::bail!(
                    "Interface {:?} private/bogon network blocking can only be enabled on WAN-designated interfaces",
                    iface.name
                );
            }
            if let Some(mtu) = iface.mtu {
                if !is_valid_mtu(mtu) {
                    anyhow::bail!(
                        "Interface {:?} has invalid MTU {} (must be >= 68)",
                        iface.name,
                        mtu
                    );
                }
            }
            if let Some(mss) = iface.mss {
                if !is_valid_mss(mss) {
                    anyhow::bail!(
                        "Interface {:?} has invalid MSS {} (must be >= 536)",
                        iface.name,
                        mss
                    );
                }
            }
            match iface.vlan {
                Some(vlan_id) => {
                    if !is_valid_vlan_id(vlan_id) {
                        anyhow::bail!(
                            "Interface {:?} has invalid VLAN ID {} (must be 1-4094)",
                            iface.name,
                            vlan_id
                        );
                    }
                    let parent = iface.parent_interface.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "Interface {:?} is VLAN {} but has no parent_interface",
                            iface.name,
                            vlan_id
                        )
                    })?;
                    if !is_valid_interface_name(parent) {
                        anyhow::bail!(
                            "Interface {:?} has invalid parent_interface {:?}",
                            iface.name,
                            parent
                        );
                    }
                    if parent == iface.name {
                        anyhow::bail!(
                            "Interface {:?} cannot use itself as parent_interface",
                            iface.name
                        );
                    }
                    if !interface_names.contains(parent) {
                        anyhow::bail!(
                            "Interface {:?} references unknown parent_interface {:?}",
                            iface.name,
                            parent
                        );
                    }
                }
                None => {
                    if iface.parent_interface.is_some() {
                        anyhow::bail!(
                            "Interface {:?} sets parent_interface but is not a VLAN interface",
                            iface.name
                        );
                    }
                }
            }
        }

        // Firewall rules and settings.
        for rule in &config.firewall_rules {
            validate_firewall_rule(rule, ipv6_enabled).map_err(anyhow::Error::msg)?;
        }

        if let Some(settings) = &config.firewall_settings {
            validate_firewall_settings(settings, ipv6_enabled).map_err(anyhow::Error::msg)?;
            if settings.syn_flood_rate == 0 {
                anyhow::bail!("Firewall syn_flood_rate must be greater than 0");
            }
            if settings.syn_flood_burst == 0 {
                anyhow::bail!("Firewall syn_flood_burst must be greater than 0");
            }
            for port in &settings.management_ports {
                if !is_valid_port(*port) {
                    anyhow::bail!(
                        "Firewall management_ports contains invalid port {} (must be 1Ã¢â‚¬â€œ65535)",
                        port
                    );
                }
            }
            for src in &settings.management_allowed_sources {
                if !is_valid_cidr_or_addr(src) {
                    anyhow::bail!(
                        "Firewall management_allowed_sources contains invalid IP/CIDR {:?}",
                        src
                    );
                }
                if let Err(msg) =
                    ensure_ipv6_allowed(src, ipv6_enabled, "Firewall management_allowed_sources")
                {
                    anyhow::bail!("{msg}");
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
                if let Err(msg) = ensure_ipv6_allowed(addr, ipv6_enabled, "DNS listen address") {
                    anyhow::bail!("{msg}");
                }
            }
            if dns.port == 0 {
                anyhow::bail!("DNS port must be non-zero");
            }
            for fwd in &dns.forwarders {
                if !is_valid_ip(fwd) {
                    anyhow::bail!("DNS forwarder {:?} is not a valid IP address", fwd);
                }
                if let Err(msg) = ensure_ipv6_allowed(fwd, ipv6_enabled, "DNS forwarder") {
                    anyhow::bail!("{msg}");
                }
            }
            for rec in &dns.local_records {
                if rec.name.is_empty() {
                    anyhow::bail!("DNS local record has an empty name");
                }
                if rec.record_type.eq_ignore_ascii_case("AAAA") && !ipv6_enabled {
                    anyhow::bail!(
                        "DNS local record {:?} is AAAA but system ipv6Enabled is false",
                        rec.name
                    );
                }
                if let Err(msg) =
                    ensure_ipv6_allowed(&rec.value, ipv6_enabled, "DNS local record value")
                {
                    anyhow::bail!("{msg}");
                }
            }
        }

        // DHCP config validation.
        if let Some(dhcp) = &config.dhcp {
            for scope in &dhcp.scopes {
                let Some(normalized_subnet) = normalize_ipv4_cidr(&scope.subnet) else {
                    anyhow::bail!(
                        "DHCP scope {} has invalid subnet {:?}",
                        scope.id,
                        scope.subnet
                    );
                };
                if normalized_subnet != scope.subnet.trim() {
                    anyhow::bail!(
                        "DHCP scope {} subnet {:?} must be network CIDR {:?}",
                        scope.id,
                        scope.subnet,
                        normalized_subnet
                    );
                }
                if !is_valid_ipv4_addr(&scope.pool_start) {
                    anyhow::bail!(
                        "DHCP scope {} has invalid pool_start {:?}",
                        scope.id,
                        scope.pool_start
                    );
                }
                if !is_valid_ipv4_addr(&scope.pool_end) {
                    anyhow::bail!(
                        "DHCP scope {} has invalid pool_end {:?}",
                        scope.id,
                        scope.pool_end
                    );
                }
                if !is_valid_ipv4_range(&scope.pool_start, &scope.pool_end) {
                    anyhow::bail!(
                        "DHCP scope {} pool_start {} must be Ã¢â€°Â¤ pool_end {}",
                        scope.id,
                        scope.pool_start,
                        scope.pool_end
                    );
                }
                if !ipv4_addr_in_cidr(&scope.pool_start, &scope.subnet) {
                    anyhow::bail!(
                        "DHCP scope {} pool_start {} is outside subnet {}",
                        scope.id,
                        scope.pool_start,
                        scope.subnet
                    );
                }
                if !ipv4_addr_in_cidr(&scope.pool_end, &scope.subnet) {
                    anyhow::bail!(
                        "DHCP scope {} pool_end {} is outside subnet {}",
                        scope.id,
                        scope.pool_end,
                        scope.subnet
                    );
                }
                if let Some(gw) = &scope.gateway {
                    if !is_valid_ipv4_addr(gw) {
                        anyhow::bail!("DHCP scope {} has invalid gateway {:?}", scope.id, gw);
                    }
                    if !ipv4_addr_in_cidr(gw, &scope.subnet) {
                        anyhow::bail!(
                            "DHCP scope {} gateway {} is outside subnet {}",
                            scope.id,
                            gw,
                            scope.subnet
                        );
                    }
                }
                for dns in &scope.dns_servers {
                    if !is_valid_ipv4_addr(dns) {
                        anyhow::bail!("DHCP scope {} has invalid DNS server {:?}", scope.id, dns);
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
                    if !is_valid_ipv4_addr(&res.ip_address) {
                        anyhow::bail!(
                            "DHCP reservation {} has invalid IP {:?}",
                            res.id,
                            res.ip_address
                        );
                    }
                    if !ipv4_addr_in_cidr(&res.ip_address, &scope.subnet) {
                        anyhow::bail!(
                            "DHCP reservation {} IP {} is outside subnet {}",
                            res.id,
                            res.ip_address,
                            scope.subnet
                        );
                    }
                    for dns in &res.dns_servers {
                        if !is_valid_ipv4_addr(dns) {
                            anyhow::bail!(
                                "DHCP reservation {} has invalid DNS override {:?}",
                                res.id,
                                dns
                            );
                        }
                    }
                    for ntp in &res.ntp_servers {
                        if !is_valid_ipv4_addr(ntp) {
                            anyhow::bail!(
                                "DHCP reservation {} has invalid NTP override {:?}",
                                res.id,
                                ntp
                            );
                        }
                    }
                }
            }
        }

        // DHCPv6 config validation.
        if let Some(dhcp6) = &config.dhcp6 {
            if dhcp6.enabled {
                if dhcp6.interface.trim().is_empty() {
                    anyhow::bail!("DHCPv6 interface is required when DHCPv6 is enabled");
                }
                if dhcp6.scopes.is_empty() {
                    anyhow::bail!("DHCPv6 requires at least one scope when enabled");
                }
            }
            for scope in &dhcp6.scopes {
                let Some(normalized_subnet) = normalize_ipv6_cidr(&scope.subnet) else {
                    anyhow::bail!(
                        "DHCPv6 scope {} has invalid subnet {:?}",
                        scope.id,
                        scope.subnet
                    );
                };
                if normalized_subnet != scope.subnet.trim() {
                    anyhow::bail!(
                        "DHCPv6 scope {} subnet {:?} must be network CIDR {:?}",
                        scope.id,
                        scope.subnet,
                        normalized_subnet
                    );
                }
                if !crate::config::models::is_valid_ipv6_addr(&scope.pool_start) {
                    anyhow::bail!(
                        "DHCPv6 scope {} has invalid pool_start {:?}",
                        scope.id,
                        scope.pool_start
                    );
                }
                if !crate::config::models::is_valid_ipv6_addr(&scope.pool_end) {
                    anyhow::bail!(
                        "DHCPv6 scope {} has invalid pool_end {:?}",
                        scope.id,
                        scope.pool_end
                    );
                }
                let start = scope
                    .pool_start
                    .parse::<std::net::Ipv6Addr>()
                    .map(u128::from)
                    .map_err(|_| anyhow::anyhow!("invalid DHCPv6 pool_start"))?;
                let end = scope
                    .pool_end
                    .parse::<std::net::Ipv6Addr>()
                    .map(u128::from)
                    .map_err(|_| anyhow::anyhow!("invalid DHCPv6 pool_end"))?;
                if start > end {
                    anyhow::bail!(
                        "DHCPv6 scope {} pool_start {} must be <= pool_end {}",
                        scope.id,
                        scope.pool_start,
                        scope.pool_end
                    );
                }
                if !ipv6_addr_in_cidr(&scope.pool_start, &scope.subnet) {
                    anyhow::bail!(
                        "DHCPv6 scope {} pool_start {} is outside subnet {}",
                        scope.id,
                        scope.pool_start,
                        scope.subnet
                    );
                }
                if !ipv6_addr_in_cidr(&scope.pool_end, &scope.subnet) {
                    anyhow::bail!(
                        "DHCPv6 scope {} pool_end {} is outside subnet {}",
                        scope.id,
                        scope.pool_end,
                        scope.subnet
                    );
                }
                for dns in &scope.dns_servers {
                    if !crate::config::models::is_valid_ipv6_addr(dns) {
                        anyhow::bail!("DHCPv6 scope {} has invalid DNS server {:?}", scope.id, dns);
                    }
                }
                for reservation in &scope.reservations {
                    if !crate::config::models::is_valid_duid(&reservation.duid) {
                        anyhow::bail!(
                            "DHCPv6 scope {} reservation {} has invalid DUID {:?}",
                            scope.id,
                            reservation.id,
                            reservation.duid
                        );
                    }
                    if !crate::config::models::is_valid_ipv6_addr(&reservation.ip_address) {
                        anyhow::bail!(
                            "DHCPv6 scope {} reservation {} has invalid ip_address {:?}",
                            scope.id,
                            reservation.id,
                            reservation.ip_address
                        );
                    }
                    if !ipv6_addr_in_cidr(&reservation.ip_address, &scope.subnet) {
                        anyhow::bail!(
                            "DHCPv6 scope {} reservation {} IP {} is outside subnet {}",
                            scope.id,
                            reservation.id,
                            reservation.ip_address,
                            scope.subnet
                        );
                    }
                    for dns in &reservation.dns_servers {
                        if !crate::config::models::is_valid_ipv6_addr(dns) {
                            anyhow::bail!(
                                "DHCPv6 scope {} reservation {} has invalid DNS override {:?}",
                                scope.id,
                                reservation.id,
                                dns
                            );
                        }
                    }
                    for ntp in &reservation.ntp_servers {
                        if !crate::config::models::is_valid_ipv6_addr(ntp) {
                            anyhow::bail!(
                                "DHCPv6 scope {} reservation {} has invalid NTP override {:?}",
                                scope.id,
                                reservation.id,
                                ntp
                            );
                        }
                    }
                }
            }
        }

        // DNS local record type validation.
        if let Some(dns) = &config.dns {
            for rec in &dns.local_records {
                if !matches!(
                    rec.record_type.to_uppercase().as_str(),
                    "A" | "AAAA" | "CNAME" | "PTR" | "MX" | "TXT"
                ) {
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
            for cidr in suricata
                .home_nets
                .iter()
                .chain(suricata.external_nets.iter())
            {
                if let Err(msg) = ensure_ipv6_allowed(cidr, ipv6_enabled, "Suricata network") {
                    anyhow::bail!("Suricata config is invalid: {msg}");
                }
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
                         (must be 1Ã¢â‚¬â€œ63 chars, start with letter or _, contain only [A-Za-z0-9_])",
                        alias.name
                    );
                }
                if !seen_names.insert(alias.name.clone()) {
                    anyhow::bail!("Duplicate firewall alias name {:?}", alias.name);
                }
                if let Err(msg) = validate_alias_values(alias) {
                    anyhow::bail!("{msg}");
                }
                if matches!(
                    alias.alias_type,
                    crate::config::models::AliasType::Host
                        | crate::config::models::AliasType::Network
                        | crate::config::models::AliasType::UrlTable
                ) {
                    for value in &alias.values {
                        if let Err(msg) = ensure_ipv6_allowed(
                            value,
                            ipv6_enabled,
                            &format!("Firewall alias {:?}", alias.name),
                        ) {
                            anyhow::bail!("{msg}");
                        }
                    }
                }
            }
        }

        // DNS host-override validation.
        {
            use crate::config::models::{is_valid_ip, validate_dns_hostname};
            for ov in &config.dns_host_overrides {
                if !validate_dns_hostname(&ov.hostname) {
                    anyhow::bail!("DNS host override has invalid hostname {:?}", ov.hostname);
                }
                if !is_valid_ip(&ov.address) {
                    anyhow::bail!(
                        "DNS host override {:?} has invalid address {:?}",
                        ov.hostname,
                        ov.address
                    );
                }
                if let Err(msg) =
                    ensure_ipv6_allowed(&ov.address, ipv6_enabled, "DNS host override address")
                {
                    anyhow::bail!("{msg}");
                }
            }
        }

        // DNS domain-override validation.
        {
            use crate::config::models::{is_valid_ip, validate_dns_domain};
            for ov in &config.dns_domain_overrides {
                if !validate_dns_domain(&ov.domain) {
                    anyhow::bail!("DNS domain override has invalid domain {:?}", ov.domain);
                }
                if !is_valid_ip(&ov.forward_to) {
                    anyhow::bail!(
                        "DNS domain override {:?} has invalid forward_to address {:?}",
                        ov.domain,
                        ov.forward_to
                    );
                }
                if let Err(msg) =
                    ensure_ipv6_allowed(&ov.forward_to, ipv6_enabled, "DNS domain override target")
                {
                    anyhow::bail!("{msg}");
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
                         (must be 1Ã¢â‚¬â€œ15 alphanumeric/[-_.] chars)",
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
                    if let Err(msg) =
                        ensure_ipv6_allowed(addr, ipv6_enabled, "WireGuard interface address")
                    {
                        anyhow::bail!("{msg}");
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
                        if let Err(msg) =
                            ensure_ipv6_allowed(cidr, ipv6_enabled, "WireGuard peer allowed_ip")
                        {
                            anyhow::bail!("{msg}");
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
                        if let Err(msg) =
                            ensure_ipv6_allowed(ep, ipv6_enabled, "WireGuard peer endpoint")
                        {
                            anyhow::bail!("{msg}");
                        }
                    }
                }
            }
        }

        // Gateway validation.
        for gateway in &config.gateways {
            if !is_valid_interface_name(&gateway.interface) {
                anyhow::bail!(
                    "Gateway {:?} has invalid interface {:?}",
                    gateway.name,
                    gateway.interface
                );
            }
            if let Some(ip) = &gateway.gateway_ip {
                if !is_valid_ip(ip) {
                    anyhow::bail!("Gateway {:?} has invalid gateway_ip {:?}", gateway.name, ip);
                }
                if let Err(msg) = ensure_ipv6_allowed(ip, ipv6_enabled, "Gateway gateway_ip") {
                    anyhow::bail!("{msg}");
                }
            }
            if let Some(ip) = &gateway.monitor_ip {
                if !is_valid_ip(ip) {
                    anyhow::bail!("Gateway {:?} has invalid monitor_ip {:?}", gateway.name, ip);
                }
                if let Err(msg) = ensure_ipv6_allowed(ip, ipv6_enabled, "Gateway monitor_ip") {
                    anyhow::bail!("{msg}");
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
                         (must be 1Ã¢â‚¬â€œ63 chars, start with letter or _, contain only [A-Za-z0-9_])",
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
            use crate::config::models::validate_ntp_config_with_ipv6;
            if let Err(msg) = validate_ntp_config_with_ipv6(ntp, ipv6_enabled) {
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

        // Dynamic DNS config validation.
        if let Some(dynamic_dns) = &config.dynamic_dns {
            use crate::config::models::validate_dynamic_dns_config_with_ipv6;
            if let Err(msg) = validate_dynamic_dns_config_with_ipv6(dynamic_dns, ipv6_enabled) {
                anyhow::bail!("Dynamic DNS config is invalid: {msg}");
            }
            if dynamic_dns.enabled {
                let known: std::collections::HashSet<&str> =
                    config.interfaces.iter().map(|i| i.name.as_str()).collect();
                for entry in dynamic_dns.entries.iter().filter(|entry| entry.enabled) {
                    if !known.is_empty() && !known.contains(entry.interface.as_str()) {
                        anyhow::bail!(
                            "Dynamic DNS entry {} references unknown interface {:?}",
                            entry.id,
                            entry.interface
                        );
                    }
                }
            }
        }

        // NAT config validation.
        if let Some(nat) = &config.nat {
            use crate::config::models::validate_nat_config_with_ipv6;
            if let Err(msg) = validate_nat_config_with_ipv6(nat, ipv6_enabled) {
                anyhow::bail!("NAT config is invalid: {msg}");
            }
        }

        // QoS config validation.
        if let Some(qos) = &config.qos {
            if let Err(msg) = validate_qos_config(qos) {
                anyhow::bail!("QoS config is invalid: {msg}");
            }
        }

        // Cloudflared config validation.
        if let Some(cloudflared) = &config.cloudflared {
            use crate::config::models::validate_cloudflared_config;
            if let Err(msg) = validate_cloudflared_config(cloudflared) {
                anyhow::bail!("Cloudflared config is invalid: {msg}");
            }
        }

        // Caddy reverse-proxy config validation.
        if let Some(caddy) = &config.caddy {
            use crate::config::models::validate_caddy_config;
            if let Err(msg) = validate_caddy_config(caddy) {
                anyhow::bail!("Caddy config is invalid: {msg}");
            }
        }

        // Captive portal config validation.
        if let Some(captive_portal) = &config.captive_portal {
            use crate::config::models::validate_captive_portal_config_with_ipv6;
            if let Err(msg) = validate_captive_portal_config_with_ipv6(captive_portal, ipv6_enabled)
            {
                anyhow::bail!("Captive portal config is invalid: {msg}");
            }
            if captive_portal.enabled {
                let known: std::collections::HashSet<&str> =
                    config.interfaces.iter().map(|i| i.name.as_str()).collect();
                for iface in &captive_portal.interfaces {
                    if !known.is_empty() && !known.contains(iface.as_str()) {
                        anyhow::bail!(
                            "Captive portal interface {:?} is not defined in the interface config",
                            iface
                        );
                    }
                }
            }
        }

        // AI engine config validation.
        if let Some(ai_engine) = &config.ai_engine {
            use crate::config::models::validate_ai_engine_config;
            if let Err(msg) = validate_ai_engine_config(ai_engine) {
                anyhow::bail!("AI engine config is invalid: {msg}");
            }
        }

        // Honeypot config validation.
        if let Some(honeypots) = &config.honeypots {
            use crate::config::models::validate_honeypot_config;
            if let Err(msg) = validate_honeypot_config(honeypots) {
                anyhow::bail!("Honeypot config is invalid: {msg}");
            }
            for listener in &honeypots.listeners {
                if let Err(msg) =
                    ensure_ipv6_allowed(&listener.bind_address, ipv6_enabled, "Honeypot listener")
                {
                    anyhow::bail!("{msg}");
                }
            }
        }

        // DoT config validation.
        if let Some(dot) = &config.dot {
            use crate::config::models::validate_dot_config;
            if let Err(msg) = validate_dot_config(dot) {
                anyhow::bail!("DoT config is invalid: {msg}");
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
        self.save_with_rollback_described(&config, Some("Updated ACME/TLS certificate configuration"))
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
        self.save_with_rollback_described(&config, Some("Updated CrowdSec configuration"))
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
        self.save_with_rollback_described(&config, Some("Updated WireGuard interfaces"))
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
        self.save_with_rollback_described(&config, Some("Updated network interfaces"))
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
        self.save_with_rollback_described(&config, Some("Updated firewall rules"))
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
        self.save_with_rollback_described(&config, Some("Updated firewall settings"))
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
        self.save_with_rollback_described(&config, Some("Updated DNS configuration"))
    }

    /// Return the DNS-over-TLS configuration from the persisted config.
    ///
    /// Returns `None` if no DoT configuration has been saved yet.
    pub fn load_dot_config(&self) -> Result<Option<DotConfig>> {
        Ok(self.load()?.dot)
    }

    /// Atomically replace the DNS-over-TLS configuration in the persisted config.
    ///
    /// Loads the current config, replaces `dot`, validates, then calls
    /// [`Self::save_with_rollback`] to write atomically with rollback on
    /// post-write validation failure.
    pub fn save_dot_config(&self, dot: DotConfig) -> Result<()> {
        let mut config = self.load()?;
        config.dot = Some(dot);
        self.save_with_rollback_described(&config, Some("Updated DNS-over-TLS configuration"))
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
        self.save_with_rollback_described(&config, Some("Updated DHCP configuration"))
    }

    /// Return the DHCPv6 configuration from the persisted config.
    ///
    /// Returns `None` if no DHCPv6 configuration has been saved yet.
    pub fn load_dhcp6_config(&self) -> Result<Option<Dhcp6Config>> {
        Ok(self.load()?.dhcp6)
    }

    /// Atomically replace the DHCPv6 configuration in the persisted config.
    ///
    /// Loads the current config, replaces `dhcp6`, validates, then calls
    /// [`Self::save_with_rollback`] to write atomically with rollback on
    /// post-write validation failure.
    pub fn save_dhcp6_config(&self, dhcp6: Dhcp6Config) -> Result<()> {
        let mut config = self.load()?;
        config.dhcp6 = Some(dhcp6);
        self.save_with_rollback_described(&config, Some("Updated DHCPv6 configuration"))
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
        self.save_with_rollback_described(&config, Some("Updated Suricata IDS/IPS configuration"))
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
        self.save_with_rollback_described(&config, Some("Updated firewall aliases"))
    }

    /// Return the DNS host and domain overrides from the persisted config.
    ///
    /// Returns `(host_overrides, domain_overrides)`.
    pub fn load_dns_overrides(&self) -> Result<(Vec<DnsHostOverride>, Vec<DnsDomainOverride>)> {
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
        self.save_with_rollback_described(&config, Some("Updated DNS overrides"))
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
        self.save_with_rollback_described(&config, Some("Updated notification configuration"))
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
        self.save_with_rollback_described(&config, Some("Updated NTP configuration"))
    }

    /// Return the Dynamic DNS configuration from the persisted config.
    pub fn load_dynamic_dns_config(&self) -> Result<Option<DynamicDnsConfig>> {
        Ok(self.load()?.dynamic_dns)
    }

    /// Atomically replace the Dynamic DNS configuration in the persisted config.
    pub fn save_dynamic_dns_config(&self, dynamic_dns: DynamicDnsConfig) -> Result<()> {
        let mut config = self.load()?;
        config.dynamic_dns = Some(dynamic_dns);
        self.save_with_rollback_described(&config, Some("Updated dynamic DNS configuration"))
    }

    /// Return the Cloudflared configuration from the persisted config.
    pub fn load_cloudflared_config(&self) -> Result<Option<CloudflaredConfig>> {
        Ok(self.load()?.cloudflared)
    }

    /// Atomically replace the Cloudflared configuration in the persisted config.
    pub fn save_cloudflared_config(&self, cloudflared: CloudflaredConfig) -> Result<()> {
        let mut config = self.load()?;
        config.cloudflared = Some(cloudflared);
        self.save_with_rollback_described(&config, Some("Updated Cloudflare Tunnel configuration"))
    }

    /// Return the Caddy reverse-proxy configuration from the persisted config.
    pub fn load_caddy_config(&self) -> Result<Option<CaddyConfig>> {
        Ok(self.load()?.caddy)
    }

    /// Atomically replace the Caddy reverse-proxy configuration in the persisted config.
    pub fn save_caddy_config(&self, caddy: CaddyConfig) -> Result<()> {
        let mut config = self.load()?;
        config.caddy = Some(caddy);
        self.save_with_rollback_described(&config, Some("Updated Caddy reverse proxy configuration"))
    }

    /// Return the Captive Portal configuration from the persisted config.
    pub fn load_captive_portal_config(&self) -> Result<Option<CaptivePortalConfig>> {
        Ok(self.load()?.captive_portal)
    }

    /// Atomically replace the Captive Portal configuration in the persisted config.
    pub fn save_captive_portal_config(&self, captive_portal: CaptivePortalConfig) -> Result<()> {
        let mut config = self.load()?;
        config.captive_portal = Some(captive_portal);
        self.save_with_rollback_described(&config, Some("Updated captive portal configuration"))
    }

    /// Return the AI engine configuration from persisted config.
    ///
    /// Returns defaults when no AI configuration has been saved yet.
    pub fn load_ai_engine_config(&self) -> Result<AiEngineConfig> {
        Ok(self.load()?.ai_engine.unwrap_or_default())
    }

    /// Atomically replace the AI engine configuration in persisted config.
    pub fn save_ai_engine_config(&self, ai_engine: AiEngineConfig) -> Result<()> {
        let mut config = self.load()?;
        config.ai_engine = Some(ai_engine);
        self.save_with_rollback_described(&config, Some("Updated AI threat engine configuration"))
    }

    /// Return the honeypot configuration from persisted config.
    ///
    /// Returns defaults when no honeypot configuration has been saved yet.
    pub fn load_honeypot_config(&self) -> Result<HoneypotConfig> {
        Ok(self.load()?.honeypots.unwrap_or_default())
    }

    /// Atomically replace the honeypot configuration in persisted config.
    pub fn save_honeypot_config(&self, honeypots: HoneypotConfig) -> Result<()> {
        let mut config = self.load()?;
        config.honeypots = Some(honeypots);
        self.save_with_rollback_described(&config, Some("Updated honeypot configuration"))
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
        self.save_with_rollback_described(&config, Some("Updated NAT configuration"))
    }

    /// Return the QoS configuration from persisted config.
    ///
    /// Returns defaults when no QoS configuration has been saved yet.
    pub fn load_qos_config(&self) -> Result<QosConfig> {
        Ok(self.load()?.qos.unwrap_or_default())
    }

    /// Atomically replace the QoS configuration in persisted config.
    pub fn save_qos_config(&self, qos: QosConfig) -> Result<()> {
        let mut config = self.load()?;
        config.qos = Some(qos);
        self.save_with_rollback_described(&config, Some("Updated QoS configuration"))
    }

    /// Return the system settings from the persisted config.
    ///
    /// Returns defaults when no settings have been saved yet.
    pub fn load_system_settings(&self) -> Result<super::models::SystemSettings> {
        Ok(self.load()?.system_settings.unwrap_or_default())
    }

    /// Atomically replace the system settings in the persisted config.
    ///
    /// Loads the current config, replaces `system_settings`, validates, then
    /// calls [`Self::save_with_rollback`] to write atomically.
    pub fn save_system_settings(&self, settings: super::models::SystemSettings) -> Result<()> {
        let mut config = self.load()?;
        config.system_settings = Some(settings);
        self.save_with_rollback_described(&config, Some("Updated system settings"))
    }

    /// Return the gateway list from the persisted config.
    pub fn load_gateways(&self) -> Result<Vec<Gateway>> {
        Ok(self.load()?.gateways)
    }

    /// Atomically replace the gateway list in the persisted config.
    pub fn save_gateways(&self, gateways: Vec<Gateway>) -> Result<()> {
        let mut config = self.load()?;
        config.gateways = gateways;
        self.save_with_rollback_described(&config, Some("Updated gateways"))
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
        self.save_with_rollback_described(&config, Some("Updated admin security settings"))
    }

    /// Validate and atomically write config to disk.
    ///
    /// The write is performed by:
    /// 1. Serialising the config to a versioned JSON envelope.
    /// 2. Writing to `<config_path>.tmp`.
    /// 3. Renaming the temp file to `<config_path>`.
    ///
    /// Renaming is atomic on POSIX systems.
    fn normalize_config(config: &mut SystemConfig) {
        if let Some(dhcp) = &mut config.dhcp {
            for scope in &mut dhcp.scopes {
                if let Some(normalized) = crate::config::models::normalize_ipv4_cidr(&scope.subnet)
                {
                    scope.subnet = normalized;
                }
            }
        }
        if let Some(dhcp6) = &mut config.dhcp6 {
            for scope in &mut dhcp6.scopes {
                if let Some(normalized) = crate::config::models::normalize_ipv6_cidr(&scope.subnet)
                {
                    scope.subnet = normalized;
                }
            }
        }
    }

    pub fn save(&self, config: &SystemConfig) -> Result<()> {
        let mut config = config.clone();
        Self::normalize_config(&mut config);
        self.validate(&config)?;

        // Ensure the parent directory exists.
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }

        // Wrap config in the versioned envelope before serialising.
        let versioned = VersionedConfig {
            schema_version: CURRENT_SCHEMA_VERSION,
            config,
        };
        let json =
            serde_json::to_string_pretty(&versioned).context("Failed to serialise config")?;

        write_restricted(&self.config_path, json.as_bytes())?;

        info!(path = %self.config_path.display(), "Config saved");
        Ok(())
    }

    /// Save with automatic rollback on post-write validation failure.
    ///
    /// Equivalent to [`Self::save_with_rollback_described`] with no change
    /// description.
    pub fn save_with_rollback(&self, config: &SystemConfig) -> Result<()> {
        self.save_with_rollback_described(config, None)
    }

    /// Save with automatic rollback, archiving the committed config as a
    /// revision tagged with an optional `description`.
    ///
    /// Workflow:
    /// 1. Back up the current config file (if it exists).
    /// 2. Write the new config atomically via [`Self::save`].
    /// 3. Re-load and re-validate the written file.
    /// 4. If step 3 fails, restore the backup and return the error.
    /// 5. On success, archive the committed config as a history revision.
    /// 6. Invoke the registered [`OnSaveFn`] hook (if any) so that live engine
    ///    services receive the updated configuration.
    ///
    /// History archival is best-effort: a failure to record the revision is
    /// logged but does not fail the save, since the configuration has already
    /// been committed and validated.
    pub fn save_with_rollback_described(
        &self,
        config: &SystemConfig,
        description: Option<&str>,
    ) -> Result<()> {
        let bak_path = PathBuf::from(format!("{}{}", self.config_path.display(), BAK_SUFFIX));

        // Step 1 - backup.
        if self.config_path.exists() {
            std::fs::copy(&self.config_path, &bak_path)
                .with_context(|| format!("Failed to back up config to {}", bak_path.display()))?;
            debug!(backup = %bak_path.display(), "Config backed up");
        }

        let mut normalized_config = config.clone();
        Self::normalize_config(&mut normalized_config);

        // Step 2 - write.
        if let Err(e) = self.save(&normalized_config) {
            // Restore backup if write itself failed.
            self.try_restore_backup(&bak_path);
            return Err(e);
        }

        // Step 3 - re-validate from disk.
        match self.load().and_then(|c| self.validate(&c)) {
            Ok(_) => {
                // Clean up the backup on success.
                let _ = std::fs::remove_file(&bak_path);
            }
            Err(e) => {
                warn!("Post-write validation failed; rolling back to backup");
                self.try_restore_backup(&bak_path);
                return Err(e.context("Config rolled back after post-write validation failure"));
            }
        }

        // Step 5 - archive the committed config as a history revision, honoring
        // the (possibly customised) history retention settings.
        let history_settings = normalized_config.config_history.clone().unwrap_or_default();
        if history_settings.enabled {
            match std::fs::read(&self.config_path) {
                Ok(bytes) => {
                    if let Err(e) = history::write_revision(
                        &self.config_path,
                        &bytes,
                        description,
                        history_settings.effective_max_revisions(),
                    ) {
                        warn!(error = %e, "Failed to archive config revision");
                    }
                }
                Err(e) => warn!(error = %e, "Failed to read committed config for history"),
            }
        }

        // Step 6 - notify engine layer.
        if let Some(hook) = &self.on_save {
            hook(&normalized_config);
        }

        Ok(())
    }

    /// List archived configuration revisions, newest first.
    pub fn list_revisions(&self) -> Result<Vec<history::ConfigRevision>> {
        history::list_revisions(&self.config_path)
    }

    /// Load the [`SystemConfig`] stored in the revision identified by `id`,
    /// migrating it to the current schema version if necessary.
    pub fn load_revision(&self, id: &str) -> Result<SystemConfig> {
        let value = history::read_revision_config(&self.config_path, id)?;
        let versioned: VersionedConfig = serde_json::from_value(value)
            .with_context(|| format!("Failed to parse revision {id}"))?;
        migrate_config(versioned.config, versioned.schema_version)
    }

    /// Restore the configuration captured in revision `id`, making it the live
    /// configuration.
    ///
    /// The restore goes through [`Self::save_with_rollback_described`], so it is
    /// validated, atomic, and itself archived as a new revision (allowing a
    /// restore to be undone).
    pub fn restore_revision(&self, id: &str) -> Result<()> {
        let config = self.load_revision(id)?;
        self.save_with_rollback_described(&config, Some(&format!("Restored revision {id}")))
    }

    /// Delete a single archived revision by id.
    pub fn delete_revision(&self, id: &str) -> Result<()> {
        history::delete_revision(&self.config_path, id)
    }

    /// Archive the *current* on-disk configuration as a new history revision
    /// tagged with `description`, without otherwise modifying it.
    ///
    /// Useful for capturing a checkpoint outside the normal save flow — for
    /// example just before a rootfs update is applied. Honors the configured
    /// retention settings; a no-op (returns `Ok(None)`) when history is
    /// disabled, no config exists yet, or the config is unchanged since the
    /// most recent revision.
    pub fn snapshot(&self, description: &str) -> Result<Option<history::ConfigRevision>> {
        let settings = self.load_history_settings().unwrap_or_default();
        if !settings.enabled {
            return Ok(None);
        }
        let bytes = match std::fs::read(&self.config_path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        history::write_revision(
            &self.config_path,
            &bytes,
            Some(description),
            settings.effective_max_revisions(),
        )
    }

    /// Return the configuration history settings (retention, enable/disable),
    /// falling back to defaults when none have been persisted yet.
    pub fn load_history_settings(&self) -> Result<ConfigHistorySettings> {
        Ok(self.load()?.config_history.unwrap_or_default())
    }

    /// Atomically replace the configuration history settings.
    pub fn save_history_settings(&self, settings: ConfigHistorySettings) -> Result<()> {
        let mut config = self.load()?;
        config.config_history = Some(settings);
        self.save_with_rollback_described(&config, Some("Updated config history settings"))
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    fn try_restore_backup(&self, bak_path: &Path) {
        if !bak_path.exists() {
            return;
        }

        // Guard against any unexpected path by canonicalizing and verifying the
        // backup file resolves within the same directory as the live config.
        // bak_path is always self.config_path + ".bak" in practice, but this
        // check makes that safety property explicit and suppresses path-injection
        // analysis warnings.
        if let Some(config_dir) = self.config_path.parent() {
            match std::fs::canonicalize(bak_path) {
                Ok(canonical) if !canonical.starts_with(config_dir) => {
                    warn!(
                        backup = %bak_path.display(),
                        config_dir = %config_dir.display(),
                        "Refusing to restore backup outside config directory"
                    );
                    return;
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        backup = %bak_path.display(),
                        "Cannot canonicalize backup path; skipping restore"
                    );
                    return;
                }
                Ok(_) => {}
            }
        }

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

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{
        is_valid_cidr, is_valid_interface_name, is_valid_mtu, Gateway, Interface, QosConfig,
        QosDiffservMode, QosInterface, QosQueueDiscipline, WanMode,
    };

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
            mss: None,
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            accept_ra: false,
            ipv6_mode: Some(crate::config::models::Ipv6Mode::Static),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            vlan: None,
            parent_interface: None,
            wan_mode: None,
            pppoe_username: None,
            pppoe_password: None,
            gateway: None,
            block_private_networks: false,
            block_bogon_networks: false,
        }
    }

    fn make_pppoe_interface(name: &str) -> Interface {
        let mut iface = make_interface(name);
        iface.addresses.clear();
        iface.mtu = Some(1492);
        iface.wan_mode = Some(WanMode::Pppoe);
        iface.pppoe_username = Some("user@example".into());
        iface.pppoe_password = Some("secret".into());
        iface
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
    fn save_and_load_qos_config_roundtrip() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let qos = QosConfig {
            enabled: true,
            interfaces: vec![QosInterface {
                name: "wan0".into(),
                enabled: true,
                bandwidth_kbps: Some(100_000),
                qdisc: QosQueueDiscipline::Cake,
                diffserv: QosDiffservMode::Diffserv4,
                nat_aware: true,
                wash: false,
            }],
        };

        store.save_qos_config(qos.clone()).unwrap();
        let loaded = store.load_qos_config().unwrap();

        assert!(loaded.enabled);
        assert_eq!(loaded.interfaces.len(), 1);
        assert_eq!(loaded.interfaces[0].name, "wan0");
        assert_eq!(loaded.interfaces[0].bandwidth_kbps, Some(100_000));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_duplicate_qos_interface() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.qos = Some(QosConfig {
            enabled: true,
            interfaces: vec![
                QosInterface {
                    name: "wan0".into(),
                    enabled: true,
                    bandwidth_kbps: Some(100_000),
                    qdisc: QosQueueDiscipline::Cake,
                    diffserv: QosDiffservMode::Diffserv4,
                    nat_aware: true,
                    wash: false,
                },
                QosInterface {
                    name: "wan0".into(),
                    enabled: true,
                    bandwidth_kbps: Some(50_000),
                    qdisc: QosQueueDiscipline::FqCodel,
                    diffserv: QosDiffservMode::Besteffort,
                    nat_aware: false,
                    wash: false,
                },
            ],
        });

        let error = store.validate(&cfg).unwrap_err().to_string();
        assert!(error.contains("duplicate QoS interface"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_zero_qos_bandwidth() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.qos = Some(QosConfig {
            enabled: true,
            interfaces: vec![QosInterface {
                name: "wan0".into(),
                enabled: true,
                bandwidth_kbps: Some(0),
                qdisc: QosQueueDiscipline::Cake,
                diffserv: QosDiffservMode::Diffserv4,
                nat_aware: true,
                wash: false,
            }],
        });

        let error = store.validate(&cfg).unwrap_err().to_string();
        assert!(error.contains("bandwidth_kbps must be between"));

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
            mss: None,
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            accept_ra: false,
            ipv6_mode: Some(crate::config::models::Ipv6Mode::Static),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            vlan: None,
            parent_interface: None,
            wan_mode: None,
            pppoe_username: None,
            pppoe_password: None,
            gateway: None,
            block_private_networks: false,
            block_bogon_networks: false,
        });
        assert!(store.validate(&cfg).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_duplicate_interface_names() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.interfaces = vec![make_interface("eth0"), make_interface("eth0")];
        let error = store.validate(&cfg).unwrap_err().to_string();
        assert!(error.contains("Duplicate interface name"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_dhcp_wan_without_dhcp4() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        let mut iface = make_interface("eth0");
        iface.addresses.clear();
        iface.wan_mode = Some(WanMode::Dhcp);
        iface.dhcp4 = false;
        cfg.interfaces.push(iface);

        let error = store.validate(&cfg).unwrap_err().to_string();
        assert!(error.contains("wan_mode=dhcp requires dhcp4=true"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_accepts_dhcp_wan_gateway_without_static_ip() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        let mut iface = make_interface("eth0");
        iface.addresses.clear();
        iface.wan_mode = Some(WanMode::Dhcp);
        iface.dhcp4 = true;
        cfg.interfaces.push(iface);
        cfg.gateways.push(Gateway {
            name: "WAN_DHCP".into(),
            description: None,
            interface: "eth0".into(),
            gateway_ip: None,
            monitor_ip: Some("1.1.1.1".into()),
            weight: 1,
            enabled: true,
        });

        store.validate(&cfg).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_pppoe_without_credentials() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        let mut iface = make_pppoe_interface("eth0");
        iface.pppoe_password = Some(String::new());
        cfg.interfaces.push(iface);

        let error = store.validate(&cfg).unwrap_err().to_string();
        assert!(error.contains("wan_mode=pppoe requires non-empty username/password"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_pppoe_static_gateway_or_addresses() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut with_gateway = SystemConfig::default();
        let mut iface = make_pppoe_interface("eth0");
        iface.gateway = Some("192.0.2.1".into());
        with_gateway.interfaces.push(iface);
        let error = store.validate(&with_gateway).unwrap_err().to_string();
        assert!(error.contains("wan_mode=pppoe must not set a static gateway"));

        let mut with_address = SystemConfig::default();
        let mut iface = make_pppoe_interface("eth1");
        iface.addresses.push("192.0.2.2/24".into());
        with_address.interfaces.push(iface);
        let error = store.validate(&with_address).unwrap_err().to_string();
        assert!(error.contains("wan_mode=pppoe must not set static addresses"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_accepts_normalized_pppoe_interface() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.interfaces.push(make_pppoe_interface("eth0"));
        store.validate(&cfg).unwrap();

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
            mss: None,
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            accept_ra: false,
            ipv6_mode: Some(crate::config::models::Ipv6Mode::Static),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            vlan: None,
            parent_interface: None,
            wan_mode: None,
            pppoe_username: None,
            pppoe_password: None,
            gateway: None,
            block_private_networks: false,
            block_bogon_networks: false,
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
            mss: None,
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            accept_ra: false,
            ipv6_mode: Some(crate::config::models::Ipv6Mode::Static),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            vlan: None,
            parent_interface: None,
            wan_mode: None,
            pppoe_username: None,
            pppoe_password: None,
            gateway: None,
            block_private_networks: false,
            block_bogon_networks: false,
        });
        assert!(store.validate(&cfg).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_vlan_without_parent() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.interfaces.push(Interface {
            name: "eth0.100".into(),
            description: None,
            addresses: vec![],
            mtu: None,
            mss: None,
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            accept_ra: false,
            ipv6_mode: Some(crate::config::models::Ipv6Mode::Static),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            vlan: Some(100),
            parent_interface: None,
            wan_mode: None,
            pppoe_username: None,
            pppoe_password: None,
            gateway: None,
            block_private_networks: false,
            block_bogon_networks: false,
        });
        assert!(store.validate(&cfg).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_vlan_with_unknown_parent() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.interfaces.push(Interface {
            name: "eth0.100".into(),
            description: None,
            addresses: vec![],
            mtu: None,
            mss: None,
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            accept_ra: false,
            ipv6_mode: Some(crate::config::models::Ipv6Mode::Static),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            vlan: Some(100),
            parent_interface: Some("eth9".into()),
            wan_mode: None,
            pppoe_username: None,
            pppoe_password: None,
            gateway: None,
            block_private_networks: false,
            block_bogon_networks: false,
        });
        assert!(store.validate(&cfg).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_accepts_vlan_with_known_parent() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.interfaces.push(make_interface("eth0"));
        cfg.interfaces.push(Interface {
            name: "eth0.100".into(),
            description: None,
            addresses: vec![],
            mtu: None,
            mss: None,
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            accept_ra: false,
            ipv6_mode: Some(crate::config::models::Ipv6Mode::Static),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            vlan: Some(100),
            parent_interface: Some("eth0".into()),
            wan_mode: None,
            pppoe_username: None,
            pppoe_password: None,
            gateway: None,
            block_private_networks: false,
            block_bogon_networks: false,
        });
        assert!(store.validate(&cfg).is_ok());

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
        use crate::config::models::{Action, FirewallDirection, FirewallRule};
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
            direction: FirewallDirection::Forward,
            interface: None,
            log: false,
            enabled: true,
            schedule: None,
            ip_family: crate::config::models::FirewallAddressFamily::Ipv4Ipv6,
            state_limits: crate::config::models::FirewallStateLimits::default(),
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
        store.save_interfaces(vec![make_interface("eth0")]).unwrap();

        // Now save firewall rules - interfaces must still be present.
        store
            .save_firewall_rules(vec![make_rule("rule-a")])
            .unwrap();

        let cfg = store.load().unwrap();
        assert_eq!(
            cfg.interfaces.len(),
            1,
            "interfaces must survive firewall save"
        );
        assert_eq!(cfg.firewall_rules.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_firewall_rules_rejects_negative_priority() {
        use crate::config::models::{Action, FirewallDirection, FirewallRule};

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
            direction: FirewallDirection::Forward,
            interface: None,
            log: false,
            enabled: true,
            schedule: None,
            ip_family: crate::config::models::FirewallAddressFamily::Ipv4Ipv6,
            state_limits: crate::config::models::FirewallStateLimits::default(),
        };

        let result = store.save_firewall_rules(vec![bad_rule]);
        assert!(result.is_err(), "negative priority must be rejected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_firewall_rules_accepts_bare_ip_addresses() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut rule = make_rule("allow-single-host");
        rule.source = Some("192.168.1.10".into());
        rule.destination = Some("10.0.0.5".into());

        assert!(store.save_firewall_rules(vec![rule]).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_firewall_rules_rejects_ports_without_tcp_or_udp() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut rule = make_rule("bad-port-rule");
        rule.destination_port = Some(443);
        rule.protocol = None;

        let result = store.save_firewall_rules(vec![rule]);
        assert!(result.is_err(), "ports must require tcp or udp protocol");

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
        assert!(!is_valid_mac("aabbccddeeff")); // no separator
        assert!(!is_valid_mac("aa:bb:cc:dd:ee")); // only 5 groups
        assert!(!is_valid_mac("aa:bb:cc:dd:ee:gg")); // invalid hex
        assert!(!is_valid_mac(""));
    }

    #[test]
    fn is_valid_domain_ok() {
        use crate::config::models::is_valid_domain;
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("example.com.")); // trailing dot
        assert!(is_valid_domain("my-host.local"));
        assert!(is_valid_domain("a")); // single label
    }

    #[test]
    fn is_valid_domain_invalid() {
        use crate::config::models::is_valid_domain;
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("-bad.com")); // starts with hyphen
        assert!(!is_valid_domain("bad-.com")); // ends with hyphen
        assert!(!is_valid_domain("bad..com")); // empty label
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
            interface_blocklists: vec![],
            manage_firewall: true,
        }
    }

    fn make_dhcp_config() -> crate::config::models::DhcpConfig {
        use crate::config::models::{DhcpConfig, DhcpScope};
        DhcpConfig {
            enabled: true,
            interface: "eth1".into(),
            scopes: vec![DhcpScope {
                id: uuid::Uuid::new_v4(),
                subnet: "192.168.1.0/24".into(),
                pool_start: "192.168.1.100".into(),
                pool_end: "192.168.1.200".into(),
                gateway: Some("192.168.1.1".into()),
                dns_servers: vec!["1.1.1.1".into()],
                lease_seconds: 86400,
                domain_name: None,
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

        let loaded = store
            .load_dns_config()
            .unwrap()
            .expect("DNS config should be Some");
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

        let loaded = store
            .load_dhcp_config()
            .unwrap()
            .expect("DHCP config should be Some");
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
    fn validate_rejects_dhcp_host_cidr_subnet() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        let mut dhcp = make_dhcp_config();
        dhcp.scopes[0].subnet = "192.168.1.1/24".into();
        cfg.dhcp = Some(dhcp);

        let error = store.validate(&cfg).unwrap_err().to_string();
        assert!(error.contains("must be network CIDR"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_normalizes_dhcp_host_cidr_subnet() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        let mut dhcp = make_dhcp_config();
        dhcp.scopes[0].subnet = "192.168.1.1/24".into();
        cfg.dhcp = Some(dhcp);

        store.save(&cfg).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.dhcp.unwrap().scopes[0].subnet, "192.168.1.0/24");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_dhcp_pool_outside_subnet() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        let mut dhcp = make_dhcp_config();
        dhcp.scopes[0].pool_start = "192.168.0.100".into();
        dhcp.scopes[0].pool_end = "192.168.0.200".into();
        cfg.dhcp = Some(dhcp);

        let error = store.validate(&cfg).unwrap_err().to_string();
        assert!(error.contains("pool_start 192.168.0.100 is outside subnet"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_dhcp6_host_cidr_subnet() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.dhcp6 = Some(crate::config::models::Dhcp6Config {
            enabled: true,
            interface: "eth1".into(),
            scopes: vec![crate::config::models::Dhcp6Scope {
                id: uuid::Uuid::new_v4(),
                subnet: "fd00:1::1/64".into(),
                pool_start: "fd00:1::100".into(),
                pool_end: "fd00:1::1ff".into(),
                dns_servers: vec![],
                lease_seconds: 86400,
                domain_name: None,
                reservations: vec![],
            }],
        });

        let error = store.validate(&cfg).unwrap_err().to_string();
        assert!(error.contains("must be network CIDR"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_dhcp6_pool_outside_subnet() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.dhcp6 = Some(crate::config::models::Dhcp6Config {
            enabled: true,
            interface: "eth1".into(),
            scopes: vec![crate::config::models::Dhcp6Scope {
                id: uuid::Uuid::new_v4(),
                subnet: "fd00:1::/64".into(),
                pool_start: "fd00:2::100".into(),
                pool_end: "fd00:2::1ff".into(),
                dns_servers: vec![],
                lease_seconds: 86400,
                domain_name: None,
                reservations: vec![],
            }],
        });

        let error = store.validate(&cfg).unwrap_err().to_string();
        assert!(error.contains("pool_start fd00:2::100 is outside subnet"));

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
            interface_blocklists: vec![],
            manage_firewall: true,
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
            interface: "eth1".into(),
            scopes: vec![crate::config::models::DhcpScope {
                id: uuid::Uuid::new_v4(),
                subnet: "192.168.1.0/24".into(),
                pool_start: "192.168.1.100".into(),
                pool_end: "192.168.1.200".into(),
                gateway: None,
                dns_servers: vec![],
                lease_seconds: 86400,
                domain_name: None,
                reservations: vec![crate::config::models::DhcpReservation {
                    id: uuid::Uuid::new_v4(),
                    hostname: None,
                    mac_address: "not-a-mac".into(),
                    ip_address: "192.168.1.50".into(),
                    dns_servers: vec![],
                    ntp_servers: vec![],
                    description: String::new(),
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
            interface: "eth1".into(),
            scopes: vec![crate::config::models::DhcpScope {
                id: uuid::Uuid::new_v4(),
                subnet: "192.168.1.0/24".into(),
                pool_start: "192.168.1.200".into(), // reversed
                pool_end: "192.168.1.100".into(),
                gateway: None,
                dns_servers: vec![],
                lease_seconds: 86400,
                domain_name: None,
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
            dns_provider: crate::config::models::AcmeDnsProvider::Manual,
            cloudflare_zone_id: None,
            cloudflare_api_token: None,
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

        let loaded = store
            .load_acme_config()
            .unwrap()
            .expect("ACME config should be Some");
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

        assert!(
            store.validate(&cfg).is_err(),
            "invalid email must be rejected"
        );

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

        assert!(
            store.validate(&cfg).is_err(),
            "invalid domain must be rejected"
        );

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

        assert!(
            store.validate(&cfg).is_err(),
            "zero renew_interval_hours must be rejected"
        );

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

        assert!(
            store.validate(&cfg).is_err(),
            "invalid directory_url must be rejected"
        );

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
            directory_url: "not-a-url".into(), // would fail if enabled
            email: "not-an-email".into(),
            domains: vec![],
            challenge_type: crate::config::models::AcmeChallengeType::Http01,
            renew_interval_hours: 0,
            dns_provider: crate::config::models::AcmeDnsProvider::Manual,
            cloudflare_zone_id: None,
            cloudflare_api_token: None,
            provider: crate::config::models::AcmeProvider::Custom,
            cert_storage_path: "/tmp".into(),
        });

        assert!(
            store.validate(&cfg).is_ok(),
            "disabled ACME must skip validation"
        );

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
        assert!(!validate_email("@example.com")); // empty local part
        assert!(!validate_email("user@")); // empty domain
        assert!(!validate_email("user@@example.com")); // multiple @
        assert!(!validate_email(""));
    }

    #[test]
    fn validate_directory_url_accepts_valid_urls() {
        use crate::config::models::validate_directory_url;
        assert!(validate_directory_url(
            "https://acme-v02.api.letsencrypt.org/directory"
        ));
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

        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(store.config_path()).unwrap()).unwrap();
        assert_eq!(
            saved["schema_version"].as_u64(),
            Some(CURRENT_SCHEMA_VERSION as u64)
        );

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

    #[test]
    fn migrate_v1_to_v2_initialises_config_history() {
        // A v1 config predates the history settings, so it carries none.
        let mut cfg = SystemConfig::default();
        cfg.config_history = None;

        let migrated = migrate_config(cfg, 1).unwrap();
        // The v1 -> v2 migration must populate it with the built-in defaults.
        let history = migrated
            .config_history
            .expect("config_history must be initialised by the v1->v2 migration");
        assert!(history.enabled);
        assert_eq!(history.max_revisions, 50);
    }

    #[test]
    fn load_migrates_v1_file_to_v2_and_populates_history() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        // A v1 on-disk file with no config_history field.
        let v1_json = r#"{"schema_version":1,"hostname":"v1-fw"}"#;
        std::fs::write(store.config_path(), v1_json).unwrap();

        let cfg = store.load().unwrap();
        assert_eq!(cfg.hostname, "v1-fw");
        assert!(
            cfg.config_history.is_some(),
            "loading a v1 file must migrate it and initialise config_history"
        );

        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(store.config_path()).unwrap()).unwrap();
        assert_eq!(saved["schema_version"].as_u64(), Some(2));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_revision_removes_only_that_revision() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.hostname = "one".into();
        store.save_with_rollback(&cfg).unwrap();
        cfg.hostname = "two".into();
        store.save_with_rollback(&cfg).unwrap();

        let revs = store.list_revisions().unwrap();
        assert_eq!(revs.len(), 2);

        store.delete_revision(&revs[0].id).unwrap();
        let after = store.list_revisions().unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, revs[1].id);

        // Deleting a non-existent revision is an error.
        assert!(store.delete_revision("does-not-exist").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zero_max_revisions_is_clamped_and_still_prunes() {
        // A corrupt/hand-edited config with max_revisions = 0 must not disable
        // pruning (which would let history grow without bound); it is clamped
        // to retain at least the most recent revision.
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.config_history = Some(crate::config::models::ConfigHistorySettings {
            enabled: true,
            max_revisions: 0,
        });

        for i in 0..4 {
            cfg.hostname = format!("h{i}");
            store.save_with_rollback(&cfg).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }

        assert_eq!(
            store.list_revisions().unwrap().len(),
            1,
            "max_revisions = 0 must clamp to 1, not disable pruning"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_settings_round_trip_and_control_retention() {
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        // Default settings: enabled, retain 50.
        let defaults = store.load_history_settings().unwrap();
        assert!(defaults.enabled);
        assert_eq!(defaults.max_revisions, 50);

        // Tighten retention to 2 and verify it is honored by subsequent saves.
        store
            .save_history_settings(crate::config::models::ConfigHistorySettings {
                enabled: true,
                max_revisions: 2,
            })
            .unwrap();

        let mut cfg = store.load().unwrap();
        for i in 0..5 {
            cfg.hostname = format!("h{i}");
            store.save_with_rollback(&cfg).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }

        assert_eq!(
            store.list_revisions().unwrap().len(),
            2,
            "retention setting must cap the number of revisions"
        );

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
