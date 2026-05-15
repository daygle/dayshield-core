//! Backup data models.
//!
//! Defines the metadata record embedded in every backup archive and the
//! configuration for the automatic backup scheduler.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Subsystem selector
// ---------------------------------------------------------------------------

/// The set of DayShield subsystems that can be individually backed up or
/// restored.
///
/// When used with [`create_backup`](super::create::create_backup), `None`
/// means **all** subsystems.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Subsystem {
    /// Network interface configuration.
    Interfaces,
    /// Firewall rules and named aliases.
    Firewall,
    /// DNS (Unbound) resolver configuration.
    Dns,
    /// DHCP server configuration.
    Dhcp,
    /// WireGuard VPN interfaces.
    WireGuard,
    /// Suricata IDS/IPS configuration.
    Suricata,
    /// CrowdSec bouncer integration configuration.
    CrowdSec,
    /// ACME / TLS certificate configuration.
    Acme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackupType {
    Manual,
    Scheduled,
    Update,
}

impl BackupType {
    pub fn as_str(self) -> &'static str {
        match self {
            BackupType::Manual => "manual",
            BackupType::Scheduled => "scheduled",
            BackupType::Update => "update",
        }
    }
}

impl Default for BackupType {
    fn default() -> Self {
        BackupType::Manual
    }
}

impl Subsystem {
    /// Return all available subsystems in canonical order.
    pub fn all() -> Vec<Subsystem> {
        vec![
            Subsystem::Interfaces,
            Subsystem::Firewall,
            Subsystem::Dns,
            Subsystem::Dhcp,
            Subsystem::WireGuard,
            Subsystem::Suricata,
            Subsystem::CrowdSec,
            Subsystem::Acme,
        ]
    }

    /// The path used for this subsystem's entry inside the backup archive.
    pub fn archive_path(&self) -> &'static str {
        match self {
            Subsystem::Interfaces => "config/interfaces.json",
            Subsystem::Firewall => "config/firewall.json",
            Subsystem::Dns => "config/dns.json",
            Subsystem::Dhcp => "config/dhcp.json",
            Subsystem::WireGuard => "config/wireguard.json",
            Subsystem::Suricata => "config/suricata.json",
            Subsystem::CrowdSec => "config/crowdsec.json",
            Subsystem::Acme => "config/acme.json",
        }
    }
}

// ---------------------------------------------------------------------------
// Backup metadata
// ---------------------------------------------------------------------------

/// Metadata record stored as `metadata.json` at the root of every backup
/// archive.
///
/// The `sha256` field holds the SHA-256 hex digest of the concatenation of
/// all config entry bytes that were written into the archive (in the order
/// defined by [`Subsystem::all`]).  This allows integrity to be verified
/// independently of the metadata entry itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Unix timestamp (seconds since epoch) when the backup was created.
    pub created_at: u64,
    /// DayShield application version string.
    pub version: String,
    /// System hostname at the time of the backup.
    pub hostname: String,
    /// Which subsystems are included in this backup.
    pub subsystems: Vec<Subsystem>,
    /// Why this backup was created.
    #[serde(default)]
    pub backup_type: BackupType,
    /// SHA-256 hex digest of the config content bytes.
    pub sha256: String,
    /// Whether the archive body is AES-256-GCM encrypted.
    pub encrypted: bool,
}

// ---------------------------------------------------------------------------
// Scheduler configuration
// ---------------------------------------------------------------------------

/// Configuration for the automatic backup scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupScheduleConfig {
    /// Whether the scheduler is active.
    pub enabled: bool,
    /// How often (in hours) to create a scheduled backup.
    pub interval_hours: u64,
    /// Maximum number of backup files to keep on disk.  Older files are
    /// deleted when this limit is exceeded.
    pub retain_count: usize,
    /// Whether scheduled backups should be encrypted.
    pub encrypt: bool,
    /// Passphrase used for encryption when `encrypt` is `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
}

impl Default for BackupScheduleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_hours: 24,
            retain_count: 7,
            encrypt: false,
            passphrase: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_subsystems_have_unique_paths() {
        let paths: Vec<_> = Subsystem::all()
            .iter()
            .map(|s| s.archive_path())
            .collect();
        let unique: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(paths.len(), unique.len());
    }

    #[test]
    fn subsystem_serialise_roundtrip() {
        let s = Subsystem::WireGuard;
        let json = serde_json::to_string(&s).unwrap();
        let back: Subsystem = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn backup_schedule_defaults_are_sane() {
        let cfg = BackupScheduleConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.interval_hours, 24);
        assert_eq!(cfg.retain_count, 7);
    }
}
