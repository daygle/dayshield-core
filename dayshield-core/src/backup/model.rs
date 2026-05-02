//! Backup data models.
//!
//! Defines the [`Subsystem`] enum that names each DayShield configuration area,
//! [`BackupMetadata`] that is stored as `metadata.json` inside every backup
//! archive, and [`BackupEntry`] used by the REST API list endpoint.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Subsystem
// ---------------------------------------------------------------------------

/// A DayShield configuration subsystem that can be individually backed up or
/// restored.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subsystem {
    Interfaces,
    Firewall,
    Aliases,
    Dns,
    Dhcp,
    WireGuard,
    Suricata,
    CrowdSec,
    Acme,
}

impl Subsystem {
    /// Return a [`Vec`] containing every available subsystem.
    pub fn all() -> Vec<Subsystem> {
        vec![
            Subsystem::Interfaces,
            Subsystem::Firewall,
            Subsystem::Aliases,
            Subsystem::Dns,
            Subsystem::Dhcp,
            Subsystem::WireGuard,
            Subsystem::Suricata,
            Subsystem::CrowdSec,
            Subsystem::Acme,
        ]
    }

    /// Return the config filename used for this subsystem inside a backup archive.
    ///
    /// Files are placed under the `config/` directory within the TAR archive,
    /// e.g. `config/interfaces.json`.
    pub fn filename(&self) -> &'static str {
        match self {
            Subsystem::Interfaces => "interfaces.json",
            Subsystem::Firewall => "firewall.json",
            Subsystem::Aliases => "aliases.json",
            Subsystem::Dns => "dns.json",
            Subsystem::Dhcp => "dhcp.json",
            Subsystem::WireGuard => "wireguard.json",
            Subsystem::Suricata => "suricata.json",
            Subsystem::CrowdSec => "crowdsec.json",
            Subsystem::Acme => "acme.json",
        }
    }
}

// ---------------------------------------------------------------------------
// BackupMetadata
// ---------------------------------------------------------------------------

/// Metadata stored as `metadata.json` inside every backup TAR archive.
///
/// The `sha256` field is a hex-encoded SHA-256 digest that covers the
/// canonical config payload (all `config/*.json` files, sorted by name).
/// Use [`crate::backup::verify::verify_tar`] to check integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Unix timestamp (seconds since epoch) when the backup was created.
    pub created_at: u64,
    /// DayShield crate version string.
    pub version: String,
    /// Hostname of the system that produced this backup.
    pub hostname: String,
    /// Which subsystems are included in this backup.
    pub subsystems: Vec<Subsystem>,
    /// SHA-256 hex digest of the canonical config payload.
    pub sha256: String,
    /// Whether the TAR archive is encrypted with AES-256-GCM.
    pub encrypted: bool,
}

// ---------------------------------------------------------------------------
// BackupEntry
// ---------------------------------------------------------------------------

/// Summary of a single backup file returned by the list endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    /// Backup filename (basename only, not the full path).
    pub filename: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Parsed metadata from the archive, or `None` when the file is unreadable
    /// or corrupt.
    pub metadata: Option<BackupMetadata>,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsystem_all_has_nine_entries() {
        assert_eq!(Subsystem::all().len(), 9);
    }

    #[test]
    fn subsystem_filenames_are_unique() {
        let names: Vec<_> = Subsystem::all().iter().map(|s| s.filename()).collect();
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(names.len(), unique.len());
    }

    #[test]
    fn subsystem_serde_roundtrip() {
        let s = Subsystem::WireGuard;
        let json = serde_json::to_string(&s).unwrap();
        let back: Subsystem = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
