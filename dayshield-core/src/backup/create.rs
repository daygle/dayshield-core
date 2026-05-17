//! Backup creation.
//!
//! [`create_backup`] serialises the requested DayShield subsystems into a
//! deterministic TAR archive, optionally encrypts the result, and writes it
//! to the backup directory.
//!
//! Archive layout:
//! ```text
//! metadata.json          ← BackupMetadata (JSON)
//! config/acme.json
//! config/aliases.json
//! config/crowdsec.json
//! config/dhcp.json
//! config/dns.json
//! config/firewall.json
//! config/interfaces.json
//! config/captive_portal.json
//! config/suricata.json
//! config/wireguard.json
//! ```
//!
//! Not all files need to be present; only the subsystems selected for this
//! backup are included.
//!
//! **Integrity**: `BackupMetadata.sha256` is the SHA-256 hex digest of the
//! concatenation of every config entry's bytes (in alphabetical path order).
//! This value can be recomputed during restore to verify the archive has not
//! been tampered with.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::ConfigStore;

use super::encrypt;
use super::model::{BackupMetadata, BackupType, Subsystem};
use super::verify::sha256_hex;

// ---------------------------------------------------------------------------
// Default locations
// ---------------------------------------------------------------------------

/// Default directory where backup archives are stored.
pub const DEFAULT_BACKUP_DIR: &str = "/etc/dayshield/backups";

/// Application version embedded in every backup's metadata.
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Internal combined types (for serialising multiple config fragments)
// ---------------------------------------------------------------------------

/// Combined firewall backup entry (rules + aliases in a single JSON file).
#[derive(Serialize, Deserialize)]
pub struct FirewallBackup {
    pub rules: Vec<crate::config::models::FirewallRule>,
    pub aliases: Vec<crate::config::models::FirewallAlias>,
}

/// Combined DNS backup entry (config + host overrides + domain overrides).
#[derive(Serialize, Deserialize)]
pub struct DnsBackup {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<crate::config::models::DnsConfig>,
    pub host_overrides: Vec<crate::config::models::DnsHostOverride>,
    pub domain_overrides: Vec<crate::config::models::DnsDomainOverride>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a DayShield backup archive.
///
/// # Parameters
///
/// * `store` - configuration store used to read the current config.
/// * `subsystems` - subsystems to include; `None` means all.
/// * `encrypt_backup` - whether to encrypt the archive.
/// * `passphrase` - passphrase for encryption (required when `encrypt_backup`
///   is `true`).
/// * `backup_dir` - directory where the backup file will be written.
///
/// # Returns
///
/// A tuple of (path to the newly created backup file, backup metadata).
pub fn create_backup(
    store: &ConfigStore,
    subsystems: Option<Vec<Subsystem>>,
    encrypt_backup: bool,
    passphrase: Option<&str>,
    backup_dir: &Path,
    backup_type: BackupType,
) -> Result<(PathBuf, BackupMetadata)> {
    if encrypt_backup && passphrase.map(|p| p.is_empty()).unwrap_or(true) {
        anyhow::bail!("a non-empty passphrase is required when encryption is enabled");
    }

    let selected = subsystems.unwrap_or_else(Subsystem::all);

    let cfg = store.load().context("failed to load system config")?;

    // -- Serialise each subsystem ------------------------------------------
    // Entries are sorted alphabetically by archive path to ensure
    // deterministic SHA-256 computation and archive layout.

    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    for sub in &selected {
        let (path, bytes) = serialise_subsystem(sub, &cfg)?;
        entries.push((path, bytes));
    }

    // Sort by archive path for deterministic ordering.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // -- Compute integrity digest ------------------------------------------
    let mut content_bytes = Vec::new();
    for (_, bytes) in &entries {
        content_bytes.extend_from_slice(bytes);
    }
    let sha256 = sha256_hex(&content_bytes);

    // -- Build metadata ----------------------------------------------------
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    let metadata = BackupMetadata {
        created_at,
        version: APP_VERSION.to_string(),
        hostname,
        subsystems: selected.clone(),
        backup_type,
        sha256,
        encrypted: encrypt_backup,
    };

    let metadata_bytes =
        serde_json::to_vec_pretty(&metadata).context("failed to serialise backup metadata")?;

    // -- Build TAR archive (in-memory) ------------------------------------
    let mut archive_buf: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut archive_buf);

        // metadata.json first.
        append_entry(&mut builder, "metadata.json", &metadata_bytes)?;

        // Config entries in sorted order.
        for (path, bytes) in &entries {
            append_entry(&mut builder, path, bytes)?;
        }

        builder.finish().context("failed to finalise TAR archive")?;
    }

    // -- Optional encryption -----------------------------------------------
    let payload = if encrypt_backup {
        let phrase = passphrase.expect("checked above");
        encrypt::encrypt(&archive_buf, phrase).context("backup encryption failed")?
    } else {
        archive_buf
    };

    // -- Write to disk -------------------------------------------------------
    std::fs::create_dir_all(backup_dir)
        .with_context(|| format!("failed to create backup directory {}", backup_dir.display()))?;

    let ext = if encrypt_backup { "tar.enc" } else { "tar" };
    let version_tag = APP_VERSION.replace('/', "-");
    let filename = format!(
        "dayshield-{}-backup-v{}-{}.{}",
        backup_type.as_str(),
        version_tag,
        created_at,
        ext,
    );
    let filepath = backup_dir.join(&filename);

    // Atomic write: write to .tmp then rename.
    let tmp = filepath.with_extension("tmp");
    std::fs::write(&tmp, &payload)
        .with_context(|| format!("failed to write backup to {}", tmp.display()))?;
    std::fs::rename(&tmp, &filepath)
        .with_context(|| format!("failed to rename backup file to {}", filepath.display()))?;

    info!(
        path = %filepath.display(),
        subsystems = ?selected,
        encrypted = encrypt_backup,
        size_bytes = payload.len(),
        "backup created"
    );

    Ok((filepath, metadata))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Serialise a single subsystem from `cfg` and return `(archive_path, bytes)`.
fn serialise_subsystem(
    sub: &Subsystem,
    cfg: &crate::config::models::SystemConfig,
) -> Result<(String, Vec<u8>)> {
    let path = sub.archive_path().to_string();
    let bytes = match sub {
        Subsystem::Interfaces => serde_json::to_vec_pretty(&cfg.interfaces),
        Subsystem::Firewall => serde_json::to_vec_pretty(&FirewallBackup {
            rules: cfg.firewall_rules.clone(),
            aliases: cfg.firewall_aliases.clone(),
        }),
        Subsystem::Dns => serde_json::to_vec_pretty(&DnsBackup {
            config: cfg.dns.clone(),
            host_overrides: cfg.dns_host_overrides.clone(),
            domain_overrides: cfg.dns_domain_overrides.clone(),
        }),
        Subsystem::Dhcp => serde_json::to_vec_pretty(&cfg.dhcp),
        Subsystem::WireGuard => serde_json::to_vec_pretty(&cfg.wireguard_interfaces),
        Subsystem::Suricata => serde_json::to_vec_pretty(&cfg.suricata),
        Subsystem::CrowdSec => serde_json::to_vec_pretty(&cfg.crowdsec),
        Subsystem::Acme => serde_json::to_vec_pretty(&cfg.acme),
        Subsystem::CaptivePortal => serde_json::to_vec_pretty(&cfg.captive_portal),
    }
    .with_context(|| format!("failed to serialise {path}"))?;
    Ok((path, bytes))
}

/// Append a single in-memory file to a TAR [`Builder`].
fn append_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    data: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).with_context(|| format!("invalid tar path: {path}"))?;
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0); // deterministic mtime
    header.set_cksum();
    builder
        .append(&header, std::io::Cursor::new(data))
        .with_context(|| format!("failed to append {path} to archive"))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::model::BackupType;
    use tempfile::TempDir;

    fn temp_store() -> (TempDir, ConfigStore) {
        let dir = TempDir::new().unwrap();
        let store = ConfigStore::with_dir(dir.path());
        (dir, store)
    }

    #[test]
    fn create_backup_produces_tar_file() {
        let backup_dir = TempDir::new().unwrap();
        let (_cfg_dir, store) = temp_store();

        let (path, _meta) = create_backup(&store, None, false, None, backup_dir.path(), BackupType::Manual).unwrap();
        assert!(path.exists());
        assert!(path.extension().map(|e| e == "tar").unwrap_or(false));
    }

    #[test]
    fn create_encrypted_backup_requires_passphrase() {
        let backup_dir = TempDir::new().unwrap();
        let (_cfg_dir, store) = temp_store();

        let result = create_backup(&store, None, true, None, backup_dir.path(), BackupType::Manual);
        assert!(result.is_err());
    }

    #[test]
    fn create_encrypted_backup_succeeds_with_passphrase() {
        let backup_dir = TempDir::new().unwrap();
        let (_cfg_dir, store) = temp_store();

        let (path, _meta) =
            create_backup(&store, None, true, Some("s3cr3t"), backup_dir.path(), BackupType::Manual).unwrap();
        assert!(path.exists());
        assert!(path.to_str().unwrap().ends_with(".tar.enc"));
    }

    #[test]
    fn selective_backup_only_includes_requested_subsystems() {
        let backup_dir = TempDir::new().unwrap();
        let (_cfg_dir, store) = temp_store();

        let (path, _meta) = create_backup(
            &store,
            Some(vec![Subsystem::Dns]),
            false,
            None,
            backup_dir.path(),
            BackupType::Manual,
        )
        .unwrap();
        assert!(path.exists());
    }
}
