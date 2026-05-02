//! Backup archive creation.
//!
//! [`create_backup`] serialises the requested subsystems from the current
//! [`crate::config::models::SystemConfig`] into JSON, assembles a TAR archive
//! with a `metadata.json` entry and a `config/` directory, optionally
//! encrypts the archive, and writes it atomically to `backup_dir`.
//!
//! # Archive layout
//!
//! ```text
//! metadata.json
//! config/interfaces.json   (when Interfaces is requested)
//! config/firewall.json     (when Firewall is requested)
//! config/aliases.json      (when Aliases is requested)
//! config/dns.json          (when Dns is requested)
//! config/dhcp.json         (when Dhcp is requested)
//! config/wireguard.json    (when WireGuard is requested)
//! config/suricata.json     (when Suricata is requested)
//! config/crowdsec.json     (when CrowdSec is requested)
//! config/acme.json         (when Acme is requested)
//! ```

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tracing::info;

use crate::config::{models::SystemConfig, storage::ConfigStore};

use super::model::{BackupMetadata, Subsystem};
use super::verify::compute_sha256;

/// Default directory where backup files are stored.
pub const DEFAULT_BACKUP_DIR: &str = "/etc/dayshield/backups";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a backup archive and write it to `backup_dir`.
///
/// * `subsystems` — which subsystems to include; `None` means all.
/// * `config_store` — source of the current [`SystemConfig`].
/// * `encrypt` — whether to encrypt the archive; requires `passphrase`.
/// * `passphrase` — AES-256-GCM passphrase, required when `encrypt` is `true`.
/// * `backup_dir` — destination directory (created if it does not exist).
///
/// Returns the path of the created backup file on success.
pub async fn create_backup(
    subsystems: Option<Vec<Subsystem>>,
    config_store: &ConfigStore,
    encrypt: bool,
    passphrase: Option<&str>,
    backup_dir: &Path,
) -> Result<PathBuf> {
    let subsystems = subsystems.unwrap_or_else(Subsystem::all);

    let config = config_store
        .load()
        .context("Failed to load system config for backup")?;

    // Serialise each subsystem.
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for subsystem in &subsystems {
        let json = serialize_subsystem(&config, subsystem)
            .with_context(|| format!("Failed to serialise {subsystem:?}"))?;
        files.insert(format!("config/{}", subsystem.filename()), json);
    }

    // Compute integrity hash before building the archive.
    let sha256 = compute_sha256(&files);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let metadata = BackupMetadata {
        created_at: now,
        version: env!("CARGO_PKG_VERSION").to_string(),
        hostname: config.hostname.clone(),
        subsystems: subsystems.clone(),
        sha256,
        encrypted: encrypt,
    };

    // Build the TAR in memory.
    let tar_bytes = build_tar(&metadata, &files).context("Failed to build TAR archive")?;

    // Optionally encrypt.
    let final_bytes = if encrypt {
        let pass = passphrase
            .ok_or_else(|| anyhow::anyhow!("passphrase required when encrypt is true"))?;
        super::encrypt::encrypt(&tar_bytes, pass).context("Failed to encrypt backup archive")?
    } else {
        tar_bytes
    };

    // Atomic write: write to a `.tmp` file then rename.
    std::fs::create_dir_all(backup_dir)
        .with_context(|| format!("Failed to create backup directory {}", backup_dir.display()))?;

    let ext = if encrypt { "tar.enc" } else { "tar" };
    let filename = format!("{}_backup.{}", now, ext);
    let output_path = backup_dir.join(&filename);
    let tmp_path = backup_dir.join(format!("{filename}.tmp"));

    std::fs::write(&tmp_path, &final_bytes)
        .with_context(|| format!("Failed to write temp backup {}", tmp_path.display()))?;

    std::fs::rename(&tmp_path, &output_path).with_context(|| {
        format!(
            "Failed to rename {} to {}",
            tmp_path.display(),
            output_path.display()
        )
    })?;

    info!(
        path = %output_path.display(),
        subsystems = ?subsystems,
        encrypted = encrypt,
        size_bytes = final_bytes.len(),
        "backup: archive created"
    );

    Ok(output_path)
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

/// Serialise one subsystem from `config` to pretty-printed JSON bytes.
fn serialize_subsystem(config: &SystemConfig, subsystem: &Subsystem) -> Result<Vec<u8>> {
    let bytes = match subsystem {
        Subsystem::Interfaces => serde_json::to_vec_pretty(&config.interfaces),
        Subsystem::Firewall => serde_json::to_vec_pretty(&config.firewall_rules),
        Subsystem::Aliases => serde_json::to_vec_pretty(&config.firewall_aliases),
        Subsystem::Dns => serde_json::to_vec_pretty(&config.dns),
        Subsystem::Dhcp => serde_json::to_vec_pretty(&config.dhcp),
        Subsystem::WireGuard => serde_json::to_vec_pretty(&config.wireguard_interfaces),
        Subsystem::Suricata => serde_json::to_vec_pretty(&config.suricata),
        Subsystem::CrowdSec => serde_json::to_vec_pretty(&config.crowdsec),
        Subsystem::Acme => serde_json::to_vec_pretty(&config.acme),
    }?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// TAR builder
// ---------------------------------------------------------------------------

/// Assemble a TAR archive in memory from `metadata` and `files`.
///
/// `metadata.json` is always the first entry; config files follow in sorted
/// order (which also matches the order used by [`compute_sha256`]).
fn build_tar(metadata: &BackupMetadata, files: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);

        let meta_json =
            serde_json::to_vec_pretty(metadata).context("Failed to serialise BackupMetadata")?;
        append_bytes(&mut builder, "metadata.json", &meta_json)?;

        for (name, bytes) in files {
            append_bytes(&mut builder, name, bytes)?;
        }

        builder
            .finish()
            .context("Failed to finalise TAR archive")?;
    }
    Ok(buf)
}

/// Append `data` as a regular file entry with `name` to `builder`.
fn append_bytes<W: Write>(
    builder: &mut tar::Builder<W>,
    name: &str,
    data: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, name, std::io::Cursor::new(data))
        .with_context(|| format!("Failed to add {name} to TAR archive"))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::verify::verify_tar;
    use crate::config::storage::ConfigStore;

    #[tokio::test]
    async fn create_backup_full_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let backup_dir = dir.path().join("backups");

        let store = ConfigStore::with_dir(&config_dir);
        let path = create_backup(None, &store, false, None, &backup_dir)
            .await
            .unwrap();

        assert!(path.exists());
        assert!(path.to_string_lossy().ends_with("_backup.tar"));

        let bytes = std::fs::read(&path).unwrap();
        let meta = verify_tar(&bytes).unwrap();
        assert_eq!(meta.subsystems.len(), Subsystem::all().len());
        assert!(!meta.encrypted);
    }

    #[tokio::test]
    async fn create_backup_selective() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::with_dir(dir.path().join("config"));
        let backup_dir = dir.path().join("backups");

        let path = create_backup(
            Some(vec![Subsystem::Dns, Subsystem::Dhcp]),
            &store,
            false,
            None,
            &backup_dir,
        )
        .await
        .unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let meta = verify_tar(&bytes).unwrap();
        assert_eq!(meta.subsystems.len(), 2);
    }

    #[tokio::test]
    async fn create_backup_encrypted_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::with_dir(dir.path().join("config"));
        let backup_dir = dir.path().join("backups");

        let path = create_backup(
            Some(vec![Subsystem::Interfaces]),
            &store,
            true,
            Some("my-pass"),
            &backup_dir,
        )
        .await
        .unwrap();

        assert!(path.to_string_lossy().ends_with("_backup.tar.enc"));

        let enc_bytes = std::fs::read(&path).unwrap();
        let tar_bytes = crate::backup::encrypt::decrypt(&enc_bytes, "my-pass").unwrap();
        let meta = verify_tar(&tar_bytes).unwrap();
        assert!(meta.encrypted);
    }

    #[tokio::test]
    async fn create_backup_encrypted_without_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::with_dir(dir.path().join("config"));
        let backup_dir = dir.path().join("backups");

        let result = create_backup(None, &store, true, None, &backup_dir).await;
        assert!(result.is_err());
    }
}
