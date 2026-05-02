//! Backup archive restoration.
//!
//! [`restore_backup`] verifies a TAR archive's SHA-256 integrity, parses the
//! included subsystem configs, and applies them to the live
//! [`crate::config::storage::ConfigStore`] using an atomic write with rollback.
//!
//! Only the subsystems listed in the backup's `metadata.json` are touched;
//! all other subsystems retain their current on-disk configuration.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use tracing::info;

use crate::config::{
    models::{
        AcmeConfig, CrowdSecConfig, DhcpConfig, DnsConfig, FirewallAlias, FirewallRule, Interface,
        SuricataConfig, WireGuardInterface,
    },
    storage::ConfigStore,
};

use super::{
    model::{BackupMetadata, Subsystem},
    verify::{read_tar, verify_tar},
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Restore a backup from raw TAR bytes (already decrypted if the archive was
/// encrypted).
///
/// 1. Verifies the SHA-256 integrity of the archive.
/// 2. Extracts each `config/*.json` file.
/// 3. Deserialises the JSON and patches the in-memory [`SystemConfig`].
/// 4. Persists the patched config via [`ConfigStore::save_with_rollback`].
///
/// Returns the [`BackupMetadata`] from the archive on success.
pub fn restore_backup(tar_bytes: &[u8], config_store: &ConfigStore) -> Result<BackupMetadata> {
    // Verify integrity and parse metadata.
    let metadata = verify_tar(tar_bytes)?;

    // Re-read files (verify_tar already iterated once; we need to iterate again).
    let (_, files) = read_tar(tar_bytes)?;

    // Load the current config so we only overwrite what's in the backup.
    let mut config = config_store
        .load()
        .context("Failed to load current config before restore")?;

    for subsystem in &metadata.subsystems {
        let filename = format!("config/{}", subsystem.filename());
        let bytes = files.get(&filename).ok_or_else(|| {
            anyhow::anyhow!(
                "Backup is missing expected file: {filename} (listed in subsystems but not present)"
            )
        })?;

        apply_subsystem(&mut config, subsystem, bytes)
            .with_context(|| format!("Failed to deserialise restored {subsystem:?} data"))?;
    }

    config_store
        .save_with_rollback(&config)
        .context("Failed to persist restored config")?;

    info!(
        hostname = %metadata.hostname,
        created_at = metadata.created_at,
        subsystems = ?metadata.subsystems,
        "backup: restore completed successfully"
    );

    Ok(metadata)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Deserialise one subsystem's JSON bytes and apply the result to `config`.
fn apply_subsystem(
    config: &mut crate::config::models::SystemConfig,
    subsystem: &Subsystem,
    bytes: &[u8],
) -> Result<()> {
    match subsystem {
        Subsystem::Interfaces => {
            config.interfaces = serde_json::from_slice::<Vec<Interface>>(bytes)?;
        }
        Subsystem::Firewall => {
            config.firewall_rules = serde_json::from_slice::<Vec<FirewallRule>>(bytes)?;
        }
        Subsystem::Aliases => {
            config.firewall_aliases = serde_json::from_slice::<Vec<FirewallAlias>>(bytes)?;
        }
        Subsystem::Dns => {
            config.dns = serde_json::from_slice::<Option<DnsConfig>>(bytes)?;
        }
        Subsystem::Dhcp => {
            config.dhcp = serde_json::from_slice::<Option<DhcpConfig>>(bytes)?;
        }
        Subsystem::WireGuard => {
            config.wireguard_interfaces =
                serde_json::from_slice::<Vec<WireGuardInterface>>(bytes)?;
        }
        Subsystem::Suricata => {
            config.suricata = serde_json::from_slice::<Option<SuricataConfig>>(bytes)?;
        }
        Subsystem::CrowdSec => {
            config.crowdsec = serde_json::from_slice::<Option<CrowdSecConfig>>(bytes)?;
        }
        Subsystem::Acme => {
            config.acme = serde_json::from_slice::<Option<AcmeConfig>>(bytes)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::create::create_backup;
    use crate::backup::model::Subsystem;

    #[tokio::test]
    async fn restore_backup_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let backup_dir = dir.path().join("backups");
        let store = ConfigStore::with_dir(&config_dir);

        let path = create_backup(None, &store, false, None, &backup_dir)
            .await
            .unwrap();
        let bytes = std::fs::read(&path).unwrap();

        let meta = restore_backup(&bytes, &store).unwrap();
        assert_eq!(meta.subsystems.len(), Subsystem::all().len());
    }

    #[test]
    fn restore_backup_tampered_data_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::with_dir(dir.path().join("config"));

        // A truncated / garbage buffer should fail integrity check.
        let result = restore_backup(b"not a valid tar archive", &store);
        assert!(result.is_err());
    }
}
