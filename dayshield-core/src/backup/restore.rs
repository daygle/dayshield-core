//! Backup restoration.
//!
//! [`restore_backup`] accepts the raw bytes of a backup archive (encrypted or
//! plain), verifies the SHA-256 integrity digest, and atomically replaces the
//! appropriate config sections via [`ConfigStore`].

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::config::ConfigStore;

use super::create::{DnsBackup, FirewallBackup};
use super::encrypt;
use super::model::{BackupMetadata, Subsystem};
use super::verify::verify_sha256;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Restore a DayShield backup from `payload`.
///
/// # Parameters
///
/// * `store` - the config store to write restored config into.
/// * `payload` - raw bytes of the backup file (either a plain TAR archive or
///   an AES-256-GCM encrypted blob, depending on `BackupMetadata.encrypted`).
/// * `passphrase` - decryption passphrase, required when the backup is
///   encrypted.
/// * `subsystems_filter` - when `Some`, only the listed subsystems are
///   restored; all others are left untouched.  `None` restores all subsystems
///   present in the backup.
///
/// # Returns
///
/// The [`BackupMetadata`] extracted from the restored archive, which callers
/// can use for confirmation messages.
pub fn restore_backup(
    store: &ConfigStore,
    payload: &[u8],
    passphrase: Option<&str>,
    subsystems_filter: Option<Vec<Subsystem>>,
) -> Result<BackupMetadata> {
    // -- Peek at metadata to check whether encryption is expected -----------
    // We try a plain TAR decode first; if that fails we assume it's encrypted.
    let archive_bytes = try_decode_payload(payload, passphrase)?;

    // -- Unpack TAR archive ------------------------------------------------
    let mut cursor = std::io::Cursor::new(archive_bytes.as_slice());
    let mut archive = tar::Archive::new(&mut cursor);

    let mut metadata: Option<BackupMetadata> = None;
    let mut config_entries: Vec<(String, Vec<u8>)> = Vec::new();

    for entry in archive.entries().context("failed to read TAR entries")? {
        let mut entry = entry.context("failed to read TAR entry")?;
        let path_str = entry
            .path()
            .context("failed to read entry path")?
            .to_string_lossy()
            .into_owned();

        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .with_context(|| format!("failed to read entry: {path_str}"))?;

        if path_str == "metadata.json" {
            let m: BackupMetadata = serde_json::from_slice(&data)
                .context("failed to parse metadata.json")?;
            metadata = Some(m);
        } else if path_str.starts_with("config/") {
            config_entries.push((path_str, data));
        }
    }

    let metadata = metadata.ok_or_else(|| anyhow::anyhow!("backup is missing metadata.json"))?;

    // -- Verify integrity --------------------------------------------------
    // Sort by path (same order used during creation) and concatenate bytes.
    config_entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut content_bytes = Vec::new();
    for (_, bytes) in &config_entries {
        content_bytes.extend_from_slice(bytes);
    }

    if !verify_sha256(&content_bytes, &metadata.sha256) {
        anyhow::bail!(
            "backup integrity check failed: SHA-256 mismatch \
             (expected {}, got {})",
            metadata.sha256,
            super::verify::sha256_hex(&content_bytes)
        );
    }

    // -- Determine which subsystems to restore ----------------------------
    let to_restore: Vec<Subsystem> = if let Some(filter) = subsystems_filter {
        metadata
            .subsystems
            .iter()
            .filter(|s| filter.contains(s))
            .cloned()
            .collect()
    } else {
        metadata.subsystems.clone()
    };

    // Build a lookup: archive_path → bytes
    let entry_map: std::collections::HashMap<&str, &[u8]> = config_entries
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();

    // -- Apply each subsystem to the config store -------------------------
    for sub in &to_restore {
        let archive_path = sub.archive_path();
        let Some(bytes) = entry_map.get(archive_path) else {
            warn!(subsystem = ?sub, "subsystem not present in backup; skipping");
            continue;
        };

        restore_subsystem(store, sub, bytes)
            .with_context(|| format!("failed to restore subsystem {archive_path}"))?;

        info!(subsystem = ?sub, "subsystem restored");
    }

    info!(
        subsystems_restored = to_restore.len(),
        backup_created_at = metadata.created_at,
        "backup restore complete"
    );

    Ok(metadata)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Attempt to decode the payload.
///
/// If the payload is a plain TAR archive (starts with a valid ustar/GNU magic)
/// or a passphrase was not provided, it is returned as-is (after a quick
/// sanity check).  Otherwise it is decrypted with the given passphrase.
fn try_decode_payload(payload: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    // A GNU TAR header has "ustar" at offset 257 or starts with a non-null
    // entry name.  A simpler heuristic: try to parse as TAR; if that fails
    // and a passphrase is available, try decryption.
    let looks_like_tar = is_valid_tar(payload);

    if looks_like_tar {
        if passphrase.is_some() {
            warn!("passphrase supplied for an unencrypted backup; ignoring it");
        }
        return Ok(payload.to_vec());
    }

    // Not obviously a TAR - attempt decryption.
    let phrase = passphrase.ok_or_else(|| {
        anyhow::anyhow!(
            "backup does not appear to be a plain TAR archive and no passphrase was provided"
        )
    })?;

    encrypt::decrypt(payload, phrase).context("failed to decrypt backup")
}

/// Quick check: does the byte slice look like a TAR archive?
///
/// A TAR archive begins with a 512-byte header.  A GNU/ustar header has the
/// magic bytes `"ustar"` at offset 257.  A v7/POSIX archive can be detected
/// by checking that the checksum field is plausible - but a simple heuristic
/// (non-empty name at offset 0) is sufficient here.
fn is_valid_tar(data: &[u8]) -> bool {
    if data.len() < 512 {
        return false;
    }
    // ustar magic at offset 257 (GNU tar writes "ustar  \0", POSIX "ustar\0").
    let magic = &data[257..262];
    magic == b"ustar"
}

/// Deserialise and restore a single subsystem from archive `bytes` into
/// `store`.
fn restore_subsystem(store: &ConfigStore, sub: &Subsystem, bytes: &[u8]) -> Result<()> {
    match sub {
        Subsystem::Interfaces => {
            let interfaces: Vec<crate::config::models::Interface> =
                serde_json::from_slice(bytes).context("failed to parse interfaces.json")?;
            store
                .save_interfaces(interfaces)
                .context("failed to save interfaces")?;
        }
        Subsystem::Firewall => {
            let fw: FirewallBackup =
                serde_json::from_slice(bytes).context("failed to parse firewall.json")?;
            store
                .save_firewall_rules(fw.rules)
                .context("failed to save firewall rules")?;
            store
                .save_firewall_aliases(fw.aliases)
                .context("failed to save firewall aliases")?;
        }
        Subsystem::Dns => {
            let dns: DnsBackup =
                serde_json::from_slice(bytes).context("failed to parse dns.json")?;
            if let Some(cfg) = dns.config {
                store
                    .save_dns_config(cfg)
                    .context("failed to save DNS config")?;
            }
            store
                .save_dns_overrides(dns.host_overrides, dns.domain_overrides)
                .context("failed to save DNS overrides")?;
        }
        Subsystem::Dhcp => {
            let dhcp: Option<crate::config::models::DhcpConfig> =
                serde_json::from_slice(bytes).context("failed to parse dhcp.json")?;
            if let Some(cfg) = dhcp {
                store
                    .save_dhcp_config(cfg)
                    .context("failed to save DHCP config")?;
            }
        }
        Subsystem::WireGuard => {
            let wg: Vec<crate::config::models::WireGuardInterface> =
                serde_json::from_slice(bytes).context("failed to parse wireguard.json")?;
            store
                .save_wireguard_interfaces(wg)
                .context("failed to save WireGuard interfaces")?;
        }
        Subsystem::Suricata => {
            let suricata: Option<crate::config::models::SuricataConfig> =
                serde_json::from_slice(bytes).context("failed to parse suricata.json")?;
            if let Some(cfg) = suricata {
                store
                    .save_suricata_config(cfg)
                    .context("failed to save Suricata config")?;
            }
        }
        Subsystem::CrowdSec => {
            let crowdsec: Option<crate::config::models::CrowdSecConfig> =
                serde_json::from_slice(bytes).context("failed to parse crowdsec.json")?;
            if let Some(cfg) = crowdsec {
                store
                    .save_crowdsec_config(cfg)
                    .context("failed to save CrowdSec config")?;
            }
        }
        Subsystem::Acme => {
            let acme: Option<crate::config::models::AcmeConfig> =
                serde_json::from_slice(bytes).context("failed to parse acme.json")?;
            if let Some(cfg) = acme {
                store
                    .save_acme_config(cfg)
                    .context("failed to save ACME config")?;
            }
        }
        Subsystem::CaptivePortal => {
            let captive_portal: Option<crate::config::models::CaptivePortalConfig> =
                serde_json::from_slice(bytes)
                    .context("failed to parse captive_portal.json")?;
            if let Some(cfg) = captive_portal {
                store
                    .save_captive_portal_config(cfg)
                    .context("failed to save Captive Portal config")?;
            }
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
    use crate::backup::model::BackupType;
    use tempfile::TempDir;

    fn setup() -> (TempDir, TempDir, ConfigStore) {
        let cfg_dir = TempDir::new().unwrap();
        let backup_dir = TempDir::new().unwrap();
        let store = ConfigStore::with_dir(cfg_dir.path());
        (cfg_dir, backup_dir, store)
    }

    #[test]
    fn roundtrip_plain() {
        let (_cfg, backup_dir, store) = setup();

        let (path, _meta) =
            create_backup(&store, None, false, None, backup_dir.path(), BackupType::Manual).unwrap();
        let bytes = std::fs::read(&path).unwrap();

        let meta = restore_backup(&store, &bytes, None, None).unwrap();
        assert_eq!(meta.subsystems.len(), Subsystem::all().len());
    }

    #[test]
    fn roundtrip_encrypted() {
        let (_cfg, backup_dir, store) = setup();

        let (path, _meta) = create_backup(
            &store,
            None,
            true,
            Some("hunter2"),
            backup_dir.path(),
            BackupType::Manual,
        )
        .unwrap();
        let bytes = std::fs::read(&path).unwrap();

        let meta = restore_backup(&store, &bytes, Some("hunter2"), None).unwrap();
        assert!(meta.encrypted);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let (_cfg, backup_dir, store) = setup();

        let (path, _meta) = create_backup(
            &store,
            None,
            true,
            Some("correct"),
            backup_dir.path(),
            BackupType::Manual,
        )
        .unwrap();
        let bytes = std::fs::read(&path).unwrap();

        assert!(restore_backup(&store, &bytes, Some("wrong"), None).is_err());
    }

    #[test]
    fn tampered_archive_fails_sha256() {
        let (_cfg, backup_dir, store) = setup();

        let (path, _meta) =
            create_backup(&store, None, false, None, backup_dir.path(), BackupType::Manual).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();

        // Flip a byte somewhere in the config section (past the first 1024 bytes).
        if bytes.len() > 1024 {
            bytes[1024] ^= 0xFF;
        }

        assert!(restore_backup(&store, &bytes, None, None).is_err());
    }

    #[test]
    fn selective_restore_skips_absent_subsystems() {
        let (_cfg, backup_dir, store) = setup();

        // Backup only DNS.
        let (path, _meta) = create_backup(
            &store,
            Some(vec![Subsystem::Dns]),
            false,
            None,
            backup_dir.path(),
            BackupType::Manual,
        )
        .unwrap();
        let bytes = std::fs::read(&path).unwrap();

        // Attempt to restore only WireGuard from a DNS-only backup (should
        // complete successfully, just warn that WireGuard isn't present).
        let meta =
            restore_backup(&store, &bytes, None, Some(vec![Subsystem::WireGuard])).unwrap();
        assert_eq!(meta.subsystems, vec![Subsystem::Dns]);
    }
}
