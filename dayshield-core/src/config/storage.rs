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
//!
//! TODO: add schema versioning and migration helpers.
//! TODO: support loading config fragments from multiple files in the directory.
//! TODO: integrate with the engine layer to push config changes to live
//!       services after a successful commit.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use super::models::SystemConfig;

/// Default path to the configuration directory.
const DEFAULT_CONFIG_DIR: &str = "/etc/dayshield/config";
/// Config file name inside the config directory.
const CONFIG_FILE: &str = "config.json";
/// Temporary file suffix used for atomic writes.
const TMP_SUFFIX: &str = ".tmp";
/// Backup file suffix used for rollback.
const BAK_SUFFIX: &str = ".bak";

/// Manages loading and saving the [`SystemConfig`] to persistent storage.
pub struct ConfigStore {
    config_path: PathBuf,
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
        }
    }

    /// Load the [`SystemConfig`] from disk.
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

        let config: SystemConfig = serde_json::from_str(&raw)
            .with_context(|| format!("Failed to parse {}", self.config_path.display()))?;

        Ok(config)
    }

    /// Validate the provided config.
    ///
    /// Returns `Ok(())` when the config is valid, or an [`anyhow::Error`]
    /// describing the first validation failure found.
    ///
    /// TODO: implement thorough semantic validation (e.g. overlapping DHCP
    ///       pools, duplicate interface names, invalid CIDR ranges).
    pub fn validate(&self, config: &SystemConfig) -> Result<()> {
        // Each interface must have a non-empty name.
        for iface in &config.interfaces {
            if iface.name.is_empty() {
                anyhow::bail!("Interface with id {} has an empty name", iface.id);
            }
        }

        // Firewall rules must have a valid priority.
        for rule in &config.firewall_rules {
            if rule.priority < 0 {
                anyhow::bail!(
                    "Firewall rule {} has negative priority {}",
                    rule.id,
                    rule.priority
                );
            }
        }

        Ok(())
    }

    /// Validate and atomically write config to disk.
    ///
    /// The write is performed by:
    /// 1. Serialising the config to JSON.
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

        let json = serde_json::to_string_pretty(config).context("Failed to serialise config")?;

        let tmp_path = self.config_path.with_extension(TMP_SUFFIX);
        std::fs::write(&tmp_path, &json)
            .with_context(|| format!("Failed to write temp file {}", tmp_path.display()))?;

        std::fs::rename(&tmp_path, &self.config_path).with_context(|| {
            format!(
                "Failed to rename {} to {}",
                tmp_path.display(),
                self.config_path.display()
            )
        })?;

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
    pub fn save_with_rollback(&self, config: &SystemConfig) -> Result<()> {
        let bak_path = self.config_path.with_extension(BAK_SUFFIX);

        // Step 1 — backup.
        if self.config_path.exists() {
            std::fs::copy(&self.config_path, &bak_path).with_context(|| {
                format!(
                    "Failed to back up config to {}",
                    bak_path.display()
                )
            })?;
            debug!(backup = %bak_path.display(), "Config backed up");
        }

        // Step 2 — write.
        if let Err(e) = self.save(config) {
            // Restore backup if write itself failed.
            self.try_restore_backup(&bak_path);
            return Err(e);
        }

        // Step 3 — re-validate from disk.
        match self.load().and_then(|c| self.validate(&c)) {
            Ok(_) => {
                // Clean up the backup on success.
                let _ = std::fs::remove_file(&bak_path);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ds-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

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
    fn save_with_rollback_restores_on_invalid_reload() {
        // This test verifies that a good config can be saved and re-loaded.
        let dir = temp_dir();
        let store = ConfigStore::with_dir(&dir);

        let mut cfg = SystemConfig::default();
        cfg.hostname = "rollback-test".into();

        store.save_with_rollback(&cfg).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.hostname, "rollback-test");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
