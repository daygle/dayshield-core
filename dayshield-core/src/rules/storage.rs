//! Persistence layer for managed ruleset metadata.
//!
//! Installed ruleset metadata is stored as a pretty-printed JSON array in:
//! ```text
//! /var/lib/dayshield/rulesets/installed.json
//! ```
//!
//! Downloaded and generated rule files live under:
//! ```text
//! /var/lib/dayshield/rulesets/<id>/original.rules
//! /var/lib/dayshield/rulesets/<id>/suricata.rules
//! ```

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::debug;

use crate::rules::models::InstalledRuleset;

/// Default base directory for managed ruleset storage.
pub const RULESETS_DIR: &str = "/var/lib/dayshield/rulesets";
/// Metadata file name within the rulesets base directory.
const METADATA_FILE: &str = "installed.json";

// ---------------------------------------------------------------------------
// RulesetStore
// ---------------------------------------------------------------------------

/// Load/save access to the installed rulesets metadata file.
pub struct RulesetStore {
    base_dir: PathBuf,
}

impl RulesetStore {
    /// Create a store using the default directory (`/var/lib/dayshield/rulesets`).
    pub fn new() -> Self {
        Self::with_dir(RULESETS_DIR)
    }

    /// Create a store using a custom directory (useful for tests).
    pub fn with_dir(dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: dir.as_ref().to_path_buf(),
        }
    }

    /// Return the path to the metadata JSON file.
    pub fn metadata_path(&self) -> PathBuf {
        self.base_dir.join(METADATA_FILE)
    }

    /// Return the working directory for a specific ruleset id.
    pub fn ruleset_dir(&self, id: &str) -> PathBuf {
        self.base_dir.join(id)
    }

    /// Return the immutable downloaded `.rules` file for a given ruleset id.
    pub fn source_rules_file(&self, id: &str) -> PathBuf {
        self.ruleset_dir(id).join("original.rules")
    }

    /// Return the generated `.rules` file Suricata reads for a given ruleset id.
    pub fn effective_rules_file(&self, id: &str) -> PathBuf {
        self.ruleset_dir(id).join("suricata.rules")
    }

    /// Return the generated `.rules` file for a given ruleset id.
    ///
    /// Kept as the public compatibility helper for existing callers.
    pub fn rules_file(&self, id: &str) -> PathBuf {
        self.effective_rules_file(id)
    }

    /// Load all installed rulesets from disk.
    ///
    /// Returns an empty `Vec` if the metadata file does not exist yet.
    pub fn load(&self) -> Result<Vec<InstalledRuleset>> {
        let path = self.metadata_path();
        if !path.exists() {
            debug!("rulesets: metadata file not found, returning empty list");
            return Ok(vec![]);
        }

        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let list: Vec<InstalledRuleset> = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse {}", path.display()))?;

        debug!("rulesets: loaded {} installed rulesets", list.len());
        Ok(list)
    }

    /// Atomically persist the installed rulesets list to disk.
    ///
    /// Uses a write-then-rename strategy so a crash mid-write cannot corrupt
    /// the metadata file.
    pub fn save(&self, rulesets: &[InstalledRuleset]) -> Result<()> {
        let path = self.metadata_path();

        // Ensure the base directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }

        let json =
            serde_json::to_string_pretty(rulesets).context("failed to serialise rulesets")?;

        // Atomic write via temp file + rename.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))?;

        debug!("rulesets: saved {} installed rulesets", rulesets.len());
        Ok(())
    }
}

impl Default for RulesetStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::models::{InstalledRuleset, RulesetStatus};
    use tempfile::TempDir;

    fn make_ruleset(id: &str) -> InstalledRuleset {
        InstalledRuleset {
            id: id.to_string(),
            display_name: "Test Ruleset".to_string(),
            source_url: "https://example.com/rules.tar.gz".to_string(),
            installed_version: Some("v1".to_string()),
            latest_version: None,
            enabled: false,
            status: RulesetStatus::Installed,
            last_error: None,
            last_checked: None,
            last_updated: None,
            local_path: Some(format!("/var/lib/dayshield/rulesets/{id}/suricata.rules")),
        }
    }

    #[test]
    fn load_returns_empty_when_no_file() {
        let dir = TempDir::new().unwrap();
        let store = RulesetStore::with_dir(dir.path());
        let list = store.load().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = RulesetStore::with_dir(dir.path());

        let rulesets = vec![make_ruleset("et-open"), make_ruleset("oisf-trafficid")];
        store.save(&rulesets).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, "et-open");
        assert_eq!(loaded[1].id, "oisf-trafficid");
    }

    #[test]
    fn save_is_atomic_on_overwrite() {
        let dir = TempDir::new().unwrap();
        let store = RulesetStore::with_dir(dir.path());

        // Write once.
        store.save(&[make_ruleset("et-open")]).unwrap();
        // Overwrite with different data.
        store
            .save(&[make_ruleset("et-open"), make_ruleset("oisf-trafficid")])
            .unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn ruleset_dir_and_rules_file_paths() {
        let store = RulesetStore::with_dir("/tmp/rulesets");
        assert_eq!(
            store.ruleset_dir("et-open"),
            PathBuf::from("/tmp/rulesets/et-open")
        );
        assert_eq!(
            store.source_rules_file("et-open"),
            PathBuf::from("/tmp/rulesets/et-open/original.rules")
        );
        assert_eq!(
            store.effective_rules_file("et-open"),
            PathBuf::from("/tmp/rulesets/et-open/suricata.rules")
        );
        assert_eq!(
            store.rules_file("et-open"),
            PathBuf::from("/tmp/rulesets/et-open/suricata.rules")
        );
    }
}
