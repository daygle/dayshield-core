//! Configuration revision history.
//!
//! Every successful commit through [`ConfigStore::save_with_rollback`] archives
//! the configuration as a timestamped, immutable revision under the
//! `history/` subdirectory of the configuration directory (alongside
//! `config.json`). This gives operators an OPNsense-style audit trail: every
//! prior configuration state can be listed, inspected and restored.
//!
//! [`ConfigStore::save_with_rollback`]: super::storage::ConfigStore::save_with_rollback
//!
//! A revision is stored as a self-describing JSON envelope:
//!
//! ```json
//! {
//!   "saved_at": 1700000000,
//!   "schema_version": 1,
//!   "description": "Updated DNS forwarders",
//!   "config": { /* verbatim config.json contents */ }
//! }
//! ```
//!
//! The `config` field holds the exact on-disk `config.json` payload (the
//! versioned envelope), so a revision can be loaded back through the same
//! migration path as the live config.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::storage::write_restricted;

/// Name of the subdirectory (under the config directory) holding revisions.
pub(crate) const HISTORY_SUBDIR: &str = "history";

/// Metadata describing a single archived configuration revision.
///
/// This is the public, serialisable view returned by listing APIs; it
/// deliberately omits the (potentially large) configuration payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigRevision {
    /// Stable identifier (the revision file name without its `.json` suffix).
    pub id: String,
    /// Unix timestamp (seconds) when the revision was archived.
    pub saved_at: i64,
    /// Schema version of the archived configuration payload.
    pub schema_version: u32,
    /// Optional human-readable description of the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Size of the revision file on disk, in bytes.
    pub size_bytes: u64,
}

/// On-disk revision envelope.
#[derive(Serialize, Deserialize)]
struct RevisionEnvelope {
    saved_at: i64,
    schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    config: serde_json::Value,
}

/// Return the history directory for the given primary config file path.
pub(crate) fn history_dir(config_path: &Path) -> PathBuf {
    let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(HISTORY_SUBDIR)
}

/// Reject revision identifiers that could escape the history directory.
fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.contains('/')
        || id.contains('\\')
        || id.contains("..")
        || id.contains('\0')
    {
        anyhow::bail!("invalid revision id {id:?}");
    }
    Ok(())
}

/// Extract the `schema_version` field from a config.json payload, defaulting to
/// `0` for pre-versioning files.
fn schema_version_of(config: &serde_json::Value) -> u32 {
    config
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32
}

/// Archive `config_bytes` (the exact bytes just written to `config.json`) as a
/// new revision under the history directory.
///
/// Returns `Ok(None)` (a no-op) when the committed configuration is byte-for-
/// byte identical to the most recent revision, which avoids cluttering the
/// history with duplicate entries produced by load-modify-save cycles that
/// don't actually change anything.
///
/// After a successful write the history is pruned to at most
/// [`MAX_HISTORY_REVISIONS`] entries (oldest removed first).
pub(crate) fn write_revision(
    config_path: &Path,
    config_bytes: &[u8],
    description: Option<&str>,
    max_revisions: usize,
) -> Result<Option<ConfigRevision>> {
    let dir = history_dir(config_path);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create history directory {}", dir.display()))?;

    let config: serde_json::Value =
        serde_json::from_slice(config_bytes).context("Failed to parse config for history")?;

    // Skip if the newest revision already holds an identical configuration.
    let existing = list_revisions(config_path)?;
    if let Some(latest) = existing.first() {
        if let Ok(latest_config) = read_revision_config(config_path, &latest.id) {
            if latest_config == config {
                debug!("Config unchanged since latest revision; skipping history snapshot");
                return Ok(None);
            }
        }
    }

    let saved_at = chrono::Utc::now().timestamp();
    let schema_version = schema_version_of(&config);
    let envelope = RevisionEnvelope {
        saved_at,
        schema_version,
        description: description.map(str::to_string),
        config,
    };

    // Millisecond timestamp plus a random suffix keeps file names ordered and
    // unique even across rapid successive saves.
    let id = format!(
        "{:014}-{}",
        chrono::Utc::now().timestamp_millis(),
        uuid::Uuid::new_v4().simple()
    );
    let path = dir.join(format!("{id}.json"));

    let json = serde_json::to_vec_pretty(&envelope).context("Failed to serialise revision")?;
    write_restricted(&path, &json)?;

    let size_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

    if let Err(e) = prune(&dir, max_revisions) {
        warn!(error = %e, "Failed to prune config history");
    }

    debug!(id = %id, "Archived config revision");
    Ok(Some(ConfigRevision {
        id,
        saved_at,
        schema_version,
        description: description.map(str::to_string),
        size_bytes,
    }))
}

/// List archived revisions, newest first.
pub(crate) fn list_revisions(config_path: &Path) -> Result<Vec<ConfigRevision>> {
    let dir = history_dir(config_path);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut revisions: Vec<ConfigRevision> = std::fs::read_dir(&dir)
        .with_context(|| format!("Failed to read history directory {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                return None;
            }
            let id = path.file_stem()?.to_str()?.to_string();
            let size_bytes = entry.metadata().ok()?.len();
            let raw = std::fs::read(&path).ok()?;
            let envelope: RevisionEnvelope = serde_json::from_slice(&raw).ok()?;
            Some(ConfigRevision {
                id,
                saved_at: envelope.saved_at,
                schema_version: envelope.schema_version,
                description: envelope.description,
                size_bytes,
            })
        })
        .collect();

    // Newest first; the id embeds a millisecond timestamp so it is a stable
    // tie-breaker for revisions sharing the same `saved_at` second.
    revisions.sort_by(|a, b| {
        b.saved_at
            .cmp(&a.saved_at)
            .then_with(|| b.id.cmp(&a.id))
    });

    Ok(revisions)
}

/// Return the verbatim `config.json` payload (versioned envelope) stored in the
/// revision identified by `id`.
pub(crate) fn read_revision_config(config_path: &Path, id: &str) -> Result<serde_json::Value> {
    validate_id(id)?;
    let path = history_dir(config_path).join(format!("{id}.json"));
    if !path.exists() {
        anyhow::bail!("revision {id} not found");
    }
    let raw = std::fs::read(&path)
        .with_context(|| format!("Failed to read revision {}", path.display()))?;
    let envelope: RevisionEnvelope =
        serde_json::from_slice(&raw).with_context(|| format!("Failed to parse revision {id}"))?;
    Ok(envelope.config)
}

/// Delete a single archived revision by id.
pub(crate) fn delete_revision(config_path: &Path, id: &str) -> Result<()> {
    validate_id(id)?;
    let path = history_dir(config_path).join(format!("{id}.json"));
    if !path.exists() {
        anyhow::bail!("revision {id} not found");
    }
    std::fs::remove_file(&path)
        .with_context(|| format!("Failed to delete revision {}", path.display()))?;
    debug!(id = %id, "Deleted config revision");
    Ok(())
}

/// Remove the oldest revisions so at most `max_revisions` remain.
fn prune(dir: &Path, max_revisions: usize) -> Result<()> {
    if max_revisions == 0 {
        return Ok(());
    }

    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();

    if files.len() <= max_revisions {
        return Ok(());
    }

    // File names embed a millisecond timestamp, so lexicographic order is
    // chronological. Remove the oldest (front) beyond the retention count.
    files.sort();
    let remove_count = files.len() - max_revisions;
    for path in files.into_iter().take(remove_count) {
        if let Err(e) = std::fs::remove_file(&path) {
            warn!(path = %path.display(), error = %e, "Failed to remove old revision");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config_path() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ds-hist-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("config.json")
    }

    fn payload(hostname: &str) -> Vec<u8> {
        format!(r#"{{"schema_version":1,"hostname":"{hostname}"}}"#).into_bytes()
    }

    #[test]
    fn write_then_list_round_trips() {
        let cfg = temp_config_path();
        let rev = write_revision(&cfg, &payload("a"), Some("first"), 50)
            .unwrap()
            .expect("first revision written");
        assert_eq!(rev.schema_version, 1);
        assert_eq!(rev.description.as_deref(), Some("first"));

        let listed = list_revisions(&cfg).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, rev.id);

        let stored = read_revision_config(&cfg, &rev.id).unwrap();
        assert_eq!(stored["hostname"], "a");

        let _ = std::fs::remove_dir_all(cfg.parent().unwrap());
    }

    #[test]
    fn identical_config_is_not_duplicated() {
        let cfg = temp_config_path();
        write_revision(&cfg, &payload("same"), None, 50).unwrap();
        let second = write_revision(&cfg, &payload("same"), None, 50).unwrap();
        assert!(second.is_none(), "identical config must not create a revision");
        assert_eq!(list_revisions(&cfg).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(cfg.parent().unwrap());
    }

    #[test]
    fn newest_revision_is_listed_first() {
        let cfg = temp_config_path();
        write_revision(&cfg, &payload("old"), None, 50).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        write_revision(&cfg, &payload("new"), None, 50).unwrap();

        let listed = list_revisions(&cfg).unwrap();
        assert_eq!(listed.len(), 2);
        let newest = read_revision_config(&cfg, &listed[0].id).unwrap();
        assert_eq!(newest["hostname"], "new");
        let _ = std::fs::remove_dir_all(cfg.parent().unwrap());
    }

    #[test]
    fn prune_enforces_retention_limit() {
        let cfg = temp_config_path();
        for i in 0..5 {
            write_revision(&cfg, &payload(&format!("h{i}")), None, 3).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let listed = list_revisions(&cfg).unwrap();
        assert_eq!(listed.len(), 3, "history must be capped at retention limit");
        // The three most recent (h2, h3, h4) must survive.
        let newest = read_revision_config(&cfg, &listed[0].id).unwrap();
        assert_eq!(newest["hostname"], "h4");
        let _ = std::fs::remove_dir_all(cfg.parent().unwrap());
    }

    #[test]
    fn read_revision_rejects_traversal() {
        let cfg = temp_config_path();
        assert!(read_revision_config(&cfg, "../config").is_err());
        assert!(read_revision_config(&cfg, "a/b").is_err());
        let _ = std::fs::remove_dir_all(cfg.parent().unwrap());
    }
}
