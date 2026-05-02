//! Automatic backup scheduler.
//!
//! [`start_backup_scheduler`] spawns a Tokio background task that checks the
//! [`BackupScheduleConfig`] stored on disk and creates a new backup whenever
//! `interval_hours` has elapsed.  Old backups beyond `retain_count` are pruned
//! automatically.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info, warn};

use crate::state::AppState;

use super::create::{create_backup, DEFAULT_BACKUP_DIR};
use super::model::BackupScheduleConfig;

// ---------------------------------------------------------------------------
// Schedule config persistence
// ---------------------------------------------------------------------------

/// File name for the scheduler configuration (lives in the same directory as
/// the main `config.json`).
const SCHEDULE_FILE: &str = "backup_schedule.json";

/// Load the [`BackupScheduleConfig`] from the config directory derived from
/// `state`.  Returns `BackupScheduleConfig::default()` if the file does not
/// exist.
pub fn load_schedule(state: &AppState) -> Result<BackupScheduleConfig> {
    let path = schedule_path(state);
    if !path.exists() {
        return Ok(BackupScheduleConfig::default());
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))
}

/// Atomically persist a [`BackupScheduleConfig`] into the config directory.
pub fn save_schedule(state: &AppState, cfg: &BackupScheduleConfig) -> Result<()> {
    let path = schedule_path(state);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config dir {}", parent.display()))?;
    }

    let json = serde_json::to_string_pretty(cfg).context("failed to serialise schedule config")?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &json)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("failed to rename to {}", path.display()))?;

    info!(path = %path.display(), "backup schedule saved");
    Ok(())
}

// ---------------------------------------------------------------------------
// Background scheduler task
// ---------------------------------------------------------------------------

/// Spawn a background Tokio task that runs the backup scheduler loop.
///
/// The task wakes up every minute and checks whether a new backup is due
/// based on the persisted [`BackupScheduleConfig`].  If the scheduler is
/// disabled or `interval_hours` is 0 the task silently waits.
pub async fn start_backup_scheduler(state: Arc<AppState>) {
    tokio::spawn(scheduler_loop(state));
}

async fn scheduler_loop(state: Arc<AppState>) {
    // Check interval: wake up every 60 seconds to poll the schedule config.
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Track the Unix timestamp of the last backup we created.
    let mut last_backup_at: u64 = 0;

    info!("backup scheduler started");

    loop {
        interval.tick().await;

        let cfg = match load_schedule(&state) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "backup scheduler: failed to load schedule config");
                continue;
            }
        };

        if !cfg.enabled || cfg.interval_hours == 0 {
            continue;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let interval_secs = cfg.interval_hours * 3600;
        if now.saturating_sub(last_backup_at) < interval_secs {
            continue;
        }

        info!("backup scheduler: creating scheduled backup");

        let backup_dir = PathBuf::from(DEFAULT_BACKUP_DIR);
        let passphrase = cfg.passphrase.as_deref().map(String::from);
        let encrypt = cfg.encrypt;
        let retain = cfg.retain_count;

        let result = {
            let p = passphrase.as_deref();
            create_backup(&state.config_store, None, encrypt, p, &backup_dir)
        };

        match result {
            Ok(path) => {
                info!(path = %path.display(), "backup scheduler: backup created");
                last_backup_at = now;

                // Prune old backups.
                if let Err(e) = prune_backups(&backup_dir, retain) {
                    warn!(error = %e, "backup scheduler: failed to prune old backups");
                }
            }
            Err(e) => {
                error!(error = %e, "backup scheduler: backup failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pruning
// ---------------------------------------------------------------------------

/// Delete the oldest backup files in `dir` so that at most `retain_count`
/// remain.
///
/// Files matching `dayshield-backup-*.tar` and `dayshield-backup-*.tar.enc`
/// are considered.  They are sorted by name (which is timestamp-based) so the
/// oldest sort first.
pub fn prune_backups(dir: &Path, retain_count: usize) -> Result<()> {
    if retain_count == 0 {
        return Ok(());
    }

    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read backup directory {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| is_backup_file(p))
        .collect();

    files.sort();

    if files.len() <= retain_count {
        return Ok(());
    }

    let to_delete = files.len() - retain_count;
    for path in files.iter().take(to_delete) {
        info!(path = %path.display(), "backup scheduler: pruning old backup");
        std::fs::remove_file(path)
            .with_context(|| format!("failed to delete {}", path.display()))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the path to the schedule config file.
fn schedule_path(state: &AppState) -> PathBuf {
    // ConfigStore exposes the config directory via the store's config path.
    // We derive the parent directory from the store's internal path.
    let config_path = state.config_store.config_path();
    config_path
        .parent()
        .unwrap_or(Path::new("/etc/dayshield/config"))
        .join(SCHEDULE_FILE)
}

/// Return `true` if `path` looks like a DayShield backup file.
fn is_backup_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    (name.starts_with("dayshield-backup-") && name.ends_with(".tar"))
        || (name.starts_with("dayshield-backup-") && name.ends_with(".tar.enc"))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn prune_keeps_newest() {
        let dir = TempDir::new().unwrap();
        // Create 5 fake backup files.
        for i in 0..5u32 {
            let ts = 1_700_000_000u64 + u64::from(i);
            let name = format!("dayshield-backup-{ts}.tar");
            std::fs::write(dir.path().join(&name), b"placeholder").unwrap();
        }
        prune_backups(dir.path(), 3).unwrap();
        let remaining: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(remaining.len(), 3);
    }

    #[test]
    fn prune_noop_when_within_retain() {
        let dir = TempDir::new().unwrap();
        for i in 0..2u32 {
            let ts = 1_700_000_000u64 + u64::from(i);
            std::fs::write(
                dir.path().join(format!("dayshield-backup-{ts}.tar")),
                b"x",
            )
            .unwrap();
        }
        prune_backups(dir.path(), 5).unwrap();
        let remaining: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn is_backup_file_matches_expected_patterns() {
        assert!(is_backup_file(Path::new(
            "dayshield-backup-1700000000.tar"
        )));
        assert!(is_backup_file(Path::new(
            "dayshield-backup-1700000000.tar.enc"
        )));
        assert!(!is_backup_file(Path::new("config.json")));
        assert!(!is_backup_file(Path::new("random.tar")));
    }
}
