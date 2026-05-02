//! Background backup scheduler.
//!
//! [`start_backup_scheduler`] spawns a Tokio task that wakes every minute,
//! reads the current [`BackupScheduleConfig`] from persistent storage, and
//! triggers a full backup when the configured interval has elapsed.
//!
//! Old backup files are pruned after each successful run so that at most
//! `retention_count` files are kept in the backup directory.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time;
use tracing::{info, warn};

use crate::state::AppState;

use super::create::{create_backup, DEFAULT_BACKUP_DIR};

/// How often the scheduler wakes up to check whether a backup is due.
const CHECK_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Spawn the background backup scheduler.
///
/// Returns immediately; the scheduler loop runs in a detached Tokio task for
/// the lifetime of the process.
pub async fn start_backup_scheduler(state: Arc<AppState>) {
    tokio::spawn(async move {
        run_scheduler(state).await;
    });
}

// ---------------------------------------------------------------------------
// Inner loop
// ---------------------------------------------------------------------------

async fn run_scheduler(state: Arc<AppState>) {
    info!("backup/scheduler: starting");

    let mut ticker = time::interval(CHECK_INTERVAL);
    // Track the Unix timestamp of the last successful backup so we can
    // enforce the configured interval.
    let mut last_backup_ts: u64 = 0;

    loop {
        ticker.tick().await;

        let schedule = match state.config_store.load_backup_schedule() {
            Ok(Some(s)) => s,
            Ok(None) => continue, // not configured
            Err(e) => {
                warn!(error = %e, "backup/scheduler: failed to load schedule config");
                continue;
            }
        };

        if !schedule.enabled || schedule.interval_hours == 0 {
            continue;
        }

        let now = unix_now();
        let interval_secs = schedule.interval_hours * 3600;

        if now.saturating_sub(last_backup_ts) < interval_secs {
            continue; // not yet due
        }

        info!(
            interval_hours = schedule.interval_hours,
            "backup/scheduler: running scheduled backup"
        );

        let backup_dir = PathBuf::from(&schedule.backup_dir);
        let passphrase = schedule.passphrase.as_deref();

        match create_backup(
            None,
            &state.config_store,
            schedule.encrypt,
            passphrase,
            &backup_dir,
        )
        .await
        {
            Ok(path) => {
                info!(path = %path.display(), "backup/scheduler: scheduled backup created");
                last_backup_ts = now;

                if let Err(e) = prune_old_backups(&backup_dir, schedule.retention_count) {
                    warn!(error = %e, "backup/scheduler: failed to prune old backups");
                }
            }
            Err(e) => {
                warn!(error = %e, "backup/scheduler: scheduled backup failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pruning
// ---------------------------------------------------------------------------

/// Delete the oldest backup files in `backup_dir`, keeping at most
/// `retention_count` files.
///
/// Files are identified by the naming convention `<unix_ts>_backup.{tar,tar.enc}`.
/// When `retention_count` is 0 no files are deleted.
pub fn prune_old_backups(backup_dir: &Path, retention_count: usize) -> anyhow::Result<()> {
    if retention_count == 0 {
        return Ok(());
    }

    let mut entries: Vec<(u64, PathBuf)> = std::fs::read_dir(backup_dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            let name = path.file_name()?.to_string_lossy().into_owned();
            if name.ends_with("_backup.tar") || name.ends_with("_backup.tar.enc") {
                let ts: u64 = name.splitn(2, '_').next()?.parse().ok()?;
                Some((ts, path))
            } else {
                None
            }
        })
        .collect();

    // Sort oldest-first so we can take the leading slice to delete.
    entries.sort_by_key(|(ts, _)| *ts);

    let to_delete = entries.len().saturating_sub(retention_count);
    for (_, path) in entries.into_iter().take(to_delete) {
        if let Err(e) = std::fs::remove_file(&path) {
            warn!(
                path = %path.display(),
                error = %e,
                "backup/scheduler: failed to delete old backup"
            );
        } else {
            info!(path = %path.display(), "backup/scheduler: pruned old backup");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_backup_file(dir: &Path, ts: u64) {
        let name = format!("{ts}_backup.tar");
        std::fs::write(dir.join(name), b"dummy").unwrap();
    }

    #[test]
    fn prune_keeps_newest_files() {
        let dir = tempfile::tempdir().unwrap();
        for ts in [100u64, 200, 300, 400, 500] {
            make_backup_file(dir.path(), ts);
        }

        prune_old_backups(dir.path(), 3).unwrap();

        let remaining: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        assert_eq!(remaining.len(), 3);
        // Oldest two (100, 200) should be gone.
        assert!(!remaining.iter().any(|n| n.starts_with("100_")));
        assert!(!remaining.iter().any(|n| n.starts_with("200_")));
    }

    #[test]
    fn prune_retention_zero_does_nothing() {
        let dir = tempfile::tempdir().unwrap();
        for ts in [1u64, 2, 3] {
            make_backup_file(dir.path(), ts);
        }

        prune_old_backups(dir.path(), 0).unwrap();

        let count = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count, 3);
    }

    #[test]
    fn prune_fewer_than_retention_does_nothing() {
        let dir = tempfile::tempdir().unwrap();
        make_backup_file(dir.path(), 1);

        prune_old_backups(dir.path(), 5).unwrap();

        let count = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count, 1);
    }
}
