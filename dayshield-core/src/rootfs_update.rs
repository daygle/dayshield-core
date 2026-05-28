//! Image-based rootfs update orchestration.
//!
//! This module replaces the former OSTree-specific update logic with a
//! version-oriented, image-based rootfs update flow:
//!
//! - Versions are discovered from GitHub-hosted releases (via the shared
//!   registry in `update.rs`).
//! - A new rootfs image artifact is **staged** to a local directory before
//!   rebooting.
//! - The initramfs reads a **pending-version marker** written here and applies
//!   the staged image on the next boot.
//! - Once userspace confirms the boot was successful, the marker is promoted
//!   to **current** and the previous version pointer is updated.
//! - If the boot fails (detected by the initramfs boot-counter / watchdog),
//!   the initramfs reverts to the previous version automatically.
//!
//! ### Disk layout (all paths are under `/var/lib/dayshield/rootfs-update/`)
//!
//! | Path | Purpose |
//! |---|---|
//! | `current.json`    | Metadata for the currently running rootfs version |
//! | `pending.json`    | Metadata for a staged image waiting to be applied on reboot |
//! | `previous.json`   | Metadata for the last known-good rootfs version |
//! | `boot-success`    | Marker written by systemd (via `signal-boot-success` unit) after a healthy boot |
//! | `recovered`       | Marker written by the initramfs when it fell back to the previous version |
//! | `staging/`        | Directory holding downloaded rootfs image artifacts before activation |
//!
//! ### User-facing language
//!
//! All types and API responses use version-oriented language:
//! **current version**, **available version**, **pending update**,
//! **previous version**, **recovered update**.
//! A/B slots, OSTree deployments, and similar internal concepts are never
//! surfaced to callers.

use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

pub const ROOTFS_UPDATE_STATE_DIR: &str = "/var/lib/dayshield/rootfs-update";
pub const ROOTFS_UPDATE_STAGING_DIR: &str = "/var/lib/dayshield/rootfs-update/staging";
pub const ROOTFS_UPDATE_HELPER: &str = "/usr/local/lib/dayshield/rootfs-update.sh";

fn state_dir() -> PathBuf {
    PathBuf::from(ROOTFS_UPDATE_STATE_DIR)
}

fn current_path() -> PathBuf {
    state_dir().join("current.json")
}

fn pending_path() -> PathBuf {
    state_dir().join("pending.json")
}

fn previous_path() -> PathBuf {
    state_dir().join("previous.json")
}

fn boot_success_marker() -> PathBuf {
    state_dir().join("boot-success")
}

fn recovered_marker() -> PathBuf {
    state_dir().join("recovered")
}

// ---------------------------------------------------------------------------
// Version metadata stored on disk
// ---------------------------------------------------------------------------

/// Persisted metadata for a single rootfs version.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootfsVersionMeta {
    /// Semantic version string, e.g. "1.2.3".
    pub version: String,
    /// Path to the staged rootfs image artifact (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    /// SHA-256 checksum of the staged artifact for integrity verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
    /// RFC 3339 timestamp when this metadata was written.
    pub recorded_at: String,
}

impl RootfsVersionMeta {
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            artifact_path: None,
            artifact_sha256: None,
            recorded_at: Utc::now().to_rfc3339(),
        }
    }
}

// ---------------------------------------------------------------------------
// Public status types (UI-facing, version-oriented only)
// ---------------------------------------------------------------------------

/// Transaction state for in-progress rootfs update operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RootfsTransactionState {
    /// No operation in progress.
    #[default]
    Idle,
    /// Checking GitHub for a newer rootfs version.
    Checking,
    /// Downloading and verifying the rootfs artifact.
    Staging,
    /// Marking the staged image ready for the next boot.
    Applying,
    /// Reverting to the previous working version.
    RollingBack,
}

/// Full rootfs update status exposed by the API.
///
/// All fields use version-oriented language.  No A/B, slot, or OSTree
/// terminology is present.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootfsUpdateStatus {
    /// Whether image-based rootfs updates are supported on this host.
    pub supported: bool,
    /// RFC 3339 timestamp of this status snapshot.
    pub checked_at: String,
    /// Version of the currently running rootfs.
    pub current_version: Option<String>,
    /// Latest version available on GitHub (from the registry check).
    pub available_version: Option<String>,
    /// Staged version waiting to be applied on the next reboot.
    pub pending_version: Option<String>,
    /// Last known-good version (available for rollback).
    pub previous_version: Option<String>,
    /// Whether a newer version is available to download.
    pub update_available: bool,
    /// Whether a reboot is required to activate a pending update.
    pub reboot_required: bool,
    /// Whether rollback to the previous version is available.
    pub rollback_available: bool,
    /// True when the system automatically recovered from a failed update.
    pub recovery_active: bool,
    /// Current operation state.
    pub transaction_state: RootfsTransactionState,
    /// Last error encountered, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Result returned by rootfs update operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootfsActionResult {
    pub operation: String,
    pub success: bool,
    pub message: String,
    pub details: Vec<String>,
    pub status: RootfsUpdateStatus,
}

/// Compact reboot-required state for UX banners.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootfsRebootState {
    pub reboot_required: bool,
    pub pending_version: Option<String>,
    pub current_version: Option<String>,
}

// ---------------------------------------------------------------------------
// In-process operation serialisation
// ---------------------------------------------------------------------------

/// Global mutex that serialises rootfs update operations so that only one
/// stage/apply/rollback can run at a time.
static OPERATION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn operation_lock() -> &'static tokio::sync::Mutex<()> {
    OPERATION_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

// ---------------------------------------------------------------------------
// Disk helpers
// ---------------------------------------------------------------------------

fn read_meta(path: &Path) -> Option<RootfsVersionMeta> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_meta(path: &Path, meta: &RootfsVersionMeta) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(meta)?;
    std::fs::write(path, text)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn marker_exists(path: &Path) -> bool {
    path.exists()
}

// ---------------------------------------------------------------------------
// Boot-success signalling
// ---------------------------------------------------------------------------

/// Called by the `dayshield-boot-success` systemd unit after a healthy boot.
///
/// Promotes `pending` → `current`, rotates `current` → `previous`, removes
/// the `recovered` marker, and writes the `boot-success` marker.
pub fn signal_boot_success() -> Result<()> {
    let _ = std::fs::create_dir_all(state_dir());

    let pending = read_meta(&pending_path());
    let current = read_meta(&current_path());

    if let Some(pending_meta) = pending {
        info!(
            version = %pending_meta.version,
            "rootfs: boot success – promoting pending version to current"
        );

        // Rotate current → previous
        if let Some(current_meta) = &current {
            write_meta(&previous_path(), current_meta)?;
        }

        // Promote pending → current
        write_meta(&current_path(), &pending_meta)?;

        // Remove pending marker
        let _ = std::fs::remove_file(pending_path());
    }

    // Write boot-success marker
    std::fs::write(boot_success_marker(), Utc::now().to_rfc3339())
        .with_context(|| "failed to write boot-success marker")?;

    // Clear recovered marker
    let _ = std::fs::remove_file(recovered_marker());

    Ok(())
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// Return the current rootfs update status.
pub async fn status() -> RootfsUpdateStatus {
    let now = Utc::now().to_rfc3339();

    let current = read_meta(&current_path());
    let pending = read_meta(&pending_path());
    let previous = read_meta(&previous_path());

    let current_version = current.as_ref().map(|m| m.version.clone());
    let pending_version = pending.as_ref().map(|m| m.version.clone());
    let previous_version = previous.as_ref().map(|m| m.version.clone());

    let reboot_required = pending_version.is_some();
    let rollback_available = previous_version.is_some();
    let recovery_active = marker_exists(&recovered_marker());

    // available_version: check the update state file via the helper
    let available_version = read_available_version_from_state();

    let update_available = match (&current_version, &available_version) {
        (Some(cur), Some(avail)) => crate::update::is_remote_version_newer(cur, avail),
        (None, Some(_)) => true,
        _ => false,
    };

    // Detect whether the update helper is installed (= supported)
    let supported = Path::new(ROOTFS_UPDATE_HELPER).exists()
        || std::env::var("DAYSHIELD_ROOTFS_UPDATE_SUPPORTED")
            .map(|v| v == "1")
            .unwrap_or(false);

    let tx_state = {
        let lock = operation_lock();
        if lock.try_lock().is_err() {
            // A background operation is in progress
            RootfsTransactionState::Staging
        } else {
            RootfsTransactionState::Idle
        }
    };

    RootfsUpdateStatus {
        supported,
        checked_at: now,
        current_version,
        available_version,
        pending_version,
        previous_version,
        update_available,
        reboot_required,
        rollback_available,
        recovery_active,
        transaction_state: tx_state,
        last_error: None,
    }
}

/// Read the available rootfs version from the shared update state file.
fn read_available_version_from_state() -> Option<String> {
    // The update state file is managed by update.rs; we read it here to avoid
    // duplicating version-check logic.
    let path = Path::new(crate::update::UPDATE_STATE_FILE_PATH);
    let text = std::fs::read_to_string(path).ok()?;
    let state: crate::update::UpdateStateFile = serde_json::from_str(&text).ok()?;
    state
        .components
        .iter()
        .find(|c| c.component == "rootfs")
        .and_then(|c| c.remote_version.clone())
}

/// Return a compact reboot-required state.
pub async fn reboot_state() -> RootfsRebootState {
    let pending = read_meta(&pending_path());
    let current = read_meta(&current_path());
    RootfsRebootState {
        reboot_required: pending.is_some(),
        pending_version: pending.map(|m| m.version),
        current_version: current.map(|m| m.version),
    }
}

/// Synchronous convenience wrapper around [`reboot_state`].
///
/// Returns `true` when a rootfs update has been staged and the system must
/// reboot to complete it.  Use this from synchronous contexts (e.g. inside
/// `update::get_status`).
pub fn reboot_state_sync() -> bool {
    pending_path().exists()
}

// ---------------------------------------------------------------------------
// Stage update (download + verify)
// ---------------------------------------------------------------------------

/// Stage the latest available rootfs update artifact.
///
/// Downloads the rootfs artifact from GitHub (via the update helper), verifies
/// its checksum, and writes a `pending.json` marker pointing to the staged
/// image.  Does **not** activate the image — that requires a reboot after
/// [`apply_update`].
pub async fn stage_update() -> Result<RootfsActionResult> {
    let _guard = operation_lock().lock().await;

    let mut details = Vec::new();

    // Run the helper script in "stage" mode if available
    let (success, message) = if Path::new(ROOTFS_UPDATE_HELPER).exists() {
        run_helper_stage(&mut details).await
    } else {
        // Fallback: best-effort stub used on development hosts
        let msg = "rootfs-update helper not installed; skipping artifact download (development mode)".to_string();
        warn!("{}", msg);
        details.push(msg.clone());
        (true, msg)
    };

    let status = status().await;
    Ok(RootfsActionResult {
        operation: "stage".to_string(),
        success,
        message,
        details,
        status,
    })
}

async fn run_helper_stage(details: &mut Vec<String>) -> (bool, String) {
    match Command::new(ROOTFS_UPDATE_HELPER)
        .arg("stage")
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
                details.push(line.to_string());
            }
            if !stderr.is_empty() {
                details.push(format!("stderr: {}", stderr.trim()));
            }
            if output.status.success() {
                info!("rootfs: stage helper completed successfully");
                (true, "Rootfs update staged successfully.".to_string())
            } else {
                let code = output.status.code().unwrap_or(-1);
                warn!(exit_code = code, "rootfs: stage helper failed");
                (false, format!("Rootfs stage failed (exit {code})."))
            }
        }
        Err(err) => {
            let msg = format!("failed to run rootfs-update helper: {err}");
            warn!("{}", msg);
            details.push(msg.clone());
            (false, msg)
        }
    }
}

// ---------------------------------------------------------------------------
// Apply update (activate pending image for next boot)
// ---------------------------------------------------------------------------

/// Mark the staged rootfs image as the active target for the next boot.
///
/// Writes an **activation marker** that the initramfs reads on startup.  A
/// reboot is required to complete the update.  If the new image fails to boot
/// (detected by the boot counter / watchdog), the initramfs reverts to the
/// previous version automatically.
pub async fn apply_update() -> Result<RootfsActionResult> {
    let _guard = operation_lock().lock().await;

    let mut details = Vec::new();

    let (success, message) = if Path::new(ROOTFS_UPDATE_HELPER).exists() {
        run_helper_apply(&mut details).await
    } else {
        // Fallback stub: write an activation marker directly
        let pending = read_meta(&pending_path());
        if let Some(meta) = &pending {
            let activation_path = state_dir().join("activate");
            match std::fs::write(&activation_path, &meta.version) {
                Ok(()) => {
                    let msg = format!(
                        "Rootfs version {} marked for activation on next boot.",
                        meta.version
                    );
                    info!(version = %meta.version, "rootfs: activation marker written");
                    details.push(msg.clone());
                    (true, msg)
                }
                Err(err) => {
                    let msg = format!("failed to write activation marker: {err}");
                    warn!("{}", msg);
                    (false, msg)
                }
            }
        } else {
            let msg = "No staged rootfs update found. Stage an update first.".to_string();
            warn!("{}", msg);
            (false, msg)
        }
    };

    let status = status().await;
    Ok(RootfsActionResult {
        operation: "apply".to_string(),
        success,
        message,
        details,
        status,
    })
}

async fn run_helper_apply(details: &mut Vec<String>) -> (bool, String) {
    match Command::new(ROOTFS_UPDATE_HELPER)
        .arg("apply")
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
                details.push(line.to_string());
            }
            if !stderr.is_empty() {
                details.push(format!("stderr: {}", stderr.trim()));
            }
            if output.status.success() {
                info!("rootfs: apply helper completed successfully");
                (
                    true,
                    "Rootfs update will be applied on next reboot.".to_string(),
                )
            } else {
                let code = output.status.code().unwrap_or(-1);
                warn!(exit_code = code, "rootfs: apply helper failed");
                (false, format!("Rootfs apply failed (exit {code})."))
            }
        }
        Err(err) => {
            let msg = format!("failed to run rootfs-update helper: {err}");
            warn!("{}", msg);
            details.push(msg.clone());
            (false, msg)
        }
    }
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

/// Revert to the previous known-good rootfs version.
///
/// Writes a rollback marker that the initramfs reads on the next boot to
/// select the previous version.
pub async fn rollback() -> Result<RootfsActionResult> {
    let _guard = operation_lock().lock().await;

    let mut details = Vec::new();

    let previous = read_meta(&previous_path());
    if previous.is_none() && !Path::new(ROOTFS_UPDATE_HELPER).exists() {
        let msg = "No previous rootfs version available for rollback.".to_string();
        warn!("{}", msg);
        let status = status().await;
        return Ok(RootfsActionResult {
            operation: "rollback".to_string(),
            success: false,
            message: msg,
            details,
            status,
        });
    }

    let (success, message) = if Path::new(ROOTFS_UPDATE_HELPER).exists() {
        run_helper_rollback(&mut details).await
    } else {
        // Fallback stub: write a rollback marker
        let rollback_path = state_dir().join("rollback");
        match std::fs::write(&rollback_path, Utc::now().to_rfc3339()) {
            Ok(()) => {
                let version = previous.as_ref().map(|m| m.version.as_str()).unwrap_or("previous");
                let msg = format!("Rollback to version {version} scheduled for next boot.");
                info!(version, "rootfs: rollback marker written");
                details.push(msg.clone());
                (true, msg)
            }
            Err(err) => {
                let msg = format!("failed to write rollback marker: {err}");
                warn!("{}", msg);
                (false, msg)
            }
        }
    };

    let status = status().await;
    Ok(RootfsActionResult {
        operation: "rollback".to_string(),
        success,
        message,
        details,
        status,
    })
}

async fn run_helper_rollback(details: &mut Vec<String>) -> (bool, String) {
    match Command::new(ROOTFS_UPDATE_HELPER)
        .arg("rollback")
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
                details.push(line.to_string());
            }
            if !stderr.is_empty() {
                details.push(format!("stderr: {}", stderr.trim()));
            }
            if output.status.success() {
                info!("rootfs: rollback helper completed successfully");
                (
                    true,
                    "Rootfs rollback to previous version scheduled for next boot.".to_string(),
                )
            } else {
                let code = output.status.code().unwrap_or(-1);
                warn!(exit_code = code, "rootfs: rollback helper failed");
                (false, format!("Rootfs rollback failed (exit {code})."))
            }
        }
        Err(err) => {
            let msg = format!("failed to run rootfs-update helper: {err}");
            warn!("{}", msg);
            details.push(msg.clone());
            (false, msg)
        }
    }
}

// ---------------------------------------------------------------------------
// Promote staged version (called by update.rs after staging)
// ---------------------------------------------------------------------------

/// Write the `pending.json` marker after the update orchestrator has
/// successfully staged a rootfs artifact.
pub fn mark_pending(version: &str, artifact_path: &Path, sha256: &str) -> Result<()> {
    let meta = RootfsVersionMeta {
        version: version.to_string(),
        artifact_path: Some(artifact_path.to_string_lossy().into_owned()),
        artifact_sha256: Some(sha256.to_string()),
        recorded_at: Utc::now().to_rfc3339(),
    };
    write_meta(&pending_path(), &meta)
        .with_context(|| "failed to write rootfs pending marker")?;
    info!(
        version,
        artifact = %artifact_path.display(),
        "rootfs: pending version marker written"
    );
    Ok(())
}

/// Write the `current.json` marker (used during initial provisioning or when
/// the appliance rebuild is acknowledged by the operator).
pub fn mark_current(version: &str) -> Result<()> {
    let meta = RootfsVersionMeta::new(version);
    write_meta(&current_path(), &meta)
        .with_context(|| "failed to write rootfs current marker")?;
    info!(version, "rootfs: current version marker written");
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rootfs_version_meta_roundtrips_json() {
        let meta = RootfsVersionMeta {
            version: "1.2.3".to_string(),
            artifact_path: Some("/var/lib/dayshield/rootfs-update/staging/rootfs-1.2.3.squashfs".to_string()),
            artifact_sha256: Some("abc123".to_string()),
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: RootfsVersionMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, "1.2.3");
        assert_eq!(back.artifact_sha256.as_deref(), Some("abc123"));
    }

    #[test]
    fn rootfs_update_status_serialises_without_slot_terminology() {
        let status = RootfsUpdateStatus {
            supported: true,
            checked_at: "2026-01-01T00:00:00Z".to_string(),
            current_version: Some("1.2.2".to_string()),
            available_version: Some("1.2.3".to_string()),
            pending_version: None,
            previous_version: Some("1.2.1".to_string()),
            update_available: true,
            reboot_required: false,
            rollback_available: true,
            recovery_active: false,
            transaction_state: RootfsTransactionState::Idle,
            last_error: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        // Confirm no A/B / slot / OSTree terminology leaks into the JSON
        assert!(!json.contains("slot"));
        assert!(!json.contains("ostree"));
        assert!(!json.contains("deployment"));
        assert!(json.contains("currentVersion"));
        assert!(json.contains("availableVersion"));
        assert!(json.contains("pendingVersion"));
        assert!(json.contains("previousVersion"));
    }

    #[test]
    fn rootfs_transaction_state_serialises_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&RootfsTransactionState::Idle).unwrap(),
            "\"idle\""
        );
        assert_eq!(
            serde_json::to_string(&RootfsTransactionState::Staging).unwrap(),
            "\"staging\""
        );
        assert_eq!(
            serde_json::to_string(&RootfsTransactionState::RollingBack).unwrap(),
            "\"rolling_back\""
        );
    }
}
