//! A/B image-based rootfs update orchestration.
//!
//! ## Model
//!
//! The disk is partitioned with two interchangeable root slots labelled
//! `DS_ROOT_A` and `DS_ROOT_B`.  At any moment exactly one slot is *current*
//! (the one we're booted from) and the other is *standby*.  Updates and
//! rollbacks both operate by writing to the standby slot and flipping which
//! slot GRUB boots next time.
//!
//! ## Files we read / write
//!
//! - `/var/lib/dayshield/rootfs-update/slots.json` — source of truth.  Records
//!   `currentSlot`, `currentVersion`, `standbySlot`, `standbyVersion`, last
//!   apply time, last successful boot time.
//! - `/var/lib/dayshield/rootfs-update/staging/*.squashfs` — downloaded but
//!   not yet applied images (kept until `apply` consumes them).
//! - `/var/lib/dayshield/rootfs-update/recovered` — written when an auto-revert
//!   occurred (so the UI can surface it).
//! - `/boot/grub/grubenv` — GRUB's environment file we manipulate with
//!   `grub-editenv` to set `saved_entry`, `boot_state`, `fallback_entry`,
//!   `boot_attempts_left`.
//!
//! ## Update flow
//!
//! 1. `download` (handled by `update.rs`) puts a verified squashfs at
//!    `staging/rootfs-vX.Y.Z.squashfs`.
//! 2. `apply()`:
//!    * Identifies the inactive slot from `slots.json`.
//!    * Formats the inactive partition (`mkfs.ext4 -L DS_ROOT_<slot>`).
//!    * Mounts it, `unsquashfs`'s the staged image into it, copies the new
//!      kernel + initrd from inside the slot's `/boot` to the shared BOOT
//!      partition under `/boot/dayshield/slot-<slot>/`.
//!    * Updates `slots.json` (standby becomes new version).
//!    * Writes grubenv: `saved_entry=ds_<new>`, `fallback_entry=ds_<old>`,
//!      `boot_state=trying`, `boot_attempts_left=3`.
//! 3. User reboots.
//! 4. GRUB boots the new slot.  Userspace eventually runs
//!    `dayshield-core signal-boot-success`, which writes
//!    `boot_state=confirmed`, unsets `boot_attempts_left`, and updates
//!    `slots.json` so the new slot is now `currentSlot`.
//! 5. If userspace fails to confirm within 3 boots, GRUB auto-falls-back to
//!    the previous slot, and the next `signal-boot-success` records the
//!    auto-revert.
//!
//! ## Rollback
//!
//! `rollback()` is symmetric to `apply()` minus the format/unsquashfs steps:
//! it just flips `saved_entry`/`fallback_entry` and reboots.  Recovery is
//! ~instant because the standby slot already contains a known-good rootfs.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
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

const SLOTS_FILE: &str = "/var/lib/dayshield/rootfs-update/slots.json";
const RECOVERED_MARKER: &str = "/var/lib/dayshield/rootfs-update/recovered";
const BOOT_SUCCESS_MARKER: &str = "/var/lib/dayshield/rootfs-update/boot-success";

const BOOT_PARTITION_MOUNT: &str = "/boot";
const BOOT_DAYSHIELD_DIR: &str = "/boot/dayshield";
const GRUBENV_FILE: &str = "/boot/grub/grubenv";

const ROOTFS_VERSION_FILE: &str = "/etc/dayshield/version";

const BOOT_ATTEMPT_LIMIT: u32 = 3;

// Active-slot tooling expects these binaries to be on PATH for the helper
// scripts dayshield-core invokes.  Documented here so it's easy to keep the
// rootfs build's package list in sync (squashfs-tools, util-linux, e2fsprogs).
const MKFS_BIN: &str = "mkfs.ext4";
const UNSQUASHFS_BIN: &str = "unsquashfs";
const GRUB_EDITENV_BIN: &str = "grub-editenv";

// ---------------------------------------------------------------------------
// Slots
// ---------------------------------------------------------------------------

/// Identifier for one of the two rootfs slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn as_str(self) -> &'static str {
        match self {
            Slot::A => "A",
            Slot::B => "B",
        }
    }

    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    /// Filesystem label of the partition for this slot.
    pub fn label(self) -> &'static str {
        match self {
            Slot::A => "DS_ROOT_A",
            Slot::B => "DS_ROOT_B",
        }
    }

    /// GRUB menuentry id.
    pub fn grub_entry_id(self) -> &'static str {
        match self {
            Slot::A => "ds_a",
            Slot::B => "ds_b",
        }
    }

    /// Directory under `/boot/dayshield/` holding this slot's kernel+initrd.
    pub fn boot_dir_name(self) -> &'static str {
        match self {
            Slot::A => "slot-a",
            Slot::B => "slot-b",
        }
    }
}

impl std::str::FromStr for Slot {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "A" => Ok(Slot::A),
            "B" => Ok(Slot::B),
            other => anyhow::bail!("invalid slot identifier: {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Slots state (persisted JSON)
// ---------------------------------------------------------------------------

/// On-disk slot state.  Single source of truth for which slot is current.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotsState {
    pub current_slot: Slot,
    pub current_version: String,
    pub standby_slot: Slot,
    pub standby_version: String,
    #[serde(default)]
    pub recorded_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_apply_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_boot_success_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_apply_started_at: Option<String>,
}

impl Default for SlotsState {
    fn default() -> Self {
        Self {
            current_slot: Slot::A,
            current_version: read_build_version().unwrap_or_else(|| "unknown".to_string()),
            standby_slot: Slot::B,
            standby_version: read_build_version().unwrap_or_else(|| "unknown".to_string()),
            recorded_at: Utc::now().to_rfc3339(),
            last_apply_at: None,
            last_boot_success_at: None,
            last_apply_started_at: None,
        }
    }
}

fn read_slots_state() -> Option<SlotsState> {
    let text = std::fs::read_to_string(SLOTS_FILE).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_slots_state(state: &SlotsState) -> Result<()> {
    if let Some(parent) = Path::new(SLOTS_FILE).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(state)?;
    std::fs::write(SLOTS_FILE, text).with_context(|| format!("failed to write {SLOTS_FILE}"))?;
    Ok(())
}

/// Best-effort load of current state, falling back to defaults if absent.
fn load_or_default_slots_state() -> SlotsState {
    if let Some(state) = read_slots_state() {
        return state;
    }
    let default = SlotsState::default();
    let _ = write_slots_state(&default);
    default
}

// ---------------------------------------------------------------------------
// Runtime detection — which slot are we actually running from?
// ---------------------------------------------------------------------------

/// Detect the running slot from the root partition's label at runtime.
/// Falls back to the persisted `currentSlot` value if the label can't be read.
pub fn detect_running_slot() -> Slot {
    if let Ok(output) = std::process::Command::new("findmnt")
        .args(["-n", "-o", "LABEL", "/"])
        .output()
    {
        if output.status.success() {
            let label = String::from_utf8_lossy(&output.stdout).trim().to_string();
            match label.as_str() {
                "DS_ROOT_A" => return Slot::A,
                "DS_ROOT_B" => return Slot::B,
                _ => {}
            }
        }
    }
    load_or_default_slots_state().current_slot
}

/// Read the build-stamped version from `/etc/dayshield/version`.
fn read_build_version() -> Option<String> {
    std::fs::read_to_string(ROOTFS_VERSION_FILE)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && v != "unknown" && v != "initial")
}

// ---------------------------------------------------------------------------
// Status (UI-facing)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RootfsTransactionState {
    #[default]
    Idle,
    Checking,
    Staging,
    Applying,
    RollingBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootfsUpdateStatus {
    pub supported: bool,
    pub checked_at: String,
    /// Slot we're currently running from (`"A"` or `"B"`).
    pub current_slot: String,
    pub current_version: Option<String>,
    /// Slot kept on standby (rollback target).
    pub standby_slot: String,
    pub standby_version: Option<String>,
    /// Latest version available from the GitHub release registry.
    pub available_version: Option<String>,
    pub update_available: bool,
    pub reboot_required: bool,
    pub rollback_available: bool,
    pub recovery_active: bool,
    pub transaction_state: RootfsTransactionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootfsActionResult {
    pub operation: String,
    pub success: bool,
    pub message: String,
    pub details: Vec<String>,
    pub status: RootfsUpdateStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootfsRebootState {
    pub reboot_required: bool,
    pub current_version: Option<String>,
    pub standby_version: Option<String>,
}

// ---------------------------------------------------------------------------
// In-process operation lock
// ---------------------------------------------------------------------------

static OPERATION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn operation_lock() -> &'static tokio::sync::Mutex<()> {
    OPERATION_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// Read the latest available rootfs version from the shared update state file.
fn read_available_version_from_state() -> Option<String> {
    let path = Path::new(crate::update::UPDATE_STATE_FILE_PATH);
    let text = std::fs::read_to_string(path).ok()?;
    let state: crate::update::UpdateStateFile = serde_json::from_str(&text).ok()?;
    state
        .components
        .iter()
        .find(|c| c.component == "rootfs")
        .and_then(|c| c.remote_version.clone())
}

/// Current rootfs update status for the UI.
pub async fn status() -> RootfsUpdateStatus {
    let now = Utc::now().to_rfc3339();

    let state = load_or_default_slots_state();
    let running_slot = detect_running_slot();

    // If the disk says we're on slot X but state file says Y, trust the disk
    // (we may have auto-reverted).  Don't write back here — signal_boot_success
    // handles state reconciliation.
    let current_slot = running_slot;
    let current_version = if running_slot == state.current_slot {
        Some(state.current_version.clone())
    } else if running_slot == state.standby_slot {
        Some(state.standby_version.clone())
    } else {
        read_build_version()
    }
    .filter(|v| !v.is_empty() && v != "unknown");

    let standby_slot = current_slot.other();
    let standby_version = if standby_slot == state.standby_slot {
        Some(state.standby_version.clone())
    } else {
        Some(state.current_version.clone())
    }
    .filter(|v| !v.is_empty() && v != "unknown");

    let available_version = read_available_version_from_state();
    let update_available = match (&current_version, &available_version) {
        (Some(cur), Some(avail)) => crate::update::is_remote_version_newer(cur, avail),
        (None, Some(_)) => true,
        _ => false,
    };

    let reboot_required = grubenv_get("boot_state").await.as_deref() == Some("trying");
    let rollback_available = standby_version.is_some();
    let recovery_active = Path::new(RECOVERED_MARKER).exists();

    let supported = which(MKFS_BIN).is_some()
        && which(UNSQUASHFS_BIN).is_some()
        && which(GRUB_EDITENV_BIN).is_some()
        && Path::new(GRUBENV_FILE).exists();

    let tx_state = if operation_lock().try_lock().is_err() {
        RootfsTransactionState::Applying
    } else {
        RootfsTransactionState::Idle
    };

    RootfsUpdateStatus {
        supported,
        checked_at: now,
        current_slot: current_slot.as_str().to_string(),
        current_version,
        standby_slot: standby_slot.as_str().to_string(),
        standby_version,
        available_version,
        update_available,
        reboot_required,
        rollback_available,
        recovery_active,
        transaction_state: tx_state,
        last_error: None,
    }
}

pub async fn reboot_state() -> RootfsRebootState {
    let s = load_or_default_slots_state();
    let reboot_required = grubenv_get("boot_state").await.as_deref() == Some("trying");
    RootfsRebootState {
        reboot_required,
        current_version: Some(s.current_version),
        standby_version: Some(s.standby_version),
    }
}

pub fn reboot_state_sync() -> bool {
    // Best-effort sync probe — used from synchronous contexts.
    let runtime = tokio::runtime::Handle::try_current();
    if let Ok(rt) = runtime {
        rt.block_on(async { grubenv_get("boot_state").await.as_deref() == Some("trying") })
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// grubenv helpers
// ---------------------------------------------------------------------------

async fn grubenv_get(key: &str) -> Option<String> {
    let output = Command::new(GRUB_EDITENV_BIN)
        .arg(GRUBENV_FILE)
        .arg("list")
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}=")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

async fn grubenv_set(key: &str, value: &str) -> Result<()> {
    let status = Command::new(GRUB_EDITENV_BIN)
        .arg(GRUBENV_FILE)
        .arg("set")
        .arg(format!("{key}={value}"))
        .status()
        .await
        .with_context(|| format!("failed to spawn {GRUB_EDITENV_BIN}"))?;
    if !status.success() {
        anyhow::bail!("grub-editenv set {key}={value} failed");
    }
    Ok(())
}

async fn grubenv_unset(key: &str) -> Result<()> {
    // unset is allowed to fail (key may not exist) — swallow the error.
    let _ = Command::new(GRUB_EDITENV_BIN)
        .arg(GRUBENV_FILE)
        .arg("unset")
        .arg(key)
        .status()
        .await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Path resolvers (slot device + boot dir)
// ---------------------------------------------------------------------------

async fn slot_device(slot: Slot) -> Result<PathBuf> {
    let output = Command::new("blkid")
        .args(["-L", slot.label()])
        .output()
        .await
        .with_context(|| "failed to spawn blkid")?;
    if !output.status.success() {
        anyhow::bail!(
            "blkid -L {} returned no device — is the slot's partition formatted with that label?",
            slot.label()
        );
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        anyhow::bail!("no device found for label {}", slot.label());
    }
    Ok(PathBuf::from(path))
}

fn slot_boot_dir(slot: Slot) -> PathBuf {
    Path::new(BOOT_DAYSHIELD_DIR).join(slot.boot_dir_name())
}

// ---------------------------------------------------------------------------
// Apply — write the staged squashfs to the inactive slot and arm GRUB
// ---------------------------------------------------------------------------

/// Apply the staged rootfs squashfs at `staged_image_path` to the inactive
/// slot.  Called from `update.rs` after the download + verify step.
pub async fn apply_staged_image(
    staged_image_path: &Path,
    version: &str,
) -> Result<RootfsActionResult> {
    let _guard = operation_lock().lock().await;

    let mut details = Vec::new();
    let started = Utc::now().to_rfc3339();

    let mut slots = load_or_default_slots_state();
    let running_slot = detect_running_slot();
    // Always target the slot we are NOT running on, regardless of what
    // slots.json claims — the disk is the source of truth for `current`.
    let target_slot = running_slot.other();
    details.push(format!(
        "running slot is {} — writing update to slot {}",
        running_slot.as_str(),
        target_slot.as_str()
    ));

    slots.last_apply_started_at = Some(started.clone());
    let _ = write_slots_state(&slots);

    let target_dev = slot_device(target_slot)
        .await
        .with_context(|| "failed to resolve target slot device")?;
    details.push(format!("target partition: {}", target_dev.display()));

    // ── Safety checks before we destructively format the target ────────────

    // 1. The target slot device must NOT be the same as the running root.
    //    This guards against single-rootfs installs (no A/B layout on disk)
    //    where both labels could end up pointing at the same partition.
    let running_dev = running_root_device().await.unwrap_or_default();
    if !running_dev.as_os_str().is_empty() && running_dev == target_dev {
        anyhow::bail!(
            "target slot device {} is the running root partition — \
             this system does not appear to have an A/B partition layout. \
             Reinstall from a current DayShield ISO (which creates DS_ROOT_A and DS_ROOT_B) \
             before in-place rootfs updates can work.",
            target_dev.display()
        );
    }

    // 2. The target slot device must not be currently mounted anywhere.
    //    mkfs.ext4 refuses to format mounted filesystems for obvious reasons,
    //    but the user-facing error is much clearer if we catch this ourselves.
    if let Some(mp) = device_mountpoint(&target_dev).await {
        anyhow::bail!(
            "target slot device {} is currently mounted at {}. \
             Refusing to format. (This usually means the system was installed \
             with a non-A/B layout; reinstall from a current DayShield ISO.)",
            target_dev.display(),
            mp.display()
        );
    }

    // ── Format the target partition fresh ─────────────────────────────────
    info!(
        slot = target_slot.as_str(),
        "rootfs: formatting target slot"
    );
    run_status(
        Command::new(MKFS_BIN)
            .args(["-F", "-L", target_slot.label()])
            .arg(&target_dev),
        "mkfs.ext4",
    )
    .await
    .with_context(|| {
        format!(
            "failed to format {} as {}",
            target_dev.display(),
            target_slot.label()
        )
    })?;
    details.push(format!(
        "formatted {} as ext4 with label {}",
        target_dev.display(),
        target_slot.label()
    ));

    // ── Mount and unsquashfs ──────────────────────────────────────────────
    let mount_dir = tempfile::tempdir().with_context(|| "failed to create temp mount dir")?;
    let mount_path = mount_dir.path();

    run_status(
        Command::new("mount")
            .args(["-t", "ext4"])
            .arg(&target_dev)
            .arg(mount_path),
        "mount",
    )
    .await
    .with_context(|| {
        format!(
            "failed to mount {} at {}",
            target_dev.display(),
            mount_path.display()
        )
    })?;

    // Use a guard so we umount even on early-return.
    let mount_guard = MountGuard(mount_path.to_path_buf());

    info!(
        slot = target_slot.as_str(),
        image = %staged_image_path.display(),
        "rootfs: extracting squashfs to target slot"
    );
    run_status(
        Command::new(UNSQUASHFS_BIN)
            .arg("-f")
            .arg("-d")
            .arg(mount_path)
            .arg(staged_image_path),
        "unsquashfs",
    )
    .await
    .with_context(|| "unsquashfs failed")?;
    details.push(format!(
        "unsquashfs'd {} to slot {}",
        staged_image_path.display(),
        target_slot.as_str()
    ));

    // ── Preserve identity / admin state into the new slot ─────────────────
    // The squashfs ships build-time defaults for these paths.  We need the
    // running system's values to survive the slot switch (root password, SSH
    // host identity, hostname, timezone, fstab UUIDs, network config,
    // DayShield admin credentials & certificates, etc.) — otherwise the new
    // slot boots with a default password and the user loses everything.
    //
    // `/var` is shared between slots and is NOT touched here.
    let preserved = copy_identity_files_to_slot(mount_path, &mut details).await;
    details.push(format!("preserved {preserved} identity files/directories"));

    // ── Copy the new kernel + initrd to /boot/dayshield/slot-X/ ───────────
    // The slot's own /boot directory (visible at mount_path/boot) holds the
    // kernel installed alongside the new rootfs.  Copy the highest-versioned
    // vmlinuz-* and initrd.img-* into the shared BOOT partition under
    // /boot/dayshield/slot-<target>/{vmlinuz,initrd.img} so GRUB can find them.
    let kernel_src = pick_latest_with_prefix(&mount_path.join("boot"), "vmlinuz-")?;
    let initrd_src = pick_latest_with_prefix(&mount_path.join("boot"), "initrd.img-")?;

    let dest_dir = slot_boot_dir(target_slot);
    std::fs::create_dir_all(&dest_dir)
        .with_context(|| format!("failed to create {}", dest_dir.display()))?;

    std::fs::copy(&kernel_src, dest_dir.join("vmlinuz"))
        .with_context(|| "failed to stage kernel into BOOT partition")?;
    std::fs::copy(&initrd_src, dest_dir.join("initrd.img"))
        .with_context(|| "failed to stage initrd into BOOT partition")?;
    details.push(format!(
        "staged {} and {} under {}",
        kernel_src.file_name().unwrap_or_default().to_string_lossy(),
        initrd_src.file_name().unwrap_or_default().to_string_lossy(),
        dest_dir.display()
    ));

    // ── Sync and unmount ──────────────────────────────────────────────────
    let _ = Command::new("sync").status().await;
    drop(mount_guard); // umount

    // ── Update slots.json (standby is now the new version) ────────────────
    let now = Utc::now().to_rfc3339();
    slots.standby_slot = target_slot;
    slots.standby_version = version.to_string();
    slots.current_slot = running_slot;
    slots.last_apply_at = Some(now.clone());
    slots.recorded_at = now;
    write_slots_state(&slots).context("failed to persist slot state")?;

    // ── Flip GRUB to boot the new slot, on probation ──────────────────────
    grubenv_set("saved_entry", target_slot.grub_entry_id()).await?;
    grubenv_set("fallback_entry", running_slot.grub_entry_id()).await?;
    grubenv_set("boot_state", "trying").await?;
    grubenv_set("boot_attempts_left", &BOOT_ATTEMPT_LIMIT.to_string()).await?;
    details.push(format!(
        "grubenv: saved_entry={}, fallback_entry={}, boot_state=trying, boot_attempts_left={}",
        target_slot.grub_entry_id(),
        running_slot.grub_entry_id(),
        BOOT_ATTEMPT_LIMIT
    ));

    // Remove any stale recovered marker (a successful apply supersedes it).
    let _ = std::fs::remove_file(RECOVERED_MARKER);

    info!(
        slot = target_slot.as_str(),
        version, "rootfs: update applied; reboot required"
    );

    let status = status().await;
    Ok(RootfsActionResult {
        operation: "apply".to_string(),
        success: true,
        message: format!(
            "Update {version} written to slot {}.  Reboot to activate.",
            target_slot.as_str()
        ),
        details,
        status,
    })
}

// ---------------------------------------------------------------------------
// Rollback — flip GRUB to the standby slot (no rsync, no extraction)
// ---------------------------------------------------------------------------

pub async fn rollback() -> Result<RootfsActionResult> {
    let _guard = operation_lock().lock().await;

    let mut details = Vec::new();
    let mut slots = load_or_default_slots_state();
    let running_slot = detect_running_slot();
    let target_slot = running_slot.other();

    // The standby slot must hold a populated, bootable rootfs.  If standby_version
    // is unknown we still try — both slots were installed identically on day 1.
    grubenv_set("saved_entry", target_slot.grub_entry_id()).await?;
    grubenv_set("fallback_entry", running_slot.grub_entry_id()).await?;
    grubenv_set("boot_state", "trying").await?;
    grubenv_set("boot_attempts_left", &BOOT_ATTEMPT_LIMIT.to_string()).await?;

    details.push(format!(
        "grubenv: saved_entry={}, fallback_entry={}, boot_state=trying, boot_attempts_left={}",
        target_slot.grub_entry_id(),
        running_slot.grub_entry_id(),
        BOOT_ATTEMPT_LIMIT
    ));

    let now = Utc::now().to_rfc3339();
    slots.last_apply_at = Some(now.clone());
    slots.recorded_at = now;
    let _ = write_slots_state(&slots);

    info!(
        target = target_slot.as_str(),
        "rootfs: rollback armed; reboot to activate standby slot"
    );

    let status = status().await;
    Ok(RootfsActionResult {
        operation: "rollback".to_string(),
        success: true,
        message: format!(
            "Rollback to slot {} armed.  Reboot to activate.",
            target_slot.as_str()
        ),
        details,
        status,
    })
}

// ---------------------------------------------------------------------------
// signal_boot_success — called by the systemd unit after a healthy boot
// ---------------------------------------------------------------------------

/// Confirm the current boot is healthy.
///
/// - Clears the GRUB probation state (`boot_state=confirmed`,
///   unset `boot_attempts_left`, unset `fallback_entry`).
/// - Updates `slots.json` so `currentSlot` matches the slot we actually
///   booted from (this handles both normal apply success AND auto-revert).
/// - On auto-revert, writes the `recovered` marker so the UI can surface it.
pub async fn signal_boot_success() -> Result<()> {
    use std::process::Command as SyncCommand;

    let running_slot = detect_running_slot();
    let mut slots = load_or_default_slots_state();

    let running_version = read_build_version().unwrap_or_else(|| {
        // Fall back to whichever side of slots.json matches the running slot.
        if running_slot == slots.current_slot {
            slots.current_version.clone()
        } else {
            slots.standby_version.clone()
        }
    });

    // Detect auto-revert: GRUB armed `trying`, but the slot we actually booted
    // is the previous (fallback) one — meaning the boot of the new slot failed
    // 3 times and GRUB redirected us back.
    let saved_entry = sync_grubenv_get("saved_entry");
    let boot_state = sync_grubenv_get("boot_state");
    let auto_reverted = boot_state.as_deref() == Some("trying")
        && saved_entry.as_deref() == Some(running_slot.other().grub_entry_id());

    if auto_reverted {
        let failed_slot = running_slot.other();
        warn!(
            failed_slot = failed_slot.as_str(),
            running_slot = running_slot.as_str(),
            "rootfs: auto-revert detected — failed slot will be the standby; UI will surface recovery"
        );

        // Record the recovery so the UI can show "Update X failed, reverted to Y".
        let _ = std::fs::create_dir_all(Path::new(ROOTFS_UPDATE_STATE_DIR));
        let _ = std::fs::write(
            RECOVERED_MARKER,
            serde_json::to_string_pretty(&serde_json::json!({
                "failedSlot": failed_slot.as_str(),
                "failedVersion": slots.standby_version,
                "revertedTo": running_slot.as_str(),
                "recoveredAt": Utc::now().to_rfc3339(),
            }))
            .unwrap_or_else(|_| String::from("{}")),
        );
    } else {
        let _ = std::fs::remove_file(RECOVERED_MARKER);
    }

    // Clear probation.
    let _ = SyncCommand::new(GRUB_EDITENV_BIN)
        .args([GRUBENV_FILE, "set"])
        .arg(format!("saved_entry={}", running_slot.grub_entry_id()))
        .status();
    let _ = SyncCommand::new(GRUB_EDITENV_BIN)
        .args([GRUBENV_FILE, "set", "boot_state=confirmed"])
        .status();
    let _ = SyncCommand::new(GRUB_EDITENV_BIN)
        .args([GRUBENV_FILE, "unset", "boot_attempts_left"])
        .status();
    let _ = SyncCommand::new(GRUB_EDITENV_BIN)
        .args([GRUBENV_FILE, "unset", "fallback_entry"])
        .status();

    // Reconcile slots.json so currentSlot reflects reality.
    let other_version = if running_slot == slots.current_slot {
        slots.standby_version.clone()
    } else {
        slots.current_version.clone()
    };
    slots.current_slot = running_slot;
    slots.current_version = running_version;
    slots.standby_slot = running_slot.other();
    slots.standby_version = other_version;
    slots.last_boot_success_at = Some(Utc::now().to_rfc3339());
    slots.recorded_at = Utc::now().to_rfc3339();
    write_slots_state(&slots)?;

    // Boot-success marker for anything watching.
    let _ = std::fs::write(BOOT_SUCCESS_MARKER, Utc::now().to_rfc3339());

    info!(
        slot = running_slot.as_str(),
        auto_reverted, "rootfs: boot success confirmed"
    );

    // Mirror identity files (root password, ssh host keys, network, etc.)
    // from the just-confirmed slot back into the standby slot.  This closes
    // the rollback gap: without it, a password change made between
    // apply-update and signal-boot-success would be lost on any future
    // rollback because the standby slot still holds the pre-update copies.
    //
    // Skipped when we got here via auto-revert — the standby slot is the
    // one that just failed to boot, and we have no reason to push the
    // running slot's state into it (the operator will repair or reapply).
    if !auto_reverted {
        if let Err(err) = sync_identity_to_standby(running_slot.other()).await {
            // Don't fail boot-success on a sync error — the boot itself
            // is healthy; log and let the operator retry from the CLI
            // with `dayshield-core rootfs-sync-identity`.
            warn!(
                error = %err,
                "rootfs: failed to mirror identity files to standby slot — rollback may lose recent credential changes"
            );
        }
    }

    Ok(())
}

/// Mount the standby slot's root partition at a temporary directory, copy the
/// IDENTITY_PATHS files from the running slot into it, then unmount.  Used by
/// `signal_boot_success` to keep both slots' user-database / host-keys /
/// network state in sync so rollback never silently loses recent changes.
pub async fn sync_identity_to_standby(standby_slot: Slot) -> Result<()> {
    let device = slot_device(standby_slot).await?;

    let running = running_root_device().await;
    if running.as_deref() == Some(device.as_path()) {
        anyhow::bail!(
            "refusing to sync identity into {} - it is the running root partition",
            device.display()
        );
    }
    if let Some(mp) = device_mountpoint(&device).await {
        anyhow::bail!(
            "standby slot device {} is already mounted at {} - refusing to sync",
            device.display(),
            mp.display()
        );
    }

    let mount_dir =
        tempfile::tempdir().context("failed to create scratch mount dir for identity sync")?;
    let mount_path = mount_dir.path();

    run_status(
        Command::new("mount").arg(&device).arg(mount_path),
        "mount standby slot for identity sync",
    )
    .await?;

    let mut details: Vec<String> = Vec::new();
    let count = copy_identity_files_to_slot(mount_path, &mut details).await;

    let umount_result = run_status(
        Command::new("umount").arg(mount_path),
        "umount standby slot",
    )
    .await;

    info!(
        slot = standby_slot.as_str(),
        copied = count,
        "rootfs: mirrored identity files to standby slot"
    );
    for line in &details {
        info!(target: "rootfs::sync_identity", "{}", line);
    }

    umount_result
}

fn sync_grubenv_get(key: &str) -> Option<String> {
    use std::process::Command as SyncCommand;
    let output = SyncCommand::new(GRUB_EDITENV_BIN)
        .arg(GRUBENV_FILE)
        .arg("list")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}=")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Subprocess helpers
// ---------------------------------------------------------------------------

async fn run_status(cmd: &mut Command, label: &str) -> Result<()> {
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("failed to spawn {label}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "?".to_string());
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("{label} exited with status {}", output.status)
        };
        anyhow::bail!("{label} failed (exit {code}): {detail}");
    }
    Ok(())
}

/// Block device underlying `/`, e.g. `/dev/sda4`.  Used to verify the target
/// slot is NOT the currently-running root partition.
async fn running_root_device() -> Option<PathBuf> {
    let output = Command::new("findmnt")
        .args(["-n", "-o", "SOURCE", "/"])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// Paths under `/` that must survive a rootfs update.  Sourced from the
/// running rootfs (`/etc/...`) and copied into the new slot mount.  Anything
/// listed here overrides the squashfs's build-time default.
///
/// `/var` is shared between slots and never touched.
const IDENTITY_PATHS: &[&str] = &[
    // Mount layout — installer's UUIDs/labels for this specific disk.
    "/etc/fstab",
    // Persistent identity.
    "/etc/machine-id",
    "/etc/hostname",
    "/etc/hosts",
    // User database — root password.
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/passwd",
    "/etc/passwd-",
    "/etc/group",
    "/etc/group-",
    "/etc/subuid",
    "/etc/subgid",
    "/etc/sudoers",
    "/etc/sudoers.d",
    // Locale & time.
    "/etc/timezone",
    "/etc/localtime",
    "/etc/locale.conf",
    "/etc/default/locale",
    "/etc/default/keyboard",
    // SSH server identity (host keys generated on first boot).
    "/etc/ssh/sshd_config",
    // NOTE: DayShield's persistent config (admin.json, config.json, certs/,
    // session.key, etc.) lives on /var/lib/dayshield/ which is on the shared
    // STATE partition — it is NOT touched by the rsync, so we do not need to
    // copy it across slots here.
    //
    // Network & services that DayShield and the installer write to.
    "/etc/systemd/network",
    "/etc/netplan",
    "/etc/network",
    "/etc/dhcp",
    "/etc/NetworkManager/system-connections",
    "/etc/systemd/timesyncd.conf",
    "/etc/chrony/chrony.conf",
    "/etc/nftables.d",
    "/etc/wireguard",
    "/etc/letsencrypt",
    "/etc/kea",
    "/etc/cloudflared",
    "/etc/crowdsec",
    "/etc/suricata",
    "/etc/ppp",
    // GRUB user overrides.
    "/etc/default/grub",
];

/// Copy each identity path from the running rootfs into `slot_root`.
/// Returns the number of paths successfully copied.
async fn copy_identity_files_to_slot(slot_root: &Path, details: &mut Vec<String>) -> usize {
    let mut count = 0usize;
    for src_rel in IDENTITY_PATHS {
        // src_rel starts with /, so we use trim_start_matches to avoid Path
        // join eating the rest.
        let trimmed = src_rel.trim_start_matches('/');
        let src = Path::new("/").join(trimmed);
        let dst = slot_root.join(trimmed);

        // Skip when source doesn't exist (not applicable on this install).
        if !src.exists() && !src.is_symlink() {
            continue;
        }
        if let Some(parent) = dst.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                details.push(format!(
                    "skip {}: failed to create {}: {err}",
                    src.display(),
                    parent.display()
                ));
                continue;
            }
        }
        // For directories use cp -a; for files copy with permissions.
        let result = if src.is_dir() {
            tokio::process::Command::new("cp")
                .args(["-a", "--no-target-directory"])
                .arg(&src)
                .arg(&dst)
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false)
        } else {
            tokio::process::Command::new("cp")
                .args(["-a"])
                .arg(&src)
                .arg(&dst)
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        if result {
            count += 1;
        } else {
            details.push(format!("warning: failed to preserve {}", src.display()));
        }
    }

    // SSH host keys: match the glob /etc/ssh/ssh_host_* (key + .pub pairs).
    if let Ok(entries) = std::fs::read_dir("/etc/ssh") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("ssh_host_") {
                let dst = slot_root.join("etc/ssh").join(name);
                let _ = std::fs::create_dir_all(dst.parent().unwrap());
                let ok = tokio::process::Command::new("cp")
                    .args(["-a"])
                    .arg(entry.path())
                    .arg(&dst)
                    .output()
                    .await
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if ok {
                    count += 1;
                }
            }
        }
    }

    count
}

/// If the device is currently mounted, return its mount point.
async fn device_mountpoint(dev: &Path) -> Option<PathBuf> {
    let output = Command::new("findmnt")
        .args(["-n", "-o", "TARGET", "--source"])
        .arg(dev)
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn pick_latest_with_prefix(dir: &Path, prefix: &str) -> Result<PathBuf> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(prefix))
                .unwrap_or(false)
        })
        .collect();
    if entries.is_empty() {
        anyhow::bail!("no file matching {prefix}* found in {}", dir.display());
    }
    entries.sort();
    Ok(entries.into_iter().last().unwrap())
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for p in std::env::split_paths(&path) {
        let candidate = p.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

struct MountGuard(PathBuf);

impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new("umount").arg(&self.0).status();
    }
}

// ---------------------------------------------------------------------------
// Helper used by /system/rootfs/apply endpoint when the user has staged via
// the older "stage then apply" flow.  Looks for the most recent squashfs in
// the staging dir and applies it.
// ---------------------------------------------------------------------------

pub async fn apply_update() -> Result<RootfsActionResult> {
    let staging = Path::new(ROOTFS_UPDATE_STAGING_DIR);
    if !staging.exists() {
        anyhow::bail!("no staged rootfs image (staging dir does not exist)");
    }
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(staging)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("squashfs"))
        .collect();
    candidates.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    let staged = candidates.into_iter().last().ok_or_else(|| {
        anyhow::anyhow!("no staged rootfs squashfs found in {ROOTFS_UPDATE_STAGING_DIR}")
    })?;
    let version = crate::update::artifact_version_from_name(
        "rootfs",
        staged.file_name().and_then(|n| n.to_str()).unwrap_or(""),
    )
    .unwrap_or_else(|| "unknown".to_string());

    // Checkpoint the current configuration so it can be restored alongside a
    // rootfs rollback. Best-effort: never block the update on history failure.
    if let Err(e) =
        crate::config::ConfigStore::new().snapshot(&format!("Before rootfs update to {version}"))
    {
        tracing::warn!(error = %e, "failed to snapshot config before rootfs update");
    }

    apply_staged_image(&staged, &version).await
}

pub async fn stage_update() -> Result<RootfsActionResult> {
    // Stage is implicit — `update.rs` writes the squashfs into the staging dir
    // during the download step.  Expose a no-op endpoint for UI compatibility.
    let status = status().await;
    Ok(RootfsActionResult {
        operation: "stage".to_string(),
        success: true,
        message: "Stage is performed implicitly during download; nothing to do.".to_string(),
        details: vec![],
        status,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_round_trip() {
        assert_eq!(Slot::A.as_str(), "A");
        assert_eq!(Slot::B.other(), Slot::A);
        assert_eq!(Slot::A.other().other(), Slot::A);
        assert_eq!("a".parse::<Slot>().unwrap(), Slot::A);
        assert_eq!("B".parse::<Slot>().unwrap(), Slot::B);
        assert!("Q".parse::<Slot>().is_err());
    }

    #[test]
    fn slot_labels_match_partitions() {
        assert_eq!(Slot::A.label(), "DS_ROOT_A");
        assert_eq!(Slot::B.label(), "DS_ROOT_B");
        assert_eq!(Slot::A.grub_entry_id(), "ds_a");
        assert_eq!(Slot::B.grub_entry_id(), "ds_b");
        assert_eq!(Slot::A.boot_dir_name(), "slot-a");
        assert_eq!(Slot::B.boot_dir_name(), "slot-b");
    }

    #[test]
    fn slots_state_round_trips_json() {
        let s = SlotsState {
            current_slot: Slot::B,
            current_version: "1.2.3".into(),
            standby_slot: Slot::A,
            standby_version: "1.2.2".into(),
            recorded_at: "2026-01-01T00:00:00Z".into(),
            last_apply_at: Some("2026-01-01T00:00:00Z".into()),
            last_boot_success_at: None,
            last_apply_started_at: None,
        };
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("\"currentSlot\":\"B\""));
        assert!(j.contains("\"standbySlot\":\"A\""));
        let back: SlotsState = serde_json::from_str(&j).unwrap();
        assert_eq!(back.current_slot, Slot::B);
        assert_eq!(back.standby_version, "1.2.2");
    }

    #[test]
    fn rootfs_transaction_state_snake_case() {
        assert_eq!(
            serde_json::to_string(&RootfsTransactionState::Idle).unwrap(),
            "\"idle\""
        );
        assert_eq!(
            serde_json::to_string(&RootfsTransactionState::RollingBack).unwrap(),
            "\"rolling_back\""
        );
    }

    #[test]
    fn identity_paths_preserve_network_boot_config() {
        for path in [
            "/etc/systemd/network",
            "/etc/netplan",
            "/etc/network",
            "/etc/dhcp",
            "/etc/NetworkManager/system-connections",
        ] {
            assert!(
                IDENTITY_PATHS.contains(&path),
                "{path} must survive A/B rootfs updates"
            );
        }
    }
}
