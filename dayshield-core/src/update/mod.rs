use std::{
    env,
    fs,
    path::{Path, PathBuf},
    process::Command as StdCommand,
    sync::OnceLock,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chrono::{Datelike, Duration as ChronoDuration, Local, NaiveTime, Timelike, Utc};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue, USER_AGENT, HeaderName};
use serde::{Deserialize, Serialize};
use tokio::{process::Command, sync::Mutex};
use tracing::{info, warn};

use crate::backup::{
    create::{create_backup, DEFAULT_BACKUP_DIR},
    model::{BackupType, Subsystem},
    restore::restore_backup,
};
use crate::state::AppState;

const SETTINGS_FILE: &str = "updates_settings.json";
const STATE_FILE: &str = "updates_state.json";
const DEFAULT_CORE_URL: &str = "https://github.com/daygle/dayshield-core";
const DEFAULT_UI_URL: &str = "https://github.com/daygle/dayshield-ui";
const DEFAULT_ROOTFS_URL: &str = "https://github.com/daygle/dayshield-rootfs";
const RUNTIME_MARKER_DIR: &str = "/var/lib/dayshield/update";
const RUNTIME_ROLLBACK_DIR: &str = "/var/lib/dayshield/update/rollback";
const DEFAULT_TRUSTED_SIGNERS_FILE: &str = "/etc/dayshield/update_trusted_signers";
const ARTIFACT_STAGING_DIR: &str = "/var/lib/dayshield/update-staging";
const UPDATE_BACKUP_KEY_FILE: &str = "update_backup_key";
const ROOTFS_SLOT_A_LABEL: &str = "DAYSHIELD_ROOT_A";
const ROOTFS_SLOT_B_LABEL: &str = "DAYSHIELD_ROOT_B";
const ROOTFS_BOOT_LABEL: &str = "DAYSHIELD_BOOT";
const ROOTFS_SLOT_MOUNT_DIR: &str = "/var/lib/dayshield/update/rootfs-slot";
const ROOTFS_BOOT_SLOT_DIR: &str = "/boot/dayshield";
const ROOTFS_GRUB_SCRIPT: &str = "/etc/grub.d/09_dayshield_ab";
const ROOTFS_GRUB_ENTRY_PREFIX: &str = "dayshield-";
const ROOTFS_ISO_UPGRADE_MARKER: &str = "rootfs-iso-upgrade.json";
const ROOTFS_BOOT_CONFIRM_DELAY_SECS: u64 = 90;
/// GitHub Releases repository: https://github.com/daygle/dayshield-core
/// Artifacts are attached to releases as: core-v1.2.3.tar.zst, ui-v1.2.3.tar.zst, etc.
const DEFAULT_REGISTRY_URL: &str = "https://api.github.com/repos/daygle/dayshield-core";
const DEFAULT_UPDATE_MODE: &str = "registry";

fn default_core_repo_path() -> String {
    env::var("DAYSHIELD_UPDATE_CORE_PATH").unwrap_or_else(|_| "/opt/dayshield-core".to_string())
}

fn default_ui_repo_path() -> String {
    env::var("DAYSHIELD_UPDATE_UI_PATH").unwrap_or_else(|_| "/opt/dayshield-ui".to_string())
}

fn default_rootfs_repo_path() -> String {
    env::var("DAYSHIELD_UPDATE_ROOTFS_PATH").unwrap_or_else(|_| "/opt/dayshield-rootfs".to_string())
}

fn default_core_repo_url() -> String {
    env::var("DAYSHIELD_UPDATE_CORE_URL").unwrap_or_else(|_| DEFAULT_CORE_URL.to_string())
}

fn default_ui_repo_url() -> String {
    env::var("DAYSHIELD_UPDATE_UI_URL").unwrap_or_else(|_| DEFAULT_UI_URL.to_string())
}

fn default_rootfs_repo_url() -> String {
    env::var("DAYSHIELD_UPDATE_ROOTFS_URL").unwrap_or_else(|_| DEFAULT_ROOTFS_URL.to_string())
}

fn default_branch() -> String {
    "main".to_string()
}

fn default_auto_check_enabled() -> bool {
    true
}

fn default_check_interval_minutes() -> u64 {
    1440
}

fn default_reboot_required_after_apply() -> bool {
    false
}

fn default_deploy_runtime_after_apply() -> bool {
    true
}

fn default_require_signed_commits() -> bool {
    false
}

fn default_verify_rootfs_manifest() -> bool {
    true
}

fn default_trusted_signers_file() -> String {
    DEFAULT_TRUSTED_SIGNERS_FILE.to_string()
}

fn default_bootstrap_missing_rootfs_repo() -> bool {
    true
}

fn default_registry_url() -> String {
    env::var("DAYSHIELD_UPDATE_REGISTRY_URL")
        .unwrap_or_else(|_| DEFAULT_REGISTRY_URL.to_string())
}

fn default_update_mode() -> String {
    env::var("DAYSHIELD_UPDATE_MODE").unwrap_or_else(|_| DEFAULT_UPDATE_MODE.to_string())
}

fn default_auto_check_frequency() -> UpdateAutoCheckFrequency {
    UpdateAutoCheckFrequency::Daily
}

fn default_auto_check_time() -> String {
    "03:00".to_string()
}

fn default_auto_check_weekday() -> UpdateWeekday {
    UpdateWeekday::Monday
}

fn default_auto_check_month_days() -> Vec<u8> {
    vec![1]
}

fn default_verify_artifact_signatures() -> bool {
    true
}

fn default_encrypt_update_config_backups() -> bool {
    false
}

fn default_enable_rootfs_ab_updates() -> bool {
    true
}

fn parse_auto_check_time(value: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(value.trim(), "%H:%M").ok()
}

fn normalize_auto_check_month_days(days: Vec<u8>) -> Vec<u8> {
    let has_first = days.contains(&1);
    let has_last = days.contains(&31);

    if has_last {
        vec![31]
    } else if has_first {
        vec![1]
    } else {
        default_auto_check_month_days()
    }
}

fn last_day_of_month(year: i32, month: u32) -> Option<u32> {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };

    let first_of_next_month = chrono::NaiveDate::from_ymd_opt(next_year, next_month, 1)?;
    let last_of_month = first_of_next_month - ChronoDuration::days(1);
    Some(last_of_month.day())
}

fn normalize_auto_check_time(value: &str) -> String {
    if parse_auto_check_time(value).is_some() {
        value.trim().to_string()
    } else {
        default_auto_check_time()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UpdateAutoCheckFrequency {
    Daily,
    Weekly,
    Monthly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UpdateWeekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl UpdateWeekday {
    fn matches(self, weekday: chrono::Weekday) -> bool {
        matches!(
            (self, weekday),
            (UpdateWeekday::Monday, chrono::Weekday::Mon)
                | (UpdateWeekday::Tuesday, chrono::Weekday::Tue)
                | (UpdateWeekday::Wednesday, chrono::Weekday::Wed)
                | (UpdateWeekday::Thursday, chrono::Weekday::Thu)
                | (UpdateWeekday::Friday, chrono::Weekday::Fri)
                | (UpdateWeekday::Saturday, chrono::Weekday::Sat)
                | (UpdateWeekday::Sunday, chrono::Weekday::Sun)
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            UpdateWeekday::Monday => "monday",
            UpdateWeekday::Tuesday => "tuesday",
            UpdateWeekday::Wednesday => "wednesday",
            UpdateWeekday::Thursday => "thursday",
            UpdateWeekday::Friday => "friday",
            UpdateWeekday::Saturday => "saturday",
            UpdateWeekday::Sunday => "sunday",
        }
    }
}

fn op_lock() -> &'static Mutex<()> {
    static OP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    OP_LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSettings {
    #[serde(default = "default_auto_check_enabled")]
    pub auto_check_enabled: bool,
    #[serde(default = "default_auto_check_frequency")]
    pub auto_check_frequency: UpdateAutoCheckFrequency,
    #[serde(default = "default_auto_check_time")]
    pub auto_check_time: String,
    #[serde(default = "default_auto_check_weekday")]
    pub auto_check_weekday: UpdateWeekday,
    #[serde(default = "default_auto_check_month_days")]
    pub auto_check_month_days: Vec<u8>,
    #[serde(default = "default_reboot_required_after_apply")]
    pub reboot_required_after_apply: bool,
    #[serde(default = "default_deploy_runtime_after_apply")]
    pub deploy_runtime_after_apply: bool,
    #[serde(default = "default_require_signed_commits")]
    pub require_signed_commits: bool,
    #[serde(default = "default_verify_rootfs_manifest")]
    pub verify_rootfs_manifest: bool,
    #[serde(default = "default_trusted_signers_file")]
    pub trusted_signers_file: String,
    #[serde(default = "default_bootstrap_missing_rootfs_repo")]
    pub bootstrap_missing_rootfs_repo: bool,
    #[serde(default = "default_core_repo_path")]
    pub core_repo_path: String,
    #[serde(default = "default_ui_repo_path")]
    pub ui_repo_path: String,
    #[serde(default = "default_rootfs_repo_path")]
    pub rootfs_repo_path: String,
    #[serde(default = "default_core_repo_url")]
    pub core_repo_url: String,
    #[serde(default = "default_ui_repo_url")]
    pub ui_repo_url: String,
    #[serde(default = "default_rootfs_repo_url")]
    pub rootfs_repo_url: String,
    #[serde(default = "default_branch")]
    pub core_branch: String,
    #[serde(default = "default_branch")]
    pub ui_branch: String,
    #[serde(default = "default_branch")]
    pub rootfs_branch: String,
    // New registry-based update settings
    #[serde(default = "default_registry_url")]
    pub registry_url: String,
    #[serde(default = "default_update_mode")]
    pub update_mode: String,
    #[serde(default = "default_verify_artifact_signatures")]
    pub verify_artifact_signatures: bool,
    #[serde(default = "default_encrypt_update_config_backups")]
    pub encrypt_update_config_backups: bool,
    #[serde(default = "default_enable_rootfs_ab_updates")]
    pub enable_rootfs_ab_updates: bool,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            auto_check_enabled: default_auto_check_enabled(),
            auto_check_frequency: default_auto_check_frequency(),
            auto_check_time: default_auto_check_time(),
            auto_check_weekday: default_auto_check_weekday(),
            auto_check_month_days: default_auto_check_month_days(),
            reboot_required_after_apply: default_reboot_required_after_apply(),
            deploy_runtime_after_apply: default_deploy_runtime_after_apply(),
            require_signed_commits: default_require_signed_commits(),
            verify_rootfs_manifest: default_verify_rootfs_manifest(),
            trusted_signers_file: default_trusted_signers_file(),
            bootstrap_missing_rootfs_repo: default_bootstrap_missing_rootfs_repo(),
            core_repo_path: default_core_repo_path(),
            ui_repo_path: default_ui_repo_path(),
            rootfs_repo_path: default_rootfs_repo_path(),
            core_repo_url: default_core_repo_url(),
            ui_repo_url: default_ui_repo_url(),
            rootfs_repo_url: default_rootfs_repo_url(),
            core_branch: default_branch(),
            ui_branch: default_branch(),
            rootfs_branch: default_branch(),
            registry_url: default_registry_url(),
            update_mode: default_update_mode(),
            verify_artifact_signatures: default_verify_artifact_signatures(),
            encrypt_update_config_backups: default_encrypt_update_config_backups(),
            enable_rootfs_ab_updates: default_enable_rootfs_ab_updates(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateComponent {
    Core,
    Ui,
    Rootfs,
    Both,
}

#[derive(Debug, Clone, Copy)]
enum RepoComponent {
    Core,
    Ui,
    Rootfs,
}

impl RepoComponent {
    fn as_str(self) -> &'static str {
        match self {
            RepoComponent::Core => "core",
            RepoComponent::Ui => "ui",
            RepoComponent::Rootfs => "rootfs",
        }
    }

    fn from_update_component(component: UpdateComponent) -> Vec<Self> {
        match component {
            UpdateComponent::Core => vec![Self::Core],
            UpdateComponent::Ui => vec![Self::Ui],
            UpdateComponent::Rootfs => vec![Self::Rootfs],
            UpdateComponent::Both => vec![Self::Core, Self::Ui],
        }
    }
}

fn ensure_registry_updatable_selection(selected_components: &[RepoComponent]) -> Result<()> {
    let rootfs_selected = selected_components
        .iter()
        .any(|c| matches!(c, RepoComponent::Rootfs));
    if rootfs_selected && selected_components.len() > 1 {
        anyhow::bail!(
            "rootfs updates must be staged separately from runtime core/ui updates"
        );
    }

    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentState {
    pub component: String,
    pub rollback_commit: Option<String>,
    pub rollback_version: Option<String>,
    pub last_applied_commit: Option<String>,
    pub deployed_commit: Option<String>,
    pub last_error: Option<String>,
    // New: Version tracking for artifact-based updates
    pub current_version: Option<String>,
    pub last_applied_version: Option<String>,
    pub remote_version: Option<String>,
    #[serde(default)]
    pub update_available: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStateFile {
    #[serde(default)]
    pub last_checked_at: Option<String>,
    #[serde(default)]
    pub last_auto_check_run: Option<String>,
    #[serde(default)]
    pub last_applied_at: Option<String>,
    #[serde(default)]
    pub pending_reboot: bool,
    #[serde(default)]
    pub pending_appliance_rebuild: bool,
    #[serde(default)]
    pub appliance_rebuild_reason: Option<String>,
    #[serde(default)]
    pub appliance_rebuild_marked_at: Option<String>,
    #[serde(default)]
    pub config_rollback_path: Option<String>,
    #[serde(default)]
    pub rootfs_update: Option<RootfsUpdateState>,
    #[serde(default)]
    pub components: Vec<ComponentState>,
    #[serde(default)]
    pub operation_logs: Vec<UpdateLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootfsUpdateState {
    pub status: String,
    pub target_slot: Option<String>,
    pub previous_slot: Option<String>,
    pub target_version: Option<String>,
    pub prepared_at: Option<String>,
    pub booted_at: Option<String>,
    pub confirmed_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLogEntry {
    pub timestamp: String,
    pub operation: String,
    pub level: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentUpdateStatus {
    pub component: String,
    pub repo_path: String,
    pub branch: String,
    pub valid_repo: bool,
    pub dirty_worktree: bool,
    pub current_commit: Option<String>,
    pub remote_commit: Option<String>,
    pub current_version: Option<String>,
    pub remote_version: Option<String>,
    pub update_available: bool,
    pub rollback_commit: Option<String>,
    pub last_applied_commit: Option<String>,
    pub last_applied_version: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatesStatus {
    pub settings: UpdateSettings,
    pub last_checked_at: Option<String>,
    pub last_applied_at: Option<String>,
    pub pending_reboot: bool,
    pub pending_appliance_rebuild: bool,
    pub appliance_rebuild_reason: Option<String>,
    pub appliance_rebuild_marked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs_slot_status: Option<RootfsSlotStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs_update: Option<RootfsUpdateState>,
    pub components: Vec<ComponentUpdateStatus>,
    /// Number of components with available updates (computed server-side)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_update_count: Option<usize>,
    #[serde(default)]
    pub operation_logs: Vec<UpdateLogEntry>,
}

// ============================================================================
// NEW: Artifact Registry Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactMetadata {
    pub component: String,
    pub version: String,
    pub download_url: String,
    pub checksum_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_release_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryManifest {
    pub components: Vec<ArtifactMetadata>,
    pub generated_at: String,
}

// ============================================================================
// GitHub Releases API support
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GitHubRelease {
    pub tag_name: String,
    pub assets: Vec<GitHubAsset>,
    pub created_at: String,
    #[serde(default)]
    pub html_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
}

fn is_github_repo_api_url(url: &str) -> bool {
    url.contains("api.github.com") && url.contains("/repos/")
}

fn registry_manifest_url(registry_url: &str) -> String {
    let trimmed = registry_url.trim_end_matches('/');
    if trimmed.ends_with(".json") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/manifest.json")
    }
}

fn github_contents_manifest_url(github_api_url: &str) -> String {
    format!("{}/contents/manifest.json", github_api_url.trim_end_matches('/'))
}

fn github_repo_slug(github_api_url: &str) -> Option<String> {
    let rest = github_api_url.split("/repos/").nth(1)?;
    let mut parts = rest.trim_matches('/').split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    Some(format!("{owner}/{repo}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatesActionResult {
    pub operation: String,
    pub success: bool,
    pub message: String,
    pub details: Vec<String>,
    pub status: UpdatesStatus,
}

fn config_dir(state: &AppState) -> PathBuf {
    state
        .config_store
        .config_path()
        .parent()
        .unwrap_or(Path::new("/etc/dayshield/config"))
        .to_path_buf()
}

fn settings_path(state: &AppState) -> PathBuf {
    config_dir(state).join(SETTINGS_FILE)
}

fn state_path(state: &AppState) -> PathBuf {
    config_dir(state).join(STATE_FILE)
}

fn rootfs_iso_upgrade_marker_path(state: &AppState) -> PathBuf {
    config_dir(state).join(ROOTFS_ISO_UPGRADE_MARKER)
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let payload = serde_json::to_string_pretty(value)?;
    std::fs::write(&tmp, payload)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn load_json_or_default<T>(path: &Path) -> T
where
    T: for<'de> Deserialize<'de> + Default,
{
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<T>(&raw).ok())
        .unwrap_or_default()
}

fn ensure_component_state<'a>(state: &'a mut UpdateStateFile, component: RepoComponent) -> &'a mut ComponentState {
    if let Some(idx) = state
        .components
        .iter()
        .position(|c| c.component == component.as_str())
    {
        return &mut state.components[idx];
    }
    state.components.push(ComponentState {
        component: component.as_str().to_string(),
        ..ComponentState::default()
    });
    let idx = state.components.len() - 1;
    &mut state.components[idx]
}

fn find_component_state<'a>(state: &'a UpdateStateFile, component: RepoComponent) -> Option<&'a ComponentState> {
    state.components.iter().find(|c| c.component == component.as_str())
}

fn component_config(settings: &UpdateSettings, component: RepoComponent) -> (String, String, String) {
    match component {
        RepoComponent::Core => (
            settings.core_repo_path.clone(),
            settings.core_repo_url.clone(),
            settings.core_branch.clone(),
        ),
        RepoComponent::Ui => (
            settings.ui_repo_path.clone(),
            settings.ui_repo_url.clone(),
            settings.ui_branch.clone(),
        ),
        RepoComponent::Rootfs => (
            settings.rootfs_repo_path.clone(),
            settings.rootfs_repo_url.clone(),
            settings.rootfs_branch.clone(),
        ),
    }
}

fn component_supports_runtime_deploy(component: RepoComponent) -> bool {
    matches!(component, RepoComponent::Core | RepoComponent::Ui)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootfsSlotStatus {
    pub supported: bool,
    pub active_slot: Option<String>,
    pub inactive_slot: Option<String>,
    pub boot_uuid: Option<String>,
    pub slot_a_uuid: Option<String>,
    pub slot_b_uuid: Option<String>,
    pub reason: Option<String>,
}

fn built_appliance_version() -> String {
    env!("CARGO_PKG_VERSION").trim_start_matches('v').to_string()
}

fn current_version_baseline(saved: Option<&ComponentState>) -> Option<String> {
    saved
        .and_then(|s| s.current_version.clone())
        .or_else(|| saved.and_then(|s| s.last_applied_version.clone()))
        .or_else(|| Some(built_appliance_version()))
}

#[derive(Debug, Clone)]
struct RootfsSlot {
    name: String,
    label: String,
    device: PathBuf,
    uuid: String,
}

impl RootfsSlot {
    fn grub_entry_id(&self) -> String {
        format!("{ROOTFS_GRUB_ENTRY_PREFIX}{}", self.name)
    }
}

#[derive(Debug, Clone)]
struct RootfsAbLayout {
    active: RootfsSlot,
    inactive: RootfsSlot,
    slot_a: RootfsSlot,
    slot_b: RootfsSlot,
    boot_uuid: String,
    efi_uuid: Option<String>,
}

fn command_stdout_sync(program: &str, args: &[&str]) -> Result<String> {
    let output = StdCommand::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {program}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!(
            "{} {} failed{}",
            program,
            args.join(" "),
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn run_system_command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("failed to run {program}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!(
            "{} {} failed{}",
            program,
            args.join(" "),
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn device_by_label(label: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(command_stdout_sync("blkid", &["-L", label])?))
}

fn device_uuid(device: &Path) -> Result<String> {
    let device = device.to_string_lossy();
    command_stdout_sync("blkid", &["-s", "UUID", "-o", "value", &device])
}

fn mount_uuid(target: &str) -> Result<String> {
    command_stdout_sync("findmnt", &["-n", "-o", "UUID", "--target", target])
}

fn slot_from_label(name: &str, label: &str) -> Result<RootfsSlot> {
    let device = device_by_label(label)?;
    let uuid = device_uuid(&device)?;
    Ok(RootfsSlot {
        name: name.to_string(),
        label: label.to_string(),
        device,
        uuid,
    })
}

fn detect_rootfs_ab_layout() -> Result<RootfsAbLayout> {
    let slot_a = slot_from_label("a", ROOTFS_SLOT_A_LABEL)?;
    let slot_b = slot_from_label("b", ROOTFS_SLOT_B_LABEL)?;
    let active_uuid = mount_uuid("/")?;
    let boot_uuid = {
        let boot_device = device_by_label(ROOTFS_BOOT_LABEL)?;
        let boot_uuid = device_uuid(&boot_device)?;
        let mounted_boot_uuid = mount_uuid("/boot")?;
        if mounted_boot_uuid != boot_uuid {
            anyhow::bail!(
                "/boot is not mounted from {} (mounted UUID {}, expected {})",
                ROOTFS_BOOT_LABEL,
                mounted_boot_uuid,
                boot_uuid
            );
        }
        boot_uuid
    };
    let efi_uuid = mount_uuid("/boot/efi").ok();

    let (active, inactive) = if active_uuid == slot_a.uuid {
        (slot_a.clone(), slot_b.clone())
    } else if active_uuid == slot_b.uuid {
        (slot_b.clone(), slot_a.clone())
    } else {
        anyhow::bail!(
            "active root UUID {} does not match {} or {}",
            active_uuid,
            ROOTFS_SLOT_A_LABEL,
            ROOTFS_SLOT_B_LABEL
        );
    };

    Ok(RootfsAbLayout {
        active,
        inactive,
        slot_a,
        slot_b,
        boot_uuid,
        efi_uuid,
    })
}

fn rootfs_slot_status(settings: &UpdateSettings, state_file: &UpdateStateFile) -> Option<RootfsSlotStatus> {
    if !settings.enable_rootfs_ab_updates {
        return Some(RootfsSlotStatus {
            supported: false,
            active_slot: None,
            inactive_slot: None,
            boot_uuid: None,
            slot_a_uuid: None,
            slot_b_uuid: None,
            reason: Some("A/B rootfs updates are disabled in update settings".to_string()),
        });
    }

    match detect_rootfs_ab_layout() {
        Ok(layout) => Some(RootfsSlotStatus {
            supported: true,
            active_slot: Some(layout.active.name),
            inactive_slot: Some(layout.inactive.name),
            boot_uuid: Some(layout.boot_uuid),
            slot_a_uuid: Some(layout.slot_a.uuid),
            slot_b_uuid: Some(layout.slot_b.uuid),
            reason: None,
        }),
        Err(err) => Some(RootfsSlotStatus {
            supported: false,
            active_slot: None,
            inactive_slot: None,
            boot_uuid: None,
            slot_a_uuid: None,
            slot_b_uuid: None,
            reason: Some(err.to_string()),
        }),
    }
    .map(|mut status| {
        if let Some(update) = &state_file.rootfs_update {
            if status.reason.is_none() {
                status.reason = update.last_error.clone();
            }
        }
        status
    })
}

fn runtime_marker_path(component: RepoComponent) -> PathBuf {
    Path::new(RUNTIME_MARKER_DIR).join(format!("{}_deployed_commit", component.as_str()))
}

fn update_backup_key_path(state: &AppState) -> PathBuf {
    config_dir(state).join(UPDATE_BACKUP_KEY_FILE)
}

fn load_or_create_update_backup_key(state: &AppState) -> Result<String> {
    let path = update_backup_key_path(state);
    if let Ok(existing) = fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create key directory {}", parent.display()))?;
    }

    let key = uuid::Uuid::new_v4().to_string();
    fs::write(&path, format!("{}\n", key))
        .with_context(|| format!("failed to write update backup key {}", path.display()))?;
    Ok(key)
}

fn snapshot_config_for_rollback(state: &AppState, encrypt: bool) -> Result<PathBuf> {
    let passphrase = if encrypt {
        Some(load_or_create_update_backup_key(state)?)
    } else {
        None
    };

    let backup_dir = PathBuf::from(DEFAULT_BACKUP_DIR);
    let (path, _meta) = create_backup(
        &state.config_store,
        Some(Subsystem::all()),
        encrypt,
        passphrase.as_deref(),
        &backup_dir,
        BackupType::Update,
    )
    .context("failed to create rollback config backup archive")?;

    Ok(path)
}

fn restore_config_from_snapshot(state: &AppState, snapshot: &Path) -> Result<()> {
    if !snapshot.exists() || !snapshot.is_file() {
        anyhow::bail!("config rollback backup archive not found: {}", snapshot.display());
    }

    let payload = fs::read(snapshot)
        .with_context(|| format!("failed to read config rollback backup {}", snapshot.display()))?;

    let passphrase = if snapshot
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(".tar.enc"))
        .unwrap_or(false)
    {
        Some(load_or_create_update_backup_key(state)?)
    } else {
        None
    };

    restore_backup(&state.config_store, &payload, passphrase.as_deref(), None)
        .with_context(|| format!("failed to restore config from {}", snapshot.display()))?;

    Ok(())
}

fn runtime_rollback_path(component: RepoComponent) -> PathBuf {
    match component {
        RepoComponent::Core => Path::new(RUNTIME_ROLLBACK_DIR).join("core/dayshield-core"),
        RepoComponent::Ui => Path::new(RUNTIME_ROLLBACK_DIR).join("ui"),
        RepoComponent::Rootfs => Path::new(RUNTIME_ROLLBACK_DIR).join("rootfs"),
    }
}

fn deployed_runtime_path(component: RepoComponent) -> PathBuf {
    match component {
        RepoComponent::Core => PathBuf::from("/usr/local/sbin/dayshield-core"),
        RepoComponent::Ui => PathBuf::from("/usr/local/share/dayshield-ui"),
        RepoComponent::Rootfs => PathBuf::from("/"),
    }
}

fn snapshot_runtime_for_rollback(component: RepoComponent) -> Result<()> {
    if !component_supports_runtime_deploy(component) {
        return Ok(());
    }

    let source = deployed_runtime_path(component);
    let backup = runtime_rollback_path(component);

    if let Some(parent) = backup.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create rollback directory {}", parent.display()))?;
    }

    if backup.exists() {
        if backup.is_dir() {
            fs::remove_dir_all(&backup)
                .with_context(|| format!("failed to clear rollback snapshot {}", backup.display()))?;
        } else {
            fs::remove_file(&backup)
                .with_context(|| format!("failed to clear rollback snapshot {}", backup.display()))?;
        }
    }

    if !source.exists() {
        anyhow::bail!(
            "{} runtime artifact missing at {}; cannot create rollback snapshot",
            component.as_str(),
            source.display()
        );
    }

    if source.is_dir() {
        copy_dir_recursive(&source, &backup)?;
    } else {
        fs::copy(&source, &backup).with_context(|| {
            format!(
                "failed to snapshot {} -> {}",
                source.display(),
                backup.display()
            )
        })?;
        let perms = fs::metadata(&source)?.permissions();
        fs::set_permissions(&backup, perms)?;
    }

    Ok(())
}

fn restore_runtime_from_snapshot(component: RepoComponent) -> Result<()> {
    if !component_supports_runtime_deploy(component) {
        return Ok(());
    }

    let snapshot = runtime_rollback_path(component);
    let target = deployed_runtime_path(component);

    if !snapshot.exists() {
        anyhow::bail!(
            "{}: no rollback snapshot available at {}",
            component.as_str(),
            snapshot.display()
        );
    }

    match component {
        RepoComponent::Core => install_file_atomic(&snapshot, &target),
        RepoComponent::Ui => install_dir_atomic(&snapshot, &target),
        RepoComponent::Rootfs => Ok(()),
    }
}

fn save_runtime_marker(component: RepoComponent, commit: &str) -> Result<()> {
    let marker = runtime_marker_path(component);
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&marker, format!("{}\n", commit))
        .with_context(|| format!("failed to write runtime marker {}", marker.display()))?;
    Ok(())
}

fn load_runtime_marker(component: RepoComponent) -> Option<String> {
    let marker = runtime_marker_path(component);
    std::fs::read_to_string(&marker)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

async fn reset_and_optionally_deploy(
    settings: &UpdateSettings,
    state_file: &mut UpdateStateFile,
    component: RepoComponent,
    target_commit: &str,
    deploy_runtime: bool,
    details: &mut Vec<String>,
) -> Result<()> {
    let (repo_path, _remote_url, _branch) = component_config(settings, component);
    run_git(&repo_path, &["reset", "--hard", target_commit]).await?;

    let head = run_git(&repo_path, &["rev-parse", "HEAD"]).await?;
    if head != target_commit {
        anyhow::bail!(
            "{}: reset verification failed (expected {}, got {})",
            component.as_str(),
            target_commit,
            head
        );
    }

    let entry = ensure_component_state(state_file, component);

    if deploy_runtime && component_supports_runtime_deploy(component) {
        deploy_component_runtime(component, &repo_path).await?;
        save_runtime_marker(component, &head)?;
        entry.deployed_commit = Some(head.clone());
        details.push(format!("{}: runtime artifacts deployed", component.as_str()));
    }

    entry.last_applied_commit = Some(head.clone());
    entry.last_error = None;
    details.push(format!("{}: moved to {}", component.as_str(), short_sha(&head)));
    Ok(())
}

async fn run_git(repo_path: &str, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .output()
        .await
        .with_context(|| format!("failed to execute git {:?}", args))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "git {:?} failed: {}{}{}",
            args,
            stderr.trim(),
            if !stderr.trim().is_empty() && !stdout.trim().is_empty() {
                " | "
            } else {
                ""
            },
            stdout.trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn run_command_in(repo_path: &str, program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .current_dir(repo_path)
        .args(args)
        .output()
        .await
        .with_context(|| format!("failed to execute {} {:?}", program, args))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "{} {:?} failed: {}{}{}",
            program,
            args,
            stderr.trim(),
            if !stderr.trim().is_empty() && !stdout.trim().is_empty() {
                " | "
            } else {
                ""
            },
            stdout.trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn ensure_command_available(program: &str) -> Result<()> {
    Command::new(program)
        .arg("--version")
        .output()
        .await
        .with_context(|| format!("required command '{}' is not available", program))?;
    Ok(())
}

async fn is_command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .await
        .is_ok()
}

async fn ensure_critical_services_healthy() -> Result<()> {
    ensure_command_available("systemctl").await?;
    let critical = ["dayshield.service", "nftables.service", "unbound.service"];
    let mut unhealthy = Vec::new();

    for unit in &critical {
        let out = Command::new("systemctl")
            .arg("is-active")
            .arg(unit)
            .output()
            .await
            .with_context(|| format!("failed to query {}", unit))?;
        let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if state != "active" {
            unhealthy.push(format!("{}={}", unit, state));
        }
    }

    if !unhealthy.is_empty() {
        anyhow::bail!(
            "critical service health check failed after update: {}",
            unhealthy.join(", ")
        );
    }

    Ok(())
}

async fn verify_commit_signature(repo_path: &str, commit: &str, trusted_signers_file: &str) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo_path);
    if !trusted_signers_file.trim().is_empty() {
        cmd.arg("-c")
            .arg(format!("gpg.ssh.allowedSignersFile={}", trusted_signers_file));
    }
    cmd.arg("verify-commit").arg(commit);

    let output = cmd
        .output()
        .await
        .with_context(|| format!("failed to verify commit signature for {}", commit))?;

    if !output.status.success() {
        anyhow::bail!(
            "commit signature verification failed for {}: {}",
            short_sha(commit),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn unique_suffix() -> String {
    Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000)
        .to_string()
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    if !src.is_dir() {
        anyhow::bail!("source directory does not exist: {}", src.display());
    }
    fs::create_dir_all(dst)
        .with_context(|| format!("failed to create directory {}", dst.display()))?;

    for entry in fs::read_dir(src)
        .with_context(|| format!("failed to read directory {}", src.display()))?
    {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path).with_context(|| {
                format!(
                    "failed to copy {} -> {}",
                    src_path.display(),
                    dst_path.display()
                )
            })?;
            let perms = fs::metadata(&src_path)?.permissions();
            fs::set_permissions(&dst_path, perms)?;
        }
    }

    Ok(())
}

fn install_file_atomic(src: &Path, target: &Path) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid target path {}", target.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let suffix = unique_suffix();
    let staged = parent.join(format!("{}.new.{}", target.file_name().unwrap_or_default().to_string_lossy(), suffix));
    let backup = parent.join(format!("{}.bak.{}", target.file_name().unwrap_or_default().to_string_lossy(), suffix));

    fs::copy(src, &staged)
        .with_context(|| format!("failed to stage {} -> {}", src.display(), staged.display()))?;

    let had_existing = target.exists();
    if had_existing {
        fs::rename(target, &backup).with_context(|| {
            format!(
                "failed to move existing target {} -> {}",
                target.display(),
                backup.display()
            )
        })?;
    }

    if let Err(err) = fs::rename(&staged, target) {
        if had_existing {
            let _ = fs::rename(&backup, target);
        }
        let _ = fs::remove_file(&staged);
        anyhow::bail!("failed to install {}: {}", target.display(), err);
    }

    if had_existing {
        let _ = fs::remove_file(&backup);
    }

    Ok(())
}

fn install_dir_atomic(src: &Path, target: &Path) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid target path {}", target.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let suffix = unique_suffix();
    let staged = parent.join(format!("{}.new.{}", target.file_name().unwrap_or_default().to_string_lossy(), suffix));
    let backup = parent.join(format!("{}.bak.{}", target.file_name().unwrap_or_default().to_string_lossy(), suffix));

    if staged.exists() {
        fs::remove_dir_all(&staged)
            .with_context(|| format!("failed to clear staged dir {}", staged.display()))?;
    }
    copy_dir_recursive(src, &staged)?;

    let had_existing = target.exists();
    if had_existing {
        fs::rename(target, &backup).with_context(|| {
            format!(
                "failed to move existing dir {} -> {}",
                target.display(),
                backup.display()
            )
        })?;
    }

    if let Err(err) = fs::rename(&staged, target) {
        if had_existing {
            let _ = fs::rename(&backup, target);
        }
        let _ = fs::remove_dir_all(&staged);
        anyhow::bail!("failed to install directory {}: {}", target.display(), err);
    }

    if had_existing {
        let _ = fs::remove_dir_all(&backup);
    }

    Ok(())
}

async fn deploy_component_runtime(component: RepoComponent, repo_path: &str) -> Result<()> {
    match component {
        RepoComponent::Core => {
            ensure_command_available("cargo").await?;
            run_command_in(repo_path, "cargo", &["build", "--release", "-p", "dayshield-core"]).await?;

            let built_bin = Path::new(repo_path).join("target/release/dayshield-core");
            if !built_bin.exists() {
                anyhow::bail!(
                    "core binary was not produced at {}",
                    built_bin.display()
                );
            }

            install_file_atomic(&built_bin, Path::new("/usr/local/sbin/dayshield-core"))?;
        }
        RepoComponent::Ui => {
            let dist_dir = Path::new(repo_path).join("dist");
            let dist_index = dist_dir.join("index.html");

            if is_command_available("npm").await {
                run_command_in(repo_path, "npm", &["ci", "--no-audit", "--no-fund"]).await?;
                run_command_in(repo_path, "npm", &["run", "build"]).await?;
            } else if !dist_index.exists() {
                anyhow::bail!(
                    "npm is unavailable and prebuilt UI assets are missing at {}",
                    dist_index.display()
                );
            }

            if !dist_index.exists() {
                anyhow::bail!(
                    "UI build output missing index.html at {}",
                    dist_dir.display()
                );
            }

            install_dir_atomic(&dist_dir, Path::new("/usr/local/share/dayshield-ui"))?;
        }
        RepoComponent::Rootfs => anyhow::bail!("rootfs runtime deployment is not supported in update flow"),
    }

    Ok(())
}

async fn ensure_origin(repo_path: &str, remote_url: &str) -> Result<()> {
    let current = run_git(repo_path, &["remote", "get-url", "origin"]).await;
    match current {
        Ok(url) => {
            if url.trim() != remote_url {
                run_git(repo_path, &["remote", "set-url", "origin", remote_url]).await?;
            }
        }
        Err(_) => {
            run_git(repo_path, &["remote", "add", "origin", remote_url]).await?;
        }
    }
    Ok(())
}

async fn remote_url_for_check(repo_path: &str, configured_url: &str) -> String {
    match run_git(repo_path, &["remote", "get-url", "origin"]).await {
        Ok(url) if !url.trim().is_empty() => url,
        _ => configured_url.to_string(),
    }
}

async fn remote_branch_head(repo_path: &str, remote_url: &str, branch: &str) -> Result<String> {
    let out = run_git(repo_path, &["ls-remote", "--heads", remote_url, branch]).await?;
    let line = out
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("no remote head found for branch {branch}"))?;

    let sha = line
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid ls-remote output for branch {branch}"))?;

    if sha.is_empty() {
        anyhow::bail!("invalid remote commit for branch {branch}");
    }

    Ok(sha.to_string())
}

async fn inspect_repo(repo_path: &str, remote_url: &str, branch: &str) -> Result<(String, String, bool)> {
    run_git(repo_path, &["rev-parse", "--is-inside-work-tree"]).await?;
    let current = run_git(repo_path, &["rev-parse", "HEAD"]).await?;
    let dirty = !run_git(repo_path, &["status", "--porcelain"]).await?.trim().is_empty();
    let effective_remote = remote_url_for_check(repo_path, remote_url).await;
    let remote = remote_branch_head(repo_path, &effective_remote, branch).await?;

    Ok((current, remote, dirty))
}

pub fn load_settings(state: &AppState) -> UpdateSettings {
    load_json_or_default(&settings_path(state))
}

pub fn save_settings(state: &AppState, settings: &UpdateSettings) -> Result<()> {
    let mut value = settings.clone();
    value.auto_check_time = normalize_auto_check_time(&value.auto_check_time);
    value.auto_check_month_days = normalize_auto_check_month_days(value.auto_check_month_days);
    if value.core_branch.trim().is_empty() {
        value.core_branch = default_branch();
    }
    if value.ui_branch.trim().is_empty() {
        value.ui_branch = default_branch();
    }
    if value.rootfs_branch.trim().is_empty() {
        value.rootfs_branch = default_branch();
    }
    if value.trusted_signers_file.trim().is_empty() {
        value.trusted_signers_file = default_trusted_signers_file();
    }
    write_json_atomic(&settings_path(state), &value)
}

fn load_state(state: &AppState) -> UpdateStateFile {
    load_json_or_default(&state_path(state))
}

fn save_state(state: &AppState, value: &UpdateStateFile) -> Result<()> {
    write_json_atomic(&state_path(state), value)
}

fn append_operation_log(
    state_file: &mut UpdateStateFile,
    operation: &str,
    level: &str,
    message: impl Into<String>,
    component: Option<&str>,
) {
    append_operation_log_with_versions(state_file, operation, level, message, component, None, None);
}

fn append_operation_log_with_versions(
    state_file: &mut UpdateStateFile,
    operation: &str,
    level: &str,
    message: impl Into<String>,
    component: Option<&str>,
    from_version: Option<&str>,
    to_version: Option<&str>,
) {
    state_file.operation_logs.push(UpdateLogEntry {
        timestamp: Utc::now().to_rfc3339(),
        operation: operation.to_string(),
        level: level.to_string(),
        message: message.into(),
        component: component.map(|v| v.to_string()),
        from_version: from_version.map(|v| v.to_string()),
        to_version: to_version.map(|v| v.to_string()),
    });

    const MAX_LOG_ENTRIES: usize = 250;
    if state_file.operation_logs.len() > MAX_LOG_ENTRIES {
        let drop_count = state_file.operation_logs.len() - MAX_LOG_ENTRIES;
        state_file.operation_logs.drain(0..drop_count);
    }
}

fn clear_appliance_rebuild_required(state_file: &mut UpdateStateFile) {
    state_file.pending_appliance_rebuild = false;
    state_file.appliance_rebuild_reason = None;
    state_file.appliance_rebuild_marked_at = Some(Utc::now().to_rfc3339());
}

fn acknowledge_rootfs_rebuild(state_file: &mut UpdateStateFile) {
    let rootfs = ensure_component_state(state_file, RepoComponent::Rootfs);
    if let Some(remote_version) = rootfs.remote_version.clone() {
        rootfs.current_version = Some(remote_version.clone());
        rootfs.last_applied_version = Some(remote_version);
        rootfs.update_available = false;
        rootfs.last_error = None;
    }
}

pub fn mark_appliance_rebuild_complete(state: &AppState) -> Result<()> {
    let mut state_file = load_state(state);
    clear_appliance_rebuild_required(&mut state_file);
    acknowledge_rootfs_rebuild(&mut state_file);
    save_state(state, &state_file)
}

// ============================================================================
// NEW: Artifact Registry Helpers
// ============================================================================

use sha2::{Sha256, Digest};

/// Verify SHA256 checksum of a file
fn verify_checksum(file_path: &Path, expected: &str) -> Result<()> {
    let data = fs::read(file_path)
        .with_context(|| format!("failed to read file {}", file_path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let result = hasher.finalize();
    let computed = result
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    
    if computed != expected {
        anyhow::bail!(
            "checksum mismatch: computed {}, expected {}",
            computed,
            expected
        );
    }
    Ok(())
}

/// Download artifact from registry
async fn download_artifact(
    url: &str,
    destination: &Path,
) -> Result<()> {
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to download artifact from {}", url))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "artifact download failed: HTTP {} from {}",
            response.status(),
            url
        );
    }

    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("failed to read artifact response from {}", url))?;

    fs::write(destination, bytes)
        .with_context(|| format!("failed to write artifact to {}", destination.display()))?;

    Ok(())
}

/// Query artifact registry for latest versions
async fn query_registry(registry_url: &str) -> Result<RegistryManifest> {
    let client = reqwest::Client::new();

    if is_github_repo_api_url(registry_url) {
        match query_github_repo_manifest(registry_url, &client).await {
            Ok(manifest) => return Ok(manifest),
            Err(err) => {
                warn!(
                    error = %err,
                    "updates: failed to fetch GitHub manifest.json; falling back to releases/latest"
                );
                return query_github_releases(registry_url, &client).await;
            }
        }
    }

    let manifest_url = registry_manifest_url(registry_url);
    query_registry_manifest_url(&client, &manifest_url).await
}

async fn query_registry_manifest_url(client: &reqwest::Client, manifest_url: &str) -> Result<RegistryManifest> {
    let response = client
        .get(manifest_url)
        .send()
        .await
        .with_context(|| format!("failed to query registry manifest at {}", manifest_url))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "registry query failed: HTTP {} from {}",
            response.status(),
            manifest_url
        );
    }

    response
        .json()
        .await
        .with_context(|| format!("failed to parse registry manifest from {}", manifest_url))
}

async fn query_github_repo_manifest(
    github_api_url: &str,
    client: &reqwest::Client,
) -> Result<RegistryManifest> {
    let manifest_url = github_contents_manifest_url(github_api_url);
    let mut request = client
        .get(&manifest_url)
        .header(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github.raw+json"),
        )
        .header(USER_AGENT, HeaderValue::from_static("dayshield-core/1.0"))
        .header(
            HeaderName::from_static("x-github-api-version"),
            HeaderValue::from_static("2022-11-28"),
        );

    if let Ok(token) = env::var("DAYSHIELD_GITHUB_TOKEN")
        .or_else(|_| env::var("GITHUB_TOKEN"))
        .or_else(|_| env::var("GH_TOKEN"))
    {
        let token = token.trim();
        if !token.is_empty() {
            let value = HeaderValue::from_str(&format!("Bearer {}", token))
                .context("invalid GitHub token value")?;
            request = request.header(AUTHORIZATION, value);
        }
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("failed to query GitHub manifest at {}", manifest_url))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "GitHub manifest query failed: HTTP {} from {}{}",
            status,
            manifest_url,
            if body.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", body.trim())
            }
        );
    }

    response
        .json()
        .await
        .with_context(|| format!("failed to parse GitHub manifest from {}", manifest_url))
}

/// Query GitHub Releases API for latest release artifacts (legacy fallback).
async fn query_github_releases(
    github_api_url: &str,
    client: &reqwest::Client,
) -> Result<RegistryManifest> {
    // Construct API URL: https://api.github.com/repos/{owner}/{repo}/releases/latest
    let releases_url = if github_api_url.ends_with('/') {
        format!("{}releases/latest", github_api_url)
    } else {
        format!("{}/releases/latest", github_api_url)
    };

    let mut request = client
        .get(&releases_url)
        .header(ACCEPT, HeaderValue::from_static("application/vnd.github+json"))
        .header(USER_AGENT, HeaderValue::from_static("dayshield-core/1.0"))
        .header(HeaderName::from_static("x-github-api-version"), HeaderValue::from_static("2022-11-28"));

    if let Ok(token) = env::var("DAYSHIELD_GITHUB_TOKEN").or_else(|_| env::var("GITHUB_TOKEN")).or_else(|_| env::var("GH_TOKEN")) {
        let token = token.trim();
        if !token.is_empty() {
            let value = HeaderValue::from_str(&format!("Bearer {}", token))
                .context("invalid GitHub token value")?;
            request = request.header(AUTHORIZATION, value);
        }
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("failed to query GitHub releases from {}", releases_url))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "GitHub releases query failed: HTTP {} from {}{}",
            status,
            releases_url,
            if body.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", body.trim())
            }
        );
    }

    let release: GitHubRelease = response
        .json()
        .await
        .with_context(|| format!("failed to parse GitHub release from {}", releases_url))?;

    // Parse assets into ArtifactMetadata
    let mut components = Vec::new();
    let component_names = ["core", "ui", "rootfs"];
    let source_repo = github_repo_slug(github_api_url);

    for comp_name in &component_names {
        // Find asset matching pattern: {component}-v*.tar.zst
        let asset_opt = release.assets.iter().find(|a| {
            a.name.starts_with(comp_name) && a.name.ends_with(".tar.zst")
        });

        if let Some(asset) = asset_opt {
            // Extract version from filename: core-v1.2.3.tar.zst -> 1.2.3
            let version_str = asset.name
                .strip_prefix(&format!("{}-v", comp_name))
                .and_then(|s| s.strip_suffix(".tar.zst"))
                .unwrap_or("unknown");

            components.push(ArtifactMetadata {
                component: comp_name.to_string(),
                version: version_str.to_string(),
                download_url: asset.browser_download_url.clone(),
                checksum_sha256: String::new(), // Will be populated from checksums.txt if available
                signature_url: None,
                source_repo: source_repo.clone(),
                source_tag: Some(release.tag_name.clone()),
                source_release_url: release.html_url.clone(),
            });

            info!(
                component = %comp_name,
                version = %version_str,
                url = %asset.browser_download_url,
                "updates: found GitHub release artifact"
            );
        }
    }

    if components.is_empty() {
        anyhow::bail!(
            "GitHub release {} has no artifacts matching pattern {{component}}-v*.tar.zst",
            release.tag_name
        );
    }

    // Try to fetch checksums from release
    if let Some(checksums_asset) = release.assets.iter().find(|a| a.name == "checksums.txt") {
        match client
            .get(&checksums_asset.browser_download_url)
            .send()
            .await
        {
            Ok(response) => {
                match response.text().await {
                    Ok(checksums_text) => {
                        // Parse checksums.txt format: SHA256 filename
                        for line in checksums_text.lines() {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                let checksum = parts[0];
                                let filename = parts[1];
                                
                                if let Some(comp) = components.iter_mut().find(|c| {
                                    filename.contains(&c.component) && filename.contains(&c.version)
                                }) {
                                    comp.checksum_sha256 = checksum.to_string();
                                }
                            }
                        }
                    },
                    Err(e) => {
                        warn!(error = %e, "updates: failed to parse checksums.txt response");
                    }
                }
            },
            Err(e) => {
                warn!(error = %e, "updates: failed to fetch checksums.txt from release");
            }
        }
    }

    Ok(RegistryManifest {
        components,
        generated_at: release.created_at.clone(),
    })
}

/// Extract artifact and deploy to target location
async fn extract_and_deploy_artifact(
    component: RepoComponent,
    artifact_path: &Path,
    target_dir: Option<&Path>,
) -> Result<()> {
    let artifact_file = std::fs::File::open(artifact_path)
        .with_context(|| format!("failed to open artifact {}", artifact_path.display()))?;
    
    let decoder = zstd::stream::Decoder::new(artifact_file)
        .with_context(|| format!("failed to initialize zstd decoder for {}", artifact_path.display()))?;
    
    let mut archive = tar::Archive::new(decoder);

    match component {
        RepoComponent::Core => {
            let tmp_dir = PathBuf::from("/tmp/dayshield-core-deploy");
            fs::create_dir_all(&tmp_dir)?;
            archive.unpack(&tmp_dir)
                .with_context(|| format!("failed to extract core artifact"))?;
            
            let binary = tmp_dir.join("dayshield-core");
            if !binary.exists() {
                anyhow::bail!("core binary not found in artifact");
            }
            
            install_file_atomic(&binary, Path::new("/usr/local/sbin/dayshield-core"))?;
            let _ = fs::remove_dir_all(&tmp_dir);
        },
        RepoComponent::Ui => {
            let target = target_dir.unwrap_or(Path::new("/usr/local/share/dayshield-ui"));
            let tmp_dir = PathBuf::from("/tmp/dayshield-ui-deploy");
            fs::create_dir_all(&tmp_dir)?;
            archive.unpack(&tmp_dir)
                .with_context(|| format!("failed to extract ui artifact"))?;
            
            let dist_dir = tmp_dir.join("dist");
            if !dist_dir.exists() {
                anyhow::bail!("dist directory not found in ui artifact");
            }
            
            install_dir_atomic(&dist_dir, target)?;
            let _ = fs::remove_dir_all(&tmp_dir);
        },
        RepoComponent::Rootfs => {
            anyhow::bail!(
                "rootfs artifacts must be staged through the A/B slot updater"
            );
        },
    }

    Ok(())
}

fn rootfs_target_path(mount_dir: &Path, absolute_path: &Path) -> PathBuf {
    mount_dir.join(absolute_path.strip_prefix("/").unwrap_or(absolute_path))
}

fn write_rootfs_fstab(mount_dir: &Path, layout: &RootfsAbLayout, slot: &RootfsSlot) -> Result<()> {
    let mut content = format!(
        "# /etc/fstab - generated by DayShield rootfs A/B updater\n\
         UUID={}  /          ext4  defaults,noatime  0  1\n\
         UUID={}  /boot      ext4  defaults,noatime  0  2\n",
        slot.uuid, layout.boot_uuid
    );
    if let Some(efi_uuid) = &layout.efi_uuid {
        content.push_str(&format!(
            "UUID={}  /boot/efi  vfat  umask=0077        0  2\n",
            efi_uuid
        ));
    }
    content.push_str("tmpfs     /tmp       tmpfs defaults           0  0\n");

    let target = rootfs_target_path(mount_dir, Path::new("/etc/fstab"));
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&target, content).with_context(|| format!("failed to write {}", target.display()))
}

async fn copy_persistent_path(mount_dir: &Path, path: &str) -> Result<()> {
    let source = Path::new(path);
    if !source.exists() {
        return Ok(());
    }

    let target = rootfs_target_path(mount_dir, source);
    if target.is_dir() {
        fs::remove_dir_all(&target)
            .with_context(|| format!("failed to remove {}", target.display()))?;
    } else if target.exists() {
        fs::remove_file(&target)
            .with_context(|| format!("failed to remove {}", target.display()))?;
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }

    let mount_dir_arg = mount_dir.to_string_lossy().to_string();
    run_system_command("cp", &["-a", "--parents", path, &mount_dir_arg]).await?;
    Ok(())
}

async fn copy_persistent_state_to_inactive(mount_dir: &Path) -> Result<()> {
    for path in [
        "/etc/dayshield",
        "/etc/wireguard",
        "/etc/cloudflared",
        "/etc/hostname",
        "/etc/hosts",
        "/etc/machine-id",
        "/etc/ssh",
        "/etc/systemd/network",
        "/var/lib/dayshield",
        "/var/lib/cloudflared",
    ] {
        copy_persistent_path(mount_dir, path).await?;
    }

    for transient in [
        "var/lib/dayshield/update-staging",
        "var/lib/dayshield/update/rootfs-slot",
    ] {
        let target = mount_dir.join(transient);
        if target.exists() {
            fs::remove_dir_all(&target)
                .with_context(|| format!("failed to remove {}", target.display()))?;
        }
    }

    Ok(())
}

fn newest_boot_file(source_boot: &Path, prefix: &str) -> Result<PathBuf> {
    let exact = source_boot.join(prefix.trim_end_matches('-'));
    if exact.exists() {
        return Ok(exact);
    }

    let mut candidates = Vec::new();
    for entry in fs::read_dir(source_boot)
        .with_context(|| format!("failed to read {}", source_boot.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == prefix.trim_end_matches('-') || name.starts_with(prefix) {
            candidates.push(entry.path());
        }
    }
    candidates.sort();
    candidates
        .pop()
        .ok_or_else(|| anyhow::anyhow!("no {} file found in {}", prefix, source_boot.display()))
}

fn copy_slot_boot_files_from_dir(source_boot: &Path, slot_name: &str) -> Result<()> {
    let vmlinuz = newest_boot_file(source_boot, "vmlinuz-")
        .or_else(|_| newest_boot_file(source_boot, "vmlinuz"))?;
    let initrd = newest_boot_file(source_boot, "initrd.img-")
        .or_else(|_| newest_boot_file(source_boot, "initrd.img"))?;
    let slot_dir = Path::new(ROOTFS_BOOT_SLOT_DIR).join(format!("slot-{slot_name}"));
    fs::create_dir_all(&slot_dir)
        .with_context(|| format!("failed to create {}", slot_dir.display()))?;
    fs::copy(&vmlinuz, slot_dir.join("vmlinuz"))
        .with_context(|| format!("failed to copy {}", vmlinuz.display()))?;
    fs::copy(&initrd, slot_dir.join("initrd.img"))
        .with_context(|| format!("failed to copy {}", initrd.display()))?;
    Ok(())
}

fn grub_script_content(layout: &RootfsAbLayout) -> String {
    format!(
        r#"#!/bin/sh
set -e
cat <<'EOF'
menuentry 'DayShield slot A' --id 'dayshield-a' {{
    search --no-floppy --fs-uuid --set=root {boot_uuid}
    linux /dayshield/slot-a/vmlinuz root=UUID={slot_a_uuid} ro quiet splash
    initrd /dayshield/slot-a/initrd.img
}}

menuentry 'DayShield slot B' --id 'dayshield-b' {{
    search --no-floppy --fs-uuid --set=root {boot_uuid}
    linux /dayshield/slot-b/vmlinuz root=UUID={slot_b_uuid} ro quiet splash
    initrd /dayshield/slot-b/initrd.img
}}
EOF
"#,
        boot_uuid = layout.boot_uuid,
        slot_a_uuid = layout.slot_a.uuid,
        slot_b_uuid = layout.slot_b.uuid
    )
}

fn write_grub_saved_default(path: &Path) -> Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let mut lines = Vec::new();
    let mut saw_default = false;
    let mut saw_save_default = false;

    for line in existing.lines() {
        if line.trim_start().starts_with("GRUB_DEFAULT=") {
            lines.push("GRUB_DEFAULT=saved".to_string());
            saw_default = true;
        } else if line.trim_start().starts_with("GRUB_SAVEDEFAULT=") {
            lines.push("GRUB_SAVEDEFAULT=false".to_string());
            saw_save_default = true;
        } else {
            lines.push(line.to_string());
        }
    }

    if !saw_default {
        lines.push("GRUB_DEFAULT=saved".to_string());
    }
    if !saw_save_default {
        lines.push("GRUB_SAVEDEFAULT=false".to_string());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", lines.join("\n")))
        .with_context(|| format!("failed to write {}", path.display()))
}

async fn install_grub_ab_entries(layout: &RootfsAbLayout, inactive_mount: &Path) -> Result<()> {
    let content = grub_script_content(layout);
    fs::write(ROOTFS_GRUB_SCRIPT, &content)
        .with_context(|| format!("failed to write {ROOTFS_GRUB_SCRIPT}"))?;
    let inactive_script = rootfs_target_path(inactive_mount, Path::new(ROOTFS_GRUB_SCRIPT));
    if let Some(parent) = inactive_script.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&inactive_script, &content)
        .with_context(|| format!("failed to write {}", inactive_script.display()))?;

    run_system_command("chmod", &["+x", ROOTFS_GRUB_SCRIPT]).await?;
    let inactive_script_arg = inactive_script.to_string_lossy().to_string();
    run_system_command("chmod", &["+x", &inactive_script_arg]).await?;

    write_grub_saved_default(Path::new("/etc/default/grub"))?;
    write_grub_saved_default(&rootfs_target_path(inactive_mount, Path::new("/etc/default/grub")))?;

    if run_system_command("grub-mkconfig", &["-o", "/boot/grub/grub.cfg"])
        .await
        .is_err()
    {
        run_system_command("update-grub", &[]).await?;
    }

    Ok(())
}

fn mirror_update_state_to_inactive(
    state: &AppState,
    state_file: &UpdateStateFile,
    inactive_mount: &Path,
) -> Result<()> {
    let state_abs = state_path(state);
    let inactive_state_path = rootfs_target_path(inactive_mount, &state_abs);
    write_json_atomic(&inactive_state_path, state_file)
}

fn update_layout_after_format(layout: &mut RootfsAbLayout, slot_name: &str, new_uuid: String) {
    layout.inactive.uuid = new_uuid.clone();
    if slot_name == "a" {
        layout.slot_a.uuid = new_uuid;
    } else {
        layout.slot_b.uuid = new_uuid;
    }
}

async fn stage_rootfs_ab_update(
    state: &AppState,
    artifact_path: &Path,
    version: &str,
    state_file: &mut UpdateStateFile,
    details: &mut Vec<String>,
) -> Result<()> {
    let settings = load_settings(state);
    if !settings.enable_rootfs_ab_updates {
        anyhow::bail!("A/B rootfs updates are disabled in update settings");
    }

    let mut layout = detect_rootfs_ab_layout()
        .context("A/B rootfs layout is not available on this appliance")?;
    let inactive_name = layout.inactive.name.clone();
    let inactive_label = layout.inactive.label.clone();
    let inactive_device = layout.inactive.device.clone();
    let inactive_device_arg = inactive_device.to_string_lossy().to_string();
    let inactive_mount = Path::new(ROOTFS_SLOT_MOUNT_DIR).join(&inactive_name);

    fs::create_dir_all(&inactive_mount)
        .with_context(|| format!("failed to create {}", inactive_mount.display()))?;
    let inactive_mount_arg = inactive_mount.to_string_lossy().to_string();
    let _ = run_system_command("umount", &[&inactive_mount_arg]).await;

    append_operation_log(
        state_file,
        "apply",
        "info",
        format!(
            "Preparing rootfs slot {} on {}",
            inactive_name,
            inactive_device.display()
        ),
        Some("rootfs"),
    );

    run_system_command(
        "mkfs.ext4",
        &["-F", "-L", &inactive_label, &inactive_device_arg],
    )
    .await?;
    let new_uuid = device_uuid(&inactive_device)?;
    update_layout_after_format(&mut layout, &inactive_name, new_uuid);

    run_system_command("mount", &[&inactive_device_arg, &inactive_mount_arg]).await?;

    let result: Result<()> = async {
        let artifact_file = std::fs::File::open(artifact_path)
            .with_context(|| format!("failed to open artifact {}", artifact_path.display()))?;
        let decoder = zstd::stream::Decoder::new(artifact_file)
            .with_context(|| format!("failed to initialize zstd decoder for {}", artifact_path.display()))?;
        let mut archive = tar::Archive::new(decoder);
        archive
            .unpack(&inactive_mount)
            .with_context(|| format!("failed to extract rootfs into {}", inactive_mount.display()))?;

        copy_persistent_state_to_inactive(&inactive_mount).await?;
        write_rootfs_fstab(&inactive_mount, &layout, &layout.inactive)?;
        fs::create_dir_all(rootfs_target_path(&inactive_mount, Path::new("/etc/dayshield")))?;
        fs::write(
            rootfs_target_path(&inactive_mount, Path::new("/etc/dayshield/rootfs-slot")),
            format!("{}\n", layout.inactive.name),
        )?;

        let _ = copy_slot_boot_files_from_dir(Path::new("/boot"), &layout.active.name);
        copy_slot_boot_files_from_dir(&inactive_mount.join("boot"), &layout.inactive.name)?;
        install_grub_ab_entries(&layout, &inactive_mount).await?;

        let rootfs_state = ensure_component_state(state_file, RepoComponent::Rootfs);
        rootfs_state.rollback_version = rootfs_state
            .current_version
            .clone()
            .or_else(|| rootfs_state.last_applied_version.clone());
        rootfs_state.remote_version = Some(version.to_string());
        rootfs_state.update_available = true;
        rootfs_state.last_error = None;

        state_file.pending_reboot = true;
        state_file.pending_appliance_rebuild = false;
        state_file.appliance_rebuild_reason = None;
        state_file.rootfs_update = Some(RootfsUpdateState {
            status: "staged".to_string(),
            target_slot: Some(layout.inactive.name.clone()),
            previous_slot: Some(layout.active.name.clone()),
            target_version: Some(version.to_string()),
            prepared_at: Some(Utc::now().to_rfc3339()),
            booted_at: None,
            confirmed_at: None,
            last_error: None,
        });

        save_state(state, state_file)?;
        mirror_update_state_to_inactive(state, state_file, &inactive_mount)?;

        let target_entry = layout.inactive.grub_entry_id();
        run_system_command("grub-reboot", &[&target_entry]).await?;
        run_system_command("sync", &[]).await?;

        details.push(format!(
            "staged rootfs {} into slot {}; reboot will trial boot {}",
            version, layout.inactive.name, target_entry
        ));
        append_operation_log(
            state_file,
            "apply",
            "success",
            format!(
                "Rootfs {} staged to slot {}; next reboot will trial boot the new slot",
                version, layout.inactive.name
            ),
            Some("rootfs"),
        );
        Ok(())
    }
    .await;

    let _ = run_system_command("umount", &[&inactive_mount_arg]).await;

    result
}

async fn build_component_status(
    settings: &UpdateSettings,
    state_file: &UpdateStateFile,
    component: RepoComponent,
) -> ComponentUpdateStatus {
    let (repo_path, remote_url, branch) = component_config(settings, component);
    let saved = find_component_state(state_file, component);

    // Registry mode reads cached state from the most recent explicit check
    // (manual or scheduled) and does not query the registry during status polls.
    if settings.update_mode == "registry" {
        return ComponentUpdateStatus {
            component: component.as_str().to_string(),
            repo_path,
            branch,
            valid_repo: true,
            dirty_worktree: false,
            current_commit: None,
            remote_commit: None,
            current_version: current_version_baseline(saved),
            remote_version: saved.and_then(|s| s.remote_version.clone()),
            update_available: saved.map(|s| s.update_available).unwrap_or(false),
            rollback_commit: saved.and_then(|s| s.rollback_commit.clone()),
            last_applied_commit: None,
            last_applied_version: saved.and_then(|s| s.last_applied_version.clone()),
            last_error: saved.and_then(|s| s.last_error.clone()),
        };
    }

    // Non-registry mode is no longer used by default but remains available if configured.
    let inspect_result = inspect_repo(&repo_path, &remote_url, &branch).await;

    match inspect_result {
        Ok((current, remote, dirty)) => ComponentUpdateStatus {
            component: component.as_str().to_string(),
            repo_path,
            branch,
            valid_repo: true,
            dirty_worktree: dirty,
            update_available: current != remote,
            current_commit: Some(current),
            remote_commit: Some(remote),
            current_version: saved.and_then(|s| s.current_version.clone()),
            remote_version: None,
            rollback_commit: saved.and_then(|s| s.rollback_commit.clone()),
            last_applied_commit: saved.and_then(|s| s.last_applied_commit.clone()),
            last_applied_version: saved.and_then(|s| s.last_applied_version.clone()),
            last_error: saved.and_then(|s| s.last_error.clone()),
        },
        Err(err) => ComponentUpdateStatus {
            component: component.as_str().to_string(),
            repo_path,
            branch,
            valid_repo: false,
            dirty_worktree: false,
            update_available: false,
            current_commit: None,
            remote_commit: None,
            current_version: saved.and_then(|s| s.current_version.clone()),
            remote_version: None,
            rollback_commit: saved.and_then(|s| s.rollback_commit.clone()),
            last_applied_commit: saved.and_then(|s| s.last_applied_commit.clone()),
            last_applied_version: saved.and_then(|s| s.last_applied_version.clone()),
            last_error: Some(err.to_string()),
        },
    }
}

pub async fn get_status(state: &AppState) -> UpdatesStatus {
    let settings = load_settings(state);
    let state_file = load_state(state);

    let core = build_component_status(
        &settings,
        &state_file,
        RepoComponent::Core,
    )
    .await;
    let ui = build_component_status(
        &settings,
        &state_file,
        RepoComponent::Ui,
    )
    .await;
    let rootfs = build_component_status(
        &settings,
        &state_file,
        RepoComponent::Rootfs,
    )
    .await;

    let components = vec![core, ui, rootfs];
    let available_update_count = components.iter().filter(|c| c.update_available).count();
    let rootfs_slot_status = rootfs_slot_status(&settings, &state_file);

    UpdatesStatus {
        settings,
        last_checked_at: state_file.last_checked_at,
        last_applied_at: state_file.last_applied_at,
        pending_reboot: state_file.pending_reboot,
        pending_appliance_rebuild: state_file.pending_appliance_rebuild,
        appliance_rebuild_reason: state_file.appliance_rebuild_reason,
        appliance_rebuild_marked_at: state_file.appliance_rebuild_marked_at,
        rootfs_slot_status,
        rootfs_update: state_file.rootfs_update,
        components,
        available_update_count: if available_update_count > 0 {
            Some(available_update_count)
        } else {
            None
        },
        operation_logs: state_file.operation_logs,
    }
}

enum CheckTrigger {
    Manual,
    Scheduled,
}

impl CheckTrigger {
    fn as_str(&self) -> &'static str {
        match self {
            CheckTrigger::Manual => "manual",
            CheckTrigger::Scheduled => "scheduled",
        }
    }
}

pub async fn check_for_updates(state: &AppState) -> Result<UpdatesStatus> {
    check_for_updates_with_trigger(state, CheckTrigger::Manual).await
}

async fn check_for_updates_with_trigger(
    state: &AppState,
    trigger: CheckTrigger,
) -> Result<UpdatesStatus> {
    let _guard = op_lock().lock().await;
    let source = trigger.as_str();

    let now = Utc::now().to_rfc3339();
    let mut state_file = load_state(state);
    state_file.last_checked_at = Some(now.clone());
    append_operation_log(
        &mut state_file,
        "check",
        "info",
        format!("{source} update check started"),
        None,
    );
    save_state(state, &state_file)?;

    // Registry-based update checking (artifact distribution)
    if let Err(err) = check_for_updates_registry(state).await {
        let mut failed_state = load_state(state);
        append_operation_log(
            &mut failed_state,
            "check",
            "error",
            format!("{source} update check failed: {err}"),
            None,
        );
        save_state(state, &failed_state)?;
        return Err(err);
    }

    let checked_status = get_status(state).await;
    let available_components: Vec<String> = checked_status
        .components
        .iter()
        .filter(|component| component.update_available)
        .map(|component| component.component.clone())
        .collect();

    let mut done_state = load_state(state);
    if available_components.is_empty() {
        append_operation_log(
            &mut done_state,
            "check",
            "info",
            format!("{source} update check completed: no updates found"),
            None,
        );
    } else {
        append_operation_log(
            &mut done_state,
            "check",
            "success",
            format!(
                "{source} update check completed: updates found for {}",
                available_components.join(", ")
            ),
            None,
        );
    }
    save_state(state, &done_state)?;
    info!("updates: registry check completed successfully");

    Ok(get_status(state).await)
}

/// Check registry for available component updates
async fn check_for_updates_registry(state: &AppState) -> Result<()> {
    let settings = load_settings(state);
    let mut state_file = load_state(state);

    match query_registry(&settings.registry_url).await {
        Ok(manifest) => {
            let mut seen_components = std::collections::HashSet::new();
            // Bootstrap tracked current version once for legacy systems that
            // predate version tracking. This prevents perpetual false positives.
            for artifact in &manifest.components {
                let comp = match artifact.component.as_str() {
                    "core" => RepoComponent::Core,
                    "ui" => RepoComponent::Ui,
                    "rootfs" => RepoComponent::Rootfs,
                    _ => continue,
                };
                seen_components.insert(comp.as_str().to_string());

                let update_available = {
                    let comp_state = ensure_component_state(&mut state_file, comp);
                    if comp_state.current_version.is_none() {
                        if let Some(applied) = comp_state.last_applied_version.clone() {
                            comp_state.current_version = Some(applied);
                        } else {
                            comp_state.current_version = Some(built_appliance_version());
                            info!(
                                component = %artifact.component,
                                version = %comp_state.current_version.as_deref().unwrap_or("unknown"),
                                "updates: bootstrapped current version baseline from registry"
                            );
                        }
                    }

                    let update_available = comp_state
                        .current_version
                        .as_ref()
                        .map(|current| current != &artifact.version)
                        .unwrap_or(false);
                    comp_state.remote_version = Some(artifact.version.clone());
                    comp_state.update_available = update_available;
                    comp_state.last_error = None;
                    update_available
                };

                if matches!(comp, RepoComponent::Rootfs) {
                    if update_available {
                        let slot_status = rootfs_slot_status(&settings, &state_file);
                        if slot_status.as_ref().map(|s| s.supported).unwrap_or(false) {
                            clear_appliance_rebuild_required(&mut state_file);
                        } else {
                            let reason = slot_status
                                .and_then(|s| s.reason)
                                .unwrap_or_else(|| "A/B rootfs slot layout is not available".to_string());
                            state_file.pending_appliance_rebuild = true;
                            state_file.appliance_rebuild_reason = Some(format!(
                                "Root filesystem image v{} is available, but in-place rootfs updates require an A/B root layout with shared /boot: {}.",
                                artifact.version, reason
                            ));
                            state_file.appliance_rebuild_marked_at = None;
                        }
                    } else {
                        clear_appliance_rebuild_required(&mut state_file);
                    }
                }

                info!(
                    component = %artifact.component,
                    version = %artifact.version,
                    update_available,
                    "updates: registry has available version"
                );
            }

            for component in [RepoComponent::Core, RepoComponent::Ui, RepoComponent::Rootfs] {
                if seen_components.contains(component.as_str()) {
                    continue;
                }

                let comp_state = ensure_component_state(&mut state_file, component);
                comp_state.remote_version = None;
                comp_state.update_available = false;
                comp_state.last_error = None;
                info!(
                    component = component.as_str(),
                    "updates: component not listed in registry manifest"
                );
            }

            if !seen_components.contains(RepoComponent::Rootfs.as_str()) {
                clear_appliance_rebuild_required(&mut state_file);
            }
            
            save_state(state, &state_file)?;
            Ok(())
        },
        Err(err) => {
            warn!(error = %err, "updates: failed to query registry");
            Err(err)
        }
    }
}

/// Apply updates from artifact registry (atomic transaction)
async fn apply_updates_registry(
    state: &AppState,
    components_to_update: Vec<RepoComponent>,
) -> Result<UpdatesActionResult> {
    let settings = load_settings(state);
    let mut state_file = load_state(state);
    let mut details = Vec::new();
    append_operation_log(
        &mut state_file,
        "apply",
        "info",
        "Artifact update apply started",
        None,
    );
    save_state(state, &state_file)?;
    
    // Step 1: Query registry for latest versions
    let manifest = query_registry(&settings.registry_url).await?;
    
    // Step 2: Download all artifacts to staging area
    let staging_dir = PathBuf::from(ARTIFACT_STAGING_DIR);
    fs::create_dir_all(&staging_dir)?;
    
    let transaction_id = uuid::Uuid::new_v4().to_string();
    let transaction_staging = staging_dir.join(&transaction_id);
    fs::create_dir_all(&transaction_staging)?;
    
    let mut downloads = Vec::new();
    
    for comp in &components_to_update {
        let artifact_opt = manifest.components.iter().find(|a| {
            match comp {
                RepoComponent::Core => a.component == "core",
                RepoComponent::Ui => a.component == "ui",
                RepoComponent::Rootfs => a.component == "rootfs",
            }
        });
        
        if let Some(artifact) = artifact_opt {
            let dest = transaction_staging.join(format!("{}-{}.tar.zst", &artifact.component, &artifact.version));
            
            download_artifact(&artifact.download_url, &dest).await?;
            verify_checksum(&dest, &artifact.checksum_sha256)?;
            
            downloads.push((artifact.component.clone(), artifact.version.clone(), dest));
            details.push(format!("downloaded and verified {}-{}", &artifact.component, &artifact.version));
            append_operation_log(
                &mut state_file,
                "apply",
                "info",
                format!("Downloaded and verified {}-{}", &artifact.component, &artifact.version),
                Some(&artifact.component),
            );
        } else {
            append_operation_log(
                &mut state_file,
                "apply",
                "info",
                format!(
                    "No registry artifact entry for '{}' in current manifest; skipping",
                    comp.as_str()
                ),
                Some(comp.as_str()),
            );
        }
    }

    if downloads.is_empty() {
        let selected = components_to_update
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let message =
            format!("no matching artifacts were published for selected components: {selected}");
        details.push(message.clone());
        append_operation_log(&mut state_file, "apply", "info", &message, None);
        save_state(state, &state_file)?;
        let _ = fs::remove_dir_all(&transaction_staging);
        return Ok(UpdatesActionResult {
            operation: "apply".to_string(),
            success: true,
            message,
            details,
            status: get_status(state).await,
        });
    }

    let config_snapshot = match snapshot_config_for_rollback(state, settings.encrypt_update_config_backups) {
        Ok(path) => path,
        Err(err) => {
            let msg = format!("failed to create config backup snapshot: {err}");
            append_operation_log(&mut state_file, "apply", "error", &msg, None);
            save_state(state, &state_file)?;
            return Ok(UpdatesActionResult {
                operation: "apply".to_string(),
                success: false,
                message: msg.clone(),
                details: vec![msg],
                status: get_status(state).await,
            });
        }
    };

    state_file.config_rollback_path = Some(config_snapshot.to_string_lossy().to_string());
    append_operation_log(
        &mut state_file,
        "apply",
        "info",
        format!("Created config backup archive: {}", config_snapshot.display()),
        None,
    );
    save_state(state, &state_file)?;
    
    // Step 3: Backup currently deployed runtime artifacts for rollback.
    for comp in &components_to_update {
        if !component_supports_runtime_deploy(*comp) {
            continue;
        }

        if let Err(err) = snapshot_runtime_for_rollback(*comp) {
            let msg = format!("failed to create rollback snapshot for {}: {}", comp.as_str(), err);
            append_operation_log(&mut state_file, "apply", "error", &msg, Some(comp.as_str()));
            save_state(state, &state_file)?;
            return Ok(UpdatesActionResult {
                operation: "apply".to_string(),
                success: false,
                message: msg.clone(),
                details: vec![msg],
                status: get_status(state).await,
            });
        }

        let entry = ensure_component_state(&mut state_file, *comp);
        entry.rollback_version = entry
            .current_version
            .clone()
            .or_else(|| entry.last_applied_version.clone());
    }

    details.push("created backup snapshots".to_string());
    append_operation_log(
        &mut state_file,
        "apply",
        "info",
        "Created backup snapshots",
        None,
    );
    
    // Step 4: Apply artifacts atomically
    for (component_name, version, artifact_path) in &downloads {
        let comp = match component_name.as_str() {
            "core" => RepoComponent::Core,
            "ui" => RepoComponent::Ui,
            "rootfs" => RepoComponent::Rootfs,
            _ => continue,
        };

        if matches!(comp, RepoComponent::Rootfs) {
            match stage_rootfs_ab_update(state, artifact_path, version, &mut state_file, &mut details).await {
                Ok(()) => continue,
                Err(err) => {
                    details.push(format!("FAILED to stage rootfs: {}", err));
                    append_operation_log(
                        &mut state_file,
                        "apply",
                        "error",
                        format!("Failed to stage rootfs: {}", err),
                        Some("rootfs"),
                    );
                    if let Some(entry) = state_file.components.iter_mut().find(|c| c.component == "rootfs") {
                        entry.last_error = Some(err.to_string());
                    }
                    save_state(state, &state_file)?;

                    return Ok(UpdatesActionResult {
                        operation: "apply".to_string(),
                        success: false,
                        message: format!("failed to stage rootfs update: {}", err),
                        details,
                        status: get_status(state).await,
                    });
                }
            }
        }
        
        match extract_and_deploy_artifact(comp, artifact_path, None).await {
            Ok(_) => {
                let previous_version = {
                    let entry = ensure_component_state(&mut state_file, comp);
                    entry.current_version.clone()
                };
                let entry = ensure_component_state(&mut state_file, comp);
                entry.current_version = Some(version.clone());
                entry.last_applied_version = Some(version.clone());
                entry.last_error = None;
                details.push(format!("deployed {}-{}", component_name, version));
                append_operation_log_with_versions(
                    &mut state_file,
                    "apply",
                    "success",
                    match previous_version.as_deref() {
                        Some(prev) => format!("Deployed {} from v{} to v{}", component_name, prev, version),
                        None => format!("Deployed {} to v{}", component_name, version),
                    },
                    Some(component_name),
                    previous_version.as_deref(),
                    Some(version.as_str()),
                );
            },
            Err(err) => {
                details.push(format!("FAILED to deploy {}: {}", component_name, err));
                append_operation_log(
                    &mut state_file,
                    "apply",
                    "error",
                    format!("Failed to deploy {}: {}", component_name, err),
                    Some(component_name),
                );
                save_state(state, &state_file)?;
                
                return Ok(UpdatesActionResult {
                    operation: "apply".to_string(),
                    success: false,
                    message: format!("failed to apply updates: {}", err),
                    details,
                    status: get_status(state).await,
                });
            }
        }
    }
    
    // Step 5: Always verify deployment health after applying updates
    let runtime_downloaded = downloads.iter().any(|(component_name, _, _)| {
        matches!(component_name.as_str(), "core" | "ui")
    });
    if runtime_downloaded {
        if let Err(err) = ensure_critical_services_healthy().await {
            details.push(format!("post-apply service health check failed: {}", err));
            append_operation_log(
                &mut state_file,
                "apply",
                "error",
                format!("Post-apply service health check failed: {}", err),
                None,
            );
            save_state(state, &state_file)?;
            
            return Ok(UpdatesActionResult {
                operation: "apply".to_string(),
                success: false,
                message: "post-apply service health check failed".to_string(),
                details,
                status: get_status(state).await,
            });
        }
        details.push("post-apply service health check passed".to_string());
        append_operation_log(
            &mut state_file,
            "apply",
            "success",
            "Post-apply service health check passed",
            None,
        );
    }
    
    // Step 6: Mark transaction complete
    state_file.last_applied_at = Some(Utc::now().to_rfc3339());

    append_operation_log(
        &mut state_file,
        "apply",
        "success",
        "Artifact update apply completed",
        None,
    );
    
    save_state(state, &state_file)?;
    
    // Cleanup staging directory
    let _ = fs::remove_dir_all(&transaction_staging);
    
    Ok(UpdatesActionResult {
        operation: "apply".to_string(),
        success: true,
        message: if components_to_update.iter().any(|c| matches!(c, RepoComponent::Rootfs)) {
            "rootfs update staged; reboot required to trial boot the new slot".to_string()
        } else {
            "updates applied successfully".to_string()
        },
        details,
        status: get_status(state).await,
    })
}

/// Helper: check if a partial component apply violates atomicity constraints.
/// Returns an error if the user is trying to apply only some components when multiple have updates available.
async fn check_atomicity_constraint(
    state: &AppState,
    selected_components: &[RepoComponent],
    force_partial_apply: bool,
) -> Result<()> {
    if force_partial_apply {
        // Bypass the check if explicitly forced by operator
        return Ok(());
    }

    if selected_components
        .iter()
        .any(|component| matches!(component, RepoComponent::Rootfs))
    {
        return Ok(());
    }

    let status = get_status(state).await;
    let available_components: Vec<&str> = status
        .components
        .iter()
        .filter(|c| c.update_available)
        .filter_map(|c| match c.component.as_str() {
            "core" => Some(RepoComponent::Core),
            "ui" => Some(RepoComponent::Ui),
            "rootfs" => Some(RepoComponent::Rootfs),
            _ => None,
        })
        .filter(|component| component_supports_runtime_deploy(*component))
        .map(|component| component.as_str())
        .collect();
    let available_count = available_components.len();
    let selected_count = selected_components
        .iter()
        .filter(|component| component_supports_runtime_deploy(**component))
        .count();

    // If multiple components have updates but user is selecting only some, that's a violation
    if available_count > 1 && selected_count < available_count {
        return Err(anyhow::anyhow!(
            "Update atomicity violation: {} components have available updates ({}), but only {} were selected. \
             Either apply all available updates, or use forcePartialApply to override this check.",
            available_count,
            available_components.join(", "),
            selected_count
        ));
    }

    Ok(())
}

pub async fn apply_updates(
    state: &AppState,
    component: UpdateComponent,
    force_partial_apply: bool,
) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;

    let selected = RepoComponent::from_update_component(component);
    ensure_registry_updatable_selection(&selected)?;

    // Check atomicity constraint before proceeding
    check_atomicity_constraint(state, &selected, force_partial_apply).await?;

    // Registry-based update application (artifact distribution)
    apply_updates_registry(state, selected).await
}

async fn rollback_rootfs_update(state: &AppState) -> Result<UpdatesActionResult> {
    let mut state_file = load_state(state);
    let update = state_file.rootfs_update.clone();
    let previous_slot = update
        .as_ref()
        .and_then(|state| state.previous_slot.clone())
        .ok_or_else(|| anyhow::anyhow!("no previous rootfs slot is recorded for rollback"))?;

    let entry = format!("{ROOTFS_GRUB_ENTRY_PREFIX}{previous_slot}");
    run_system_command("grub-reboot", &[&entry]).await?;
    state_file.pending_reboot = true;
    state_file.rootfs_update = Some(RootfsUpdateState {
        status: "rollbackScheduled".to_string(),
        last_error: None,
        ..update.unwrap_or(RootfsUpdateState {
            status: "rollbackScheduled".to_string(),
            target_slot: None,
            previous_slot: Some(previous_slot.clone()),
            target_version: None,
            prepared_at: None,
            booted_at: None,
            confirmed_at: None,
            last_error: None,
        })
    });
    append_operation_log(
        &mut state_file,
        "rollback",
        "success",
        format!("Rootfs rollback scheduled to slot {previous_slot}; reboot required"),
        Some("rootfs"),
    );
    save_state(state, &state_file)?;

    Ok(UpdatesActionResult {
        operation: "rollback".to_string(),
        success: true,
        message: "rootfs rollback scheduled; reboot required".to_string(),
        details: vec![format!("scheduled next boot into rootfs slot {previous_slot}")],
        status: get_status(state).await,
    })
}

pub async fn rollback_updates(
    state: &AppState,
    component: UpdateComponent,
    force_partial_apply: bool,
) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;

    let settings = load_settings(state);
    let mut state_file = load_state(state);
    let selected = RepoComponent::from_update_component(component);
    ensure_registry_updatable_selection(&selected)?;

    if selected.len() == 1 && matches!(selected[0], RepoComponent::Rootfs) {
        return rollback_rootfs_update(state).await;
    }

    // Check atomicity constraint before proceeding
    check_atomicity_constraint(state, &selected, force_partial_apply).await?;

    let mut details = Vec::new();
    let mut rolled_back_components: usize = 0;
    append_operation_log(
        &mut state_file,
        "rollback",
        "info",
        "Rollback started",
        None,
    );

    info!(component = ?component, "updates: rollback started");

    for comp in selected {
        if settings.update_mode == "registry" {
            let previous_version = {
                let entry = ensure_component_state(&mut state_file, comp);
                entry.rollback_version.clone()
            };

            let target_version = match previous_version {
                Some(version) => version,
                None => {
                    let msg = format!(
                        "{}: no rollback snapshot/version available",
                        comp.as_str()
                    );
                    details.push(msg.clone());
                    append_operation_log(&mut state_file, "rollback", "error", msg.clone(), Some(comp.as_str()));
                    continue;
                }
            };

            let current_before = {
                let entry = ensure_component_state(&mut state_file, comp);
                entry.current_version.clone()
            };

            if let Err(err) = restore_runtime_from_snapshot(comp) {
                let msg = format!("{}: rollback failed ({err})", comp.as_str());
                {
                    let entry = ensure_component_state(&mut state_file, comp);
                    entry.last_error = Some(msg.clone());
                }
                append_operation_log(&mut state_file, "rollback", "error", msg.clone(), Some(comp.as_str()));
                save_state(state, &state_file)?;
                let status = get_status(state).await;
                return Ok(UpdatesActionResult {
                    operation: "rollback".to_string(),
                    success: false,
                    message: "rollback failed".to_string(),
                    details: vec![msg],
                    status,
                });
            }

            {
                let entry = ensure_component_state(&mut state_file, comp);
                entry.current_version = Some(target_version.clone());
                entry.last_applied_version = Some(target_version.clone());
                entry.rollback_version = current_before.clone();
                entry.last_error = None;
            }

            details.push(format!("{}: rolled back to {}", comp.as_str(), target_version));
            append_operation_log_with_versions(
                &mut state_file,
                "rollback",
                "success",
                match current_before.as_deref() {
                    Some(prev) => format!(
                        "Rolled back {} from v{} to v{}",
                        comp.as_str(),
                        prev,
                        target_version
                    ),
                    None => format!("Rolled back {} to v{}", comp.as_str(), target_version),
                },
                Some(comp.as_str()),
                current_before.as_deref(),
                Some(target_version.as_str()),
            );
            rolled_back_components += 1;
            continue;
        }

        let (repo_path, _remote_url, _branch) = component_config(&settings, comp);

        if let Err(err) = ensure_repo_writable(&repo_path) {
            let msg = format!(
                "{}: repository is read-only; rollback requires writable repo ({err})",
                comp.as_str()
            );
            {
                let entry = ensure_component_state(&mut state_file, comp);
                entry.last_error = Some(msg.clone());
            }
            append_operation_log(&mut state_file, "rollback", "error", msg.clone(), Some(comp.as_str()));
            save_state(state, &state_file)?;
            let status = get_status(state).await;
            return Ok(UpdatesActionResult {
                operation: "rollback".to_string(),
                success: false,
                message: "rollback failed".to_string(),
                details: vec![msg],
                status,
            });
        }

        let target = {
            let entry = ensure_component_state(&mut state_file, comp);
            match &entry.rollback_commit {
                Some(c) => c.clone(),
                None => {
                    details.push(format!("{}: no rollback commit available", comp.as_str()));
                    continue;
                }
            }
        };

        let current = run_git(&repo_path, &["rev-parse", "HEAD"]).await?;
        let result = reset_and_optionally_deploy(
            &settings,
            &mut state_file,
            comp,
            &target,
            settings.deploy_runtime_after_apply,
            &mut details,
        )
        .await;

        if let Err(err) = result {
            let msg = format!("{}: rollback failed ({err})", comp.as_str());
            {
                let entry = ensure_component_state(&mut state_file, comp);
                entry.last_error = Some(msg.clone());
            }
            append_operation_log(&mut state_file, "rollback", "error", msg.clone(), Some(comp.as_str()));
            save_state(state, &state_file)?;
            let status = get_status(state).await;
            return Ok(UpdatesActionResult {
                operation: "rollback".to_string(),
                success: false,
                message: "rollback failed".to_string(),
                details: vec![msg],
                status,
            });
        }

        {
            let entry = ensure_component_state(&mut state_file, comp);
            entry.rollback_commit = Some(current);
            entry.last_error = None;
        }
        append_operation_log(
            &mut state_file,
            "rollback",
            "success",
            format!("Rolled back {}", comp.as_str()),
            Some(comp.as_str()),
        );
        rolled_back_components += 1;
    }

    if rolled_back_components == 0 {
        append_operation_log(
            &mut state_file,
            "rollback",
            "error",
            "Rollback failed: no components could be rolled back",
            None,
        );
        save_state(state, &state_file)?;
        let status = get_status(state).await;
        return Ok(UpdatesActionResult {
            operation: "rollback".to_string(),
            success: false,
            message: "rollback failed: no rollback snapshot available".to_string(),
            details,
            status,
        });
    }

    if settings.update_mode == "registry" {
        let config_snapshot = state_file.config_rollback_path.clone();
        let snapshot_path = match config_snapshot {
            Some(path) => PathBuf::from(path),
            None => {
                append_operation_log(
                    &mut state_file,
                    "rollback",
                    "error",
                    "Rollback failed: no config backup archive available",
                    None,
                );
                save_state(state, &state_file)?;
                let status = get_status(state).await;
                return Ok(UpdatesActionResult {
                    operation: "rollback".to_string(),
                    success: false,
                    message: "rollback failed: no config backup archive available".to_string(),
                    details,
                    status,
                });
            }
        };

        if let Err(err) = restore_config_from_snapshot(state, &snapshot_path) {
            let msg = format!("failed to restore config snapshot ({}): {}", snapshot_path.display(), err);
            append_operation_log(&mut state_file, "rollback", "error", &msg, None);
            save_state(state, &state_file)?;
            let status = get_status(state).await;
            return Ok(UpdatesActionResult {
                operation: "rollback".to_string(),
                success: false,
                message: "rollback failed".to_string(),
                details: vec![msg],
                status,
            });
        }

        append_operation_log(
            &mut state_file,
            "rollback",
            "success",
            format!("Restored config backup archive: {}", snapshot_path.display()),
            None,
        );
        state_file.config_rollback_path = None;
    }

    state_file.last_applied_at = Some(Utc::now().to_rfc3339());
    state_file.pending_reboot = false;
    append_operation_log(
        &mut state_file,
        "rollback",
        "success",
        "Rollback completed",
        None,
    );
    save_state(state, &state_file)?;

    info!("updates: rollback completed");

    let status = get_status(state).await;
    Ok(UpdatesActionResult {
        operation: "rollback".to_string(),
        success: true,
        message: "rollback completed".to_string(),
        details,
        status,
    })
}

pub async fn validate_updates(
    state: &AppState,
    component: UpdateComponent,
    force_partial_apply: bool,
) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;

    let selected_repos = RepoComponent::from_update_component(component);
    ensure_registry_updatable_selection(&selected_repos)?;

    // Check atomicity constraint before proceeding
    check_atomicity_constraint(state, &selected_repos, force_partial_apply).await?;

    let status = get_status(state).await;
    let mut details = Vec::new();
    let mut success = true;
    let mut warning_count: usize = 0;

    let selected = selected_repos
        .into_iter()
        .map(|c| c.as_str().to_string())
        .collect::<Vec<_>>();

    for comp in &status.components {
        if !selected.iter().any(|s| s == &comp.component) {
            continue;
        }

        if !comp.valid_repo {
            success = false;
            details.push(format!("{}: repository is not valid", comp.component));
            continue;
        }

        // Registry mode: validate using versions (current_commit is None)
        if comp.current_commit.is_none() && comp.current_version.is_some() {
            match (&comp.current_version, &comp.last_applied_version) {
                (Some(current), Some(applied)) if current == applied => {
                    details.push(format!("{}: registry validation ok ({})", comp.component, current));
                }
                (Some(current), Some(applied)) => {
                    success = false;
                    details.push(format!(
                        "{}: version mismatch (current {}, expected {})",
                        comp.component, current, applied
                    ));
                }
                (Some(current), None) => {
                    warning_count += 1;
                    details.push(format!(
                        "{}: no applied baseline, current version {}",
                        comp.component, current
                    ));
                }
                _ => {
                    success = false;
                    details.push(format!("{}: unable to determine current version", comp.component));
                }
            }
        } else {
            // Git mode: validate using commits
            match (&comp.current_commit, &comp.last_applied_commit) {
                (Some(current), Some(applied)) if current == applied => {
                    details.push(format!("{}: git validation ok ({})", comp.component, short_sha(current)));
                }
                (Some(current), Some(applied)) => {
                    success = false;
                    details.push(format!(
                        "{}: validation mismatch (current {}, expected {})",
                        comp.component,
                        short_sha(current),
                        short_sha(applied)
                    ));
                }
                (Some(current), None) => {
                    warning_count += 1;
                    details.push(format!(
                        "{}: no applied baseline, current {}",
                        comp.component,
                        short_sha(current)
                    ));
                }
                _ => {
                    success = false;
                    details.push(format!("{}: unable to read current commit", comp.component));
                }
            }
        }

        let repo_component = match comp.component.as_str() {
            "core" => Some(RepoComponent::Core),
            "ui" => Some(RepoComponent::Ui),
            _ => None,
        };

        if let Some(repo_component) = repo_component {
            if !component_supports_runtime_deploy(repo_component) {
                continue;
            }

            let marker = load_runtime_marker(repo_component);
            match (&comp.current_commit, marker) {
                (Some(current), Some(deployed)) if current == &deployed => {
                    details.push(format!(
                        "{}: runtime validation ok ({})",
                        comp.component,
                        short_sha(current)
                    ));
                }
                (Some(current), Some(deployed)) => {
                    success = false;
                    details.push(format!(
                        "{}: runtime mismatch (deployed {}, expected {})",
                        comp.component,
                        short_sha(&deployed),
                        short_sha(current)
                    ));
                }
                (Some(current), None) => {
                    warning_count += 1;
                    details.push(format!(
                        "{}: runtime marker missing (expected {})",
                        comp.component,
                        short_sha(current)
                    ));
                }
                _ => {}
            }
        }
    }

    info!(success, "updates: validation completed");

    let core_version = status
        .components
        .iter()
        .find(|c| c.component == "core")
        .and_then(|c| c.current_version.clone());
    let ui_version = status
        .components
        .iter()
        .find(|c| c.component == "ui")
        .and_then(|c| c.current_version.clone());

    let validation_summary = if success {
        match (core_version.as_deref(), ui_version.as_deref()) {
            (Some(core), Some(ui)) => {
                format!("Validation completed successfully (Core v{core}/UI v{ui})")
            }
            _ => "Validation completed successfully".to_string(),
        }
    } else {
        "Validation failed".to_string()
    };

    let mut state_file = load_state(state);
    append_operation_log_with_versions(
        &mut state_file,
        "validate",
        if success { "success" } else { "error" },
        validation_summary,
        None,
        None,
        None,
    );
    save_state(state, &state_file)?;

    Ok(UpdatesActionResult {
        operation: "validate".to_string(),
        success,
        message: if success && warning_count > 0 {
            format!("validation passed with {warning_count} note(s)")
        } else if success {
            "validation passed".to_string()
        } else {
            "validation failed".to_string()
        },
        details,
        status,
    })
}

fn short_sha(commit: &str) -> String {
    commit.chars().take(8).collect()
}

fn ensure_repo_writable(repo_path: &str) -> Result<()> {
    use std::io::Write;

    let git_dir = Path::new(repo_path).join(".git");
    if !git_dir.exists() {
        anyhow::bail!("missing git directory: {}", git_dir.display());
    }

    let probe = git_dir.join(".dayshield-write-probe");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&probe)
        .with_context(|| format!("repository is not writable: {}", repo_path))?;

    file.write_all(b"probe")
        .with_context(|| format!("repository is not writable: {}", repo_path))?;

    let _ = std::fs::remove_file(&probe);
    Ok(())
}

pub fn start_rootfs_boot_finalizer(state: std::sync::Arc<AppState>) {
    tokio::spawn(async move {
        if let Err(err) = reconcile_rootfs_boot_state(&state).await {
            warn!(error = %err, "updates: rootfs boot finalizer failed");
        }
    });
}

fn rootfs_confirm_delay() -> Duration {
    env::var("DAYSHIELD_ROOTFS_CONFIRM_DELAY_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(ROOTFS_BOOT_CONFIRM_DELAY_SECS))
}

fn load_rootfs_iso_upgrade_marker(state: &AppState) -> Result<Option<RootfsUpdateState>> {
    let path = rootfs_iso_upgrade_marker_path(state);
    if !path.exists() {
        return Ok(None);
    }
    let payload = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let update: RootfsUpdateState = serde_json::from_str(&payload)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(update))
}

fn remove_rootfs_iso_upgrade_marker(state: &AppState) {
    let path = rootfs_iso_upgrade_marker_path(state);
    if path.exists() {
        let _ = fs::remove_file(path);
    }
}

async fn reconcile_rootfs_boot_state(state: &AppState) -> Result<()> {
    let mut state_file = load_state(state);
    let update = match load_rootfs_iso_upgrade_marker(state)? {
        Some(update) if update.status == "staged" || update.status == "booted" => {
            state_file.rootfs_update = Some(update.clone());
            append_operation_log(
                &mut state_file,
                "apply",
                "info",
                "Loaded rootfs upgrade state staged by ISO installer",
                Some("rootfs"),
            );
            save_state(state, &state_file)?;
            update
        }
        _ => match state_file.rootfs_update.clone() {
            Some(update) if update.status == "staged" || update.status == "booted" => update,
            _ => return Ok(()),
        },
    };
    let target_slot = match update.target_slot.clone() {
        Some(slot) => slot,
        None => return Ok(()),
    };

    let layout = match detect_rootfs_ab_layout() {
        Ok(layout) => layout,
        Err(err) => {
            warn!(error = %err, "updates: cannot reconcile rootfs boot state without A/B layout");
            return Ok(());
        }
    };

    if layout.active.name != target_slot {
        return Ok(());
    }

    let mut booted_update = update.clone();
    booted_update.status = "booted".to_string();
    if booted_update.booted_at.is_none() {
        booted_update.booted_at = Some(Utc::now().to_rfc3339());
    }
    state_file.rootfs_update = Some(booted_update.clone());
    append_operation_log(
        &mut state_file,
        "apply",
        "info",
        format!("Booted rootfs slot {target_slot}; waiting for health confirmation"),
        Some("rootfs"),
    );
    save_state(state, &state_file)?;

    tokio::time::sleep(rootfs_confirm_delay()).await;

    let mut state_file = load_state(state);
    match ensure_critical_services_healthy().await {
        Ok(()) => {
            let entry_id = layout.active.grub_entry_id();
            run_system_command("grub-set-default", &[&entry_id]).await?;

            let target_version = state_file
                .rootfs_update
                .as_ref()
                .and_then(|update| update.target_version.clone());
            let rootfs = ensure_component_state(&mut state_file, RepoComponent::Rootfs);
            if let Some(version) = target_version.clone() {
                rootfs.current_version = Some(version.clone());
                rootfs.last_applied_version = Some(version);
            }
            rootfs.update_available = false;
            rootfs.last_error = None;

            if let Some(update) = &mut state_file.rootfs_update {
                update.status = "confirmed".to_string();
                update.confirmed_at = Some(Utc::now().to_rfc3339());
                update.last_error = None;
            }
            state_file.pending_reboot = false;
            state_file.pending_appliance_rebuild = false;
            state_file.appliance_rebuild_reason = None;
            state_file.last_applied_at = Some(Utc::now().to_rfc3339());
            append_operation_log(
                &mut state_file,
                "apply",
                "success",
                format!("Rootfs slot {target_slot} confirmed healthy and set as default"),
                Some("rootfs"),
            );
            save_state(state, &state_file)?;
            remove_rootfs_iso_upgrade_marker(state);
        }
        Err(err) => {
            let previous_slot = state_file
                .rootfs_update
                .as_ref()
                .and_then(|update| update.previous_slot.clone());
            let message = format!("Rootfs slot {target_slot} failed health confirmation: {err}");
            if let Some(update) = &mut state_file.rootfs_update {
                update.status = "rollbackScheduled".to_string();
                update.last_error = Some(message.clone());
            }
            if let Some(rootfs) = state_file.components.iter_mut().find(|c| c.component == "rootfs") {
                rootfs.last_error = Some(message.clone());
            }
            append_operation_log(
                &mut state_file,
                "apply",
                "error",
                &message,
                Some("rootfs"),
            );

            if let Some(previous_slot) = previous_slot {
                let entry_id = format!("{ROOTFS_GRUB_ENTRY_PREFIX}{previous_slot}");
                run_system_command("grub-reboot", &[&entry_id]).await?;
                append_operation_log(
                    &mut state_file,
                    "rollback",
                    "info",
                    format!("Scheduled automatic rootfs rollback to slot {previous_slot}"),
                    Some("rootfs"),
                );
                save_state(state, &state_file)?;
                remove_rootfs_iso_upgrade_marker(state);
                let _ = run_system_command("systemctl", &["reboot"]).await;
            } else {
                save_state(state, &state_file)?;
                remove_rootfs_iso_upgrade_marker(state);
            }
        }
    }

    Ok(())
}

pub async fn start_update_checker(state: std::sync::Arc<AppState>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        info!("updates: periodic checker started");

        loop {
            ticker.tick().await;

            let settings = load_settings(&state);
            if !settings.auto_check_enabled {
                continue;
            }

            let now = Local::now();
            let scheduled_time = match parse_auto_check_time(&settings.auto_check_time) {
                Some(time) => time,
                None => continue,
            };

            if now.time().hour() < scheduled_time.hour()
                || (now.time().hour() == scheduled_time.hour() && now.time().minute() < scheduled_time.minute())
            {
                continue;
            }

            let occurrence_key = match settings.auto_check_frequency {
                UpdateAutoCheckFrequency::Daily => now.format("%Y-%m-%d").to_string(),
                UpdateAutoCheckFrequency::Weekly => {
                    if !settings.auto_check_weekday.matches(now.weekday()) {
                        continue;
                    }
                    format!(
                        "{}-w{:02}-{}",
                        now.iso_week().year(),
                        now.iso_week().week(),
                        settings.auto_check_weekday.as_str()
                    )
                }
                UpdateAutoCheckFrequency::Monthly => {
                    let day = now.day() as u8;
                    let is_first_day = settings.auto_check_month_days.contains(&1) && day == 1;
                    let is_last_day = settings.auto_check_month_days.contains(&31)
                        && last_day_of_month(now.year(), now.month())
                            .map(|last_day| day as u32 == last_day)
                            .unwrap_or(false);

                    if !is_first_day && !is_last_day {
                        continue;
                    }

                    if is_last_day {
                        format!("{:04}-{:02}-last", now.year(), now.month())
                    } else {
                        format!("{:04}-{:02}-01", now.year(), now.month())
                    }
                }
            };

            let mut state_file = load_state(&state);
            if state_file.last_auto_check_run.as_deref() == Some(occurrence_key.as_str()) {
                continue;
            }
            state_file.last_auto_check_run = Some(occurrence_key.clone());
            if let Err(err) = save_state(&state, &state_file) {
                warn!(error = %err, "updates: failed to persist auto-check schedule state");
                continue;
            }

            match check_for_updates_with_trigger(&state, CheckTrigger::Scheduled).await {
                Ok(status) => {
                    let available = status.components.iter().filter(|c| c.update_available).count();
                    info!(available, "updates: periodic check completed");
                }
                Err(err) => {
                    warn!(error = %err, "updates: periodic check failed");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{github_repo_slug, registry_manifest_url, ArtifactMetadata, RegistryManifest};

    #[test]
    fn registry_manifest_url_appends_manifest_filename() {
        assert_eq!(
            registry_manifest_url("https://updates.example.com"),
            "https://updates.example.com/manifest.json"
        );
        assert_eq!(
            registry_manifest_url("https://updates.example.com/"),
            "https://updates.example.com/manifest.json"
        );
        assert_eq!(
            registry_manifest_url("https://updates.example.com/manifest.json"),
            "https://updates.example.com/manifest.json"
        );
    }

    #[test]
    fn github_repo_slug_extracts_owner_and_repo() {
        assert_eq!(
            github_repo_slug("https://api.github.com/repos/daygle/dayshield-core"),
            Some("daygle/dayshield-core".to_string())
        );
        assert_eq!(github_repo_slug("https://example.com"), None);
    }

    #[test]
    fn manifest_supports_independent_component_metadata() {
        let manifest = RegistryManifest {
            generated_at: "2026-05-18T00:00:00Z".to_string(),
            components: vec![ArtifactMetadata {
                component: "rootfs".to_string(),
                version: "2026.05.10".to_string(),
                download_url: "https://example.invalid/rootfs.tar.zst".to_string(),
                checksum_sha256: "abc123".to_string(),
                signature_url: Some("https://example.invalid/rootfs.sig".to_string()),
                source_repo: Some("daygle/dayshield-rootfs".to_string()),
                source_tag: Some("v2026.05.10".to_string()),
                source_release_url: Some(
                    "https://github.com/daygle/dayshield-rootfs/releases/tag/v2026.05.10"
                        .to_string(),
                ),
            }],
        };

        let json = serde_json::to_string(&manifest).expect("serialize manifest");
        let parsed: RegistryManifest = serde_json::from_str(&json).expect("deserialize manifest");
        let comp = parsed.components.first().expect("component entry");
        assert_eq!(comp.source_repo.as_deref(), Some("daygle/dayshield-rootfs"));
        assert_eq!(comp.source_tag.as_deref(), Some("v2026.05.10"));
        assert_eq!(
            comp.source_release_url.as_deref(),
            Some("https://github.com/daygle/dayshield-rootfs/releases/tag/v2026.05.10")
        );
    }

    #[test]
    fn manifest_metadata_fields_are_backward_compatible() {
        let legacy = r#"{
            "generatedAt": "2026-05-18T00:00:00Z",
            "components": [{
                "component": "core",
                "version": "1.0.0",
                "downloadUrl": "https://example.invalid/core.tar.zst",
                "checksumSha256": "def456"
            }]
        }"#;

        let parsed: RegistryManifest = serde_json::from_str(legacy).expect("parse legacy manifest");
        let comp = parsed.components.first().expect("component entry");
        assert!(comp.source_repo.is_none());
        assert!(comp.source_tag.is_none());
        assert!(comp.source_release_url.is_none());
    }
}
