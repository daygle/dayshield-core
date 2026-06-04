use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{Datelike, Duration as ChronoDuration, Local, NaiveTime, Timelike, Utc};
use reqwest::header::{HeaderName, HeaderValue, ACCEPT, USER_AGENT};
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
/// Default absolute path of the persisted update state file.
/// This constant is published so that `rootfs_update` can read the file
/// without requiring access to AppState.
pub const UPDATE_STATE_FILE_PATH: &str = "/var/lib/dayshield/config/updates_state.json";
const DEFAULT_CORE_URL: &str = "https://github.com/daygle/dayshield-core";
const DEFAULT_UI_URL: &str = "https://github.com/daygle/dayshield-ui";
const DEFAULT_ROOTFS_URL: &str = "https://github.com/daygle/dayshield-rootfs";
const RUNTIME_MARKER_DIR: &str = "/var/lib/dayshield/update";
const RUNTIME_ROLLBACK_DIR: &str = "/var/lib/dayshield/update/rollback";
const DEFAULT_TRUSTED_SIGNERS_FILE: &str = "/var/lib/dayshield/update_trusted_signers";
const ARTIFACT_STAGING_DIR: &str = "/var/lib/dayshield/update-staging";
const UPDATE_BACKUP_KEY_FILE: &str = "update_backup_key";
const UPDATE_HTTP_USER_AGENT: &str = concat!("dayshield-core/", env!("CARGO_PKG_VERSION"));
const ALL_REPO_COMPONENTS: [RepoComponent; 3] = [
    RepoComponent::Core,
    RepoComponent::Ui,
    RepoComponent::Rootfs,
];
/// GitHub Releases repository: https://github.com/daygle/dayshield-core
/// Artifacts are attached to releases as: core-v1.2.3.tar.zst, ui-v1.2.3.tar.zst, etc.
const DEFAULT_REGISTRY_URL: &str = "https://api.github.com/repos/daygle/dayshield-core";

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

fn default_auto_apply_updates() -> bool {
    false
}

fn default_auto_reboot_after_apply() -> bool {
    false
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

fn default_verify_rootfs_metadata() -> bool {
    true
}

fn default_trusted_signers_file() -> String {
    DEFAULT_TRUSTED_SIGNERS_FILE.to_string()
}

fn default_bootstrap_missing_rootfs_repo() -> bool {
    true
}

fn default_registry_url() -> String {
    env::var("DAYSHIELD_UPDATE_REGISTRY_URL").unwrap_or_else(|_| DEFAULT_REGISTRY_URL.to_string())
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
    // Off by default until the release pipeline starts publishing detached
    // `.sig` files alongside each artifact AND the trusted_signers_file is
    // provisioned with the project's release pubkey.  Operators flip this on
    // in the management UI once both are in place.  See README for the
    // ed25519 signing setup the build workflow needs.
    false
}

fn default_encrypt_update_config_backups() -> bool {
    false
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
    #[serde(default = "default_auto_apply_updates")]
    pub auto_apply_updates: bool,
    #[serde(default = "default_auto_reboot_after_apply")]
    pub auto_reboot_after_apply: bool,
    #[serde(default = "default_reboot_required_after_apply")]
    pub reboot_required_after_apply: bool,
    #[serde(default = "default_deploy_runtime_after_apply")]
    pub deploy_runtime_after_apply: bool,
    #[serde(default = "default_require_signed_commits")]
    pub require_signed_commits: bool,
    #[serde(default = "default_verify_rootfs_metadata")]
    pub verify_rootfs_metadata: bool,
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
    #[serde(default = "default_verify_artifact_signatures")]
    pub verify_artifact_signatures: bool,
    #[serde(default = "default_encrypt_update_config_backups")]
    pub encrypt_update_config_backups: bool,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            auto_check_enabled: default_auto_check_enabled(),
            auto_check_frequency: default_auto_check_frequency(),
            auto_check_time: default_auto_check_time(),
            auto_check_weekday: default_auto_check_weekday(),
            auto_check_month_days: default_auto_check_month_days(),
            auto_apply_updates: default_auto_apply_updates(),
            auto_reboot_after_apply: default_auto_reboot_after_apply(),
            reboot_required_after_apply: default_reboot_required_after_apply(),
            deploy_runtime_after_apply: default_deploy_runtime_after_apply(),
            require_signed_commits: default_require_signed_commits(),
            verify_rootfs_metadata: default_verify_rootfs_metadata(),
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
            verify_artifact_signatures: default_verify_artifact_signatures(),
            encrypt_update_config_backups: default_encrypt_update_config_backups(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateComponent {
    Core,
    Ui,
    Rootfs,
    All,
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

    fn display_name(self) -> &'static str {
        match self {
            RepoComponent::Core => "Core",
            RepoComponent::Ui => "UI",
            RepoComponent::Rootfs => "rootfs",
        }
    }

    fn from_update_component(component: UpdateComponent) -> Vec<Self> {
        match component {
            UpdateComponent::Core => vec![Self::Core],
            UpdateComponent::Ui => vec![Self::Ui],
            UpdateComponent::Rootfs => vec![Self::Rootfs],
            UpdateComponent::All => vec![Self::Core, Self::Ui, Self::Rootfs],
        }
    }
}

fn component_log_label(component: &str) -> String {
    component
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| match value {
            "core" => RepoComponent::Core.display_name().to_string(),
            "ui" => RepoComponent::Ui.display_name().to_string(),
            "rootfs" => RepoComponent::Rootfs.display_name().to_string(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn component_log_prefix(component: Option<&str>) -> Option<String> {
    component
        .map(component_log_label)
        .filter(|label| !label.is_empty())
        .map(|label| format!("[{label}]"))
}

fn component_log_message(message: String, component: Option<&str>) -> String {
    match component_log_prefix(component) {
        Some(prefix) if !message.starts_with(&prefix) => format!("{prefix} {message}"),
        _ => message,
    }
}

fn component_log_display_value(components: &[RepoComponent]) -> String {
    components
        .iter()
        .map(|component| component.display_name())
        .collect::<Vec<_>>()
        .join(", ")
}

fn ensure_registry_updatable_selection(_selected_components: &[RepoComponent]) -> Result<()> {
    // All components — including rootfs — are handled through the artifact
    // registry.  Rootfs artifacts are staged to disk for initramfs-driven
    // activation on the next boot rather than applied in-place.
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
    pub components: Vec<ComponentState>,
    #[serde(default)]
    pub operation_logs: Vec<UpdateLogEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<UpdateOperationProgress>,
    /// ETag cache for GitHub Releases API responses.
    /// Key: API URL, value: (ETag header value, cached response body).
    /// 304 Not Modified responses don't count against GitHub's rate limit.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub release_etag_cache: HashMap<String, (String, String)>,
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
pub struct UpdateOperationProgress {
    pub operation: String,
    pub phase: String,
    pub status: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_downloaded: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,
    pub started_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
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
    pub rollback_version: Option<String>,
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
    pub components: Vec<ComponentUpdateStatus>,
    /// Number of components with available updates (computed server-side)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_update_count: Option<usize>,
    #[serde(default)]
    pub operation_logs: Vec<UpdateLogEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<UpdateOperationProgress>,
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
    /// When true the manifest only covers the components listed (e.g. a single
    /// GitHub repo's releases). Missing components should not be flagged as
    /// errors - they are simply not tracked by this registry source.
    #[serde(default)]
    pub partial: bool,
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

fn github_repo_parts(url: &str) -> Option<(String, String)> {
    let trimmed = url.trim().trim_end_matches('/');
    let rest = if let Some(rest) = trimmed.split("api.github.com/repos/").nth(1) {
        rest
    } else if let Some(rest) = trimmed.split("github.com/").nth(1) {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        rest
    } else {
        return None;
    };

    let mut parts = rest.trim_matches('/').split('/');
    let owner = parts.next()?;
    let repo = parts.next()?.trim_end_matches(".git");
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

fn github_repo_api_url(url: &str) -> Option<String> {
    let (owner, repo) = github_repo_parts(url)?;
    Some(format!("https://api.github.com/repos/{owner}/{repo}"))
}

fn github_repo_slug(url: &str) -> Option<String> {
    let (owner, repo) = github_repo_parts(url)?;
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
        .unwrap_or(Path::new("/var/lib/dayshield/config"))
        .to_path_buf()
}

fn settings_path(state: &AppState) -> PathBuf {
    config_dir(state).join(SETTINGS_FILE)
}

fn state_path(state: &AppState) -> PathBuf {
    config_dir(state).join(STATE_FILE)
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let payload = serde_json::to_string_pretty(value)?;
    std::fs::write(&tmp, payload).with_context(|| format!("failed to write {}", tmp.display()))?;
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

fn ensure_component_state<'a>(
    state: &'a mut UpdateStateFile,
    component: RepoComponent,
) -> &'a mut ComponentState {
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

fn find_component_state<'a>(
    state: &'a UpdateStateFile,
    component: RepoComponent,
) -> Option<&'a ComponentState> {
    state
        .components
        .iter()
        .find(|c| c.component == component.as_str())
}

fn component_config(
    settings: &UpdateSettings,
    component: RepoComponent,
) -> (String, String, String) {
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

fn built_appliance_version() -> String {
    env!("CARGO_PKG_VERSION")
        .trim_start_matches('v')
        .to_string()
}

fn current_version_baseline(saved: Option<&ComponentState>) -> Option<String> {
    saved
        .and_then(|s| s.current_version.clone())
        .or_else(|| saved.and_then(|s| s.last_applied_version.clone()))
        .or_else(|| Some(built_appliance_version()))
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
        anyhow::bail!(
            "config rollback backup archive not found: {}",
            snapshot.display()
        );
    }

    let payload = fs::read(snapshot).with_context(|| {
        format!(
            "failed to read config rollback backup {}",
            snapshot.display()
        )
    })?;

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
            fs::remove_dir_all(&backup).with_context(|| {
                format!("failed to clear rollback snapshot {}", backup.display())
            })?;
        } else {
            fs::remove_file(&backup).with_context(|| {
                format!("failed to clear rollback snapshot {}", backup.display())
            })?;
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

async fn ensure_command_available(program: &str) -> Result<()> {
    Command::new(program)
        .arg("--version")
        .output()
        .await
        .with_context(|| format!("required command '{}' is not available", program))?;
    Ok(())
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

    for entry in
        fs::read_dir(src).with_context(|| format!("failed to read directory {}", src.display()))?
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

fn install_file_atomic(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = dst.with_extension(format!("tmp.{}", unique_suffix()));
    fs::copy(src, &tmp)
        .with_context(|| format!("failed to copy {} -> {}", src.display(), tmp.display()))?;
    let perms = fs::metadata(src)?.permissions();
    fs::set_permissions(&tmp, perms)?;
    fs::rename(&tmp, dst)
        .with_context(|| format!("failed to rename {} -> {}", tmp.display(), dst.display()))?;
    Ok(())
}

fn install_dir_atomic(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = dst.with_extension(format!("tmp.{}", unique_suffix()));
    copy_dir_recursive(src, &tmp)?;
    if dst.exists() {
        let old = dst.with_extension(format!("old.{}", unique_suffix()));
        fs::rename(dst, &old)
            .with_context(|| format!("failed to rename {} -> {}", dst.display(), old.display()))?;
        fs::rename(&tmp, dst).with_context(|| {
            format!("failed to rename {} -> {}", tmp.display(), dst.display())
        })?;
        if old.is_dir() {
            fs::remove_dir_all(&old)
                .with_context(|| format!("failed to remove old dir {}", old.display()))?;
        }
    } else {
        fs::rename(&tmp, dst).with_context(|| {
            format!("failed to rename {} -> {}", tmp.display(), dst.display())
        })?;
    }
    Ok(())
}

fn deploy_artifact(src: &Path, component: RepoComponent) -> Result<()> {
    match component {
        RepoComponent::Core => {
            let dst = deployed_runtime_path(component);
            install_file_atomic(src, &dst)
        }
        RepoComponent::Ui => {
            let dst = deployed_runtime_path(component);
            install_dir_atomic(src, &dst)
        }
        RepoComponent::Rootfs => {
            // rootfs is activated on next boot via initramfs; just stage it.
            let staging_dir = PathBuf::from(ARTIFACT_STAGING_DIR);
            fs::create_dir_all(&staging_dir).with_context(|| {
                format!(
                    "failed to create staging directory {}",
                    staging_dir.display()
                )
            })?;
            let dst = staging_dir.join(
                src.file_name()
                    .ok_or_else(|| anyhow::anyhow!("rootfs artifact has no filename"))?,
            );
            install_file_atomic(src, &dst)
        }
    }
}

async fn run_git_command(args: &[&str], repo_path: &Path) -> Result<std::process::Output> {
    Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()
        .await
        .with_context(|| {
            format!(
                "failed to run git {} in {}",
                args.join(" "),
                repo_path.display()
            )
        })
}

async fn get_current_commit(repo_path: &Path) -> Result<String> {
    let output = run_git_command(&["rev-parse", "HEAD"], repo_path).await?;
    if !output.status.success() {
        anyhow::bail!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn get_remote_commit(repo_path: &Path, branch: &str) -> Result<String> {
    let remote_ref = format!("origin/{}", branch);
    let output = run_git_command(&["rev-parse", &remote_ref], repo_path).await?;
    if !output.status.success() {
        anyhow::bail!(
            "git rev-parse {} failed: {}",
            remote_ref,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn is_commit_signed(repo_path: &Path, commit: &str) -> Result<bool> {
    let output = run_git_command(&["verify-commit", "--raw", commit], repo_path).await?;
    Ok(output.status.success())
}

async fn is_worktree_dirty(repo_path: &Path) -> Result<bool> {
    let output = run_git_command(&["status", "--porcelain"], repo_path).await?;
    if !output.status.success() {
        anyhow::bail!(
            "git status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(!output.stdout.is_empty())
}

async fn fetch_remote(repo_path: &Path) -> Result<()> {
    let output = run_git_command(&["fetch", "origin"], repo_path).await?;
    if !output.status.success() {
        anyhow::bail!(
            "git fetch origin failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

async fn reset_hard_to_remote(repo_path: &Path, branch: &str) -> Result<()> {
    let remote_ref = format!("origin/{}", branch);
    let output = run_git_command(&["reset", "--hard", &remote_ref], repo_path).await?;
    if !output.status.success() {
        anyhow::bail!(
            "git reset --hard {} failed: {}",
            remote_ref,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

async fn is_valid_git_repo(path: &Path) -> bool {
    run_git_command(&["rev-parse", "--git-dir"], path)
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn clone_repo(url: &str, path: &Path, branch: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.with_context(|| {
            format!("failed to create parent directory {}", parent.display())
        })?;
    }
    let output = Command::new("git")
        .args(["clone", "--branch", branch, "--depth", "1", url])
        .arg(path)
        .output()
        .await
        .context("failed to run git clone")?;
    if !output.status.success() {
        anyhow::bail!(
            "git clone {} failed: {}",
            url,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn load_state(state_file: &Path) -> UpdateStateFile {
    load_json_or_default(state_file)
}

fn save_state(state: &UpdateStateFile, state_file: &Path) -> Result<()> {
    write_json_atomic(state_file, state)
}

fn append_log(state: &mut UpdateStateFile, entry: UpdateLogEntry) {
    const MAX_LOG_ENTRIES: usize = 500;
    state.operation_logs.push(entry);
    if state.operation_logs.len() > MAX_LOG_ENTRIES {
        let drain_count = state.operation_logs.len() - MAX_LOG_ENTRIES;
        state.operation_logs.drain(0..drain_count);
    }
}

fn log_entry(
    operation: &str,
    level: &str,
    message: String,
    component: Option<&str>,
) -> UpdateLogEntry {
    UpdateLogEntry {
        timestamp: Utc::now().to_rfc3339(),
        operation: operation.to_string(),
        level: level.to_string(),
        message: component_log_message(message, component),
        component: component.map(|c| c.to_string()),
        from_version: None,
        to_version: None,
    }
}

fn log_entry_with_versions(
    operation: &str,
    level: &str,
    message: String,
    component: Option<&str>,
    from_version: Option<String>,
    to_version: Option<String>,
) -> UpdateLogEntry {
    UpdateLogEntry {
        timestamp: Utc::now().to_rfc3339(),
        operation: operation.to_string(),
        level: level.to_string(),
        message: component_log_message(message, component),
        component: component.map(|c| c.to_string()),
        from_version,
        to_version,
    }
}

fn write_progress(
    update_state: &mut UpdateStateFile,
    state_file: &Path,
    progress: UpdateOperationProgress,
) {
    update_state.progress = Some(progress);
    let _ = save_state(update_state, state_file);
}

fn clear_progress(update_state: &mut UpdateStateFile, state_file: &Path) {
    update_state.progress = None;
    let _ = save_state(update_state, state_file);
}

fn make_progress(
    operation: &str,
    phase: &str,
    status: &str,
    message: &str,
    component: Option<&str>,
    percent: Option<u8>,
) -> UpdateOperationProgress {
    let now = Utc::now().to_rfc3339();
    UpdateOperationProgress {
        operation: operation.to_string(),
        phase: phase.to_string(),
        status: status.to_string(),
        message: component_log_message(message.to_string(), component),
        component: component.map(|c| c.to_string()),
        percent,
        bytes_downloaded: None,
        bytes_total: None,
        started_at: now.clone(),
        updated_at: now,
        completed_at: None,
    }
}

// ============================================================================
// Public API
// ============================================================================

pub async fn get_update_status(state: &AppState) -> UpdatesStatus {
    let settings = load_settings(state);
    let state_file = state_path(state);
    let update_state = load_state(&state_file);
    build_status(settings, &update_state).await
}

async fn build_status(settings: UpdateSettings, update_state: &UpdateStateFile) -> UpdatesStatus {
    let components = build_component_statuses(&settings, update_state).await;
    let available_update_count = components.iter().filter(|c| c.update_available).count();
    UpdatesStatus {
        settings,
        last_checked_at: update_state.last_checked_at.clone(),
        last_applied_at: update_state.last_applied_at.clone(),
        pending_reboot: update_state.pending_reboot,
        pending_appliance_rebuild: update_state.pending_appliance_rebuild,
        appliance_rebuild_reason: update_state.appliance_rebuild_reason.clone(),
        appliance_rebuild_marked_at: update_state.appliance_rebuild_marked_at.clone(),
        components,
        available_update_count: Some(available_update_count),
        operation_logs: update_state.operation_logs.clone(),
        progress: update_state.progress.clone(),
    }
}

async fn build_component_statuses(
    settings: &UpdateSettings,
    update_state: &UpdateStateFile,
) -> Vec<ComponentUpdateStatus> {
    let mut statuses = Vec::new();
    for component in ALL_REPO_COMPONENTS {
        let saved = find_component_state(update_state, component);
        statuses.push(build_component_status(settings, component, saved).await);
    }
    statuses
}

async fn build_component_status(
    settings: &UpdateSettings,
    component: RepoComponent,
    saved: Option<&ComponentState>,
) -> ComponentUpdateStatus {
    let (repo_path, _url, branch) = component_config(settings, component);
    let repo_path = PathBuf::from(&repo_path);
    let valid_repo = is_valid_git_repo(&repo_path).await;
    let dirty_worktree = if valid_repo {
        is_worktree_dirty(&repo_path).await.unwrap_or(false)
    } else {
        false
    };
    let current_commit = if valid_repo {
        get_current_commit(&repo_path).await.ok()
    } else {
        None
    };
    let remote_commit = if valid_repo {
        get_remote_commit(&repo_path, &branch).await.ok()
    } else {
        None
    };

    let current_version = saved.and_then(|s| s.current_version.clone());
    let remote_version = saved.and_then(|s| s.remote_version.clone());
    let update_available = match (&current_version, &remote_version) {
        (Some(cur), Some(rem)) => cur != rem,
        _ => match (&current_commit, &remote_commit) {
            (Some(cur), Some(rem)) => cur != rem,
            _ => false,
        },
    };

    ComponentUpdateStatus {
        component: component.as_str().to_string(),
        repo_path: repo_path.to_string_lossy().into_owned(),
        branch,
        valid_repo,
        dirty_worktree,
        current_commit,
        remote_commit,
        current_version,
        remote_version,
        update_available,
        rollback_commit: saved.and_then(|s| s.rollback_commit.clone()),
        rollback_version: saved.and_then(|s| s.rollback_version.clone()),
        last_applied_commit: saved.and_then(|s| s.last_applied_commit.clone()),
        last_applied_version: saved.and_then(|s| s.last_applied_version.clone()),
        last_error: saved.and_then(|s| s.last_error.clone()),
    }
}

pub async fn check_for_updates(state: &AppState) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;
    let settings = load_settings(state);
    let state_file = state_path(state);
    let mut update_state = load_state(&state_file);

    write_progress(
        &mut update_state,
        &state_file,
        make_progress("check", "fetching", "running", "Fetching updates…", None, None),
    );

    let mut details = Vec::new();
    let mut any_error = false;

    for component in ALL_REPO_COMPONENTS {
        let (repo_path, url, branch) = component_config(&settings, component);
        let repo_path = PathBuf::from(&repo_path);
        let comp_str = component.as_str();

        if !is_valid_git_repo(&repo_path).await {
            if settings.bootstrap_missing_rootfs_repo
                || !matches!(component, RepoComponent::Rootfs)
            {
                match clone_repo(&url, &repo_path, &branch).await {
                    Ok(()) => {
                        details.push(format!(
                            "[{}] Cloned repository from {}",
                            component.display_name(),
                            url
                        ));
                    }
                    Err(e) => {
                        let msg = format!(
                            "[{}] Failed to clone repository: {}",
                            component.display_name(),
                            e
                        );
                        details.push(msg.clone());
                        append_log(
                            &mut update_state,
                            log_entry("check", "error", msg, Some(comp_str)),
                        );
                        any_error = true;
                        continue;
                    }
                }
            } else {
                details.push(format!(
                    "[{}] Repository not found at {}, skipping",
                    component.display_name(),
                    repo_path.display()
                ));
                continue;
            }
        }

        match fetch_remote(&repo_path).await {
            Ok(()) => {}
            Err(e) => {
                let msg = format!(
                    "[{}] Failed to fetch updates: {}",
                    component.display_name(),
                    e
                );
                details.push(msg.clone());
                append_log(
                    &mut update_state,
                    log_entry("check", "error", msg, Some(comp_str)),
                );
                any_error = true;
                continue;
            }
        }

        let current = get_current_commit(&repo_path).await.ok();
        let remote = get_remote_commit(&repo_path, &branch).await.ok();
        let update_available = match (&current, &remote) {
            (Some(c), Some(r)) => c != r,
            _ => false,
        };

        let comp_state = ensure_component_state(&mut update_state, component);
        comp_state.last_error = None;
        if update_available {
            let msg = format!(
                "[{}] Update available: {} -> {}",
                component.display_name(),
                current.as_deref().unwrap_or("unknown"),
                remote.as_deref().unwrap_or("unknown")
            );
            details.push(msg.clone());
            append_log(
                &mut update_state,
                log_entry("check", "info", msg, Some(comp_str)),
            );
        } else {
            let msg = format!("[{}] Already up to date", component.display_name());
            details.push(msg.clone());
            append_log(
                &mut update_state,
                log_entry("check", "info", msg, Some(comp_str)),
            );
        }
        comp_state.update_available = update_available;
    }

    update_state.last_checked_at = Some(Utc::now().to_rfc3339());
    clear_progress(&mut update_state, &state_file);
    save_state(&update_state, &state_file)?;

    let status = build_status(settings, &update_state).await;
    Ok(UpdatesActionResult {
        operation: "check".to_string(),
        success: !any_error,
        message: if any_error {
            "Check completed with errors".to_string()
        } else {
            "Check completed successfully".to_string()
        },
        details,
        status,
    })
}

pub async fn apply_updates(
    state: &AppState,
    component: UpdateComponent,
) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;
    let settings = load_settings(state);
    let state_file = state_path(state);
    let mut update_state = load_state(&state_file);

    let selected_components = RepoComponent::from_update_component(component);
    ensure_registry_updatable_selection(&selected_components)?;
    let comp_label = component_log_display_value(&selected_components);

    write_progress(
        &mut update_state,
        &state_file,
        make_progress(
            "apply",
            "preparing",
            "running",
            "Preparing to apply updates…",
            None,
            None,
        ),
    );

    let mut details = Vec::new();
    let mut any_error = false;

    for repo_component in selected_components {
        let (repo_path, _url, branch) = component_config(&settings, repo_component);
        let repo_path = PathBuf::from(&repo_path);
        let comp_str = repo_component.as_str();

        if !is_valid_git_repo(&repo_path).await {
            let msg = format!(
                "[{}] Repository not found at {}; run check first",
                repo_component.display_name(),
                repo_path.display()
            );
            details.push(msg.clone());
            append_log(
                &mut update_state,
                log_entry("apply", "error", msg, Some(comp_str)),
            );
            any_error = true;
            continue;
        }

        let current_commit = match get_current_commit(&repo_path).await {
            Ok(c) => c,
            Err(e) => {
                let msg = format!(
                    "[{}] Failed to get current commit: {}",
                    repo_component.display_name(),
                    e
                );
                details.push(msg.clone());
                append_log(
                    &mut update_state,
                    log_entry("apply", "error", msg, Some(comp_str)),
                );
                any_error = true;
                continue;
            }
        };

        let remote_commit = match get_remote_commit(&repo_path, &branch).await {
            Ok(c) => c,
            Err(e) => {
                let msg = format!(
                    "[{}] Failed to get remote commit: {}",
                    repo_component.display_name(),
                    e
                );
                details.push(msg.clone());
                append_log(
                    &mut update_state,
                    log_entry("apply", "error", msg, Some(comp_str)),
                );
                any_error = true;
                continue;
            }
        };

        if current_commit == remote_commit {
            let msg = format!("[{}] Already up to date", repo_component.display_name());
            details.push(msg.clone());
            append_log(
                &mut update_state,
                log_entry("apply", "info", msg, Some(comp_str)),
            );
            continue;
        }

        if settings.require_signed_commits {
            match is_commit_signed(&repo_path, &remote_commit).await {
                Ok(true) => {}
                Ok(false) => {
                    let msg = format!(
                        "[{}] Remote commit {} is not signed; aborting",
                        repo_component.display_name(),
                        &remote_commit[..8]
                    );
                    details.push(msg.clone());
                    append_log(
                        &mut update_state,
                        log_entry("apply", "error", msg, Some(comp_str)),
                    );
                    any_error = true;
                    continue;
                }
                Err(e) => {
                    let msg = format!(
                        "[{}] Failed to verify commit signature: {}",
                        repo_component.display_name(),
                        e
                    );
                    details.push(msg.clone());
                    append_log(
                        &mut update_state,
                        log_entry("apply", "error", msg, Some(comp_str)),
                    );
                    any_error = true;
                    continue;
                }
            }
        }

        // Snapshot rollback state before applying
        if let Err(e) = snapshot_runtime_for_rollback(repo_component) {
            let msg = format!(
                "[{}] Failed to snapshot rollback state: {}",
                repo_component.display_name(),
                e
            );
            details.push(msg.clone());
            append_log(
                &mut update_state,
                log_entry("apply", "warn", msg, Some(comp_str)),
            );
        }

        let comp_state = ensure_component_state(&mut update_state, repo_component);
        comp_state.rollback_commit = Some(current_commit.clone());

        match reset_hard_to_remote(&repo_path, &branch).await {
            Ok(()) => {
                let comp_state = ensure_component_state(&mut update_state, repo_component);
                comp_state.last_applied_commit = Some(remote_commit.clone());
                comp_state.deployed_commit = Some(remote_commit.clone());
                comp_state.last_error = None;
                comp_state.update_available = false;

                let msg = format!(
                    "[{}] Updated: {} -> {}",
                    repo_component.display_name(),
                    &current_commit[..8],
                    &remote_commit[..8]
                );
                details.push(msg.clone());
                append_log(
                    &mut update_state,
                    log_entry("apply", "info", msg, Some(comp_str)),
                );

                if settings.deploy_runtime_after_apply
                    && component_supports_runtime_deploy(repo_component)
                {
                    // Deploy logic would go here for runtime artifacts
                }
            }
            Err(e) => {
                let comp_state = ensure_component_state(&mut update_state, repo_component);
                comp_state.last_error = Some(e.to_string());

                let msg = format!(
                    "[{}] Failed to apply update: {}",
                    repo_component.display_name(),
                    e
                );
                details.push(msg.clone());
                append_log(
                    &mut update_state,
                    log_entry("apply", "error", msg, Some(comp_str)),
                );
                any_error = true;
            }
        }
    }

    update_state.last_applied_at = Some(Utc::now().to_rfc3339());
    clear_progress(&mut update_state, &state_file);
    save_state(&update_state, &state_file)?;

    let status = build_status(settings, &update_state).await;
    Ok(UpdatesActionResult {
        operation: "apply".to_string(),
        success: !any_error,
        message: if any_error {
            format!("Apply [{comp_label}] completed with errors")
        } else {
            format!("Apply [{comp_label}] completed successfully")
        },
        details,
        status,
    })
}

pub async fn rollback_updates(
    state: &AppState,
    component: UpdateComponent,
) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;
    let settings = load_settings(state);
    let state_file = state_path(state);
    let mut update_state = load_state(&state_file);
    let selected_components = RepoComponent::from_update_component(component);
    let comp_label = component_log_display_value(&selected_components);

    let mut details = Vec::new();
    let mut any_error = false;

    for repo_component in selected_components {
        let (repo_path, _url, _branch) = component_config(&settings, repo_component);
        let repo_path = PathBuf::from(&repo_path);
        let comp_str = repo_component.as_str();

        let saved = find_component_state(&update_state, repo_component);
        let rollback_commit = match saved.and_then(|s| s.rollback_commit.clone()) {
            Some(c) => c,
            None => {
                let msg = format!(
                    "[{}] No rollback commit recorded",
                    repo_component.display_name()
                );
                details.push(msg.clone());
                append_log(
                    &mut update_state,
                    log_entry("rollback", "error", msg, Some(comp_str)),
                );
                any_error = true;
                continue;
            }
        };

        match reset_hard_to_remote_ref(&repo_path, &rollback_commit).await {
            Ok(()) => {
                let comp_state = ensure_component_state(&mut update_state, repo_component);
                let prev = comp_state.last_applied_commit.clone();
                comp_state.deployed_commit = Some(rollback_commit.clone());
                comp_state.last_applied_commit = Some(rollback_commit.clone());
                comp_state.rollback_commit = prev;
                comp_state.last_error = None;

                // Restore runtime snapshot
                if let Err(e) = restore_runtime_from_snapshot(repo_component) {
                    let msg = format!(
                        "[{}] Failed to restore runtime snapshot: {}",
                        repo_component.display_name(),
                        e
                    );
                    details.push(msg.clone());
                    append_log(
                        &mut update_state,
                        log_entry("rollback", "warn", msg, Some(comp_str)),
                    );
                }

                let msg = format!(
                    "[{}] Rolled back to {}",
                    repo_component.display_name(),
                    &rollback_commit[..8]
                );
                details.push(msg.clone());
                append_log(
                    &mut update_state,
                    log_entry("rollback", "info", msg, Some(comp_str)),
                );
            }
            Err(e) => {
                let comp_state = ensure_component_state(&mut update_state, repo_component);
                comp_state.last_error = Some(e.to_string());

                let msg = format!(
                    "[{}] Rollback failed: {}",
                    repo_component.display_name(),
                    e
                );
                details.push(msg.clone());
                append_log(
                    &mut update_state,
                    log_entry("rollback", "error", msg, Some(comp_str)),
                );
                any_error = true;
            }
        }
    }

    save_state(&update_state, &state_file)?;
    let status = build_status(settings, &update_state).await;
    Ok(UpdatesActionResult {
        operation: "rollback".to_string(),
        success: !any_error,
        message: if any_error {
            format!("Rollback [{comp_label}] completed with errors")
        } else {
            format!("Rollback [{comp_label}] completed successfully")
        },
        details,
        status,
    })
}

async fn reset_hard_to_remote_ref(repo_path: &Path, commit: &str) -> Result<()> {
    let output = run_git_command(&["reset", "--hard", commit], repo_path).await?;
    if !output.status.success() {
        anyhow::bail!(
            "git reset --hard {} failed: {}",
            commit,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn get_update_logs(state: &AppState) -> Vec<UpdateLogEntry> {
    let state_file = state_path(state);
    let update_state = load_state(&state_file);
    update_state.operation_logs
}

pub fn clear_update_logs(state: &AppState) -> Result<()> {
    let state_file = state_path(state);
    let mut update_state = load_state(&state_file);
    update_state.operation_logs.clear();
    save_state(&update_state, &state_file)
}

// ============================================================================
// Registry-based update flow (new)
// ============================================================================

/// Download an artifact from a URL into a local staging directory.
/// Returns the path to the downloaded file.
async fn download_artifact(url: &str, staging_dir: &Path) -> Result<PathBuf> {
    let client = build_http_client()?;

    // Extract filename from URL
    let filename = url
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("cannot derive filename from URL: {}", url))?;

    fs::create_dir_all(staging_dir).with_context(|| {
        format!("failed to create staging directory {}", staging_dir.display())
    })?;

    let dest_path = staging_dir.join(filename);

    info!("Downloading artifact {} -> {}", url, dest_path.display());

    let response = client
        .get(url)
        .header(USER_AGENT, UPDATE_HTTP_USER_AGENT)
        .send()
        .await
        .with_context(|| format!("failed to fetch artifact from {}", url))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "artifact download {} returned HTTP {}",
            url,
            response.status()
        );
    }

    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("failed to read artifact bytes from {}", url))?;

    fs::write(&dest_path, &bytes)
        .with_context(|| format!("failed to write artifact to {}", dest_path.display()))?;

    Ok(dest_path)
}

/// Apply a downloaded artifact for a given component.
/// For core/ui: installs to the runtime paths.
/// For rootfs: stages for next-boot activation.
fn apply_downloaded_artifact(artifact_path: &Path, component: RepoComponent) -> Result<()> {
    deploy_artifact(artifact_path, component)
}

fn is_artifact_version(version: &str) -> bool {
    let mut segment_count = 0;
    for segment in version.split('.') {
        if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        segment_count += 1;
    }

    segment_count >= 2 && segment_count <= 4
}

fn artifact_version_segments(version: &str) -> Option<Vec<u64>> {
    if !is_artifact_version(version) {
        return None;
    }
    version
        .split('.')
        .map(|s| s.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()
}

fn is_newer_artifact_version(current: &str, remote: &str) -> bool {
    let Some((current_segments, remote_segments)) = artifact_version_segments(current)
        .zip(artifact_version_segments(remote))
    else {
        return current != remote;
    };

    let segment_count = current_segments.len().max(remote_segments.len());
    for idx in 0..segment_count {
        let current_segment = current_segments.get(idx).copied().unwrap_or(0);
        let remote_segment = remote_segments.get(idx).copied().unwrap_or(0);
        if remote_segment > current_segment {
            return true;
        }
        if remote_segment < current_segment {
            return false;
        }
    }
    false
}

/// Fetch the registry manifest from the given URL.
/// Handles GitHub Releases API responses directly.
async fn fetch_registry_manifest(
    registry_url: &str,
    update_state: &mut UpdateStateFile,
) -> Result<RegistryManifest> {
    let client = build_http_client()?;

    // Check if the URL points to a GitHub Releases API endpoint
    // (e.g. https://api.github.com/repos/{owner}/{repo})
    if let Some(api_base) = github_repo_api_url(registry_url) {
        return fetch_github_releases_manifest(&client, &api_base, update_state).await;
    }

    // Fall back to fetching a plain JSON manifest
    let response = client
        .get(registry_url)
        .header(USER_AGENT, UPDATE_HTTP_USER_AGENT)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .with_context(|| format!("failed to fetch registry manifest from {}", registry_url))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "registry manifest fetch {} returned HTTP {}",
            registry_url,
            response.status()
        );
    }

    let manifest: RegistryManifest = response
        .json()
        .await
        .with_context(|| format!("failed to parse registry manifest from {}", registry_url))?;

    Ok(manifest)
}

/// Build a `RegistryManifest` from the GitHub Releases API for the given repo.
/// Fetches the latest release and maps assets to `ArtifactMetadata` entries.
async fn fetch_github_releases_manifest(
    client: &reqwest::Client,
    api_base: &str,
    update_state: &mut UpdateStateFile,
) -> Result<RegistryManifest> {
    let releases_url = format!("{api_base}/releases");

    // Build request with conditional ETag header if we have a cached response.
    let cached = update_state
        .release_etag_cache
        .get(&releases_url)
        .cloned();
    let mut req = client
        .get(&releases_url)
        .header(USER_AGENT, UPDATE_HTTP_USER_AGENT)
        .header(ACCEPT, "application/vnd.github+json");
    if let Some((ref etag, _)) = cached {
        req = req.header(
            HeaderName::from_static("if-none-match"),
            HeaderValue::from_str(etag).unwrap_or_else(|_| HeaderValue::from_static("")),
        );
    }
    let response = req
        .send()
        .await
        .with_context(|| format!("failed to fetch GitHub releases from {}", releases_url))?;

    let status = response.status();
    if status == reqwest::StatusCode::NOT_MODIFIED {
        // Use the cached response body.
        if let Some((_, ref body)) = cached {
            let releases: Vec<GitHubRelease> = serde_json::from_str(body)
                .context("failed to parse cached GitHub releases response")?;
            return github_releases_to_manifest(releases, api_base);
        }
    }

    if !status.is_success() {
        anyhow::bail!(
            "GitHub releases fetch {} returned HTTP {}",
            releases_url,
            status
        );
    }

    // Extract ETag for next time.
    let new_etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body = response
        .text()
        .await
        .with_context(|| format!("failed to read GitHub releases body from {}", releases_url))?;

    // Cache the response body alongside the new ETag (if any).
    if let Some(etag) = new_etag {
        update_state
            .release_etag_cache
            .insert(releases_url.clone(), (etag, body.clone()));
    }

    let releases: Vec<GitHubRelease> =
        serde_json::from_str(&body).context("failed to parse GitHub releases response")?;

    github_releases_to_manifest(releases, api_base)
}

fn github_releases_to_manifest(
    releases: Vec<GitHubRelease>,
    api_base: &str,
) -> Result<RegistryManifest> {
    // Use the latest release (first in the list, newest by GitHub convention).
    let latest = releases
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no releases found in GitHub releases response"))?;

    let tag = latest.tag_name.trim_start_matches('v').to_string();
    let source_repo = github_repo_slug(api_base).map(|s| format!("https://github.com/{s}"));
    let source_release_url = latest.html_url.clone();

    // Map each well-known asset to a component.
    let known_components = ["core", "ui", "rootfs"];
    let mut components: Vec<ArtifactMetadata> = Vec::new();

    for component_name in &known_components {
        // Find the main artifact asset (e.g. core-v1.2.3.tar.zst)
        let artifact_asset = latest.assets.iter().find(|a| {
            let name = a.name.to_lowercase();
            name.starts_with(component_name)
                && !name.ends_with(".sha256")
                && !name.ends_with(".sig")
        });

        let Some(asset) = artifact_asset else {
            continue;
        };

        // Find checksum asset (e.g. core-v1.2.3.tar.zst.sha256)
        let checksum_asset = latest.assets.iter().find(|a| {
            a.name
                .to_lowercase()
                .starts_with(component_name)
                && a.name.ends_with(".sha256")
        });

        // Find signature asset (e.g. core-v1.2.3.tar.zst.sig)
        let sig_asset = latest.assets.iter().find(|a| {
            a.name
                .to_lowercase()
                .starts_with(component_name)
                && a.name.ends_with(".sig")
        });

        // Fetch the checksum content (it's a small text file).
        // We defer the actual fetch to apply time — store the URL here and
        // resolve during apply.  For now, store the URL as a placeholder.
        let checksum_sha256 = checksum_asset
            .map(|a| a.browser_download_url.clone())
            .unwrap_or_default();

        let version = extract_asset_version(&asset.name, component_name).unwrap_or_else(|| tag.clone());

        components.push(ArtifactMetadata {
            component: component_name.to_string(),
            version,
            download_url: asset.browser_download_url.clone(),
            checksum_sha256,
            signature_url: sig_asset.map(|a| a.browser_download_url.clone()),
            source_repo: source_repo.clone(),
            source_tag: Some(latest.tag_name.clone()),
            source_release_url: source_release_url.clone(),
        });
    }

    Ok(RegistryManifest {
        components,
        generated_at: latest.created_at.clone(),
        partial: true,
    })
}

fn extract_asset_version<'a>(asset_name: &'a str, component: &str) -> Option<String> {
    // Asset names follow the pattern: {component}-v{version}.{ext}
    // e.g. core-v1.2.3.tar.zst
    let stripped = asset_name
        .strip_prefix(component)?
        .strip_prefix('-')?
        .strip_prefix('v');

    let version = stripped.unwrap_or_else(|| {
        asset_name
            .strip_prefix(component)
            .and_then(|s| s.strip_prefix('-'))
            .unwrap_or(asset_name)
    });

    // Strip known archive suffixes to isolate the version string.
    let version = [".tar.zst", ".tar.gz", ".tar.bz2", ".tar.xz", ".squashfs"]
        .iter()
        .fold(version, |v, ext| v.strip_suffix(ext).unwrap_or(v));

    // For rootfs assets the suffix may be: rootfs-v1.2.3.squashfs or
    // rootfs-1.2.3.squashfs — handle the case where the component name is
    // embedded differently.
    let version = if version.contains(component) {
        version
            .split(component)
            .last()
            .map(|s| s.trim_start_matches(['-', '_', 'v']))
            .filter(|s| !s.is_empty())
            .unwrap_or(version)
    } else {
        version
    };

    // Validate it looks like a version number.
    let version = version.trim_start_matches('v');
    if is_artifact_version(version) {
        Some(version.to_string())
    } else {
        None
    }
}

fn rootfs_staged_version(staging_dir: &Path) -> Option<String> {
    let entries = std::fs::read_dir(staging_dir).ok()?;
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if name.starts_with("rootfs") && name.ends_with(".squashfs") {
                extract_asset_version(&name, "rootfs")
            } else {
                None
            }
        })
        .filter(|v| is_artifact_version(v))?;
    Some(version.to_string())
}

async fn resolve_checksum_url(checksum_url: &str) -> Result<String> {
    // The checksum file contains the hex SHA-256 digest, possibly followed by
    // a filename, in the style of `sha256sum` output.  We want only the hex
    // digest (the first whitespace-separated token on the first non-empty line).
    let client = build_http_client()?;
    let response = client
        .get(checksum_url)
        .header(USER_AGENT, UPDATE_HTTP_USER_AGENT)
        .send()
        .await
        .with_context(|| format!("failed to fetch checksum from {}", checksum_url))?;
    if !response.status().is_success() {
        anyhow::bail!(
            "checksum fetch {} returned HTTP {}",
            checksum_url,
            response.status()
        );
    }
    let body = response
        .text()
        .await
        .with_context(|| format!("failed to read checksum body from {}", checksum_url))?;
    body.lines()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| l.split_whitespace().next())
        .map(|s| s.to_lowercase())
        .ok_or_else(|| anyhow::anyhow!("checksum file {} is empty or malformed", checksum_url))
}

fn compute_file_sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("failed to open {} for hashing", path.display()))?;
    let mut buffer = [0u8; 65536];
    loop {
        use std::io::Read;
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn load_settings(state: &AppState) -> UpdateSettings {
    load_json_or_default(&settings_path(state))
}

pub fn save_settings(state: &AppState, settings: &UpdateSettings) -> Result<()> {
    let mut value = settings.clone();
    value.auto_check_time = normalize_auto_check_time(&value.auto_check_time);
    value.auto_check_month_days = normalize_auto_check_month_days(value.auto_check_month_days);
    write_json_atomic(&settings_path(state), &value)
}

/// Periodic auto-check scheduler
pub async fn run_auto_check_scheduler(state: &AppState) -> Result<()> {
    let settings = load_settings(state);
    if !settings.auto_check_enabled {
        return Ok(());
    }

    let state_file = state_path(state);
    let update_state = load_state(&state_file);

    let now = Local::now();

    // Parse the scheduled time
    let scheduled_time = parse_auto_check_time(&settings.auto_check_time)
        .unwrap_or_else(|| NaiveTime::from_hms_opt(3, 0, 0).unwrap());

    // Check if we should run now based on frequency
    let should_run = match settings.auto_check_frequency {
        UpdateAutoCheckFrequency::Daily => {
            // Run if we haven't run today yet and current time is past scheduled time
            let today = now.date_naive();
            let already_ran_today = update_state
                .last_auto_check_run
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.date_naive() == today)
                .unwrap_or(false);
            !already_ran_today && now.time() >= scheduled_time
        }
        UpdateAutoCheckFrequency::Weekly => {
            let this_week_monday = {
                let days_from_monday =
                    now.weekday().num_days_from_monday() as i64;
                now.date_naive() - ChronoDuration::days(days_from_monday)
            };
            let already_ran_this_week = update_state
                .last_auto_check_run
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| {
                    let run_date = dt.date_naive();
                    let days_from_monday =
                        run_date.weekday().num_days_from_monday() as i64;
                    run_date - ChronoDuration::days(days_from_monday) == this_week_monday
                })
                .unwrap_or(false);
            let is_scheduled_weekday = settings.auto_check_weekday.matches(now.weekday());
            !already_ran_this_week && is_scheduled_weekday && now.time() >= scheduled_time
        }
        UpdateAutoCheckFrequency::Monthly => {
            let this_month_year = (now.year(), now.month());
            let already_ran_this_month = update_state
                .last_auto_check_run
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| (dt.year(), dt.month()) == this_month_year)
                .unwrap_or(false);

            let is_scheduled_day = settings.auto_check_month_days.iter().any(|&d| {
                if d == 31 {
                    // "last day of month"
                    last_day_of_month(now.year(), now.month())
                        .map(|last| now.day() == last)
                        .unwrap_or(false)
                } else {
                    now.day() == d as u32
                }
            });
            !already_ran_this_month && is_scheduled_day && now.time() >= scheduled_time
        }
    };

    if !should_run {
        return Ok(());
    }

    info!("Auto-check scheduler: running scheduled update check");
    check_for_updates(state).await?;

    // Update last_auto_check_run
    let state_file = state_path(state);
    let mut update_state = load_state(&state_file);
    update_state.last_auto_check_run = Some(Utc::now().to_rfc3339());
    save_state(&update_state, &state_file)?;

    Ok(())
}

// ============================================================================
// Registry-based check/apply flow
// ============================================================================

pub async fn registry_check_for_updates(state: &AppState) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;
    let settings = load_settings(state);
    let state_file = state_path(state);
    let mut update_state = load_state(&state_file);

    write_progress(
        &mut update_state,
        &state_file,
        make_progress(
            "registry_check",
            "fetching",
            "running",
            "Fetching artifact registry manifest…",
            None,
            None,
        ),
    );

    let manifest = match fetch_registry_manifest(&settings.registry_url, &mut update_state).await {
        Ok(m) => m,
        Err(e) => {
            let msg = format!("Failed to fetch registry manifest: {e}");
            append_log(
                &mut update_state,
                log_entry("registry_check", "error", msg.clone(), None),
            );
            clear_progress(&mut update_state, &state_file);
            save_state(&update_state, &state_file)?;
            anyhow::bail!(msg);
        }
    };

    let mut details = Vec::new();

    for artifact in &manifest.components {
        let component = match artifact.component.as_str() {
            "core" => RepoComponent::Core,
            "ui" => RepoComponent::Ui,
            "rootfs" => RepoComponent::Rootfs,
            other => {
                details.push(format!("Unknown component in manifest: {other}"));
                continue;
            }
        };
        let comp_str = component.as_str();

        let comp_state = ensure_component_state(&mut update_state, component);
        comp_state.remote_version = Some(artifact.version.clone());

        // Determine current installed version
        let current_version = comp_state
            .current_version
            .clone()
            .or_else(|| comp_state.last_applied_version.clone())
            .unwrap_or_else(built_appliance_version);

        let update_available = is_newer_artifact_version(&current_version, &artifact.version);
        comp_state.update_available = update_available;

        if update_available {
            let msg = format!(
                "Update available: {} -> {}",
                current_version, artifact.version
            );
            details.push(format!("[{}] {msg}", component.display_name()));
            append_log(
                &mut update_state,
                log_entry("registry_check", "info", msg, Some(comp_str)),
            );
        } else {
            let msg = format!("Already up to date ({})", current_version);
            details.push(format!("[{}] {msg}", component.display_name()));
            append_log(
                &mut update_state,
                log_entry("registry_check", "info", msg, Some(comp_str)),
            );
        }
    }

    update_state.last_checked_at = Some(Utc::now().to_rfc3339());
    clear_progress(&mut update_state, &state_file);
    save_state(&update_state, &state_file)?;

    let status = build_status(settings, &update_state).await;
    Ok(UpdatesActionResult {
        operation: "registry_check".to_string(),
        success: true,
        message: "Registry check completed successfully".to_string(),
        details,
        status,
    })
}

pub async fn registry_apply_updates(
    state: &AppState,
    component: UpdateComponent,
) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;
    let settings = load_settings(state);
    let state_file = state_path(state);
    let mut update_state = load_state(&state_file);

    let selected_components = RepoComponent::from_update_component(component);
    let comp_label = component_log_display_value(&selected_components);

    write_progress(
        &mut update_state,
        &state_file,
        make_progress(
            "registry_apply",
            "preparing",
            "running",
            "Preparing registry-based update…",
            None,
            None,
        ),
    );

    let manifest = match fetch_registry_manifest(&settings.registry_url, &mut update_state).await {
        Ok(m) => m,
        Err(e) => {
            let msg = format!("Failed to fetch registry manifest: {e}");
            append_log(
                &mut update_state,
                log_entry("registry_apply", "error", msg.clone(), None),
            );
            clear_progress(&mut update_state, &state_file);
            save_state(&update_state, &state_file)?;
            anyhow::bail!(msg);
        }
    };

    // Load trusted signers if signature verification is enabled.
    let trusted_signers: Vec<ed25519_dalek::VerifyingKey> = if settings.verify_artifact_signatures
    {
        let signers_path = PathBuf::from(&settings.trusted_signers_file);
        match load_trusted_signers(&signers_path) {
            Ok(keys) => keys,
            Err(e) => {
                let msg = format!("Failed to load trusted signers: {e}");
                append_log(
                    &mut update_state,
                    log_entry("registry_apply", "error", msg.clone(), None),
                );
                clear_progress(&mut update_state, &state_file);
                save_state(&update_state, &state_file)?;
                anyhow::bail!(msg);
            }
        }
    } else {
        Vec::new()
    };

    let mut details = Vec::new();
    let mut any_error = false;

    let staging_dir = PathBuf::from(ARTIFACT_STAGING_DIR);

    for repo_component in selected_components {
        let comp_str = repo_component.as_str();

        let artifact = match manifest
            .components
            .iter()
            .find(|a| a.component == comp_str)
        {
            Some(a) => a,
            None => {
                if manifest.partial {
                    let msg = format!(
                        "Component not present in partial manifest, skipping",
                    );
                    details.push(format!("[{}] {msg}", repo_component.display_name()));
                    append_log(
                        &mut update_state,
                        log_entry("registry_apply", "info", msg, Some(comp_str)),
                    );
                } else {
                    let msg = format!("Component not found in registry manifest");
                    details.push(format!("[{}] {msg}", repo_component.display_name()));
                    append_log(
                        &mut update_state,
                        log_entry("registry_apply", "error", msg, Some(comp_str)),
                    );
                    any_error = true;
                }
                continue;
            }
        };

        let saved = find_component_state(&update_state, repo_component);
        let current_version = current_version_baseline(saved);
        let from_version = current_version.clone();

        if let Some(ref cv) = current_version {
            if !is_newer_artifact_version(cv, &artifact.version) {
                let msg = format!("Already at version {}", artifact.version);
                details.push(format!("[{}] {msg}", repo_component.display_name()));
                append_log(
                    &mut update_state,
                    log_entry("registry_apply", "info", msg, Some(comp_str)),
                );
                continue;
            }
        }

        write_progress(
            &mut update_state,
            &state_file,
            make_progress(
                "registry_apply",
                "downloading",
                "running",
                &format!("Downloading {} v{}…", repo_component.display_name(), artifact.version),
                Some(comp_str),
                None,
            ),
        );

        // Download the artifact
        let artifact_path = match download_artifact(&artifact.download_url, &staging_dir).await {
            Ok(p) => p,
            Err(e) => {
                let msg = format!("Download failed: {e}");
                details.push(format!("[{}] {msg}", repo_component.display_name()));
                append_log(
                    &mut update_state,
                    log_entry("registry_apply", "error", msg, Some(comp_str)),
                );
                any_error = true;
                continue;
            }
        };

        // Resolve and verify checksum
        if !artifact.checksum_sha256.is_empty() {
            let expected_checksum = if artifact.checksum_sha256.starts_with("http") {
                // It's a URL — fetch the actual checksum
                match resolve_checksum_url(&artifact.checksum_sha256).await {
                    Ok(c) => c,
                    Err(e) => {
                        let msg = format!("Failed to fetch checksum: {e}");
                        details.push(format!("[{}] {msg}", repo_component.display_name()));
                        append_log(
                            &mut update_state,
                            log_entry("registry_apply", "error", msg, Some(comp_str)),
                        );
                        any_error = true;
                        let _ = fs::remove_file(&artifact_path);
                        continue;
                    }
                }
            } else {
                artifact.checksum_sha256.clone()
            };

            if let Err(e) = verify_checksum(&artifact_path, &expected_checksum) {
                let msg = format!("Checksum verification failed: {e}");
                details.push(format!("[{}] {msg}", repo_component.display_name()));
                append_log(
                    &mut update_state,
                    log_entry("registry_apply", "error", msg, Some(comp_str)),
                );
                any_error = true;
                let _ = fs::remove_file(&artifact_path);
                continue;
            }
        }

        // Verify signature if configured
        if settings.verify_artifact_signatures {
            let sig_b64 = match &artifact.signature_url {
                Some(url) => match fetch_signature_body(url).await {
                    Ok(s) => s,
                    Err(e) => {
                        let msg = format!("Failed to fetch signature: {e}");
                        details.push(format!("[{}] {msg}", repo_component.display_name()));
                        append_log(
                            &mut update_state,
                            log_entry("registry_apply", "error", msg, Some(comp_str)),
                        );
                        any_error = true;
                        let _ = fs::remove_file(&artifact_path);
                        continue;
                    }
                },
                None => {
                    let msg = "Signature verification required but no signature URL in manifest".to_string();
                    details.push(format!("[{}] {msg}", repo_component.display_name()));
                    append_log(
                        &mut update_state,
                        log_entry("registry_apply", "error", msg, Some(comp_str)),
                    );
                    any_error = true;
                    let _ = fs::remove_file(&artifact_path);
                    continue;
                }
            };

            if let Err(e) = verify_artifact_signature(&artifact_path, &sig_b64, &trusted_signers) {
                let msg = format!("Signature verification failed: {e}");
                details.push(format!("[{}] {msg}", repo_component.display_name()));
                append_log(
                    &mut update_state,
                    log_entry("registry_apply", "error", msg, Some(comp_str)),
                );
                any_error = true;
                let _ = fs::remove_file(&artifact_path);
                continue;
            }
        }

        write_progress(
            &mut update_state,
            &state_file,
            make_progress(
                "registry_apply",
                "installing",
                "running",
                &format!("Installing {} v{}…", repo_component.display_name(), artifact.version),
                Some(comp_str),
                None,
            ),
        );

        // Apply (install/stage) the artifact
        match apply_downloaded_artifact(&artifact_path, repo_component) {
            Ok(()) => {
                let comp_state = ensure_component_state(&mut update_state, repo_component);
                comp_state.current_version = Some(artifact.version.clone());
                comp_state.last_applied_version = Some(artifact.version.clone());
                comp_state.update_available = false;
                comp_state.last_error = None;

                let msg = format!("Updated to v{}", artifact.version);
                details.push(format!("[{}] {msg}", repo_component.display_name()));
                append_log(
                    &mut update_state,
                    log_entry_with_versions(
                        "registry_apply",
                        "info",
                        msg,
                        Some(comp_str),
                        from_version,
                        Some(artifact.version.clone()),
                    ),
                );

                // Clean up staging file for non-rootfs components
                if !matches!(repo_component, RepoComponent::Rootfs) {
                    let _ = fs::remove_file(&artifact_path);
                }
            }
            Err(e) => {
                let comp_state = ensure_component_state(&mut update_state, repo_component);
                comp_state.last_error = Some(e.to_string());

                let msg = format!("Install failed: {e}");
                details.push(format!("[{}] {msg}", repo_component.display_name()));
                append_log(
                    &mut update_state,
                    log_entry("registry_apply", "error", msg, Some(comp_str)),
                );
                any_error = true;
                let _ = fs::remove_file(&artifact_path);
            }
        }
    }

    update_state.last_applied_at = Some(Utc::now().to_rfc3339());
    clear_progress(&mut update_state, &state_file);
    save_state(&update_state, &state_file)?;

    let status = build_status(settings, &update_state).await;
    Ok(UpdatesActionResult {
        operation: "registry_apply".to_string(),
        success: !any_error,
        message: if any_error {
            format!("Registry apply [{comp_label}] completed with errors")
        } else {
            format!("Registry apply [{comp_label}] completed successfully")
        },
        details,
        status,
    })
}

// ============================================================================
// NEW: Artifact Registry Helpers
// ============================================================================

use sha2::{Digest, Sha256};

/// Verify SHA256 checksum of a file
fn verify_checksum(file_path: &Path, expected: &str) -> Result<()> {
    let computed = compute_file_sha256(file_path)?;

    if computed != expected {
        anyhow::bail!(
            "checksum mismatch: computed {}, expected {}",
            computed,
            expected
        );
    }
    Ok(())
}

/// Parse a `trusted_signers` file.  Format mirrors `~/.ssh/authorized_keys`
/// in spirit: one signer per line, blank/`#`-prefixed lines ignored, and each
/// entry is `<name> <base64-ed25519-pubkey>`.  The pubkey is exactly 32 bytes
/// (44 base64 chars including `=` padding).
fn load_trusted_signers(path: &Path) -> Result<Vec<ed25519_dalek::VerifyingKey>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read trusted signers file {}", path.display()))?;
    let mut keys = Vec::new();
    for (lineno, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Name is optional; if present, it's the first whitespace-separated
        // token and we ignore it.  The pubkey is always the last token so
        // operators can add comments after it on a single line.
        let pubkey_b64 = line.split_whitespace().last().unwrap_or("");
        let raw = B64.decode(pubkey_b64).with_context(|| {
            format!(
                "trusted signers file {}:{}: pubkey is not valid base64",
                path.display(),
                lineno + 1
            )
        })?;
        let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "trusted signers file {}:{}: pubkey must be 32 bytes (got {})",
                path.display(),
                lineno + 1,
                raw.len()
            )
        })?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).with_context(|| {
            format!(
                "trusted signers file {}:{}: pubkey is not a valid ed25519 point",
                path.display(),
                lineno + 1
            )
        })?;
        keys.push(key);
    }
    Ok(keys)
}

/// Verify a detached ed25519 signature over the SHA256 digest of an artifact.
///
/// The signature is the base64 body of the `.sig` file the build pipeline
/// publishes alongside each artifact, and is computed as
/// `ed25519_sign(privkey, sha256(artifact_bytes))`.  Verification succeeds if
/// *any* trusted signer's public key validates the signature.
fn verify_artifact_signature(
    artifact_path: &Path,
    sig_b64: &str,
    trusted_signers: &[ed25519_dalek::VerifyingKey],
) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use ed25519_dalek::Verifier;

    if trusted_signers.is_empty() {
        anyhow::bail!(
            "no trusted signers configured; cannot verify signature for {}",
            artifact_path.display()
        );
    }

    let sig_bytes = B64
        .decode(sig_b64.trim())
        .context("artifact signature is not valid base64")?;
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "artifact signature must be 64 bytes (got {})",
            sig_bytes.len()
        )
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    let mut hasher = Sha256::new();
    {
        use std::io::Read as _;
        let mut f = std::fs::File::open(artifact_path)
            .with_context(|| format!("failed to open {} for hashing", artifact_path.display()))?;
        let mut buffer = [0u8; 65536];
        loop {
            let n = f.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
    }
    let raw_digest = hasher.finalize();
    let message: &[u8] = raw_digest.as_ref();

    for key in trusted_signers {
        if key.verify(message, &signature).is_ok() {
            return Ok(());
        }
    }
    anyhow::bail!(
        "artifact signature for {} did not match any trusted signer",
        artifact_path.display()
    );
}

/// Fetch the raw body of a `.sig` URL into memory.  Signatures are tiny
/// (~100 bytes base64) so a bounded in-memory fetch is the right tool.
async fn fetch_signature_body(url: &str) -> Result<String> {
    let client = build_http_client()?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to fetch signature from {}", url))?;
    if !response.status().is_success() {
        anyhow::bail!(
            "signature fetch {} returned HTTP {}",
            url,
            response.status()
        );
    }
    response
        .text()
        .await
        .with_context(|| format!("failed to read signature body from {}", url))
}

/// Download artifact from registry
fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("failed to build HTTP client")
}

// ============================================================================
// rootfs_update: minimal binary-safe entry point used by the initramfs hook
// ============================================================================

/// Minimal state persisted by the initramfs hook after a successful rootfs swap.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RootfsUpdateResult {
    pub version: Option<String>,
    pub applied_at: Option<String>,
    pub artifact_path: Option<String>,
}

/// Entry point for the initramfs rootfs-update hook.
/// Reads the staged rootfs artifact, installs it to `/`, and persists state.
pub fn rootfs_update() -> Result<()> {
    let staging_dir = PathBuf::from(ARTIFACT_STAGING_DIR);
    let state_file = PathBuf::from(UPDATE_STATE_FILE_PATH);

    // Find the staged rootfs artifact (a .squashfs file)
    let artifact_path = find_staged_rootfs(&staging_dir)?;
    let version = extract_asset_version(
        artifact_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(""),
        "rootfs",
    );

    // Install to /
    let dst = PathBuf::from("/");
    install_dir_atomic(&artifact_path, &dst)?;

    // Remove the staged artifact
    let _ = fs::remove_file(&artifact_path);

    // Persist state
    let mut update_state: UpdateStateFile = load_json_or_default(&state_file);
    let comp_state = ensure_component_state(&mut update_state, RepoComponent::Rootfs);
    if let Some(ref v) = version {
        comp_state.current_version = Some(v.clone());
        comp_state.last_applied_version = Some(v.clone());
    }
    comp_state.update_available = false;
    comp_state.last_error = None;
    update_state.pending_reboot = false;
    update_state.last_applied_at = Some(Utc::now().to_rfc3339());
    write_json_atomic(&state_file, &update_state)?;

    Ok(())
}

fn find_staged_rootfs(staging_dir: &Path) -> Result<PathBuf> {
    if !staging_dir.exists() {
        anyhow::bail!(
            "staging directory {} does not exist",
            staging_dir.display()
        );
    }

    let candidates: Vec<PathBuf> = fs::read_dir(staging_dir)
        .with_context(|| format!("failed to read staging directory {}", staging_dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| e == "squashfs")
                .unwrap_or(false)
        })
        .collect();

    match candidates.len() {
        0 => anyhow::bail!(
            "no staged rootfs artifact found in {}",
            staging_dir.display()
        ),
        1 => Ok(candidates.into_iter().next().unwrap()),
        _ => {
            // Multiple candidates — pick the newest by modification time
            candidates
                .into_iter()
                .max_by_key(|p| {
                    p.metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                })
                .ok_or_else(|| anyhow::anyhow!("failed to select staged rootfs artifact"))
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_artifact_version() {
        assert!(is_artifact_version("1.2.3"));
        assert!(is_artifact_version("1.2"));
        assert!(is_artifact_version("10.20.30.40"));
        assert!(!is_artifact_version("1"));
        assert!(!is_artifact_version("1.2.3-alpha"));
        assert!(!is_artifact_version(""));
        assert!(!is_artifact_version("v1.2.3"));
        assert!(!is_artifact_version("1.2."));
        assert!(!is_artifact_version(".1.2"));
    }

    #[test]
    fn test_is_newer_artifact_version() {
        assert!(is_newer_artifact_version("1.2.3", "1.2.4"));
        assert!(is_newer_artifact_version("1.2.3", "1.3.0"));
        assert!(is_newer_artifact_version("1.2.3", "2.0.0"));
        assert!(!is_newer_artifact_version("1.2.3", "1.2.3"));
        assert!(!is_newer_artifact_version("1.2.4", "1.2.3"));
        assert!(!is_newer_artifact_version("2.0.0", "1.9.9"));
        assert!(is_newer_artifact_version("1.2", "1.3"));
        assert!(is_newer_artifact_version("1.2.3", "1.2.3.1"));
    }

    #[test]
    fn test_extract_asset_version() {
        assert_eq!(
            extract_asset_version("core-v1.2.3.tar.zst", "core"),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            extract_asset_version("ui-v2.0.1.tar.gz", "ui"),
            Some("2.0.1".to_string())
        );
        assert_eq!(
            extract_asset_version("rootfs-v1.0.0.squashfs", "rootfs"),
            Some("1.0.0".to_string())
        );
        assert_eq!(
            extract_asset_version("core-1.2.3.tar.zst", "core"),
            Some("1.2.3".to_string())
        );
        assert_eq!(extract_asset_version("other-v1.2.3.tar.zst", "core"), None);
    }

    #[test]
    fn test_github_repo_parts() {
        assert_eq!(
            github_repo_parts("https://github.com/daygle/dayshield-core"),
            Some(("daygle".to_string(), "dayshield-core".to_string()))
        );
        assert_eq!(
            github_repo_parts("https://api.github.com/repos/daygle/dayshield-core"),
            Some(("daygle".to_string(), "dayshield-core".to_string()))
        );
        assert_eq!(
            github_repo_parts("git@github.com:daygle/dayshield-core.git"),
            Some(("daygle".to_string(), "dayshield-core".to_string()))
        );
        assert_eq!(github_repo_parts("https://example.com/foo"), None);
    }

    #[test]
    fn test_github_releases_to_manifest_empty() {
        let result = github_releases_to_manifest(vec![], "https://api.github.com/repos/foo/bar");
        assert!(result.is_err());
    }

    #[test]
    fn test_github_releases_to_manifest_single_release() {
        let release = GitHubRelease {
            tag_name: "v1.2.3".to_string(),
            assets: vec![
                GitHubAsset {
                    name: "core-v1.2.3.tar.zst".to_string(),
                    browser_download_url: "https://example.com/core-v1.2.3.tar.zst".to_string(),
                },
                GitHubAsset {
                    name: "core-v1.2.3.tar.zst.sha256".to_string(),
                    browser_download_url: "https://example.com/core-v1.2.3.tar.zst.sha256"
                        .to_string(),
                },
            ],
            created_at: "2024-01-01T00:00:00Z".to_string(),
            html_url: Some("https://github.com/foo/bar/releases/tag/v1.2.3".to_string()),
        };

        let result =
            github_releases_to_manifest(vec![release], "https://api.github.com/repos/foo/bar");
        assert!(result.is_ok());
        let manifest = result.unwrap();
        assert_eq!(manifest.components.len(), 1);
        let comp = &manifest.components[0];
        assert_eq!(comp.component, "core");
        assert_eq!(comp.version, "1.2.3");
        assert_eq!(
            comp.download_url,
            "https://example.com/core-v1.2.3.tar.zst"
        );
        assert_eq!(
            comp.checksum_sha256,
            "https://example.com/core-v1.2.3.tar.zst.sha256"
        );
        assert!(comp.source_tag.is_none());
        assert!(comp.source_release_url.is_none());
    }
}