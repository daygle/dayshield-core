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
pub const UPDATE_STATE_FILE_PATH: &str = "/etc/dayshield/config/updates_state.json";
const DEFAULT_CORE_URL: &str = "https://github.com/daygle/dayshield-core";
const DEFAULT_UI_URL: &str = "https://github.com/daygle/dayshield-ui";
const DEFAULT_ROOTFS_URL: &str = "https://github.com/daygle/dayshield-rootfs";
const RUNTIME_MARKER_DIR: &str = "/var/lib/dayshield/update";
const RUNTIME_ROLLBACK_DIR: &str = "/var/lib/dayshield/update/rollback";
const DEFAULT_TRUSTED_SIGNERS_FILE: &str = "/etc/dayshield/update_trusted_signers";
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
    true
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
            UpdateComponent::Both => vec![Self::Core, Self::Ui, Self::Rootfs],
        }
    }
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
        .unwrap_or(Path::new("/etc/dayshield/config"))
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

fn install_file_atomic(src: &Path, target: &Path) -> Result<()> {
    install_file_atomic_with_mode(src, target, None)
}

fn install_executable_file_atomic(src: &Path, target: &Path) -> Result<()> {
    install_file_atomic_with_mode(src, target, Some(0o755))
}

fn install_file_atomic_with_mode(src: &Path, target: &Path, mode: Option<u32>) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid target path {}", target.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let suffix = unique_suffix();
    let staged = parent.join(format!(
        "{}.new.{}",
        target.file_name().unwrap_or_default().to_string_lossy(),
        suffix
    ));
    let backup = parent.join(format!(
        "{}.bak.{}",
        target.file_name().unwrap_or_default().to_string_lossy(),
        suffix
    ));

    fs::copy(src, &staged)
        .with_context(|| format!("failed to stage {} -> {}", src.display(), staged.display()))?;
    if let Some(mode) = mode {
        set_file_mode(&staged, mode)?;
    }

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

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .with_context(|| format!("failed to read permissions for {}", path.display()))?
        .permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

fn install_dir_atomic(src: &Path, target: &Path) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid target path {}", target.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let suffix = unique_suffix();
    let staged = parent.join(format!(
        "{}.new.{}",
        target.file_name().unwrap_or_default().to_string_lossy(),
        suffix
    ));
    let backup = parent.join(format!(
        "{}.bak.{}",
        target.file_name().unwrap_or_default().to_string_lossy(),
        suffix
    ));

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

/// Find the rootfs image file inside an extracted artifact directory.
/// Looks for common rootfs image extensions.
fn find_rootfs_image(dir: &Path) -> Result<PathBuf> {
    let candidates = [
        "rootfs.squashfs",
        "rootfs.erofs",
        "rootfs.img",
        "rootfs.ext4",
    ];
    for name in &candidates {
        let path = dir.join(name);
        if path.exists() {
            return Ok(path);
        }
    }
    // Fallback: find any file with a known image extension
    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read staging dir {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "squashfs" | "erofs" | "img" | "ext4") {
                return Ok(path);
            }
        }
    }
    anyhow::bail!(
        "no rootfs image found in artifact (expected rootfs.squashfs, rootfs.erofs, or rootfs.img)"
    )
}

/// Compute a hex-encoded SHA-256 digest of a file.
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
    append_operation_log_with_versions(
        state_file, operation, level, message, component, None, None,
    );
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
    let message_str: String = message.into();

    // Publish to live logs so update actions appear in the Logs / Live Logs view.
    crate::live_logs::ui::publish(crate::live_logs::LogEvent::UpdateEvent {
        timestamp: Utc::now().to_rfc3339(),
        operation: operation.to_string(),
        level: level.to_string(),
        message: message_str.clone(),
        component: component.map(|s| s.to_string()),
    });

    state_file.operation_logs.push(UpdateLogEntry {
        timestamp: Utc::now().to_rfc3339(),
        operation: operation.to_string(),
        level: level.to_string(),
        message: message_str,
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

fn clear_rootfs_update_required(state_file: &mut UpdateStateFile) {
    clear_appliance_rebuild_required(state_file);
    let rootfs = ensure_component_state(state_file, RepoComponent::Rootfs);
    rootfs.remote_version = rootfs
        .current_version
        .clone()
        .or_else(|| rootfs.last_applied_version.clone())
        .or_else(|| Some(built_appliance_version()));
    rootfs.update_available = false;
    rootfs.last_error = None;
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

use sha2::{Digest, Sha256};

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
fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("failed to build HTTP client")
}

pub(crate) async fn download_artifact(url: &str, destination: &Path) -> Result<()> {
    let client = build_http_client()?;
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
async fn query_registry(
    registry_url: &str,
    fetch_checksums: bool,
    etag_cache: &mut HashMap<String, (String, String)>,
) -> Result<RegistryManifest> {
    let client = build_http_client()?;

    if let Some(github_api_url) = github_repo_api_url(registry_url) {
        return query_github_releases(&github_api_url, &client, fetch_checksums, etag_cache).await;
    }

    anyhow::bail!("updates: registry URL must point to a GitHub repository")
}

async fn query_registry_with_component_fallbacks(
    settings: &UpdateSettings,
    fetch_checksums: bool,
    etag_cache: &mut HashMap<String, (String, String)>,
) -> Result<RegistryManifest> {
    let mut manifest = query_registry(&settings.registry_url, fetch_checksums, etag_cache).await?;

    let mut seen_components = manifest
        .components
        .iter()
        .map(|artifact| artifact.component.clone())
        .collect::<HashSet<_>>();

    for component in ALL_REPO_COMPONENTS {
        if seen_components.contains(component.as_str()) {
            continue;
        }

        let (_, repo_url, _) = component_config(settings, component);
        let Some(api_url) = github_repo_api_url(&repo_url) else {
            warn!(
                component = component.as_str(),
                repo_url,
                "updates: component repo URL is not a GitHub repo URL; cannot query release fallback"
            );
            continue;
        };

        match query_registry(&api_url, fetch_checksums, etag_cache).await {
            Ok(component_manifest) => {
                let mut added = 0usize;
                for artifact in component_manifest
                    .components
                    .into_iter()
                    .filter(|artifact| artifact.component == component.as_str())
                {
                    manifest.components.push(artifact);
                    added += 1;
                }

                if added == 0 {
                    warn!(
                        component = component.as_str(),
                        repo_url,
                        "updates: component repo release did not include a matching artifact"
                    );
                } else {
                    seen_components.insert(component.as_str().to_string());
                }
            }
            Err(err) => {
                let err_text = err.to_string();
                if err_text.contains("HTTP 404") || component.as_str() == "rootfs" {
                    info!(
                        component = component.as_str(),
                        repo_url,
                        error = %err,
                        "updates: component repo release fallback not found"
                    );
                } else {
                    warn!(
                        component = component.as_str(),
                        repo_url,
                        error = %err,
                        "updates: failed to query component repo release fallback"
                    );
                }
            }
        }
    }

    Ok(manifest)
}

fn artifact_version_from_name(component: &str, asset_name: &str) -> Option<String> {
    let prefix = format!("{component}-v");
    let stripped = asset_name.strip_prefix(&prefix)?;
    let version = stripped
        .strip_suffix(".tar.zst")
        .or_else(|| {
            if component == "rootfs" {
                stripped.strip_suffix(".squashfs")
            } else {
                None
            }
        })
        .filter(|v| is_artifact_version(v))?;
    Some(version.to_string())
}

fn is_artifact_version(version: &str) -> bool {
    let mut segment_count = 0;
    for segment in version.split('.') {
        if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        segment_count += 1;
    }

    segment_count >= 2
}

fn artifact_version_segments(version: &str) -> Option<Vec<u64>> {
    if !is_artifact_version(version) {
        return None;
    }

    version
        .split('.')
        .map(|segment| segment.parse::<u64>().ok())
        .collect()
}

pub fn is_remote_version_newer(current: &str, remote: &str) -> bool {
    let (Some(current_segments), Some(remote_segments)) = (
        artifact_version_segments(current),
        artifact_version_segments(remote),
    ) else {
        return current != remote;
    };

    let segment_count = current_segments.len().max(remote_segments.len());
    for idx in 0..segment_count {
        let current_segment = current_segments.get(idx).copied().unwrap_or(0);
        let remote_segment = remote_segments.get(idx).copied().unwrap_or(0);
        if remote_segment != current_segment {
            return remote_segment > current_segment;
        }
    }

    false
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn checksum_from_text(text: &str, filename: &str) -> Option<String> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(checksum) = parts.next() else {
            continue;
        };
        if !is_sha256_hex(checksum) {
            continue;
        }

        let Some(listed_name) = parts.next() else {
            return Some(checksum.to_string());
        };
        let listed_name = listed_name.trim_start_matches('*').trim_start_matches("./");

        if listed_name == filename || listed_name.ends_with(&format!("/{filename}")) {
            return Some(checksum.to_string());
        }
    }

    None
}

async fn fetch_github_asset_text(client: &reqwest::Client, asset: &GitHubAsset) -> Result<String> {
    client
        .get(&asset.browser_download_url)
        .header(USER_AGENT, HeaderValue::from_static(UPDATE_HTTP_USER_AGENT))
        .send()
        .await
        .with_context(|| format!("failed to fetch {}", asset.name))?
        .text()
        .await
        .with_context(|| format!("failed to read {}", asset.name))
}

async fn populate_github_release_checksums(
    client: &reqwest::Client,
    release: &GitHubRelease,
    components: &mut [ArtifactMetadata],
) {
    if let Some(checksums_asset) = release.assets.iter().find(|a| a.name == "checksums.txt") {
        match fetch_github_asset_text(client, checksums_asset).await {
            Ok(checksums_text) => {
                for component in components.iter_mut() {
                    let Some(filename) = component.download_url.rsplit('/').next() else {
                        continue;
                    };
                    if let Some(checksum) = checksum_from_text(&checksums_text, filename) {
                        component.checksum_sha256 = checksum;
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "updates: failed to fetch checksums.txt from release");
            }
        }
    }

    for component in components.iter_mut() {
        if !component.checksum_sha256.is_empty() {
            continue;
        }

        let Some(artifact_name) = component.download_url.rsplit('/').next() else {
            continue;
        };
        let checksum_name = format!("{artifact_name}.sha256");
        let Some(checksum_asset) = release.assets.iter().find(|a| a.name == checksum_name) else {
            warn!(
                component = %component.component,
                artifact = artifact_name,
                "updates: no checksum asset found for GitHub release artifact"
            );
            continue;
        };

        match fetch_github_asset_text(client, checksum_asset).await {
            Ok(checksum_text) => {
                if let Some(checksum) = checksum_from_text(&checksum_text, artifact_name) {
                    component.checksum_sha256 = checksum;
                } else {
                    warn!(
                        component = %component.component,
                        artifact = artifact_name,
                        "updates: checksum asset did not contain a SHA-256 for artifact"
                    );
                }
            }
            Err(e) => {
                warn!(
                    component = %component.component,
                    artifact = artifact_name,
                    error = %e,
                    "updates: failed to fetch artifact checksum asset"
                );
            }
        }
    }
}

/// Query GitHub Releases API for latest release artifacts.
///
/// Uses ETag-based conditional requests: if the cached ETag matches the
/// server's current ETag, GitHub returns 304 Not Modified which does NOT
/// count against the unauthenticated rate limit (60 req/hr/IP).
async fn query_github_releases(
    github_api_url: &str,
    client: &reqwest::Client,
    fetch_checksums: bool,
    etag_cache: &mut HashMap<String, (String, String)>,
) -> Result<RegistryManifest> {
    use reqwest::header::IF_NONE_MATCH;

    // Construct API URL: https://api.github.com/repos/{owner}/{repo}/releases/latest
    let releases_url = if github_api_url.ends_with('/') {
        format!("{}releases/latest", github_api_url)
    } else {
        format!("{}/releases/latest", github_api_url)
    };

    let mut request = client
        .get(&releases_url)
        .header(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        )
        .header(USER_AGENT, HeaderValue::from_static(UPDATE_HTTP_USER_AGENT))
        .header(
            HeaderName::from_static("x-github-api-version"),
            HeaderValue::from_static("2022-11-28"),
        );

    // Attach cached ETag so GitHub can return 304 (free, no rate-limit cost)
    if let Some((cached_etag, _)) = etag_cache.get(&releases_url) {
        if let Ok(val) = HeaderValue::from_str(cached_etag) {
            request = request.header(IF_NONE_MATCH, val);
        }
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("failed to query GitHub releases from {}", releases_url))?;

    let status = response.status();

    // 304 Not Modified — use cached body (free, doesn't count against rate limit)
    if status == reqwest::StatusCode::NOT_MODIFIED {
        if let Some((_, cached_body)) = etag_cache.get(&releases_url) {
            let release: GitHubRelease = serde_json::from_str(cached_body)
                .with_context(|| "failed to parse cached GitHub release")?;
            return build_manifest_from_release(release, client, fetch_checksums, github_api_url)
                .await;
        }
        // Cache miss despite 304 — remove stale entry and bail; next attempt re-fetches
        etag_cache.remove(&releases_url);
        anyhow::bail!(
            "GitHub returned 304 but ETag cache is empty for {}",
            releases_url
        );
    }

    if !status.is_success() {
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

    // 200 — store new ETag and body for future conditional requests
    let new_etag = response
        .headers()
        .get("ETag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body = response.text().await.with_context(|| {
        format!(
            "failed to read GitHub release response from {}",
            releases_url
        )
    })?;

    if let Some(etag) = new_etag {
        etag_cache.insert(releases_url.clone(), (etag, body.clone()));
    }

    let release: GitHubRelease = serde_json::from_str(&body)
        .with_context(|| format!("failed to parse GitHub release from {}", releases_url))?;

    build_manifest_from_release(release, client, fetch_checksums, github_api_url).await
}

/// Convert a parsed `GitHubRelease` into a `RegistryManifest`.
/// Shared by the fresh-fetch (200) and cached (304) paths.
async fn build_manifest_from_release(
    release: GitHubRelease,
    client: &reqwest::Client,
    fetch_checksums: bool,
    github_api_url: &str,
) -> Result<RegistryManifest> {
    let mut components = Vec::new();
    let component_names = ["core", "ui", "rootfs"];
    let source_repo = github_repo_slug(github_api_url);

    for comp_name in &component_names {
        // For rootfs prefer the standalone squashfs image artifact over the full
        // rootfs archive — the squashfs is what the initramfs update hook uses.
        let asset_opt = if *comp_name == "rootfs" {
            release
                .assets
                .iter()
                .find(|a| {
                    a.name.ends_with(".squashfs")
                        && artifact_version_from_name("rootfs", &a.name).is_some()
                })
                .or_else(|| {
                    release
                        .assets
                        .iter()
                        .find(|a| artifact_version_from_name(comp_name, &a.name).is_some())
                })
        } else {
            release
                .assets
                .iter()
                .find(|a| artifact_version_from_name(comp_name, &a.name).is_some())
        };

        if let Some(asset) = asset_opt {
            let version_str = artifact_version_from_name(comp_name, &asset.name)
                .unwrap_or_else(|| release.tag_name.trim_start_matches('v').to_string());

            components.push(ArtifactMetadata {
                component: comp_name.to_string(),
                version: version_str.clone(),
                download_url: asset.browser_download_url.clone(),
                checksum_sha256: String::new(),
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
        let found: Vec<&str> = release.assets.iter().map(|a| a.name.as_str()).collect();
        if found.is_empty() {
            anyhow::bail!(
                "GitHub release {} has no published assets (release may still be building)",
                release.tag_name
            );
        } else {
            anyhow::bail!(
                "GitHub release {} has no artifacts matching patterns core-v*.tar.zst / ui-v*.tar.zst / rootfs-v*.squashfs; found: {}",
                release.tag_name,
                found.join(", ")
            );
        }
    }

    if fetch_checksums {
        populate_github_release_checksums(client, &release, &mut components).await;
    }

    Ok(RegistryManifest {
        components,
        generated_at: release.created_at.clone(),
        partial: true,
    })
}

/// Extract artifact and deploy to target location
/// Stage a standalone rootfs squashfs image directly to the update staging dir.
/// Bypasses the tar/zstd path entirely — the squashfs is not archive-wrapped.
fn stage_rootfs_squashfs_direct(artifact_path: &Path) -> Result<()> {
    let staging_dir = PathBuf::from(crate::rootfs_update::ROOTFS_UPDATE_STAGING_DIR);
    fs::create_dir_all(&staging_dir)?;

    let image_filename = artifact_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("rootfs.squashfs")
        .to_string();

    let dest = staging_dir.join(&image_filename);
    // Use plain file mode (0o644) — squashfs is a data image, not an executable.
    install_file_atomic_with_mode(artifact_path, &dest, Some(0o644))?;

    let sha256 = compute_file_sha256(&dest)?;

    let version = artifact_path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| artifact_version_from_name("rootfs", n))
        .unwrap_or_else(|| "unknown".to_string());

    if let Err(err) = crate::rootfs_update::mark_pending(&version, &dest, &sha256) {
        warn!(
            error = %err,
            version,
            "updates: failed to write rootfs pending marker; artifact staged but not marked"
        );
    } else {
        info!(
            version,
            artifact = %dest.display(),
            "updates: rootfs squashfs staged and pending marker written"
        );
    }

    Ok(())
}

async fn extract_and_deploy_artifact(
    component: RepoComponent,
    artifact_path: &Path,
    target_dir: Option<&Path>,
) -> Result<()> {
    // Rootfs squashfs images are not tar-wrapped — handle them directly.
    if matches!(component, RepoComponent::Rootfs)
        && artifact_path.extension().and_then(|e| e.to_str()) == Some("squashfs")
    {
        return stage_rootfs_squashfs_direct(artifact_path);
    }

    let artifact_file = std::fs::File::open(artifact_path)
        .with_context(|| format!("failed to open artifact {}", artifact_path.display()))?;

    let decoder = zstd::stream::Decoder::new(artifact_file).with_context(|| {
        format!(
            "failed to initialize zstd decoder for {}",
            artifact_path.display()
        )
    })?;

    let mut archive = tar::Archive::new(decoder);

    match component {
        RepoComponent::Core => {
            let tmp_dir = PathBuf::from("/tmp/dayshield-core-deploy");
            fs::create_dir_all(&tmp_dir)?;
            archive
                .unpack(&tmp_dir)
                .with_context(|| format!("failed to extract core artifact"))?;

            let binary = tmp_dir.join("dayshield-core");
            if !binary.exists() {
                anyhow::bail!("core binary not found in artifact");
            }

            install_executable_file_atomic(&binary, Path::new("/usr/local/sbin/dayshield-core"))?;

            // Also update the rootfs-update helper when bundled in the core artifact
            let helper = tmp_dir.join("rootfs-update.sh");
            if helper.exists() {
                let helper_dest = Path::new(crate::rootfs_update::ROOTFS_UPDATE_HELPER);
                match install_executable_file_atomic(&helper, helper_dest) {
                    Ok(()) => info!(
                        target = %helper_dest.display(),
                        "updates: installed bundled rootfs-update helper"
                    ),
                    Err(err) => warn!(
                        error = %err,
                        target = %helper_dest.display(),
                        "updates: skipping bundled rootfs-update helper install"
                    ),
                }
            }

            let _ = fs::remove_dir_all(&tmp_dir);
        }
        RepoComponent::Ui => {
            let target = target_dir.unwrap_or(Path::new("/usr/local/share/dayshield-ui"));
            let tmp_dir = PathBuf::from("/tmp/dayshield-ui-deploy");
            fs::create_dir_all(&tmp_dir)?;
            archive
                .unpack(&tmp_dir)
                .with_context(|| format!("failed to extract ui artifact"))?;

            let dist_dir = tmp_dir.join("dist");
            if !dist_dir.exists() {
                anyhow::bail!("dist directory not found in ui artifact");
            }

            install_dir_atomic(&dist_dir, target)?;
            let _ = fs::remove_dir_all(&tmp_dir);
        }
        RepoComponent::Rootfs => {
            // Stage the rootfs image artifact for initramfs-driven activation
            // on the next boot.  The artifact is a .tar.zst containing a
            // rootfs image file (e.g. rootfs.squashfs).
            let staging_dir = PathBuf::from(crate::rootfs_update::ROOTFS_UPDATE_STAGING_DIR);
            fs::create_dir_all(&staging_dir)?;

            // Extract to a temp location first
            let tmp_dir = PathBuf::from("/tmp/dayshield-rootfs-stage");
            fs::create_dir_all(&tmp_dir)?;
            archive
                .unpack(&tmp_dir)
                .with_context(|| "failed to extract rootfs artifact")?;

            // Find the rootfs image file inside the extracted archive
            let image_path = find_rootfs_image(&tmp_dir)?;
            let image_filename = image_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("rootfs.img")
                .to_string();

            let dest = staging_dir.join(&image_filename);
            install_executable_file_atomic(&image_path, &dest)?;
            let _ = fs::remove_dir_all(&tmp_dir);

            // Compute SHA-256 of the staged image for integrity verification
            let sha256 = compute_file_sha256(&dest)?;

            // Extract version from artifact filename, e.g. rootfs-v1.2.3.tar.zst
            let version = artifact_path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| artifact_version_from_name("rootfs", n))
                .unwrap_or_else(|| "unknown".to_string());

            // Write the pending-version marker for rootfs_update and the
            // initramfs to pick up on the next boot.
            if let Err(err) = crate::rootfs_update::mark_pending(&version, &dest, &sha256) {
                warn!(
                    error = %err,
                    version,
                    "updates: failed to write rootfs pending marker; artifact staged but not marked"
                );
            } else {
                info!(
                    version,
                    artifact = %dest.display(),
                    "updates: rootfs artifact staged and pending marker written"
                );
            }
        }
    }

    Ok(())
}

async fn build_component_status(
    settings: &UpdateSettings,
    state_file: &UpdateStateFile,
    component: RepoComponent,
) -> ComponentUpdateStatus {
    let (repo_path, _remote_url, branch) = component_config(settings, component);
    let saved = find_component_state(state_file, component);

    ComponentUpdateStatus {
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
        rollback_version: saved.and_then(|s| s.rollback_version.clone()),
        last_applied_commit: None,
        last_applied_version: saved.and_then(|s| s.last_applied_version.clone()),
        last_error: saved.and_then(|s| s.last_error.clone()),
    }
}

pub async fn get_status(state: &AppState) -> UpdatesStatus {
    let settings = load_settings(state);
    let state_file = load_state(state);

    let core = build_component_status(&settings, &state_file, RepoComponent::Core).await;
    let ui = build_component_status(&settings, &state_file, RepoComponent::Ui).await;
    let rootfs = build_component_status(&settings, &state_file, RepoComponent::Rootfs).await;

    let components = vec![core, ui, rootfs];
    let available_update_count = components.iter().filter(|c| c.update_available).count();

    // Include reboot_required from the rootfs pending-update marker if present.
    let rootfs_reboot_required = crate::rootfs_update::reboot_state_sync();

    UpdatesStatus {
        settings,
        last_checked_at: state_file.last_checked_at,
        last_applied_at: state_file.last_applied_at,
        pending_reboot: state_file.pending_reboot || rootfs_reboot_required,
        pending_appliance_rebuild: state_file.pending_appliance_rebuild,
        appliance_rebuild_reason: state_file.appliance_rebuild_reason,
        appliance_rebuild_marked_at: state_file.appliance_rebuild_marked_at,
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

    match query_registry_with_component_fallbacks(
        &settings,
        false,
        &mut state_file.release_etag_cache,
    )
    .await
    {
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
                        .map(|current| is_remote_version_newer(current, &artifact.version))
                        .unwrap_or(false);
                    comp_state.remote_version = Some(artifact.version.clone());
                    comp_state.update_available = update_available;
                    comp_state.last_error = None;
                    update_available
                };

                if matches!(comp, RepoComponent::Rootfs) && !update_available {
                    clear_rootfs_update_required(&mut state_file);
                }

                info!(
                    component = %artifact.component,
                    version = %artifact.version,
                    update_available,
                    "updates: registry has available version"
                );
            }

            if !seen_components.contains(RepoComponent::Rootfs.as_str()) {
                clear_rootfs_update_required(&mut state_file);
            }

            save_state(state, &state_file)?;
            Ok(())
        }
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

    // Step 1: Query registry for latest versions (with checksums for artifact verification)
    let manifest = query_registry_with_component_fallbacks(
        &settings,
        true,
        &mut state_file.release_etag_cache,
    )
    .await?;

    // Step 2: Download all artifacts to staging area
    let staging_dir = PathBuf::from(ARTIFACT_STAGING_DIR);
    fs::create_dir_all(&staging_dir)?;

    let transaction_id = uuid::Uuid::new_v4().to_string();
    let transaction_staging = staging_dir.join(&transaction_id);
    fs::create_dir_all(&transaction_staging)?;

    let mut downloads = Vec::new();
    let mut skipped_up_to_date: Vec<String> = Vec::new();

    for comp in &components_to_update {
        let artifact_opt = manifest.components.iter().find(|a| match comp {
            RepoComponent::Core => a.component == "core",
            RepoComponent::Ui => a.component == "ui",
            RepoComponent::Rootfs => a.component == "rootfs",
        });

        if let Some(artifact) = artifact_opt {
            let current_version = state_file
                .components
                .iter()
                .find(|entry| entry.component == artifact.component)
                .and_then(|entry| {
                    entry
                        .current_version
                        .clone()
                        .or_else(|| entry.last_applied_version.clone())
                });

            if current_version
                .as_deref()
                .map(|current| !is_remote_version_newer(current, &artifact.version))
                .unwrap_or(false)
            {
                skipped_up_to_date.push(format!("{}-{}", artifact.component, artifact.version));
                append_operation_log(
                    &mut state_file,
                    "apply",
                    "info",
                    format!(
                        "{} already at or newer than v{}; skipping apply",
                        artifact.component, artifact.version
                    ),
                    Some(&artifact.component),
                );
                continue;
            }

            // Use the actual filename from the download URL so the file
            // extension is preserved (.squashfs for rootfs, .tar.zst for others).
            // extract_and_deploy_artifact dispatches on the extension.
            let dest_filename = artifact
                .download_url
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    format!("{}-{}.tar.zst", &artifact.component, &artifact.version)
                });
            let dest = transaction_staging.join(&dest_filename);

            download_artifact(&artifact.download_url, &dest).await?;
            if artifact.checksum_sha256.is_empty() {
                if settings.verify_artifact_signatures {
                    anyhow::bail!(
                        "no checksum available for {}; cannot verify artifact integrity",
                        dest_filename
                    );
                } else {
                    warn!(
                        component = %artifact.component,
                        version = %artifact.version,
                        "updates: no checksum available for artifact; skipping verification"
                    );
                }
            } else {
                verify_checksum(&dest, &artifact.checksum_sha256)?;
            }

            downloads.push((artifact.component.clone(), artifact.version.clone(), dest));
            details.push(format!(
                "downloaded and verified {}-{}",
                &artifact.component, &artifact.version
            ));
            append_operation_log(
                &mut state_file,
                "apply",
                "info",
                format!(
                    "Downloaded and verified {}-{}",
                    &artifact.component, &artifact.version
                ),
                Some(&artifact.component),
            );
        } else {
            append_operation_log(
                &mut state_file,
                "apply",
                "info",
                format!(
                    "No published artifact entry for '{}' in current release set; skipping",
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
        let message = if !skipped_up_to_date.is_empty() {
            format!("no updates available for selected components: {selected}")
        } else {
            format!("no matching artifacts were published for selected components: {selected}")
        };
        details.push(message.clone());
        if !skipped_up_to_date.is_empty() {
            details.push(format!(
                "already current: {}",
                skipped_up_to_date.join(", ")
            ));
        }
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

    let config_snapshot =
        match snapshot_config_for_rollback(state, settings.encrypt_update_config_backups) {
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
        format!(
            "Created config backup archive: {}",
            config_snapshot.display()
        ),
        None,
    );
    save_state(state, &state_file)?;

    // Step 3: Backup currently deployed runtime artifacts for rollback.
    for comp in &components_to_update {
        if !component_supports_runtime_deploy(*comp) {
            continue;
        }

        if let Err(err) = snapshot_runtime_for_rollback(*comp) {
            let msg = format!(
                "failed to create rollback snapshot for {}: {}",
                comp.as_str(),
                err
            );
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
                        Some(prev) => {
                            format!("Deployed {} from v{} to v{}", component_name, prev, version)
                        }
                        None => format!("Deployed {} to v{}", component_name, version),
                    },
                    Some(component_name),
                    previous_version.as_deref(),
                    Some(version.as_str()),
                );
            }
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
    let runtime_downloaded = downloads
        .iter()
        .any(|(component_name, _, _)| matches!(component_name.as_str(), "core" | "ui"));
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
        message: "updates applied successfully".to_string(),
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
    let selected = RepoComponent::from_update_component(component);
    apply_repo_component_selection(state, selected, force_partial_apply).await
}

async fn apply_repo_component_selection(
    state: &AppState,
    selected: Vec<RepoComponent>,
    force_partial_apply: bool,
) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;

    ensure_registry_updatable_selection(&selected)?;

    // Check atomicity constraint before proceeding
    check_atomicity_constraint(state, &selected, force_partial_apply).await?;

    // Registry-based update application (artifact distribution)
    apply_updates_registry(state, selected).await
}

pub async fn rollback_updates(
    state: &AppState,
    component: UpdateComponent,
    force_partial_apply: bool,
) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;

    let mut state_file = load_state(state);
    let selected = RepoComponent::from_update_component(component);
    ensure_registry_updatable_selection(&selected)?;

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
        let previous_version = {
            let entry = ensure_component_state(&mut state_file, comp);
            entry.rollback_version.clone()
        };

        let target_version = match previous_version {
            Some(version) => version,
            None => {
                let msg = format!("{}: no rollback snapshot/version available", comp.as_str());
                details.push(msg.clone());
                append_operation_log(
                    &mut state_file,
                    "rollback",
                    "error",
                    msg.clone(),
                    Some(comp.as_str()),
                );
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
            append_operation_log(
                &mut state_file,
                "rollback",
                "error",
                msg.clone(),
                Some(comp.as_str()),
            );
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

        details.push(format!(
            "{}: rolled back to {}",
            comp.as_str(),
            target_version
        ));
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
        let msg = format!(
            "failed to restore config snapshot ({}): {}",
            snapshot_path.display(),
            err
        );
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
        format!(
            "Restored config backup archive: {}",
            snapshot_path.display()
        ),
        None,
    );
    state_file.config_rollback_path = None;

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
                    details.push(format!(
                        "{}: registry validation ok ({})",
                        comp.component, current
                    ));
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
                    details.push(format!(
                        "{}: unable to determine current version",
                        comp.component
                    ));
                }
            }
        } else {
            // Git mode: validate using commits
            match (&comp.current_commit, &comp.last_applied_commit) {
                (Some(current), Some(applied)) if current == applied => {
                    details.push(format!(
                        "{}: git validation ok ({})",
                        comp.component,
                        short_sha(current)
                    ));
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

fn component_update_available(status: &UpdatesStatus, component: &str) -> bool {
    status
        .components
        .iter()
        .any(|entry| entry.component == component && entry.update_available)
}

fn runtime_update_selection(status: &UpdatesStatus) -> Vec<RepoComponent> {
    let mut selected = Vec::new();
    if component_update_available(status, RepoComponent::Core.as_str()) {
        selected.push(RepoComponent::Core);
    }
    if component_update_available(status, RepoComponent::Ui.as_str()) {
        selected.push(RepoComponent::Ui);
    }
    selected
}

fn component_selection_label(components: &[RepoComponent]) -> String {
    components
        .iter()
        .map(|component| component.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn append_scheduled_log(
    state: &AppState,
    operation: &str,
    level: &str,
    message: impl Into<String>,
    component: Option<&str>,
) -> Result<()> {
    let mut state_file = load_state(state);
    append_operation_log(&mut state_file, operation, level, message, component);
    save_state(state, &state_file)
}

async fn request_scheduled_reboot(state: &AppState, reason: &str) -> Result<()> {
    append_scheduled_log(state, "reboot", "info", reason, Some("rootfs"))?;
    info!(reason = %reason, "updates: scheduled reboot requested");

    Command::new("systemctl")
        .arg("--no-block")
        .arg("reboot")
        .spawn()
        .with_context(|| "failed to spawn systemctl reboot for scheduled update")?
        .wait()
        .await
        .with_context(|| "systemctl reboot failed for scheduled update")?;

    Ok(())
}

async fn activate_scheduled_rootfs_update(
    state: &AppState,
    settings: &UpdateSettings,
) -> Result<()> {
    append_scheduled_log(
        state,
        "apply",
        "info",
        "Scheduled system image activation started",
        Some("rootfs"),
    )?;

    let result = crate::rootfs_update::apply_update().await?;
    append_scheduled_log(
        state,
        "apply",
        if result.success { "success" } else { "error" },
        result.message.clone(),
        Some("rootfs"),
    )?;

    if !result.success {
        anyhow::bail!(result.message);
    }

    if settings.auto_reboot_after_apply {
        request_scheduled_reboot(
            state,
            "Scheduled system image update activated; rebooting automatically",
        )
        .await?;
    } else {
        append_scheduled_log(
            state,
            "apply",
            "info",
            "Scheduled system image update activated; reboot required",
            Some("rootfs"),
        )?;
    }

    Ok(())
}

async fn run_scheduled_update_actions(
    state: &AppState,
    status: &UpdatesStatus,
    settings: &UpdateSettings,
) -> Result<()> {
    if !settings.auto_apply_updates {
        return Ok(());
    }

    let rootfs_status = crate::rootfs_update::status().await;
    if rootfs_status.reboot_required {
        if settings.auto_reboot_after_apply {
            request_scheduled_reboot(
                state,
                "Scheduled system image update is pending; rebooting automatically",
            )
            .await?;
        } else {
            append_scheduled_log(
                state,
                "apply",
                "info",
                "Scheduled app updates deferred until the pending system image update has booted",
                Some("rootfs"),
            )?;
        }
        return Ok(());
    }

    if component_update_available(status, RepoComponent::Rootfs.as_str()) {
        append_scheduled_log(
            state,
            "apply",
            "info",
            "Scheduled update applying system image before app updates",
            Some("rootfs"),
        )?;

        let result =
            apply_repo_component_selection(state, vec![RepoComponent::Rootfs], false).await?;
        if !result.success {
            anyhow::bail!(result.message);
        }

        activate_scheduled_rootfs_update(state, settings).await?;
        return Ok(());
    }

    if !settings.deploy_runtime_after_apply {
        append_scheduled_log(
            state,
            "apply",
            "info",
            "Scheduled app update deployment skipped by update settings",
            None,
        )?;
        return Ok(());
    }

    let runtime_components = runtime_update_selection(status);
    if runtime_components.is_empty() {
        return Ok(());
    }

    let runtime_label = component_selection_label(&runtime_components);
    append_scheduled_log(
        state,
        "apply",
        "info",
        format!("Scheduled app update deployment started for {runtime_label}"),
        None,
    )?;

    let result = apply_repo_component_selection(state, runtime_components, false).await?;
    if !result.success {
        anyhow::bail!(result.message);
    }

    append_scheduled_log(
        state,
        "apply",
        "success",
        "Scheduled app update deployment completed",
        None,
    )?;

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
                || (now.time().hour() == scheduled_time.hour()
                    && now.time().minute() < scheduled_time.minute())
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
                    let available = status
                        .components
                        .iter()
                        .filter(|c| c.update_available)
                        .count();
                    info!(available, "updates: periodic check completed");
                    if let Err(err) =
                        run_scheduled_update_actions(&state, &status, &settings).await
                    {
                        warn!(error = %err, "updates: scheduled update action failed");
                    }
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
    #[cfg(unix)]
    use super::install_executable_file_atomic;
    use super::{
        artifact_version_from_name, checksum_from_text, github_repo_api_url, github_repo_slug,
        ArtifactMetadata, RegistryManifest,
    };

    #[test]
    fn github_repo_slug_extracts_owner_and_repo() {
        assert_eq!(
            github_repo_slug("https://api.github.com/repos/daygle/dayshield-core"),
            Some("daygle/dayshield-core".to_string())
        );
        assert_eq!(
            github_repo_slug("https://github.com/daygle/dayshield-ui.git"),
            Some("daygle/dayshield-ui".to_string())
        );
        assert_eq!(github_repo_slug("https://example.com"), None);
    }

    #[test]
    fn github_repo_api_url_normalizes_supported_github_urls() {
        assert_eq!(
            github_repo_api_url("https://github.com/daygle/dayshield-ui"),
            Some("https://api.github.com/repos/daygle/dayshield-ui".to_string())
        );
        assert_eq!(
            github_repo_api_url(
                "https://api.github.com/repos/daygle/dayshield-rootfs/releases/latest"
            ),
            Some("https://api.github.com/repos/daygle/dayshield-rootfs".to_string())
        );
    }

    #[test]
    fn artifact_version_from_name_requires_component_tarball_name() {
        assert_eq!(
            artifact_version_from_name("ui", "ui-v1.2.3.tar.zst"),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            artifact_version_from_name("rootfs", "rootfs-v1.0.1.tar.zst"),
            Some("1.0.1".to_string())
        );
        assert_eq!(
            artifact_version_from_name("rootfs", "rootfs-v2026.05.21.tar.zst"),
            Some("2026.05.21".to_string())
        );
        // Rootfs also accepts the standalone squashfs image artifact
        assert_eq!(
            artifact_version_from_name("rootfs", "rootfs-v1.2.3.squashfs"),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            artifact_version_from_name("rootfs", "rootfs-v2026.05.21.squashfs"),
            Some("2026.05.21".to_string())
        );
        // squashfs suffix is rootfs-only; other components must use .tar.zst
        assert_eq!(
            artifact_version_from_name("core", "core-v1.2.3.squashfs"),
            None
        );
        assert_eq!(
            artifact_version_from_name("ui", "dayshield-ui-v1.2.3.tar.zst"),
            None
        );
    }

    #[test]
    fn remote_version_detection_requires_newer_numeric_version() {
        assert!(super::is_remote_version_newer("1.0.0", "1.0.1"));
        assert!(super::is_remote_version_newer("1.0.9", "1.0.10"));
        assert!(!super::is_remote_version_newer("1.0.0", "1.0.0"));
        assert!(!super::is_remote_version_newer("1.0.1", "1.0.0"));
        assert!(!super::is_remote_version_newer("1.0.0", "1.0"));
    }

    #[test]
    fn checksum_from_text_supports_checksum_files_and_sidecars() {
        let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            checksum_from_text(
                &format!("{checksum}  ui-v1.2.3.tar.zst\n"),
                "ui-v1.2.3.tar.zst"
            ),
            Some(checksum.to_string())
        );
        assert_eq!(
            checksum_from_text(&format!("{checksum}\n"), "rootfs-v1.2.3.tar.zst"),
            Some(checksum.to_string())
        );
        assert_eq!(
            checksum_from_text(
                &format!("{checksum}  core-v1.2.3.tar.zst\n"),
                "ui-v1.2.3.tar.zst"
            ),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_executable_file_atomic_sets_executable_mode() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let dir = tempfile::tempdir().expect("temp dir");
        let src = dir.path().join("helper.sh");
        let target = dir.path().join("installed-helper.sh");
        fs::write(&src, b"#!/bin/sh\n").expect("write helper");
        fs::set_permissions(&src, fs::Permissions::from_mode(0o644))
            .expect("set source permissions");

        install_executable_file_atomic(&src, &target).expect("install executable");

        let mode = fs::metadata(&target)
            .expect("target metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn manifest_supports_independent_component_metadata() {
        let manifest = RegistryManifest {
            generated_at: "2026-05-18T00:00:00Z".to_string(),
            partial: false,
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
