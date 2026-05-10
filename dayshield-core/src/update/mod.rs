use std::{
    env,
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::{process::Command, sync::Mutex};
use tracing::{info, warn};

use crate::state::AppState;

const SETTINGS_FILE: &str = "updates_settings.json";
const STATE_FILE: &str = "updates_state.json";
const DEFAULT_CORE_URL: &str = "https://github.com/daygle/dayshield-core";
const DEFAULT_UI_URL: &str = "https://github.com/daygle/dayshield-ui";
const DEFAULT_ROOTFS_URL: &str = "https://github.com/daygle/dayshield-rootfs";
const RUNTIME_MARKER_DIR: &str = "/var/lib/dayshield/update";
const DEFAULT_TRUSTED_SIGNERS_FILE: &str = "/etc/dayshield/update_trusted_signers";
const ROOTFS_LIVE_REPORT_FILE: &str = "/var/lib/dayshield/rootfs-live-update/last-run.json";

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
    60
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

fn op_lock() -> &'static Mutex<()> {
    static OP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    OP_LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSettings {
    #[serde(default = "default_auto_check_enabled")]
    pub auto_check_enabled: bool,
    #[serde(default = "default_check_interval_minutes")]
    pub check_interval_minutes: u64,
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
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            auto_check_enabled: default_auto_check_enabled(),
            check_interval_minutes: default_check_interval_minutes(),
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentState {
    pub component: String,
    pub rollback_commit: Option<String>,
    pub last_applied_commit: Option<String>,
    pub deployed_commit: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStateFile {
    pub last_checked_at: Option<String>,
    pub last_applied_at: Option<String>,
    pub pending_reboot: bool,
    pub pending_appliance_rebuild: bool,
    pub appliance_rebuild_reason: Option<String>,
    pub appliance_rebuild_marked_at: Option<String>,
    #[serde(default)]
    pub components: Vec<ComponentState>,
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
    pub update_available: bool,
    pub rollback_commit: Option<String>,
    pub last_applied_commit: Option<String>,
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
    pub rootfs_live_update: Option<RootfsLiveUpdateSummary>,
    pub components: Vec<ComponentUpdateStatus>,
    /// Number of components with available updates (computed server-side)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_update_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RootfsLiveUpdateSummary {
    pub report_timestamp: Option<String>,
    pub report_commit: Option<String>,
    #[serde(default)]
    pub staged_files: Vec<String>,
    pub backup_dir: Option<String>,
    #[serde(default)]
    pub changed_units: Vec<String>,
    pub migration_from_version: Option<u64>,
    pub migration_to_version: Option<u64>,
    pub rollback_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RootfsLiveUpdateReport {
    pub timestamp: Option<String>,
    pub commit: Option<String>,
    #[serde(default)]
    pub staged_files: Vec<String>,
    pub backup_dir: Option<String>,
    #[serde(default)]
    pub changed_units: Vec<String>,
    pub migration_from_version: Option<u64>,
    pub migration_to_version: Option<u64>,
    pub rollback_available: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RootfsLiveUpdatePolicy {
    pub require_rebuild: Option<bool>,
    pub reason: Option<String>,
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
    matches!(component, RepoComponent::Core | RepoComponent::Ui | RepoComponent::Rootfs)
}

fn runtime_marker_path(component: RepoComponent) -> PathBuf {
    Path::new(RUNTIME_MARKER_DIR).join(format!("{}_deployed_commit", component.as_str()))
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

fn ensure_parent_writable(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid path {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;

    let probe = parent.join(format!(".dayshield-write-probe-{}", unique_suffix()));
    std::fs::write(&probe, b"probe")
        .with_context(|| format!("path is not writable: {}", parent.display()))?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

async fn preflight_component(settings: &UpdateSettings, component: RepoComponent) -> Result<(String, String)> {
    let (repo_path, remote_url, branch) = component_config(settings, component);

    if matches!(component, RepoComponent::Rootfs) {
        ensure_rootfs_repo_bootstrapped(settings).await?;
    }

    ensure_repo_writable(&repo_path)
        .with_context(|| format!("{}: repo preflight failed", component.as_str()))?;

    let (current, remote, dirty) = inspect_repo(&repo_path, &remote_url, &branch)
        .await
        .with_context(|| format!("{}: inspect preflight failed", component.as_str()))?;

    if dirty {
        anyhow::bail!(
            "{}: repository has local changes; aborting update to avoid destructive reset",
            component.as_str()
        );
    }

    if settings.deploy_runtime_after_apply && component_supports_runtime_deploy(component) {
        match component {
            RepoComponent::Core => {
                ensure_parent_writable(Path::new("/usr/local/sbin/dayshield-core"))?;
            }
            RepoComponent::Ui => {
                ensure_parent_writable(Path::new("/usr/local/share/dayshield-ui"))?;
            }
            RepoComponent::Rootfs => {
                ensure_command_available("sh").await?;
                if settings.verify_rootfs_manifest {
                    ensure_command_available("sha256sum").await?;
                }
                let apply_script = Path::new(&repo_path).join("scripts/apply-live-update.sh");
                if !apply_script.is_file() {
                    anyhow::bail!(
                        "rootfs live update script is missing at {}",
                        apply_script.display()
                    );
                }
            }
        }
    }

    Ok((current, remote))
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
        if matches!(component, RepoComponent::Rootfs) && settings.verify_rootfs_manifest {
            verify_rootfs_manifest(&repo_path).await?;
            details.push("rootfs: manifest verification passed".to_string());
        }
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

async fn ensure_rootfs_repo_bootstrapped(settings: &UpdateSettings) -> Result<()> {
    let repo_path = Path::new(&settings.rootfs_repo_path);
    if repo_path.join(".git").exists() {
        return Ok(());
    }

    if !settings.bootstrap_missing_rootfs_repo {
        anyhow::bail!(
            "rootfs repository is missing at {} and bootstrap is disabled",
            settings.rootfs_repo_path
        );
    }

    ensure_command_available("git").await?;

    if let Some(parent) = repo_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let output = Command::new("git")
        .arg("clone")
        .arg("--branch")
        .arg(&settings.rootfs_branch)
        .arg("--single-branch")
        .arg(&settings.rootfs_repo_url)
        .arg(&settings.rootfs_repo_path)
        .output()
        .await
        .with_context(|| {
            format!(
                "failed to bootstrap rootfs repo into {}",
                settings.rootfs_repo_path
            )
        })?;

    if !output.status.success() {
        anyhow::bail!(
            "failed to bootstrap rootfs repo: {}",
            String::from_utf8_lossy(&output.stderr).trim()
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

async fn load_rootfs_live_update_policy(repo_path: &str, commit: &str) -> Result<RootfsLiveUpdatePolicy> {
    let spec = format!("{}:{}", commit, "config/live-update-policy.json");
    match run_git(repo_path, &["show", &spec]).await {
        Ok(raw) => Ok(serde_json::from_str::<RootfsLiveUpdatePolicy>(&raw)
            .with_context(|| "invalid config/live-update-policy.json")?),
        Err(_) => Ok(RootfsLiveUpdatePolicy::default()),
    }
}

async fn verify_rootfs_manifest(repo_path: &str) -> Result<()> {
    ensure_command_available("sha256sum").await?;
    let manifest_path = Path::new(repo_path).join("config/live-update-manifest.sha256");
    if !manifest_path.is_file() {
        anyhow::bail!(
            "missing rootfs manifest {}",
            manifest_path.display()
        );
    }

    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let expected = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("invalid manifest line: {}", trimmed))?;
        let rel_path = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("invalid manifest line: {}", trimmed))?;

        let out = run_command_in(repo_path, "sha256sum", &[rel_path]).await?;
        let actual = out
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("invalid sha256sum output for {}", rel_path))?;

        if actual != expected {
            anyhow::bail!(
                "manifest mismatch for {} (expected {}, got {})",
                rel_path,
                expected,
                actual
            );
        }
    }

    Ok(())
}

fn load_rootfs_live_update_summary() -> Option<RootfsLiveUpdateSummary> {
    let report = fs::read_to_string(ROOTFS_LIVE_REPORT_FILE)
        .ok()
        .and_then(|raw| serde_json::from_str::<RootfsLiveUpdateReport>(&raw).ok())?;

    Some(RootfsLiveUpdateSummary {
        report_timestamp: report.timestamp,
        report_commit: report.commit,
        staged_files: report.staged_files,
        backup_dir: report.backup_dir,
        changed_units: report.changed_units,
        migration_from_version: report.migration_from_version,
        migration_to_version: report.migration_to_version,
        rollback_available: report.rollback_available.unwrap_or(false),
    })
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

async fn rollback_rootfs_live_update_runtime(repo_path: &str) -> Result<()> {
    ensure_command_available("sh").await?;
    run_command_in(
        repo_path,
        "sh",
        &["scripts/apply-live-update.sh", "--rollback-latest", "--non-interactive"],
    )
    .await?;
    ensure_critical_services_healthy().await?;
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
            ensure_command_available("npm").await?;
            run_command_in(repo_path, "npm", &["ci", "--no-audit", "--no-fund"]).await?;
            run_command_in(repo_path, "npm", &["run", "build"]).await?;

            let dist_dir = Path::new(repo_path).join("dist");
            if !dist_dir.join("index.html").exists() {
                anyhow::bail!(
                    "UI build output missing index.html at {}",
                    dist_dir.display()
                );
            }

            install_dir_atomic(&dist_dir, Path::new("/usr/local/share/dayshield-ui"))?;
        }
        RepoComponent::Rootfs => {
            ensure_command_available("sh").await?;
            run_command_in(repo_path, "sh", &["scripts/apply-live-update.sh", "--non-interactive"]).await?;
            ensure_critical_services_healthy().await?;
        }
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
    if value.check_interval_minutes == 0 {
        value.check_interval_minutes = 1;
    }
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

fn mark_appliance_rebuild_required(state_file: &mut UpdateStateFile, reason: impl Into<String>) {
    state_file.pending_appliance_rebuild = true;
    state_file.appliance_rebuild_reason = Some(reason.into());
    state_file.appliance_rebuild_marked_at = Some(Utc::now().to_rfc3339());
}

fn clear_appliance_rebuild_required(state_file: &mut UpdateStateFile) {
    state_file.pending_appliance_rebuild = false;
    state_file.appliance_rebuild_reason = None;
    state_file.appliance_rebuild_marked_at = Some(Utc::now().to_rfc3339());
}

pub fn mark_appliance_rebuild_complete(state: &AppState) -> Result<()> {
    let mut state_file = load_state(state);
    state_file.pending_appliance_rebuild = false;
    state_file.appliance_rebuild_reason = None;
    state_file.appliance_rebuild_marked_at = Some(Utc::now().to_rfc3339());
    save_state(state, &state_file)
}

async fn build_component_status(
    settings: &UpdateSettings,
    state_file: &UpdateStateFile,
    component: RepoComponent,
) -> ComponentUpdateStatus {
    let (repo_path, remote_url, branch) = component_config(settings, component);

    let inspect_result = inspect_repo(&repo_path, &remote_url, &branch).await;
    let saved = find_component_state(state_file, component);

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
            rollback_commit: saved.and_then(|s| s.rollback_commit.clone()),
            last_applied_commit: saved.and_then(|s| s.last_applied_commit.clone()),
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
            rollback_commit: saved.and_then(|s| s.rollback_commit.clone()),
            last_applied_commit: saved.and_then(|s| s.last_applied_commit.clone()),
            last_error: Some(err.to_string()),
        },
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

    UpdatesStatus {
        settings,
        last_checked_at: state_file.last_checked_at,
        last_applied_at: state_file.last_applied_at,
        pending_reboot: state_file.pending_reboot,
        pending_appliance_rebuild: state_file.pending_appliance_rebuild,
        appliance_rebuild_reason: state_file.appliance_rebuild_reason,
        appliance_rebuild_marked_at: state_file.appliance_rebuild_marked_at,
        rootfs_live_update: load_rootfs_live_update_summary(),
        components,
        available_update_count: if available_update_count > 0 {
                if !is_command_available("cargo").await {
                    return Err(anyhow::anyhow!("cargo is not available"));
                }
        } else {
            None
        },
                if !is_command_available("npm").await {
                    return Err(anyhow::anyhow!("npm is not available"));
                }
}

pub async fn check_for_updates(state: &AppState) -> Result<UpdatesStatus> {
                if !is_command_available("sh").await {
                    return Err(anyhow::anyhow!("sh is not available"));
                }

                    if !is_command_available("sha256sum").await {
                        return Err(anyhow::anyhow!("sha256sum is not available"));
                    }
    let mut state_file = load_state(state);
    state_file.last_checked_at = Some(now);
    save_state(state, &state_file)?;

    Ok(get_status(state).await)
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

    let status = get_status(state).await;
    let available_count = status
        .components
        .iter()
        .filter(|c| c.update_available)
        .count();

    // If multiple components have updates but user is selecting only some, that's a violation
    if available_count > 1 && selected_components.len() < available_count {
        let available_components: Vec<&str> = status
            .components
            .iter()
            .filter(|c| c.update_available)
            .map(|c| c.component.as_str())
            .collect();

        return Err(anyhow::anyhow!(
            "Update atomicity violation: {} components have available updates ({}), but only {} were selected. \
             Either apply all available updates, or use forcePartialApply to override this check.",
            available_count,
            available_components.join(", "),
            selected_components.len()
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

    let settings = load_settings(state);
    let mut state_file = load_state(state);

    let selected = RepoComponent::from_update_component(component);

    // Check atomicity constraint before proceeding
    check_atomicity_constraint(state, &selected, force_partial_apply).await?;

    let mut details = Vec::new();
    let mut any_applied = false;
    let mut core_updated = false;
    let mut core_runtime_deployed = false;
    let mut rootfs_updated = false;
    let mut rootfs_runtime_deployed = false;

    info!(
        component = ?component,
        deploy_runtime = settings.deploy_runtime_after_apply,
        "updates: apply started"
    );

    // Preflight all selected components before making any changes.
    let mut baselines: Vec<(RepoComponent, String, String)> = Vec::new();
    for comp in &selected {
        match preflight_component(&settings, *comp).await {
            Ok((current, remote)) => {
                baselines.push((*comp, current, remote));
            }
            Err(err) => {
                let msg = format!("{}: preflight failed ({err})", comp.as_str());
                let entry = ensure_component_state(&mut state_file, *comp);
                entry.last_error = Some(msg.clone());
                save_state(state, &state_file)?;
                warn!(component = %comp.as_str(), error = %err, "updates: apply preflight failed");
                let status = get_status(state).await;
                return Ok(UpdatesActionResult {
                    operation: "apply".to_string(),
                    success: false,
                    message: "update preflight failed".to_string(),
                    details: vec![msg],
                    status,
                });
            }
        }
    }

    let mut progressed: Vec<(RepoComponent, String)> = Vec::new();

    for (comp, current, remote) in baselines {
        let (repo_path, remote_url, branch) = component_config(&settings, comp);

        if current == remote {
            details.push(format!("{}: already up to date", comp.as_str()));
            continue;
        }

        {
            let entry = ensure_component_state(&mut state_file, comp);
            entry.rollback_commit = Some(current.clone());
            entry.last_error = None;
        }

        info!(component = %comp.as_str(), branch = %branch, "updates: applying component");

        let mut deploy_runtime_for_component = settings.deploy_runtime_after_apply;

        let apply_result: Result<()> = async {
            ensure_origin(&repo_path, &remote_url).await?;
            run_git(&repo_path, &["fetch", "--quiet", "origin", &branch]).await?;
            let target_ref = format!("origin/{branch}");
            let target_commit = run_git(&repo_path, &["rev-parse", &target_ref]).await?;

            if settings.require_signed_commits {
                verify_commit_signature(&repo_path, &target_commit, &settings.trusted_signers_file).await?;
                details.push(format!(
                    "{}: commit signature verified ({})",
                    comp.as_str(),
                    short_sha(&target_commit)
                ));
            }

            if matches!(comp, RepoComponent::Rootfs) {
                let policy = load_rootfs_live_update_policy(&repo_path, &target_commit).await?;
                if policy.require_rebuild.unwrap_or(false) {
                    deploy_runtime_for_component = false;
                    mark_appliance_rebuild_required(
                        &mut state_file,
                        policy.reason.unwrap_or_else(|| {
                            "rootfs policy requires appliance rebuild for this update".to_string()
                        }),
                    );
                    details.push(
                        "rootfs: live update blocked by policy; appliance rebuild required".to_string(),
                    );
                }
            }

            if deploy_runtime_for_component {
                match comp {
                    RepoComponent::Core => {
                        if !is_command_available("cargo").await {
                            deploy_runtime_for_component = false;
                            mark_appliance_rebuild_required(
                                &mut state_file,
                                "core repository changed but cargo is unavailable on this system; rebuild appliance artifacts to deploy updated core runtime",
                            );
                            details.push(
                                "core: runtime deployment skipped because cargo is unavailable; appliance rebuild required".to_string(),
                            );
                        }
                    }
                    RepoComponent::Ui => {
                        if !is_command_available("npm").await {
                            deploy_runtime_for_component = false;
                            mark_appliance_rebuild_required(
                                &mut state_file,
                                "ui repository changed but npm is unavailable on this system; rebuild appliance artifacts to deploy updated UI runtime",
                            );
                            details.push(
                                "ui: runtime deployment skipped because npm is unavailable; appliance rebuild required".to_string(),
                            );
                        }
                    }
                    RepoComponent::Rootfs => {}
                }
            }

            reset_and_optionally_deploy(
                &settings,
                &mut state_file,
                comp,
                &target_commit,
                deploy_runtime_for_component,
                &mut details,
            )
            .await?;
            Ok(())
        }
        .await;

        if let Err(err) = apply_result {
            let msg = format!("{}: apply failed ({err})", comp.as_str());
            {
                let entry = ensure_component_state(&mut state_file, comp);
                entry.last_error = Some(msg.clone());
            }
            warn!(component = %comp.as_str(), error = %err, "updates: apply failed; attempting transactional rollback");

            // Roll back current component first.
            let _ = reset_and_optionally_deploy(
                &settings,
                &mut state_file,
                comp,
                &current,
                settings.deploy_runtime_after_apply,
                &mut details,
            )
            .await;

            // Roll back previously applied components.
            for (done_comp, done_commit) in progressed.iter().rev() {
                let _ = reset_and_optionally_deploy(
                    &settings,
                    &mut state_file,
                    *done_comp,
                    done_commit,
                    settings.deploy_runtime_after_apply,
                    &mut details,
                )
                .await;
            }

            save_state(state, &state_file)?;
            let status = get_status(state).await;
            return Ok(UpdatesActionResult {
                operation: "apply".to_string(),
                success: false,
                message: "update apply failed and transactional rollback was attempted".to_string(),
                details: vec![msg],
                status,
            });
        }

        any_applied = true;
        progressed.push((comp, current));
        if matches!(comp, RepoComponent::Core) {
            core_updated = true;
            if deploy_runtime_for_component {
                core_runtime_deployed = true;
            }
        }
        if matches!(comp, RepoComponent::Rootfs) {
            rootfs_updated = true;
            if deploy_runtime_for_component {
                rootfs_runtime_deployed = true;
            }
        }
    }

    if any_applied {
        state_file.last_applied_at = Some(Utc::now().to_rfc3339());
        if settings.reboot_required_after_apply || core_runtime_deployed {
            state_file.pending_reboot = true;
        }
        if rootfs_updated {
            if rootfs_runtime_deployed {
                clear_appliance_rebuild_required(&mut state_file);
                state_file.pending_reboot = true;
                details.push(
                    "rootfs: live runtime update applied; existing /etc and /var settings were preserved".to_string(),
                );
            } else {
                mark_appliance_rebuild_required(
                    &mut state_file,
                    "rootfs repository changed; runtime deployment is disabled, so rebuild appliance artifacts before shipping this rootfs update",
                );
                details.push(
                    "rootfs: runtime deployment disabled, appliance rebuild required for rootfs.tar.zst and installer ISO".to_string(),
                );
            }
        }

        if core_runtime_deployed || rootfs_runtime_deployed {
            ensure_critical_services_healthy().await?;
            details.push("post-apply health check passed for critical services".to_string());
        }
    }
    save_state(state, &state_file)?;

    info!(
        applied = any_applied,
        core_updated,
        pending_reboot = state_file.pending_reboot,
        "updates: apply completed"
    );

    let status = get_status(state).await;
    Ok(UpdatesActionResult {
        operation: "apply".to_string(),
        success: true,
        message: if any_applied {
            "updates applied successfully".to_string()
        } else {
            "no updates were required".to_string()
        },
        details,
        status,
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

    // Check atomicity constraint before proceeding
    check_atomicity_constraint(state, &selected, force_partial_apply).await?;

    let mut details = Vec::new();
    let mut rootfs_rolled_back = false;

    info!(component = ?component, "updates: rollback started");

    for comp in selected {
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

        if matches!(comp, RepoComponent::Rootfs) {
            rootfs_rolled_back = true;
        }
    }

    state_file.last_applied_at = Some(Utc::now().to_rfc3339());
    state_file.pending_reboot = false;
    if rootfs_rolled_back {
        if settings.deploy_runtime_after_apply {
            clear_appliance_rebuild_required(&mut state_file);
            state_file.pending_reboot = true;
            details.push(
                "rootfs: live runtime rollback applied; existing /etc and /var settings were preserved".to_string(),
            );
        } else {
            mark_appliance_rebuild_required(
                &mut state_file,
                "rootfs rollback completed while runtime deployment is disabled; rebuild appliance artifacts to ship rollback state",
            );
            details.push(
                "rootfs: runtime deployment disabled, appliance rebuild required to ship rollback".to_string(),
            );
        }
    }
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

        let repo_component = match comp.component.as_str() {
            "core" => Some(RepoComponent::Core),
            "ui" => Some(RepoComponent::Ui),
            "rootfs" => Some(RepoComponent::Rootfs),
            _ => None,
        };

        if let Some(repo_component) = repo_component {
            if !component_supports_runtime_deploy(repo_component) {
                continue;
            }

            if matches!(repo_component, RepoComponent::Rootfs) && status.pending_appliance_rebuild {
                success = false;
                details.push(format!(
                    "{}: appliance rebuild pending{}",
                    comp.component,
                    status
                        .appliance_rebuild_reason
                        .as_ref()
                        .map(|reason| format!(" ({reason})"))
                        .unwrap_or_default()
                ));
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

    if let Some(rootfs_live) = &status.rootfs_live_update {
        if !rootfs_live.staged_files.is_empty() {
            warning_count += 1;
            details.push(format!(
                "rootfs: {} staged config delta file(s) pending merge",
                rootfs_live.staged_files.len()
            ));
        }
    }

    info!(success, "updates: validation completed");

    Ok(UpdatesActionResult {
        operation: "validate".to_string(),
        success,
        message: if success && warning_count > 0 {
            format!("validation passed with {warning_count} warning(s)")
        } else if success {
            "validation passed".to_string()
        } else {
            "validation failed".to_string()
        },
        details,
        status,
    })
}

pub async fn rollback_rootfs_live_update(state: &AppState) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;

    let settings = load_settings(state);
    let mut state_file = load_state(state);
    let mut details = Vec::new();

    let (repo_path, _url, _branch) = component_config(&settings, RepoComponent::Rootfs);
    ensure_repo_writable(&repo_path)?;
    rollback_rootfs_live_update_runtime(&repo_path).await?;
    let head = run_git(&repo_path, &["rev-parse", "HEAD"]).await?;
    save_runtime_marker(RepoComponent::Rootfs, &head)?;

    let entry = ensure_component_state(&mut state_file, RepoComponent::Rootfs);
    entry.deployed_commit = Some(head.clone());
    entry.last_applied_commit = Some(head.clone());
    entry.last_error = None;

    state_file.last_applied_at = Some(Utc::now().to_rfc3339());
    state_file.pending_reboot = true;
    clear_appliance_rebuild_required(&mut state_file);
    save_state(state, &state_file)?;

    details.push("rootfs: live rollback completed from latest runtime backup snapshot".to_string());

    let status = get_status(state).await;
    Ok(UpdatesActionResult {
        operation: "rootfs-live-rollback".to_string(),
        success: true,
        message: "rootfs live rollback completed".to_string(),
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

pub async fn start_update_checker(state: std::sync::Arc<AppState>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut last_run: Option<Instant> = None;
        info!("updates: periodic checker started");

        loop {
            ticker.tick().await;

            let settings = load_settings(&state);
            if !settings.auto_check_enabled {
                continue;
            }

            let interval = Duration::from_secs(settings.check_interval_minutes.max(1) * 60);
            if let Some(prev) = last_run {
                if prev.elapsed() < interval {
                    continue;
                }
            }

            match check_for_updates(&state).await {
                Ok(status) => {
                    let available = status.components.iter().filter(|c| c.update_available).count();
                    info!(available, "updates: periodic check completed");
                }
                Err(err) => {
                    warn!(error = %err, "updates: periodic check failed");
                }
            }

            last_run = Some(Instant::now());
        }
    });
}
