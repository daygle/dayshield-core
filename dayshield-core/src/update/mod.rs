use std::{
    env,
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

fn default_core_repo_path() -> String {
    env::var("DAYSHIELD_UPDATE_CORE_PATH").unwrap_or_else(|_| "/opt/dayshield-core".to_string())
}

fn default_ui_repo_path() -> String {
    env::var("DAYSHIELD_UPDATE_UI_PATH").unwrap_or_else(|_| "/opt/dayshield-ui".to_string())
}

fn default_core_repo_url() -> String {
    env::var("DAYSHIELD_UPDATE_CORE_URL").unwrap_or_else(|_| DEFAULT_CORE_URL.to_string())
}

fn default_ui_repo_url() -> String {
    env::var("DAYSHIELD_UPDATE_UI_URL").unwrap_or_else(|_| DEFAULT_UI_URL.to_string())
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
    #[serde(default = "default_core_repo_path")]
    pub core_repo_path: String,
    #[serde(default = "default_ui_repo_path")]
    pub ui_repo_path: String,
    #[serde(default = "default_core_repo_url")]
    pub core_repo_url: String,
    #[serde(default = "default_ui_repo_url")]
    pub ui_repo_url: String,
    #[serde(default = "default_branch")]
    pub core_branch: String,
    #[serde(default = "default_branch")]
    pub ui_branch: String,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            auto_check_enabled: default_auto_check_enabled(),
            check_interval_minutes: default_check_interval_minutes(),
            reboot_required_after_apply: default_reboot_required_after_apply(),
            core_repo_path: default_core_repo_path(),
            ui_repo_path: default_ui_repo_path(),
            core_repo_url: default_core_repo_url(),
            ui_repo_url: default_ui_repo_url(),
            core_branch: default_branch(),
            ui_branch: default_branch(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateComponent {
    Core,
    Ui,
    Both,
}

#[derive(Debug, Clone, Copy)]
enum RepoComponent {
    Core,
    Ui,
}

impl RepoComponent {
    fn as_str(self) -> &'static str {
        match self {
            RepoComponent::Core => "core",
            RepoComponent::Ui => "ui",
        }
    }

    fn from_update_component(component: UpdateComponent) -> Vec<Self> {
        match component {
            UpdateComponent::Core => vec![Self::Core],
            UpdateComponent::Ui => vec![Self::Ui],
            UpdateComponent::Both => vec![Self::Core, Self::Ui],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentState {
    pub component: String,
    pub rollback_commit: Option<String>,
    pub last_applied_commit: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStateFile {
    pub last_checked_at: Option<String>,
    pub last_applied_at: Option<String>,
    pub pending_reboot: bool,
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
    pub components: Vec<ComponentUpdateStatus>,
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
    }
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

async fn inspect_repo(repo_path: &str, remote_url: &str, branch: &str) -> Result<(String, String, bool)> {
    run_git(repo_path, &["rev-parse", "--is-inside-work-tree"]).await?;
    ensure_origin(repo_path, remote_url).await?;
    run_git(repo_path, &["fetch", "--quiet", "origin", branch]).await?;

    let current = run_git(repo_path, &["rev-parse", "HEAD"]).await?;
    let remote_ref = format!("origin/{branch}");
    let remote = run_git(repo_path, &["rev-parse", &remote_ref]).await?;
    let dirty = !run_git(repo_path, &["status", "--porcelain"]).await?.trim().is_empty();

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
    write_json_atomic(&settings_path(state), &value)
}

fn load_state(state: &AppState) -> UpdateStateFile {
    load_json_or_default(&state_path(state))
}

fn save_state(state: &AppState, value: &UpdateStateFile) -> Result<()> {
    write_json_atomic(&state_path(state), value)
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

    UpdatesStatus {
        settings,
        last_checked_at: state_file.last_checked_at,
        last_applied_at: state_file.last_applied_at,
        pending_reboot: state_file.pending_reboot,
        components: vec![core, ui],
    }
}

pub async fn check_for_updates(state: &AppState) -> Result<UpdatesStatus> {
    let _guard = op_lock().lock().await;

    let now = Utc::now().to_rfc3339();
    let mut state_file = load_state(state);
    state_file.last_checked_at = Some(now);
    save_state(state, &state_file)?;

    Ok(get_status(state).await)
}

pub async fn apply_updates(state: &AppState, component: UpdateComponent) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;

    let settings = load_settings(state);
    let mut state_file = load_state(state);

    let mut details = Vec::new();
    let mut any_applied = false;

    for comp in RepoComponent::from_update_component(component) {
        let (repo_path, remote_url, branch) = component_config(&settings, comp);
        let entry = ensure_component_state(&mut state_file, comp);

        match inspect_repo(&repo_path, &remote_url, &branch).await {
            Ok((current, remote, _dirty)) => {
                if current == remote {
                    details.push(format!("{}: already up to date", comp.as_str()));
                    continue;
                }

                entry.rollback_commit = Some(current.clone());
                entry.last_error = None;

                let apply_result = run_git(&repo_path, &["reset", "--hard", &remote]).await;
                if let Err(err) = apply_result {
                    let _ = run_git(&repo_path, &["reset", "--hard", &current]).await;
                    let msg = format!("{}: apply failed, rolled back ({err})", comp.as_str());
                    entry.last_error = Some(msg.clone());
                    save_state(state, &state_file)?;
                    let status = get_status(state).await;
                    return Ok(UpdatesActionResult {
                        operation: "apply".to_string(),
                        success: false,
                        message: "update apply failed and rollback was attempted".to_string(),
                        details: vec![msg],
                        status,
                    });
                }

                let head = run_git(&repo_path, &["rev-parse", "HEAD"]).await?;
                if head != remote {
                    let _ = run_git(&repo_path, &["reset", "--hard", &current]).await;
                    let msg = format!(
                        "{}: validation failed (HEAD {} does not match target {})",
                        comp.as_str(),
                        head,
                        remote
                    );
                    entry.last_error = Some(msg.clone());
                    save_state(state, &state_file)?;
                    let status = get_status(state).await;
                    return Ok(UpdatesActionResult {
                        operation: "apply".to_string(),
                        success: false,
                        message: "update validation failed and rollback was attempted".to_string(),
                        details: vec![msg],
                        status,
                    });
                }

                entry.last_applied_commit = Some(head.clone());
                details.push(format!("{}: updated to {}", comp.as_str(), short_sha(&head)));
                any_applied = true;
            }
            Err(err) => {
                let msg = format!("{}: unable to inspect repo ({err})", comp.as_str());
                entry.last_error = Some(msg.clone());
                save_state(state, &state_file)?;
                let status = get_status(state).await;
                return Ok(UpdatesActionResult {
                    operation: "apply".to_string(),
                    success: false,
                    message: "update apply failed".to_string(),
                    details: vec![msg],
                    status,
                });
            }
        }
    }

    if any_applied {
        state_file.last_applied_at = Some(Utc::now().to_rfc3339());
        if settings.reboot_required_after_apply {
            state_file.pending_reboot = true;
        }
    }
    save_state(state, &state_file)?;

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

pub async fn rollback_updates(state: &AppState, component: UpdateComponent) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;

    let settings = load_settings(state);
    let mut state_file = load_state(state);
    let mut details = Vec::new();

    for comp in RepoComponent::from_update_component(component) {
        let (repo_path, _remote_url, _branch) = component_config(&settings, comp);
        let entry = ensure_component_state(&mut state_file, comp);

        let target = match &entry.rollback_commit {
            Some(c) => c.clone(),
            None => {
                details.push(format!("{}: no rollback commit available", comp.as_str()));
                continue;
            }
        };

        let current = run_git(&repo_path, &["rev-parse", "HEAD"]).await?;
        run_git(&repo_path, &["reset", "--hard", &target]).await?;
        let validated = run_git(&repo_path, &["rev-parse", "HEAD"]).await?;

        if validated != target {
            let msg = format!("{}: rollback validation failed", comp.as_str());
            entry.last_error = Some(msg.clone());
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

        entry.rollback_commit = Some(current);
        entry.last_applied_commit = Some(validated.clone());
        entry.last_error = None;
        details.push(format!("{}: rolled back to {}", comp.as_str(), short_sha(&validated)));
    }

    state_file.last_applied_at = Some(Utc::now().to_rfc3339());
    save_state(state, &state_file)?;

    let status = get_status(state).await;
    Ok(UpdatesActionResult {
        operation: "rollback".to_string(),
        success: true,
        message: "rollback completed".to_string(),
        details,
        status,
    })
}

pub async fn validate_updates(state: &AppState, component: UpdateComponent) -> Result<UpdatesActionResult> {
    let _guard = op_lock().lock().await;

    let status = get_status(state).await;
    let mut details = Vec::new();
    let mut success = true;

    let selected = RepoComponent::from_update_component(component)
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
                details.push(format!("{}: validation ok ({})", comp.component, short_sha(current)));
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

    Ok(UpdatesActionResult {
        operation: "validate".to_string(),
        success,
        message: if success {
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
