//! System schedules runtime.
//!
//! Provides a lightweight cron-like scheduler for DayShield system jobs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::api::{acme, dynamic_dns, rulesets};
use crate::state::AppState;

const CONFIG_FILE: &str = "system_schedules.json";
const STATUS_FILE: &str = "system_schedules_status.json";
const CONFIG_DIR_FALLBACK: &str = "/etc/dayshield/config";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleJobType {
    DynamicDnsUpdate,
    AcmeRenew,
    SuricataRulesetsUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemScheduleJobConfig {
    pub job: ScheduleJobType,
    pub enabled: bool,
    pub interval_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemSchedulesConfig {
    pub jobs: Vec<SystemScheduleJobConfig>,
}

impl Default for SystemSchedulesConfig {
    fn default() -> Self {
        Self {
            jobs: vec![
                SystemScheduleJobConfig {
                    job: ScheduleJobType::DynamicDnsUpdate,
                    enabled: false,
                    interval_minutes: 10,
                },
                SystemScheduleJobConfig {
                    job: ScheduleJobType::AcmeRenew,
                    enabled: false,
                    interval_minutes: 360,
                },
                SystemScheduleJobConfig {
                    job: ScheduleJobType::SuricataRulesetsUpdate,
                    enabled: false,
                    interval_minutes: 240,
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SchedulesStatusStore {
    pub jobs: Vec<ScheduledJobRuntimeStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduledJobRuntimeStatus {
    pub job: ScheduleJobType,
    pub last_run_at: Option<String>,
    pub last_success: Option<bool>,
    pub last_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemScheduleJobStatus {
    pub job: ScheduleJobType,
    pub enabled: bool,
    pub interval_minutes: u32,
    pub last_run_at: Option<String>,
    pub last_success: Option<bool>,
    pub last_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemSchedulesResponse {
    pub jobs: Vec<SystemScheduleJobStatus>,
}

pub fn load_config(state: &AppState) -> Result<SystemSchedulesConfig> {
    let path = config_path(state);
    if !path.exists() {
        return Ok(SystemSchedulesConfig::default());
    }

    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let parsed: SystemSchedulesConfig = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    Ok(with_default_jobs(parsed))
}

pub fn save_config(state: &AppState, cfg: &SystemSchedulesConfig) -> Result<SystemSchedulesConfig> {
    validate_config(cfg)?;
    let normalized = with_default_jobs(cfg.clone());

    let path = config_path(state);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config dir {}", parent.display()))?;
    }

    let raw = serde_json::to_string_pretty(&normalized)
        .context("failed to serialize schedules config")?;
    let tmp = path.with_extension("tmp");
    write_restricted(&tmp, raw.as_bytes())?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))?;

    Ok(normalized)
}

pub fn get_response(state: &AppState) -> Result<SystemSchedulesResponse> {
    let cfg = load_config(state)?;
    let status = load_status(state).unwrap_or_default();
    Ok(build_response(cfg, status))
}

pub async fn run_job_now(
    state: Arc<AppState>,
    job: ScheduleJobType,
) -> Result<SystemScheduleJobStatus> {
    let cfg = load_config(&state)?;
    let mut status = load_status(&state).unwrap_or_default();

    let target_cfg = cfg
        .jobs
        .iter()
        .find(|item| item.job == job)
        .cloned()
        .unwrap_or(SystemScheduleJobConfig {
            job: job.clone(),
            enabled: false,
            interval_minutes: 60,
        });

    let runtime = execute_job(&state, &job).await;
    upsert_runtime_status(&mut status, runtime.clone());
    save_status(&state, &status)?;

    Ok(SystemScheduleJobStatus {
        job,
        enabled: target_cfg.enabled,
        interval_minutes: target_cfg.interval_minutes,
        last_run_at: runtime.last_run_at,
        last_success: runtime.last_success,
        last_message: runtime.last_message,
    })
}

pub async fn start_scheduler(state: Arc<AppState>) {
    tokio::spawn(scheduler_loop(state));
}

async fn scheduler_loop(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!("system schedules started");

    loop {
        interval.tick().await;

        let cfg = match load_config(&state) {
            Ok(cfg) => cfg,
            Err(err) => {
                warn!(error = %err, "schedules: failed to load config");
                continue;
            }
        };

        let mut status = load_status(&state).unwrap_or_default();
        let mut dirty = false;

        for job_cfg in cfg.jobs.iter().filter(|job| job.enabled) {
            if !is_due(job_cfg, &status) {
                continue;
            }

            let runtime = execute_job(&state, &job_cfg.job).await;
            upsert_runtime_status(&mut status, runtime);
            dirty = true;
        }

        if dirty {
            if let Err(err) = save_status(&state, &status) {
                warn!(error = %err, "schedules: failed to persist status");
            }
        }
    }
}

async fn execute_job(state: &Arc<AppState>, job: &ScheduleJobType) -> ScheduledJobRuntimeStatus {
    let now = Utc::now().to_rfc3339();

    let (success, message) = match job {
        ScheduleJobType::DynamicDnsUpdate => match dynamic_dns::run_update_now(state).await {
            Ok(result) => {
                let failed = result.entries.iter().filter(|entry| !entry.success).count();
                if failed == 0 {
                    (true, format!("updated {} Dynamic DNS entries", result.entries.len()))
                } else {
                    (
                        false,
                        format!(
                            "dynamic DNS update completed with {} failure(s) out of {} entries",
                            failed,
                            result.entries.len()
                        ),
                    )
                }
            }
            Err(err) => (false, err.to_string()),
        },
        ScheduleJobType::AcmeRenew => match acme::run_acme_renewal(state).await {
            Ok(msg) => (true, msg),
            Err(err) => (false, err.to_string()),
        },
        ScheduleJobType::SuricataRulesetsUpdate => {
            match rulesets::run_scheduled_ruleset_updates(state).await {
                Ok((updated, failed)) if failed == 0 => {
                    (true, format!("updated {} ruleset(s)", updated))
                }
                Ok((updated, failed)) => (
                    false,
                    format!(
                        "updated {} ruleset(s) with {} failure(s)",
                        updated, failed
                    ),
                ),
                Err(err) => (false, err.to_string()),
            }
        }
    };

    if success {
        info!(job = ?job, message = %message, "schedules: job completed");
    } else {
        error!(job = ?job, message = %message, "schedules: job failed");
    }

    ScheduledJobRuntimeStatus {
        job: job.clone(),
        last_run_at: Some(now),
        last_success: Some(success),
        last_message: Some(message),
    }
}

fn is_due(job_cfg: &SystemScheduleJobConfig, status: &SchedulesStatusStore) -> bool {
    let Some(runtime) = status.jobs.iter().find(|entry| entry.job == job_cfg.job) else {
        return true;
    };

    let Some(last_run_at) = runtime.last_run_at.as_ref() else {
        return true;
    };

    let parsed = DateTime::parse_from_rfc3339(last_run_at)
        .ok()
        .map(|ts| ts.with_timezone(&Utc));
    let Some(last) = parsed else {
        return true;
    };

    let elapsed = Utc::now() - last;
    elapsed.num_minutes() >= i64::from(job_cfg.interval_minutes)
}

fn validate_config(cfg: &SystemSchedulesConfig) -> Result<()> {
    let mut seen = HashMap::new();

    for job in &cfg.jobs {
        if !(1..=10080).contains(&job.interval_minutes) {
            anyhow::bail!(
                "schedule interval for {:?} must be between 1 and 10080 minutes",
                job.job
            );
        }

        if seen.insert(job.job.clone(), true).is_some() {
            anyhow::bail!("duplicate schedule job entry for {:?}", job.job);
        }
    }

    Ok(())
}

fn build_response(cfg: SystemSchedulesConfig, status: SchedulesStatusStore) -> SystemSchedulesResponse {
    let mut by_job: HashMap<ScheduleJobType, ScheduledJobRuntimeStatus> = HashMap::new();
    for item in status.jobs {
        by_job.insert(item.job.clone(), item);
    }

    SystemSchedulesResponse {
        jobs: cfg
            .jobs
            .into_iter()
            .map(|job| {
                let runtime = by_job.get(&job.job);
                SystemScheduleJobStatus {
                    job: job.job,
                    enabled: job.enabled,
                    interval_minutes: job.interval_minutes,
                    last_run_at: runtime.and_then(|entry| entry.last_run_at.clone()),
                    last_success: runtime.and_then(|entry| entry.last_success),
                    last_message: runtime.and_then(|entry| entry.last_message.clone()),
                }
            })
            .collect(),
    }
}

fn upsert_runtime_status(store: &mut SchedulesStatusStore, runtime: ScheduledJobRuntimeStatus) {
    if let Some(item) = store.jobs.iter_mut().find(|item| item.job == runtime.job) {
        *item = runtime;
        return;
    }
    store.jobs.push(runtime);
}

fn load_status(state: &AppState) -> Result<SchedulesStatusStore> {
    let path = status_path(state);
    if !path.exists() {
        return Ok(SchedulesStatusStore::default());
    }

    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let parsed: SchedulesStatusStore = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    Ok(parsed)
}

fn save_status(state: &AppState, status: &SchedulesStatusStore) -> Result<()> {
    let path = status_path(state);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create status dir {}", parent.display()))?;
    }

    let raw = serde_json::to_string_pretty(status)
        .context("failed to serialize schedules status")?;
    let tmp = path.with_extension("tmp");
    write_restricted(&tmp, raw.as_bytes())?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))?;

    Ok(())
}

fn with_default_jobs(mut cfg: SystemSchedulesConfig) -> SystemSchedulesConfig {
    let has_ddns = cfg.jobs.iter().any(|job| job.job == ScheduleJobType::DynamicDnsUpdate);
    let has_acme = cfg.jobs.iter().any(|job| job.job == ScheduleJobType::AcmeRenew);
    let has_rulesets = cfg
        .jobs
        .iter()
        .any(|job| job.job == ScheduleJobType::SuricataRulesetsUpdate);

    if !has_ddns {
        cfg.jobs.push(SystemScheduleJobConfig {
            job: ScheduleJobType::DynamicDnsUpdate,
            enabled: false,
            interval_minutes: 10,
        });
    }

    if !has_acme {
        cfg.jobs.push(SystemScheduleJobConfig {
            job: ScheduleJobType::AcmeRenew,
            enabled: false,
            interval_minutes: 360,
        });
    }

    if !has_rulesets {
        cfg.jobs.push(SystemScheduleJobConfig {
            job: ScheduleJobType::SuricataRulesetsUpdate,
            enabled: false,
            interval_minutes: 240,
        });
    }

    cfg
}

#[cfg(unix)]
fn write_restricted(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;

    file.write_all(data)
        .with_context(|| format!("failed to write {}", path.display()))?;

    Ok(())
}

#[cfg(not(unix))]
fn write_restricted(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn config_path(state: &AppState) -> PathBuf {
    state
        .config_store
        .config_path()
        .parent()
        .unwrap_or(Path::new(CONFIG_DIR_FALLBACK))
        .join(CONFIG_FILE)
}

fn status_path(state: &AppState) -> PathBuf {
    state
        .config_store
        .config_path()
        .parent()
        .unwrap_or(Path::new(CONFIG_DIR_FALLBACK))
        .join(STATUS_FILE)
}
