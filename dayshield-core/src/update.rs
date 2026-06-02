// The update subsystem is held to a stricter standard than the rest of the
// crate: re-enable the dead-code and unused-import lints that `main.rs` allows
// crate-wide so unused update code is caught instead of silently accumulating.
#![warn(dead_code, unused_imports)]

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
use tracing::{debug, info, warn};

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

fn default_core_repo_url() -> String {
    env::var("DAYSHIELD_UPDATE_CORE_URL").unwrap_or_else(|_| DEFAULT_CORE_URL.to_string())
}

fn default_ui_repo_url() -> String {
    env::var("DAYSHIELD_UPDATE_UI_URL").unwrap_or_else(|_| DEFAULT_UI_URL.to_string())
}

fn default_rootfs_repo_url() -> String {
    env::var("DAYSHIELD_UPDATE_ROOTFS_URL").unwrap_or_else(|_| DEFAULT_ROOTFS_URL.to_string())
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

fn default_reboot_required_after_apply() -> bool {
    false
}

fn default_deploy_runtime_after_apply() -> bool {
    true
}

fn default_trusted_signers_file() -> String {
    DEFAULT_TRUSTED_SIGNERS_FILE.to_string()
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
    #[serde(default = "default_trusted_signers_file")]
    pub trusted_signers_file: String,
    #[serde(default = "default_core_repo_url")]
    pub core_repo_url: String,
    #[serde(default = "default_ui_repo_url")]
    pub ui_repo_url: String,
    #[serde(default = "default_rootfs_repo_url")]
    pub rootfs_repo_url: String,
    // Registry-based update settings
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
            trusted_signers_file: default_trusted_signers_file(),
            core_repo_url: default_core_repo_url(),
            ui_repo_url: default_ui_repo_url(),
            rootfs_repo_url: default_rootfs_repo_url(),
            registry_url: default_registry_url(),
            verify_artifact_signatures: default_verify_artifact_signatures(),
            encrypt_update_config_backups: default_encrypt_update_config_backups(),
        }
    }
}

/// Which software components to include in an update, check, or rollback operation.
///
/// - `Core`    — the `dayshield-core` binary only
/// - `Ui`      — the management UI static assets only
/// - `Rootfs`  — the full OS rootfs image (staged; requires reboot to activate)
/// - `All`     — all three components together (serialized as `"all"`;
///               the legacy value `"both"` is accepted as an alias)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateComponent {
    Core,
    Ui,
    Rootfs,
    /// Update all components (Core + UI + Rootfs).
    /// Accepts the legacy alias `"both"` for backward compatibility with
    /// existing API clients that predate the rename.
    #[serde(alias = "both")]
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
