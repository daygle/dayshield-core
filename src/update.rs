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
const ARTIFACT_STAGING_DIR: &str = "/var/lib/dayshield/update/staging";