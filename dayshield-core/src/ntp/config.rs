//! NTP persistence helpers.
//!
//! Thin wrappers over [`crate::config::ConfigStore`] that load and save
//! [`NtpConfig`] without callers needing to know about the underlying
//! [`SystemConfig`] structure.

use anyhow::Result;

use crate::config::ConfigStore;
use crate::ntp::model::NtpConfig;

/// Load the [`NtpConfig`] from the persisted configuration.
///
/// Returns the clean-install default config when no NTP configuration has been
/// saved yet.
pub fn load(store: &ConfigStore) -> Result<NtpConfig> {
    Ok(store.load_ntp_config()?.unwrap_or_default())
}

/// Atomically persist an updated [`NtpConfig`].
///
/// Validates the config before writing and rolls back on failure.
pub fn save(store: &ConfigStore, cfg: NtpConfig) -> Result<()> {
    store.save_ntp_config(cfg)
}
