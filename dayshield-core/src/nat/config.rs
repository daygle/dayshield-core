//! NAT persistence helpers.
//!
//! Thin wrappers over [`crate::config::ConfigStore`] that load and save
//! [`NatConfig`] without callers needing to know about the underlying
//! [`SystemConfig`] structure.

use anyhow::Result;

use crate::config::ConfigStore;
use crate::nat::model::NatConfig;

/// Load the [`NatConfig`] from the persisted configuration.
///
/// Returns a default (automatic-mode, no WAN interfaces) config when none has
/// been saved yet.
pub fn load(store: &ConfigStore) -> Result<NatConfig> {
    Ok(store.load_nat_config()?.unwrap_or_default())
}

/// Atomically persist an updated [`NatConfig`].
///
/// Validates the config before writing and rolls back on failure.
pub fn save(store: &ConfigStore, cfg: NatConfig) -> Result<()> {
    store.save_nat_config(cfg)
}
