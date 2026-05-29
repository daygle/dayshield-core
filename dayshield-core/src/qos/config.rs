//! Thin QoS persistence wrappers over [`crate::config::ConfigStore`].

use anyhow::Result;

use crate::{config::ConfigStore, qos::model::QosConfig};

pub fn load(store: &ConfigStore) -> Result<QosConfig> {
    store.load_qos_config()
}

pub fn save(store: &ConfigStore, cfg: QosConfig) -> Result<()> {
    store.save_qos_config(cfg)
}
