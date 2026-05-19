//! Configuration module.
//!
//! Provides typed configuration models (see [`models`]) and a persistent
//! storage layer (see [`storage`]) that loads from and saves to
//! `/etc/dayshield/config/`.

pub mod models;
pub mod storage;

pub use models::SystemConfig;
pub use storage::ConfigStore;
