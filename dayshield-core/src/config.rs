//! Configuration module.
//!
//! Provides typed configuration models (see [`models`]) and a persistent
//! storage layer (see [`storage`]) that loads from and saves to
//! `/var/lib/dayshield/config/`. Past configurations are archived as
//! restorable revisions (see [`history`]).

pub mod history;
pub mod models;
pub mod storage;

pub use history::ConfigRevision;
pub use models::SystemConfig;
pub use storage::ConfigStore;
