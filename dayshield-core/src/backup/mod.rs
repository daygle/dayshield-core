//! Backup and restore subsystem.
//!
//! Provides full and selective configuration backup, encrypted archive support,
//! SHA-256 integrity verification, and an automatic scheduled backup loop.
//!
//! # Module layout
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`model`]     | Data types: [`model::Subsystem`], [`model::BackupMetadata`], [`model::BackupEntry`] |
//! | [`create`]    | Build a TAR archive from [`crate::config::models::SystemConfig`] |
//! | [`restore`]   | Extract and apply a TAR archive back to [`crate::config::storage::ConfigStore`] |
//! | [`verify`]    | Compute canonical SHA-256 hash and verify archive integrity |
//! | [`encrypt`]   | AES-256-GCM encrypt / decrypt with a passphrase-derived key |
//! | [`scheduler`] | Background tokio task for periodic automated backups |

pub mod create;
pub mod encrypt;
pub mod model;
pub mod restore;
pub mod scheduler;
pub mod verify;
