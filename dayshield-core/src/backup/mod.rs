//! Backup and restore subsystem.
//!
//! Provides:
//! - Full or selective configuration backup into a TAR archive.
//! - Optional AES-256-GCM encryption of the archive.
//! - SHA-256 integrity verification.
//! - Backup restoration from an uploaded archive.
//! - Automatic scheduled backups via a background Tokio task.
//!
//! # Usage
//!
//! Call [`scheduler::start_backup_scheduler`] at application startup to enable
//! the automatic scheduler.  The REST API (see `api/backup.rs`) exposes
//! all operations over HTTP.

pub mod create;
pub mod encrypt;
pub mod model;
pub mod restore;
pub mod scheduler;
pub mod verify;
