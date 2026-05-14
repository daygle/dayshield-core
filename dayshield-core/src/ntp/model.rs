//! NTP data models.
//!
//! [`NtpConfig`] is defined in `config::models` so that it forms part of the
//! persisted [`SystemConfig`].  This module re-exports it for callers that
//! only import from `ntp::model`, and defines the transient [`NtpStatus`]
//! type that is never persisted.

pub use crate::config::models::{validate_ntp_config, NtpConfig};

use serde::{Deserialize, Serialize};

/// Snapshot of the NTP daemon's current synchronisation state.
///
/// This value is computed on-demand by [`crate::ntp::status`] and is never
/// written to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpStatus {
    /// Whether the host clock is currently synchronised to an NTP source.
    pub synchronized: bool,
    /// The NTP source currently being used (IP address or hostname).
    pub server: Option<String>,
    /// Clock offset from the reference server in milliseconds.
    /// Positive means the local clock is ahead.
    pub offset_ms: f64,
    /// RMS jitter of recent clock offsets in milliseconds.
    pub jitter_ms: f64,
    /// NTP stratum reported by the active daemon, or 0 when unavailable.
    pub stratum: u8,
    /// ISO 8601 timestamp of the last successful synchronisation,
    /// or `None` when the clock has never been synchronised.
    pub last_sync: Option<String>,
    /// Name of the backing NTP daemon: `"chrony"` or `"systemd-timesyncd"`.
    pub daemon: String,
}
