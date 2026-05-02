//! Notification event model.

pub use crate::config::models::{NotifyCategory, NotifyConfig};

/// A single notification event queued for delivery.
#[derive(Debug, Clone)]
pub struct NotifyEvent {
    /// Alert category — used to filter against `NotifyConfig::categories`.
    pub category: NotifyCategory,
    /// Email subject line.
    pub subject: String,
    /// Email body (plain text).
    pub body: String,
    /// Unix timestamp (seconds since epoch) when the event was created.
    pub timestamp: u64,
}
