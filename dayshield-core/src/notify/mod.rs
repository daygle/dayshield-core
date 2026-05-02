//! Notifications subsystem.
//!
//! Provides email alerting for Suricata, CrowdSec, ACME, and system events.
//!
//! # Usage
//!
//! 1. At startup, call [`queue::NotifyQueue::new`] to get `(queue, rx)`.
//! 2. Store the [`queue::NotifyQueue`] in [`crate::state::AppState`].
//! 3. Call [`worker::start_notify_worker`] with `(state, rx)`.
//! 4. Anywhere that needs to send a notification, clone the queue from state
//!    and call [`queue::NotifyQueue::enqueue`].

pub mod model;
pub mod queue;
pub mod rate_limit;
pub mod smtp;
pub mod templates;
pub mod worker;

pub use model::{NotifyCategory, NotifyConfig, NotifyEvent};
pub use queue::NotifyQueue;
pub use smtp::NotifyError;
