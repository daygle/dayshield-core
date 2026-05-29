//! QoS data models.
//!
//! All QoS types are defined in [`crate::config::models`] so they are part of
//! the persisted [`crate::config::models::SystemConfig`].  This module
//! re-exports them for callers that import from `qos::model`.

pub use crate::config::models::{QosConfig, QosDiffservMode, QosInterface, QosQueueDiscipline};
