//! QoS subsystem - Smart Queue Management configuration.
//!
//! The runtime engine lives in [`crate::engine::qos`].  This module mirrors
//! other DayShield subsystems by exposing typed models, validation helpers, and
//! thin persistence wrappers over the shared [`crate::config::ConfigStore`].

pub mod config;
pub mod model;
pub mod validate;
