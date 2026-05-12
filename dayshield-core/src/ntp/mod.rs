//! NTP subsystem - client synchronisation and optional LAN server.
//!
//! # Overview
//!
//! This module provides:
//! - [`model`]    - [`NtpConfig`] and [`NtpStatus`] types.
//! - [`validate`] - validation rules for [`NtpConfig`].
//! - [`config`]   - thin persistence wrappers over the shared [`ConfigStore`].
//! - [`apply`]    - engine: writes config files and restarts system services.
//! - [`status`]   - queries the running NTP daemon for live timing metrics.
//!
//! # Service selection
//!
//! | `serve_clients` | Service used         |
//! |-----------------|----------------------|
//! | `false`         | `systemd-timesyncd`  |
//! | `true`          | `chrony`             |

pub mod apply;
pub mod config;
pub mod model;
pub mod status;
pub mod validate;
