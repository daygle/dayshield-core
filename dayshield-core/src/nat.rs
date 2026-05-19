//! NAT subsystem - outbound NAT, port forwards, and NAT reflection.
//!
//! # Overview
//!
//! This module provides:
//! - [`model`]    - rich NAT types re-exported from [`crate::config::models`].
//! - [`validate`] - validation helpers for [`NatConfig`] and [`NatRule`].
//! - [`config`]   - thin persistence wrappers over the shared [`ConfigStore`].
//! - [`nftables`] - deterministic nftables NAT generator.
//!
//! # Outbound modes
//!
//! | Mode        | Behaviour                                               |
//! |-------------|--------------------------------------------------------|
//! | `automatic` | Auto masquerade on every listed WAN interface           |
//! | `hybrid`    | Auto masquerade + user-defined masquerade/SNAT rules    |
//! | `manual`    | Only user-defined rules; no automatic masquerade        |
//!
//! # Address families
//!
//! NAT rules are IPv4 by default. IPv6 NAT rules are accepted only when the
//! global `ipv6Enabled` setting is enabled, and are emitted into `table ip6 nat`.

pub mod config;
pub mod model;
pub mod nftables;
pub mod validate;
