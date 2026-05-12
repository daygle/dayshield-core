//! NAT subsystem - outbound NAT, port forwards, and NAT reflection.
//!
//! # Overview
//!
//! This module provides:
//! - [`model`]    - rich NAT types re-exported from [`crate::config::models`].
//! - [`validate`] - validation helpers for [`NatConfig`] and [`NatRule`].
//! - [`config`]   - thin persistence wrappers over the shared [`ConfigStore`].
//! - [`nftables`] - deterministic nftables (`table ip nat`) generator.
//!
//! # Outbound modes
//!
//! | Mode        | Behaviour                                               |
//! |-------------|--------------------------------------------------------|
//! | `automatic` | Auto masquerade on every listed WAN interface           |
//! | `hybrid`    | Auto masquerade + user-defined masquerade/SNAT rules    |
//! | `manual`    | Only user-defined rules; no automatic masquerade        |
//!
//! # IPv4 boundary
//!
//! All NAT rules are IPv4-only.  IPv6 addresses and IPv6 interfaces are
//! rejected by the validator and will never appear in nftables output.

pub mod config;
pub mod model;
pub mod nftables;
pub mod validate;
