//! NAT data models.
//!
//! All NAT types are defined in [`crate::config::models`] so they form part of
//! the persisted [`SystemConfig`].  This module re-exports them for callers
//! that only import from `nat::model`.

pub use crate::config::models::{
    AddressFamily, NatConfig, NatInterface, NatProtocol, NatRule, NatRuleType, NatTranslation,
    OutboundMode,
};
