//! Managed Suricata ruleset subsystem.
//!
//! This module provides automatic download, installation, update, and
//! enable/disable of curated Suricata rulesets so users no longer need to
//! manage rule files manually.
//!
//! # Architecture
//!
//! | Component        | Purpose                                                       |
//! |-----------------|---------------------------------------------------------------|
//! | [`models`]      | Data types: [`InstalledRuleset`], [`CuratedSource`], status.  |
//! | [`sources`]     | Built-in curated source definitions (ET Open, …).            |
//! | [`storage`]     | Load/save ruleset metadata from disk (`installed.json`).      |
//! | [`manager`]     | Install, update, enable, disable, and remove rulesets.       |

pub mod manager;
pub mod models;
pub mod sources;
pub mod storage;
