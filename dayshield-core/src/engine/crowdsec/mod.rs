//! CrowdSec integration engine.
//!
//! # Overview
//!
//! This module implements:
//!
//! - [`CrowdSecClient`] - HTTP client that communicates with the CrowdSec
//!   Local API (LAPI) to retrieve active remediation decisions.
//! - [`generate_ban_set_nft`] - pure function that renders an nftables script
//!   to define and populate a named ban set from the decision list.
//! - [`update_ban_set`] - applies the generated nftables script via `nft -f`.
//! - [`refresh_decisions`] - high-level helper used by API handlers and a
//!   background polling loop: fetches decisions, updates nftables, and stores
//!   the results in the shared [`AppState`].
//!
//! # CrowdSec LAPI Integration
//!
//! The LAPI is queried at `GET <lapi_url>/v1/decisions`.  The `X-Api-Key`
//! header carries the bouncer API key.  The endpoint returns a JSON array of
//! decision objects, or `null` when there are currently no active decisions.

use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::{
    config::models::{validate_ip_or_cidr, CrowdSecConfig, CrowdSecDecision},
    state::AppState,
};

// ---------------------------------------------------------------------------
// LAPI wire format
// ---------------------------------------------------------------------------

/// Decision object as returned by `GET /v1/decisions`.
///
/// This is a subset of the full LAPI schema; only the fields needed by the
/// bouncer are mapped.
#[derive(Debug, Deserialize)]
struct LapiDecision {
    pub id: i64,
    pub value: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub scope: String,
    pub duration: String,
}

// ---------------------------------------------------------------------------
// CrowdSecClient
// ---------------------------------------------------------------------------

/// HTTP client for the CrowdSec Local API.
pub struct CrowdSecClient {
    lapi_url: String,
    api_key: String,
    http: reqwest::Client,
}

impl CrowdSecClient {
    /// Create a new [`CrowdSecClient`] for the given LAPI endpoint.
    pub fn new(lapi_url: String, api_key: String) -> Self {
        Self {
            lapi_url,
            api_key,
            http: reqwest::Client::new(),
        }
    }

    /// Fetch the current list of active decisions from the LAPI.
    ///
    /// Calls `GET <lapi_url>/v1/decisions` with the configured `X-Api-Key`
    /// header.  Returns an empty `Vec` when the LAPI reports no active
    /// decisions (the endpoint returns JSON `null` in that case).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the LAPI returns a
    /// non-2xx status code.
    pub async fn fetch_decisions(&self) -> Result<Vec<CrowdSecDecision>> {
        let url = format!("{}/v1/decisions", self.lapi_url.trim_end_matches('/'));

        debug!(url = %url, "crowdsec: fetching decisions from LAPI");

        let response = self
            .http
            .get(&url)
            .header("X-Api-Key", &self.api_key)
            .send()
            .await
            .context("failed to connect to CrowdSec LAPI")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("CrowdSec LAPI returned {}: {}", status, body);
        }

        // The LAPI returns `null` (not `[]`) when there are no decisions.
        let raw: Option<Vec<LapiDecision>> = response
            .json()
            .await
            .context("failed to parse CrowdSec LAPI response")?;

        let decisions = raw
            .unwrap_or_default()
            .into_iter()
            .map(|d| CrowdSecDecision {
                id: d.id,
                value: d.value,
                type_: d.type_,
                scope: d.scope,
                duration: d.duration,
            })
            .collect();

        Ok(decisions)
    }
}

// ---------------------------------------------------------------------------
// nftables ban-set management
// ---------------------------------------------------------------------------

/// nftables table name used exclusively for CrowdSec ban sets.
const CROWDSEC_TABLE: &str = "inet dayshield_crowdsec";

/// Generate an nftables script that defines and populates named ban sets.
///
/// Two sets are created inside a dedicated `dayshield_crowdsec` table:
///
/// - `<alias_name>` - `type ipv4_addr`, populated with IPv4 addresses and
///   CIDR ranges from `"ban"` decisions.
/// - `<alias_name>_v6` - `type ipv6_addr`, populated with IPv6 addresses and
///   CIDR ranges from `"ban"` decisions.
///
/// Each set declares the `interval` flag so that CIDR ranges are accepted.
/// Both sets are flushed before being repopulated so stale bans are removed.
///
/// Only decisions whose `type_` field equals `"ban"` (case-insensitive) are
/// included.
pub fn generate_ban_set_nft(alias_name: &str, decisions: &[CrowdSecDecision]) -> String {
    let mut out = String::new();
    let v6_name = format!("{alias_name}_v6");

    out.push_str("# CrowdSec ban set - auto-generated by DayShield; do not edit by hand\n");

    // Ensure the table exists.
    out.push_str("add table inet dayshield_crowdsec\n");

    // Ensure both sets exist (idempotent).
    out.push_str(&format!(
        "add set inet dayshield_crowdsec {alias_name} {{ type ipv4_addr; flags interval; }}\n"
    ));
    out.push_str(&format!(
        "add set inet dayshield_crowdsec {v6_name} {{ type ipv6_addr; flags interval; }}\n"
    ));

    // Flush current elements so stale bans are removed.
    out.push_str(&format!("flush set inet dayshield_crowdsec {alias_name}\n"));
    out.push_str(&format!("flush set inet dayshield_crowdsec {v6_name}\n"));

    // Split valid ban decisions by address family. Invalid values are skipped
    // so one bad LAPI item cannot break the whole nftables update.
    let ban_decisions: Vec<&str> = decisions
        .iter()
        .filter(|d| d.type_.eq_ignore_ascii_case("ban"))
        .map(|d| d.value.as_str())
        .filter(|value| validate_ip_or_cidr(value))
        .collect();

    let (bans_v4, bans_v6): (Vec<&str>, Vec<&str>) =
        ban_decisions.into_iter().partition(|v| is_ipv4_value(v));

    if !bans_v4.is_empty() {
        let elements = bans_v4.join(", ");
        out.push_str(&format!(
            "add element inet dayshield_crowdsec {alias_name} {{ {elements} }}\n"
        ));
    }

    if !bans_v6.is_empty() {
        let elements = bans_v6.join(", ");
        out.push_str(&format!(
            "add element inet dayshield_crowdsec {v6_name} {{ {elements} }}\n"
        ));
    }

    out
}

/// Return `true` if `value` is an IPv4 address or IPv4 CIDR prefix.
///
/// Used to partition decision values into the correct nftables set type.
fn is_ipv4_value(value: &str) -> bool {
    // CIDR: check the address part only.
    if let Some((addr, _prefix)) = value.split_once('/') {
        return addr.parse::<std::net::Ipv4Addr>().is_ok();
    }
    value.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Apply the CrowdSec ban set to the running nftables ruleset.
///
/// Generates an nftables script via [`generate_ban_set_nft`], writes it to a
/// uniquely-named temporary file, and executes `nft -f <tmpfile>`.
///
/// A unique file name is used for each invocation (based on a random UUID) to
/// avoid any predictable-path symlink race conditions.
///
/// # Errors
///
/// Returns an error if the temp file cannot be written or `nft` exits
/// non-zero.
pub async fn update_ban_set(alias_name: &str, decisions: &[CrowdSecDecision]) -> Result<()> {
    let script = generate_ban_set_nft(alias_name, decisions);
    let tmp = format!(
        "/tmp/dayshield_crowdsec_{}.nft",
        uuid::Uuid::new_v4().simple()
    );

    std::fs::write(&tmp, &script)
        .with_context(|| format!("failed to write nft script to {tmp}"))?;

    info!(
        alias_name,
        bans = decisions
            .iter()
            .filter(|d| d.type_.eq_ignore_ascii_case("ban"))
            .count(),
        "crowdsec: applying ban set via nft"
    );

    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "dayshield_crowdsec"])
        .output()
        .await;

    let output_result = Command::new("nft").args(["-f", &tmp]).output().await;

    if let Err(e) = std::fs::remove_file(&tmp) {
        debug!(path = %tmp, error = %e, "crowdsec: failed to remove nft temp file");
    }

    let out = output_result.context("failed to spawn nft")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("nft -f failed: {stderr}");
    }

    info!(alias_name, "crowdsec: ban set updated");
    Ok(())
}

// ---------------------------------------------------------------------------
// High-level refresh helper
// ---------------------------------------------------------------------------

/// Fetch new decisions from the LAPI, update the nftables ban set, and store
/// the results in the shared [`AppState`].
///
/// This function is called:
/// - Immediately after a `POST /crowdsec/config` to pick up the new
///   configuration without waiting for the next polling interval.
/// - Periodically by a background task (not started here; that is the
///   responsibility of the caller).
///
/// A failure to update nftables is logged as a warning but does **not**
/// propagate as an error - the in-memory cache is still refreshed so that
/// `GET /crowdsec/decisions` can always return the latest data.
pub async fn refresh_decisions(config: &CrowdSecConfig, state: &Arc<AppState>) -> Result<()> {
    info!(lapi_url = %config.lapi_url, "crowdsec: refreshing decisions");

    let client = CrowdSecClient::new(config.lapi_url.clone(), config.api_key.clone());

    let decisions = client
        .fetch_decisions()
        .await
        .context("crowdsec: failed to fetch decisions from LAPI")?;

    info!(count = decisions.len(), "crowdsec: fetched decisions");

    // Update the nftables ban set; failures are non-fatal.
    if let Err(e) = update_ban_set(&config.ban_alias_name, &decisions).await {
        warn!(error = %e, "crowdsec: failed to update nftables ban set");
    }

    // Persist the latest decisions in the shared in-memory cache.
    {
        let mut cache = state.crowdsec_decisions.write().await;
        *cache = decisions;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_decision(id: i64, value: &str, type_: &str) -> CrowdSecDecision {
        CrowdSecDecision {
            id,
            value: value.to_string(),
            type_: type_.to_string(),
            scope: "Ip".to_string(),
            duration: "4h".to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // generate_ban_set_nft
    // -----------------------------------------------------------------------

    #[test]
    fn ban_set_nft_empty_decisions() {
        let out = generate_ban_set_nft("crowdsec_bans", &[]);
        assert!(out.contains("add table inet dayshield_crowdsec"));
        assert!(out.contains("add set inet dayshield_crowdsec crowdsec_bans"));
        assert!(out.contains("add set inet dayshield_crowdsec crowdsec_bans_v6"));
        assert!(out.contains("flush set inet dayshield_crowdsec crowdsec_bans"));
        assert!(out.contains("flush set inet dayshield_crowdsec crowdsec_bans_v6"));
        // No "add element" line when there are no bans.
        assert!(!out.contains("add element"));
    }

    #[test]
    fn ban_set_nft_single_ban_ipv4() {
        let decisions = vec![make_decision(1, "1.2.3.4", "ban")];
        let out = generate_ban_set_nft("crowdsec_bans", &decisions);
        assert!(out.contains("add element inet dayshield_crowdsec crowdsec_bans { 1.2.3.4 }"));
        // No v6 add element line since there are no IPv6 bans.
        assert!(!out.contains("add element inet dayshield_crowdsec crowdsec_bans_v6"));
    }

    #[test]
    fn ban_set_nft_single_ban_ipv6() {
        let decisions = vec![make_decision(2, "2001:db8::1", "ban")];
        let out = generate_ban_set_nft("crowdsec_bans", &decisions);
        assert!(
            out.contains("add element inet dayshield_crowdsec crowdsec_bans_v6 { 2001:db8::1 }")
        );
        // No v4 element line since there are no IPv4 bans.
        assert!(!out.contains("add element inet dayshield_crowdsec crowdsec_bans {"));
    }

    #[test]
    fn ban_set_nft_multiple_bans() {
        let decisions = vec![
            make_decision(1, "1.2.3.4", "ban"),
            make_decision(2, "5.6.7.8", "ban"),
            make_decision(3, "10.0.0.0/8", "ban"),
        ];
        let out = generate_ban_set_nft("crowdsec_bans", &decisions);
        assert!(out.contains("1.2.3.4"));
        assert!(out.contains("5.6.7.8"));
        assert!(out.contains("10.0.0.0/8"));
    }

    #[test]
    fn ban_set_nft_ipv6_cidr() {
        let decisions = vec![make_decision(5, "2001:db8::/32", "ban")];
        let out = generate_ban_set_nft("crowdsec_bans", &decisions);
        assert!(
            out.contains("add element inet dayshield_crowdsec crowdsec_bans_v6 { 2001:db8::/32 }")
        );
    }

    #[test]
    fn ban_set_nft_ignores_non_ban_decisions() {
        let decisions = vec![
            make_decision(1, "1.2.3.4", "captcha"),
            make_decision(2, "5.6.7.8", "throttle"),
        ];
        let out = generate_ban_set_nft("crowdsec_bans", &decisions);
        // Should NOT include these IPs because they are not "ban" type.
        assert!(!out.contains("add element"));
    }

    #[test]
    fn ban_set_nft_case_insensitive_ban_type() {
        let decisions = vec![make_decision(1, "9.9.9.9", "Ban")];
        let out = generate_ban_set_nft("crowdsec_bans", &decisions);
        assert!(out.contains("9.9.9.9"));
    }

    #[test]
    fn ban_set_nft_custom_alias_name() {
        let out = generate_ban_set_nft("my_custom_set", &[]);
        assert!(out.contains("add set inet dayshield_crowdsec my_custom_set"));
        assert!(out.contains("flush set inet dayshield_crowdsec my_custom_set"));
    }

    #[test]
    fn ban_set_nft_flushes_before_adding() {
        let decisions = vec![make_decision(1, "1.2.3.4", "ban")];
        let out = generate_ban_set_nft("crowdsec_bans", &decisions);
        let flush_pos = out.find("flush set").expect("flush set missing");
        let add_pos = out.find("add element").expect("add element missing");
        assert!(flush_pos < add_pos, "flush must appear before add element");
    }

    // -----------------------------------------------------------------------
    // is_ipv4_value
    // -----------------------------------------------------------------------

    #[test]
    fn is_ipv4_value_detects_ipv4_address() {
        assert!(is_ipv4_value("1.2.3.4"));
        assert!(is_ipv4_value("192.168.1.1"));
        assert!(!is_ipv4_value("::1"));
        assert!(!is_ipv4_value("2001:db8::1"));
    }

    #[test]
    fn is_ipv4_value_detects_ipv4_cidr() {
        assert!(is_ipv4_value("10.0.0.0/8"));
        assert!(!is_ipv4_value("2001:db8::/32"));
    }

    // -----------------------------------------------------------------------
    // validate_api_key / validate_ip_or_cidr (via config models)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_api_key_non_empty() {
        use crate::config::models::validate_api_key;
        assert!(validate_api_key("some-bouncer-key-abc123"));
        assert!(!validate_api_key(""));
        assert!(!validate_api_key("   "));
    }

    #[test]
    fn validate_ip_or_cidr_accepts_ips_and_cidrs() {
        use crate::config::models::validate_ip_or_cidr;
        assert!(validate_ip_or_cidr("1.2.3.4"));
        assert!(validate_ip_or_cidr("::1"));
        assert!(validate_ip_or_cidr("192.168.0.0/24"));
        assert!(validate_ip_or_cidr("2001:db8::/32"));
        assert!(!validate_ip_or_cidr("not-an-ip"));
        assert!(!validate_ip_or_cidr("999.999.999.999"));
    }
}
