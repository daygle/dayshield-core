//! CrowdSec integration — threat intelligence and automatic IP remediation.
//!
//! TODO: implement CrowdSec Local API (LAPI) client.
//! TODO: poll the LAPI decisions endpoint and sync bans to nftables.
//! TODO: implement a bouncer registration flow using the CrowdSec API key.
//! TODO: expose active decision count in the metrics layer.
//! TODO: implement allowlist management to protect known-good IPs.
//! TODO: integrate CrowdSec hub scenario sync for community threat feeds.

use anyhow::Result;
use tracing::info;

use crate::config::models::CrowdsecPolicy;

/// Synchronise the active CrowdSec decisions against the local policy list.
///
/// TODO: contact the LAPI, retrieve current decisions, and apply matching
///       policies (e.g. add IPs to an nftables set).
pub async fn sync_decisions(policies: &[CrowdsecPolicy]) -> Result<()> {
    info!(
        policies = policies.len(),
        "crowdsec: sync_decisions called (stub)"
    );
    Ok(())
}

/// Register this instance as a CrowdSec bouncer.
///
/// TODO: POST to `<LAPI>/v1/watchers/login` with the machine credentials.
pub async fn register_bouncer(api_url: &str) -> Result<String> {
    info!(api_url, "crowdsec: register_bouncer called (stub)");
    // TODO: return the API key issued by the LAPI.
    Ok(String::from("stub-api-key"))
}
