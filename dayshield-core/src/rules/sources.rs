//! Built-in curated Suricata ruleset sources.
//!
//! Add new entries here to expose additional community rulesets to users.

use crate::rules::models::CuratedSource;

/// Return the list of all built-in curated ruleset sources.
///
/// These are shown on the "Available Rulesets" page in the UI.  Users can
/// install any of them with a single API call.
pub fn curated_sources() -> Vec<CuratedSource> {
    vec![
        CuratedSource {
            id: "et-open".to_string(),
            display_name: "Emerging Threats Open".to_string(),
            description: "Community ruleset from Proofpoint's Emerging Threats project, \
                covering a wide range of network threats including malware, \
                exploit kits, botnets, and scanning activity. \
                This DayShield build tracks the Suricata 6.x compatible feed. \
                Freely available under the BSD license."
                .to_string(),
            url: "https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"
                .to_string(),
            license: "BSD".to_string(),
            vendor: "Proofpoint / Emerging Threats".to_string(),
        },
        CuratedSource {
            id: "oisf-trafficid".to_string(),
            display_name: "OISF Traffic ID Rules".to_string(),
            description: "OISF traffic identification rules for protocol \
                and application classification."
                .to_string(),
            url: "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules".to_string(),
            license: "GPL-2.0".to_string(),
            vendor: "OISF".to_string(),
        },
    ]
}
