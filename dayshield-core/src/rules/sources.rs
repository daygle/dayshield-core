//! Built-in curated Suricata ruleset sources.
//!
//! Add new entries here to expose additional community rulesets to users.

use crate::rules::models::CuratedSource;

const ET_OPEN_SURICATA6_RULES_BASE: &str =
    "https://rules.emergingthreats.net/open/suricata-6.0/rules";

fn et_open_group_source(group_slug: &str) -> CuratedSource {
    let display = group_slug
        .strip_prefix("emerging-")
        .unwrap_or(group_slug)
        .split(['-', '_', '.'])
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => {
                    let mut s = String::new();
                    s.extend(first.to_uppercase());
                    s.push_str(chars.as_str());
                    s
                }
                None => String::new(),
            }
        })
        .collect::<Vec<String>>()
        .join(" ");

    CuratedSource {
        id: format!("et-open/{group_slug}"),
        display_name: format!("ET Open {display}"),
        description: format!(
            "Emerging Threats Open Suricata 6.x group: {group_slug}.rules"
        ),
        url: format!("{ET_OPEN_SURICATA6_RULES_BASE}/{group_slug}.rules"),
        license: "BSD".to_string(),
        vendor: "Proofpoint / Emerging Threats".to_string(),
    }
}

/// Return the list of all built-in curated ruleset sources.
///
/// These are shown on the "Available Rulesets" page in the UI.  Users can
/// install any of them with a single API call.
pub fn curated_sources() -> Vec<CuratedSource> {
    // NOTE: `classification.config` and `compromised-ips.txt` from the ET index are
    // not Suricata rules files and are intentionally excluded from curated installables.
    let et_open_group_slugs = [
        "botcc.portgrouped",
        "botcc",
        "ciarmy",
        "compromised",
        "drop",
        "dshield",
        "emerging-activex",
        "emerging-adware_pup",
        "emerging-attack_response",
        "emerging-chat",
        "emerging-coinminer",
        "emerging-current_events",
        "emerging-deleted",
        "emerging-dns",
        "emerging-dos",
        "emerging-exploit",
        "emerging-exploit_kit",
        "emerging-ftp",
        "emerging-games",
        "emerging-hunting",
        "emerging-icmp",
        "emerging-icmp_info",
        "emerging-imap",
        "emerging-inappropriate",
        "emerging-info",
        "emerging-ja3",
        "emerging-malware",
        "emerging-misc",
        "emerging-mobile_malware",
        "emerging-netbios",
        "emerging-p2p",
        "emerging-phishing",
        "emerging-policy",
        "emerging-pop3",
        "emerging-retired",
        "emerging-rpc",
        "emerging-scada",
        "emerging-scan",
        "emerging-shellcode",
        "emerging-smtp",
        "emerging-snmp",
        "emerging-sql",
        "emerging-telnet",
        "emerging-tftp",
        "emerging-user_agents",
        "emerging-voip",
        "emerging-web_client",
        "emerging-web_server",
        "emerging-web_specific_apps",
        "emerging-worm",
        "threatview_CS_c2",
        "tor",
    ];

    let sources: Vec<CuratedSource> = et_open_group_slugs
        .into_iter()
        .map(et_open_group_source)
        .collect();

    sources
}
