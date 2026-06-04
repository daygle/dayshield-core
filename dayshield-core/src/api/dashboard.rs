//! Dashboard summary endpoints.
//!
//! - `GET /dashboard/cards`    - canonical dashboard card set for all modules
//! - `GET /dashboard/system`   - host resource usage (CPU, RAM, disk, uptime)
//! - `GET /dashboard/network`  - WAN/LAN interface overview
//! - `GET /dashboard/security` - recent Suricata alerts, CrowdSec decisions, firewall stats
//! - `GET /dashboard/acme`     - ACME certificate expiry summary

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, response::IntoResponse, Json};
use serde::Serialize;
use tracing::warn;

use crate::backup::create::DEFAULT_BACKUP_DIR;
use crate::backup::model::BackupScheduleConfig;
use crate::backup::scheduler::load_schedule;
use crate::config::models::{
    Dhcp6Config, DhcpConfig, NatConfig, OutboundMode, SuricataConfig, SystemConfig,
};
use crate::engine::acme::AcmeEngine;
use crate::engine::interfaces::list_kernel_interfaces;
use crate::metrics::MetricsSnapshot;
use crate::rules::models::{InstalledRuleset, RulesetStatus};
use crate::rules::storage::RulesetStore;
use crate::schedules::{self, SystemSchedulesResponse};
use crate::state::{
    AppState, SVC_ACME, SVC_CAPTIVE_PORTAL, SVC_CLOUDFLARED, SVC_CROWDSEC, SVC_DHCP, SVC_DNS,
    SVC_HONEYPOT, SVC_NFTABLES, SVC_SURICATA, SVC_VPN,
};

// ---------------------------------------------------------------------------
// GET /dashboard/cards
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardCardsResponse {
    pub generated_at: String,
    pub cards: Vec<DashboardCard>,
}

/// Canonical card descriptor consumed by the management UI dashboard.
///
/// This endpoint is intentionally module-oriented rather than visual-layout
/// oriented. The UI can choose how many cards to display per row without
/// needing to duplicate backend knowledge about which modules exist.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardCard {
    pub id: &'static str,
    pub title: &'static str,
    pub module: &'static str,
    pub category: &'static str,
    pub status: &'static str,
    pub status_label: String,
    pub summary: String,
    pub metrics: Vec<DashboardCardMetric>,
    pub links: Vec<DashboardCardLink>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_control: Option<DashboardCardServiceControl>,
    pub order: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardCardMetric {
    pub label: &'static str,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardCardLink {
    pub label: &'static str,
    pub href: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardCardServiceControl {
    pub service_id: &'static str,
    pub status_href: String,
    pub actions: Vec<DashboardCardServiceAction>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardCardServiceAction {
    pub id: &'static str,
    pub label: &'static str,
    pub method: &'static str,
    pub href: String,
    pub variant: &'static str,
    pub requires_confirmation: bool,
}

struct DashboardCardInputs<'a> {
    cfg: &'a SystemConfig,
    services: &'a HashMap<String, bool>,
    snapshot: Option<&'a MetricsSnapshot>,
    disk_percent: f64,
    backup_schedule: BackupScheduleConfig,
    backup_count: usize,
    installed_rulesets: &'a [InstalledRuleset],
    schedules: Option<SystemSchedulesResponse>,
    update_settings: crate::update::UpdateSettings,
    active_crowdsec_decisions: usize,
    ai_threat_count: usize,
    ai_blocked_count: usize,
    honeypot_events_last_24h: usize,
    honeypot_unique_ips: usize,
}

pub async fn get_cards(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut cfg = state.config_store.load().unwrap_or_default();
    cfg.interfaces = state.interfaces.read().await.clone();
    cfg.firewall_rules = state.firewall_rules.read().await.clone();

    let services = state.services.read().await.clone();
    let snapshot = {
        let buf = state.metrics_buffer.read().await;
        buf.latest().cloned()
    };
    let disk_percent = snapshot
        .as_ref()
        .map(|s| s.system.disk_percent)
        .filter(|value| *value > 0.0)
        .unwrap_or_else(|| 0.0);
    let disk_percent = if disk_percent > 0.0 {
        disk_percent
    } else {
        read_disk_percent("/").await
    };

    let backup_schedule = load_schedule(&state).unwrap_or_default();
    let backup_count = count_backup_files(Path::new(DEFAULT_BACKUP_DIR));
    let installed_rulesets = RulesetStore::new().load().unwrap_or_default();
    let schedules = schedules::get_response(&state).ok();
    let update_settings = crate::update::load_settings(&state);
    let active_crowdsec_decisions = state.crowdsec_decisions.read().await.len();
    let ai_threat_count = state
        .ai_runtime
        .recent_threat_events(100)
        .map(|events| events.len())
        .unwrap_or(0);
    let ai_blocked_count = state.ai_runtime.list_blocked().await.len();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let honeypot_events_last_24h = state
        .honeypot_runtime
        .count_events_since(now.saturating_sub(86_400))
        .unwrap_or(0);
    let honeypot_unique_ips = state
        .honeypot_runtime
        .source_ips(1000)
        .map(|ips| ips.len())
        .unwrap_or(0);

    let cards = build_dashboard_cards(DashboardCardInputs {
        cfg: &cfg,
        services: &services,
        snapshot: snapshot.as_ref(),
        disk_percent,
        backup_schedule,
        backup_count,
        installed_rulesets: &installed_rulesets,
        schedules,
        update_settings,
        active_crowdsec_decisions,
        ai_threat_count,
        ai_blocked_count,
        honeypot_events_last_24h,
        honeypot_unique_ips,
    });

    Json(DashboardCardsResponse {
        generated_at: chrono::Utc::now().to_rfc3339(),
        cards,
    })
}

fn build_dashboard_cards(inputs: DashboardCardInputs<'_>) -> Vec<DashboardCard> {
    let cfg = inputs.cfg;
    let system = cfg.system_settings.clone().unwrap_or_default();
    let firewall_settings = cfg.firewall_settings.clone().unwrap_or_default();
    let nat = cfg.nat.clone().unwrap_or_default();
    let dns = cfg.dns.clone().unwrap_or_default();
    let dot = cfg.dot.clone().unwrap_or_default();
    let dhcp = cfg.dhcp.clone().unwrap_or_else(default_dhcp_card_config);
    let dhcp6 = cfg.dhcp6.clone().unwrap_or_else(default_dhcp6_card_config);
    let suricata = cfg
        .suricata
        .clone()
        .unwrap_or_else(default_suricata_card_config);
    let crowdsec = cfg.crowdsec.clone();
    let acme = cfg.acme.clone();
    let notify = cfg.notify.clone().unwrap_or_default();
    let ntp = cfg.ntp.clone().unwrap_or_default();
    let dynamic_dns = cfg.dynamic_dns.clone().unwrap_or_default();
    let cloudflared = cfg.cloudflared.clone().unwrap_or_default();
    let captive_portal = cfg.captive_portal.clone().unwrap_or_default();
    let ai_engine = cfg.ai_engine.clone().unwrap_or_default();
    let honeypots = cfg.honeypots.clone().unwrap_or_default();
    let admin_security = cfg.admin_security.clone().unwrap_or_default();
    let logging = cfg.logging.clone().unwrap_or_default();

    let mut cards = Vec::new();

    let cpu = inputs
        .snapshot
        .map(|s| s.system.cpu_percent)
        .unwrap_or_default();
    let ram = inputs
        .snapshot
        .map(|s| s.system.ram_percent)
        .unwrap_or_default();
    let uptime = inputs
        .snapshot
        .map(|s| s.system.uptime_seconds)
        .unwrap_or_default();
    let (system_status, system_label) = resource_status(cpu, ram, inputs.disk_percent);
    cards.push(card(
        10,
        "system",
        "System",
        "System",
        "system",
        system_status,
        system_label,
        format!(
            "{} serving API/UI on port {} with IPv6 {}",
            system.hostname,
            system.web_port,
            enabled_word(system.ipv6_enabled)
        ),
        vec![
            metric("CPU", format_percent(cpu)),
            metric("RAM", format_percent(ram)),
            metric("Disk", format_percent(inputs.disk_percent)),
            metric("Uptime", format_duration(uptime)),
        ],
        vec![
            link("System settings", "/system/config"),
            link("System status", "/system/status"),
        ],
    ));

    let enabled_ifaces = cfg.interfaces.iter().filter(|iface| iface.enabled).count();
    let wan_ifaces = cfg
        .interfaces
        .iter()
        .filter(|iface| iface.wan_mode.is_some() || iface.gateway.is_some())
        .count();
    let vlan_ifaces = cfg
        .interfaces
        .iter()
        .filter(|iface| iface.vlan.is_some())
        .count();
    let interface_status = if enabled_ifaces == 0 { "warning" } else { "ok" };
    cards.push(card(
        20,
        "interfaces",
        "Interfaces",
        "Network Interfaces",
        "network",
        interface_status,
        if enabled_ifaces == 0 {
            "No enabled interfaces".to_string()
        } else {
            format!("{enabled_ifaces} enabled")
        },
        "Managed physical, VLAN, WAN, LAN, and IPv6 interface configuration".to_string(),
        vec![
            metric("Total", cfg.interfaces.len()),
            metric("Enabled", enabled_ifaces),
            metric("WAN", wan_ifaces),
            metric("VLANs", vlan_ifaces),
        ],
        vec![link("Interfaces", "/interfaces")],
    ));

    let enabled_gateways = cfg
        .gateways
        .iter()
        .filter(|gateway| gateway.enabled)
        .count();
    let gateway_status = if cfg.gateways.is_empty() {
        "disabled"
    } else if enabled_gateways == 0 {
        "warning"
    } else {
        "ok"
    };
    cards.push(card(
        30,
        "gateways",
        "Gateways",
        "Routing Gateways",
        "network",
        gateway_status,
        match (cfg.gateways.len(), enabled_gateways) {
            (0, _) => "Not configured".to_string(),
            (_, 0) => "Configured but disabled".to_string(),
            (_, n) => format!("{n} active"),
        },
        "Named upstream gateways for default routing, monitoring, and multi-WAN policy".to_string(),
        vec![
            metric("Total", cfg.gateways.len()),
            metric("Enabled", enabled_gateways),
            metric(
                "Monitored",
                cfg.gateways
                    .iter()
                    .filter(|gateway| gateway.monitor_ip.is_some())
                    .count(),
            ),
        ],
        vec![link("Gateways", "/gateways")],
    ));

    let enabled_firewall_rules = cfg
        .firewall_rules
        .iter()
        .filter(|rule| rule.enabled)
        .count();
    let (firewall_status, firewall_label) =
        service_status(inputs.services, SVC_NFTABLES, true, "Firewall active");
    let state_count = inputs
        .snapshot
        .map(|s| s.firewall.state_count)
        .unwrap_or_default();
    cards.push(with_service_control(
        card(
            40,
            "firewall",
            "Firewall",
            "Firewall Policy",
            "security",
            firewall_status,
            firewall_label,
            "Stateful packet filtering with global defaults, aliases, schedules, and anti-lockout"
                .to_string(),
            vec![
                metric("Rules", cfg.firewall_rules.len()),
                metric("Enabled", enabled_firewall_rules),
                metric("Aliases", cfg.firewall_aliases.len()),
                metric("States", state_count),
                metric(
                    "Anti-lockout",
                    yes_no(firewall_settings.management_anti_lockout),
                ),
            ],
            vec![
                link("Rules", "/firewall/rules"),
                link("Settings", "/firewall/settings"),
                link("Aliases", "/firewall/aliases"),
            ],
        ),
        SVC_NFTABLES,
    ));

    cards.push(nat_card(50, &nat));

    let dns_blocklists: usize = dns
        .interface_blocklists
        .iter()
        .map(|group| {
            group
                .blocklists
                .iter()
                .filter(|entry| entry.enabled)
                .count()
        })
        .sum();
    let (dns_status, dns_label) =
        service_status(inputs.services, SVC_DNS, dns.enabled, "Resolver active");
    cards.push(with_service_control(
        card(
            60,
            "dns",
            "DNS",
            "Recursive DNS",
            "services",
            dns_status,
            dns_label,
            "Unbound resolver, forwarders, DNSSEC, local records, and per-interface blocklists"
                .to_string(),
            vec![
                metric("Port", dns.port),
                metric("Forwarders", dns.forwarders.len()),
                metric("Local records", dns.local_records.len()),
                metric("Blocklists", dns_blocklists),
                metric("DNSSEC", yes_no(dns.dnssec)),
            ],
            vec![
                link("DNS config", "/dns/config"),
                link("DNS overrides", "/dns/overrides"),
            ],
        ),
        SVC_DNS,
    ));

    let dot_ready = dot.cert_pem.is_some() && dot.key_pem.is_some() || dot.acme_domain.is_some();
    cards.push(with_service_control(
        card(
            70,
            "dns-over-tls",
            "DNS-over-TLS",
            "DoT Listener",
            "services",
            if !dot.enabled {
                "disabled"
            } else if dot_ready {
                "ok"
            } else {
                "warning"
            },
            if !dot.enabled {
                "Disabled".to_string()
            } else if dot_ready {
                "TLS material configured".to_string()
            } else {
                "Certificate needed".to_string()
            },
            "Encrypted DNS listener backed by static certificate material or ACME".to_string(),
            vec![
                metric("Port", dot.port),
                metric("LAN only", yes_no(dot.lan_only)),
                metric(
                    "Certificate",
                    if dot.acme_domain.is_some() {
                        "ACME"
                    } else if dot_ready {
                        "Static"
                    } else {
                        "Missing"
                    },
                ),
            ],
            vec![
                link("DoT config", "/dns/dot/config"),
                link("ACME config", "/acme/config"),
            ],
        ),
        SVC_DNS,
    ));

    let dhcp_enabled = dhcp.enabled || dhcp6.enabled;
    let (dhcp_status, dhcp_label) =
        service_status(inputs.services, SVC_DHCP, dhcp_enabled, "DHCP active");
    cards.push(with_service_control(
        card(
            80,
            "dhcp",
            "DHCP",
            "DHCPv4 / DHCPv6",
            "services",
            dhcp_status,
            dhcp_label,
            "Kea/dnsmasq address assignment, lease pools, static reservations, and DHCPv6 scopes"
                .to_string(),
            vec![
                metric("IPv4 scopes", dhcp.scopes.len()),
                metric(
                    "IPv4 reservations",
                    dhcp.scopes
                        .iter()
                        .map(|scope| scope.reservations.len())
                        .sum::<usize>(),
                ),
                metric("IPv6 scopes", dhcp6.scopes.len()),
                metric(
                    "IPv6 reservations",
                    dhcp6
                        .scopes
                        .iter()
                        .map(|scope| scope.reservations.len())
                        .sum::<usize>(),
                ),
            ],
            vec![
                link("DHCPv4 config", "/dhcp/config"),
                link("DHCPv6 config", "/dhcp6/config"),
                link("Leases", "/dhcp/leases"),
            ],
        ),
        SVC_DHCP,
    ));

    let wg_enabled = cfg
        .wireguard_interfaces
        .iter()
        .filter(|iface| iface.enabled)
        .count();
    let wg_peers: usize = cfg
        .wireguard_interfaces
        .iter()
        .map(|iface| iface.peers.len())
        .sum();
    let (wg_status, wg_label) =
        service_status(inputs.services, SVC_VPN, wg_enabled > 0, "VPN active");
    cards.push(card(
        90,
        "wireguard",
        "WireGuard",
        "VPN",
        "network",
        wg_status,
        wg_label,
        "WireGuard server interfaces, peers, tunnel addresses, and interface firewall rules"
            .to_string(),
        vec![
            metric("Interfaces", cfg.wireguard_interfaces.len()),
            metric("Enabled", wg_enabled),
            metric("Peers", wg_peers),
        ],
        vec![link("WireGuard", "/wireguard/interfaces")],
    ));

    let suricata_alerts = inputs
        .snapshot
        .map(|s| s.suricata.alerts_last_minute)
        .unwrap_or_default();
    let (suricata_status, suricata_label) = service_status(
        inputs.services,
        SVC_SURICATA,
        suricata.enabled,
        "IDS/IPS active",
    );
    cards.push(with_service_control(
        card(
            100,
            "suricata",
            "Suricata",
            "IDS / IPS",
            "security",
            suricata_status,
            suricata_label,
            "Network intrusion detection or prevention, monitored interfaces, and alert logs"
                .to_string(),
            vec![
                metric("Mode", suricata.mode.to_uppercase()),
                metric("Interfaces", suricata.interfaces.len()),
                metric("Rule sources", suricata.rule_sources.len()),
                metric("Alerts/min", suricata_alerts),
            ],
            vec![
                link("Suricata config", "/suricata/config"),
                link("Alerts", "/suricata/alerts"),
                link("Rule sources", "/suricata/rulesets"),
            ],
        ),
        SVC_SURICATA,
    ));

    let ruleset_updates = inputs
        .installed_rulesets
        .iter()
        .filter(|ruleset| ruleset.status == RulesetStatus::UpdateAvailable)
        .count();
    let ruleset_failed = inputs
        .installed_rulesets
        .iter()
        .filter(|ruleset| ruleset.status == RulesetStatus::Failed)
        .count();
    cards.push(card(
        110,
        "managed-rulesets",
        "Managed Rulesets",
        "Threat Feeds",
        "security",
        if ruleset_failed > 0 {
            "critical"
        } else if ruleset_updates > 0 {
            "warning"
        } else if inputs.installed_rulesets.is_empty() {
            "disabled"
        } else {
            "ok"
        },
        if ruleset_failed > 0 {
            format!("{ruleset_failed} failed")
        } else if ruleset_updates > 0 {
            format!("{ruleset_updates} update available")
        } else if inputs.installed_rulesets.is_empty() {
            "No managed feeds".to_string()
        } else {
            "Feeds current".to_string()
        },
        "Curated Suricata ruleset installation, enablement, disabled rules, and updates"
            .to_string(),
        vec![
            metric("Installed", inputs.installed_rulesets.len()),
            metric(
                "Enabled",
                inputs
                    .installed_rulesets
                    .iter()
                    .filter(|ruleset| ruleset.enabled)
                    .count(),
            ),
            metric("Updates", ruleset_updates),
            metric("Failed", ruleset_failed),
        ],
        vec![
            link("Installed", "/rulesets"),
            link("Available", "/rulesets/available"),
        ],
    ));

    let crowdsec_enabled = crowdsec.as_ref().map(|cfg| cfg.enabled).unwrap_or(false);
    let (crowdsec_status, crowdsec_label) = service_status(
        inputs.services,
        SVC_CROWDSEC,
        crowdsec_enabled,
        "Bouncer active",
    );
    cards.push(with_service_control(
        card(
            120,
            "crowdsec",
            "CrowdSec",
            "CrowdSec Bouncer",
            "security",
            crowdsec_status,
            crowdsec_label,
            "CrowdSec Local API decisions synchronized into DayShield enforcement".to_string(),
            vec![
                metric("Configured", yes_no(crowdsec_enabled)),
                metric("Decisions", inputs.active_crowdsec_decisions),
                metric(
                    "Poll seconds",
                    crowdsec
                        .as_ref()
                        .map(|cfg| cfg.update_interval.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
            ],
            vec![
                link("CrowdSec config", "/crowdsec/config"),
                link("Decisions", "/crowdsec/decisions"),
            ],
        ),
        SVC_CROWDSEC,
    ));

    let enabled_honeypots = honeypots
        .listeners
        .iter()
        .filter(|listener| listener.enabled)
        .count();
    let (honeypot_status, honeypot_label) = service_status(
        inputs.services,
        SVC_HONEYPOT,
        honeypots.enabled && enabled_honeypots > 0,
        "Listeners active",
    );
    cards.push(card(
        130,
        "honeypots",
        "Honeypots",
        "Low-Interaction Sensors",
        "security",
        honeypot_status,
        honeypot_label,
        "Low-interaction listener traps feeding the AI threat engine and event history".to_string(),
        vec![
            metric("Listeners", honeypots.listeners.len()),
            metric("Enabled", enabled_honeypots),
            metric("Events 24h", inputs.honeypot_events_last_24h),
            metric("Source IPs", inputs.honeypot_unique_ips),
        ],
        vec![
            link("Honeypot config", "/honeypots/config"),
            link("Events", "/honeypots/events"),
        ],
    ));

    cards.push(card(
        140,
        "ai-threat-engine",
        "AI Threat Engine",
        "AI Policy",
        "security",
        if !ai_engine.enabled {
            "disabled"
        } else if ai_engine.automatic_blocking {
            "ok"
        } else {
            "info"
        },
        if !ai_engine.enabled {
            "Disabled".to_string()
        } else if ai_engine.automatic_blocking {
            "Automatic blocking enabled".to_string()
        } else {
            "Monitoring only".to_string()
        },
        "Local threat scoring, traffic candidates, policy suggestions, intents, and action history"
            .to_string(),
        vec![
            metric("Threat events", inputs.ai_threat_count),
            metric("Blocked IPs", inputs.ai_blocked_count),
            metric(
                "Block threshold",
                format!("{:.0}%", ai_engine.risk_score_block_threshold * 100.0),
            ),
            metric("Training", yes_no(ai_engine.training_enabled)),
        ],
        vec![
            link("AI config", "/api/ai/config"),
            link("Threats", "/api/ai/threats"),
            link("Suggestions", "/api/ai/suggestions"),
        ],
    ));

    let acme_enabled = acme.as_ref().map(|cfg| cfg.enabled).unwrap_or(false);
    let (acme_status, acme_label) =
        service_status(inputs.services, SVC_ACME, acme_enabled, "Renewal active");
    cards.push(card(
        150,
        "acme",
        "ACME",
        "TLS Certificates",
        "services",
        if acme_enabled
            && acme
                .as_ref()
                .map(|cfg| cfg.domains.is_empty())
                .unwrap_or(true)
        {
            "warning"
        } else {
            acme_status
        },
        if acme_enabled
            && acme
                .as_ref()
                .map(|cfg| cfg.domains.is_empty())
                .unwrap_or(true)
        {
            "No domains configured".to_string()
        } else {
            acme_label
        },
        "Automatic certificate issuance and renewal for management UI, DoT, and services"
            .to_string(),
        vec![
            metric(
                "Domains",
                acme.as_ref().map(|cfg| cfg.domains.len()).unwrap_or(0),
            ),
            metric(
                "Challenge",
                acme.as_ref()
                    .map(|cfg| format!("{:?}", cfg.challenge_type).to_lowercase())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            metric(
                "Renew hours",
                acme.as_ref()
                    .map(|cfg| cfg.renew_interval_hours.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ],
        vec![
            link("ACME config", "/acme/config"),
            link("ACME status", "/acme/status"),
        ],
    ));

    cards.push(card(
        160,
        "dynamic-dns",
        "Dynamic DNS",
        "DDNS",
        "services",
        if !dynamic_dns.enabled {
            "disabled"
        } else if dynamic_dns.entries.iter().any(|entry| entry.enabled) {
            "ok"
        } else {
            "warning"
        },
        if !dynamic_dns.enabled {
            "Disabled".to_string()
        } else {
            format!(
                "{} enabled records",
                dynamic_dns
                    .entries
                    .iter()
                    .filter(|entry| entry.enabled)
                    .count()
            )
        },
        "Provider updates for publishing WAN interface addresses to DNS records".to_string(),
        vec![
            metric("Entries", dynamic_dns.entries.len()),
            metric(
                "Enabled",
                dynamic_dns
                    .entries
                    .iter()
                    .filter(|entry| entry.enabled)
                    .count(),
            ),
            metric(
                "Interval",
                format!("{}s", dynamic_dns.check_interval_seconds),
            ),
        ],
        vec![
            link("Dynamic DNS", "/dynamic-dns/config"),
            link("Status", "/dynamic-dns/status"),
        ],
    ));

    let cloudflared_configured = !cloudflared.tunnel_token.trim().is_empty();
    let cloudflared_ready = cloudflared_configured && !cloudflared.ingress.is_empty();
    let (cloudflared_status, cloudflared_label) = service_status(
        inputs.services,
        SVC_CLOUDFLARED,
        cloudflared.enabled,
        "Tunnel active",
    );
    cards.push(with_service_control(
        card(
            170,
            "cloudflared",
            "Cloudflared",
            "Cloudflare Tunnel",
            "services",
            if cloudflared.enabled && !cloudflared_ready {
                "warning"
            } else {
                cloudflared_status
            },
            if cloudflared.enabled && !cloudflared_ready {
                "Tunnel configuration incomplete".to_string()
            } else {
                cloudflared_label
            },
            "Outbound Cloudflare Tunnel publishing selected local services without inbound NAT"
                .to_string(),
            vec![
                metric("Ingress", cloudflared.ingress.len()),
                metric("Token", yes_no(cloudflared_configured)),
                metric("Log level", cloudflared.log_level),
            ],
            vec![
                link("Cloudflared config", "/cloudflared/config"),
                link("Status", "/cloudflared/status"),
            ],
        ),
        SVC_CLOUDFLARED,
    ));

    let portal_ready = !captive_portal.interfaces.is_empty();
    let (portal_status, portal_label) = service_status(
        inputs.services,
        SVC_CAPTIVE_PORTAL,
        captive_portal.enabled,
        "Portal active",
    );
    cards.push(card(
        180,
        "captive-portal",
        "Captive Portal",
        "Client Portal",
        "services",
        if captive_portal.enabled && !portal_ready {
            "warning"
        } else {
            portal_status
        },
        if captive_portal.enabled && !portal_ready {
            "No interfaces selected".to_string()
        } else {
            portal_label
        },
        "Guest/client network authorization, vouchers, walled garden, and sessions".to_string(),
        vec![
            metric("Interfaces", captive_portal.interfaces.len()),
            metric(
                "Auth mode",
                format!("{:?}", captive_portal.auth_mode).to_lowercase(),
            ),
            metric("Vouchers", captive_portal.vouchers.len()),
            metric("Bypass MACs", captive_portal.bypass_macs.len()),
        ],
        vec![
            link("Portal config", "/captive-portal/config"),
            link("Sessions", "/captive-portal/sessions"),
        ],
    ));

    cards.push(with_service_control(
        card(
            190,
            "ntp",
            "NTP",
            "Time Sync",
            "services",
            if !ntp.enabled {
                "disabled"
            } else if ntp.upstream_servers.is_empty() {
                "warning"
            } else {
                "ok"
            },
            if !ntp.enabled {
                "Disabled".to_string()
            } else if ntp.upstream_servers.is_empty() {
                "No upstream servers".to_string()
            } else {
                "Time sync configured".to_string()
            },
            "Host clock synchronization and optional LAN NTP service".to_string(),
            vec![
                metric("Upstreams", ntp.upstream_servers.len()),
                metric("Serve clients", yes_no(ntp.serve_clients)),
                metric("Listen interfaces", ntp.listen_interfaces.len()),
            ],
            vec![
                link("NTP config", "/ntp/config"),
                link("NTP status", "/ntp/status"),
            ],
        ),
        "ntp",
    ));

    cards.push(card(
        200,
        "notifications",
        "Notifications",
        "Email Alerts",
        "services",
        if !notify.enabled {
            "disabled"
        } else if notify.to_addresses.is_empty() {
            "warning"
        } else {
            "ok"
        },
        if !notify.enabled {
            "Disabled".to_string()
        } else if notify.to_addresses.is_empty() {
            "No recipients".to_string()
        } else {
            "Email alerts enabled".to_string()
        },
        "SMTP email notifications, category filters, rate limiting, and digest delivery"
            .to_string(),
        vec![
            metric("Recipients", notify.to_addresses.len()),
            metric("Categories", notify.categories.len()),
            metric("Rate/min", notify.rate_limit_per_minute),
            metric("Digest", yes_no(notify.digest_mode)),
        ],
        vec![
            link("Notifications", "/notify/config"),
            link("Categories", "/notify/categories"),
        ],
    ));

    cards.push(card(
        210,
        "backups",
        "Backups",
        "Backup / Restore",
        "maintenance",
        if inputs.backup_schedule.enabled {
            "ok"
        } else if inputs.backup_count > 0 {
            "info"
        } else {
            "disabled"
        },
        if inputs.backup_schedule.enabled {
            "Scheduled backups enabled".to_string()
        } else if inputs.backup_count > 0 {
            "Manual backups available".to_string()
        } else {
            "No scheduled backups".to_string()
        },
        "Manual and scheduled configuration backup archives with optional encryption".to_string(),
        vec![
            metric("Backups", inputs.backup_count),
            metric(
                "Interval",
                format!("{}h", inputs.backup_schedule.interval_hours),
            ),
            metric("Retain", inputs.backup_schedule.retain_count),
            metric("Encrypt", yes_no(inputs.backup_schedule.encrypt)),
        ],
        vec![
            link("Create backup", "/backup/create"),
            link("Backup list", "/backup/list"),
            link("Scheduler", "/backup/scheduler"),
        ],
    ));

    let update_settings = inputs.update_settings;
    cards.push(card(
        220,
        "updates",
        "Updates",
        "Software Updates",
        "maintenance",
        if update_settings.auto_check_enabled {
            "ok"
        } else {
            "info"
        },
        if update_settings.auto_check_enabled {
            "Auto-check enabled".to_string()
        } else {
            "Manual checks only".to_string()
        },
        "Core, UI, and rootfs update settings, validation, rollback, and appliance rebuild state"
            .to_string(),
        vec![
            metric("Auto check", yes_no(update_settings.auto_check_enabled)),
            metric(
                "Verify signatures",
                yes_no(update_settings.verify_artifact_signatures),
            ),
            metric(
                "Runtime deploy",
                yes_no(update_settings.deploy_runtime_after_apply),
            ),
        ],
        vec![
            link("Update status", "/system/updates/status"),
            link("Update settings", "/system/updates/settings"),
        ],
    ));

    let schedule_jobs_enabled = inputs
        .schedules
        .as_ref()
        .map(|value| value.jobs.iter().filter(|job| job.enabled).count())
        .unwrap_or(0);
    let schedule_jobs_failed = inputs
        .schedules
        .as_ref()
        .map(|value| {
            value
                .jobs
                .iter()
                .filter(|job| job.last_success == Some(false))
                .count()
        })
        .unwrap_or(0);
    cards.push(card(
        230,
        "system-schedules",
        "Schedules",
        "System Jobs",
        "maintenance",
        if schedule_jobs_failed > 0 {
            "warning"
        } else if schedule_jobs_enabled > 0 {
            "ok"
        } else {
            "disabled"
        },
        if schedule_jobs_failed > 0 {
            format!("{schedule_jobs_failed} recent failures")
        } else if schedule_jobs_enabled > 0 {
            format!("{schedule_jobs_enabled} jobs enabled")
        } else {
            "No scheduled jobs enabled".to_string()
        },
        "Scheduled Dynamic DNS updates, ACME renewal, and managed ruleset refresh jobs".to_string(),
        vec![
            metric(
                "Jobs",
                inputs
                    .schedules
                    .as_ref()
                    .map(|value| value.jobs.len())
                    .unwrap_or(0),
            ),
            metric("Enabled", schedule_jobs_enabled),
            metric("Failures", schedule_jobs_failed),
        ],
        vec![link("Schedules", "/system/schedules")],
    ));

    cards.push(card(
        240,
        "logs-metrics",
        "Logs & Metrics",
        "Observability",
        "maintenance",
        if inputs.snapshot.is_some() {
            "ok"
        } else {
            "unknown"
        },
        if inputs.snapshot.is_some() {
            "Metrics flowing".to_string()
        } else {
            "Awaiting metrics snapshot".to_string()
        },
        "Live logs, historical log search, metrics snapshots, WebSockets, and logging output"
            .to_string(),
        vec![
            metric("Log level", empty_dash(logging.level)),
            metric("Overrides", logging.module_overrides.len()),
            metric("Syslog", yes_no(logging.syslog)),
            metric(
                "Metric ifaces",
                inputs.snapshot.map(|s| s.network.len()).unwrap_or(0),
            ),
        ],
        vec![
            link("Log search", "/logs/search"),
            link("Live logs", "/logs/ws"),
            link("Metrics", "/metrics"),
        ],
    ));

    let password_rules = usize::from(admin_security.require_uppercase)
        + usize::from(admin_security.require_number)
        + usize::from(admin_security.require_special);
    cards.push(card(
        250,
        "admin-security",
        "Admin Security",
        "Authentication",
        "system",
        if password_rules == 0 || admin_security.max_login_attempts == 0 {
            "warning"
        } else {
            "ok"
        },
        if password_rules == 0 {
            "Basic password policy".to_string()
        } else {
            "Hardened login policy".to_string()
        },
        "JWT session lifetime, login lockout, and administrator password complexity policy"
            .to_string(),
        vec![
            metric(
                "Session",
                format!("{}m", admin_security.session_timeout_minutes),
            ),
            metric("Lockout attempts", admin_security.max_login_attempts),
            metric(
                "Lockout",
                format!("{}m", admin_security.lockout_duration_minutes),
            ),
            metric("Password rules", password_rules),
        ],
        vec![
            link("Admin security", "/admin/security"),
            link("Auth status", "/auth/status"),
        ],
    ));

    cards.sort_by_key(|card| card.order);
    cards
}

fn card(
    order: u16,
    id: &'static str,
    title: &'static str,
    module: &'static str,
    category: &'static str,
    status: &'static str,
    status_label: impl Into<String>,
    summary: impl Into<String>,
    metrics: Vec<DashboardCardMetric>,
    links: Vec<DashboardCardLink>,
) -> DashboardCard {
    DashboardCard {
        id,
        title,
        module,
        category,
        status,
        status_label: status_label.into(),
        summary: summary.into(),
        metrics,
        links,
        service_control: None,
        order,
    }
}

fn with_service_control(mut card: DashboardCard, service_id: &'static str) -> DashboardCard {
    card.service_control = Some(DashboardCardServiceControl {
        service_id,
        status_href: format!("/system/services/{service_id}"),
        actions: ["start", "stop", "restart"]
            .into_iter()
            .map(|action| DashboardCardServiceAction {
                id: action,
                label: match action {
                    "start" => "Start",
                    "stop" => "Stop",
                    "restart" => "Restart",
                    _ => action,
                },
                method: "POST",
                href: format!("/system/services/{service_id}/{action}"),
                variant: match action {
                    "start" => "primary",
                    "stop" => "danger",
                    "restart" => "neutral",
                    _ => "neutral",
                },
                requires_confirmation: action == "stop",
            })
            .collect(),
    });
    card
}

fn metric(label: &'static str, value: impl ToString) -> DashboardCardMetric {
    DashboardCardMetric {
        label,
        value: value.to_string(),
    }
}

fn link(label: &'static str, href: &'static str) -> DashboardCardLink {
    DashboardCardLink { label, href }
}

fn service_status(
    services: &HashMap<String, bool>,
    service: &str,
    enabled: bool,
    healthy_label: &'static str,
) -> (&'static str, String) {
    if !enabled {
        return ("disabled", "Disabled".to_string());
    }

    match services.get(service).copied() {
        Some(true) => ("ok", healthy_label.to_string()),
        Some(false) => ("warning", "Configured, service not healthy".to_string()),
        None => ("unknown", "Runtime state unknown".to_string()),
    }
}

fn resource_status(
    cpu_percent: f64,
    ram_percent: f64,
    disk_percent: f64,
) -> (&'static str, String) {
    let peak = cpu_percent.max(ram_percent).max(disk_percent);
    if peak >= 95.0 {
        ("critical", "Resource pressure critical".to_string())
    } else if peak >= 85.0 {
        ("warning", "Resource pressure elevated".to_string())
    } else {
        ("ok", "System resources healthy".to_string())
    }
}

fn nat_card(order: u16, nat: &NatConfig) -> DashboardCard {
    let status = match nat.outbound_mode {
        OutboundMode::Automatic | OutboundMode::Hybrid if nat.wan_interfaces.is_empty() => {
            "warning"
        }
        OutboundMode::Manual if nat.rules.is_empty() => "warning",
        _ => "ok",
    };
    let label = match nat.outbound_mode {
        OutboundMode::Automatic | OutboundMode::Hybrid if nat.wan_interfaces.is_empty() => {
            "No WAN interfaces selected"
        }
        OutboundMode::Manual if nat.rules.is_empty() => "Manual mode without rules",
        OutboundMode::Automatic => "Automatic outbound NAT",
        OutboundMode::Hybrid => "Hybrid outbound NAT",
        OutboundMode::Manual => "Manual outbound NAT",
    };

    card(
        order,
        "nat",
        "NAT",
        "Network Address Translation",
        "network",
        status,
        label,
        "Outbound NAT, port forwards, one-to-one translations, and NAT reflection",
        vec![
            metric("Mode", nat_mode_label(&nat.outbound_mode)),
            metric("WAN", nat.wan_interfaces.len()),
            metric("Rules", nat.rules.len()),
            metric("Reflection", yes_no(nat.nat_reflection)),
        ],
        vec![
            link("NAT config", "/nat/config"),
            link("NAT rules", "/nat/rules"),
            link("NAT interfaces", "/nat/interfaces"),
        ],
    )
}

fn nat_mode_label(mode: &OutboundMode) -> &'static str {
    match mode {
        OutboundMode::Automatic => "automatic",
        OutboundMode::Hybrid => "hybrid",
        OutboundMode::Manual => "manual",
    }
}

fn format_percent(value: f64) -> String {
    format!("{value:.0}%")
}

fn format_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    if days > 0 {
        return format!("{days}d");
    }
    let hours = seconds / 3_600;
    if hours > 0 {
        return format!("{hours}h");
    }
    let minutes = seconds / 60;
    format!("{minutes}m")
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}

fn enabled_word(value: bool) -> &'static str {
    if value {
        "enabled"
    } else {
        "disabled"
    }
}

fn empty_dash(value: String) -> String {
    if value.trim().is_empty() {
        "-".to_string()
    } else {
        value
    }
}

fn count_backup_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .map(looks_like_backup_file)
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

fn looks_like_backup_file(name: &str) -> bool {
    let has_backup_prefix = name.starts_with("dayshield-backup-")
        || name.starts_with("dayshield-") && name.contains("-backup-");
    has_backup_prefix && (name.ends_with(".tar") || name.ends_with(".tar.enc"))
}

fn default_dhcp_card_config() -> DhcpConfig {
    DhcpConfig {
        enabled: false,
        interface: String::new(),
        scopes: vec![],
    }
}

fn default_dhcp6_card_config() -> Dhcp6Config {
    Dhcp6Config {
        enabled: false,
        interface: String::new(),
        scopes: vec![],
    }
}

fn default_suricata_card_config() -> SuricataConfig {
    SuricataConfig {
        enabled: false,
        interfaces: vec![],
        mode: "ids".to_string(),
        home_nets: vec![],
        external_nets: vec![],
        rule_sources: vec![],
        eve_log_enabled: false,
        eve_log_path: "/var/log/suricata/eve.json".to_string(),
        stats_log_enabled: false,
        stats_log_path: "/var/log/suricata/stats.log".to_string(),
        stats_interval_seconds: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn test_cards() -> Vec<DashboardCard> {
        let cfg = SystemConfig::default();
        let services = HashMap::new();

        build_dashboard_cards(DashboardCardInputs {
            cfg: &cfg,
            services: &services,
            snapshot: None,
            disk_percent: 0.0,
            backup_schedule: BackupScheduleConfig::default(),
            backup_count: 0,
            installed_rulesets: &[],
            schedules: None,
            update_settings: crate::update::UpdateSettings::default(),
            active_crowdsec_decisions: 0,
            ai_threat_count: 0,
            ai_blocked_count: 0,
            honeypot_events_last_24h: 0,
            honeypot_unique_ips: 0,
        })
    }

    #[test]
    fn dashboard_cards_have_unique_ids_titles_and_links() {
        let cards = test_cards();

        let ids: HashSet<_> = cards.iter().map(|card| card.id).collect();
        assert_eq!(ids.len(), cards.len(), "dashboard card IDs must be unique");

        let titles: HashSet<_> = cards.iter().map(|card| card.title).collect();
        assert_eq!(
            titles.len(),
            cards.len(),
            "dashboard card titles must be unique"
        );

        for card in &cards {
            let hrefs: HashSet<_> = card.links.iter().map(|link| link.href).collect();
            assert_eq!(
                hrefs.len(),
                card.links.len(),
                "dashboard card {} has duplicate links",
                card.id
            );
        }
    }

    #[test]
    fn dashboard_cards_cover_current_backend_modules() {
        let cards = test_cards();
        let ids: HashSet<_> = cards.iter().map(|card| card.id).collect();
        let expected = [
            "system",
            "interfaces",
            "gateways",
            "firewall",
            "nat",
            "dns",
            "dns-over-tls",
            "dhcp",
            "wireguard",
            "suricata",
            "managed-rulesets",
            "crowdsec",
            "honeypots",
            "ai-threat-engine",
            "acme",
            "dynamic-dns",
            "cloudflared",
            "captive-portal",
            "ntp",
            "notifications",
            "backups",
            "updates",
            "system-schedules",
            "logs-metrics",
            "admin-security",
        ];

        assert_eq!(cards.len(), expected.len());
        for id in expected {
            assert!(ids.contains(id), "missing dashboard card: {id}");
        }
    }

    #[test]
    fn dashboard_cards_are_strictly_ordered() {
        let cards = test_cards();
        assert!(cards
            .windows(2)
            .all(|window| window[0].order < window[1].order));
    }

    #[test]
    fn dashboard_service_cards_expose_runtime_controls() {
        let cards = test_cards();
        let expected = [
            ("firewall", SVC_NFTABLES),
            ("dns", SVC_DNS),
            ("dns-over-tls", SVC_DNS),
            ("dhcp", SVC_DHCP),
            ("suricata", SVC_SURICATA),
            ("crowdsec", SVC_CROWDSEC),
            ("cloudflared", SVC_CLOUDFLARED),
            ("ntp", "ntp"),
        ];

        for (card_id, service_id) in expected {
            let card = cards
                .iter()
                .find(|card| card.id == card_id)
                .unwrap_or_else(|| panic!("missing dashboard card: {card_id}"));
            let control = card
                .service_control
                .as_ref()
                .unwrap_or_else(|| panic!("missing service control for {card_id}"));
            assert_eq!(control.service_id, service_id);
            assert_eq!(
                control.status_href,
                format!("/system/services/{service_id}")
            );
            assert_eq!(control.actions.len(), 3);
            assert!(control.actions.iter().any(|action| {
                action.id == "stop" && action.variant == "danger" && action.requires_confirmation
            }));
        }
    }

}

// ---------------------------------------------------------------------------
// GET /dashboard/system
// ---------------------------------------------------------------------------

/// Response for `GET /dashboard/system`.
#[derive(Serialize)]
pub struct DashboardSystemStatus {
    pub hostname: String,
    /// System uptime in seconds.
    pub uptime: u64,
    /// 1-minute, 5-minute, 15-minute load averages.
    pub loadavg: [f64; 3],
    /// CPU utilisation as a percentage (0–100).
    pub cpu_percent: f64,
    /// RAM utilisation as a percentage (0–100).
    pub ram_percent: f64,
    /// Root filesystem utilisation as a percentage (0–100).
    pub disk_percent: f64,
    /// CPU temperature in Celsius (`None` when unavailable).
    pub temperature: Option<f64>,
}

pub async fn get_system_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Pull the latest snapshot from the metrics buffer (non-blocking read).
    let snapshot = {
        let buf = state.metrics_buffer.read().await;
        buf.latest().cloned()
    };

    let (cpu_percent, ram_percent, loadavg, uptime, temperature) = match snapshot {
        Some(s) => (
            s.system.cpu_percent,
            s.system.ram_percent,
            [s.system.loadavg_1, s.system.loadavg_5, s.system.loadavg_15],
            s.system.uptime_seconds,
            if s.system.temperature_c > 0.0 {
                Some(s.system.temperature_c)
            } else {
                None
            },
        ),
        None => (0.0, 0.0, [0.0, 0.0, 0.0], 0, None),
    };

    let disk_percent = read_disk_percent("/").await;

    let hostname = state
        .config_store
        .load_system_settings()
        .map(|s| s.hostname)
        .unwrap_or_else(|_| "dayshield".into());

    Json(DashboardSystemStatus {
        hostname,
        uptime,
        loadavg,
        cpu_percent,
        ram_percent,
        disk_percent,
        temperature,
    })
}

/// Read root-filesystem usage percentage by calling `df -B1 <mount>`.
async fn read_disk_percent(mount: &str) -> f64 {
    // `df -B1 <path>` output line 2: Filesystem 1B-blocks Used Available Use% Mounted
    let output = tokio::process::Command::new("df")
        .args(["-B1", mount])
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            // Skip header line, parse second line.
            if let Some(line) = text.lines().nth(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Use% is at index 4 (e.g. "42%"), or compute from blocks.
                if parts.len() >= 5 {
                    return parts[4].trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
                }
            }
            0.0
        }
        _ => 0.0,
    }
}

// ---------------------------------------------------------------------------
// GET /dashboard/network
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct LanIface {
    pub name: String,
    pub description: Option<String>,
    pub ip: Option<String>,
    pub ipv6: Option<String>,
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct NetworkStatus {
    pub wan_iface: String,
    pub wan_iface_description: Option<String>,
    pub wan_ip: Option<String>,
    pub wan_ipv6: Option<String>,
    /// `"up"`, `"down"`, or `"unknown"`
    pub gateway_status: &'static str,
    /// WAN receive throughput in bytes/second (from last metrics snapshot).
    pub wan_rx_bps: f64,
    /// WAN transmit throughput in bytes/second.
    pub wan_tx_bps: f64,
    pub lan_ifaces: Vec<LanIface>,
}

pub async fn get_network_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Gather configured interfaces.
    let configured = state.interfaces.read().await.clone();

    // Gather latest network throughput from metrics.
    let net_metrics = {
        let buf = state.metrics_buffer.read().await;
        buf.latest().map(|s| s.network.clone()).unwrap_or_default()
    };

    // Determine the WAN uplink using explicit WAN configuration when available.
    let wan = configured
        .iter()
        .find(|i| i.wan_mode.is_some() || i.gateway.is_some())
        .or_else(|| configured.iter().find(|i| i.enabled));
    let wan_name = wan.map(|i| i.name.clone()).unwrap_or_else(|| "eth0".into());
    let wan_description = wan.and_then(|i| i.description.clone());

    // Resolve live kernel addresses (needed for DHCP interfaces whose config
    // addresses vec is intentionally empty).
    let kernel_ifaces = list_kernel_interfaces().await.unwrap_or_default();
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map(|settings| settings.ipv6_enabled)
        .unwrap_or(false);
    let kernel_ip_for = |name: &str, ipv6: bool| -> Option<String> {
        kernel_ifaces
            .iter()
            .find(|ki| ki.name == name)
            .and_then(|ki| {
                ki.addresses.iter().find(|a| {
                    if ipv6 {
                        a.contains(':')
                    } else {
                        a.contains('.')
                    }
                })
            })
            // Strip the CIDR prefix length (e.g. "192.168.1.1/24" → "192.168.1.1").
            .map(|cidr| cidr.split('/').next().unwrap_or(cidr).to_string())
    };
    let wan_ip = wan
        .and_then(|i| i.addresses.iter().find(|cidr| cidr.contains('.')))
        .map(|cidr| cidr.split('/').next().unwrap_or(cidr).to_string())
        .or_else(|| kernel_ip_for(&wan_name, false));
    let wan_ipv6 = if ipv6_enabled {
        wan.and_then(|i| i.addresses.iter().find(|cidr| cidr.contains(':')))
            .map(|cidr| cidr.split('/').next().unwrap_or(cidr).to_string())
            .or_else(|| kernel_ip_for(&wan_name, true))
    } else {
        None
    };

    let wan_metrics = net_metrics.iter().find(|m| m.name == wan_name);
    let wan_rx_bps = wan_metrics.map(|m| m.rx_bps as f64).unwrap_or(0.0);
    let wan_tx_bps = wan_metrics.map(|m| m.tx_bps as f64).unwrap_or(0.0);

    // Gateway reachability: try to read the default route from /proc/net/route.
    let gateway_status = gateway_reachable().await;

    let lan_ifaces = configured
        .iter()
        .filter(|i| i.name != wan_name)
        .map(|i| LanIface {
            name: i.name.clone(),
            description: i.description.clone(),
            ip: i
                .addresses
                .iter()
                .find(|cidr| cidr.contains('.'))
                .map(|cidr| cidr.split('/').next().unwrap_or(cidr).to_string())
                .or_else(|| kernel_ip_for(&i.name, false)),
            ipv6: if ipv6_enabled {
                i.addresses
                    .iter()
                    .find(|cidr| cidr.contains(':'))
                    .map(|cidr| cidr.split('/').next().unwrap_or(cidr).to_string())
                    .or_else(|| kernel_ip_for(&i.name, true))
            } else {
                None
            },
            enabled: i.enabled,
        })
        .collect();

    Json(NetworkStatus {
        wan_iface: wan_name,
        wan_iface_description: wan_description,
        wan_ip,
        wan_ipv6,
        gateway_status,
        wan_rx_bps,
        wan_tx_bps,
        lan_ifaces,
    })
}

/// Returns `"up"` when a default route exists in `/proc/net/route`, else `"down"`.
async fn gateway_reachable() -> &'static str {
    match tokio::fs::read_to_string("/proc/net/route").await {
        Ok(content) => {
            // Each line after the header: Iface Destination Gateway ...
            // A destination of 00000000 is the default route.
            let has_default = content.lines().skip(1).any(|line| {
                let mut cols = line.split_whitespace();
                cols.next(); // iface
                cols.next().map(|dest| dest == "00000000").unwrap_or(false)
            });
            if has_default {
                "up"
            } else {
                "down"
            }
        }
        Err(_) => "unknown",
    }
}

// ---------------------------------------------------------------------------
// GET /dashboard/security
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SecurityStatus {
    pub firewall_rule_count: usize,
    pub firewall_state_count: u64,
    pub suricata_alert_rate: f64,
    pub crowdsec_active_decisions: usize,
    pub honeypot_events_last_24h: usize,
    pub honeypot_unique_ips: usize,
}

pub async fn get_security_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let firewall_rule_count = state.firewall_rules.read().await.len();
    let crowdsec_active_decisions = state.crowdsec_decisions.read().await.len();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let honeypot_events_last_24h = state
        .honeypot_runtime
        .count_events_since(now.saturating_sub(86_400))
        .unwrap_or(0);
    let honeypot_unique_ips = state
        .honeypot_runtime
        .source_ips(1000)
        .map(|ips| ips.len())
        .unwrap_or(0);

    let (firewall_state_count, suricata_alert_rate) = {
        let buf = state.metrics_buffer.read().await;
        let snap = buf.latest();
        (
            snap.map(|s| s.firewall.state_count).unwrap_or(0),
            snap.map(|s| s.suricata.alerts_last_minute as f64 / 60.0)
                .unwrap_or(0.0),
        )
    };

    Json(SecurityStatus {
        firewall_rule_count,
        firewall_state_count,
        suricata_alert_rate,
        crowdsec_active_decisions,
        honeypot_events_last_24h,
        honeypot_unique_ips,
    })
}

// ---------------------------------------------------------------------------
// GET /dashboard/acme
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct AcmeStatus {
    pub domains: Vec<String>,
    pub cert_exists: bool,
    pub needs_renewal: bool,
    /// Days until primary certificate expires; `0` when no cert exists.
    pub expires_in_days: i64,
    pub next_renewal: Option<String>,
}

pub async fn get_acme_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let acme_cfg = state.config_store.load_acme_config().ok().flatten();

    let (domains, cert_exists, needs_renewal, expires_in_days, next_renewal) = match acme_cfg {
        Some(cfg) if cfg.enabled => {
            let domains = cfg.domains.clone();
            let primary = domains.first().cloned();
            let engine = AcmeEngine::new(cfg.clone());

            let (cert_exists, needs_renewal, expires_in_days) =
                if let Some(primary_domain) = &primary {
                    let cert_path = engine.cert_path(primary_domain);
                    let exists = cert_path.exists();
                    let renewal_check = engine.renewal_check().await.unwrap_or(true);
                    let days = if exists {
                        cert_expiry_days(cert_path.to_str().unwrap_or_default())
                            .await
                            .unwrap_or(0)
                    } else {
                        0
                    };
                    (exists, !exists || renewal_check, days)
                } else {
                    (false, false, 0)
                };

            let next = cfg
                .domains
                .first()
                .map(|_| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let next_secs = now + cfg.renew_interval_hours * 3600;
                    chrono::DateTime::from_timestamp(next_secs as i64, 0).map(|dt| dt.to_rfc3339())
                })
                .flatten();

            (domains, cert_exists, needs_renewal, expires_in_days, next)
        }
        _ => (vec![], false, false, 0, None),
    };

    Json(AcmeStatus {
        domains,
        cert_exists,
        needs_renewal,
        expires_in_days,
        next_renewal,
    })
}

/// Read the expiry of a PEM certificate file and return days remaining.
async fn cert_expiry_days(path: &str) -> Option<i64> {
    let output = tokio::process::Command::new("openssl")
        .args(["x509", "-noout", "-enddate", "-in", path])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // Output: "notAfter=May 28 12:00:00 2026 GMT"
    let text = String::from_utf8_lossy(&output.stdout);
    let date_str = text.trim().strip_prefix("notAfter=")?;

    // Parse with chrono; openssl uses a non-ISO format.
    let dt =
        chrono::DateTime::parse_from_str(&format!("{date_str} +0000"), "%b %e %H:%M:%S %Y %Z %z")
            .ok()?;

    let now = chrono::Utc::now();
    Some(dt.signed_duration_since(now).num_days())
}
