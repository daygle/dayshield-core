use std::{
    collections::HashMap,
    net::IpAddr,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    ai_model::AiModel,
    config::models::{
        Action, AiEngineConfig, FirewallDirection, FirewallRule, NotifyCategory,
    },
    engine::nftables::apply_rules_with_captive,
    notify::model::NotifyEvent,
    state::AppState,
};

const THREAT_EVENTS_TREE: &str = "threat_events";
const THREAT_EVENTS_BY_ID_TREE: &str = "threat_events_by_id";
const MAINTENANCE_INTERVAL_SECONDS: u64 = 15;
const AI_BLOCK_RULE_PRIORITY: i32 = -32000;
const ESCALATE_EVENT_COUNT: usize = 3;
const QUARANTINE_EVENT_COUNT: usize = 5;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowMetadata {
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub event_source: String,
    pub action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatEvent {
    pub id: String,
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub event_source: String,
    pub action: Option<String>,
    pub signature: Option<String>,
    pub alert_severity: Option<u8>,
    pub risk_score: f64,
    pub reasons: Vec<String>,
    pub blocked: bool,
    pub block_expires_at: Option<u64>,
    pub escalated: bool,
    pub quarantine: bool,
    pub manually_unblocked: bool,
    pub label: Option<f64>,
    pub feedback: Option<String>,
    pub feedback_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedEntry {
    pub ip: String,
    pub added_at: u64,
    pub expires_at: Option<u64>,
    pub quarantine: bool,
}

#[derive(Debug, Clone)]
struct ActiveBlock {
    ip: IpAddr,
    added_at: u64,
    expires_at: Option<u64>,
    quarantine: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum FeedbackKind {
    FalsePositive,
    ConfirmedMalicious,
}

impl FeedbackKind {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "false_positive" => Some(Self::FalsePositive),
            "confirmed_malicious" => Some(Self::ConfirmedMalicious),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            FeedbackKind::FalsePositive => "false_positive",
            FeedbackKind::ConfirmedMalicious => "confirmed_malicious",
        }
    }

    fn label(self) -> f64 {
        match self {
            FeedbackKind::FalsePositive => 0.0,
            FeedbackKind::ConfirmedMalicious => 1.0,
        }
    }
}

#[derive(Clone)]
pub struct AiRuntime {
    store: Arc<ThreatEventStore>,
    active_blocks: Arc<Mutex<HashMap<IpAddr, ActiveBlock>>>,
    maintenance_started: Arc<AtomicBool>,
    model: Arc<Mutex<AiModel>>,
}

impl AiRuntime {
    pub fn new(config_dir: &Path, model_config: AiEngineConfig) -> Self {
        let primary_path = config_dir.join("ai_engine").join("threat_events.db");
        let store = ThreatEventStore::open(&primary_path).unwrap_or_else(|e| {
            warn!(error = %e, path = %primary_path.display(), "ai_engine: falling back to temporary event store");
            ThreatEventStore::temporary().expect("failed to create temporary threat event store")
        });

        Self {
            store: Arc::new(store),
            active_blocks: Arc::new(Mutex::new(HashMap::new())),
            maintenance_started: Arc::new(AtomicBool::new(false)),
            model: Arc::new(Mutex::new(AiModel::new(config_dir, &model_config))),
        }
    }

    pub fn start_background_tasks(&self, state: Arc<AppState>) {
        if self
            .maintenance_started
            .swap(true, Ordering::SeqCst)
        {
            return;
        }

        let this = self.clone();
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(MAINTENANCE_INTERVAL_SECONDS));
            loop {
                ticker.tick().await;
                if let Err(e) = this.expire_blocks_and_reconcile(&state_clone).await {
                    warn!(error = %e, "ai_engine: failed to reconcile expiring blocks");
                }
            }
        });

        let this = self.clone();
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = this.start_suricata_scoring(state_clone).await {
                warn!(error = %e, "ai_engine: suricata scoring task failed");
            }
        });

        let this = self.clone();
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = this.start_firewall_scoring(state_clone).await {
                warn!(error = %e, "ai_engine: firewall scoring task failed");
            }
        });
    }

    async fn start_firewall_scoring(&self, state: Arc<AppState>) -> Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::logs::LogEvent>(256);
        tokio::spawn(async move {
            crate::logs::firewall::stream_firewall(tx).await;
        });

        while let Some(event) = rx.recv().await {
            if let Err(e) = self.handle_firewall_event(&state, event).await {
                warn!(error = %e, "ai_engine: failed to process firewall event");
            }
        }

        Ok(())
    }

    async fn handle_firewall_event(
        &self,
        state: &Arc<AppState>,
        event: crate::logs::LogEvent,
    ) -> Result<()> {
        let (timestamp, action, src_ip, dst_ip, protocol, src_port, dst_port, iface) = match event {
            crate::logs::LogEvent::FirewallEvent {
                timestamp,
                action,
                src_ip,
                dest_ip,
                proto,
                sport,
                dport,
                iface,
            } => (timestamp, action, src_ip, dest_ip, proto, sport, dport, iface),
            _ => return Ok(()),
        };

        if src_ip.is_empty() || dst_ip.is_empty() {
            return Ok(());
        }

        let policy = state.config_store.load_ai_engine_config().unwrap_or_default();
        if !policy.enabled {
            return Ok(());
        }

        let history = self.gather_history_features(state, &src_ip, policy.escalation_window_seconds).await?;
        let (risk_score, reasons) = self
            .model
            .lock()
            .await
            .predict_firewall_event(
                &action,
                &protocol,
                &src_ip,
                &dst_ip,
                Some(src_port).filter(|p| *p != 0),
                Some(dst_port).filter(|p| *p != 0),
                &iface,
                &history,
            )
            .await?;

        if risk_score <= 0.0 {
            return Ok(());
        }

        let flow = FlowMetadata {
            timestamp: Self::parse_suricata_timestamp(&timestamp).unwrap_or_else(now_unix_secs),
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port: Some(src_port).filter(|p| *p != 0),
            dst_port: Some(dst_port).filter(|p| *p != 0),
            protocol: protocol.clone(),
            event_source: "firewall".to_string(),
            action: Some(action.clone()),
        };

        self.submit_risk_assessment(
            state,
            flow,
            risk_score,
            reasons,
            None,
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn submit_risk_assessment(
        &self,
        state: &Arc<AppState>,
        flow: FlowMetadata,
        risk_score: f64,
        reasons: Vec<String>,
        signature: Option<String>,
        alert_severity: Option<u8>,
    ) -> Result<ThreatEvent> {
        let policy = state
            .config_store
            .load_ai_engine_config()
            .unwrap_or_default();

        let mut blocked = false;
        let mut block_expires_at = None;
        let mut escalated = false;
        let mut quarantine = false;

        if policy.enabled && risk_score >= policy.risk_score_block_threshold {
            let src_ip = flow.src_ip.parse::<IpAddr>().ok();
            if let Some(ip) = src_ip {
                let high_risk_events = self
                    .store
                    .count_recent_high_risk_events(
                        &flow.src_ip,
                        now_unix_secs().saturating_sub(policy.escalation_window_seconds),
                        policy.risk_score_block_threshold,
                    )?;

                let (duration, did_escalate, is_quarantine) =
                    compute_escalated_block(high_risk_events + 1, &policy);

                escalated = did_escalate;
                quarantine = is_quarantine;

                if policy.automatic_blocking {
                    blocked = true;
                    block_expires_at = duration.map(|d| now_unix_secs().saturating_add(d));
                    let mut blocks = self.active_blocks.lock().await;
                    blocks.insert(
                        ip,
                        ActiveBlock {
                            ip,
                            added_at: now_unix_secs(),
                            expires_at: block_expires_at,
                            quarantine,
                        },
                    );
                    drop(blocks);
                    self.reconcile_block_rules(state).await?;
                }
            }
        }

        let event = ThreatEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: flow.timestamp,
            src_ip: flow.src_ip,
            dst_ip: flow.dst_ip,
            src_port: flow.src_port,
            dst_port: flow.dst_port,
            protocol: flow.protocol,
            event_source: flow.event_source,
            action: flow.action,
            signature,
            alert_severity,
            risk_score,
            reasons,
            blocked,
            block_expires_at,
            escalated,
            quarantine,
            manually_unblocked: false,
            label: None,
            feedback: None,
            feedback_at: None,
        };

        self.store.insert_event(&event)?;

        if event.blocked && (event.escalated || event.quarantine) {
            let body = format!(
                "AI flagged high-risk traffic from {} to {} (risk_score={:.3}, escalated={}, quarantine={})",
                event.src_ip, event.dst_ip, event.risk_score, event.escalated, event.quarantine
            );
            let _ = state
                .notify_queue
                .enqueue(NotifyEvent {
                    category: NotifyCategory::System,
                    subject: "[AI] Threat escalation".to_string(),
                    body,
                    timestamp: now_unix_secs(),
                })
                .await;
        }

        Ok(event)
    }

    pub fn recent_threat_events(&self, limit: usize) -> Result<Vec<ThreatEvent>> {
        self.store.list_recent(limit)
    }

    pub fn get_threat_event(&self, id: &str) -> Result<Option<ThreatEvent>> {
        self.store.get_by_id(id)
    }

    pub async fn update_model_config(&self, config: &AiEngineConfig) -> Result<()> {
        let mut model = self.model.lock().await;
        model.apply_config(config)
    }

    pub async fn unblock_ip(&self, state: &Arc<AppState>, ip: IpAddr) -> Result<bool> {
        let removed = {
            let mut blocks = self.active_blocks.lock().await;
            blocks.remove(&ip).is_some()
        };

        if removed {
            self.reconcile_block_rules(state).await?;

            let override_event = ThreatEvent {
                id: Uuid::new_v4().to_string(),
                timestamp: now_unix_secs(),
                src_ip: ip.to_string(),
                dst_ip: "manual_override".to_string(),
                src_port: None,
                dst_port: None,
                protocol: "manual".to_string(),
                event_source: "manual".to_string(),
                action: None,
                signature: None,
                alert_severity: None,
                risk_score: 0.0,
                reasons: vec!["manual unblock override".to_string()],
                blocked: false,
                block_expires_at: None,
                escalated: false,
                quarantine: false,
                manually_unblocked: true,
                label: Some(0.0),
                feedback: Some("manual_unblock".to_string()),
                feedback_at: Some(now_unix_secs()),
            };
            self.store.insert_event(&override_event)?;
        }

        Ok(removed)
    }

    pub async fn list_blocked(&self) -> Vec<BlockedEntry> {
        let now = now_unix_secs();
        let blocks = self.active_blocks.lock().await;
        blocks
            .values()
            .filter(|b| b.expires_at.map(|e| e > now).unwrap_or(true))
            .map(|b| BlockedEntry {
                ip: b.ip.to_string(),
                added_at: b.added_at,
                expires_at: b.expires_at,
                quarantine: b.quarantine,
            })
            .collect()
    }

    async fn expire_blocks_and_reconcile(&self, state: &Arc<AppState>) -> Result<()> {
        let now = now_unix_secs();
        let changed = {
            let mut blocks = self.active_blocks.lock().await;
            let before = blocks.len();
            blocks.retain(|_, block| block.expires_at.map(|exp| exp > now).unwrap_or(true));
            before != blocks.len()
        };

        if changed {
            self.reconcile_block_rules(state).await?;
        }

        Ok(())
    }

    async fn start_suricata_scoring(&self, state: Arc<AppState>) -> Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::logs::LogEvent>(256);
        tokio::spawn(async move {
            crate::logs::suricata::stream_suricata(tx).await;
        });

        while let Some(event) = rx.recv().await {
            if let Err(e) = self.handle_suricata_event(&state, event).await {
                warn!(error = %e, "ai_engine: failed to process suricata alert");
            }
        }

        Ok(())
    }

    async fn handle_suricata_event(
        &self,
        state: &Arc<AppState>,
        event: crate::logs::LogEvent,
    ) -> Result<()> {
        let (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, signature, severity, category) = match event {
            crate::logs::LogEvent::SuricataAlert {
                timestamp,
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                proto,
                signature,
                severity,
                category,
            } => (
                timestamp,
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                proto,
                signature,
                severity,
                category,
            ),
            _ => return Ok(()),
        };

        if src_ip.is_empty() || dst_ip.is_empty() {
            return Ok(());
        }

        let policy = state.config_store.load_ai_engine_config().unwrap_or_default();
        if !policy.enabled {
            return Ok(());
        }

        let history = self.gather_history_features(state, &src_ip, policy.escalation_window_seconds).await?;
        let (risk_score, reasons) = self
            .model
            .lock()
            .await
            .predict_suricata_alert(
                &signature,
                severity,
                category.as_deref(),
                &protocol,
                &src_ip,
                &dst_ip,
                src_port,
                dst_port,
                &history,
            )
            .await?;

        if risk_score <= 0.0 {
            return Ok(());
        }

        let flow = FlowMetadata {
            timestamp: Self::parse_suricata_timestamp(&timestamp).unwrap_or_else(now_unix_secs),
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol: protocol.clone(),
            event_source: "suricata".to_string(),
            action: None,
        };

        self.submit_risk_assessment(
            state,
            flow,
            risk_score,
            reasons,
            Some(signature),
            Some(severity),
        )
        .await?;
        Ok(())
    }

    pub async fn apply_feedback(
        &self,
        state: &Arc<AppState>,
        id: &str,
        feedback: FeedbackKind,
    ) -> Result<Option<ThreatEvent>> {
        let mut event = match self.get_threat_event(id)? {
            Some(event) => event,
            None => return Ok(None),
        };

        event.feedback = Some(feedback.as_str().to_string());
        event.feedback_at = Some(now_unix_secs());
        event.label = Some(feedback.label());
        self.store.insert_event(&event)?;
        self.retrain_model_from_history(state).await?;
        Ok(Some(event))
    }

    async fn gather_history_features(
        &self,
        state: &Arc<AppState>,
        src_ip: &str,
        window_seconds: u64,
    ) -> Result<crate::ai_model::AiContextFeatures> {
        let min_timestamp = now_unix_secs().saturating_sub(window_seconds);
        let recent_events = self.store.list_recent(2000)?;

        let mut high_risk_count = 0.0;
        let mut feedback_malicious = 0.0;
        let mut feedback_false_positive = 0.0;
        let mut manual_unblock = 0.0;
        let mut firewall_drops = 0.0;
        let mut firewall_accepts = 0.0;
        let mut scan_events = 0.0;

        for event in recent_events.into_iter() {
            if event.src_ip != src_ip || event.timestamp < min_timestamp {
                continue;
            }
            if event.risk_score >= 0.8 {
                high_risk_count += 1.0;
            }
            if event.feedback.as_deref() == Some("confirmed_malicious") {
                feedback_malicious += 1.0;
            }
            if event.feedback.as_deref() == Some("false_positive") {
                feedback_false_positive += 1.0;
            }
            if event.manually_unblocked {
                manual_unblock += 1.0;
            }
            if event.event_source == "firewall" {
                if event.action.as_deref().map_or(false, |a| a.eq_ignore_ascii_case("drop")) {
                    firewall_drops += 1.0;
                }
                if event.action.as_deref().map_or(false, |a| a.eq_ignore_ascii_case("accept")) {
                    firewall_accepts += 1.0;
                }
            }
            if Self::is_scan_like_event(&event) {
                scan_events += 1.0;
            }
        }

        let crowdsec_decisions = {
            let decisions = state.crowdsec_decisions.read().await;
            decisions
                .iter()
                .filter(|decision| decision.value.contains(src_ip))
                .count() as f64
        };

        let dns_blocklist_configured = state
            .config_store
            .load()
            .map(|cfg| {
                cfg.dns
                    .as_ref()
                    .map(|dns| dns.interface_blocklists.iter().flat_map(|group| group.blocklists.iter()).count())
                    .unwrap_or(0)
            })
            .unwrap_or(0)
            .min(1) as f64;

        Ok(crate::ai_model::AiContextFeatures {
            recent_high_risk_count: high_risk_count,
            recent_feedback_malicious: feedback_malicious,
            recent_feedback_false_positive: feedback_false_positive,
            recent_manual_unblock: manual_unblock,
            recent_firewall_drops: firewall_drops,
            recent_firewall_accepts: firewall_accepts,
            recent_scan_events: scan_events,
            crowdsec_decisions,
            dns_blocklist_configured,
        })
    }

    async fn retrain_model_from_history(&self, state: &Arc<AppState>) -> Result<()> {
        let mut events = self.store.list_recent(2000)?;
        events.sort_by_key(|event| event.timestamp);

        let mut samples = Vec::new();

        for event in events.iter().filter(|event| event.label.is_some()) {
            let label = event.label.unwrap();
            let history = self.history_features_for_event(state, event, &events).await?;
            let features = AiModel::build_feature_vector(
                event.signature.as_deref(),
                event.alert_severity,
                None,
                &event.protocol,
                &event.src_ip,
                &event.dst_ip,
                event.src_port,
                event.dst_port,
                event.action.as_deref(),
                None,
                &history,
            ).0;
            samples.push((features, label));
        }

        let mut model = self.model.lock().await;
        model.retrain_from_feedback(&samples)?;

        Ok(())
    }

    async fn history_features_for_event(
        &self,
        state: &Arc<AppState>,
        target: &ThreatEvent,
        events: &[ThreatEvent],
    ) -> Result<crate::ai_model::AiContextFeatures> {
        let window_seconds = 3600;
        let min_timestamp = target.timestamp.saturating_sub(window_seconds);

        let mut high_risk_count = 0.0;
        let mut feedback_malicious = 0.0;
        let mut feedback_false_positive = 0.0;
        let mut manual_unblock = 0.0;
        let mut firewall_drops = 0.0;
        let mut firewall_accepts = 0.0;
        let mut scan_events = 0.0;

        for event in events.iter() {
            if event.timestamp >= target.timestamp {
                break;
            }
            if event.src_ip != target.src_ip || event.timestamp < min_timestamp {
                continue;
            }
            if event.risk_score >= 0.8 {
                high_risk_count += 1.0;
            }
            if event.feedback.as_deref() == Some("confirmed_malicious") {
                feedback_malicious += 1.0;
            }
            if event.feedback.as_deref() == Some("false_positive") {
                feedback_false_positive += 1.0;
            }
            if event.manually_unblocked {
                manual_unblock += 1.0;
            }
            if event.event_source == "firewall" {
                if event.action.as_deref().map_or(false, |a| a.eq_ignore_ascii_case("drop")) {
                    firewall_drops += 1.0;
                }
                if event.action.as_deref().map_or(false, |a| a.eq_ignore_ascii_case("accept")) {
                    firewall_accepts += 1.0;
                }
            }
            if Self::is_scan_like_event(event) {
                scan_events += 1.0;
            }
        }

        let crowdsec_decisions = {
            let decisions = state.crowdsec_decisions.read().await;
            decisions
                .iter()
                .filter(|decision| decision.value.contains(&target.src_ip))
                .count() as f64
        };

        let dns_blocklist_configured = state
            .config_store
            .load()
            .map(|cfg| {
                cfg.dns
                    .as_ref()
                    .map(|dns| dns.interface_blocklists.iter().flat_map(|group| group.blocklists.iter()).count())
                    .unwrap_or(0)
            })
            .unwrap_or(0)
            .min(1) as f64;

        Ok(crate::ai_model::AiContextFeatures {
            recent_high_risk_count: high_risk_count,
            recent_feedback_malicious: feedback_malicious,
            recent_feedback_false_positive: feedback_false_positive,
            recent_manual_unblock: manual_unblock,
            recent_firewall_drops: firewall_drops,
            recent_firewall_accepts: firewall_accepts,
            recent_scan_events: scan_events,
            crowdsec_decisions,
            dns_blocklist_configured,
        })
    }

    fn is_scan_like_event(event: &ThreatEvent) -> bool {
        let lower = event
            .signature
            .as_deref()
            .unwrap_or_default()
            .to_lowercase();
        let scan_terms = ["scan", "recon", "port sweep", "nmap", "masscan"];
        scan_terms.iter().any(|term| lower.contains(term))
    }

    fn parse_suricata_timestamp(timestamp: &str) -> Option<u64> {
        chrono::DateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.f%z")
            .map(|dt| dt.timestamp().try_into().unwrap_or_default())
            .ok()
    }

    async fn reconcile_block_rules(&self, state: &Arc<AppState>) -> Result<()> {
        let config = state.config_store.load()?;
        let mut rules = config.firewall_rules.clone();

        for block in self.list_blocked().await {
            let source = match block.ip.parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => format!("{}/32", block.ip),
                Ok(IpAddr::V6(_)) => format!("{}/128", block.ip),
                Err(_) => continue,
            };

            rules.push(FirewallRule {
                id: Uuid::new_v4(),
                description: Some(if block.quarantine {
                    format!("AI quarantine block: {}", block.ip)
                } else {
                    format!("AI temporary block: {}", block.ip)
                }),
                priority: AI_BLOCK_RULE_PRIORITY,
                source: Some(source),
                destination: None,
                protocol: None,
                source_port: None,
                destination_port: None,
                action: Action::Drop,
                direction: FirewallDirection::Input,
                interface: None,
                log: true,
                enabled: true,
                schedule: None,
                ip_family: if block.ip.contains(':') {
                    crate::config::models::FirewallAddressFamily::Ipv6
                } else {
                    crate::config::models::FirewallAddressFamily::Ipv4
                },
                state_limits: crate::config::models::FirewallStateLimits::default(),
            });
        }

        let captive_sessions = if let Some(portal) = config.captive_portal.as_ref() {
            let sessions = crate::captive_portal::load_sessions(&state.config_store)
                .unwrap_or_default();
            crate::captive_portal::active_sessions(portal, &sessions)
        } else {
            vec![]
        };

        apply_rules_with_captive(
            &rules,
            config.nat.as_ref(),
            &config.firewall_aliases,
            config.firewall_settings.as_ref(),
            config
                .system_settings
                .as_ref()
                .map(|settings| settings.ipv6_enabled)
                .unwrap_or(false),
            config.captive_portal.as_ref(),
            &captive_sessions,
            &config.interfaces,
        )
        .await
        .context("failed to apply AI-enforced temporary block rules")?;

        Ok(())
    }
}

pub async fn start_background_tasks(state: Arc<AppState>) {
    state
        .ai_runtime
        .start_background_tasks(Arc::clone(&state));
}

pub async fn submit_flow_risk(
    state: &Arc<AppState>,
    flow: FlowMetadata,
    risk_score: f64,
    reasons: Vec<String>,
) -> Result<ThreatEvent> {
    state
        .ai_runtime
        .submit_risk_assessment(state, flow, risk_score, reasons, None, None)
        .await
}

pub fn get_recent_threat_events(state: &Arc<AppState>, limit: usize) -> Result<Vec<ThreatEvent>> {
    state.ai_runtime.recent_threat_events(limit)
}

pub fn get_threat_event_by_id(state: &Arc<AppState>, id: &str) -> Result<Option<ThreatEvent>> {
    state.ai_runtime.get_threat_event(id)
}

pub async fn unblock_ip(state: &Arc<AppState>, ip: IpAddr) -> Result<bool> {
    state.ai_runtime.unblock_ip(state, ip).await
}

pub fn compute_escalated_block(
    events_in_window: usize,
    policy: &AiEngineConfig,
) -> (Option<u64>, bool, bool) {
    let base = policy.block_duration_seconds;

    if events_in_window >= QUARANTINE_EVENT_COUNT {
        return (None, true, true);
    }

    if events_in_window >= ESCALATE_EVENT_COUNT {
        if base == 0 {
            return (None, true, false);
        }
        return (Some(base.saturating_mul(6)), true, false);
    }

    if base == 0 {
        (None, false, false)
    } else {
        (Some(base), false, false)
    }
}

struct ThreatEventStore {
    events: sled::Tree,
    by_id: sled::Tree,
}

impl ThreatEventStore {
    fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let db = sled::open(path)
            .with_context(|| format!("failed to open sled db at {}", path.display()))?;

        Ok(Self {
            events: db.open_tree(THREAT_EVENTS_TREE)?,
            by_id: db.open_tree(THREAT_EVENTS_BY_ID_TREE)?,
        })
    }

    fn temporary() -> Result<Self> {
        let db = sled::Config::new().temporary(true).open()?;
        Ok(Self {
            events: db.open_tree(THREAT_EVENTS_TREE)?,
            by_id: db.open_tree(THREAT_EVENTS_BY_ID_TREE)?,
        })
    }

    fn insert_event(&self, event: &ThreatEvent) -> Result<()> {
        let key = format!("{:020}-{}", event.timestamp, event.id);
        let bytes = serde_json::to_vec(event)?;
        self.events.insert(key.as_bytes(), bytes)?;
        self.by_id.insert(event.id.as_bytes(), key.as_bytes())?;
        self.events.flush()?;
        self.by_id.flush()?;
        Ok(())
    }

    fn list_recent(&self, limit: usize) -> Result<Vec<ThreatEvent>> {
        let mut out = Vec::new();
        for item in self.events.iter().rev().take(limit) {
            let (_k, v) = item?;
            let evt = serde_json::from_slice::<ThreatEvent>(&v)?;
            out.push(evt);
        }
        Ok(out)
    }

    fn get_by_id(&self, id: &str) -> Result<Option<ThreatEvent>> {
        let Some(event_key) = self.by_id.get(id.as_bytes())? else {
            return Ok(None);
        };
        let Some(raw) = self.events.get(event_key)? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice::<ThreatEvent>(&raw)?))
    }

    fn count_recent_high_risk_events(
        &self,
        src_ip: &str,
        min_timestamp: u64,
        threshold: f64,
    ) -> Result<usize> {
        let mut count = 0usize;
        for item in self.events.iter().rev() {
            let (_k, v) = item?;
            let evt = serde_json::from_slice::<ThreatEvent>(&v)?;
            if evt.timestamp < min_timestamp {
                break;
            }
            if evt.src_ip == src_ip && evt.risk_score >= threshold {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy(block_duration_seconds: u64) -> AiEngineConfig {
        let mut cfg = AiEngineConfig::default();
        cfg.enabled = true;
        cfg.automatic_blocking = true;
        cfg.risk_score_block_threshold = 0.8;
        cfg.escalation_window_seconds = 300;
        cfg.block_duration_seconds = block_duration_seconds;
        cfg
    }

    #[test]
    fn escalation_is_deterministic() {
        let policy = test_policy(60);

        assert_eq!(compute_escalated_block(1, &policy), (Some(60), false, false));
        assert_eq!(compute_escalated_block(3, &policy), (Some(360), true, false));
        assert_eq!(compute_escalated_block(5, &policy), (None, true, true));
    }

    #[test]
    fn escalation_with_zero_base_duration_is_permanent_when_triggered() {
        let policy = test_policy(0);

        assert_eq!(compute_escalated_block(1, &policy), (None, false, false));
        assert_eq!(compute_escalated_block(3, &policy), (None, true, false));
        assert_eq!(compute_escalated_block(5, &policy), (None, true, true));
    }

    #[test]
    fn threat_store_insert_and_get_roundtrip() {
        let store = ThreatEventStore::temporary().unwrap();
        let event = ThreatEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: 1_700_000_000,
            src_ip: "10.0.0.2".to_string(),
            dst_ip: "8.8.8.8".to_string(),
            src_port: Some(12345),
            dst_port: Some(53),
            protocol: "udp".to_string(),
            event_source: "test".to_string(),
            action: Some("DROP".to_string()),
            signature: None,
            alert_severity: None,
            risk_score: 0.92,
            reasons: vec!["suspicious dns burst".to_string()],
            blocked: true,
            block_expires_at: Some(1_700_000_300),
            escalated: false,
            quarantine: false,
            manually_unblocked: false,
            label: None,
            feedback: None,
            feedback_at: None,
        };

        store.insert_event(&event).unwrap();
        let loaded = store.get_by_id(&event.id).unwrap().unwrap();
        assert_eq!(loaded.id, event.id);
        assert_eq!(loaded.src_ip, "10.0.0.2");

        let recent = store.list_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].id, event.id);
    }

    #[test]
    fn count_recent_high_risk_events_respects_threshold_and_window() {
        let store = ThreatEventStore::temporary().unwrap();
        let base_ts = 1_700_000_000;

        let low_risk = ThreatEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: base_ts,
            src_ip: "10.0.0.2".to_string(),
            dst_ip: "8.8.8.8".to_string(),
            src_port: Some(12345),
            dst_port: Some(53),
            protocol: "udp".to_string(),
            event_source: "test".to_string(),
            action: Some("DROP".to_string()),
            signature: None,
            alert_severity: None,
            risk_score: 0.5,
            reasons: vec!["low risk".to_string()],
            blocked: false,
            block_expires_at: None,
            escalated: false,
            quarantine: false,
            manually_unblocked: false,
            label: None,
            feedback: None,
            feedback_at: None,
        };
        store.insert_event(&low_risk).unwrap();

        let high_risk_recent = ThreatEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: base_ts + 10,
            src_ip: "10.0.0.2".to_string(),
            dst_ip: "8.8.4.4".to_string(),
            src_port: Some(12346),
            dst_port: Some(443),
            protocol: "tcp".to_string(),
            event_source: "test".to_string(),
            action: Some("DROP".to_string()),
            signature: None,
            alert_severity: None,
            risk_score: 0.95,
            reasons: vec!["high risk".to_string()],
            blocked: true,
            block_expires_at: Some(base_ts + 70),
            escalated: false,
            quarantine: false,
            manually_unblocked: false,
            label: None,
            feedback: None,
            feedback_at: None,
        };
        store.insert_event(&high_risk_recent).unwrap();

        let high_risk_other_ip = ThreatEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: base_ts + 20,
            src_ip: "10.0.0.3".to_string(),
            dst_ip: "1.1.1.1".to_string(),
            src_port: Some(12347),
            dst_port: Some(80),
            protocol: "tcp".to_string(),
            event_source: "test".to_string(),
            action: Some("DROP".to_string()),
            signature: None,
            alert_severity: None,
            risk_score: 0.99,
            reasons: vec!["other ip".to_string()],
            blocked: true,
            block_expires_at: Some(base_ts + 80),
            escalated: false,
            quarantine: false,
            manually_unblocked: false,
            label: None,
            feedback: None,
            feedback_at: None,
        };
        store.insert_event(&high_risk_other_ip).unwrap();

        let all_recent_for_src = store
            .count_recent_high_risk_events("10.0.0.2", base_ts, 0.8)
            .unwrap();
        assert_eq!(all_recent_for_src, 1);

        let none_in_future_window = store
            .count_recent_high_risk_events("10.0.0.2", base_ts + 11, 0.8)
            .unwrap();
        assert_eq!(none_in_future_window, 0);
    }
}
