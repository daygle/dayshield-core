use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
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
    config::models::{
        Action, AiEngineConfig, FirewallRule, NotifyCategory,
    },
    engine::nftables::apply_rules,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub risk_score: f64,
    pub reasons: Vec<String>,
    pub blocked: bool,
    pub block_expires_at: Option<u64>,
    pub escalated: bool,
    pub quarantine: bool,
    pub manually_unblocked: bool,
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

#[derive(Clone)]
pub struct AiRuntime {
    store: Arc<ThreatEventStore>,
    active_blocks: Arc<Mutex<HashMap<IpAddr, ActiveBlock>>>,
    maintenance_started: Arc<AtomicBool>,
}

impl AiRuntime {
    pub fn new(config_dir: &Path) -> Self {
        let primary_path = config_dir.join("ai_engine").join("threat_events.db");
        let store = ThreatEventStore::open(&primary_path).unwrap_or_else(|e| {
            warn!(error = %e, path = %primary_path.display(), "ai_engine: falling back to temporary event store");
            ThreatEventStore::temporary().expect("failed to create temporary threat event store")
        });

        Self {
            store: Arc::new(store),
            active_blocks: Arc::new(Mutex::new(HashMap::new())),
            maintenance_started: Arc::new(AtomicBool::new(false)),
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
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(MAINTENANCE_INTERVAL_SECONDS));
            loop {
                ticker.tick().await;
                if let Err(e) = this.expire_blocks_and_reconcile(&state).await {
                    warn!(error = %e, "ai_engine: failed to reconcile expiring blocks");
                }
            }
        });
    }

    pub async fn submit_risk_assessment(
        &self,
        state: &Arc<AppState>,
        flow: FlowMetadata,
        risk_score: f64,
        reasons: Vec<String>,
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
            risk_score,
            reasons,
            blocked,
            block_expires_at,
            escalated,
            quarantine,
            manually_unblocked: false,
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
                risk_score: 0.0,
                reasons: vec!["manual unblock override".to_string()],
                blocked: false,
                block_expires_at: None,
                escalated: false,
                quarantine: false,
                manually_unblocked: true,
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
                interface: None,
                log: true,
                enabled: true,
                schedule: None,
            });
        }

        apply_rules(
            &rules,
            config.nat.as_ref(),
            &config.firewall_aliases,
            config.firewall_settings.as_ref(),
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
        .submit_risk_assessment(state, flow, risk_score, reasons)
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

pub fn default_ai_store_path(config_dir: &Path) -> PathBuf {
    config_dir.join("ai_engine").join("threat_events.db")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalation_is_deterministic() {
        let policy = AiEngineConfig {
            enabled: true,
            automatic_blocking: true,
            risk_score_block_threshold: 0.8,
            escalation_window_seconds: 300,
            block_duration_seconds: 60,
        };

        assert_eq!(compute_escalated_block(1, &policy), (Some(60), false, false));
        assert_eq!(compute_escalated_block(3, &policy), (Some(360), true, false));
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
            risk_score: 0.92,
            reasons: vec!["suspicious dns burst".to_string()],
            blocked: true,
            block_expires_at: Some(1_700_000_300),
            escalated: false,
            quarantine: false,
            manually_unblocked: false,
        };

        store.insert_event(&event).unwrap();
        let loaded = store.get_by_id(&event.id).unwrap().unwrap();
        assert_eq!(loaded.id, event.id);
        assert_eq!(loaded.src_ip, "10.0.0.2");

        let recent = store.list_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].id, event.id);
    }
}
