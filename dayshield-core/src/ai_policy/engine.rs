use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::sync::RwLock;
use tracing::warn;

use crate::{
    ai_policy::{
        auto_enforcer::{apply_suggestion_to_rules, undo_change, AppliedChange},
        event_classifier::classify_event,
        intent_resolver::{resolve_intent, ResolvedIntent},
        models::{
            ApplySuggestionRequest, ApplySuggestionResponse, AutomationMode, Decision,
            DecisionAction, Event, Intent, ModeRequest, RuleAudit, SetIntentsRequest, Suggestion,
            TrafficCandidate, UndoResponse,
        },
        rule_auditor::audit_rules,
        rule_suggester::build_suggestion,
    },
    state::AppState,
};

const DEFAULT_SUGGESTIONS_PATH: &str = "/var/lib/dayshield/ai/suggestions.json";
const DEFAULT_ACTION_LOG_PATH: &str = "/var/log/dayshield/ai_actions.log";
const DEFAULT_INTENTS_PATH: &str = "/etc/dayshield/intents.json";
const DEFAULT_MODE_PATH: &str = "/var/lib/dayshield/ai/mode.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LoggedAction {
    suggestion_id: String,
    decision: Decision,
    change: AppliedChange,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModeConfig {
    #[serde(default)]
    pub default: AutomationMode,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub per_interface: HashMap<String, AutomationMode>,
}

impl Default for ModeConfig {
    fn default() -> Self {
        Self {
            default: AutomationMode::MonitorOnly,
            per_interface: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum PersistedModeConfig {
    Global(AutomationMode),
    Config(ModeConfig),
}

impl From<PersistedModeConfig> for ModeConfig {
    fn from(value: PersistedModeConfig) -> Self {
        match value {
            PersistedModeConfig::Global(mode) => ModeConfig {
                default: mode,
                per_interface: HashMap::new(),
            },
            PersistedModeConfig::Config(config) => config,
        }
    }
}

#[derive(Clone)]
pub struct AiPolicyEngine {
    mode: Arc<RwLock<ModeConfig>>,
    suggestions: Arc<RwLock<Vec<Suggestion>>>,
    intents: Arc<RwLock<Vec<Intent>>>,
    recent_events: Arc<RwLock<Vec<Event>>>,
    applied_actions: Arc<RwLock<Vec<LoggedAction>>>,
    suggestions_path: PathBuf,
    action_log_path: PathBuf,
    intents_path: PathBuf,
    mode_path: PathBuf,
    started: Arc<AtomicBool>,
}

impl AiPolicyEngine {
    pub fn new() -> Self {
        Self::with_paths(
            PathBuf::from(DEFAULT_SUGGESTIONS_PATH),
            PathBuf::from(DEFAULT_ACTION_LOG_PATH),
            PathBuf::from(DEFAULT_INTENTS_PATH),
            PathBuf::from(DEFAULT_MODE_PATH),
        )
    }

    pub fn with_paths(
        suggestions_path: PathBuf,
        action_log_path: PathBuf,
        intents_path: PathBuf,
        mode_path: PathBuf,
    ) -> Self {
        let suggestions = read_json_or_default(&suggestions_path, Vec::<Suggestion>::new());
        let intents = read_json_or_default(&intents_path, Vec::<Intent>::new());
        let mode = read_mode_config_or_default(&mode_path);

        Self {
            mode: Arc::new(RwLock::new(mode)),
            suggestions: Arc::new(RwLock::new(suggestions)),
            intents: Arc::new(RwLock::new(intents)),
            recent_events: Arc::new(RwLock::new(Vec::new())),
            applied_actions: Arc::new(RwLock::new(Vec::new())),
            suggestions_path,
            action_log_path,
            intents_path,
            mode_path,
            started: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start_background_tasks(&self, state: Arc<AppState>) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }

        let this = self.clone();
        tokio::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::live_logs::LogEvent>(256);
            tokio::spawn(async move {
                crate::live_logs::firewall::stream_firewall(tx).await;
            });

            while let Some(event) = rx.recv().await {
                if let Err(e) = this.handle_log_event(&state, event).await {
                    warn!(error = %e, "ai_policy: failed to handle firewall log event");
                }
            }
        });
    }

    async fn handle_log_event(
        &self,
        state: &Arc<AppState>,
        event: crate::live_logs::LogEvent,
    ) -> Result<()> {
        let event = match event {
            crate::live_logs::LogEvent::FirewallEvent {
                timestamp,
                action,
                src_ip,
                dest_ip,
                proto,
                sport,
                dport,
                iface,
            } => Event {
                timestamp,
                direction: if iface.is_empty() {
                    "outbound".to_string()
                } else {
                    "inbound".to_string()
                },
                action,
                src_ip,
                dest_ip,
                protocol: proto,
                src_port: Some(sport).filter(|p| *p != 0),
                dest_port: Some(dport).filter(|p| *p != 0),
                iface,
            },
            _ => return Ok(()),
        };
        if event.src_ip.parse::<std::net::Ipv4Addr>().is_err()
            || event.dest_ip.parse::<std::net::Ipv4Addr>().is_err()
        {
            return Ok(());
        }

        self.process_event(state, event).await
    }

    pub async fn process_event(&self, state: &Arc<AppState>, event: Event) -> Result<()> {
        let recent_events_snapshot = {
            let mut recent_events = self.recent_events.write().await;
            recent_events.push(event.clone());
            if recent_events.len() > 512 {
                let keep_from = recent_events.len().saturating_sub(512);
                recent_events.drain(0..keep_from);
            }
            recent_events.clone()
        };

        let mode = self.get_mode(None).await;
        let intents = self.intents.read().await.clone();
        let classes = classify_event(&event, &recent_events_snapshot);
        let resolved_intent = resolve_intent(&event, &intents);

        if !should_generate_suggestion(&event, &classes, resolved_intent.as_ref()) {
            return Ok(());
        }

        let mut suggestion = build_suggestion(event.clone(), &classes);
        if let Some(resolved_intent) = resolved_intent {
            suggestion.decision.action = resolved_intent.action;
            suggestion.decision.reason = resolved_intent.reason;
            suggestion.decision.confidence = resolved_intent.confidence;
        }

        {
            let mut suggestions = self.suggestions.write().await;
            suggestions.push(suggestion.clone());
            persist_json(&self.suggestions_path, &*suggestions)?;
        }

        if matches!(mode, AutomationMode::FullAiControl) {
            let _ = self
                .apply_suggestion(
                    state,
                    ApplySuggestionRequest {
                        suggestion_id: suggestion.id.clone(),
                        approve: true,
                    },
                    true,
                )
                .await?;
        }

        Ok(())
    }

    pub async fn list_suggestions(&self, state: &Arc<AppState>) -> Result<Vec<Suggestion>> {
        let mut suggestions = self.suggestions.read().await.clone();
        if matches!(
            self.get_mode(None).await,
            AutomationMode::SuggestEdits | AutomationMode::FullAiControl
        ) {
            let intents = self.intents.read().await.clone();
            let rules = state.config_store.load_firewall_rules().unwrap_or_default();
            let audits = audit_rules(&rules, &intents, &now_rfc3339());
            append_audit_suggestions(&mut suggestions, audits);
        }
        Ok(suggestions)
    }

    pub async fn list_traffic_candidates(&self) -> Vec<TrafficCandidate> {
        let intents = self.intents.read().await.clone();
        let recent = self.recent_events.read().await.clone();
        build_traffic_candidates(&recent, &intents)
    }

    pub async fn get_intents(&self) -> Vec<Intent> {
        self.intents.read().await.clone()
    }

    pub async fn set_intents(&self, request: SetIntentsRequest) -> Result<Vec<Intent>> {
        let mut intents = self.intents.write().await;
        *intents = request.intents;
        persist_json(&self.intents_path, &*intents)?;
        Ok(intents.clone())
    }

    pub async fn get_mode(&self, iface: Option<String>) -> AutomationMode {
        let mode = self.mode.read().await;
        iface
            .as_ref()
            .and_then(|name| mode.per_interface.get(name).cloned())
            .unwrap_or_else(|| mode.default.clone())
    }

    pub async fn set_mode(&self, request: ModeRequest, iface: Option<String>) -> Result<AutomationMode> {
        let mut mode = self.mode.write().await;

        let result = if let Some(iface) = iface {
            mode.per_interface.insert(iface.clone(), request.mode.clone());
            mode.per_interface.get(&iface).cloned().unwrap_or_else(|| mode.default.clone())
        } else {
            mode.default = request.mode.clone();
            mode.default.clone()
        };

        persist_json(&self.mode_path, &*mode)?;
        Ok(result)
    }

    pub async fn apply_suggestion(
        &self,
        state: &Arc<AppState>,
        request: ApplySuggestionRequest,
        auto_applied: bool,
    ) -> Result<ApplySuggestionResponse> {
        let maybe = {
            let suggestions = self.suggestions.read().await;
            suggestions
                .iter()
                .find(|s| s.id == request.suggestion_id)
                .cloned()
        };
        let mut suggestion = match maybe {
            Some(s) => s,
            None => {
                return Ok(ApplySuggestionResponse {
                    applied: false,
                    message: "suggestion not found".to_string(),
                    decision: None,
                })
            }
        };

        if !request.approve {
            let mut suggestions = self.suggestions.write().await;
            if let Some(existing) = suggestions
                .iter_mut()
                .find(|s| s.id == request.suggestion_id)
            {
                existing.rejected = true;
                persist_json(&self.suggestions_path, &*suggestions)?;
            }
            return Ok(ApplySuggestionResponse {
                applied: false,
                message: "suggestion rejected".to_string(),
                decision: None,
            });
        }

        let mut decision = suggestion.decision.clone();
        decision.auto_applied = auto_applied;
        decision.timestamp = now_rfc3339();
        decision.action = materialize_action(decision.action.clone());
        suggestion.decision = decision.clone();

        let change = self.apply_to_firewall_rules(state, &suggestion).await?;
        if let Some(change) = change {
            {
                let mut actions = self.applied_actions.write().await;
                let logged = LoggedAction {
                    suggestion_id: suggestion.id.clone(),
                    decision: decision.clone(),
                    change,
                };
                actions.push(logged.clone());
                append_json_line(&self.action_log_path, &logged)?;
            }

            let mut suggestions = self.suggestions.write().await;
            if let Some(existing) = suggestions
                .iter_mut()
                .find(|s| s.id == request.suggestion_id)
            {
                existing.applied = true;
                existing.decision = decision.clone();
            }
            persist_json(&self.suggestions_path, &*suggestions)?;
        }

        Ok(ApplySuggestionResponse {
            applied: true,
            message: "suggestion applied".to_string(),
            decision: Some(decision),
        })
    }

    pub async fn undo_last_action(&self, state: &Arc<AppState>) -> Result<UndoResponse> {
        let maybe_last = {
            let mut actions = self.applied_actions.write().await;
            actions.pop()
        };

        let Some(last) = maybe_last else {
            return Ok(UndoResponse {
                undone: false,
                message: "no actions to undo".to_string(),
                decision: None,
            });
        };

        self.update_firewall_rules(state, |rules| {
            undo_change(rules, &last.change);
            Ok(())
        })
        .await?;

        Ok(UndoResponse {
            undone: true,
            message: "last AI action undone".to_string(),
            decision: Some(last.decision),
        })
    }

    async fn apply_to_firewall_rules(
        &self,
        state: &Arc<AppState>,
        suggestion: &Suggestion,
    ) -> Result<Option<AppliedChange>> {
        self.update_firewall_rules(state, |rules| {
            Ok(apply_suggestion_to_rules(rules, suggestion))
        })
        .await
    }

    async fn update_firewall_rules<T, F>(&self, state: &Arc<AppState>, mutate: F) -> Result<T>
    where
        F: FnOnce(&mut Vec<crate::config::models::FirewallRule>) -> Result<T>,
    {
        let mut cache = state.firewall_rules.write().await;
        let old_rules = state
            .config_store
            .load_firewall_rules()
            .context("failed to load firewall rules for AI policy update")?;
        let mut new_rules = old_rules.clone();
        let result = mutate(&mut new_rules)?;

        state
            .config_store
            .save_firewall_rules(new_rules.clone())
            .context("failed to persist firewall rules for AI policy update")?;
        *cache = new_rules;

        if let Err(apply_err) =
            crate::captive_portal::apply_current_ruleset_nft(&state.config_store).await
        {
            let _ = state.config_store.save_firewall_rules(old_rules.clone());
            *cache = old_rules;
            return Err(anyhow::anyhow!(
                "failed to apply nftables after AI policy update: {apply_err}"
            ));
        }

        Ok(result)
    }
}

fn append_audit_suggestions(suggestions: &mut Vec<Suggestion>, audits: Vec<RuleAudit>) {
    for audit in audits {
        let synthetic = Suggestion {
            id: format!("audit:{}", audit.recommendation),
            event: Event {
                timestamp: audit.timestamp.clone(),
                direction: "audit".to_string(),
                action: "AUDIT".to_string(),
                src_ip: "0.0.0.0".to_string(),
                dest_ip: "0.0.0.0".to_string(),
                protocol: "any".to_string(),
                src_port: None,
                dest_port: None,
                iface: "n/a".to_string(),
            },
            decision: Decision {
                action: DecisionAction::EditRule,
                reason: format!("{}: {}", audit.finding, audit.recommendation),
                confidence: 0.7,
                auto_applied: false,
                timestamp: audit.timestamp,
            },
            target_rule_id: audit.rule_id,
            applied: false,
            rejected: false,
        };
        if !suggestions.iter().any(|s| s.id == synthetic.id) {
            suggestions.push(synthetic);
        }
    }
}

fn materialize_action(action: DecisionAction) -> DecisionAction {
    match action {
        DecisionAction::SuggestAllow => DecisionAction::Allow,
        DecisionAction::SuggestDeny => DecisionAction::Deny,
        other => other,
    }
}

fn should_generate_suggestion(
    event: &Event,
    classes: &[crate::ai_policy::event_classifier::EventClass],
    resolved_intent: Option<&ResolvedIntent>,
) -> bool {
    if resolved_intent.is_some() {
        return true;
    }

    if event.action.eq_ignore_ascii_case("drop")
        || event.action.eq_ignore_ascii_case("reject")
        || event.action.eq_ignore_ascii_case("block")
    {
        return true;
    }

    classes.contains(&crate::ai_policy::event_classifier::EventClass::PortScan)
        || classes.contains(&crate::ai_policy::event_classifier::EventClass::RepeatedAttempts)
        || classes.contains(&crate::ai_policy::event_classifier::EventClass::NewService)
}

fn build_traffic_candidates(recent: &[Event], intents: &[Intent]) -> Vec<TrafficCandidate> {
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    #[derive(Clone)]
    struct Aggregate {
        exemplar: Event,
        first_seen: String,
        last_seen: String,
        count: usize,
    }

    let mut aggregates: BTreeMap<String, Aggregate> = BTreeMap::new();
    for event in recent.iter().rev().take(256).cloned() {
        let key = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            event.iface,
            event.direction,
            event.action,
            event.src_ip,
            event.dest_ip,
            event.protocol,
            event.src_port.unwrap_or_default(),
            event.dest_port.unwrap_or_default()
        );
        aggregates
            .entry(key)
            .and_modify(|existing| {
                existing.count += 1;
                existing.last_seen = event.timestamp.clone();
            })
            .or_insert_with(|| Aggregate {
                exemplar: event.clone(),
                first_seen: event.timestamp.clone(),
                last_seen: event.timestamp.clone(),
                count: 1,
            });
    }

    let mut candidates = aggregates
        .into_values()
        .map(|aggregate| {
            let resolved = resolve_intent(&aggregate.exemplar, intents);
            let (recommended_action, confidence, reason, matched_intent_id, matched_intent_name) =
                if let Some(resolved) = resolved {
                    (
                        resolved.action,
                        resolved.confidence,
                        resolved.reason,
                        Some(resolved.intent_id),
                        Some(resolved.intent_name),
                    )
                } else if aggregate.exemplar.action.eq_ignore_ascii_case("drop")
                    || aggregate.exemplar.action.eq_ignore_ascii_case("reject")
                {
                    (
                        DecisionAction::SuggestDeny,
                        0.55,
                        "Observed blocked traffic without a matching intent".to_string(),
                        None,
                        None,
                    )
                } else {
                    (
                        DecisionAction::SuggestAllow,
                        0.5,
                        "Observed permitted traffic without a matching intent".to_string(),
                        None,
                        None,
                    )
                };

            let mut hasher = Sha256::new();
            hasher.update(aggregate.exemplar.timestamp.as_bytes());
            hasher.update(aggregate.exemplar.iface.as_bytes());
            hasher.update(aggregate.exemplar.src_ip.as_bytes());
            hasher.update(aggregate.exemplar.dest_ip.as_bytes());
            hasher.update(aggregate.exemplar.protocol.as_bytes());
            let id = hasher
                .finalize()
                .iter()
                .take(12)
                .map(|b| format!("{:02x}", b))
                .collect::<String>();

            TrafficCandidate {
                id,
                timestamp: aggregate.last_seen.clone(),
                first_seen: aggregate.first_seen,
                last_seen: aggregate.last_seen,
                direction: aggregate.exemplar.direction,
                observed_action: aggregate.exemplar.action,
                src_ip: aggregate.exemplar.src_ip,
                dst_ip: aggregate.exemplar.dest_ip,
                protocol: aggregate.exemplar.protocol,
                src_port: aggregate.exemplar.src_port,
                dst_port: aggregate.exemplar.dest_port,
                iface: aggregate.exemplar.iface,
                observation_count: aggregate.count,
                recommended_action,
                confidence,
                reason,
                matched_intent_id,
                matched_intent_name,
            }
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    candidates
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn read_json_or_default<T>(path: &Path, default: T) -> T
where
    T: serde::de::DeserializeOwned,
{
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or(default),
        Err(_) => default,
    }
}

fn read_mode_config_or_default(path: &Path) -> ModeConfig {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<PersistedModeConfig>(&raw)
            .map(ModeConfig::from)
            .unwrap_or_default(),
        Err(_) => ModeConfig::default(),
    }
}

fn persist_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let raw = serde_json::to_vec_pretty(value)?;
    std::fs::write(&tmp, raw).with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn append_json_line<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let line = serde_json::to_string(value)?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writeln!(file, "{line}").with_context(|| format!("failed to append {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn set_and_get_mode_roundtrip() {
        let dir = tempdir().unwrap();
        let engine = AiPolicyEngine::with_paths(
            dir.path().join("suggestions.json"),
            dir.path().join("actions.log"),
            dir.path().join("intents.json"),
            dir.path().join("mode.json"),
        );
        let mode = engine
            .set_mode(ModeRequest {
                mode: AutomationMode::SuggestEdits,
            },
            None)
            .await
            .unwrap();
        assert!(matches!(mode, AutomationMode::SuggestEdits));
        assert!(matches!(
            engine.get_mode(None).await,
            AutomationMode::SuggestEdits
        ));
    }

    #[tokio::test]
    async fn set_and_get_interface_mode() {
        let dir = tempdir().unwrap();
        let engine = AiPolicyEngine::with_paths(
            dir.path().join("suggestions.json"),
            dir.path().join("actions.log"),
            dir.path().join("intents.json"),
            dir.path().join("mode.json"),
        );

        // Default mode remains monitor-only until set.
        assert!(matches!(engine.get_mode(None).await, AutomationMode::MonitorOnly));

        let mode = engine
            .set_mode(
                ModeRequest {
                    mode: AutomationMode::FullAiControl,
                },
                Some("eth0".to_string()),
            )
            .await
            .unwrap();

        assert!(matches!(mode, AutomationMode::FullAiControl));
        assert!(matches!(engine.get_mode(Some("eth0".to_string())).await, AutomationMode::FullAiControl));
        assert!(matches!(engine.get_mode(Some("eth1".to_string())).await, AutomationMode::MonitorOnly));
    }
}
