use std::{
    collections::HashMap,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use tokio::sync::RwLock;
use tracing::warn;

use crate::{
    ai_firewall::{
        auto_enforcer::{apply_suggestion_to_rules, undo_change, AppliedChange},
        event_classifier::{classify_event, is_block_action, is_scoped_allow_event},
        intent_resolver::{resolve_intent, ResolvedIntent},
        models::{
            ApplySuggestionRequest, ApplySuggestionResponse, AutomationMode, AutomationSettings,
            Decision, DecisionAction, Event, Intent, ModeRequest, RuleAudit, SetIntentsRequest,
            Suggestion, TrafficCandidate, UndoResponse, ZeroTrustBootstrapRequest,
            ZeroTrustBootstrapResponse,
        },
        rule_auditor::audit_rules,
        rule_suggester::build_suggestion,
    },
    config::models::{
        effective_management_ports, AcmeChallengeType, Action, FirewallAddressFamily,
        FirewallChainPolicy, FirewallDirection, FirewallRule, FirewallSettings,
        FirewallStateLimits, LogPosition, Protocol, SystemConfig,
    },
    state::AppState,
};

const DEFAULT_SUGGESTIONS_PATH: &str = "/var/lib/dayshield/ai/suggestions.json";
const DEFAULT_ACTION_LOG_PATH: &str = "/var/log/dayshield/ai_actions.log";
const DEFAULT_INTENTS_PATH: &str = "/var/lib/dayshield/ai/intents.json";
const DEFAULT_MODE_PATH: &str = "/var/lib/dayshield/ai/mode.json";
const DEFAULT_AUTOMATION_SETTINGS_PATH: &str = "/var/lib/dayshield/ai/automation_settings.json";
const ZERO_TRUST_BASELINE_PRIORITY: i32 = -125;
const PRIVATE_IPV4_SOURCES: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const PRIVATE_IPV6_SOURCES: &[&str] = &["fc00::/7", "fe80::/10"];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LoggedAction {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    iface: Option<String>,
    suggestion_id: String,
    decision: Decision,
    change: AppliedChange,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ActionHistoryEntry {
    pub iface: Option<String>,
    pub suggestion_id: String,
    pub decision: Decision,
    pub change: AppliedChange,
}

impl From<LoggedAction> for ActionHistoryEntry {
    fn from(action: LoggedAction) -> Self {
        Self {
            iface: action.iface,
            suggestion_id: action.suggestion_id,
            decision: action.decision,
            change: action.change,
        }
    }
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationSettingsConfig {
    #[serde(default)]
    pub default: AutomationSettings,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub per_interface: HashMap<String, AutomationSettings>,
}

impl Default for AutomationSettingsConfig {
    fn default() -> Self {
        Self {
            default: AutomationSettings::default(),
            per_interface: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum PersistedAutomationSettingsConfig {
    Config(AutomationSettingsConfig),
    Global(AutomationSettings),
}

impl From<PersistedAutomationSettingsConfig> for AutomationSettingsConfig {
    fn from(value: PersistedAutomationSettingsConfig) -> Self {
        match value {
            PersistedAutomationSettingsConfig::Config(config) => config,
            PersistedAutomationSettingsConfig::Global(settings) => AutomationSettingsConfig {
                default: settings,
                per_interface: HashMap::new(),
            },
        }
    }
}

#[derive(Clone)]
pub struct AiPolicyEngine {
    mode: Arc<RwLock<ModeConfig>>,
    suggestions: Arc<RwLock<Vec<Suggestion>>>,
    intents: Arc<RwLock<Vec<Intent>>>,
    automation_settings: Arc<RwLock<AutomationSettingsConfig>>,
    recent_events: Arc<RwLock<Vec<Event>>>,
    applied_actions: Arc<RwLock<Vec<LoggedAction>>>,
    suggestions_path: PathBuf,
    action_log_path: PathBuf,
    intents_path: PathBuf,
    mode_path: PathBuf,
    automation_settings_path: PathBuf,
    started: Arc<AtomicBool>,
}

impl AiPolicyEngine {
    pub fn new() -> Self {
        Self::with_paths(
            PathBuf::from(DEFAULT_SUGGESTIONS_PATH),
            PathBuf::from(DEFAULT_ACTION_LOG_PATH),
            PathBuf::from(DEFAULT_INTENTS_PATH),
            PathBuf::from(DEFAULT_MODE_PATH),
            PathBuf::from(DEFAULT_AUTOMATION_SETTINGS_PATH),
        )
    }

    pub fn with_paths(
        suggestions_path: PathBuf,
        action_log_path: PathBuf,
        intents_path: PathBuf,
        mode_path: PathBuf,
        automation_settings_path: PathBuf,
    ) -> Self {
        let suggestions = read_json_or_default(&suggestions_path, Vec::<Suggestion>::new());
        let intents = read_json_or_default(&intents_path, Vec::<Intent>::new());
        let mode = read_mode_config_or_default(&mode_path);
        let automation_settings =
            read_automation_settings_config_or_default(&automation_settings_path);
        let applied_actions = read_json_lines_or_default(&action_log_path);

        Self {
            mode: Arc::new(RwLock::new(mode)),
            suggestions: Arc::new(RwLock::new(suggestions)),
            intents: Arc::new(RwLock::new(intents)),
            automation_settings: Arc::new(RwLock::new(automation_settings)),
            recent_events: Arc::new(RwLock::new(Vec::new())),
            applied_actions: Arc::new(RwLock::new(applied_actions)),
            suggestions_path,
            action_log_path,
            intents_path,
            mode_path,
            automation_settings_path,
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
                    warn!(error = %e, "ai_firewall: failed to handle firewall log event");
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

        let mode = self.mode_for_event(&event).await;
        let intents = self.intents.read().await.clone();
        let classes = classify_event(&event, &recent_events_snapshot);
        let resolved_intent = resolve_intent(&event, &intents);
        let matched_intent = resolved_intent.is_some();

        if !should_generate_suggestion(&event, &classes, resolved_intent.as_ref()) {
            return Ok(());
        }

        let mut suggestion = build_suggestion(event.clone(), &classes);
        if let Some(resolved_intent) = &resolved_intent {
            suggestion.decision.action = resolved_intent.action.clone();
            suggestion.decision.reason = resolved_intent.reason.clone();
            suggestion.decision.confidence = resolved_intent.confidence;
        }

        {
            let mut suggestions = self.suggestions.write().await;
            suggestions.push(suggestion.clone());
            persist_json(&self.suggestions_path, &*suggestions)?;
        }

        if matches!(mode, AutomationMode::FullAiControl) {
            let settings = self.automation_settings_for_event(&event).await;
            if self
                .can_auto_apply(state, &suggestion, matched_intent, &settings)
                .await
            {
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
        }

        Ok(())
    }

    pub async fn list_suggestions(
        &self,
        state: &Arc<AppState>,
        iface: Option<String>,
    ) -> Result<Vec<Suggestion>> {
        let iface = normalize_iface(iface);
        let mut suggestions = self.suggestions.read().await.clone();
        filter_suggestions_by_iface(&mut suggestions, iface.as_deref());

        if matches!(
            self.get_mode(iface.clone()).await,
            AutomationMode::SuggestEdits | AutomationMode::FullAiControl
        ) {
            let intents = self.get_intents(iface.clone()).await;
            let mut rules = state.config_store.load_firewall_rules().unwrap_or_default();
            filter_rules_by_iface(&mut rules, iface.as_deref());
            let audits = audit_rules(&rules, &intents, &now_rfc3339());
            append_audit_suggestions(&mut suggestions, audits, iface.as_deref());
        }
        Ok(suggestions)
    }

    pub async fn list_traffic_candidates(&self, iface: Option<String>) -> Vec<TrafficCandidate> {
        let iface = normalize_iface(iface);
        let intents = self.get_intents(iface.clone()).await;
        let mut recent = self.recent_events.read().await.clone();
        filter_events_by_iface(&mut recent, iface.as_deref());
        build_traffic_candidates(&recent, &intents)
    }

    pub async fn get_intents(&self, iface: Option<String>) -> Vec<Intent> {
        let iface = normalize_iface(iface);
        let mut intents = self.intents.read().await.clone();
        filter_intents_by_iface(&mut intents, iface.as_deref());
        intents
    }

    pub async fn set_intents(
        &self,
        mut request: SetIntentsRequest,
        iface: Option<String>,
    ) -> Result<Vec<Intent>> {
        let iface = normalize_iface(iface);
        let mut intents = self.intents.write().await;

        if let Some(iface) = iface.as_deref() {
            for intent in &mut request.intents {
                intent.condition.iface = Some(iface.to_string());
            }
            intents.retain(|intent| !intent_matches_iface(intent, iface));
            intents.extend(request.intents);
        } else {
            *intents = request.intents;
        }

        persist_json(&self.intents_path, &*intents)?;

        let mut scoped = intents.clone();
        filter_intents_by_iface(&mut scoped, iface.as_deref());
        Ok(scoped)
    }

    pub async fn get_automation_settings(&self, iface: Option<String>) -> AutomationSettings {
        let iface = normalize_iface(iface);
        let settings = self.automation_settings.read().await;
        iface
            .as_ref()
            .and_then(|name| settings.per_interface.get(name).cloned())
            .unwrap_or_else(|| settings.default.clone())
    }

    pub async fn set_automation_settings(
        &self,
        mut settings: AutomationSettings,
        iface: Option<String>,
    ) -> Result<AutomationSettings> {
        let iface = normalize_iface(iface);
        settings.auto_apply_confidence_threshold =
            settings.auto_apply_confidence_threshold.min(100);
        let mut config = self.automation_settings.write().await;

        let result = if let Some(iface) = iface {
            config.per_interface.insert(iface.clone(), settings.clone());
            config
                .per_interface
                .get(&iface)
                .cloned()
                .unwrap_or_else(|| config.default.clone())
        } else {
            config.default = settings.clone();
            config.default.clone()
        };

        persist_json(&self.automation_settings_path, &*config)?;
        Ok(result)
    }

    pub async fn get_mode(&self, iface: Option<String>) -> AutomationMode {
        let iface = normalize_iface(iface);
        let mode = self.mode.read().await;
        iface
            .as_ref()
            .and_then(|name| mode.per_interface.get(name).cloned())
            .unwrap_or_else(|| mode.default.clone())
    }

    async fn mode_for_event(&self, event: &Event) -> AutomationMode {
        let iface = (!event.iface.trim().is_empty()).then(|| event.iface.clone());
        self.get_mode(iface).await
    }

    async fn automation_settings_for_event(&self, event: &Event) -> AutomationSettings {
        let iface = (!event.iface.trim().is_empty()).then(|| event.iface.clone());
        self.get_automation_settings(iface).await
    }

    pub async fn set_mode(
        &self,
        request: ModeRequest,
        iface: Option<String>,
    ) -> Result<AutomationMode> {
        let iface = normalize_iface(iface);
        let mut mode = self.mode.write().await;

        let result = if let Some(iface) = iface {
            mode.per_interface
                .insert(iface.clone(), request.mode.clone());
            mode.per_interface
                .get(&iface)
                .cloned()
                .unwrap_or_else(|| mode.default.clone())
        } else {
            mode.default = request.mode.clone();
            mode.default.clone()
        };

        persist_json(&self.mode_path, &*mode)?;
        Ok(result)
    }

    pub async fn bootstrap_zero_trust(
        &self,
        state: &Arc<AppState>,
        request: ZeroTrustBootstrapRequest,
        iface: Option<String>,
    ) -> Result<ZeroTrustBootstrapResponse> {
        let iface = normalize_iface(iface);

        let mode = if request.set_suggest_mode {
            self.set_mode(
                ModeRequest {
                    mode: AutomationMode::SuggestEdits,
                },
                iface.clone(),
            )
            .await?
        } else {
            self.get_mode(iface.clone()).await
        };

        let mut automation_settings = self.get_automation_settings(iface.clone()).await;
        harden_zero_trust_automation_settings(&mut automation_settings);
        automation_settings = self
            .set_automation_settings(automation_settings, iface.clone())
            .await?;

        let mut firewall_settings_hardened = false;
        let mut baseline_rules_added = 0;
        let mut baseline_rules_updated = 0;
        let mut baseline_rule_ids = Vec::new();

        if request.harden_firewall || request.include_legit_services {
            let old_config = state
                .config_store
                .load()
                .context("failed to load config for zero-trust bootstrap")?;
            let mut new_config = old_config.clone();
            let ipv6_enabled = new_config
                .system_settings
                .as_ref()
                .map(|settings| settings.ipv6_enabled)
                .unwrap_or(false);

            if request.harden_firewall {
                let mut firewall_settings =
                    new_config.firewall_settings.clone().unwrap_or_default();
                harden_zero_trust_firewall_settings(
                    &mut firewall_settings,
                    new_config.system_settings.as_ref(),
                );
                new_config.firewall_settings = Some(firewall_settings);
                firewall_settings_hardened = true;
            }

            if request.include_legit_services {
                let baseline_rules =
                    build_zero_trust_baseline_rules(&new_config, iface.as_deref(), ipv6_enabled);
                for rule in baseline_rules {
                    baseline_rule_ids.push(rule.id.to_string());
                    if let Some(existing) = new_config
                        .firewall_rules
                        .iter_mut()
                        .find(|existing| existing.id == rule.id)
                    {
                        *existing = rule;
                        baseline_rules_updated += 1;
                    } else {
                        new_config.firewall_rules.push(rule);
                        baseline_rules_added += 1;
                    }
                }
            }

            state
                .config_store
                .save_with_rollback(&new_config)
                .context("failed to persist zero-trust bootstrap config")?;
            {
                let mut cache = state.firewall_rules.write().await;
                *cache = new_config.firewall_rules.clone();
            }

            if let Err(apply_err) =
                crate::captive_portal::apply_current_ruleset_nft(&state.config_store).await
            {
                let _ = state.config_store.save_with_rollback(&old_config);
                {
                    let mut cache = state.firewall_rules.write().await;
                    *cache = old_config.firewall_rules;
                }
                return Err(anyhow::anyhow!(
                    "failed to apply nftables after zero-trust bootstrap: {apply_err}"
                ));
            }
        }

        Ok(ZeroTrustBootstrapResponse {
            applied: true,
            message: "zero-trust bootstrap enabled: input/forward default-deny with audit logging and scoped service exceptions".to_string(),
            mode,
            automation_settings,
            firewall_settings_hardened,
            baseline_rules_added,
            baseline_rules_updated,
            baseline_rule_ids,
        })
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
            None if !request.approve => {
                self.reject_suggestion(&request.suggestion_id).await?;
                return Ok(ApplySuggestionResponse {
                    applied: false,
                    message: "suggestion rejected".to_string(),
                    decision: None,
                });
            }
            None => {
                return Ok(ApplySuggestionResponse {
                    applied: false,
                    message: "suggestion not found".to_string(),
                    decision: None,
                })
            }
        };

        if !request.approve {
            self.reject_suggestion(&request.suggestion_id).await?;
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

        let Some(change) = self.apply_to_firewall_rules(state, &suggestion).await? else {
            return Ok(ApplySuggestionResponse {
                applied: false,
                message: "suggestion did not map to a firewall rule change".to_string(),
                decision: Some(decision),
            });
        };

        {
            let mut actions = self.applied_actions.write().await;
            let logged = LoggedAction {
                iface: normalize_iface(Some(suggestion.event.iface.clone())),
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

        Ok(ApplySuggestionResponse {
            applied: true,
            message: "suggestion applied".to_string(),
            decision: Some(decision),
        })
    }

    async fn reject_suggestion(&self, suggestion_id: &str) -> Result<()> {
        let mut suggestions = self.suggestions.write().await;
        if let Some(existing) = suggestions.iter_mut().find(|s| s.id == suggestion_id) {
            existing.rejected = true;
        } else {
            suggestions.push(rejected_placeholder_suggestion(suggestion_id.to_string()));
        }
        persist_json(&self.suggestions_path, &*suggestions)
    }

    pub async fn list_action_history(&self, iface: Option<String>) -> Vec<ActionHistoryEntry> {
        let iface = normalize_iface(iface);
        let actions = self.applied_actions.read().await;
        actions
            .iter()
            .rev()
            .filter(|action| logged_action_matches_iface(action, iface.as_deref()))
            .cloned()
            .map(ActionHistoryEntry::from)
            .collect()
    }

    pub async fn undo_last_action(
        &self,
        state: &Arc<AppState>,
        iface: Option<String>,
    ) -> Result<UndoResponse> {
        let iface = normalize_iface(iface);
        let maybe_last = {
            let actions = self.applied_actions.read().await;
            actions
                .iter()
                .rev()
                .find(|action| logged_action_matches_iface(action, iface.as_deref()))
                .cloned()
        };

        let Some(last) = maybe_last else {
            return Ok(UndoResponse {
                undone: false,
                message: match iface.as_deref() {
                    Some(iface) => format!("no actions to undo for interface {iface}"),
                    None => "no actions to undo".to_string(),
                },
                decision: None,
            });
        };

        self.update_firewall_rules(state, |rules| {
            undo_change(rules, &last.change);
            Ok(())
        })
        .await?;

        {
            let mut actions = self.applied_actions.write().await;
            if let Some(pos) = actions
                .iter()
                .rposition(|action| action.suggestion_id == last.suggestion_id)
            {
                actions.remove(pos);
            }
            persist_json_lines(&self.action_log_path, &*actions)?;
        }

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
        let mut cache = state.firewall_rules.write().await;
        let old_rules = state
            .config_store
            .load_firewall_rules()
            .context("failed to load firewall rules for AI policy update")?;
        let mut new_rules = old_rules.clone();
        let Some(change) = apply_suggestion_to_rules(&mut new_rules, suggestion) else {
            return Ok(None);
        };

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

        Ok(Some(change))
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

    async fn can_auto_apply(
        &self,
        state: &Arc<AppState>,
        suggestion: &Suggestion,
        matched_intent: bool,
        settings: &AutomationSettings,
    ) -> bool {
        if suggestion.decision.confidence < settings.threshold_fraction() {
            return false;
        }
        if settings.require_intent_match && !matched_intent {
            return false;
        }
        if settings.require_protocol {
            let protocol = suggestion.event.protocol.trim();
            if protocol.is_empty() || protocol.eq_ignore_ascii_case("any") {
                return false;
            }
        }
        if settings.require_destination_port
            && matches!(
                suggestion.event.protocol.to_ascii_lowercase().as_str(),
                "tcp" | "udp"
            )
            && suggestion.event.dest_port.is_none()
        {
            return false;
        }
        if settings.require_ip_family
            && (suggestion.event.src_ip.parse::<Ipv4Addr>().is_err()
                || suggestion.event.dest_ip.parse::<Ipv4Addr>().is_err())
        {
            return false;
        }
        if !settings.allow_edit_rule
            && matches!(suggestion.decision.action, DecisionAction::EditRule)
        {
            return false;
        }
        if !settings.allow_remove_rule
            && matches!(suggestion.decision.action, DecisionAction::RemoveRule)
        {
            return false;
        }
        if settings.protect_management_interface {
            let firewall_settings = state
                .config_store
                .load_firewall_settings()
                .unwrap_or_default();
            if firewall_settings
                .management_interface
                .as_deref()
                .is_some_and(|iface| iface == suggestion.event.iface)
            {
                return false;
            }
            if suggestion
                .event
                .dest_port
                .is_some_and(|port| firewall_settings.management_ports.contains(&port))
            {
                return false;
            }
        }
        if settings.max_auto_apply_per_hour > 0 {
            let actions = self.applied_actions.read().await;
            let iface = normalize_iface(Some(suggestion.event.iface.clone()));
            let recent = recent_auto_apply_count(&actions, iface.as_deref());
            if recent >= settings.max_auto_apply_per_hour as usize {
                return false;
            }
        }

        true
    }
}

fn harden_zero_trust_automation_settings(settings: &mut AutomationSettings) {
    settings.auto_apply_confidence_threshold = settings.auto_apply_confidence_threshold.max(90);
    settings.require_intent_match = true;
    settings.require_protocol = true;
    settings.require_destination_port = true;
    settings.require_ip_family = true;
    if settings.max_auto_apply_per_hour == 0 || settings.max_auto_apply_per_hour > 3 {
        settings.max_auto_apply_per_hour = 3;
    }
    settings.allow_edit_rule = false;
    settings.allow_remove_rule = false;
    settings.protect_management_interface = true;
}

fn harden_zero_trust_firewall_settings(
    settings: &mut FirewallSettings,
    system_settings: Option<&crate::config::models::SystemSettings>,
) {
    settings.input_policy = FirewallChainPolicy::Drop;
    settings.forward_policy = FirewallChainPolicy::Drop;
    settings.output_policy = FirewallChainPolicy::Accept;
    settings.drop_invalid_state = true;
    settings.syn_flood_protection = true;
    settings.management_anti_lockout = true;
    settings.log_position = LogPosition::Before;

    for port in effective_management_ports(settings, system_settings) {
        if !settings.management_ports.contains(&port) {
            settings.management_ports.push(port);
        }
    }
    settings.management_ports.sort_unstable();
    settings.management_ports.dedup();
}

fn build_zero_trust_baseline_rules(
    config: &SystemConfig,
    iface: Option<&str>,
    ipv6_enabled: bool,
) -> Vec<FirewallRule> {
    let mut rules = Vec::new();

    if let Some(dns) = config
        .dns
        .as_ref()
        .filter(|dns| dns.enabled && dns.port != 0)
    {
        let service_ifaces = baseline_lan_interfaces(config, iface);
        push_private_service_rules(
            &mut rules,
            "dns-udp",
            "DNS resolver (UDP)",
            Protocol::Udp,
            dns.port,
            &service_ifaces,
            ipv6_enabled,
        );
        push_private_service_rules(
            &mut rules,
            "dns-tcp",
            "DNS resolver (TCP)",
            Protocol::Tcp,
            dns.port,
            &service_ifaces,
            ipv6_enabled,
        );
    }

    if let Some(dot) = config
        .dot
        .as_ref()
        .filter(|dot| dot.enabled && dot.port != 0)
    {
        if dot.lan_only {
            let service_ifaces = baseline_lan_interfaces(config, iface);
            push_private_service_rules(
                &mut rules,
                "dot",
                "DNS-over-TLS listener",
                Protocol::Tcp,
                dot.port,
                &service_ifaces,
                ipv6_enabled,
            );
        } else {
            for service_iface in baseline_public_interfaces(iface) {
                push_zero_trust_rule(
                    &mut rules,
                    "dot-public",
                    "DNS-over-TLS listener",
                    Protocol::Tcp,
                    None,
                    None,
                    Some(dot.port),
                    service_iface.as_deref(),
                    if ipv6_enabled {
                        FirewallAddressFamily::Ipv4Ipv6
                    } else {
                        FirewallAddressFamily::Ipv4
                    },
                );
            }
        }
    }

    if let Some(dhcp) = config.dhcp.as_ref().filter(|dhcp| dhcp.enabled) {
        for service_iface in configured_service_interfaces(config, iface, &dhcp.interface) {
            push_zero_trust_rule(
                &mut rules,
                "dhcpv4",
                "DHCPv4 server",
                Protocol::Udp,
                None,
                Some(68),
                Some(67),
                service_iface.as_deref(),
                FirewallAddressFamily::Ipv4,
            );
        }
    }

    if ipv6_enabled {
        if let Some(dhcp6) = config.dhcp6.as_ref().filter(|dhcp6| dhcp6.enabled) {
            for service_iface in configured_service_interfaces(config, iface, &dhcp6.interface) {
                push_zero_trust_rule(
                    &mut rules,
                    "dhcpv6",
                    "DHCPv6 server",
                    Protocol::Udp,
                    None,
                    Some(546),
                    Some(547),
                    service_iface.as_deref(),
                    FirewallAddressFamily::Ipv6,
                );
            }
        }
    }

    if let Some(ntp) = config
        .ntp
        .as_ref()
        .filter(|ntp| ntp.enabled && ntp.serve_clients)
    {
        let service_ifaces = configured_listen_interfaces(config, iface, &ntp.listen_interfaces);
        push_private_service_rules(
            &mut rules,
            "ntp",
            "NTP server",
            Protocol::Udp,
            123,
            &service_ifaces,
            ipv6_enabled,
        );
    }

    for wg in config
        .wireguard_interfaces
        .iter()
        .filter(|wg| wg.enabled && wg.listen_port != 0)
    {
        for service_iface in baseline_public_interfaces(iface) {
            push_zero_trust_rule(
                &mut rules,
                &format!("wireguard-{}", wg.name),
                "WireGuard listener",
                Protocol::Udp,
                None,
                None,
                Some(wg.listen_port),
                service_iface.as_deref(),
                if ipv6_enabled {
                    FirewallAddressFamily::Ipv4Ipv6
                } else {
                    FirewallAddressFamily::Ipv4
                },
            );
        }
    }

    if let Some(acme) = config
        .acme
        .as_ref()
        .filter(|acme| acme.enabled && acme.challenge_type.eq(&AcmeChallengeType::Http01))
    {
        if !acme.domains.is_empty() {
            for service_iface in baseline_public_interfaces(iface) {
                push_zero_trust_rule(
                    &mut rules,
                    "acme-http01",
                    "ACME HTTP-01 challenge",
                    Protocol::Tcp,
                    None,
                    None,
                    Some(80),
                    service_iface.as_deref(),
                    if ipv6_enabled {
                        FirewallAddressFamily::Ipv4Ipv6
                    } else {
                        FirewallAddressFamily::Ipv4
                    },
                );
            }
        }
    }

    if let Some(portal) = config
        .captive_portal
        .as_ref()
        .filter(|portal| portal.enabled && portal.listen_port != 0)
    {
        let service_ifaces = configured_listen_interfaces(config, iface, &portal.interfaces);
        push_private_service_rules(
            &mut rules,
            "captive-portal",
            "Captive portal listener",
            Protocol::Tcp,
            portal.listen_port,
            &service_ifaces,
            ipv6_enabled,
        );
    }

    rules
}

fn push_private_service_rules(
    rules: &mut Vec<FirewallRule>,
    service_key: &str,
    label: &str,
    protocol: Protocol,
    destination_port: u16,
    ifaces: &[Option<String>],
    ipv6_enabled: bool,
) {
    for service_iface in ifaces {
        for source in PRIVATE_IPV4_SOURCES {
            push_zero_trust_rule(
                rules,
                service_key,
                label,
                protocol.clone(),
                Some(source),
                None,
                Some(destination_port),
                service_iface.as_deref(),
                FirewallAddressFamily::Ipv4,
            );
        }
        if ipv6_enabled {
            for source in PRIVATE_IPV6_SOURCES {
                push_zero_trust_rule(
                    rules,
                    service_key,
                    label,
                    protocol.clone(),
                    Some(source),
                    None,
                    Some(destination_port),
                    service_iface.as_deref(),
                    FirewallAddressFamily::Ipv6,
                );
            }
        }
    }
}

fn push_zero_trust_rule(
    rules: &mut Vec<FirewallRule>,
    service_key: &str,
    label: &str,
    protocol: Protocol,
    source: Option<&str>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    iface: Option<&str>,
    ip_family: FirewallAddressFamily,
) {
    rules.push(FirewallRule {
        id: stable_zero_trust_rule_id(
            service_key,
            &protocol,
            source,
            source_port,
            destination_port,
            iface,
            &ip_family,
        ),
        description: Some(format!("AI zero-trust baseline: {label}")),
        priority: ZERO_TRUST_BASELINE_PRIORITY,
        source: source.map(str::to_string),
        destination: None,
        protocol: Some(protocol),
        source_port,
        destination_port,
        ip_family,
        action: Action::Accept,
        direction: FirewallDirection::Input,
        interface: iface.map(str::to_string),
        log: false,
        enabled: true,
        schedule: None,
        state_limits: FirewallStateLimits::default(),
    });
}

fn baseline_lan_interfaces(config: &SystemConfig, iface: Option<&str>) -> Vec<Option<String>> {
    if let Some(iface) = iface {
        return vec![Some(iface.to_string())];
    }

    let ifaces = config
        .interfaces
        .iter()
        .filter(|iface| iface.enabled && iface.wan_mode.is_none() && iface.gateway.is_none())
        .map(|iface| Some(iface.name.clone()))
        .collect::<Vec<_>>();
    if ifaces.is_empty() {
        vec![None]
    } else {
        ifaces
    }
}

fn baseline_public_interfaces(iface: Option<&str>) -> Vec<Option<String>> {
    match iface {
        Some(iface) => vec![Some(iface.to_string())],
        None => vec![None],
    }
}

fn configured_service_interfaces(
    config: &SystemConfig,
    requested_iface: Option<&str>,
    configured_iface: &str,
) -> Vec<Option<String>> {
    let configured_iface = configured_iface.trim();
    if configured_iface.is_empty() {
        return baseline_lan_interfaces(config, requested_iface);
    }

    match requested_iface {
        Some(requested_iface) if !iface_eq(requested_iface, configured_iface) => Vec::new(),
        _ => vec![Some(configured_iface.to_string())],
    }
}

fn configured_listen_interfaces(
    config: &SystemConfig,
    requested_iface: Option<&str>,
    configured_ifaces: &[String],
) -> Vec<Option<String>> {
    let mut result = configured_ifaces
        .iter()
        .map(|iface| iface.trim())
        .filter(|iface| !iface.is_empty())
        .filter(|iface| {
            requested_iface
                .map(|requested_iface| iface_eq(requested_iface, iface))
                .unwrap_or(true)
        })
        .map(|iface| Some(iface.to_string()))
        .collect::<Vec<_>>();

    if result.is_empty()
        && configured_ifaces
            .iter()
            .all(|iface| iface.trim().is_empty())
    {
        result = baseline_lan_interfaces(config, requested_iface);
    }

    result
}

fn stable_zero_trust_rule_id(
    service_key: &str,
    protocol: &Protocol,
    source: Option<&str>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    iface: Option<&str>,
    ip_family: &FirewallAddressFamily,
) -> uuid::Uuid {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"dayshield-ai-zero-trust");
    hasher.update(service_key.as_bytes());
    hasher.update(protocol_key(protocol).as_bytes());
    hasher.update(source.unwrap_or("any").as_bytes());
    hasher.update(source_port.unwrap_or_default().to_be_bytes());
    hasher.update(destination_port.unwrap_or_default().to_be_bytes());
    hasher.update(iface.unwrap_or("any").as_bytes());
    hasher.update(family_key(ip_family).as_bytes());

    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

fn protocol_key(protocol: &Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
        Protocol::Icmpv6 => "icmpv6",
        Protocol::Any => "any",
    }
}

fn family_key(family: &FirewallAddressFamily) -> &'static str {
    match family {
        FirewallAddressFamily::Ipv4 => "ipv4",
        FirewallAddressFamily::Ipv6 => "ipv6",
        FirewallAddressFamily::Ipv4Ipv6 => "ipv4_ipv6",
    }
}

fn append_audit_suggestions(
    suggestions: &mut Vec<Suggestion>,
    audits: Vec<RuleAudit>,
    iface: Option<&str>,
) {
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
                iface: iface.unwrap_or("n/a").to_string(),
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

fn rejected_placeholder_suggestion(id: String) -> Suggestion {
    let timestamp = now_rfc3339();
    Suggestion {
        id,
        event: Event {
            timestamp: timestamp.clone(),
            direction: "unknown".to_string(),
            action: "REJECTED".to_string(),
            src_ip: "0.0.0.0".to_string(),
            dest_ip: "0.0.0.0".to_string(),
            protocol: "any".to_string(),
            src_port: None,
            dest_port: None,
            iface: "n/a".to_string(),
        },
        decision: Decision {
            action: DecisionAction::EditRule,
            reason: "Suggestion rejected before it was persisted".to_string(),
            confidence: 0.0,
            auto_applied: false,
            timestamp,
        },
        target_rule_id: None,
        applied: false,
        rejected: true,
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
    classes: &[crate::ai_firewall::event_classifier::EventClass],
    resolved_intent: Option<&ResolvedIntent>,
) -> bool {
    if resolved_intent.is_some() {
        return true;
    }

    if is_block_action(&event.action) {
        return true;
    }

    classes.contains(&crate::ai_firewall::event_classifier::EventClass::PortScan)
        || classes.contains(&crate::ai_firewall::event_classifier::EventClass::RepeatedAttempts)
        || classes.contains(&crate::ai_firewall::event_classifier::EventClass::NewService)
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
                } else if is_block_action(&aggregate.exemplar.action) {
                    if is_scoped_allow_event(&aggregate.exemplar) {
                        (
                            DecisionAction::SuggestAllow,
                            (0.45 + (aggregate.count.min(6) as f32 * 0.05)).min(0.75),
                            "Zero-trust baseline blocked scoped LAN traffic; verify and add a narrow allow rule if expected".to_string(),
                            None,
                            None,
                        )
                    } else {
                        (
                            DecisionAction::SuggestDeny,
                            0.55,
                            "Observed blocked traffic without a matching intent".to_string(),
                            None,
                            None,
                        )
                    }
                } else {
                    let scoped_allow_candidate =
                        is_scoped_allow_candidate(&aggregate.exemplar, intents);
                    if scoped_allow_candidate {
                        (
                            DecisionAction::SuggestAllow,
                            0.5,
                            "Observed permitted LAN traffic without a matching intent; verify and add a scoped allow rule".to_string(),
                            None,
                            None,
                        )
                    } else {
                        (
                            DecisionAction::EditRule,
                            0.42,
                            "Observed permitted traffic without trusted scope; refine existing rules before allowing".to_string(),
                            None,
                            None,
                        )
                    }
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

fn is_scoped_allow_candidate(event: &Event, intents: &[Intent]) -> bool {
    if !is_scoped_allow_event(event) {
        return false;
    }

    intents.iter().any(|intent| {
        intent.lan_only
            || intent
                .condition
                .traffic_scope
                .as_deref()
                .is_some_and(|scope| scope.eq_ignore_ascii_case("lan"))
    })
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn normalize_iface(iface: Option<String>) -> Option<String> {
    iface
        .map(|iface| iface.trim().to_string())
        .filter(|iface| !iface.is_empty())
}

fn iface_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn event_matches_iface(event: &Event, iface: &str) -> bool {
    iface_eq(&event.iface, iface)
}

fn intent_matches_iface(intent: &Intent, iface: &str) -> bool {
    intent
        .condition
        .iface
        .as_deref()
        .is_some_and(|intent_iface| iface_eq(intent_iface, iface))
}

fn filter_events_by_iface(events: &mut Vec<Event>, iface: Option<&str>) {
    if let Some(iface) = iface {
        events.retain(|event| event_matches_iface(event, iface));
    }
}

fn filter_suggestions_by_iface(suggestions: &mut Vec<Suggestion>, iface: Option<&str>) {
    if let Some(iface) = iface {
        suggestions.retain(|suggestion| event_matches_iface(&suggestion.event, iface));
    }
}

fn filter_intents_by_iface(intents: &mut Vec<Intent>, iface: Option<&str>) {
    if let Some(iface) = iface {
        intents.retain(|intent| intent_matches_iface(intent, iface));
    }
}

fn filter_rules_by_iface(
    rules: &mut Vec<crate::config::models::FirewallRule>,
    iface: Option<&str>,
) {
    if let Some(iface) = iface {
        rules.retain(|rule| {
            rule.interface
                .as_deref()
                .is_some_and(|rule_iface| iface_eq(rule_iface, iface))
        });
    }
}

fn logged_action_matches_iface(action: &LoggedAction, iface: Option<&str>) -> bool {
    let Some(iface) = iface else {
        return true;
    };

    action
        .iface
        .as_deref()
        .is_some_and(|action_iface| iface_eq(action_iface, iface))
        || applied_change_matches_iface(&action.change, iface)
}

fn applied_change_matches_iface(change: &AppliedChange, iface: &str) -> bool {
    match change {
        AppliedChange::AddedRule { rule } | AppliedChange::RemovedRule { rule } => {
            firewall_rule_matches_iface(rule, iface)
        }
        AppliedChange::UpdatedRule { before, after } => {
            firewall_rule_matches_iface(before, iface) || firewall_rule_matches_iface(after, iface)
        }
    }
}

fn firewall_rule_matches_iface(rule: &crate::config::models::FirewallRule, iface: &str) -> bool {
    rule.interface
        .as_deref()
        .is_some_and(|rule_iface| iface_eq(rule_iface, iface))
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

fn read_json_lines_or_default<T>(path: &Path) -> Vec<T>
where
    T: serde::de::DeserializeOwned,
{
    std::fs::read_to_string(path)
        .ok()
        .map(|raw| {
            raw.lines()
                .filter_map(|line| serde_json::from_str::<T>(line).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn read_mode_config_or_default(path: &Path) -> ModeConfig {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<PersistedModeConfig>(&raw)
            .map(ModeConfig::from)
            .unwrap_or_default(),
        Err(_) => ModeConfig::default(),
    }
}

fn read_automation_settings_config_or_default(path: &Path) -> AutomationSettingsConfig {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<PersistedAutomationSettingsConfig>(&raw)
            .map(AutomationSettingsConfig::from)
            .unwrap_or_default(),
        Err(_) => AutomationSettingsConfig::default(),
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

fn persist_json_lines<T: serde::Serialize>(path: &Path, values: &[T]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let tmp = path.with_extension("tmp");
    let mut raw = String::new();
    for value in values {
        raw.push_str(&serde_json::to_string(value)?);
        raw.push('\n');
    }
    std::fs::write(&tmp, raw).with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn recent_auto_apply_count(actions: &[LoggedAction], iface: Option<&str>) -> usize {
    let cutoff = Utc::now() - Duration::hours(1);
    actions
        .iter()
        .filter(|action| logged_action_matches_iface(action, iface))
        .filter(|action| action.decision.auto_applied)
        .filter(|action| {
            chrono::DateTime::parse_from_rfc3339(&action.decision.timestamp)
                .map(|timestamp| timestamp.with_timezone(&Utc) >= cutoff)
                .unwrap_or(false)
        })
        .count()
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
            dir.path().join("automation_settings.json"),
        );
        let mode = engine
            .set_mode(
                ModeRequest {
                    mode: AutomationMode::SuggestEdits,
                },
                None,
            )
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
            dir.path().join("automation_settings.json"),
        );

        // Default mode remains monitor-only until set.
        assert!(matches!(
            engine.get_mode(None).await,
            AutomationMode::MonitorOnly
        ));

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
        assert!(matches!(
            engine.get_mode(Some("eth0".to_string())).await,
            AutomationMode::FullAiControl
        ));
        assert!(matches!(
            engine.get_mode(Some("eth1".to_string())).await,
            AutomationMode::MonitorOnly
        ));
    }

    #[tokio::test]
    async fn set_and_get_interface_automation_settings() {
        let dir = tempdir().unwrap();
        let engine = AiPolicyEngine::with_paths(
            dir.path().join("suggestions.json"),
            dir.path().join("actions.log"),
            dir.path().join("intents.json"),
            dir.path().join("mode.json"),
            dir.path().join("automation_settings.json"),
        );

        let mut lan_settings = AutomationSettings::default();
        lan_settings.auto_apply_confidence_threshold = 42;

        let saved = engine
            .set_automation_settings(lan_settings.clone(), Some("lan0".to_string()))
            .await
            .unwrap();

        assert_eq!(saved.auto_apply_confidence_threshold, 42);
        assert_eq!(
            engine
                .get_automation_settings(Some("lan0".to_string()))
                .await
                .auto_apply_confidence_threshold,
            42
        );
        assert_eq!(
            engine
                .get_automation_settings(Some("wan0".to_string()))
                .await
                .auto_apply_confidence_threshold,
            AutomationSettings::default().auto_apply_confidence_threshold
        );
    }

    #[tokio::test]
    async fn rejecting_unpersisted_suggestion_records_placeholder() {
        let dir = tempdir().unwrap();
        let engine = AiPolicyEngine::with_paths(
            dir.path().join("suggestions.json"),
            dir.path().join("actions.log"),
            dir.path().join("intents.json"),
            dir.path().join("mode.json"),
            dir.path().join("automation_settings.json"),
        );
        let suggestion_id = "audit:Tighten the rule by specifying destination port/protocol";

        engine.reject_suggestion(suggestion_id).await.unwrap();

        let suggestions = engine.suggestions.read().await;
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].id, suggestion_id);
        assert!(suggestions[0].rejected);
    }

    #[tokio::test]
    async fn interface_intents_replace_only_that_interface() {
        let dir = tempdir().unwrap();
        let engine = AiPolicyEngine::with_paths(
            dir.path().join("suggestions.json"),
            dir.path().join("actions.log"),
            dir.path().join("intents.json"),
            dir.path().join("mode.json"),
            dir.path().join("automation_settings.json"),
        );

        engine
            .set_intents(
                SetIntentsRequest {
                    intents: vec![
                        test_intent("lan-initial", Some("lan0")),
                        test_intent("wan-initial", Some("wan0")),
                    ],
                },
                None,
            )
            .await
            .unwrap();

        let scoped = engine
            .set_intents(
                SetIntentsRequest {
                    intents: vec![test_intent("lan-replacement", None)],
                },
                Some("lan0".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].name, "lan-replacement");
        assert_eq!(scoped[0].condition.iface.as_deref(), Some("lan0"));

        let all = engine.get_intents(None).await;
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|intent| intent.name == "wan-initial"));
        assert!(all.iter().any(|intent| intent.name == "lan-replacement"));
        assert!(!all.iter().any(|intent| intent.name == "lan-initial"));
    }

    #[tokio::test]
    async fn traffic_candidates_filter_by_interface() {
        let dir = tempdir().unwrap();
        let engine = AiPolicyEngine::with_paths(
            dir.path().join("suggestions.json"),
            dir.path().join("actions.log"),
            dir.path().join("intents.json"),
            dir.path().join("mode.json"),
            dir.path().join("automation_settings.json"),
        );

        {
            let mut events = engine.recent_events.write().await;
            events.push(test_event("lan0", "10.0.0.2", "10.0.0.1"));
            events.push(test_event("wan0", "203.0.113.10", "10.0.0.1"));
        }

        let lan = engine
            .list_traffic_candidates(Some("lan0".to_string()))
            .await;
        assert_eq!(lan.len(), 1);
        assert_eq!(lan[0].iface, "lan0");

        let all = engine.list_traffic_candidates(None).await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn traffic_candidates_without_lan_scope_prefer_edit_rule() {
        let dir = tempdir().unwrap();
        let engine = AiPolicyEngine::with_paths(
            dir.path().join("suggestions.json"),
            dir.path().join("actions.log"),
            dir.path().join("intents.json"),
            dir.path().join("mode.json"),
            dir.path().join("automation_settings.json"),
        );

        {
            let mut events = engine.recent_events.write().await;
            events.push(test_event("wan0", "203.0.113.10", "10.0.0.1"));
        }

        let candidates = engine.list_traffic_candidates(None).await;
        assert_eq!(candidates.len(), 1);
        assert!(matches!(
            candidates[0].recommended_action,
            DecisionAction::EditRule
        ));
    }

    #[tokio::test]
    async fn zero_trust_dropped_lan_service_candidate_suggests_allow() {
        let dir = tempdir().unwrap();
        let engine = AiPolicyEngine::with_paths(
            dir.path().join("suggestions.json"),
            dir.path().join("actions.log"),
            dir.path().join("intents.json"),
            dir.path().join("mode.json"),
            dir.path().join("automation_settings.json"),
        );

        {
            let mut event = test_event("lan0", "10.0.0.2", "10.0.0.1");
            event.action = "DEFAULT-BLOCK INPUT".to_string();
            let mut events = engine.recent_events.write().await;
            events.push(event);
        }

        let candidates = engine.list_traffic_candidates(None).await;
        assert_eq!(candidates.len(), 1);
        assert!(matches!(
            candidates[0].recommended_action,
            DecisionAction::SuggestAllow
        ));
    }

    #[test]
    fn zero_trust_baseline_includes_enabled_legit_services() {
        let mut config = SystemConfig::default();
        config.interfaces = vec![test_interface("lan0", false), test_interface("wan0", true)];
        config.dns = Some(crate::config::models::DnsConfig::default());
        config.dhcp = Some(crate::config::models::DhcpConfig {
            enabled: true,
            interface: "lan0".to_string(),
            scopes: Vec::new(),
        });
        config.ntp = Some(crate::config::models::NtpConfig {
            enabled: true,
            upstream_servers: vec!["0.pool.ntp.org".to_string()],
            serve_clients: true,
            listen_interfaces: vec!["lan0".to_string()],
        });

        let rules = build_zero_trust_baseline_rules(&config, None, false);

        assert!(rules.iter().any(|rule| {
            rule.interface.as_deref() == Some("lan0")
                && matches!(rule.protocol.as_ref(), Some(Protocol::Udp))
                && rule.destination_port == Some(53)
        }));
        assert!(rules.iter().any(|rule| {
            rule.interface.as_deref() == Some("lan0")
                && matches!(rule.protocol.as_ref(), Some(Protocol::Tcp))
                && rule.destination_port == Some(53)
        }));
        assert!(rules.iter().any(|rule| {
            rule.interface.as_deref() == Some("lan0")
                && matches!(rule.protocol.as_ref(), Some(Protocol::Udp))
                && rule.source_port == Some(68)
                && rule.destination_port == Some(67)
        }));
        assert!(rules.iter().any(|rule| {
            rule.interface.as_deref() == Some("lan0")
                && matches!(rule.protocol.as_ref(), Some(Protocol::Udp))
                && rule.destination_port == Some(123)
        }));
        assert!(!rules
            .iter()
            .any(|rule| rule.interface.as_deref() == Some("wan0")));
    }

    fn test_intent(name: &str, iface: Option<&str>) -> Intent {
        Intent {
            id: name.to_string(),
            name: name.to_string(),
            description: None,
            enabled: true,
            desired_action: DecisionAction::Allow,
            condition: crate::ai_firewall::models::IntentCondition {
                iface: iface.map(str::to_string),
                ..Default::default()
            },
            protocol: None,
            port: None,
            lan_only: false,
            allowed_sources: Vec::new(),
        }
    }

    fn test_event(iface: &str, src_ip: &str, dest_ip: &str) -> Event {
        Event {
            timestamp: now_rfc3339(),
            direction: "inbound".to_string(),
            action: "ACCEPT".to_string(),
            src_ip: src_ip.to_string(),
            dest_ip: dest_ip.to_string(),
            protocol: "tcp".to_string(),
            src_port: Some(54321),
            dest_port: Some(443),
            iface: iface.to_string(),
        }
    }

    fn test_interface(name: &str, wan: bool) -> crate::config::models::Interface {
        crate::config::models::Interface {
            name: name.to_string(),
            description: None,
            addresses: vec!["192.168.1.1/24".to_string()],
            mtu: None,
            mss: None,
            enabled: true,
            dhcp4: wan,
            ipv6_mode: crate::config::models::Ipv6Mode::default(),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            vlan: None,
            parent_interface: None,
            wan_mode: wan.then_some(crate::config::models::WanMode::Dhcp),
            pppoe_username: None,
            pppoe_password: None,
            gateway: None,
            block_private_networks: false,
            block_bogon_networks: false,
        }
    }
}
