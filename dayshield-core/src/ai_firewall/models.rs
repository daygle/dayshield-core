use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutomationMode {
    MonitorOnly,
    SuggestEdits,
    FullAiControl,
}

impl Default for AutomationMode {
    fn default() -> Self {
        Self::MonitorOnly
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    Allow,
    Deny,
    SuggestAllow,
    SuggestDeny,
    EditRule,
    RemoveRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: String,
    pub direction: String,
    pub action: String,
    pub src_ip: String,
    pub dest_ip: String,
    pub protocol: String,
    pub src_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub iface: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntentCondition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub action: DecisionAction,
    pub reason: String,
    pub confidence: f32,
    pub auto_applied: bool,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suggestion {
    pub id: String,
    pub event: Event,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_rule_id: Option<String>,
    #[serde(default)]
    pub applied: bool,
    #[serde(default)]
    pub rejected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    #[serde(default = "default_intent_id")]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_desired_action")]
    pub desired_action: DecisionAction,
    #[serde(default)]
    pub condition: IntentCondition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub lan_only: bool,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficCandidate {
    pub id: String,
    pub timestamp: String,
    pub first_seen: String,
    pub last_seen: String,
    pub direction: String,
    pub observed_action: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub iface: String,
    pub observation_count: usize,
    pub recommended_action: DecisionAction,
    pub confidence: f32,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_intent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_intent_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAudit {
    pub timestamp: String,
    pub rule_id: Option<String>,
    pub finding: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplySuggestionRequest {
    pub suggestion_id: String,
    #[serde(default = "default_true")]
    pub approve: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AutomationSettings {
    pub auto_apply_confidence_threshold: u8,
    pub require_intent_match: bool,
    pub require_protocol: bool,
    pub require_destination_port: bool,
    pub require_ip_family: bool,
    pub max_auto_apply_per_hour: u32,
    pub allow_edit_rule: bool,
    pub allow_remove_rule: bool,
    pub protect_management_interface: bool,
}

impl Default for AutomationSettings {
    fn default() -> Self {
        Self {
            auto_apply_confidence_threshold: 75,
            require_intent_match: true,
            require_protocol: true,
            require_destination_port: true,
            require_ip_family: true,
            max_auto_apply_per_hour: 10,
            allow_edit_rule: false,
            allow_remove_rule: false,
            protect_management_interface: true,
        }
    }
}

impl AutomationSettings {
    pub fn threshold_fraction(&self) -> f32 {
        f32::from(self.auto_apply_confidence_threshold.min(100)) / 100.0
    }
}

fn default_true() -> bool {
    true
}

fn default_intent_id() -> String {
    Uuid::new_v4().to_string()
}

fn default_desired_action() -> DecisionAction {
    DecisionAction::Allow
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetIntentsRequest {
    pub intents: Vec<Intent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeRequest {
    pub mode: AutomationMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplySuggestionResponse {
    pub applied: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoResponse {
    pub undone: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ZeroTrustBootstrapRequest {
    pub set_suggest_mode: bool,
    pub harden_firewall: bool,
    pub include_legit_services: bool,
}

impl Default for ZeroTrustBootstrapRequest {
    fn default() -> Self {
        Self {
            set_suggest_mode: true,
            harden_firewall: true,
            include_legit_services: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZeroTrustBootstrapResponse {
    pub applied: bool,
    pub message: String,
    pub mode: AutomationMode,
    pub automation_settings: AutomationSettings,
    pub firewall_settings_hardened: bool,
    pub baseline_rules_added: usize,
    pub baseline_rules_updated: usize,
    pub baseline_rule_ids: Vec<String>,
}
