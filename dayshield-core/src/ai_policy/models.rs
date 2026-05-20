use serde::{Deserialize, Serialize};

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
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub port: u16,
    #[serde(default)]
    pub lan_only: bool,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
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

fn default_true() -> bool {
    true
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
