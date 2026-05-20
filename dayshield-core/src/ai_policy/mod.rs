pub mod auto_enforcer;
pub mod engine;
pub mod event_classifier;
pub mod intent_resolver;
pub mod models;
pub mod rule_auditor;
pub mod rule_suggester;

use std::sync::Arc;

use crate::state::AppState;

pub async fn start_background_tasks(state: Arc<AppState>) {
    state
        .ai_policy_engine
        .start_background_tasks(Arc::clone(&state));
}
