//! Admin security settings API endpoints.
//!
//! | Method | Path              | Description                        |
//! |--------|-------------------|------------------------------------|
//! | GET    | `/admin/security` | Get admin security settings        |
//! | PUT    | `/admin/security` | Update admin security settings     |

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::config::models::AdminSecuritySettings;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// GET /admin/security
// ---------------------------------------------------------------------------

/// Get the current admin security settings.
pub async fn get_security(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let settings = state
        .config_store
        .load_admin_security_settings()
        .unwrap_or_default();
    Json(settings)
}

// ---------------------------------------------------------------------------
// PUT /admin/security
// ---------------------------------------------------------------------------

/// Update admin security settings.
pub async fn update_security(
    State(state): State<Arc<AppState>>,
    Json(settings): Json<AdminSecuritySettings>,
) -> impl IntoResponse {
    if settings.session_timeout_minutes == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "session_timeout_minutes must be greater than 0" })),
        );
    }
    if settings.min_password_length < 4 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "min_password_length must be at least 4" })),
        );
    }

    match state.config_store.save_admin_security_settings(settings) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "admin security settings updated" })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to save settings: {e}") })),
        ),
    }
}
