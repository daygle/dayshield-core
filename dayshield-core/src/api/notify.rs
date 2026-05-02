//! Notification REST API endpoints.
//!
//! | Method | Path                  | Description                               |
//! |--------|-----------------------|-------------------------------------------|
//! | GET    | `/notify/config`      | Get the current notification config       |
//! | POST   | `/notify/config`      | Update the notification config            |
//! | POST   | `/notify/test`        | Send a test email using the current config |
//! | GET    | `/notify/categories`  | List available notification categories    |

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use tracing::info;

use crate::config::models::{validate_notify_config, NotifyCategory, NotifyConfig};
use crate::notify::smtp::{send_email, NotifyError};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum NotifyApiError {
    #[error("validation error: {0}")]
    ValidationFailed(String),

    #[error("SMTP error: {0}")]
    SmtpError(String),

    #[error("rate limited")]
    RateLimited,

    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),
}

impl From<NotifyError> for NotifyApiError {
    fn from(e: NotifyError) -> Self {
        match e {
            NotifyError::SmtpError(s) => NotifyApiError::SmtpError(s),
            NotifyError::ConfigError(s) => NotifyApiError::ValidationFailed(s),
            NotifyError::RateLimited => NotifyApiError::RateLimited,
            NotifyError::QueueFull => NotifyApiError::SmtpError("queue full".into()),
        }
    }
}

impl IntoResponse for NotifyApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            NotifyApiError::ValidationFailed(_) => StatusCode::BAD_REQUEST,
            NotifyApiError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            NotifyApiError::SmtpError(_) | NotifyApiError::StorageError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// GET /notify/config
// ---------------------------------------------------------------------------

/// Return the current notification configuration.
///
/// Returns the stored config, or a default (disabled) config when none has
/// been saved yet.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, NotifyApiError> {
    let cfg = state
        .config_store
        .load_notify_config()
        .map_err(NotifyApiError::StorageError)?
        .unwrap_or_default();
    Ok(Json(cfg))
}

// ---------------------------------------------------------------------------
// POST /notify/config
// ---------------------------------------------------------------------------

/// Replace the notification configuration.
///
/// Validates the submitted config before persisting it.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<NotifyConfig>,
) -> Result<impl IntoResponse, NotifyApiError> {
    if let Err(msg) = validate_notify_config(&req) {
        return Err(NotifyApiError::ValidationFailed(msg));
    }

    state
        .config_store
        .save_notify_config(req.clone())
        .map_err(NotifyApiError::StorageError)?;

    info!(
        enabled = req.enabled,
        smtp_server = %req.smtp_server,
        "Notification config updated via API"
    );

    Ok(Json(req))
}

// ---------------------------------------------------------------------------
// POST /notify/test
// ---------------------------------------------------------------------------

/// Send a test email using the current notification configuration.
///
/// Returns 400 when notifications are disabled or misconfigured, 500 on
/// SMTP failure.
pub async fn send_test(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, NotifyApiError> {
    let cfg = state
        .config_store
        .load_notify_config()
        .map_err(NotifyApiError::StorageError)?
        .unwrap_or_default();

    if !cfg.enabled {
        return Err(NotifyApiError::ValidationFailed(
            "notifications are not enabled".into(),
        ));
    }
    if let Err(msg) = validate_notify_config(&cfg) {
        return Err(NotifyApiError::ValidationFailed(msg));
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let subject = "[DayShield] Test notification";
    let body = format!(
        "DayShield Test Email\n\
         ====================\n\
         This is a test notification sent at Unix timestamp {ts}.\n\
         If you received this, your SMTP configuration is working correctly.\n"
    );

    send_email(&cfg, subject, &body)
        .await
        .map_err(NotifyApiError::from)?;

    info!("Test notification sent via API");

    Ok(Json(
        serde_json::json!({ "status": "ok", "message": "test email sent" }),
    ))
}

// ---------------------------------------------------------------------------
// GET /notify/categories
// ---------------------------------------------------------------------------

/// Return the list of available notification categories.
pub async fn get_categories() -> impl IntoResponse {
    let categories = vec![
        serde_json::json!({ "name": "suricata",  "description": "Suricata IDS/IPS alerts" }),
        serde_json::json!({ "name": "crowd_sec", "description": "CrowdSec remediation decisions" }),
        serde_json::json!({ "name": "acme",      "description": "ACME certificate events" }),
        serde_json::json!({ "name": "system",    "description": "System-level alerts" }),
    ];
    Json(categories)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn notify_api_error_status_codes() {
        assert_eq!(
            NotifyApiError::ValidationFailed("bad".into())
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            NotifyApiError::RateLimited.into_response().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            NotifyApiError::SmtpError("conn refused".into())
                .into_response()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            NotifyApiError::StorageError(anyhow::anyhow!("disk"))
                .into_response()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn notify_error_mapping() {
        let api_err: NotifyApiError = NotifyError::RateLimited.into();
        assert!(matches!(api_err, NotifyApiError::RateLimited));

        let api_err: NotifyApiError = NotifyError::ConfigError("x".into()).into();
        assert!(matches!(api_err, NotifyApiError::ValidationFailed(_)));

        let api_err: NotifyApiError = NotifyError::SmtpError("timeout".into()).into();
        assert!(matches!(api_err, NotifyApiError::SmtpError(_)));
    }
}
