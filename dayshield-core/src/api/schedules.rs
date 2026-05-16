//! System schedules API.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::schedules::{self, ScheduleJobType, SystemSchedulesConfig, SystemSchedulesResponse};
use crate::state::AppState;

#[derive(Debug, thiserror::Error)]
pub enum SchedulesApiError {
    #[error("validation error: {0}")]
    ValidationError(String),

    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),
}

impl IntoResponse for SchedulesApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            SchedulesApiError::ValidationError(_) => StatusCode::BAD_REQUEST,
            SchedulesApiError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

pub async fn get_schedules(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SchedulesApiError> {
    let response = schedules::get_response(&state).map_err(SchedulesApiError::StorageError)?;
    Ok(Json(response))
}

pub async fn update_schedules(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SystemSchedulesConfig>,
) -> Result<impl IntoResponse, SchedulesApiError> {
    let _saved = schedules::save_config(&state, &req).map_err(SchedulesApiError::StorageError)?;
    let response = schedules::get_response(&state).map_err(SchedulesApiError::StorageError)?;
    Ok(Json(response))
}

pub async fn run_schedule_job(
    State(state): State<Arc<AppState>>,
    Path(job): Path<String>,
) -> Result<impl IntoResponse, SchedulesApiError> {
    let parsed = match job.as_str() {
        "dynamic_dns_update" => ScheduleJobType::DynamicDnsUpdate,
        "acme_renew" => ScheduleJobType::AcmeRenew,
        "suricata_rulesets_update" => ScheduleJobType::SuricataRulesetsUpdate,
        _ => {
            return Err(SchedulesApiError::ValidationError(
                "unsupported schedule job".into(),
            ))
        }
    };

    let _ = schedules::run_job_now(Arc::clone(&state), parsed)
        .await
        .map_err(SchedulesApiError::StorageError)?;

    let response: SystemSchedulesResponse =
        schedules::get_response(&state).map_err(SchedulesApiError::StorageError)?;
    Ok(Json(response))
}
