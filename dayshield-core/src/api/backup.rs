//! Backup and restore REST API endpoints.
//!
//! | Method | Path                        | Description                                |
//! |--------|-----------------------------|--------------------------------------------|
//! | POST   | `/backup/create`            | Create a new backup archive                |
//! | GET    | `/backup/list`              | List backup files on disk                  |
//! | GET    | `/backup/download/{file}`   | Download a specific backup file            |
//! | DELETE | `/backup/{file}`            | Delete a specific backup file              |
//! | POST   | `/backup/restore`           | Restore from an uploaded backup file       |
//! | GET    | `/backup/scheduler`         | Get the automatic scheduler configuration  |
//! | POST   | `/backup/scheduler`         | Update the automatic scheduler config      |

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::state::AppState;

use crate::backup::{
    create::{create_backup, DEFAULT_BACKUP_DIR},
    model::{BackupMetadata, BackupScheduleConfig, Subsystem},
    restore::restore_backup,
    scheduler::{load_schedule, prune_backups, save_schedule},
};

/// Maximum accepted request size for `POST /backup/restore` (64 MiB).
pub const MAX_BACKUP_RESTORE_BYTES: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum BackupApiError {
    #[error("validation error: {0}")]
    ValidationFailed(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),
}

impl IntoResponse for BackupApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            BackupApiError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            BackupApiError::NotFound(_) => StatusCode::NOT_FOUND,
            BackupApiError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /backup/create`.
#[derive(Debug, Deserialize)]
pub struct CreateBackupRequest {
    /// Subsystems to include; `null` or absent means all.
    #[serde(default)]
    pub subsystems: Option<Vec<Subsystem>>,
    /// Whether to encrypt the backup archive.
    #[serde(default)]
    pub encrypt: bool,
    /// Passphrase for encryption; required when `encrypt` is `true`.
    #[serde(default)]
    pub passphrase: Option<String>,
}

/// Response body for `POST /backup/create`.
#[derive(Serialize)]
pub struct CreateBackupResponse {
    /// File name of the created backup (not a full path).
    pub filename: String,
    /// SHA-256 hex digest of the backup's config content.
    pub sha256: String,
    /// Unix timestamp when the backup was created.
    pub created_at: u64,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Whether the backup is encrypted.
    pub encrypted: bool,
}

/// A single entry in the `GET /backup/list` response.
#[derive(Serialize)]
pub struct BackupListEntry {
    pub filename: String,
    pub size_bytes: u64,
    /// Whether the file appears to be encrypted (`.tar.enc` extension).
    pub encrypted: bool,
}

/// Query parameters for `POST /backup/restore`.
#[derive(Deserialize)]
pub struct RestoreQuery {
    /// Decryption passphrase (required for encrypted backups).
    #[serde(default)]
    pub passphrase: Option<String>,
    /// Comma-separated list of subsystem names to restore.  Absent means all.
    #[serde(default)]
    pub subsystems: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /backup/create`
///
/// Creates a new backup archive and returns metadata about it.
pub async fn create_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateBackupRequest>,
) -> Result<impl IntoResponse, BackupApiError> {
    if req.encrypt && req.passphrase.as_deref().map(str::is_empty).unwrap_or(true) {
        return Err(BackupApiError::ValidationFailed(
            "passphrase is required when encrypt is true".into(),
        ));
    }

    let backup_dir = PathBuf::from(DEFAULT_BACKUP_DIR);
    let passphrase = req.passphrase.as_deref().map(String::from);

    let (path, meta) = create_backup(
        &state.config_store,
        req.subsystems,
        req.encrypt,
        passphrase.as_deref(),
        &backup_dir,
    )
    .map_err(BackupApiError::StorageError)?;

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    let size_bytes = std::fs::metadata(&path)
        .map(|m| m.len())
        .unwrap_or(0);

    info!(filename = %filename, size_bytes = %size_bytes, "backup created via API");

    Ok(Json(CreateBackupResponse {
        filename,
        sha256: meta.sha256,
        created_at: meta.created_at,
        size_bytes,
        encrypted: meta.encrypted,
    }))
}

/// `GET /backup/list`
///
/// Returns a list of backup files available on disk.
pub async fn list_handler(
    State(_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, BackupApiError> {
    let backup_dir = Path::new(DEFAULT_BACKUP_DIR);

    if !backup_dir.exists() {
        return Ok(Json(Vec::<BackupListEntry>::new()));
    }

    let mut entries: Vec<BackupListEntry> = std::fs::read_dir(backup_dir)
        .map_err(|e| BackupApiError::StorageError(anyhow::anyhow!("read_dir: {e}")))?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            let name = path.file_name()?.to_str()?.to_string();
            if !is_backup_filename(&name) {
                return None;
            }
            let size = e.metadata().ok()?.len();
            let encrypted = name.ends_with(".tar.enc");
            Some(BackupListEntry {
                filename: name,
                size_bytes: size,
                encrypted,
            })
        })
        .collect();

    entries.sort_by(|a, b| a.filename.cmp(&b.filename));

    Ok(Json(entries))
}

/// `GET /backup/download/{filename}`
///
/// Streams the raw bytes of the requested backup file to the client.
pub async fn download_handler(
    State(_state): State<Arc<AppState>>,
    AxumPath(filename): AxumPath<String>,
) -> Result<Response, BackupApiError> {
    let path = safe_backup_path(&filename)?;

    if !path.exists() {
        return Err(BackupApiError::NotFound(format!(
            "backup file not found: {filename}"
        )));
    }

    let bytes = std::fs::read(&path)
        .map_err(|e| BackupApiError::StorageError(anyhow::anyhow!("read {filename}: {e}")))?;

    let content_type = if filename.ends_with(".tar.enc") {
        "application/octet-stream"
    } else {
        "application/x-tar"
    };

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(axum::body::Body::from(bytes))
        .map_err(|e| BackupApiError::StorageError(anyhow::anyhow!("build response: {e}")))?;

    Ok(response)
}

/// `DELETE /backup/{filename}`
///
/// Deletes the specified backup file from disk.
pub async fn delete_handler(
    State(_state): State<Arc<AppState>>,
    AxumPath(filename): AxumPath<String>,
) -> Result<impl IntoResponse, BackupApiError> {
    let path = safe_backup_path(&filename)?;

    if !path.exists() {
        return Err(BackupApiError::NotFound(format!(
            "backup file not found: {filename}"
        )));
    }

    std::fs::remove_file(&path)
        .map_err(|e| BackupApiError::StorageError(anyhow::anyhow!("remove {filename}: {e}")))?;

    info!(filename = %filename, "backup deleted via API");

    Ok(Json(serde_json::json!({ "status": "ok", "deleted": filename })))
}

/// `POST /backup/restore`
///
/// Accepts the raw bytes of a backup file in the request body and restores
/// the configuration.
///
/// Query parameters:
/// - `passphrase` - decryption passphrase (required for encrypted backups).
/// - `subsystems` - comma-separated list of subsystems to restore (optional).
pub async fn restore_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RestoreQuery>,
    body: Bytes,
) -> Result<impl IntoResponse, BackupApiError> {
    if body.is_empty() {
        return Err(BackupApiError::ValidationFailed(
            "request body must contain the backup file bytes".into(),
        ));
    }
    if body.len() > MAX_BACKUP_RESTORE_BYTES {
        return Err(BackupApiError::ValidationFailed(format!(
            "backup file too large: max {} bytes",
            MAX_BACKUP_RESTORE_BYTES
        )));
    }

    let subsystems_filter: Option<Vec<Subsystem>> = query
        .subsystems
        .as_deref()
        .map(parse_subsystem_list)
        .transpose()
        .map_err(BackupApiError::ValidationFailed)?;

    let meta = restore_backup(
        &state.config_store,
        &body,
        query.passphrase.as_deref(),
        subsystems_filter,
    )
    .map_err(BackupApiError::StorageError)?;

    info!(
        created_at = meta.created_at,
        subsystems = ?meta.subsystems,
        "backup restored via API"
    );

    Ok(Json(meta))
}

/// `GET /backup/scheduler`
///
/// Returns the current automatic backup scheduler configuration.
/// The `passphrase` field is always redacted in the response.
pub async fn get_scheduler_handler(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, BackupApiError> {
    let mut cfg = load_schedule(&state).map_err(BackupApiError::StorageError)?;
    cfg.passphrase = None;
    Ok(Json(cfg))
}

/// `POST /backup/scheduler`
///
/// Updates the automatic backup scheduler configuration.
pub async fn update_scheduler_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BackupScheduleConfig>,
) -> Result<impl IntoResponse, BackupApiError> {
    if req.interval_hours == 0 {
        return Err(BackupApiError::ValidationFailed(
            "interval_hours must be greater than 0".into(),
        ));
    }
    if req.retain_count == 0 {
        return Err(BackupApiError::ValidationFailed(
            "retain_count must be greater than 0".into(),
        ));
    }
    if req.encrypt && req.passphrase.as_deref().map(str::is_empty).unwrap_or(true) {
        return Err(BackupApiError::ValidationFailed(
            "passphrase is required when encrypt is true".into(),
        ));
    }

    save_schedule(&state, &req).map_err(BackupApiError::StorageError)?;

    info!(
        enabled = req.enabled,
        interval_hours = req.interval_hours,
        "backup scheduler config updated via API"
    );

    // Prune immediately if enabled.
    if req.enabled {
        let backup_dir = PathBuf::from(DEFAULT_BACKUP_DIR);
        if backup_dir.exists() {
            if let Err(e) = prune_backups(&backup_dir, req.retain_count) {
                warn!(error = %e, "failed to prune backups after scheduler update");
            }
        }
    }

    let mut resp = req;
    resp.passphrase = None;
    Ok(Json(resp))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the full path to a backup file, rejecting path traversal attempts.
fn safe_backup_path(filename: &str) -> Result<PathBuf, BackupApiError> {
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return Err(BackupApiError::ValidationFailed(
            "invalid backup filename".into(),
        ));
    }
    if !is_backup_filename(filename) {
        return Err(BackupApiError::ValidationFailed(
            "filename does not look like a DayShield backup".into(),
        ));
    }
    Ok(PathBuf::from(DEFAULT_BACKUP_DIR).join(filename))
}

/// Return `true` if `name` looks like a DayShield backup filename.
fn is_backup_filename(name: &str) -> bool {
    (name.starts_with("dayshield-backup-") && name.ends_with(".tar"))
        || (name.starts_with("dayshield-backup-") && name.ends_with(".tar.enc"))
}

/// Parse a comma-separated list of subsystem names.
fn parse_subsystem_list(s: &str) -> Result<Vec<Subsystem>, String> {
    s.split(',')
        .map(|item| {
            serde_json::from_value(serde_json::Value::String(item.trim().to_lowercase()))
                .map_err(|_| format!("unknown subsystem: {item}"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_backup_path_rejects_traversal() {
        assert!(safe_backup_path("../etc/passwd").is_err());
        assert!(safe_backup_path("../../secret").is_err());
    }

    #[test]
    fn safe_backup_path_rejects_non_backup_names() {
        assert!(safe_backup_path("config.json").is_err());
        assert!(safe_backup_path("random.tar").is_err());
    }

    #[test]
    fn safe_backup_path_accepts_valid_names() {
        assert!(safe_backup_path("dayshield-backup-1700000000.tar").is_ok());
        assert!(safe_backup_path("dayshield-backup-1700000000.tar.enc").is_ok());
    }

    #[test]
    fn parse_subsystem_list_valid() {
        let subs = parse_subsystem_list("dns,dhcp,firewall").unwrap();
        assert_eq!(subs.len(), 3);
        assert!(subs.contains(&Subsystem::Dns));
        assert!(subs.contains(&Subsystem::Dhcp));
        assert!(subs.contains(&Subsystem::Firewall));
    }

    #[test]
    fn parse_subsystem_list_invalid() {
        assert!(parse_subsystem_list("dns,nonexistent").is_err());
    }

    #[test]
    fn backup_api_error_status_codes() {
        use axum::response::IntoResponse;
        let e = BackupApiError::ValidationFailed("bad".into());
        assert_eq!(e.into_response().status(), StatusCode::UNPROCESSABLE_ENTITY);
        let e = BackupApiError::NotFound("x".into());
        assert_eq!(e.into_response().status(), StatusCode::NOT_FOUND);
        let e = BackupApiError::StorageError(anyhow::anyhow!("disk"));
        assert_eq!(e.into_response().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
