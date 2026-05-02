//! REST API handlers for the backup and restore subsystem.
//!
//! # Route summary
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | `POST`   | `/backup`                      | Create a new backup archive |
//! | `GET`    | `/backup`                      | List backup files on disk |
//! | `GET`    | `/backup/schedule`             | Get the backup schedule config |
//! | `POST`   | `/backup/schedule`             | Update the backup schedule config |
//! | `POST`   | `/backup/restore`              | Restore from an uploaded backup file |
//! | `GET`    | `/backup/{filename}`           | Download a backup file |
//! | `DELETE` | `/backup/{filename}`           | Delete a backup file |
//! | `GET`    | `/backup/{filename}/verify`    | Verify a backup file's integrity |
//! | `POST`   | `/backup/{filename}/restore`   | Restore from an existing on-disk backup |

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use tracing::{info, warn};

use crate::{
    backup::{
        create::{create_backup, DEFAULT_BACKUP_DIR},
        encrypt::decrypt,
        model::{BackupEntry, BackupMetadata, Subsystem},
        restore::restore_backup,
        scheduler::prune_old_backups,
        verify::verify_tar,
    },
    config::models::BackupScheduleConfig,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the backup API handlers.
#[derive(Debug, thiserror::Error)]
pub enum BackupApiError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("validation error: {0}")]
    ValidationFailed(String),

    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),
}

impl IntoResponse for BackupApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            BackupApiError::NotFound(_) => StatusCode::NOT_FOUND,
            BackupApiError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
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

/// Request body for `POST /backup`.
#[derive(serde::Deserialize)]
pub struct CreateBackupRequest {
    /// Which subsystems to include; omit to include all.
    pub subsystems: Option<Vec<Subsystem>>,
    /// Whether to encrypt the archive.
    #[serde(default)]
    pub encrypt: bool,
    /// Passphrase for encryption (required when `encrypt` is `true`).
    pub passphrase: Option<String>,
    /// Override the backup directory (defaults to `/etc/dayshield/backups`).
    pub backup_dir: Option<String>,
}

/// Response body for `POST /backup`.
#[derive(serde::Serialize)]
pub struct CreateBackupResponse {
    pub filename: String,
    pub metadata: BackupMetadata,
}

/// Request body for `POST /backup/schedule` and `POST /backup/{filename}/restore`.
#[derive(serde::Deserialize)]
pub struct PassphraseRequest {
    /// Decryption passphrase — required only when the archive is encrypted.
    pub passphrase: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /backup` — create a new backup archive.
pub async fn create_backup_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateBackupRequest>,
) -> Result<impl IntoResponse, BackupApiError> {
    if req.encrypt && req.passphrase.is_none() {
        return Err(BackupApiError::ValidationFailed(
            "passphrase is required when encrypt is true".into(),
        ));
    }

    let backup_dir = PathBuf::from(
        req.backup_dir
            .as_deref()
            .unwrap_or(DEFAULT_BACKUP_DIR),
    );

    let path = create_backup(
        req.subsystems,
        &state.config_store,
        req.encrypt,
        req.passphrase.as_deref(),
        &backup_dir,
    )
    .await?;

    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Re-read the archive to extract metadata for the response.
    let tar_bytes = if req.encrypt {
        let enc = std::fs::read(&path)?;
        decrypt(&enc, req.passphrase.as_deref().unwrap_or(""))
            .map_err(anyhow::Error::from)?
    } else {
        std::fs::read(&path)?
    };

    let metadata = verify_tar(&tar_bytes).map_err(anyhow::Error::from)?;

    info!(filename = %filename, "backup: create endpoint returned");
    Ok(Json(CreateBackupResponse { filename, metadata }))
}

/// `GET /backup` — list all backup files in the default backup directory.
pub async fn list_backups_handler(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, BackupApiError> {
    let schedule = state
        .config_store
        .load_backup_schedule()
        .map_err(anyhow::Error::from)?;

    let backup_dir = PathBuf::from(
        schedule
            .as_ref()
            .map(|s| s.backup_dir.as_str())
            .unwrap_or(DEFAULT_BACKUP_DIR),
    );

    let entries = list_backup_entries(&backup_dir)?;
    Ok(Json(entries))
}

/// `GET /backup/schedule` — return the current backup schedule configuration.
pub async fn get_schedule_handler(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, BackupApiError> {
    let schedule = state
        .config_store
        .load_backup_schedule()
        .map_err(anyhow::Error::from)?
        .unwrap_or_default();

    Ok(Json(schedule))
}

/// `POST /backup/schedule` — update the backup schedule configuration.
pub async fn update_schedule_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BackupScheduleConfig>,
) -> Result<impl IntoResponse, BackupApiError> {
    if req.enabled {
        if req.interval_hours == 0 {
            return Err(BackupApiError::ValidationFailed(
                "interval_hours must be greater than 0".into(),
            ));
        }
        if req.encrypt && req.passphrase.is_none() {
            return Err(BackupApiError::ValidationFailed(
                "passphrase is required when encrypt is true".into(),
            ));
        }
    }

    state
        .config_store
        .save_backup_schedule(req.clone())
        .map_err(anyhow::Error::from)?;

    info!(enabled = req.enabled, interval_hours = req.interval_hours, "backup: schedule updated");
    Ok(Json(req))
}

/// `POST /backup/restore` — restore from an uploaded backup file (raw bytes body).
///
/// The `X-Backup-Passphrase` request header supplies the decryption passphrase
/// for encrypted archives.
pub async fn restore_upload_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, BackupApiError> {
    let passphrase = headers
        .get("x-backup-passphrase")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let tar_bytes = maybe_decrypt(&body, passphrase.as_deref())?;

    let metadata = restore_backup(&tar_bytes, &state.config_store).map_err(anyhow::Error::from)?;

    info!("backup: restore from upload completed");
    Ok(Json(metadata))
}

/// `GET /backup/{filename}` — download a backup file.
pub async fn download_backup_handler(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> Result<Response, BackupApiError> {
    validate_filename(&filename)?;

    let backup_dir = resolve_backup_dir(&state)?;
    let path = backup_dir.join(&filename);

    if !path.exists() {
        return Err(BackupApiError::NotFound(format!(
            "backup file {filename} not found"
        )));
    }

    let bytes = std::fs::read(&path).map_err(|e| anyhow::anyhow!("Failed to read backup: {e}"))?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(axum::body::Body::from(bytes))
        .map_err(|e| anyhow::anyhow!("Failed to build response: {e}"))?;

    Ok(response)
}

/// `DELETE /backup/{filename}` — delete a backup file.
pub async fn delete_backup_handler(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> Result<impl IntoResponse, BackupApiError> {
    validate_filename(&filename)?;

    let backup_dir = resolve_backup_dir(&state)?;
    let path = backup_dir.join(&filename);

    if !path.exists() {
        return Err(BackupApiError::NotFound(format!(
            "backup file {filename} not found"
        )));
    }

    std::fs::remove_file(&path)
        .map_err(|e| anyhow::anyhow!("Failed to delete backup {filename}: {e}"))?;

    info!(filename = %filename, "backup: deleted");
    Ok(Json(serde_json::json!({ "status": "deleted", "filename": filename })))
}

/// `GET /backup/{filename}/verify` — verify the integrity of an on-disk backup.
///
/// The `X-Backup-Passphrase` header is required for encrypted archives.
pub async fn verify_backup_handler(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, BackupApiError> {
    validate_filename(&filename)?;

    let backup_dir = resolve_backup_dir(&state)?;
    let path = backup_dir.join(&filename);

    if !path.exists() {
        return Err(BackupApiError::NotFound(format!(
            "backup file {filename} not found"
        )));
    }

    let raw_bytes =
        std::fs::read(&path).map_err(|e| anyhow::anyhow!("Failed to read backup: {e}"))?;

    let passphrase = headers
        .get("x-backup-passphrase")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let tar_bytes = maybe_decrypt(&raw_bytes, passphrase.as_deref())?;

    let metadata = verify_tar(&tar_bytes).map_err(anyhow::Error::from)?;

    info!(filename = %filename, "backup: integrity verified");
    Ok(Json(serde_json::json!({
        "status": "ok",
        "filename": filename,
        "metadata": metadata,
    })))
}

/// `POST /backup/{filename}/restore` — restore from an existing on-disk backup.
pub async fn restore_from_disk_handler(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
    Json(req): Json<PassphraseRequest>,
) -> Result<impl IntoResponse, BackupApiError> {
    validate_filename(&filename)?;

    let backup_dir = resolve_backup_dir(&state)?;
    let path = backup_dir.join(&filename);

    if !path.exists() {
        return Err(BackupApiError::NotFound(format!(
            "backup file {filename} not found"
        )));
    }

    let raw_bytes =
        std::fs::read(&path).map_err(|e| anyhow::anyhow!("Failed to read backup: {e}"))?;

    let tar_bytes = maybe_decrypt(&raw_bytes, req.passphrase.as_deref())?;

    let metadata = restore_backup(&tar_bytes, &state.config_store).map_err(anyhow::Error::from)?;

    info!(filename = %filename, "backup: restore from disk completed");
    Ok(Json(metadata))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the backup directory from the stored schedule config or the default.
fn resolve_backup_dir(state: &AppState) -> Result<PathBuf, BackupApiError> {
    let schedule = state
        .config_store
        .load_backup_schedule()
        .map_err(anyhow::Error::from)?;

    Ok(PathBuf::from(
        schedule
            .as_ref()
            .map(|s| s.backup_dir.as_str())
            .unwrap_or(DEFAULT_BACKUP_DIR),
    ))
}

/// Build a list of [`BackupEntry`] objects from files in `backup_dir`.
fn list_backup_entries(backup_dir: &PathBuf) -> Result<Vec<BackupEntry>, BackupApiError> {
    if !backup_dir.exists() {
        return Ok(vec![]);
    }

    let mut entries: Vec<BackupEntry> = std::fs::read_dir(backup_dir)
        .map_err(|e| anyhow::anyhow!("Failed to read backup directory: {e}"))?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            let filename = path.file_name()?.to_string_lossy().into_owned();
            if !filename.ends_with("_backup.tar") && !filename.ends_with("_backup.tar.enc") {
                return None;
            }
            let size_bytes = e.metadata().ok()?.len();

            // Try to peek inside unencrypted archives for metadata.
            let metadata = if !filename.ends_with(".enc") {
                std::fs::read(&path)
                    .ok()
                    .and_then(|b| verify_tar(&b).ok())
            } else {
                None // Cannot inspect encrypted archives without a passphrase.
            };

            Some(BackupEntry {
                filename,
                size_bytes,
                metadata,
            })
        })
        .collect();

    // Sort newest-first by filename (which starts with a Unix timestamp).
    entries.sort_by(|a, b| b.filename.cmp(&a.filename));

    Ok(entries)
}

/// If `passphrase` is provided, decrypt `data`; otherwise return it as-is.
fn maybe_decrypt(data: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, BackupApiError> {
    if let Some(pass) = passphrase {
        decrypt(data, pass)
            .map_err(|e| BackupApiError::ValidationFailed(format!("Decryption failed: {e}")))
    } else {
        Ok(data.to_vec())
    }
}

/// Validate that `filename` is a safe basename (no directory separators).
fn validate_filename(filename: &str) -> Result<(), BackupApiError> {
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return Err(BackupApiError::ValidationFailed(
            "filename must not contain path separators or '..'".into(),
        ));
    }
    if !filename.ends_with("_backup.tar") && !filename.ends_with("_backup.tar.enc") {
        return Err(BackupApiError::ValidationFailed(
            "filename must match the pattern <timestamp>_backup.{tar,tar.enc}".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_filename_rejects_path_traversal() {
        assert!(validate_filename("../etc/passwd_backup.tar").is_err());
        assert!(validate_filename("/etc/passwd_backup.tar").is_err());
        assert!(validate_filename("../_backup.tar").is_err());
    }

    #[test]
    fn validate_filename_rejects_wrong_extension() {
        assert!(validate_filename("123456789_backup.zip").is_err());
        assert!(validate_filename("123456789_other.tar").is_err());
    }

    #[test]
    fn validate_filename_accepts_valid_names() {
        assert!(validate_filename("1714600000_backup.tar").is_ok());
        assert!(validate_filename("1714600000_backup.tar.enc").is_ok());
    }

    #[test]
    fn backup_api_error_status_codes() {
        let not_found = BackupApiError::NotFound("x".into()).into_response();
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

        let validation = BackupApiError::ValidationFailed("y".into()).into_response();
        assert_eq!(validation.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let storage =
            BackupApiError::StorageError(anyhow::anyhow!("disk error")).into_response();
        assert_eq!(storage.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
