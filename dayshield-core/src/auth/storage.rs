//! User storage — persist the admin account to `/etc/dayshield/admin.json`.
//!
//! # Guarantees
//!
//! - **Atomic writes**: new content is written to a sibling `.tmp` file and
//!   then renamed into place, so a mid-write crash cannot corrupt the record.
//! - **Directory creation**: the `/etc/dayshield` directory is created if it
//!   does not exist.
//!
//! # File layout
//!
//! The file contains a single JSON object that serialises [`User`]:
//!
//! ```json
//! {
//!   "username": "admin",
//!   "password_hash": "$argon2id$v=19$…",
//!   "created_at": 1710000000
//! }
//! ```

use std::path::{Path, PathBuf};

use crate::auth::model::{AuthError, User};

// ---------------------------------------------------------------------------
// Permission-aware write helper
// ---------------------------------------------------------------------------

/// Write `data` to `path` with mode 0o600 (owner read/write only).
#[cfg(unix)]
fn write_restricted_auth(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_restricted_auth(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, data)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default path to the persisted admin user record.
pub const DEFAULT_ADMIN_PATH: &str = "/etc/dayshield/admin.json";

// ---------------------------------------------------------------------------
// UserStore
// ---------------------------------------------------------------------------

/// Manages loading and saving the single admin [`User`] record.
pub struct UserStore {
    path: PathBuf,
}

impl UserStore {
    /// Create a [`UserStore`] that reads/writes the default path.
    pub fn new() -> Self {
        Self::with_path(DEFAULT_ADMIN_PATH)
    }

    /// Create a [`UserStore`] that reads/writes a custom path (useful in
    /// tests that must not touch `/etc`).
    pub fn with_path(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Return the filesystem path managed by this store.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Default for UserStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Load the admin [`User`] from `path`.
///
/// Returns `None` when the file does not yet exist (first-time setup).
pub fn load_user(path: &Path) -> Result<Option<User>, AuthError> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|e| AuthError::StorageError(format!("read admin.json: {e}")))?;

    let user: User = serde_json::from_str(&raw)
        .map_err(|e| AuthError::StorageError(format!("parse admin.json: {e}")))?;

    Ok(Some(user))
}

/// Persist `user` to `path` using an atomic write with mode 0o600.
///
/// The directory is created if it does not exist.
pub fn save_user(path: &Path, user: &User) -> Result<(), AuthError> {
    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| AuthError::StorageError(format!("create dir: {e}")))?;
    }

    let json = serde_json::to_string_pretty(user)
        .map_err(|e| AuthError::StorageError(format!("serialise user: {e}")))?;

    // Write to a temporary sibling file with restricted permissions, then
    // rename atomically so the admin credentials file is owner-read/write only.
    let tmp_path = {
        let mut name = path
            .file_name()
            .unwrap_or_default()
            .to_os_string();
        name.push(".tmp");
        path.with_file_name(name)
    };

    write_restricted_auth(&tmp_path, json.as_bytes())
        .map_err(|e| AuthError::StorageError(format!("write tmp file: {e}")))?;

    std::fs::rename(&tmp_path, path)
        .map_err(|e| AuthError::StorageError(format!("atomic rename: {e}")))?;

    Ok(())
}

/// Replace the admin user's password hash with `new_hash` and persist.
pub fn update_password(path: &Path, new_hash: &str) -> Result<(), AuthError> {
    let mut user = load_user(path)?.ok_or_else(|| {
        AuthError::StorageError("admin user does not exist; cannot update password".into())
    })?;

    user.password_hash = new_hash.to_string();
    save_user(path, &user)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::model::User;

    fn make_user() -> User {
        User::new("admin", "$argon2id$v=19$m=256,t=1,p=1$dGVzdA$placeholder")
    }

    #[test]
    fn roundtrip_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.json");

        let user = make_user();
        save_user(&path, &user).expect("save must succeed");

        let loaded = load_user(&path)
            .expect("load must succeed")
            .expect("user must be present");

        assert_eq!(loaded.username, "admin");
        assert_eq!(loaded.password_hash, user.password_hash);
    }

    #[test]
    fn load_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.json");
        let result = load_user(&path).expect("load must succeed");
        assert!(result.is_none());
    }

    #[test]
    fn update_password_changes_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.json");

        save_user(&path, &make_user()).expect("save must succeed");
        update_password(&path, "$argon2id$v=19$m=256,t=1,p=1$new$hash")
            .expect("update must succeed");

        let loaded = load_user(&path).unwrap().unwrap();
        assert_eq!(
            loaded.password_hash,
            "$argon2id$v=19$m=256,t=1,p=1$new$hash"
        );
    }

    #[test]
    fn update_password_fails_when_no_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.json");
        let result = update_password(&path, "new-hash");
        assert!(matches!(result, Err(AuthError::StorageError(_))));
    }

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir").join("admin.json");
        save_user(&path, &make_user()).expect("save in sub-dir must succeed");
        assert!(path.exists());
    }
}
