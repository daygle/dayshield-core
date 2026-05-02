//! SHA-256 integrity verification for backup archives.
//!
//! # Canonical hash
//!
//! To avoid the chicken-and-egg problem of hashing a TAR that already contains
//! the hash, the SHA-256 digest is computed over the **config payload only**
//! (the `config/*.json` files inside the archive), not the metadata entry.
//!
//! The canonical form used as input to SHA-256 is:
//!
//! ```text
//! For each (filename, content) pair, sorted lexicographically by filename:
//!     SHA-256_of_filename_bytes ++ ":" ++ SHA-256_of_file_content_bytes ++ "\n"
//! ```
//!
//! This design is deterministic, independent of file ordering in the archive,
//! and allows verification without re-serialising the config.

use std::collections::BTreeMap;
use std::io::Read;

use anyhow::Result;
use sha2::{Digest, Sha256};

use super::model::BackupMetadata;

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

/// Compute the canonical SHA-256 hex digest over a sorted map of config files.
///
/// Iterates `files` in sorted key order.  For each `(name, bytes)` pair it
/// hashes `SHA256(name) + ":" + SHA256(bytes) + "\n"` into a running hasher
/// and returns the final hex-encoded digest.
pub fn compute_sha256(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut outer = Sha256::new();
    for (name, bytes) in files {
        let name_hash = hex::encode(Sha256::digest(name.as_bytes()));
        let data_hash = hex::encode(Sha256::digest(bytes));
        outer.update(name_hash.as_bytes());
        outer.update(b":");
        outer.update(data_hash.as_bytes());
        outer.update(b"\n");
    }
    hex::encode(outer.finalize())
}

// ---------------------------------------------------------------------------
// Archive verification
// ---------------------------------------------------------------------------

/// Verify the integrity of a (already-decrypted) TAR archive and return its
/// [`BackupMetadata`].
///
/// # Steps
///
/// 1. Read all entries from the TAR.
/// 2. Parse `metadata.json` into [`BackupMetadata`].
/// 3. Collect all `config/*.json` entries into a [`BTreeMap`].
/// 4. Compute the canonical SHA-256 and compare with `metadata.sha256`.
/// 5. Return `Ok(metadata)` on success, or an error describing the first
///    failure.
pub fn verify_tar(tar_bytes: &[u8]) -> Result<BackupMetadata> {
    let (metadata, files) = read_tar(tar_bytes)?;

    let metadata = metadata
        .ok_or_else(|| anyhow::anyhow!("Backup archive is missing metadata.json"))?;

    let computed = compute_sha256(&files);
    anyhow::ensure!(
        computed == metadata.sha256,
        "SHA-256 integrity check failed: expected {}, computed {}",
        metadata.sha256,
        computed
    );

    Ok(metadata)
}

/// Read a TAR archive and return `(metadata, config_files)`.
///
/// `metadata` is `None` when `metadata.json` is absent from the archive.
/// `config_files` is a sorted map of `config/<name>` → file bytes.
pub fn read_tar(
    tar_bytes: &[u8],
) -> Result<(Option<BackupMetadata>, BTreeMap<String, Vec<u8>>)> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let mut metadata: Option<BackupMetadata> = None;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.to_string_lossy().into_owned();
        // Normalise the path by stripping any leading `./`.
        let path = raw_path
            .strip_prefix("./")
            .unwrap_or(&raw_path)
            .to_string();

        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;

        if path == "metadata.json" {
            let m: BackupMetadata = serde_json::from_slice(&contents)
                .map_err(|e| anyhow::anyhow!("Failed to parse metadata.json: {e}"))?;
            metadata = Some(m);
        } else if path.starts_with("config/") {
            files.insert(path, contents);
        }
    }

    Ok((metadata, files))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_files(pairs: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_vec()))
            .collect()
    }

    #[test]
    fn sha256_empty_map_is_deterministic() {
        let files = BTreeMap::new();
        let h1 = compute_sha256(&files);
        let h2 = compute_sha256(&files);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // 32-byte SHA-256 → 64 hex chars
    }

    #[test]
    fn sha256_order_independent() {
        let files_a = make_files(&[("config/a.json", b"aaa"), ("config/b.json", b"bbb")]);
        // BTreeMap guarantees sorted iteration, so adding in reverse order
        // still gives the same digest.
        let mut files_b = BTreeMap::new();
        files_b.insert("config/b.json".to_string(), b"bbb".to_vec());
        files_b.insert("config/a.json".to_string(), b"aaa".to_vec());

        assert_eq!(compute_sha256(&files_a), compute_sha256(&files_b));
    }

    #[test]
    fn sha256_different_content_gives_different_digest() {
        let a = make_files(&[("config/x.json", b"v1")]);
        let b = make_files(&[("config/x.json", b"v2")]);
        assert_ne!(compute_sha256(&a), compute_sha256(&b));
    }
}
