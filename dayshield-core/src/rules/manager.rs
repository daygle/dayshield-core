//! Managed Suricata ruleset manager.
//!
//! Implements install, update, enable, disable, and remove operations for
//! curated Suricata rulesets.
//!
//! # Download strategy
//!
//! URLs ending in `.tar.gz` or `.tgz` are downloaded as archives and all
//! `.rules` files inside are concatenated into a single `suricata.rules` file.
//! Plain `.rules` URLs are downloaded directly.
//!
//! # Safe update flow
//!
//! 1. Download to a temp file (`suricata.rules.tmp`).
//! 2. Validate basic structure (must contain at least one non-comment line).
//! 3. Atomically rename the temp file over the live file.
//! 4. On any failure the existing live file is left untouched.
//!
//! # Suricata integration
//!
//! Enabling a ruleset calls [`crate::engine::suricata::apply_config`] to
//! regenerate `suricata.yaml` (which automatically includes all enabled
//! managed rulesets via the `apply_config` path).  The same happens on
//! disable.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use flate2::read::GzDecoder;
use tar::Archive;
use tracing::{info, warn};

use crate::config::storage::ConfigStore;
use crate::engine::suricata::apply_config;
use crate::rules::models::{CuratedSource, InstalledRuleset, RulesetStatus};
use crate::rules::sources::curated_sources;
use crate::rules::storage::RulesetStore;

// ---------------------------------------------------------------------------
// RulesetManager
// ---------------------------------------------------------------------------

/// Provides install / update / enable / disable operations for managed rulesets.
pub struct RulesetManager {
    store: RulesetStore,
    /// Path to the DayShield config directory (used to load the Suricata config
    /// so we can re-apply it after enable/disable changes).
    config_dir: PathBuf,
}

impl RulesetManager {
    /// Create a manager backed by production paths.
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        Self {
            store: RulesetStore::new(),
            config_dir: config_dir.as_ref().to_path_buf(),
        }
    }

    /// Create a manager with custom directories (useful for tests).
    pub fn with_dirs(config_dir: impl AsRef<Path>, rulesets_dir: impl AsRef<Path>) -> Self {
        Self {
            store: RulesetStore::with_dir(rulesets_dir),
            config_dir: config_dir.as_ref().to_path_buf(),
        }
    }

    // -----------------------------------------------------------------------
    // Public operations
    // -----------------------------------------------------------------------

    /// Return all installed rulesets.
    pub fn list_installed(&self) -> Result<Vec<InstalledRuleset>> {
        self.store.load()
    }

    /// Install a curated ruleset by id.
    ///
    /// Downloads the ruleset from its configured URL, validates it, and stores
    /// it under the managed directory.  If the ruleset was already installed
    /// this is equivalent to a forced update.
    pub async fn install(&self, id: &str) -> Result<InstalledRuleset> {
        let source = find_source(id)?;
        info!(id, url = %source.url, "rulesets: installing");

        let mut rulesets = self.store.load()?;

        // Mark as installing (in memory only; we persist after success/failure).
        let idx = rulesets.iter().position(|r| r.id == id);

        let rules_path = self.store.rules_file(id);

        // Perform the download + install.
        match self.download_and_install(&source, &rules_path).await {
            Ok(version) => {
                let local_path = rules_path.to_string_lossy().into_owned();
                let now = Utc::now();

                let ruleset = InstalledRuleset {
                    id: id.to_string(),
                    display_name: source.display_name.clone(),
                    source_url: source.url.clone(),
                    installed_version: version.clone(),
                    latest_version: version,
                    enabled: false, // disabled by default; user must explicitly enable
                    status: RulesetStatus::Installed,
                    last_error: None,
                    last_checked: Some(now),
                    last_updated: Some(now),
                    local_path: Some(local_path),
                };

                if let Some(i) = idx {
                    // Preserve enabled state from previous install.
                    let was_enabled = rulesets[i].enabled;
                    rulesets[i] = ruleset.clone();
                    rulesets[i].enabled = was_enabled;
                } else {
                    rulesets.push(ruleset.clone());
                }

                self.store.save(&rulesets)?;
                info!(id, "rulesets: install complete");
                Ok(rulesets.iter().find(|r| r.id == id).cloned().unwrap_or(ruleset))
            }
            Err(e) => {
                warn!(id, error = %e, "rulesets: install failed");
                let error_msg = e.to_string();

                if let Some(i) = idx {
                    rulesets[i].status = RulesetStatus::Failed;
                    rulesets[i].last_error = Some(error_msg.clone());
                    self.store.save(&rulesets)?;
                    Ok(rulesets[i].clone())
                } else {
                    // First install failed – store a failure record.
                    let failed = InstalledRuleset {
                        id: id.to_string(),
                        display_name: source.display_name.clone(),
                        source_url: source.url.clone(),
                        installed_version: None,
                        latest_version: None,
                        enabled: false,
                        status: RulesetStatus::Failed,
                        last_error: Some(error_msg),
                        last_checked: None,
                        last_updated: None,
                        local_path: None,
                    };
                    rulesets.push(failed.clone());
                    self.store.save(&rulesets)?;
                    Ok(failed)
                }
            }
        }
    }

    /// Check whether a newer version of the ruleset is available.
    ///
    /// Sends a HEAD request (with `If-None-Match` / `If-Modified-Since` headers
    /// when applicable) and compares ETags / Last-Modified values.
    pub async fn check_update(&self, id: &str) -> Result<InstalledRuleset> {
        let mut rulesets = self.store.load()?;
        let idx = rulesets.iter().position(|r| r.id == id)
            .with_context(|| format!("ruleset '{id}' is not installed"))?;

        let source_url = rulesets[idx].source_url.clone();
        let installed_version = rulesets[idx].installed_version.clone();

        info!(id, "rulesets: checking for updates");

        let client = reqwest::Client::builder()
            .user_agent("dayshield-core/1.0")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("failed to build HTTP client")?;

        let mut req = client.head(&source_url);
        if let Some(ref etag) = installed_version {
            req = req.header("If-None-Match", etag.as_str());
        }

        let response = req.send().await.context("HEAD request failed")?;
        let now = Utc::now();

        let latest_version = version_from_response(response.headers());

        let update_available = latest_version
            .as_ref()
            .map(|lv| Some(lv) != installed_version.as_ref())
            .unwrap_or(false);

        rulesets[idx].last_checked = Some(now);
        rulesets[idx].latest_version = latest_version;
        if update_available {
            rulesets[idx].status = RulesetStatus::UpdateAvailable;
        }

        self.store.save(&rulesets)?;
        info!(id, update_available, "rulesets: update check complete");
        Ok(rulesets[idx].clone())
    }

    /// Check for updates on all installed rulesets.
    pub async fn check_all_updates(&self) -> Result<Vec<InstalledRuleset>> {
        let rulesets = self.store.load()?;
        let mut results = Vec::new();
        for rs in &rulesets {
            match self.check_update(&rs.id).await {
                Ok(updated) => results.push(updated),
                Err(e) => {
                    warn!(id = rs.id, error = %e, "rulesets: update check failed");
                    results.push(rs.clone());
                }
            }
        }
        Ok(results)
    }

    /// Apply an available update for an installed ruleset.
    ///
    /// The existing rules file is preserved until the new download has been
    /// fully validated; on failure the previous version stays active.
    pub async fn update(&self, id: &str) -> Result<InstalledRuleset> {
        // Re-using install; it already handles the safe swap.
        let mut result = self.install(id).await?;

        // If the ruleset was enabled, re-apply the Suricata config so that
        // Suricata picks up the new rules.
        if result.enabled {
            if let Err(e) = self.apply_suricata_config().await {
                warn!(id, error = %e, "rulesets: suricata reload after update failed");
            }
        }

        // Reload to get the freshest metadata.
        let rulesets = self.store.load()?;
        if let Some(r) = rulesets.iter().find(|r| r.id == id) {
            result = r.clone();
        }
        Ok(result)
    }

    /// Enable an installed ruleset so Suricata includes it in its rule set.
    pub async fn enable(&self, id: &str) -> Result<InstalledRuleset> {
        let mut rulesets = self.store.load()?;
        let idx = rulesets.iter().position(|r| r.id == id)
            .with_context(|| format!("ruleset '{id}' is not installed"))?;

        if rulesets[idx].local_path.is_none() {
            bail!("ruleset '{id}' has no local rules file; try installing it first");
        }

        rulesets[idx].enabled = true;
        self.store.save(&rulesets)?;

        // Regenerate and apply the Suricata configuration.
        if let Err(e) = self.apply_suricata_config().await {
            warn!(id, error = %e, "rulesets: suricata reload after enable failed");
        }

        info!(id, "rulesets: enabled");
        Ok(rulesets[idx].clone())
    }

    /// Disable an installed ruleset so Suricata no longer includes it.
    pub async fn disable(&self, id: &str) -> Result<InstalledRuleset> {
        let mut rulesets = self.store.load()?;
        let idx = rulesets.iter().position(|r| r.id == id)
            .with_context(|| format!("ruleset '{id}' is not installed"))?;

        rulesets[idx].enabled = false;
        self.store.save(&rulesets)?;

        // Regenerate and apply the Suricata configuration.
        if let Err(e) = self.apply_suricata_config().await {
            warn!(id, error = %e, "rulesets: suricata reload after disable failed");
        }

        info!(id, "rulesets: disabled");
        Ok(rulesets[idx].clone())
    }

    /// Remove an installed ruleset from disk and metadata.
    ///
    /// The ruleset is automatically disabled before removal so Suricata no
    /// longer references the deleted file.
    pub async fn uninstall(&self, id: &str) -> Result<()> {
        // Disable first to update suricata config.
        let _ = self.disable(id).await;

        let mut rulesets = self.store.load()?;
        let Some(idx) = rulesets.iter().position(|r| r.id == id) else {
            return Ok(()); // already gone
        };

        // Remove the local rules file and directory.
        let ruleset_dir = self.store.ruleset_dir(id);
        if ruleset_dir.exists() {
            std::fs::remove_dir_all(&ruleset_dir)
                .with_context(|| format!("failed to remove {}", ruleset_dir.display()))?;
        }

        rulesets.remove(idx);
        self.store.save(&rulesets)?;
        info!(id, "rulesets: uninstalled");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Download a ruleset from its source URL and write the combined rules to
    /// the given destination path atomically.
    ///
    /// Returns the version string (ETag or Last-Modified) from the HTTP response.
    async fn download_and_install(
        &self,
        source: &CuratedSource,
        dest: &Path,
    ) -> Result<Option<String>> {
        if is_blocked_suricata_ruleset_url(&source.url) {
            bail!(
                "ruleset source '{}' is incompatible: Suricata 7.0 feeds are not supported on this appliance",
                source.url
            );
        }

        let client = reqwest::Client::builder()
            .user_agent("dayshield-core/1.0")
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .context("failed to build HTTP client")?;

        let response = client
            .get(&source.url)
            .send()
            .await
            .context("failed to start download")?;

        if !response.status().is_success() {
            bail!("download failed with HTTP {}", response.status());
        }

        let version = version_from_response(response.headers());

        let bytes = response
            .bytes()
            .await
            .context("failed to download ruleset bytes")?;

        info!(id = source.id, bytes = bytes.len(), "rulesets: downloaded");

        // Ensure the destination directory exists.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let tmp_dest = dest.with_extension("rules.tmp");

        let url_lower = source.url.to_lowercase();
        if url_lower.ends_with(".tar.gz") || url_lower.ends_with(".tgz") {
            // Extract .rules files from tar.gz, concatenate into combined file.
            install_from_targz(&bytes, &tmp_dest)
                .context("failed to extract rules from tar.gz")?;
        } else {
            // Plain .rules file – write directly.
            std::fs::write(&tmp_dest, &bytes)
                .context("failed to write rules file")?;
        }

        // Basic validation: must contain at least one non-comment, non-blank line.
        validate_rules_file(&tmp_dest)
            .context("downloaded rules file failed validation")?;

        // Atomic rename.
        std::fs::rename(&tmp_dest, dest)
            .with_context(|| format!("failed to rename {} to {}", tmp_dest.display(), dest.display()))?;

        Ok(version)
    }

    /// Load the current Suricata config and re-apply it.
    ///
    /// The `apply_config` function in [`crate::engine::suricata`] automatically
    /// reads all enabled managed rulesets and includes their paths in the
    /// generated `suricata.yaml`.
    /// List all rules in a ruleset with their enabled/disabled state.
    pub fn list_rules(&self, id: &str) -> Result<Vec<crate::rules::models::Rule>> {
        let rules_path = self.store.rules_file(id);
        if !rules_path.exists() {
            bail!("ruleset '{}' rules file not found", id);
        }

        let content = std::fs::read_to_string(&rules_path)
            .context("failed to read rules file")?;

        let disabled = self.load_disabled_rules(id)?;
        let disabled_set: std::collections::HashSet<_> = disabled.ids.into_iter().collect();

        let rules = parse_rules(&content, &disabled_set);
        Ok(rules)
    }

    /// Load the set of disabled rule IDs for a ruleset.
    pub fn load_disabled_rules(&self, id: &str) -> Result<crate::rules::models::DisabledRules> {
        let disabled_path = self.store.ruleset_dir(id).join("disabled-rules.json");
        if !disabled_path.exists() {
            return Ok(crate::rules::models::DisabledRules::default());
        }

        let content = std::fs::read_to_string(&disabled_path)
            .context("failed to read disabled-rules.json")?;
        let disabled = serde_json::from_str(&content)
            .context("failed to parse disabled-rules.json")?;
        Ok(disabled)
    }

    /// Save the set of disabled rule IDs for a ruleset.
    pub fn save_disabled_rules(&self, id: &str, disabled: &crate::rules::models::DisabledRules) -> Result<()> {
        let disabled_path = self.store.ruleset_dir(id).join("disabled-rules.json");
        std::fs::create_dir_all(disabled_path.parent().unwrap())?;
        let json = serde_json::to_string_pretty(disabled)?;
        std::fs::write(&disabled_path, json)
            .context("failed to write disabled-rules.json")?;
        Ok(())
    }

    /// Regenerate the effective rules file, filtering out disabled rules.
    /// This updates the main rules file that Suricata uses.
    pub fn regenerate_effective_rules(&self, id: &str) -> Result<()> {
        let rules_path = self.store.rules_file(id);
        if !rules_path.exists() {
            return Ok(());
        }

        // Read the original rules file
        let original_content = std::fs::read_to_string(&rules_path)
            .context("failed to read rules file")?;

        // Load disabled rules
        let disabled = self.load_disabled_rules(id)?;
        let disabled_set: std::collections::HashSet<_> = disabled.ids.into_iter().collect();

        // Filter rules: keep only those that are not disabled
        let filtered_lines: Vec<&str> = original_content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                
                // Always keep empty lines, comments, and file headers
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return true;
                }

                // Check if this rule is disabled
                if let Some(sid_start) = trimmed.find("sid:") {
                    let after_sid = &trimmed[sid_start + 4..];
                    if let Some(sid_end) = after_sid.find(|c| !char::is_numeric(c)) {
                        let rule_id = &after_sid[..sid_end];
                        if disabled_set.contains(rule_id) {
                            return false; // Exclude this disabled rule
                        }
                    }
                }

                true
            })
            .collect();

        // Write the filtered content back
        let filtered_content = filtered_lines.join("\n");
        std::fs::write(&rules_path, filtered_content)
            .context("failed to write filtered rules file")?;

        Ok(())
    }

    pub async fn apply_suricata_config(&self) -> Result<()> {
        let cs = ConfigStore::with_dir(&self.config_dir);
        let cfg = cs
            .load_suricata_config()
            .context("failed to load suricata config")?;

        let cfg = cfg.unwrap_or_else(|| crate::config::models::SuricataConfig {
            enabled: false,
            interfaces: vec![],
            mode: "ids".to_string(),
            home_nets: vec![],
            external_nets: vec![],
            rule_sources: vec![],
            eve_log_enabled: false,
            eve_log_path: "/var/log/suricata/eve.json".into(),
            stats_log_enabled: false,
            stats_log_path: "/var/log/suricata/stats.log".into(),
            stats_interval_seconds: 0,
        });

        apply_config(&cfg).await
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Parse individual rules from a rules file content.
/// Returns rules with enabled flag based on disabled_set.
fn parse_rules(content: &str, disabled_set: &std::collections::HashSet<String>) -> Vec<crate::rules::models::Rule> {
    let mut rules = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Try to parse Suricata rule
        // Format: action proto src_ip src_port -> dst_ip dst_port (options...)
        if let Some((action, rest)) = trimmed.split_once(' ') {
            // Extract rule ID from the options section
            if let Some(sid_start) = rest.find("sid:") {
                let after_sid = &rest[sid_start + 4..];
                if let Some(sid_end) = after_sid.find(|c| !char::is_numeric(c)) {
                    let rule_id = after_sid[..sid_end].to_string();
                    let is_enabled = !disabled_set.contains(&rule_id);

                    // Extract signature/message from msg: field
                    let signature = if let Some(msg_start) = rest.find("msg:\"") {
                        let after_msg = &rest[msg_start + 5..];
                        if let Some(msg_end) = after_msg.find('"') {
                            after_msg[..msg_end].to_string()
                        } else {
                            rule_id.clone()
                        }
                    } else {
                        rule_id.clone()
                    };

                    rules.push(crate::rules::models::Rule {
                        id: rule_id,
                        action: action.to_string(),
                        signature,
                        enabled: is_enabled,
                        raw: trimmed.to_string(),
                    });
                }
            }
        }
    }

    rules
}

// ---------------------------------------------------------------------------

/// Return true when the URL clearly targets a Suricata 7.x feed.
fn is_blocked_suricata_ruleset_url(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    u.contains("suricata-7.0") || u.contains("/suricata-7/") || u.contains("suricata-7.")
}

// ---------------------------------------------------------------------------

/// Find a curated source by id.
fn find_source(id: &str) -> Result<CuratedSource> {
    let normalized_id = match id {
        // Backward compatibility: older installs may have used this curated id.
        "et-open-6" => "et-open",
        other => other,
    };

    curated_sources()
        .into_iter()
        .find(|s| s.id == normalized_id)
        .with_context(|| format!("unknown curated ruleset source: '{id}'"))
}

/// Extract a version tag from HTTP response headers.
///
/// Priority: `ETag` → `Last-Modified` → `None`.
fn version_from_response(headers: &reqwest::header::HeaderMap) -> Option<String> {
    if let Some(etag) = headers.get(reqwest::header::ETAG) {
        return etag.to_str().ok().map(str::to_owned);
    }
    if let Some(lm) = headers.get(reqwest::header::LAST_MODIFIED) {
        return lm.to_str().ok().map(str::to_owned);
    }
    None
}

/// Extract all `.rules` files from a `tar.gz` byte slice, concatenate them,
/// and write the result to `dest`.
fn install_from_targz(data: &[u8], dest: &Path) -> Result<()> {
    let decoder = GzDecoder::new(data);
    let mut archive = Archive::new(decoder);

    let mut outfile = std::fs::File::create(dest)
        .with_context(|| format!("failed to create {}", dest.display()))?;

    let mut rule_count = 0usize;

    for entry in archive.entries().context("failed to read tar archive")? {
        let mut entry = entry.context("bad tar entry")?;
        let path = entry.path().context("bad entry path")?;

        let is_rules = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("rules"))
            .unwrap_or(false);

        if !is_rules {
            continue;
        }

        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
        writeln!(outfile, "# --- {fname} ---")
            .context("failed to write rules header")?;

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).context("failed to read tar entry")?;
        outfile.write_all(&buf).context("failed to write rules body")?;

        // Ensure each file ends with a newline.
        if buf.last() != Some(&b'\n') {
            writeln!(outfile).context("failed to write trailing newline")?;
        }

        rule_count += 1;
    }

    if rule_count == 0 {
        bail!("tar archive contained no .rules files");
    }

    info!(rule_files = rule_count, path = %dest.display(), "rulesets: extracted rules from tar.gz");
    Ok(())
}

/// Basic validation of a rules file: at least one non-comment, non-blank line.
fn validate_rules_file(path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let has_content = content
        .lines()
        .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'));

    if !has_content {
        bail!("rules file appears to be empty or contains only comments");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::models::RulesetStatus;
    use tempfile::TempDir;

    // -------------------------------------------------------------------
    // install_from_targz
    // -------------------------------------------------------------------

    fn make_targz(rules: &[(&str, &str)]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let gz_buf = Vec::new();
        let enc = GzEncoder::new(gz_buf, Compression::default());
        let mut tar = tar::Builder::new(enc);

        for (name, content) in rules {
            let bytes = content.as_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, bytes).unwrap();
        }

        tar.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn extract_rules_from_targz() {
        let data = make_targz(&[
            ("emerging-malware.rules", "alert tcp any any -> any any (msg:\"test\"; sid:1;)\n"),
            ("emerging-scan.rules", "alert tcp any any -> any any (msg:\"scan\"; sid:2;)\n"),
            ("not-rules.txt", "ignored"),
        ]);

        let dir = TempDir::new().unwrap();
        let dest = dir.path().join("suricata.rules");
        install_from_targz(&data, &dest).unwrap();

        let content = std::fs::read_to_string(&dest).unwrap();
        assert!(content.contains("emerging-malware.rules"));
        assert!(content.contains("sid:1"));
        assert!(content.contains("emerging-scan.rules"));
        assert!(content.contains("sid:2"));
        // Plain text file should not appear
        assert!(!content.contains("ignored"));
    }

    #[test]
    fn extract_targz_fails_if_no_rules_files() {
        let data = make_targz(&[("readme.txt", "no rules here")]);
        let dir = TempDir::new().unwrap();
        let dest = dir.path().join("suricata.rules");
        let result = install_from_targz(&data, &dest);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // validate_rules_file
    // -------------------------------------------------------------------

    #[test]
    fn validate_passes_with_rule_content() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.rules");
        std::fs::write(&path, "alert tcp any any -> any any (msg:\"test\"; sid:1;)\n").unwrap();
        assert!(validate_rules_file(&path).is_ok());
    }

    #[test]
    fn validate_fails_on_empty_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.rules");
        std::fs::write(&path, "").unwrap();
        assert!(validate_rules_file(&path).is_err());
    }

    #[test]
    fn validate_fails_on_comments_only() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("comments.rules");
        std::fs::write(&path, "# This is a comment\n# Another comment\n").unwrap();
        assert!(validate_rules_file(&path).is_err());
    }

    // -------------------------------------------------------------------
    // version_from_response
    // -------------------------------------------------------------------

    #[test]
    fn version_prefers_etag_over_last_modified() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ETAG,
            "\"abc123\"".parse().unwrap(),
        );
        headers.insert(
            reqwest::header::LAST_MODIFIED,
            "Wed, 01 Jan 2025 00:00:00 GMT".parse().unwrap(),
        );
        let v = version_from_response(&headers);
        assert_eq!(v.as_deref(), Some("\"abc123\""));
    }

    #[test]
    fn version_falls_back_to_last_modified() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::LAST_MODIFIED,
            "Wed, 01 Jan 2025 00:00:00 GMT".parse().unwrap(),
        );
        let v = version_from_response(&headers);
        assert!(v.is_some());
        assert!(v.unwrap().contains("2025"));
    }

    #[test]
    fn version_returns_none_when_no_headers() {
        let headers = reqwest::header::HeaderMap::new();
        assert!(version_from_response(&headers).is_none());
    }

    // -------------------------------------------------------------------
    // find_source
    // -------------------------------------------------------------------

    #[test]
    fn find_source_returns_et_open() {
        let src = find_source("et-open").unwrap();
        assert_eq!(src.id, "et-open");
        assert!(src.url.contains("emergingthreats.net"));
    }

    #[test]
    fn find_source_maps_legacy_et_open_6_to_et_open() {
        let src = find_source("et-open-6").unwrap();
        assert_eq!(src.id, "et-open");
        assert!(src.url.contains("suricata-6.0"));
    }

    #[test]
    fn find_source_returns_error_for_unknown() {
        assert!(find_source("nonexistent").is_err());
    }

    #[test]
    fn blocked_url_detection_matches_suricata_7_feeds() {
        assert!(is_blocked_suricata_ruleset_url("https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz"));
        assert!(is_blocked_suricata_ruleset_url("https://example.com/suricata-7.1/foo.rules"));
        assert!(!is_blocked_suricata_ruleset_url("https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"));
        assert!(!is_blocked_suricata_ruleset_url("https://openinfosecfoundation.org/rules/trafficid/trafficid.rules"));
    }
}
