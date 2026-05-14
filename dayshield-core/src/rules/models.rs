//! Data models for the managed Suricata ruleset subsystem.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// RulesetStatus
// ---------------------------------------------------------------------------

/// The current lifecycle state of a managed ruleset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RulesetStatus {
    /// The ruleset is installed and up to date.
    Installed,
    /// An update has been detected but not yet applied.
    UpdateAvailable,
    /// The last install or update operation failed; see `last_error`.
    Failed,
}

// ---------------------------------------------------------------------------
// InstalledRuleset
// ---------------------------------------------------------------------------

/// Metadata for a managed ruleset that has been downloaded and installed.
///
/// Persisted as a JSON array in
/// `/var/lib/dayshield/rulesets/installed.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledRuleset {
    /// Unique identifier – matches the curated-source `id` (e.g. `"et-open"`).
    pub id: String,
    /// Human-readable display name (e.g. `"Emerging Threats Open"`).
    pub display_name: String,
    /// URL the ruleset was downloaded from.
    pub source_url: String,
    /// Version tag for the installed copy.
    ///
    /// Populated from the HTTP `ETag` or `Last-Modified` response header at
    /// download time.  Used to detect newer versions on subsequent checks.
    pub installed_version: Option<String>,
    /// Version tag from the most recent update check.
    ///
    /// When this differs from `installed_version` the status should be
    /// [`RulesetStatus::UpdateAvailable`].
    pub latest_version: Option<String>,
    /// Whether this ruleset is currently active in the Suricata configuration.
    pub enabled: bool,
    /// Current lifecycle state.
    pub status: RulesetStatus,
    /// Error message from the last failed operation, or `None` if healthy.
    pub last_error: Option<String>,
    /// Timestamp of the most recent update check.
    pub last_checked: Option<DateTime<Utc>>,
    /// Timestamp of the most recent successful install or update.
    pub last_updated: Option<DateTime<Utc>>,
    /// Absolute path to the combined `.rules` file on disk.
    ///
    /// This is the path added to Suricata's `rule-files` section when the
    /// ruleset is enabled.
    pub local_path: Option<String>,
}

// ---------------------------------------------------------------------------
// CuratedSource
// ---------------------------------------------------------------------------

/// A built-in curated ruleset source definition.
///
/// These are the rulesets visible on the "Available" list in the UI.  Users
/// can install them with a single click without needing to know URLs or file
/// formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuratedSource {
    /// Unique identifier, e.g. `"et-open"`.
    pub id: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Short description of the ruleset's coverage and origin.
    pub description: String,
    /// Download URL (`.rules` file or `.tar.gz` archive).
    pub url: String,
    /// License under which the rules are distributed.
    pub license: String,
    /// Vendor / maintainer name.
    pub vendor: String,
}

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

/// A single Suricata rule parsed from a .rules file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule ID (e.g., "1000001")
    pub id: String,
    /// Rule action: alert, drop, pass, etc.
    pub action: String,
    /// Rule signature/description text
    pub signature: String,
    /// Whether this rule is currently enabled (not disabled)
    pub enabled: bool,
    /// Raw rule line for reference
    pub raw: String,
}

// ---------------------------------------------------------------------------
// DisabledRules
// ---------------------------------------------------------------------------

/// Set of disabled rule IDs for a ruleset.
/// Persisted as JSON in `rulesets/{id}/disabled-rules.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DisabledRules {
    pub ids: Vec<String>,
}
