//! Logging initialisation.
//!
//! Sets up a `tracing-subscriber` with an `EnvFilter` so that the log level
//! can be controlled via the `RUST_LOG` environment variable.
//!
//! # Output formats
//!
//! Set the `LOG_FORMAT` environment variable to choose the output format:
//!
//! - `LOG_FORMAT=json`  – structured JSON lines (for production deployments and
//!   log-aggregation pipelines).
//! - `LOG_FORMAT=text` or unset – human-readable text (default).
//!
//! # Syslog integration
//!
//! Set `LOG_SYSLOG=1` to additionally forward log records to the local syslog
//! daemon via the `/dev/log` Unix socket (RFC 3164 format).  This allows
//! standard OS-level log aggregation tools (`rsyslog`, `journald`, `syslog-ng`)
//! to consume DayShield log events alongside other system services.
//!
//! # Per-module log level overrides
//!
//! Per-module overrides can be provided either through `RUST_LOG` (e.g.
//! `RUST_LOG=info,dayshield_core::engine=debug`) or programmatically via
//! [`init_with_config`] after loading the system configuration.
//!
//! The filter can also be updated at runtime without restarting the process
//! using [`update_filter`].

use std::sync::OnceLock;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, reload, EnvFilter, Registry};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Log output format.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable text (default).
    #[default]
    Text,
    /// Structured JSON lines.
    Json,
}

/// Per-module log level configuration loaded from the system config.
///
/// Each entry in `module_overrides` is a pair of `(module_path, level)`.
/// For example: `("dayshield_core::engine", "debug")`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LoggingConfig {
    /// Base log level (e.g. `"info"`, `"debug"`, `"warn"`).  Falls back to
    /// the `RUST_LOG` environment variable and then to `"info"` if absent.
    #[serde(default)]
    pub level: String,
    /// Output format.
    #[serde(default)]
    pub format: LogFormat,
    /// Per-module level overrides (module path → level string).
    #[serde(default)]
    pub module_overrides: std::collections::HashMap<String, String>,
    /// When `true`, also forward log records to the system syslog daemon.
    #[serde(default)]
    pub syslog: bool,
}

// Global handle used to update the filter at runtime without restarting.
static FILTER_HANDLE: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

/// Build an [`EnvFilter`] from a [`LoggingConfig`].
///
/// The filter directive string is built as:
/// `<base_level>[,<module>=<level>...]`
///
/// `RUST_LOG` is consulted first; if set it overrides the config-level value.
fn build_filter(config: &LoggingConfig) -> EnvFilter {
    // Prefer RUST_LOG; otherwise use the config level; otherwise "info".
    let base = if let Ok(env) = std::env::var("RUST_LOG") {
        if !env.is_empty() {
            return EnvFilter::try_new(&env).unwrap_or_else(|_| EnvFilter::new("info"));
        }
        config.level.clone()
    } else {
        config.level.clone()
    };

    let base = if base.is_empty() { "info".to_string() } else { base };

    // Append per-module overrides.
    if config.module_overrides.is_empty() {
        EnvFilter::try_new(&base).unwrap_or_else(|_| EnvFilter::new("info"))
    } else {
        let overrides: String = config
            .module_overrides
            .iter()
            .map(|(module, level)| format!(",{}={}", module, level))
            .collect();
        let directive = format!("{}{}", base, overrides);
        EnvFilter::try_new(&directive).unwrap_or_else(|_| EnvFilter::new("info"))
    }
}

/// Initialise the global tracing subscriber with default settings.
///
/// Uses the `RUST_LOG` environment variable for log-level control; falls back
/// to `info` if the variable is absent or malformed.
///
/// The output format is controlled by the `LOG_FORMAT` environment variable:
/// set to `"json"` for JSON output, or leave unset for text output.
///
/// Syslog forwarding is enabled when the `LOG_SYSLOG` environment variable is
/// set to `"1"`.
pub fn init() {
    let format = std::env::var("LOG_FORMAT").unwrap_or_default();
    let syslog = std::env::var("LOG_SYSLOG").unwrap_or_default() == "1";

    let config = LoggingConfig {
        level: String::new(),
        format: if format == "json" { LogFormat::Json } else { LogFormat::Text },
        module_overrides: Default::default(),
        syslog,
    };
    init_with_config(&config);
}

/// Initialise the global tracing subscriber using the provided [`LoggingConfig`].
///
/// This is the preferred entry point when a system configuration has already
/// been loaded.  Environment variable overrides (`RUST_LOG`, `LOG_FORMAT`,
/// `LOG_SYSLOG`) still take precedence over the values in `config`.
pub fn init_with_config(config: &LoggingConfig) {
    let filter = build_filter(config);
    let (filter_layer, handle) = reload::Layer::new(filter);

    // `OnceLock::set` fails silently if already set (subscriber already init).
    let _ = FILTER_HANDLE.set(handle);

    // Respect LOG_FORMAT env var regardless of config.format.
    let env_format = std::env::var("LOG_FORMAT").unwrap_or_default();
    let use_json = env_format == "json" || config.format == LogFormat::Json;

    let env_syslog = std::env::var("LOG_SYSLOG").unwrap_or_default() == "1";
    let use_syslog = env_syslog || config.syslog;

    if use_json {
        let subscriber = Registry::default()
            .with(filter_layer)
            .with(fmt::layer().json().with_target(true));
        if use_syslog {
            subscriber
                .with(SyslogLayer::new())
                .try_init()
                .ok();
        } else {
            subscriber.try_init().ok();
        }
    } else {
        let subscriber = Registry::default()
            .with(filter_layer)
            .with(fmt::layer().with_target(true));
        if use_syslog {
            subscriber
                .with(SyslogLayer::new())
                .try_init()
                .ok();
        } else {
            subscriber.try_init().ok();
        }
    }
}

/// Update the active log filter at runtime.
///
/// This allows per-module log levels defined in the system configuration to
/// take effect without restarting the process.  Has no effect if the global
/// subscriber has not been initialised yet.
pub fn update_filter(config: &LoggingConfig) {
    if let Some(handle) = FILTER_HANDLE.get() {
        let new_filter = build_filter(config);
        let _ = handle.modify(|f| *f = new_filter);
    }
}

// ── Syslog layer ─────────────────────────────────────────────────────────────

/// A lightweight `tracing` layer that forwards log records to the local syslog
/// daemon via the `/dev/log` Unix socket (RFC 3164 format).
///
/// Messages are sent as UDP datagrams to the socket; if the socket is not
/// available the layer degrades silently so that startup continues normally.
struct SyslogLayer {
    socket: Option<std::os::unix::net::UnixDatagram>,
    hostname: String,
}

impl SyslogLayer {
    /// Create a new [`SyslogLayer`].
    ///
    /// Opens a connection to `/dev/log`; if that fails the layer is created in
    /// a degraded (no-op) state so the rest of logging still works.
    fn new() -> Self {
        // We need an unbound datagram socket to send to /dev/log.
        let socket = std::os::unix::net::UnixDatagram::unbound()
            .ok()
            .and_then(|s| {
                // Try to connect; fall back to None on failure.
                s.connect("/dev/log").ok().map(|_| s)
            });
        let host = hostname::get_hostname();
        Self { socket, hostname: host }
    }

    /// Send a formatted RFC 3164 syslog message.
    fn send(&self, severity: u8, message: &str) {
        if let Some(socket) = &self.socket {
            // Facility 1 = user-level messages.
            let facility: u8 = 1;
            let priority = facility * 8 + severity;
            let tag = "dayshield-core";
            let msg = format!("<{priority}>{tag}: {message}");
            let _ = socket.send(msg.as_bytes());
        }
    }
}

/// RFC 3164 severity levels (lower = more severe).
mod syslog_severity {
    pub const ERR: u8 = 3;
    pub const WARNING: u8 = 4;
    pub const NOTICE: u8 = 5;
    pub const INFO: u8 = 6;
    pub const DEBUG: u8 = 7;
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SyslogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        use tracing::Level;

        let severity = match *event.metadata().level() {
            Level::ERROR => syslog_severity::ERR,
            Level::WARN => syslog_severity::WARNING,
            Level::INFO => syslog_severity::INFO,
            Level::DEBUG | Level::TRACE => syslog_severity::DEBUG,
        };

        // Extract the message field from the event.
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        if !visitor.0.is_empty() {
            self.send(severity, &visitor.0);
        }
    }
}

/// Extracts the `message` field from a tracing event.
struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }
}

/// Minimal hostname helper that avoids a new crate dependency.
mod hostname {
    pub fn get_hostname() -> String {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| {
                let trimmed = s.trim().to_string();
                if trimmed.is_empty() { "localhost".to_string() } else { trimmed }
            })
            .unwrap_or_else(|_| "localhost".to_string())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_filter_default_is_info() {
        // Without RUST_LOG or a configured level the filter should default to "info".
        std::env::remove_var("RUST_LOG");
        let config = LoggingConfig::default();
        let filter = build_filter(&config);
        // Just verify it can be built – the exact directive string is an impl detail.
        drop(filter);
    }

    #[test]
    fn build_filter_with_module_overrides() {
        std::env::remove_var("RUST_LOG");
        let mut config = LoggingConfig::default();
        config.level = "info".to_string();
        config
            .module_overrides
            .insert("dayshield_core::engine".to_string(), "debug".to_string());
        let filter = build_filter(&config);
        drop(filter);
    }

    #[test]
    fn logging_config_default() {
        let cfg = LoggingConfig::default();
        assert_eq!(cfg.format, LogFormat::Text);
        assert!(!cfg.syslog);
        assert!(cfg.module_overrides.is_empty());
    }
}
