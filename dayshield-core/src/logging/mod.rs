//! Logging initialisation.
//!
//! Sets up a `tracing-subscriber` with an `EnvFilter` so that the log level
//! can be controlled via the `RUST_LOG` environment variable.
//!
//! TODO: add JSON-formatted log output for production deployments.
//! TODO: integrate with syslog for OS-level log aggregation.
//! TODO: add per-module log level overrides in the system config.

use tracing_subscriber::{fmt, EnvFilter};

/// Initialise the global tracing subscriber.
///
/// Uses the `RUST_LOG` environment variable for log-level control; falls back
/// to `info` if the variable is absent or malformed.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt().with_env_filter(filter).with_target(true).init();
}
