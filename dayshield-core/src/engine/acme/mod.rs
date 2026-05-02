//! ACME engine — automatic TLS certificate issuance and renewal.
//!
//! TODO: implement ACME account creation and registration.
//! TODO: implement HTTP-01 and DNS-01 challenge solvers.
//! TODO: implement certificate issuance for configured domains.
//! TODO: implement background renewal (check every 12 h, renew at 30 days).
//! TODO: emit certificate expiry metrics to the metrics layer.
//! TODO: integrate with the reverse-proxy / HAProxy to hot-reload certs.

use anyhow::Result;
use tracing::info;

use crate::config::models::AcmeConfig;

/// Issue or renew certificates for all domains in the given [`AcmeConfig`].
///
/// TODO: shell out to an ACME client (e.g. `certbot` or `acme.sh`) or use a
///       native Rust ACME library.
pub async fn issue_certificates(config: &AcmeConfig) -> Result<()> {
    info!(
        enabled = config.enabled,
        domains = ?config.domains,
        "acme: issue_certificates called (stub)"
    );
    Ok(())
}

/// Check whether any managed certificate is due for renewal.
///
/// Returns `true` if at least one certificate requires renewal.
///
/// TODO: read the certificate file from disk and check its `notAfter` field.
pub async fn renewal_check(config: &AcmeConfig) -> Result<bool> {
    info!(
        domains = ?config.domains,
        "acme: renewal_check called (stub)"
    );
    // TODO: return true when a cert expires within 30 days.
    Ok(false)
}
