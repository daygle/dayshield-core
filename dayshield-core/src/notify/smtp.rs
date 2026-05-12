//! SMTP client - sends notification emails via SMTP over TLS.
//!
//! Uses `lettre` with the `smtp-transport` + `rustls-tls` features.
//! IPv4-only: the host is resolved to the first IPv4 address found.

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use lettre::message::{header::ContentType, Message};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{Address, SmtpTransport, Transport};
use tracing::{debug, warn};

use crate::config::models::NotifyConfig;

/// Errors that can occur in the notification subsystem.
#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    /// An SMTP-level failure (connection, authentication, send).
    #[error("SMTP error: {0}")]
    SmtpError(String),

    /// A configuration value is missing or invalid.
    #[error("config error: {0}")]
    ConfigError(String),

    /// The per-minute rate limit has been exceeded.
    #[error("rate limited: too many emails sent recently")]
    RateLimited,

    /// The internal notification queue is full.
    #[error("notification queue is full")]
    QueueFull,
}

/// Resolve `host` to the first IPv4 address reachable on `port`.
///
/// Returns an error when no IPv4 address can be found - IPv6-only hosts are
/// intentionally rejected to keep the subsystem deterministic on
/// IPv4-only networks.
fn resolve_ipv4(host: &str, port: u16) -> Result<Ipv4Addr, NotifyError> {
    let addrs = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| NotifyError::SmtpError(format!("DNS resolution failed for {host}: {e}")))?;

    for addr in addrs {
        if let SocketAddr::V4(v4) = addr {
            return Ok(*v4.ip());
        }
    }
    Err(NotifyError::SmtpError(format!(
        "no IPv4 address found for {host}"
    )))
}

/// Build a `lettre` [`SmtpTransport`] from the supplied config.
fn build_transport(cfg: &NotifyConfig) -> Result<SmtpTransport, NotifyError> {
    let ipv4 = resolve_ipv4(&cfg.smtp_server, cfg.smtp_port)?;
    debug!(smtp_server = %cfg.smtp_server, ipv4 = %ipv4, port = cfg.smtp_port, "Using SMTP server");

    let tls_params = TlsParameters::builder(cfg.smtp_server.clone())
        .build_rustls()
        .map_err(|e| NotifyError::SmtpError(format!("TLS parameter build failed: {e}")))?;

    let creds = Credentials::new(cfg.smtp_username.clone(), cfg.smtp_password.clone());

    let transport = SmtpTransport::builder_dangerous(ipv4.to_string())
        .port(cfg.smtp_port)
        .tls(Tls::Required(tls_params))
        .credentials(creds)
        .authentication(vec![Mechanism::Login, Mechanism::Plain])
        .timeout(Some(Duration::from_secs(10)))
        .build();

    Ok(transport)
}

/// Send a single email using the given [`NotifyConfig`].
///
/// Retries once on transient failure.
///
/// # Errors
///
/// Returns [`NotifyError::ConfigError`] when the from/to addresses cannot be
/// parsed, or [`NotifyError::SmtpError`] on transport failures.
pub async fn send_email(cfg: &NotifyConfig, subject: &str, body: &str) -> Result<(), NotifyError> {
    if cfg.to_addresses.is_empty() {
        return Err(NotifyError::ConfigError(
            "to_addresses is empty".to_string(),
        ));
    }

    let from: Address = cfg
        .from_address
        .parse()
        .map_err(|e| NotifyError::ConfigError(format!("invalid from_address: {e}")))?;

    // Build the message with all recipients.
    let mut builder = Message::builder().from(from.into());
    for addr in &cfg.to_addresses {
        let to: Address = addr
            .parse()
            .map_err(|e| NotifyError::ConfigError(format!("invalid to_address {addr}: {e}")))?;
        builder = builder.to(to.into());
    }
    let email = builder
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .map_err(|e| NotifyError::SmtpError(format!("message build failed: {e}")))?;

    // Attempt 1.
    let transport = build_transport(cfg)?;
    match do_send(&transport, &email) {
        Ok(()) => return Ok(()),
        Err(e) => {
            warn!(error = %e, "First SMTP send attempt failed; retrying once");
        }
    }

    // Retry once with a fresh transport.
    let transport = build_transport(cfg)?;
    do_send(&transport, &email)
}

fn do_send(transport: &SmtpTransport, email: &Message) -> Result<(), NotifyError> {
    transport
        .send(email)
        .map(|_| ())
        .map_err(|e| NotifyError::SmtpError(e.to_string()))
}
