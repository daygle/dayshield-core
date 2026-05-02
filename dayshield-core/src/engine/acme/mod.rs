//! ACME engine — automatic TLS certificate issuance and renewal.
//!
//! This module implements the full ACME (RFC 8555) certificate lifecycle:
//!
//! - [`AcmeEngine`] — holds configuration; drives account and order management.
//! - [`AcmeEngine::ensure_account`] — creates or loads the ACME account keypair
//!   and registers it with the directory server.
//! - [`AcmeEngine::order_certificate`] — submits a new order, completes HTTP-01
//!   challenges by temporarily binding port 80, finalises with a CSR generated
//!   by `rcgen`, and writes the certificate + private key to
//!   `cert_storage_path`.
//! - [`AcmeEngine::renewal_check`] — returns `true` when the stored certificate
//!   is absent or has been on disk for more than 60 days (heuristic for
//!   Let's Encrypt 90-day certs).
//!
//! # HTTP-01 challenge server
//!
//! [`AcmeEngine::order_certificate`] spins up a temporary Axum listener on
//! `0.0.0.0:80` that serves the ACME key-authorization token.  The listener
//! is shut down as soon as the order becomes `Ready` (or times out).
//!
//! # DNS-01 challenges
//!
//! DNS-01 requires creating a TXT record `_acme-challenge.<domain>`.  Because
//! DNS provider APIs vary widely, automatic DNS record creation is **not**
//! implemented.  Calling [`AcmeEngine::order_certificate`] with
//! `challenge_type = Dns01` will return [`AcmeError::Dns01ManualRequired`]
//! containing the domain name and the required TXT record value so the caller
//! can create the record via their preferred method.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use rcgen::CertificateParams;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::models::{AcmeChallengeType, AcmeConfig};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the ACME engine.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// An error returned by the `instant-acme` ACME client.
    #[error("ACME protocol error: {0}")]
    Protocol(#[from] instant_acme::Error),

    /// An error from the `rcgen` certificate / key-pair generator.
    #[error("certificate generation error: {0}")]
    CertGen(#[from] rcgen::Error),

    /// An I/O error (reading / writing files, binding port 80, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON (de)serialisation error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The ACME order did not become `Ready` within the polling window.
    #[error("challenge timeout: {0}")]
    ChallengeTimeout(String),

    /// DNS-01 requires manual DNS record creation (automated DNS API not
    /// configured).  The error message contains the domain and TXT value.
    #[error(
        "DNS-01 challenge requires manual setup: create TXT record \
         _acme-challenge.{domain} with value \"{value}\""
    )]
    Dns01ManualRequired { domain: String, value: String },

    /// Any other engine error.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Shared challenge map used by the temporary HTTP-01 server
// ---------------------------------------------------------------------------

/// Maps ACME challenge token → key-authorization string.
type ChallengeMap = Arc<RwLock<HashMap<String, String>>>;

// ---------------------------------------------------------------------------
// AcmeEngine
// ---------------------------------------------------------------------------

/// Drives ACME certificate issuance and renewal for the configured domains.
pub struct AcmeEngine {
    /// The ACME configuration in effect.
    pub config: AcmeConfig,
}

impl AcmeEngine {
    /// Create a new [`AcmeEngine`] from the given configuration.
    pub fn new(config: AcmeConfig) -> Self {
        Self { config }
    }

    // ------------------------------------------------------------------
    // Derived paths
    // ------------------------------------------------------------------

    fn credentials_path(&self) -> PathBuf {
        PathBuf::from(&self.config.cert_storage_path).join("acme_account.json")
    }

    pub fn cert_path(&self, domain: &str) -> PathBuf {
        let safe = Self::safe_filename(domain);
        PathBuf::from(&self.config.cert_storage_path).join(format!("{safe}.crt"))
    }

    fn key_path(&self, domain: &str) -> PathBuf {
        let safe = Self::safe_filename(domain);
        PathBuf::from(&self.config.cert_storage_path).join(format!("{safe}.key"))
    }

    fn safe_filename(domain: &str) -> String {
        domain
            .replace('.', "_")
            .replace('*', "wildcard")
            .replace('/', "_")
    }

    // ------------------------------------------------------------------
    // Public methods
    // ------------------------------------------------------------------

    /// Ensure that a valid ACME account exists and return it.
    ///
    /// If `<cert_storage_path>/acme_account.json` exists the credentials are
    /// loaded from that file.  Otherwise a new account is registered with the
    /// ACME directory and the credentials are persisted for future use.
    pub async fn ensure_account(&self) -> Result<Account, AcmeError> {
        std::fs::create_dir_all(&self.config.cert_storage_path)?;

        let creds_path = self.credentials_path();

        if creds_path.exists() {
            debug!(path = ?creds_path, "acme: loading existing account credentials");
            let json = std::fs::read_to_string(&creds_path)?;
            let creds: AccountCredentials = serde_json::from_str(&json)?;
            let account = Account::from_credentials(creds)
                .await
                .map_err(AcmeError::Protocol)?;
            info!("acme: account loaded from credentials file");
            return Ok(account);
        }

        info!(
            email = %self.config.email,
            directory = %self.config.directory_url,
            "acme: registering new account"
        );

        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", self.config.email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            &self.config.directory_url,
            None,
        )
        .await
        .map_err(AcmeError::Protocol)?;

        let creds_json = serde_json::to_string(&credentials)?;
        std::fs::write(&creds_path, &creds_json)?;
        info!(path = ?creds_path, "acme: account credentials saved");

        Ok(account)
    }

    /// Issue (or renew) certificates for all configured domains.
    ///
    /// Workflow:
    /// 1. Ensure an ACME account exists via [`Self::ensure_account`].
    /// 2. Submit a new order for every domain in [`AcmeConfig::domains`].
    /// 3. Complete domain validation via HTTP-01 or DNS-01.
    /// 4. Wait for the order to become `Ready`.
    /// 5. Generate an ECDSA key-pair and a CSR via `rcgen`.
    /// 6. Finalise the order and download the signed certificate chain.
    /// 7. Write the PEM certificate and private key to `cert_storage_path`.
    ///
    /// # HTTP-01
    ///
    /// A temporary Axum server is bound on `0.0.0.0:80` while the ACME server
    /// verifies the challenge.  This requires port 80 to be free and accessible
    /// from the public internet (or the ACME directory's vantage point).
    ///
    /// # DNS-01
    ///
    /// Returns [`AcmeError::Dns01ManualRequired`] with the required TXT record
    /// details.  The caller must create the DNS record and call
    /// [`Self::order_certificate`] again after propagation.
    pub async fn order_certificate(&self) -> Result<(), AcmeError> {
        if self.config.domains.is_empty() {
            return Err(AcmeError::Other("no domains configured".into()));
        }

        let account = self.ensure_account().await?;

        let identifiers: Vec<Identifier> = self
            .config
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .map_err(AcmeError::Protocol)?;

        let authorizations = order
            .authorizations()
            .await
            .map_err(AcmeError::Protocol)?;

        // Collect challenges ------------------------------------------------

        // Map of token -> key-authorization string for all HTTP-01 challenges.
        let mut http01_tokens: HashMap<String, String> = HashMap::new();
        let mut challenge_urls: Vec<String> = Vec::new();

        for auth in &authorizations {
            let Identifier::Dns(domain) = &auth.identifier;

            match self.config.challenge_type {
                AcmeChallengeType::Http01 => {
                    let challenge = auth
                        .challenges
                        .iter()
                        .find(|c| c.r#type == ChallengeType::Http01)
                        .ok_or_else(|| {
                            AcmeError::Other(format!(
                                "no HTTP-01 challenge available for domain {domain}"
                            ))
                        })?;

                    let key_auth = order.key_authorization(challenge);
                    http01_tokens
                        .insert(challenge.token.clone(), key_auth.as_str().to_string());
                    challenge_urls.push(challenge.url.clone());

                    info!(
                        domain = %domain,
                        token = %challenge.token,
                        "acme: HTTP-01 challenge prepared"
                    );
                }
                AcmeChallengeType::Dns01 => {
                    let challenge = auth
                        .challenges
                        .iter()
                        .find(|c| c.r#type == ChallengeType::Dns01)
                        .ok_or_else(|| {
                            AcmeError::Other(format!(
                                "no DNS-01 challenge available for domain {domain}"
                            ))
                        })?;

                    let key_auth = order.key_authorization(challenge);
                    let dns_value = key_auth.dns_value();

                    warn!(
                        domain = %domain,
                        txt_name = format!("_acme-challenge.{domain}"),
                        txt_value = %dns_value,
                        "acme: DNS-01 requires manual TXT record creation"
                    );

                    return Err(AcmeError::Dns01ManualRequired {
                        domain: domain.clone(),
                        value: dns_value,
                    });
                }
            }
        }

        // Start HTTP-01 challenge server (HTTP-01 path only) ----------------

        let challenge_map: ChallengeMap = Arc::new(RwLock::new(http01_tokens));
        let server_handle = start_http01_server(Arc::clone(&challenge_map)).await?;

        // Mark challenges as ready ------------------------------------------

        for url in &challenge_urls {
            order
                .set_challenge_ready(url)
                .await
                .map_err(AcmeError::Protocol)?;
        }

        // Poll until the order is Ready (or times out) ----------------------

        const MAX_ATTEMPTS: u32 = 20;
        const POLL_DELAY: Duration = Duration::from_secs(3);

        let mut ready = false;
        for attempt in 0..MAX_ATTEMPTS {
            let state = order.refresh().await.map_err(AcmeError::Protocol)?;
            match state.status {
                OrderStatus::Ready => {
                    ready = true;
                    break;
                }
                OrderStatus::Invalid => {
                    server_handle.abort();
                    return Err(AcmeError::Other(
                        "order became invalid during authorization".into(),
                    ));
                }
                _ => {
                    debug!(attempt, status = ?state.status, "acme: waiting for order to become ready");
                    tokio::time::sleep(POLL_DELAY).await;
                }
            }
            if attempt + 1 == MAX_ATTEMPTS {
                server_handle.abort();
                return Err(AcmeError::ChallengeTimeout(
                    "order did not become Ready within the polling window".into(),
                ));
            }
        }

        // Stop the challenge server now that the order is Ready -------------
        server_handle.abort();

        if !ready {
            return Err(AcmeError::ChallengeTimeout(
                "order did not become Ready".into(),
            ));
        }

        // Generate private key and CSR via rcgen ----------------------------

        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(AcmeError::CertGen)?;

        let params = CertificateParams::new(self.config.domains.clone())
            .map_err(AcmeError::CertGen)?;

        let csr = params
            .serialize_request(&key_pair)
            .map_err(AcmeError::CertGen)?;

        // Finalise the order ------------------------------------------------

        order
            .finalize(csr.der())
            .await
            .map_err(AcmeError::Protocol)?;

        // Download the certificate chain ------------------------------------

        const CERT_POLL_DELAY: Duration = Duration::from_secs(2);
        const CERT_MAX_ATTEMPTS: u32 = 10;

        let cert_chain_pem = {
            let mut cert_pem: Option<String> = None;
            for _ in 0..CERT_MAX_ATTEMPTS {
                match order.certificate().await.map_err(AcmeError::Protocol)? {
                    Some(pem) => {
                        cert_pem = Some(pem);
                        break;
                    }
                    None => tokio::time::sleep(CERT_POLL_DELAY).await,
                }
            }
            cert_pem.ok_or_else(|| {
                AcmeError::ChallengeTimeout(
                    "certificate not available after finalisation".into(),
                )
            })?
        };

        // Persist certificate and private key --------------------------------

        std::fs::create_dir_all(&self.config.cert_storage_path)?;

        let primary = &self.config.domains[0];
        std::fs::write(self.cert_path(primary), &cert_chain_pem)?;
        std::fs::write(self.key_path(primary), key_pair.serialize_pem())?;

        info!(
            domain = %primary,
            cert_path = ?self.cert_path(primary),
            "acme: certificate issued and stored successfully"
        );

        Ok(())
    }

    /// Check whether any managed certificate needs renewal.
    ///
    /// Returns `true` when the primary domain certificate is absent **or**
    /// its on-disk modification time is older than 60 days (heuristic for
    /// Let's Encrypt's 90-day validity period).
    pub async fn renewal_check(&self) -> Result<bool, AcmeError> {
        let primary = self
            .config
            .domains
            .first()
            .ok_or_else(|| AcmeError::Other("no domains configured".into()))?;

        let cert_path = self.cert_path(primary);

        if !cert_path.exists() {
            info!(domain = %primary, "acme: no certificate on disk — renewal required");
            return Ok(true);
        }

        let metadata = std::fs::metadata(&cert_path)?;
        let modified = metadata
            .modified()
            .map_err(|e| AcmeError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        let age = modified
            .elapsed()
            .unwrap_or(Duration::from_secs(u64::MAX));

        // Renew if the certificate is older than 60 days.
        let renewal_threshold = Duration::from_secs(60 * 86400);
        let needs_renewal = age > renewal_threshold;

        if needs_renewal {
            info!(
                domain = %primary,
                age_days = age.as_secs() / 86400,
                "acme: certificate is due for renewal"
            );
        } else {
            debug!(
                domain = %primary,
                age_days = age.as_secs() / 86400,
                "acme: certificate is still valid"
            );
        }

        Ok(needs_renewal)
    }
}

// ---------------------------------------------------------------------------
// HTTP-01 challenge server
// ---------------------------------------------------------------------------

/// Handler for `GET /.well-known/acme-challenge/:token`.
async fn http01_challenge_handler(
    Path(token): Path<String>,
    State(map): State<ChallengeMap>,
) -> impl IntoResponse {
    let guard = map.read().await;
    match guard.get(&token) {
        Some(auth) => (StatusCode::OK, auth.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Bind port 80 and serve HTTP-01 challenge tokens from `map`.
///
/// Returns a [`tokio::task::JoinHandle`] that the caller should `.abort()`
/// once the ACME server has verified the challenge.
///
/// # Errors
///
/// Returns [`AcmeError::Other`] if port 80 cannot be bound (e.g. already in
/// use or insufficient privileges).
async fn start_http01_server(
    map: ChallengeMap,
) -> Result<tokio::task::JoinHandle<()>, AcmeError> {
    let app = Router::new()
        .route(
            "/.well-known/acme-challenge/:token",
            get(http01_challenge_handler),
        )
        .with_state(map);

    let listener = TcpListener::bind("0.0.0.0:80").await.map_err(|e| {
        AcmeError::Other(format!("failed to bind port 80 for HTTP-01 challenge: {e}"))
    })?;

    info!("acme: HTTP-01 challenge server listening on 0.0.0.0:80");

    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            warn!("acme: HTTP-01 challenge server stopped: {e}");
        }
    });

    Ok(handle)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{AcmeChallengeType, AcmeProvider};

    fn test_config() -> AcmeConfig {
        AcmeConfig {
            enabled: true,
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            email: "admin@example.com".into(),
            domains: vec!["example.com".into()],
            challenge_type: AcmeChallengeType::Http01,
            renew_interval_hours: 24,
            provider: AcmeProvider::LetsEncrypt,
            cert_storage_path: "/tmp/acme-test".into(),
        }
    }

    // -----------------------------------------------------------------------
    // AcmeEngine::safe_filename
    // -----------------------------------------------------------------------

    #[test]
    fn safe_filename_dots_replaced() {
        let name = AcmeEngine::safe_filename("example.com");
        assert_eq!(name, "example_com");
    }

    #[test]
    fn safe_filename_wildcard_replaced() {
        let name = AcmeEngine::safe_filename("*.example.com");
        assert_eq!(name, "wildcard_example_com");
    }

    #[test]
    fn safe_filename_no_special_chars() {
        let name = AcmeEngine::safe_filename("sub-domain.example.com");
        assert_eq!(name, "sub-domain_example_com");
    }

    // -----------------------------------------------------------------------
    // AcmeEngine derived paths
    // -----------------------------------------------------------------------

    #[test]
    fn cert_path_uses_primary_domain_safe_name() {
        let engine = AcmeEngine::new(test_config());
        let path = engine.cert_path("example.com");
        assert!(path.to_str().unwrap().ends_with("example_com.crt"));
    }

    #[test]
    fn key_path_uses_primary_domain_safe_name() {
        let engine = AcmeEngine::new(test_config());
        let path = engine.key_path("example.com");
        assert!(path.to_str().unwrap().ends_with("example_com.key"));
    }

    #[test]
    fn credentials_path_is_inside_cert_storage() {
        let engine = AcmeEngine::new(test_config());
        let path = engine.credentials_path();
        assert!(path.starts_with("/tmp/acme-test"));
        assert!(path.to_str().unwrap().ends_with("acme_account.json"));
    }

    // -----------------------------------------------------------------------
    // renewal_check — no cert on disk
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn renewal_check_returns_true_when_no_cert() {
        // Use a unique directory that definitely has no cert file.
        let dir = std::env::temp_dir()
            .join(format!("acme-test-{}", uuid::Uuid::new_v4().simple()));
        let mut cfg = test_config();
        cfg.cert_storage_path = dir.to_str().unwrap().to_string();
        let engine = AcmeEngine::new(cfg);
        let needs = engine.renewal_check().await.unwrap();
        assert!(needs, "expected renewal_check to return true when cert is absent");
    }

    #[tokio::test]
    async fn renewal_check_returns_false_for_fresh_cert() {
        let dir = std::env::temp_dir()
            .join(format!("acme-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut cfg = test_config();
        cfg.cert_storage_path = dir.to_str().unwrap().to_string();

        // Write a fresh (just-created) cert file.
        let engine = AcmeEngine::new(cfg);
        let cert_path = engine.cert_path("example.com");
        std::fs::write(&cert_path, "placeholder").unwrap();

        let needs = engine.renewal_check().await.unwrap();
        assert!(!needs, "expected renewal_check to return false for a fresh cert");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn renewal_check_errors_with_no_domains() {
        let mut cfg = test_config();
        cfg.domains = vec![];
        let engine = AcmeEngine::new(cfg);
        let result = engine.renewal_check().await;
        assert!(result.is_err(), "expected error when no domains configured");
    }
}

