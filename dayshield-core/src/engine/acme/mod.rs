//! ACME engine — automatic TLS certificate issuance and renewal.
//!
//! # Overview
//!
//! This module implements the full ACME (RFC 8555) certificate lifecycle:
//!
//! 1. **Account management** — create or load a persistent P-256 ECDSA account
//!    keypair and register it with the ACME directory.
//! 2. **Certificate issuance** — order a certificate for every domain in
//!    [`AcmeConfig::domains`], prove ownership via HTTP-01 or DNS-01 challenges,
//!    generate an RSA/EC CSR, and download the signed certificate chain.
//! 3. **Certificate storage** — write `cert.pem`, `key.pem`, and `chain.pem`
//!    to [`AcmeConfig::cert_storage_path`].
//! 4. **Renewal scheduler** — a background Tokio task that wakes every
//!    [`AcmeConfig::renew_interval_hours`] hours and renews any certificate
//!    whose `notAfter` is within 30 days.
//!
//! # Challenge types
//!
//! | Variant | How ownership is proved |
//! |---------|------------------------|
//! | HTTP-01 | Token served at `http://<domain>/.well-known/acme-challenge/<token>` |
//! | DNS-01  | `_acme-challenge.<domain>` TXT record set to the key authorisation hash |
//!
//! HTTP-01 tokens are held in the in-process [`ChallengeStore`] so that the
//! Axum route `GET /.well-known/acme-challenge/{token}` can serve them without
//! any filesystem I/O.
//!
//! DNS-01 provisioning is intentionally left as a no-op in this implementation.
//! Operators should wire up the [`DnsChallengeRequest`] callback to their
//! DNS provider's API.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    Order, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::models::{AcmeConfig, AcmeChallengeType};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Renew a certificate when it expires within this many days.
const RENEW_THRESHOLD_DAYS: i64 = 30;

/// Path of the account credentials file relative to [`AcmeConfig::cert_storage_path`].
const ACCOUNT_FILE: &str = "account.json";
/// PEM file written for the certificate chain.
const CERT_FILE: &str = "cert.pem";
/// PEM file written for the private key matching the certificate.
const KEY_FILE: &str = "key.pem";
/// PEM file written for the full chain (cert + intermediates).
const CHAIN_FILE: &str = "chain.pem";

// ---------------------------------------------------------------------------
// Challenge store
// ---------------------------------------------------------------------------

/// Thread-safe in-memory store for pending HTTP-01 ACME challenge tokens.
///
/// The Axum route at `GET /.well-known/acme-challenge/{token}` reads from this
/// map to serve the key-authorisation string required by the ACME server.
#[derive(Debug, Default, Clone)]
pub struct ChallengeStore {
    inner: Arc<RwLock<HashMap<String, String>>>,
}

impl ChallengeStore {
    /// Insert a challenge token → key-authorisation mapping.
    pub async fn insert(&self, token: String, key_auth: String) {
        self.inner.write().await.insert(token, key_auth);
    }

    /// Look up a challenge token and return the key-authorisation string, if
    /// present.
    pub async fn get(&self, token: &str) -> Option<String> {
        self.inner.read().await.get(token).cloned()
    }

    /// Remove a challenge token once it is no longer needed.
    pub async fn remove(&self, token: &str) {
        self.inner.write().await.remove(token);
    }
}

// ---------------------------------------------------------------------------
// DNS challenge callback
// ---------------------------------------------------------------------------

/// A pending DNS-01 challenge that must be provisioned by the operator.
///
/// The operator should create a `_acme-challenge.<domain>` TXT record with
/// value [`DnsChallengeRequest::txt_value`] before calling
/// [`AcmeEngine::notify_dns_challenge_ready`].
#[derive(Debug, Clone)]
pub struct DnsChallengeRequest {
    /// The domain being validated.
    pub domain: String,
    /// The full TXT record name, e.g. `_acme-challenge.example.com`.
    pub record_name: String,
    /// The TXT record value (key-authorisation digest).
    pub txt_value: String,
}

// ---------------------------------------------------------------------------
// ACME engine
// ---------------------------------------------------------------------------

/// ACME certificate engine.
///
/// Holds the runtime configuration and the shared HTTP-01 challenge store.
/// A single instance is created at startup and shared (via [`Arc`]) between
/// the background renewal task and the HTTP challenge route.
#[derive(Clone)]
pub struct AcmeEngine {
    pub config: AcmeConfig,
    /// Shared token store for HTTP-01 challenges.
    pub challenge_store: ChallengeStore,
}

impl AcmeEngine {
    /// Create a new [`AcmeEngine`] with the given configuration.
    pub fn new(config: AcmeConfig) -> Self {
        Self {
            config,
            challenge_store: ChallengeStore::default(),
        }
    }

    // ------------------------------------------------------------------
    // Account management
    // ------------------------------------------------------------------

    /// Create or load the ACME account for the configured e-mail address.
    ///
    /// If an `account.json` file exists in [`AcmeConfig::cert_storage_path`]
    /// the credentials are loaded from disk.  Otherwise a new account is
    /// registered with the ACME directory and the credentials are saved.
    ///
    /// Returns the [`Account`] ready for use in an order.
    pub async fn ensure_account(&self) -> Result<Account> {
        let storage = PathBuf::from(&self.config.cert_storage_path);
        std::fs::create_dir_all(&storage)
            .with_context(|| format!("failed to create cert storage dir {}", storage.display()))?;

        let account_path = storage.join(ACCOUNT_FILE);

        if account_path.exists() {
            info!(path = %account_path.display(), "acme: loading existing account credentials");
            let raw = std::fs::read_to_string(&account_path)
                .with_context(|| format!("failed to read {}", account_path.display()))?;
            let creds: AccountCredentials = serde_json::from_str(&raw)
                .with_context(|| "failed to deserialise account credentials")?;
            let account = Account::from_credentials(creds)
                .await
                .context("failed to restore ACME account from credentials")?;
            info!("acme: account loaded from disk");
            return Ok(account);
        }

        info!(email = %self.config.email, "acme: registering new account");

        let directory_url = self.directory_url();
        let (account, creds) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", self.config.email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await
        .context("failed to register ACME account")?;

        let creds_json = serde_json::to_string_pretty(&creds)
            .context("failed to serialise account credentials")?;
        std::fs::write(&account_path, &creds_json)
            .with_context(|| format!("failed to save account credentials to {}", account_path.display()))?;

        info!(path = %account_path.display(), "acme: account credentials saved");
        Ok(account)
    }

    // ------------------------------------------------------------------
    // Certificate issuance
    // ------------------------------------------------------------------

    /// Issue (or renew) a certificate covering all domains in the config.
    ///
    /// Steps:
    /// 1. Obtain / load the ACME account.
    /// 2. Place a new order for all configured domains.
    /// 3. Complete each authorisation challenge (HTTP-01 or DNS-01).
    /// 4. Finalise the order with a CSR generated from a fresh EC P-256 key.
    /// 5. Download and persist the certificate chain and private key.
    ///
    /// Returns the PEM-encoded certificate chain.
    pub async fn order_certificate(&self) -> Result<String> {
        if !self.config.enabled {
            anyhow::bail!("ACME is disabled in configuration");
        }
        if self.config.domains.is_empty() {
            anyhow::bail!("no domains configured for ACME");
        }

        info!(
            domains = ?self.config.domains,
            challenge = ?self.config.challenge_type,
            "acme: starting certificate order"
        );

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
            .context("failed to place ACME order")?;

        info!(
            url = order.url(),
            "acme: order placed"
        );

        // Collect authorisations and complete the requested challenges.
        self.fulfill_authorizations(&mut order).await?;

        // Wait for the order to become ready (all challenges validated).
        self.wait_for_ready(&mut order).await?;

        // Generate a fresh EC key and CSR.
        let (key_pem, cert_chain_pem) = self.finalize_order(&mut order).await?;

        // Persist certificate and key to disk.
        self.save_certificate(&cert_chain_pem, &key_pem)?;

        info!(
            domains = ?self.config.domains,
            "acme: certificate issued successfully"
        );

        Ok(cert_chain_pem)
    }

    // ------------------------------------------------------------------
    // Renewal check
    // ------------------------------------------------------------------

    /// Check whether the stored certificate for the first configured domain is
    /// due for renewal (expires within [`RENEW_THRESHOLD_DAYS`] days).
    ///
    /// Returns `true` if the certificate should be renewed.
    pub fn renewal_check(&self) -> bool {
        let cert_path = PathBuf::from(&self.config.cert_storage_path).join(CERT_FILE);
        match self.cert_expiry_days(&cert_path) {
            Ok(days_left) => {
                info!(days_left, "acme: certificate expiry check");
                days_left <= RENEW_THRESHOLD_DAYS
            }
            Err(e) => {
                warn!(error = %e, "acme: could not read certificate; treating as needing renewal");
                true
            }
        }
    }

    /// Return the number of days until the certificate at `path` expires.
    pub fn cert_expiry_days(&self, path: &Path) -> Result<i64> {
        use x509_parser::prelude::*;

        if !path.exists() {
            anyhow::bail!("certificate file not found: {}", path.display());
        }
        let pem_data =
            std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let (_, pem) =
            parse_x509_pem(&pem_data).map_err(|e| anyhow::anyhow!("PEM parse error: {e:?}"))?;
        let (_, cert) = parse_x509_certificate(&pem.contents)
            .map_err(|e| anyhow::anyhow!("X.509 parse error: {e:?}"))?;
        let not_after = cert.validity().not_after.timestamp();
        let now = chrono::Utc::now().timestamp();
        Ok((not_after - now) / 86_400)
    }

    // ------------------------------------------------------------------
    // Background renewal scheduler
    // ------------------------------------------------------------------

    /// Spawn a background Tokio task that periodically checks for expiring
    /// certificates and renews them.
    ///
    /// The task wakes every [`AcmeConfig::renew_interval_hours`] hours.
    /// If [`renewal_check`] returns `true`, [`order_certificate`] is called.
    ///
    /// The caller should keep the returned [`tokio::task::JoinHandle`] alive
    /// for the lifetime of the process (or abort it on shutdown).
    pub fn spawn_renewal_scheduler(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval_hours = self.config.renew_interval_hours;
        info!(
            interval_hours,
            "acme: starting background renewal scheduler"
        );

        tokio::spawn(async move {
            let interval = Duration::from_secs(interval_hours * 3600);
            loop {
                tokio::time::sleep(interval).await;

                if !self.config.enabled {
                    info!("acme: disabled — skipping renewal check");
                    continue;
                }

                info!("acme: running scheduled renewal check");
                if self.renewal_check() {
                    info!("acme: certificate is due for renewal — ordering now");
                    match self.order_certificate().await {
                        Ok(_) => info!("acme: scheduled renewal succeeded"),
                        Err(e) => error!(error = %e, "acme: scheduled renewal failed"),
                    }
                } else {
                    info!("acme: certificate is valid; no renewal needed");
                }
            }
        })
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Resolve the ACME directory URL from the config.
    ///
    /// Falls back to the Let's Encrypt production directory when no explicit
    /// URL is provided.
    fn directory_url(&self) -> &str {
        if let Some(url) = &self.config.directory_url {
            url.as_str()
        } else {
            LetsEncrypt::Production.url()
        }
    }

    /// Complete the challenge for every pending authorisation in `order`.
    async fn fulfill_authorizations(&self, order: &mut Order) -> Result<()> {
        let authorizations = order
            .authorizations()
            .await
            .context("failed to fetch order authorizations")?;

        for authz in &authorizations {
            match authz.status {
                instant_acme::AuthorizationStatus::Valid => {
                    info!("acme: authorization already valid; skipping challenge");
                    continue;
                }
                instant_acme::AuthorizationStatus::Pending => {}
                _ => {
                    anyhow::bail!(
                        "unexpected authorization status: {:?}",
                        authz.status
                    );
                }
            }

            let challenge_type = match self.config.challenge_type {
                AcmeChallengeType::Http01 => ChallengeType::Http01,
                AcmeChallengeType::Dns01 => ChallengeType::Dns01,
            };

            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == challenge_type)
                .with_context(|| {
                    format!(
                        "ACME server did not offer a {:?} challenge for {:?}",
                        self.config.challenge_type, authz.identifier
                    )
                })?;

            let key_auth = order
                .key_authorization(challenge)
                .as_str()
                .to_owned();

            match self.config.challenge_type {
                AcmeChallengeType::Http01 => {
                    // Serve the token from the in-process challenge store.
                    self.challenge_store
                        .insert(challenge.token.clone(), key_auth.clone())
                        .await;
                    info!(
                        token = %challenge.token,
                        "acme: HTTP-01 challenge token registered"
                    );
                }
                AcmeChallengeType::Dns01 => {
                    // Compute the key-authorisation digest (base64url of SHA-256).
                    let digest = compute_sha256(key_auth.as_bytes());
                    let txt_value = URL_SAFE_NO_PAD.encode(digest);
                    let domain = match &authz.identifier {
                        Identifier::Dns(d) => d.clone(),
                    };
                    let record_name = format!("_acme-challenge.{}", domain);
                    // Log the required DNS record.  In a production system the
                    // caller would wire this to a DNS provider API.
                    warn!(
                        record = %record_name,
                        value = %txt_value,
                        "acme: DNS-01 — provision TXT record before challenge validation"
                    );
                    info!(
                        record = %record_name,
                        value = %txt_value,
                        "acme: DNS-01 challenge details"
                    );
                    // Small sleep to allow the operator / automation to set the record.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }

            // Notify the ACME server that we are ready.
            order
                .set_challenge_ready(&challenge.url)
                .await
                .context("failed to notify ACME server of challenge readiness")?;

            info!(
                identifier = ?authz.identifier,
                "acme: notified ACME server of challenge readiness"
            );
        }

        Ok(())
    }

    /// Poll the order until its status becomes `Ready` or `Invalid`.
    async fn wait_for_ready(&self, order: &mut Order) -> Result<()> {
        let mut attempts = 0u32;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let state = order.refresh().await.context("failed to refresh order state")?;
            info!(status = ?state.status, attempt = attempts, "acme: order status check");

            match state.status {
                OrderStatus::Ready => return Ok(()),
                OrderStatus::Processing => {}
                OrderStatus::Pending => {}
                OrderStatus::Invalid => {
                    anyhow::bail!("ACME order became Invalid — check challenge responses");
                }
                OrderStatus::Valid => return Ok(()),
            }

            attempts += 1;
            if attempts >= 20 {
                anyhow::bail!("timed out waiting for ACME order to become Ready");
            }
        }
    }

    /// Generate a CSR, finalise the order, and poll until the certificate is
    /// available.  Returns `(key_pem, cert_chain_pem)`.
    async fn finalize_order(&self, order: &mut Order) -> Result<(String, String)> {
        // Generate a new EC P-256 key for this certificate.
        let key_pair = KeyPair::generate().context("failed to generate certificate key pair")?;
        let key_pem = key_pair.serialize_pem();

        // Build a CSR covering all configured domains.
        let mut params = CertificateParams::new(self.config.domains.clone())
            .context("failed to build CSR parameters")?;
        params.distinguished_name = DistinguishedName::new();

        let csr = params
            .serialize_request(&key_pair)
            .context("failed to serialise CSR")?;
        let csr_der = csr.der();

        order
            .finalize(csr_der)
            .await
            .context("failed to finalise ACME order")?;

        // Poll until the certificate is available.
        let cert_chain_pem = loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let state = order.refresh().await.context("failed to refresh order after finalise")?;
            info!(status = ?state.status, "acme: polling for certificate");
            match state.status {
                OrderStatus::Valid => {
                    break order
                        .certificate()
                        .await
                        .context("failed to download certificate")?
                        .context("ACME server returned no certificate")?;
                }
                OrderStatus::Processing => continue,
                _ => anyhow::bail!("unexpected order status while waiting for cert: {:?}", state.status),
            }
        };

        Ok((key_pem, cert_chain_pem))
    }

    /// Write the certificate chain and private key to the storage path.
    fn save_certificate(&self, cert_chain_pem: &str, key_pem: &str) -> Result<()> {
        let storage = PathBuf::from(&self.config.cert_storage_path);
        std::fs::create_dir_all(&storage)
            .with_context(|| format!("failed to create cert storage dir {}", storage.display()))?;

        let cert_path = storage.join(CERT_FILE);
        let key_path = storage.join(KEY_FILE);
        let chain_path = storage.join(CHAIN_FILE);

        std::fs::write(&cert_path, cert_chain_pem)
            .with_context(|| format!("failed to write {}", cert_path.display()))?;
        std::fs::write(&key_path, key_pem)
            .with_context(|| format!("failed to write {}", key_path.display()))?;
        // Write full chain as an alias to cert.pem for broad compatibility.
        std::fs::write(&chain_path, cert_chain_pem)
            .with_context(|| format!("failed to write {}", chain_path.display()))?;

        info!(
            cert = %cert_path.display(),
            key  = %key_path.display(),
            "acme: certificate and key written to disk"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper — SHA-256 via sha2
// ---------------------------------------------------------------------------

/// Compute a SHA-256 digest of `data`.
fn compute_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Legacy API (used by existing callers in main engine)
// ---------------------------------------------------------------------------

/// Issue or renew certificates for all domains in the given [`AcmeConfig`].
///
/// This is a thin wrapper around [`AcmeEngine::order_certificate`] kept for
/// backwards compatibility with any existing callers.
pub async fn issue_certificates(config: &AcmeConfig) -> Result<()> {
    info!(
        enabled = config.enabled,
        domains = ?config.domains,
        "acme: issue_certificates called"
    );
    let engine = AcmeEngine::new(config.clone());
    engine.order_certificate().await.map(|_| ())
}

/// Check whether any managed certificate is due for renewal.
///
/// Returns `true` if at least one certificate requires renewal.
pub async fn renewal_check(config: &AcmeConfig) -> Result<bool> {
    info!(
        domains = ?config.domains,
        "acme: renewal_check called"
    );
    let engine = AcmeEngine::new(config.clone());
    Ok(engine.renewal_check())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{AcmeChallengeType, AcmeConfig, AcmeProvider};

    fn base_config() -> AcmeConfig {
        AcmeConfig {
            enabled: true,
            provider: AcmeProvider::LetsEncrypt,
            email: "admin@example.com".into(),
            directory_url: None,
            domains: vec!["example.com".into()],
            cert_storage_path: "/tmp/test-acme-certs".into(),
            challenge_type: AcmeChallengeType::Http01,
            renew_interval_hours: 12,
        }
    }

    #[test]
    fn new_engine_has_empty_challenge_store() {
        let engine = AcmeEngine::new(base_config());
        // The store must be created empty; we check this synchronously.
        let store = engine.challenge_store.inner.try_read().unwrap();
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn challenge_store_insert_and_get() {
        let engine = AcmeEngine::new(base_config());
        engine
            .challenge_store
            .insert("tok1".into(), "key-auth-1".into())
            .await;
        let val = engine.challenge_store.get("tok1").await;
        assert_eq!(val.as_deref(), Some("key-auth-1"));
    }

    #[tokio::test]
    async fn challenge_store_remove() {
        let engine = AcmeEngine::new(base_config());
        engine
            .challenge_store
            .insert("tok2".into(), "key-auth-2".into())
            .await;
        engine.challenge_store.remove("tok2").await;
        assert!(engine.challenge_store.get("tok2").await.is_none());
    }

    #[tokio::test]
    async fn challenge_store_missing_key_returns_none() {
        let engine = AcmeEngine::new(base_config());
        assert!(engine.challenge_store.get("nonexistent").await.is_none());
    }

    #[test]
    fn renewal_check_missing_cert_returns_true() {
        let mut cfg = base_config();
        cfg.cert_storage_path = format!("/tmp/acme-no-cert-{}", uuid::Uuid::new_v4());
        let engine = AcmeEngine::new(cfg);
        // No certificate on disk → should report needing renewal.
        assert!(engine.renewal_check());
    }

    #[test]
    fn directory_url_defaults_to_lets_encrypt() {
        let engine = AcmeEngine::new(base_config());
        assert!(engine.directory_url().contains("letsencrypt.org"));
    }

    #[test]
    fn directory_url_custom_override() {
        let mut cfg = base_config();
        cfg.directory_url = Some("https://acme.example.com/dir".into());
        let engine = AcmeEngine::new(cfg);
        assert_eq!(engine.directory_url(), "https://acme.example.com/dir");
    }

    #[test]
    fn compute_sha256_produces_32_bytes() {
        let hash = compute_sha256(b"hello world");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn compute_sha256_deterministic() {
        let h1 = compute_sha256(b"test");
        let h2 = compute_sha256(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_sha256_different_inputs_differ() {
        let h1 = compute_sha256(b"foo");
        let h2 = compute_sha256(b"bar");
        assert_ne!(h1, h2);
    }
}
