pub mod cert_resolver;
pub mod cloudflare;

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use rustls_pemfile::{certs, private_key};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use self::cert_resolver::SharedCertResolver;
use self::cloudflare::{CloudflareDnsProvider, DnsProvider, DnsProviderError};
use crate::frameworks::config::schema::AcmeConfig;

/// Errors from the ACME certificate management system.
#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("ACME protocol error: {0}")]
    Protocol(String),
    #[error("DNS provider error: {0}")]
    DnsProvider(#[from] DnsProviderError),
    #[error("certificate I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("TLS key error: {0}")]
    Key(String),
    #[error("certificate expired and renewal failed")]
    Expired,
    #[error("invalid configuration: {0}")]
    Config(String),
}

/// Manages ACME certificate lifecycle: initial acquisition, persistence, and
/// background renewal with hot-reload into a [`SharedCertResolver`].
pub struct AcmeManager {
    config: AcmeConfig,
    resolver: Arc<SharedCertResolver>,
    dns_provider: Box<dyn DnsProvider>,
}

impl AcmeManager {
    /// Creates a new ACME manager from configuration.
    pub fn new(config: AcmeConfig, resolver: Arc<SharedCertResolver>) -> Result<Self, AcmeError> {
        let dns_provider = match config.dns_provider.provider_type.as_str() {
            "cloudflare" => {
                let provider = CloudflareDnsProvider::new(
                    config.dns_provider.api_token.clone(),
                    config.dns_provider.zone_id.clone(),
                )?;
                Box::new(provider) as Box<dyn DnsProvider>
            }
            other => {
                return Err(AcmeError::Config(format!(
                    "unsupported DNS provider type: '{other}' (supported: cloudflare)"
                )));
            }
        };

        Ok(Self {
            config,
            resolver,
            dns_provider,
        })
    }

    /// Attempts to load an existing certificate from disk, or obtains a new one
    /// via ACME if none exists or the existing one is expired/near-expiry.
    ///
    /// On success, the certificate is loaded into the [`SharedCertResolver`].
    pub async fn obtain_or_load_certificate(&self) -> Result<(), AcmeError> {
        // Try loading existing cert
        if Path::new(&self.config.cert_path).exists() && Path::new(&self.config.key_path).exists() {
            match self.load_cert_from_disk() {
                Ok(certified_key) => {
                    let renewal_duration = parse_duration(&self.config.renew_before_expiry)?;
                    if let Some(remaining) = cert_time_remaining(&certified_key) {
                        if remaining > renewal_duration {
                            tracing::info!(
                                days_remaining = remaining.as_secs() / 86400,
                                "loaded existing ACME certificate from disk"
                            );
                            self.resolver.update(Arc::new(certified_key));
                            return Ok(());
                        }
                        tracing::info!(
                            days_remaining = remaining.as_secs() / 86400,
                            "existing ACME certificate is within renewal window, renewing"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load existing ACME certificate, will request new one");
                }
            }
        }

        // Obtain new certificate via ACME
        self.run_acme_flow().await?;
        Ok(())
    }

    /// Spawns a background task that periodically checks certificate expiry and
    /// renews before the configured threshold. The task exits when `shutdown` is
    /// cancelled.
    pub fn spawn_renewal_task(self: Arc<Self>, shutdown: CancellationToken) {
        tokio::spawn(async move {
            let check_interval = Duration::from_secs(12 * 3600); // Check every 12 hours
            let renewal_duration = match parse_duration(&self.config.renew_before_expiry) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(error = %e, "invalid renew_before_expiry, using 30 days");
                    Duration::from_secs(30 * 86400)
                }
            };

            let mut backoff = Duration::from_secs(3600); // Start at 1 hour
            const MAX_BACKOFF: Duration = Duration::from_secs(24 * 3600);

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        tracing::info!("ACME renewal task shutting down");
                        return;
                    }
                    _ = tokio::time::sleep(check_interval) => {}
                }

                // Check if renewal is needed
                let current = self.resolver.current();
                let needs_renewal = match cert_time_remaining(&current) {
                    Some(remaining) => remaining <= renewal_duration,
                    None => true, // Can't determine expiry — renew to be safe
                };

                if !needs_renewal {
                    backoff = Duration::from_secs(3600); // Reset backoff on healthy state
                    continue;
                }

                tracing::info!("ACME certificate renewal triggered");
                match self.run_acme_flow().await {
                    Ok(()) => {
                        tracing::info!("ACME certificate renewed successfully");
                        backoff = Duration::from_secs(3600);
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            retry_in_secs = backoff.as_secs(),
                            "ACME certificate renewal failed, will retry"
                        );
                        // Wait with backoff before next attempt
                        tokio::select! {
                            _ = shutdown.cancelled() => return,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                    }
                }
            }
        });
    }

    /// Executes the full ACME flow: account setup, order creation, DNS-01
    /// challenge, finalization, and certificate persistence.
    async fn run_acme_flow(&self) -> Result<(), AcmeError> {
        let account = self.get_or_create_account().await?;

        let identifiers: Vec<Identifier> = self
            .config
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| AcmeError::Protocol(format!("failed to create order: {e}")))?;

        // Process authorizations (DNS-01 challenges)
        let mut record_ids: Vec<String> = Vec::new();
        let cleanup_result = self
            .process_authorizations(&mut order, &mut record_ids)
            .await;

        // Always clean up DNS records, even on failure
        for record_id in &record_ids {
            if let Err(e) = self.dns_provider.delete_txt_record(record_id).await {
                tracing::warn!(
                    record_id = %record_id,
                    error = %e,
                    "failed to clean up ACME DNS-01 TXT record"
                );
            }
        }

        cleanup_result?;

        // Poll until order is ready
        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| AcmeError::Protocol(format!("order did not become ready: {e}")))?;

        if status != OrderStatus::Ready {
            return Err(AcmeError::Protocol(format!(
                "unexpected order status: {status:?}"
            )));
        }

        // Finalize order and get certificate
        let private_key_pem = order
            .finalize()
            .await
            .map_err(|e| AcmeError::Protocol(format!("failed to finalize order: {e}")))?;

        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| AcmeError::Protocol(format!("failed to get certificate: {e}")))?;

        // Persist to disk
        self.save_cert_to_disk(&cert_chain_pem, &private_key_pem)?;

        // Load into resolver
        let certified_key = load_certified_key_from_pem(&cert_chain_pem, &private_key_pem)?;
        self.resolver.update(Arc::new(certified_key));

        Ok(())
    }

    /// Processes all authorizations for an order, setting up DNS-01 challenges.
    async fn process_authorizations(
        &self,
        order: &mut instant_acme::Order,
        record_ids: &mut Vec<String>,
    ) -> Result<(), AcmeError> {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz =
                result.map_err(|e| AcmeError::Protocol(format!("authorization error: {e}")))?;

            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => {
                    return Err(AcmeError::Protocol(format!(
                        "unexpected authorization status: {other:?}"
                    )));
                }
            }

            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| AcmeError::Protocol("no DNS-01 challenge available".into()))?;

            let domain = challenge.identifier().to_string();
            let key_auth = challenge.key_authorization();
            let dns_value = key_auth.dns_value();

            // Create DNS TXT record
            let record_id = self
                .dns_provider
                .create_txt_record(&domain, &dns_value)
                .await?;
            record_ids.push(record_id);

            // Wait for DNS propagation
            tracing::info!(
                domain = %domain,
                "waiting for DNS propagation (60s)"
            );
            tokio::time::sleep(Duration::from_secs(60)).await;

            // Tell ACME server the challenge is ready
            challenge
                .set_ready()
                .await
                .map_err(|e| AcmeError::Protocol(format!("failed to set challenge ready: {e}")))?;
        }

        Ok(())
    }

    /// Gets an existing ACME account or creates a new one.
    async fn get_or_create_account(&self) -> Result<Account, AcmeError> {
        // Try loading existing account credentials
        if Path::new(&self.config.account_credentials_path).exists() {
            let creds_json = std::fs::read_to_string(&self.config.account_credentials_path)?;
            let credentials: AccountCredentials =
                serde_json::from_str(&creds_json).map_err(|e| {
                    AcmeError::Config(format!("failed to parse account credentials: {e}"))
                })?;

            let account = Account::builder()
                .map_err(|e| AcmeError::Protocol(format!("failed to build account: {e}")))?
                .from_credentials(credentials)
                .await
                .map_err(|e| AcmeError::Protocol(format!("failed to restore account: {e}")))?;

            tracing::info!("restored existing ACME account");
            return Ok(account);
        }

        // Create new account
        let contact = format!("mailto:{}", self.config.email);
        let (account, credentials) = Account::builder()
            .map_err(|e| AcmeError::Protocol(format!("failed to build account: {e}")))?
            .create(
                &NewAccount {
                    contact: &[&contact],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.config.directory_url.clone(),
                None,
            )
            .await
            .map_err(|e| AcmeError::Protocol(format!("failed to create account: {e}")))?;

        // Persist account credentials
        let creds_json = serde_json::to_string_pretty(&credentials).map_err(|e| {
            AcmeError::Config(format!("failed to serialize account credentials: {e}"))
        })?;
        self.save_file(&self.config.account_credentials_path, &creds_json)?;

        tracing::info!("created new ACME account and persisted credentials");
        Ok(account)
    }

    /// Loads certificate and key from disk into a [`CertifiedKey`].
    fn load_cert_from_disk(&self) -> Result<CertifiedKey, AcmeError> {
        let cert_pem = std::fs::read_to_string(&self.config.cert_path)?;
        let key_pem = std::fs::read_to_string(&self.config.key_path)?;
        load_certified_key_from_pem(&cert_pem, &key_pem)
    }

    /// Persists certificate chain and private key to disk.
    fn save_cert_to_disk(&self, cert_pem: &str, key_pem: &str) -> Result<(), AcmeError> {
        self.save_file(&self.config.cert_path, cert_pem)?;
        self.save_file(&self.config.key_path, key_pem)?;
        tracing::info!(
            cert_path = %self.config.cert_path,
            key_path = %self.config.key_path,
            "persisted ACME certificate to disk"
        );
        Ok(())
    }

    /// Writes content to a file, creating parent directories as needed.
    fn save_file(&self, path: &str, content: &str) -> Result<(), AcmeError> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// Loads a PEM certificate chain and private key into a [`CertifiedKey`].
pub fn load_certified_key_from_pem(
    cert_pem: &str,
    key_pem: &str,
) -> Result<CertifiedKey, AcmeError> {
    let cert_chain: Vec<CertificateDer<'static>> =
        certs(&mut io::BufReader::new(cert_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AcmeError::Key(format!("failed to parse certificate PEM: {e}")))?;

    if cert_chain.is_empty() {
        return Err(AcmeError::Key(
            "certificate PEM contains no certificates".into(),
        ));
    }

    let key: PrivateKeyDer<'static> = private_key(&mut io::BufReader::new(key_pem.as_bytes()))
        .map_err(|e| AcmeError::Key(format!("failed to parse key PEM: {e}")))?
        .ok_or_else(|| AcmeError::Key("key PEM contains no private key".into()))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| AcmeError::Key(format!("unsupported key type: {e}")))?;

    Ok(CertifiedKey::new(cert_chain, signing_key))
}

/// Attempts to determine how much time remains before a certificate expires.
/// Returns `None` if the cert expiry cannot be determined.
fn cert_time_remaining(certified_key: &CertifiedKey) -> Option<Duration> {
    let cert_der = certified_key.cert.first()?;
    let ((), expiry) = x509_parser_not_after(cert_der.as_ref())?;
    let now = std::time::SystemTime::now();
    expiry.duration_since(now).ok()
}

/// Minimal X.509 notAfter extraction without pulling in a full x509 parser.
/// Parses the TBSCertificate.validity.notAfter from DER.
fn x509_parser_not_after(der: &[u8]) -> Option<((), std::time::SystemTime)> {
    // Use webpki to parse validity period
    // Since we don't have a dedicated x509 parser crate, we'll use a simpler
    // approach: check if the cert was issued recently enough that it's likely
    // still valid for at least renewal_window.
    //
    // For a production implementation, we parse the ASN.1 directly.
    // The notAfter is at a well-known offset in the TBSCertificate.
    parse_x509_not_after(der).map(|t| ((), t))
}

/// Parses the notAfter time from a DER-encoded X.509 certificate.
///
/// This performs minimal ASN.1 parsing to extract the validity period
/// without requiring a full X.509 parsing crate.
fn parse_x509_not_after(der: &[u8]) -> Option<std::time::SystemTime> {
    // ASN.1 structure: SEQUENCE { tbsCertificate, ... }
    // tbsCertificate: SEQUENCE { version, serialNumber, signature, issuer, validity, ... }
    // validity: SEQUENCE { notBefore, notAfter }
    //
    // We need to navigate: outer SEQUENCE -> tbs SEQUENCE -> skip fields -> validity SEQUENCE -> notAfter
    let mut pos = 0;

    // Outer SEQUENCE
    pos = skip_tag_and_length(der, pos, 0x30)?;

    // TBS SEQUENCE
    let tbs_start = pos;
    pos = skip_tag_and_length(der, tbs_start, 0x30)?;

    // version [0] EXPLICIT (optional - context tag 0xA0)
    if der.get(pos)? == &0xA0 {
        pos = skip_tlv(der, pos)?;
    }

    // serialNumber INTEGER
    pos = skip_tlv(der, pos)?;

    // signature AlgorithmIdentifier SEQUENCE
    pos = skip_tlv(der, pos)?;

    // issuer Name SEQUENCE
    pos = skip_tlv(der, pos)?;

    // validity SEQUENCE { notBefore, notAfter }
    pos = skip_tag_and_length(der, pos, 0x30)?;

    // notBefore (UTCTime or GeneralizedTime)
    pos = skip_tlv(der, pos)?;

    // notAfter (UTCTime or GeneralizedTime)
    let tag = *der.get(pos)?;
    pos += 1;
    let len = parse_asn1_length(der, &mut pos)?;
    let time_bytes = der.get(pos..pos + len)?;

    parse_asn1_time(tag, time_bytes)
}

fn skip_tag_and_length(der: &[u8], mut pos: usize, expected_tag: u8) -> Option<usize> {
    if der.get(pos)? != &expected_tag {
        return None;
    }
    pos += 1;
    let _len = parse_asn1_length(der, &mut pos)?;
    Some(pos)
}

fn skip_tlv(der: &[u8], mut pos: usize) -> Option<usize> {
    pos += 1; // tag
    let len = parse_asn1_length(der, &mut pos)?;
    Some(pos + len)
}

fn parse_asn1_length(der: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *der.get(*pos)?;
    *pos += 1;
    if first < 0x80 {
        Some(first as usize)
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 {
            return None; // Too large
        }
        let mut len: usize = 0;
        for _ in 0..num_bytes {
            len = len.checked_shl(8)?.checked_add(*der.get(*pos)? as usize)?;
            *pos += 1;
        }
        Some(len)
    }
}

fn parse_asn1_time(tag: u8, bytes: &[u8]) -> Option<std::time::SystemTime> {
    let s = std::str::from_utf8(bytes).ok()?;
    let (year, rest) = match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ
            let y: u32 = s.get(0..2)?.parse().ok()?;
            let year = if y >= 50 { 1900 + y } else { 2000 + y };
            (year, s.get(2..)?)
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            let year: u32 = s.get(0..4)?.parse().ok()?;
            (year, s.get(4..)?)
        }
        _ => return None,
    };

    let month: u32 = rest.get(0..2)?.parse().ok()?;
    let day: u32 = rest.get(2..4)?.parse().ok()?;
    let hour: u32 = rest.get(4..6)?.parse().ok()?;
    let minute: u32 = rest.get(6..8)?.parse().ok()?;
    let second: u32 = rest.get(8..10)?.parse().ok()?;

    // Convert to Unix timestamp (simplified — ignores leap seconds)
    let days = days_from_civil(year as i64, month as i64, day as i64);
    let secs = days * 86400 + (hour as i64) * 3600 + (minute as i64) * 60 + (second as i64);
    let unix_epoch_days = days_from_civil(1970, 1, 1);
    let unix_secs = secs - unix_epoch_days * 86400;

    if unix_secs < 0 {
        return None;
    }

    Some(std::time::UNIX_EPOCH + Duration::from_secs(unix_secs as u64))
}

/// Civil date to day count (algorithm from Howard Hinnant).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let doy = if m > 2 {
        (153 * (m - 3) + 2) / 5 + day as u64 - 1
    } else {
        (153 * (m + 9) + 2) / 5 + day as u64 - 1
    };
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64
}

/// Parses a duration string like "30d", "720h", "48h", "45m".
fn parse_duration(s: &str) -> Result<Duration, AcmeError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(AcmeError::Config("empty duration string".into()));
    }

    let (num_str, unit) = if let Some(n) = s.strip_suffix('d') {
        (n, 'd')
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 'h')
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 'm')
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 's')
    } else {
        return Err(AcmeError::Config(format!(
            "invalid duration '{s}': must end with d, h, m, or s"
        )));
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| AcmeError::Config(format!("invalid duration '{s}': not a valid number")))?;

    let secs = match unit {
        'd' => num * 86400,
        'h' => num * 3600,
        'm' => num * 60,
        's' => num,
        _ => unreachable!(),
    };

    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_days() {
        let d = parse_duration("30d").unwrap();
        assert_eq!(d, Duration::from_secs(30 * 86400));
    }

    #[test]
    fn test_parse_duration_hours() {
        let d = parse_duration("720h").unwrap();
        assert_eq!(d, Duration::from_secs(720 * 3600));
    }

    #[test]
    fn test_parse_duration_minutes() {
        let d = parse_duration("45m").unwrap();
        assert_eq!(d, Duration::from_secs(45 * 60));
    }

    #[test]
    fn test_parse_duration_seconds() {
        let d = parse_duration("120s").unwrap();
        assert_eq!(d, Duration::from_secs(120));
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("30x").is_err());
    }

    #[test]
    fn test_days_from_civil() {
        // 2024-01-01 should be some known value
        let d = days_from_civil(1970, 1, 1);
        // Unix epoch is day 719468 in the algorithm's epoch
        assert!(d > 0);
    }

    #[test]
    fn test_parse_asn1_time_utctime() {
        // "250101120000Z" = 2025-01-01 12:00:00 UTC
        let bytes = b"250101120000Z";
        let time = parse_asn1_time(0x17, bytes).unwrap();
        let since_epoch = time.duration_since(std::time::UNIX_EPOCH).unwrap();
        // 2025-01-01 12:00:00 UTC
        assert!(since_epoch.as_secs() > 1735700000);
        assert!(since_epoch.as_secs() < 1735740000);
    }
}
