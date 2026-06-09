use serde::Deserialize;
use thiserror::Error;

/// Errors from DNS provider operations.
#[derive(Debug, Error)]
pub enum DnsProviderError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API error ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("zone not found for domain: {0}")]
    ZoneNotFound(String),
    #[error("invalid configuration: {0}")]
    Config(String),
}

/// Trait for DNS providers that can manage TXT records for ACME DNS-01 challenges.
///
/// Implementations must be able to create and remove `_acme-challenge.{domain}`
/// TXT records. This trait is object-safe so providers can be swapped at runtime.
#[async_trait::async_trait]
pub trait DnsProvider: Send + Sync {
    /// Creates a TXT record for ACME DNS-01 validation.
    ///
    /// # Arguments
    /// * `domain` — The fully-qualified domain (without `_acme-challenge.` prefix;
    ///   the implementation adds it).
    /// * `value` — The DNS-01 key authorization digest value.
    ///
    /// Returns a record identifier that can be passed to [`delete_txt_record`].
    async fn create_txt_record(
        &self,
        domain: &str,
        value: &str,
    ) -> Result<String, DnsProviderError>;

    /// Deletes a previously created TXT record by its identifier.
    async fn delete_txt_record(&self, record_id: &str) -> Result<(), DnsProviderError>;
}

/// Cloudflare DNS provider for ACME DNS-01 challenges.
///
/// Uses the Cloudflare API v4 to create and delete `_acme-challenge` TXT records.
pub struct CloudflareDnsProvider {
    client: reqwest::Client,
    api_token: String,
    zone_id: Option<String>,
}

impl CloudflareDnsProvider {
    /// Creates a new Cloudflare DNS provider.
    ///
    /// # Arguments
    /// * `api_token` — Cloudflare API token with DNS edit permissions.
    ///   Supports `${ENV_VAR}` syntax for reading from environment.
    /// * `zone_id` — Optional zone ID. If `None`, auto-detected from domain.
    pub fn new(api_token: String, zone_id: Option<String>) -> Result<Self, DnsProviderError> {
        let resolved_token = expand_env_var(&api_token);
        if resolved_token.is_empty() {
            return Err(DnsProviderError::Config(
                "api_token is empty (check environment variable)".into(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(DnsProviderError::Http)?;

        Ok(Self {
            client,
            api_token: resolved_token,
            zone_id,
        })
    }

    /// Resolves the zone ID for a given domain, either from config or via API lookup.
    async fn resolve_zone_id(&self, domain: &str) -> Result<String, DnsProviderError> {
        if let Some(ref zone_id) = self.zone_id {
            return Ok(zone_id.clone());
        }
        self.find_zone_id(domain).await
    }

    /// Auto-detects the Cloudflare zone ID by walking up the domain hierarchy.
    async fn find_zone_id(&self, domain: &str) -> Result<String, DnsProviderError> {
        // Walk up the domain: "sub.example.com" -> "example.com" -> "com"
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 0..parts.len().saturating_sub(1) {
            let candidate = parts[i..].join(".");
            let url = format!(
                "https://api.cloudflare.com/client/v4/zones?name={}&status=active",
                candidate
            );

            let resp = self
                .client
                .get(&url)
                .header("Authorization", format!("Bearer {}", self.api_token))
                .header("Content-Type", "application/json")
                .send()
                .await?;

            let status = resp.status().as_u16();
            let body: CloudflareListResponse = resp.json().await?;

            if !body.success {
                let msg = body
                    .errors
                    .into_iter()
                    .map(|e| e.message)
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(DnsProviderError::Api {
                    status,
                    message: msg,
                });
            }

            if let Some(zone) = body.result.into_iter().next() {
                tracing::info!(
                    zone_id = %zone.id,
                    zone_name = %zone.name,
                    "auto-detected Cloudflare zone"
                );
                return Ok(zone.id);
            }
        }

        Err(DnsProviderError::ZoneNotFound(domain.to_string()))
    }
}

#[async_trait::async_trait]
impl DnsProvider for CloudflareDnsProvider {
    async fn create_txt_record(
        &self,
        domain: &str,
        value: &str,
    ) -> Result<String, DnsProviderError> {
        let zone_id = self.resolve_zone_id(domain).await?;
        let record_name = format!("_acme-challenge.{domain}");

        let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");

        let payload = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120
        });

        tracing::debug!(
            zone_id = %zone_id,
            record = %record_name,
            "creating ACME DNS-01 TXT record via Cloudflare"
        );

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        let status = resp.status().as_u16();
        let body: CloudflareRecordResponse = resp.json().await?;

        if !body.success {
            let msg = body
                .errors
                .into_iter()
                .map(|e| e.message)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(DnsProviderError::Api {
                status,
                message: msg,
            });
        }

        let record_id = body
            .result
            .map(|r| r.id)
            .ok_or_else(|| DnsProviderError::Api {
                status,
                message: "no record ID in response".into(),
            })?;

        tracing::info!(
            record_id = %record_id,
            record = %record_name,
            "created ACME DNS-01 TXT record"
        );

        // Return composite ID so delete_txt_record can resolve zone_id
        Ok(format!("{zone_id}/{record_id}"))
    }

    async fn delete_txt_record(&self, record_id: &str) -> Result<(), DnsProviderError> {
        // We need the zone_id to delete — store it in the record_id format: "zone_id/record_id"
        let (zone_id, actual_record_id) = record_id
            .split_once('/')
            .ok_or_else(|| DnsProviderError::Config("invalid record_id format".into()))?;

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{actual_record_id}"
        );

        tracing::debug!(
            record_id = %actual_record_id,
            zone_id = %zone_id,
            "deleting ACME DNS-01 TXT record via Cloudflare"
        );

        let resp = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body: CloudflareBaseResponse = resp.json().await?;
            let msg = body
                .errors
                .into_iter()
                .map(|e| e.message)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(DnsProviderError::Api {
                status,
                message: msg,
            });
        }

        tracing::info!(record_id = %actual_record_id, "deleted ACME DNS-01 TXT record");
        Ok(())
    }
}

/// Expands `${ENV_VAR}` syntax in a string value. If the string matches the
/// pattern `${...}`, the environment variable is looked up. Otherwise the
/// original value is returned unchanged.
pub fn expand_env_var(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with("${") && trimmed.ends_with('}') {
        let var_name = &trimmed[2..trimmed.len() - 1];
        match std::env::var(var_name) {
            Ok(val) => val,
            Err(_) => {
                tracing::warn!(
                    var = %var_name,
                    "environment variable not set, using empty string"
                );
                String::new()
            }
        }
    } else {
        value.to_string()
    }
}

// --- Cloudflare API response types ---

#[derive(Debug, Deserialize)]
struct CloudflareBaseResponse {
    #[allow(dead_code)]
    success: bool,
    errors: Vec<CloudflareError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareListResponse {
    success: bool,
    errors: Vec<CloudflareError>,
    result: Vec<CloudflareZone>,
}

#[derive(Debug, Deserialize)]
struct CloudflareRecordResponse {
    success: bool,
    errors: Vec<CloudflareError>,
    result: Option<CloudflareRecord>,
}

#[derive(Debug, Deserialize)]
struct CloudflareZone {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareRecord {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_env_var_literal() {
        assert_eq!(expand_env_var("my-token-value"), "my-token-value");
    }

    #[test]
    fn test_expand_env_var_env_syntax() {
        std::env::set_var("TEST_ACME_TOKEN_123", "secret-value");
        assert_eq!(expand_env_var("${TEST_ACME_TOKEN_123}"), "secret-value");
        std::env::remove_var("TEST_ACME_TOKEN_123");
    }

    #[test]
    fn test_expand_env_var_missing_env() {
        assert_eq!(expand_env_var("${NONEXISTENT_VAR_XYZ_ACME_TEST}"), "");
    }

    #[test]
    fn test_expand_env_var_partial_syntax() {
        // Not a valid env var pattern — returned as-is
        assert_eq!(expand_env_var("${INCOMPLETE"), "${INCOMPLETE");
        assert_eq!(expand_env_var("prefix_${VAR}"), "prefix_${VAR}");
    }

    #[test]
    fn test_cloudflare_provider_empty_token_rejected() {
        let result = CloudflareDnsProvider::new(String::new(), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_cloudflare_provider_env_empty_rejected() {
        // Use an env var that doesn't exist
        let result =
            CloudflareDnsProvider::new("${NONEXISTENT_VAR_ACME_CLOUD_TEST}".to_string(), None);
        assert!(result.is_err());
    }
}
