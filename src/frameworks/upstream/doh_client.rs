use std::time::Duration;

use async_trait::async_trait;

use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};
use crate::use_cases::zone_authority::ZoneSourceAuth;

const DOH_TIMEOUT_SECS: u64 = 10;

/// DNS-over-HTTPS upstream resolver (RFC 8484).
///
/// Sends the DNS wire-format query as an HTTP POST to the configured URL with
/// `Content-Type: application/dns-message` and reads the wire-format response.
/// Supports optional Bearer or Basic HTTP authentication.
#[derive(Debug, Clone)]
pub struct DnsHttpsClient {
    url: String,
    auth: Option<ZoneSourceAuth>,
}

impl DnsHttpsClient {
    pub fn new(url: String, auth: Option<ZoneSourceAuth>) -> Self {
        Self { url, auth }
    }
}

#[async_trait]
impl UpstreamResolver for DnsHttpsClient {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
        let url = self.url.clone();
        let auth = self.auth.clone();

        tokio::task::spawn_blocking(move || resolve_doh_blocking(&url, &query, auth.as_ref()))
            .await
            .map_err(|e| UpstreamResolveError::Protocol(format!("DoH task join error: {e}")))?
    }
}

fn resolve_doh_blocking(
    url: &str,
    query: &[u8],
    auth: Option<&ZoneSourceAuth>,
) -> Result<Vec<u8>, UpstreamResolveError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(DOH_TIMEOUT_SECS))
        .build()
        .map_err(|e| {
            UpstreamResolveError::Protocol(format!("failed to build DoH HTTP client: {e}"))
        })?;

    let mut request = client
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query.to_vec());

    if let Some(zone_auth) = auth {
        request = match zone_auth {
            ZoneSourceAuth::Bearer(token) => request.bearer_auth(token),
            ZoneSourceAuth::Basic { username, password } => {
                request.basic_auth(username, Some(password))
            }
        };
    }

    let response = request.send().map_err(|e| {
        UpstreamResolveError::Protocol(format!("DoH request to '{url}' failed: {e}"))
    })?;

    if !response.status().is_success() {
        return Err(UpstreamResolveError::Protocol(format!(
            "DoH server at '{url}' returned status {}",
            response.status()
        )));
    }

    let body = response.bytes().map_err(|e| {
        UpstreamResolveError::Protocol(format!("failed to read DoH response from '{url}': {e}"))
    })?;

    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_client_new_stores_url_and_auth() {
        let client = DnsHttpsClient::new(
            "https://dns.example.com/dns-query".to_string(),
            Some(ZoneSourceAuth::Bearer("token".to_string())),
        );
        assert_eq!(client.url, "https://dns.example.com/dns-query");
        assert!(matches!(client.auth, Some(ZoneSourceAuth::Bearer(_))));
    }

    #[test]
    fn doh_client_new_without_auth() {
        let client = DnsHttpsClient::new("https://dns.example.com/dns-query".to_string(), None);
        assert!(client.auth.is_none());
    }
}
