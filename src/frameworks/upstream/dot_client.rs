use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_client::client::{ClientHandle, DnssecClient};
use hickory_client::proto::op::{Message, Query};
use hickory_client::proto::rr::{DNSClass, Name, RecordType};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::rustls::{client_config, tls_client_connect};
use hickory_client::proto::xfer::DnsMultiplexer;
use tokio::sync::Mutex;

use crate::frameworks::upstream::DnsUdpTcpClient;
use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};

const DOT_DEFAULT_PORT: u16 = 853;
const DOT_TIMEOUT: Duration = Duration::from_secs(10);

/// A cached DoT client connection shared across queries.
///
/// `DnssecClient` does not implement `Debug`, so we wrap the cache in a newtype
/// that provides a no-op `Debug` impl so that `DnsTlsClient` can still derive it.
#[derive(Clone, Default)]
struct ClientCache(Arc<Mutex<Option<DnssecClient>>>);

impl fmt::Debug for ClientCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCache").finish_non_exhaustive()
    }
}

/// DNS resolver that sends queries over DNS-over-TLS (DoT).
#[derive(Debug, Clone)]
pub struct DnsTlsClient {
    endpoint: DotEndpoint,
    server_name: String,
    bootstrap_resolvers: Vec<SocketAddr>,
    client_cache: ClientCache,
}

#[derive(Debug, Clone)]
enum DotEndpoint {
    Static(SocketAddr),
    Hostname { host: String, port: u16 },
}

impl DnsTlsClient {
    pub fn new(address: SocketAddr, server_name: String) -> Self {
        Self {
            endpoint: DotEndpoint::Static(address),
            server_name,
            bootstrap_resolvers: vec![SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53)],
            client_cache: ClientCache::default(),
        }
    }

    pub fn new_hostname(host: String, port: u16) -> Self {
        let server_name = host_without_trailing_dot(&host);
        Self {
            endpoint: DotEndpoint::Hostname { host, port },
            server_name,
            bootstrap_resolvers: vec![SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53)],
            client_cache: ClientCache::default(),
        }
    }

    pub fn with_bootstrap_resolvers(mut self, resolvers: Vec<SocketAddr>) -> Self {
        if !resolvers.is_empty() {
            self.bootstrap_resolvers = resolvers;
        }
        self
    }

    pub fn parse_endpoint(value: &str) -> Result<Self, UpstreamResolveError> {
        let endpoint = value.strip_prefix("tls://").unwrap_or(value);

        if endpoint.trim().is_empty() {
            return Err(UpstreamResolveError::Protocol(
                "invalid DoT upstream address; endpoint is empty".to_string(),
            ));
        }

        if endpoint.parse::<SocketAddr>().is_ok() {
            let address = endpoint
                .parse::<SocketAddr>()
                .map_err(|e| UpstreamResolveError::Protocol(format!("{e}")))?;
            return Ok(Self::new(address, address.ip().to_string()));
        }

        if endpoint.parse::<IpAddr>().is_ok() {
            let ip = endpoint
                .parse::<IpAddr>()
                .map_err(|e| UpstreamResolveError::Protocol(format!("{e}")))?;
            return Ok(Self::new(
                SocketAddr::new(ip, DOT_DEFAULT_PORT),
                ip.to_string(),
            ));
        }

        if let Some((host, port)) = parse_hostname_with_optional_port(endpoint)? {
            return Ok(Self::new_hostname(host, port));
        }

        Err(UpstreamResolveError::Protocol(
            "invalid DoT upstream address; expected tls://<host>[:port], <host>:<port>, <host>, tls://<ip>[:port], <ip>:<port>, or <ip>".to_string(),
        ))
    }

    async fn resolve_address(&self) -> Result<SocketAddr, UpstreamResolveError> {
        match &self.endpoint {
            DotEndpoint::Static(address) => Ok(*address),
            DotEndpoint::Hostname { host, port } => {
                match tokio::net::lookup_host((host.as_str(), *port)).await {
                    Ok(mut addrs) => addrs.next().ok_or_else(|| {
                        UpstreamResolveError::Protocol(format!(
                            "no resolved address for DoT hostname '{host}:{port}'"
                        ))
                    }),
                    Err(os_error) => self
                        .resolve_hostname_via_bootstrap(host, *port)
                        .await
                        .map_err(|bootstrap_error| {
                            UpstreamResolveError::Protocol(format!(
                                "failed to resolve DoT hostname '{host}:{port}' using OS resolver ({os_error}) and bootstrap resolvers ({bootstrap_error})"
                            ))
                        }),
                }
            }
        }
    }

    async fn resolve_hostname_via_bootstrap(
        &self,
        host: &str,
        port: u16,
    ) -> Result<SocketAddr, UpstreamResolveError> {
        let a_query = build_dns_query(host, RecordType::A)?;
        let aaaa_query = build_dns_query(host, RecordType::AAAA)?;

        for resolver in &self.bootstrap_resolvers {
            let client = DnsUdpTcpClient::new(*resolver);

            if let Ok(address) = try_extract_ip_from_response(&client, &a_query, port).await {
                return Ok(address);
            }

            if let Ok(address) = try_extract_ip_from_response(&client, &aaaa_query, port).await {
                return Ok(address);
            }
        }

        Err(UpstreamResolveError::Protocol(format!(
            "bootstrap resolvers did not return usable A/AAAA records for '{host}'"
        )))
    }

    fn extract_question(
        query: &[u8],
    ) -> Result<(Name, DNSClass, RecordType), UpstreamResolveError> {
        let message = Message::from_vec(query)
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;
        let question = message
            .queries()
            .first()
            .ok_or_else(|| UpstreamResolveError::Protocol("query contains no questions".into()))?;

        Ok((
            question.name().clone(),
            question.query_class(),
            question.query_type(),
        ))
    }

    async fn resolve_dot(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamResolveError> {
        let (name, query_class, query_type) = Self::extract_question(query)?;

        // Try the cached TLS connection first (clone to release the lock before I/O).
        let cached = self.client_cache.0.lock().await.clone();
        if let Some(mut client) = cached {
            match tokio::time::timeout(
                DOT_TIMEOUT,
                client.query(name.clone(), query_class, query_type),
            )
            .await
            {
                Ok(Ok(response)) => {
                    return response
                        .to_vec()
                        .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")));
                }
                _ => {
                    // Stale connection — evict and fall through to reconnect.
                    *self.client_cache.0.lock().await = None;
                }
            }
        }

        // Establish a fresh TLS connection.
        let address = self.resolve_address().await?;
        let provider = TokioRuntimeProvider::default();
        let tls_config = Arc::new(client_config());
        let (stream, sender) =
            tls_client_connect(address, self.server_name.clone(), tls_config, provider);
        let multiplexer = DnsMultiplexer::new(stream, sender, None);
        let (mut client, background) = DnssecClient::connect(multiplexer)
            .await
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

        tokio::spawn(background);

        let response =
            tokio::time::timeout(DOT_TIMEOUT, client.query(name, query_class, query_type))
                .await
                .map_err(|_| UpstreamResolveError::Timeout)?
                .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

        // Cache the connection for subsequent queries.
        *self.client_cache.0.lock().await = Some(client.clone());

        response
            .to_vec()
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))
    }
}

#[async_trait]
impl UpstreamResolver for DnsTlsClient {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
        self.resolve_dot(&query).await
    }
}

fn host_without_trailing_dot(value: &str) -> String {
    value.trim_end_matches('.').to_string()
}

fn fqdn_host(value: &str) -> String {
    if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{value}.")
    }
}

fn build_dns_query(host: &str, query_type: RecordType) -> Result<Vec<u8>, UpstreamResolveError> {
    let fqdn = fqdn_host(host);
    let name = Name::from_ascii(&fqdn).map_err(|e| {
        UpstreamResolveError::Protocol(format!("invalid DoT hostname '{host}': {e}"))
    })?;

    let mut message = Message::new();
    message.set_id(1);
    message.set_recursion_desired(true);
    message.add_query(Query::query(name, query_type));

    message
        .to_vec()
        .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))
}

async fn try_extract_ip_from_response(
    client: &DnsUdpTcpClient,
    query: &[u8],
    port: u16,
) -> Result<SocketAddr, UpstreamResolveError> {
    let response = client.resolve(query.to_vec()).await?;
    let message = Message::from_vec(&response)
        .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

    for answer in message.answers() {
        let data = answer.data();
        if let Some(ipv4) = data.as_a() {
            return Ok(SocketAddr::new(IpAddr::V4(ipv4.0), port));
        }

        if let Some(ipv6) = data.as_aaaa() {
            return Ok(SocketAddr::new(IpAddr::V6(ipv6.0), port));
        }
    }

    Err(UpstreamResolveError::Protocol(
        "no A/AAAA records in bootstrap response".to_string(),
    ))
}

fn parse_hostname_with_optional_port(
    value: &str,
) -> Result<Option<(String, u16)>, UpstreamResolveError> {
    if let Some((host, port_str)) = value.rsplit_once(':') {
        if !host.contains(':') {
            let host = host_without_trailing_dot(host);
            validate_hostname(&host)?;
            let port = port_str.parse::<u16>().map_err(|e| {
                UpstreamResolveError::Protocol(format!("invalid DoT port '{port_str}': {e}"))
            })?;
            return Ok(Some((host, port)));
        }
    }

    let host = host_without_trailing_dot(value);
    validate_hostname(&host)?;
    Ok(Some((host, DOT_DEFAULT_PORT)))
}

fn validate_hostname(host: &str) -> Result<(), UpstreamResolveError> {
    if host.is_empty() || host.len() > 253 {
        return Err(UpstreamResolveError::Protocol(
            "invalid DoT hostname length".to_string(),
        ));
    }

    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(UpstreamResolveError::Protocol(
                "invalid DoT hostname label length".to_string(),
            ));
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(UpstreamResolveError::Protocol(
                "invalid DoT hostname label; leading/trailing hyphen is not allowed".to_string(),
            ));
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(UpstreamResolveError::Protocol(
                "invalid DoT hostname label characters".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dot_endpoint_allows_tls_scheme_and_default_port() {
        let client = DnsTlsClient::parse_endpoint("tls://1.1.1.1").unwrap();

        match client.endpoint {
            DotEndpoint::Static(address) => assert_eq!(address, "1.1.1.1:853".parse().unwrap()),
            DotEndpoint::Hostname { .. } => panic!("expected static endpoint"),
        }
        assert_eq!(client.server_name, "1.1.1.1");
    }

    #[test]
    fn parse_dot_endpoint_allows_hostname_and_preserves_sni_name() {
        let client = DnsTlsClient::parse_endpoint("tls://dns.example.com:853").unwrap();

        match client.endpoint {
            DotEndpoint::Hostname { host, port } => {
                assert_eq!(host, "dns.example.com");
                assert_eq!(port, 853);
            }
            DotEndpoint::Static(_) => panic!("expected hostname endpoint"),
        }
        assert_eq!(client.server_name, "dns.example.com");
    }

    #[test]
    fn parse_dot_endpoint_defaults_hostname_port() {
        let client = DnsTlsClient::parse_endpoint("dns.example.com").unwrap();

        match client.endpoint {
            DotEndpoint::Hostname { host, port } => {
                assert_eq!(host, "dns.example.com");
                assert_eq!(port, 853);
            }
            DotEndpoint::Static(_) => panic!("expected hostname endpoint"),
        }
    }

    #[test]
    fn parse_dot_endpoint_rejects_invalid_host() {
        let error = DnsTlsClient::parse_endpoint("tls://dns_example.com").unwrap_err();
        assert!(matches!(error, UpstreamResolveError::Protocol(_)));
    }

    #[test]
    fn dot_client_defaults_bootstrap_resolver_to_cloudflare() {
        let client = DnsTlsClient::parse_endpoint("tls://dns.example.com").unwrap();
        assert_eq!(
            client.bootstrap_resolvers,
            vec!["1.1.1.1:53".parse().unwrap()]
        );
    }

    #[test]
    fn extract_question_rejects_empty_query() {
        let error = DnsTlsClient::extract_question(&[0u8; 12]).unwrap_err();
        assert!(matches!(error, UpstreamResolveError::Protocol(_)));
    }
}
