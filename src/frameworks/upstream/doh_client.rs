use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use hickory_net::h2::HttpsClientStream;
use hickory_net::http::SetHeaders as DohSetHeaders;
use hickory_net::tls::client_config;
use hickory_net::xfer::{DnsRequestSender, FirstAnswer};
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use http::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use tokio::sync::Mutex;
use url::Url;

use super::runtime::{OutboundRouting, RoutedRuntimeProvider};
use crate::frameworks::upstream::DnsUdpTcpClient;
use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};
use crate::use_cases::zone_authority::ZoneSourceAuth;

const DOH_DEFAULT_PORT: u16 = 443;
const DOH_DEFAULT_PATH: &str = "/dns-query";
const DOH_TIMEOUT: Duration = Duration::from_secs(10);

/// A cached `HttpsClientStream` (H2 over TLS) connection shared across queries.
///
/// `HttpsClientStream` does not implement `Debug`, so we use a no-op `Debug` wrapper.
#[derive(Clone, Default)]
struct ClientCache(Arc<Mutex<Option<HttpsClientStream>>>);

impl fmt::Debug for ClientCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCache").finish_non_exhaustive()
    }
}

/// Pre-built `Authorization` header injected into every DoH request.
///
/// The header value is constructed and validated at build time so that
/// `set_headers` is infallible during request dispatch.
#[derive(Debug)]
struct DohAuthHeaders {
    value: HeaderValue,
}

impl DohSetHeaders for DohAuthHeaders {
    fn set_headers(
        &self,
        headers: &mut HeaderMap<HeaderValue>,
    ) -> Result<(), hickory_net::NetError> {
        headers.insert(AUTHORIZATION, self.value.clone());
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum DohEndpoint {
    Static(SocketAddr),
    Hostname { host: String, port: u16 },
}

/// DNS-over-HTTPS upstream resolver (RFC 8484) backed by hickory-net HTTP/2 transport.
///
/// Parses an `https://host[:port][/path]` URL at construction time. On the first
/// query it resolves the hostname (via the OS resolver or bootstrap resolvers),
/// establishes an H2 over TLS connection, and caches the `HttpsClientStream` for
/// reuse — evicting it on error, mirroring the `DnsTlsClient` pattern.
/// Supports optional Bearer or Basic authentication via the HTTP `Authorization`
/// header injected through hickory-net's `SetHeaders` trait.
#[derive(Debug, Clone)]
pub struct DnsHttpsClient {
    endpoint: DohEndpoint,
    server_name: Arc<str>,
    path: Arc<str>,
    bootstrap_resolvers: Vec<SocketAddr>,
    auth_headers: Option<Arc<DohAuthHeaders>>,
    client_cache: ClientCache,
    routing: OutboundRouting,
}

impl DnsHttpsClient {
    /// Parse an `https://…` URL and return a ready-to-use client.
    ///
    /// Returns an error if the URL scheme is not `https`, the host is missing,
    /// or the auth value would produce an invalid HTTP header.
    pub fn new(url: String, auth: Option<ZoneSourceAuth>) -> Result<Self, UpstreamResolveError> {
        let (endpoint, server_name, path) = parse_doh_url(&url)?;
        let auth_headers = match auth {
            None => None,
            Some(zone_auth) => Some(Arc::new(build_auth_headers(&zone_auth)?)),
        };
        Ok(Self {
            endpoint,
            server_name: server_name.into(),
            path: path.into(),
            bootstrap_resolvers: vec![SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53)],
            auth_headers,
            client_cache: ClientCache::default(),
            routing: OutboundRouting::new(None, None),
        })
    }

    pub fn with_bootstrap_resolvers(mut self, resolvers: Vec<SocketAddr>) -> Self {
        if !resolvers.is_empty() {
            self.bootstrap_resolvers = resolvers;
        }
        self
    }

    pub fn with_routing(mut self, routing: OutboundRouting) -> Self {
        self.routing = routing;
        self
    }

    fn extract_question(
        query: &[u8],
    ) -> Result<(Name, DNSClass, RecordType), UpstreamResolveError> {
        let message = Message::from_vec(query)
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;
        let question = message
            .queries
            .first()
            .ok_or_else(|| UpstreamResolveError::Protocol("query contains no questions".into()))?;
        Ok((
            question.name().clone(),
            question.query_class(),
            question.query_type(),
        ))
    }

    async fn resolve_address(&self) -> Result<SocketAddr, UpstreamResolveError> {
        match &self.endpoint {
            DohEndpoint::Static(address) => Ok(*address),
            DohEndpoint::Hostname { host, port } => {
                match tokio::net::lookup_host((host.as_str(), *port)).await {
                    Ok(mut addrs) => addrs.next().ok_or_else(|| {
                        UpstreamResolveError::Protocol(format!(
                            "no resolved address for DoH hostname '{host}:{port}'"
                        ))
                    }),
                    Err(os_error) => self
                        .resolve_hostname_via_bootstrap(host, *port)
                        .await
                        .map_err(|bootstrap_error| {
                            UpstreamResolveError::Protocol(format!(
                                "failed to resolve DoH hostname '{host}:{port}' \
                                 using OS resolver ({os_error}) and bootstrap resolvers ({bootstrap_error})"
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
        let a_query = build_bootstrap_query(host, RecordType::A)?;
        let aaaa_query = build_bootstrap_query(host, RecordType::AAAA)?;

        for resolver_addr in &self.bootstrap_resolvers {
            let client = DnsUdpTcpClient::new(*resolver_addr);

            if let Ok(addr) = try_extract_ip_from_response(&client, &a_query, port).await {
                return Ok(addr);
            }
            if let Ok(addr) = try_extract_ip_from_response(&client, &aaaa_query, port).await {
                return Ok(addr);
            }
        }

        Err(UpstreamResolveError::Protocol(format!(
            "bootstrap resolvers did not return usable A/AAAA records for '{host}'"
        )))
    }

    async fn connect(&self) -> Result<HttpsClientStream, UpstreamResolveError> {
        let address = self.resolve_address().await?;
        let tls_config = Arc::new(
            client_config()
                .map_err(|e| UpstreamResolveError::Protocol(format!("TLS config error: {e}")))?,
        );
        let provider = RoutedRuntimeProvider::new(self.routing.clone());
        let mut builder = HttpsClientStream::builder(tls_config, provider);
        if let Some(auth) = &self.auth_headers {
            builder.set_headers(Arc::clone(auth) as Arc<dyn DohSetHeaders>);
        }
        builder
            .build(
                address,
                Arc::clone(&self.server_name),
                Arc::clone(&self.path),
            )
            .await
            .map_err(|e| UpstreamResolveError::Protocol(format!("DoH connect error: {e}")))
    }

    async fn resolve_doh(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamResolveError> {
        let (name, query_class, query_type) = Self::extract_question(query)?;

        // Try the cached connection first (clone to release the lock before I/O).
        let cached = self.client_cache.0.lock().await.clone();
        if let Some(mut stream) = cached {
            match send_query(&mut stream, name.clone(), query_class, query_type).await {
                Ok(response) => {
                    return response
                        .to_vec()
                        .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")));
                }
                Err(_) => {
                    // Stale connection — evict and fall through to reconnect.
                    *self.client_cache.0.lock().await = None;
                }
            }
        }

        // Establish a fresh H2 connection.
        let mut stream = self.connect().await?;

        let response = send_query(&mut stream, name, query_class, query_type).await?;

        // Cache the connection for subsequent queries.
        *self.client_cache.0.lock().await = Some(stream);

        response
            .to_vec()
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))
    }
}

#[async_trait]
impl UpstreamResolver for DnsHttpsClient {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
        self.resolve_doh(&query).await
    }
}

// ── Per-query send helper ─────────────────────────────────────────────────────

async fn send_query(
    stream: &mut HttpsClientStream,
    name: Name,
    query_class: DNSClass,
    query_type: RecordType,
) -> Result<hickory_proto::op::DnsResponse, UpstreamResolveError> {
    let mut msg = Message::new(rand::random::<u16>(), MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut q = Query::new();
    q.set_name(name);
    q.set_query_type(query_type);
    q.set_query_class(query_class);
    msg.add_query(q);

    let dns_request = DnsRequest::new(msg, DnsRequestOptions::default());

    tokio::time::timeout(DOH_TIMEOUT, stream.send_message(dns_request).first_answer())
        .await
        .map_err(|_| UpstreamResolveError::Timeout)?
        .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))
}

// ── URL parsing ──────────────────────────────────────────────────────────────

fn parse_doh_url(url_str: &str) -> Result<(DohEndpoint, String, String), UpstreamResolveError> {
    let url = Url::parse(url_str)
        .map_err(|e| UpstreamResolveError::Protocol(format!("invalid DoH URL '{url_str}': {e}")))?;

    if url.scheme() != "https" {
        return Err(UpstreamResolveError::Protocol(format!(
            "DoH URL must use https scheme, got '{}'",
            url.scheme()
        )));
    }

    let host = url
        .host_str()
        .ok_or_else(|| UpstreamResolveError::Protocol("DoH URL missing host".into()))?;

    let port = url.port().unwrap_or(DOH_DEFAULT_PORT);

    let path = {
        let p = url.path();
        if p.is_empty() || p == "/" {
            DOH_DEFAULT_PATH.to_string()
        } else {
            p.to_string()
        }
    };

    let endpoint = match host.parse::<IpAddr>() {
        Ok(ip) => DohEndpoint::Static(SocketAddr::new(ip, port)),
        Err(_) => DohEndpoint::Hostname {
            host: host.to_string(),
            port,
        },
    };

    Ok((endpoint, host.to_string(), path))
}

// ── Auth header builder ───────────────────────────────────────────────────────

fn build_auth_headers(auth: &ZoneSourceAuth) -> Result<DohAuthHeaders, UpstreamResolveError> {
    let value_str = match auth {
        ZoneSourceAuth::Bearer(token) => format!("Bearer {token}"),
        ZoneSourceAuth::Basic { username, password } => {
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
            format!("Basic {encoded}")
        }
    };

    let value = HeaderValue::from_str(&value_str)
        .map_err(|e| UpstreamResolveError::Protocol(format!("invalid auth header value: {e}")))?;

    Ok(DohAuthHeaders { value })
}

// ── Bootstrap helpers ─────────────────────────────────────────────────────────

fn build_bootstrap_query(
    host: &str,
    query_type: RecordType,
) -> Result<Vec<u8>, UpstreamResolveError> {
    let fqdn = if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{host}.")
    };
    let name = Name::from_ascii(&fqdn).map_err(|e| {
        UpstreamResolveError::Protocol(format!("invalid DoH hostname '{host}': {e}"))
    })?;

    let mut message = Message::new(1, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
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

    for answer in &message.answers {
        match &answer.data {
            RData::A(a) => return Ok(SocketAddr::new(IpAddr::V4(a.0), port)),
            RData::AAAA(aaaa) => return Ok(SocketAddr::new(IpAddr::V6(aaaa.0), port)),
            _ => {}
        }
    }

    Err(UpstreamResolveError::Protocol(
        "no A/AAAA records in bootstrap response".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_doh_url_ip_endpoint() {
        let (endpoint, server_name, path) = parse_doh_url("https://1.1.1.1/dns-query").unwrap();
        assert!(
            matches!(endpoint, DohEndpoint::Static(addr) if addr == "1.1.1.1:443".parse().unwrap())
        );
        assert_eq!(server_name, "1.1.1.1");
        assert_eq!(path, "/dns-query");
    }

    #[test]
    fn parse_doh_url_hostname_endpoint() {
        let (endpoint, server_name, path) =
            parse_doh_url("https://cloudflare-dns.com/dns-query").unwrap();
        assert!(
            matches!(endpoint, DohEndpoint::Hostname { ref host, port } if host == "cloudflare-dns.com" && port == 443)
        );
        assert_eq!(server_name, "cloudflare-dns.com");
        assert_eq!(path, "/dns-query");
    }

    #[test]
    fn parse_doh_url_custom_port() {
        let (endpoint, _, _) = parse_doh_url("https://1.1.1.1:8443/dns-query").unwrap();
        assert!(matches!(endpoint, DohEndpoint::Static(addr) if addr.port() == 8443));
    }

    #[test]
    fn parse_doh_url_defaults_path_when_missing() {
        let (_, _, path) = parse_doh_url("https://cloudflare-dns.com").unwrap();
        assert_eq!(path, "/dns-query");
    }

    #[test]
    fn parse_doh_url_rejects_http_scheme() {
        let err = parse_doh_url("http://1.1.1.1/dns-query").unwrap_err();
        assert!(matches!(err, UpstreamResolveError::Protocol(_)));
    }

    #[test]
    fn parse_doh_url_rejects_missing_host() {
        let err = parse_doh_url("https://:443/dns-query").unwrap_err();
        assert!(matches!(err, UpstreamResolveError::Protocol(_)));
    }

    #[test]
    fn doh_client_new_with_bearer_auth() {
        let client = DnsHttpsClient::new(
            "https://dns.example.com/dns-query".to_string(),
            Some(ZoneSourceAuth::Bearer("token123".to_string())),
        )
        .unwrap();
        assert!(client.auth_headers.is_some());
    }

    #[test]
    fn doh_client_new_without_auth() {
        let client =
            DnsHttpsClient::new("https://dns.example.com/dns-query".to_string(), None).unwrap();
        assert!(client.auth_headers.is_none());
    }

    #[test]
    fn doh_client_new_with_basic_auth() {
        let client = DnsHttpsClient::new(
            "https://dns.example.com/dns-query".to_string(),
            Some(ZoneSourceAuth::Basic {
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        )
        .unwrap();
        assert!(client.auth_headers.is_some());
    }

    #[test]
    fn doh_client_new_rejects_http_url() {
        let err =
            DnsHttpsClient::new("http://dns.example.com/dns-query".to_string(), None).unwrap_err();
        assert!(matches!(err, UpstreamResolveError::Protocol(_)));
    }

    #[test]
    fn doh_client_defaults_bootstrap_to_cloudflare() {
        let client =
            DnsHttpsClient::new("https://dns.example.com/dns-query".to_string(), None).unwrap();
        assert_eq!(
            client.bootstrap_resolvers,
            vec!["1.1.1.1:53".parse::<SocketAddr>().unwrap()]
        );
    }
}
