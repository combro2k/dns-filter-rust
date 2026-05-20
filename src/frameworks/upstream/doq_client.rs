use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_net::quic::QuicClientStreamBuilder;
use hickory_net::tls::client_config;
use hickory_net::xfer::{DnsRequestSender, FirstAnswer};
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use quinn::Runtime;
use tokio::sync::Mutex;

use super::runtime::OutboundRouting;
use crate::frameworks::upstream::DnsUdpTcpClient;
use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};

const DOQ_DEFAULT_PORT: u16 = 8853;
const DOQ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Default)]
struct ClientCache(Arc<Mutex<Option<hickory_net::quic::QuicClientStream>>>);

impl fmt::Debug for ClientCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCache").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
enum DoqEndpoint {
    Static(SocketAddr),
    Hostname { host: String, port: u16 },
}

/// DNS-over-QUIC upstream resolver (RFC 9250).
#[derive(Debug, Clone)]
pub struct DnsQuicClient {
    endpoint: DoqEndpoint,
    server_name: Arc<str>,
    bootstrap_resolvers: Vec<SocketAddr>,
    client_cache: ClientCache,
    routing: OutboundRouting,
}

impl DnsQuicClient {
    pub fn new(address: SocketAddr, server_name: String) -> Self {
        Self {
            endpoint: DoqEndpoint::Static(address),
            server_name: server_name.into(),
            bootstrap_resolvers: vec![SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53)],
            client_cache: ClientCache::default(),
            routing: OutboundRouting::new(None, None),
        }
    }

    pub fn new_hostname(host: String, port: u16) -> Self {
        Self {
            endpoint: DoqEndpoint::Hostname {
                host: host.clone(),
                port,
            },
            server_name: host_without_trailing_dot(&host).into(),
            bootstrap_resolvers: vec![SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53)],
            client_cache: ClientCache::default(),
            routing: OutboundRouting::new(None, None),
        }
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

    pub fn parse_endpoint(value: &str) -> Result<Self, UpstreamResolveError> {
        let endpoint = value.strip_prefix("quic://").unwrap_or(value);

        if endpoint.trim().is_empty() {
            return Err(UpstreamResolveError::Protocol(
                "invalid DoQ upstream address; endpoint is empty".to_string(),
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
                SocketAddr::new(ip, DOQ_DEFAULT_PORT),
                ip.to_string(),
            ));
        }

        if let Some((host, port)) = parse_hostname_with_optional_port(endpoint)? {
            return Ok(Self::new_hostname(host, port));
        }

        Err(UpstreamResolveError::Protocol(
            "invalid DoQ upstream address; expected quic://<host>[:port], <host>:<port>, <host>, quic://<ip>[:port], <ip>:<port>, or <ip>".to_string(),
        ))
    }

    async fn resolve_address(&self) -> Result<SocketAddr, UpstreamResolveError> {
        match &self.endpoint {
            DoqEndpoint::Static(address) => Ok(*address),
            DoqEndpoint::Hostname { host, port } => {
                match tokio::net::lookup_host((host.as_str(), *port)).await {
                    Ok(mut addrs) => addrs.next().ok_or_else(|| {
                        UpstreamResolveError::Protocol(format!(
                            "no resolved address for DoQ hostname '{host}:{port}'"
                        ))
                    }),
                    Err(os_error) => self
                        .resolve_hostname_via_bootstrap(host, *port)
                        .await
                        .map_err(|bootstrap_error| {
                            UpstreamResolveError::Protocol(format!(
                                "failed to resolve DoQ hostname '{host}:{port}' using OS resolver ({os_error}) and bootstrap resolvers ({bootstrap_error})"
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

        for resolver in &self.bootstrap_resolvers {
            let client = DnsUdpTcpClient::new(*resolver).with_routing(self.routing.clone());

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

    async fn connect(&self) -> Result<hickory_net::quic::QuicClientStream, UpstreamResolveError> {
        let address = self.resolve_address().await?;
        let tls_config = client_config()
            .map_err(|e| UpstreamResolveError::Protocol(format!("TLS config error: {e}")))?;

        let builder = QuicClientStreamBuilder::default().crypto_config(tls_config);

        if self.routing.fwmark.is_some() {
            let socket = build_quic_socket(address, &self.routing)?;
            return builder
                .build_with_future(socket, address, Arc::clone(&self.server_name))
                .await
                .map_err(|e| UpstreamResolveError::Protocol(format!("DoQ connect error: {e}")));
        }

        let builder = if let Some(bind_ip) = self.routing.bind_address {
            builder.bind_addr(SocketAddr::new(bind_ip, 0))
        } else {
            builder
        };

        builder
            .build(address, Arc::clone(&self.server_name))
            .await
            .map_err(|e| UpstreamResolveError::Protocol(format!("DoQ connect error: {e}")))
    }

    async fn resolve_doq(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamResolveError> {
        let _ = build_doq_request(query)?;

        let cached = self.client_cache.0.lock().await.clone();
        if let Some(mut stream) = cached {
            match send_query(&mut stream, query).await {
                Ok(response) => {
                    return response
                        .to_vec()
                        .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")));
                }
                Err(_) => {
                    *self.client_cache.0.lock().await = None;
                }
            }
        }

        let mut stream = self.connect().await?;
        let response = send_query(&mut stream, query).await?;
        *self.client_cache.0.lock().await = Some(stream);

        response
            .to_vec()
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))
    }
}

#[async_trait]
impl UpstreamResolver for DnsQuicClient {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
        self.resolve_doq(&query).await
    }
}

async fn send_query(
    stream: &mut hickory_net::quic::QuicClientStream,
    query: &[u8],
) -> Result<hickory_proto::op::DnsResponse, UpstreamResolveError> {
    let dns_request = build_doq_request(query)?;

    tokio::time::timeout(DOQ_TIMEOUT, stream.send_message(dns_request).first_answer())
        .await
        .map_err(|_| UpstreamResolveError::Timeout)?
        .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))
}

fn build_doq_request(query: &[u8]) -> Result<DnsRequest, UpstreamResolveError> {
    let mut message =
        Message::from_vec(query).map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

    if message.queries.is_empty() {
        return Err(UpstreamResolveError::Protocol(
            "query contains no questions".into(),
        ));
    }

    message.metadata.id = 0;
    Ok(DnsRequest::new(message, DnsRequestOptions::default()))
}

fn build_quic_socket(
    server_addr: SocketAddr,
    routing: &OutboundRouting,
) -> Result<Arc<dyn quinn::AsyncUdpSocket>, UpstreamResolveError> {
    use socket2::{Domain, Protocol, Socket, Type};

    let local_addr = match routing.bind_address {
        Some(ip) => {
            if ip.is_ipv4() != server_addr.is_ipv4() {
                return Err(UpstreamResolveError::Protocol(format!(
                    "DoQ bind_address '{ip}' does not match upstream address family '{server_addr}'"
                )));
            }
            SocketAddr::new(ip, 0)
        }
        None => match server_addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::from([0u16; 8]), 0),
        },
    };

    let domain = match local_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    #[cfg(target_os = "linux")]
    if let Some(mark) = routing.fwmark {
        socket.set_mark(mark)?;
    }

    socket.set_nonblocking(true)?;
    socket.bind(&local_addr.into())?;

    quinn::TokioRuntime
        .wrap_udp_socket(socket.into())
        .map_err(UpstreamResolveError::Io)
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

fn build_bootstrap_query(
    host: &str,
    query_type: RecordType,
) -> Result<Vec<u8>, UpstreamResolveError> {
    let fqdn = fqdn_host(host);
    let name = Name::from_ascii(&fqdn).map_err(|e| {
        UpstreamResolveError::Protocol(format!("invalid DoQ hostname '{host}': {e}"))
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

fn parse_hostname_with_optional_port(
    value: &str,
) -> Result<Option<(String, u16)>, UpstreamResolveError> {
    if let Some((host, port_str)) = value.rsplit_once(':') {
        if !host.contains(':') {
            let host = host_without_trailing_dot(host);
            validate_hostname(&host)?;
            let port = port_str.parse::<u16>().map_err(|e| {
                UpstreamResolveError::Protocol(format!("invalid DoQ port '{port_str}': {e}"))
            })?;
            return Ok(Some((host, port)));
        }
    }

    let host = host_without_trailing_dot(value);
    validate_hostname(&host)?;
    Ok(Some((host, DOQ_DEFAULT_PORT)))
}

fn validate_hostname(host: &str) -> Result<(), UpstreamResolveError> {
    if host.is_empty() || host.len() > 253 {
        return Err(UpstreamResolveError::Protocol(
            "invalid DoQ hostname length".to_string(),
        ));
    }

    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(UpstreamResolveError::Protocol(
                "invalid DoQ hostname label length".to_string(),
            ));
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(UpstreamResolveError::Protocol(
                "invalid DoQ hostname label; leading/trailing hyphen is not allowed".to_string(),
            ));
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(UpstreamResolveError::Protocol(
                "invalid DoQ hostname label characters".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_doq_endpoint_allows_quic_scheme_and_default_port() {
        let client = DnsQuicClient::parse_endpoint("quic://1.1.1.1").unwrap();

        match client.endpoint {
            DoqEndpoint::Static(address) => assert_eq!(address, "1.1.1.1:8853".parse().unwrap()),
            DoqEndpoint::Hostname { .. } => panic!("expected static endpoint"),
        }
        assert_eq!(&*client.server_name, "1.1.1.1");
    }

    #[test]
    fn parse_doq_endpoint_allows_hostname_and_preserves_server_name() {
        let client = DnsQuicClient::parse_endpoint("quic://dns.example.com:8853").unwrap();

        match client.endpoint {
            DoqEndpoint::Hostname { host, port } => {
                assert_eq!(host, "dns.example.com");
                assert_eq!(port, 8853);
            }
            DoqEndpoint::Static(_) => panic!("expected hostname endpoint"),
        }
        assert_eq!(&*client.server_name, "dns.example.com");
    }

    #[test]
    fn parse_doq_endpoint_defaults_hostname_port() {
        let client = DnsQuicClient::parse_endpoint("dns.example.com").unwrap();

        match client.endpoint {
            DoqEndpoint::Hostname { host, port } => {
                assert_eq!(host, "dns.example.com");
                assert_eq!(port, 8853);
            }
            DoqEndpoint::Static(_) => panic!("expected hostname endpoint"),
        }
    }

    #[test]
    fn parse_doq_endpoint_rejects_invalid_host() {
        let error = DnsQuicClient::parse_endpoint("quic://dns_example.com").unwrap_err();
        assert!(matches!(error, UpstreamResolveError::Protocol(_)));
    }

    #[test]
    fn doq_client_defaults_bootstrap_resolver_to_cloudflare() {
        let client = DnsQuicClient::parse_endpoint("quic://dns.example.com").unwrap();
        assert_eq!(
            client.bootstrap_resolvers,
            vec!["1.1.1.1:53".parse().unwrap()]
        );
    }

    #[test]
    fn build_doq_request_sets_message_id_to_zero() {
        let mut message = Message::new(42, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));

        let request = build_doq_request(&message.to_vec().unwrap()).unwrap();
        assert_eq!(request.id, 0);
    }

    #[test]
    fn build_doq_request_rejects_empty_query() {
        let error = match build_doq_request(&[0u8; 12]) {
            Ok(_) => panic!("expected build_doq_request to fail"),
            Err(error) => error,
        };
        assert!(matches!(error, UpstreamResolveError::Protocol(_)));
    }
}
