use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use hickory_proto::op::Message;

use super::bind_tcp_tokio;
use super::tls::{autogenerate_tls_cert_if_missing, build_tls_server_config};
use crate::frameworks::config::schema::TlsSocketConfig;
use crate::use_cases::request_pipeline::{
    build_servfail_response, DnsPipelineRequest, DnsRequestPipeline,
};

/// Errors that can occur when creating or running a [`DotServer`].
#[derive(Debug, Error)]
pub enum DotListenerError {
    #[error("invalid bind address '{addr}': {source}")]
    InvalidAddress {
        addr: String,
        source: std::net::AddrParseError,
    },
    #[error("failed to bind TCP on {addr}: {source}")]
    BindFailed { addr: SocketAddr, source: io::Error },
    #[error("TLS configuration error: {0}")]
    Tls(String),
    #[error("listener runtime error: {0}")]
    Runtime(io::Error),
}

/// Protocol adapter identification stub.
#[derive(Debug, Clone)]
pub struct DotAdapter;

impl DotAdapter {
    pub fn protocol_name(&self) -> &'static str {
        "dot"
    }
}

/// DNS-over-TLS server (RFC 7858).
///
/// Accepts DNS queries as RFC 7766 length-prefixed messages over TLS.
/// This is essentially DNS TCP with a mandatory TLS layer — no HTTP
/// framing is involved.
pub struct DotServer {
    bind_addrs: Vec<SocketAddr>,
    tls_acceptor: Arc<TlsAcceptor>,
    pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
}

/// A DoT server with all sockets already bound, ready to serve queries.
///
/// Created by [`DotServer::bind`]. The separation allows callers to drop
/// privileges between binding (which may require root for port 853) and
/// serving (which runs as an unprivileged user).
pub struct BoundDotServer {
    listeners: Vec<TcpListener>,
    tls_acceptor: Arc<TlsAcceptor>,
    pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
}

impl DotServer {
    /// Creates a new `DotServer` from a [`TlsSocketConfig`] and request pipeline slot.
    ///
    /// Validates bind addresses and loads the TLS certificate and key. Returns an
    /// error immediately if the TLS material is invalid or addresses are unparseable.
    pub fn new(
        config: &TlsSocketConfig,
        pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
    ) -> Result<Self, DotListenerError> {
        let mut bind_addrs = Vec::with_capacity(config.addresses.len());
        for addr in &config.addresses {
            let raw = if addr.contains(':') {
                format!("[{addr}]:{}", config.port)
            } else {
                format!("{addr}:{}", config.port)
            };
            let parsed =
                raw.parse::<SocketAddr>()
                    .map_err(|e| DotListenerError::InvalidAddress {
                        addr: raw,
                        source: e,
                    })?;
            bind_addrs.push(parsed);
        }

        let tls = &config.tls;
        let autogenerate = tls.autogenerate.unwrap_or(false);
        if autogenerate {
            autogenerate_tls_cert_if_missing(&tls.cert_path, &tls.key_path, &config.addresses)
                .map_err(|e| DotListenerError::Tls(e.to_string()))?;
        }
        let tls_config = build_tls_server_config(&tls.cert_path, &tls.key_path)
            .map_err(|e| DotListenerError::Tls(e.to_string()))?;
        let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(tls_config)));

        Ok(Self {
            bind_addrs,
            tls_acceptor,
            pipeline_slot,
        })
    }

    /// Binds TCP listeners on all configured addresses.
    ///
    /// Returns a [`BoundDotServer`] that can be used to start serving queries.
    /// This separation allows the caller to drop privileges between binding
    /// (which may require root) and serving.
    pub async fn bind(self) -> Result<BoundDotServer, DotListenerError> {
        let mut listeners = Vec::with_capacity(self.bind_addrs.len());

        for bind_addr in &self.bind_addrs {
            let tcp = bind_tcp_tokio(*bind_addr).map_err(|e| DotListenerError::BindFailed {
                addr: *bind_addr,
                source: e,
            })?;

            tracing::info!(addr = %bind_addr, "DoT listener bound (TLS)");
            listeners.push(tcp);
        }

        Ok(BoundDotServer {
            listeners,
            tls_acceptor: self.tls_acceptor,
            pipeline_slot: self.pipeline_slot,
        })
    }
}

impl BoundDotServer {
    /// Serves DoT queries on the previously bound sockets until a fatal error occurs.
    pub async fn serve(self) -> Result<(), DotListenerError> {
        let mut tasks = Vec::new();

        for listener in self.listeners {
            let acceptor = Arc::clone(&self.tls_acceptor);
            let pipeline = Arc::clone(&self.pipeline_slot);
            tasks.push(tokio::spawn(run_dot(listener, acceptor, pipeline)));
        }

        // Wait for the first task to exit (which signals a fatal error).
        let (result, _idx, _remaining) = futures::future::select_all(tasks).await;
        flatten_join(result)
    }
}

fn flatten_join(
    result: Result<Result<(), DotListenerError>, tokio::task::JoinError>,
) -> Result<(), DotListenerError> {
    match result {
        Ok(inner) => inner,
        Err(e) => Err(DotListenerError::Runtime(io::Error::other(e.to_string()))),
    }
}

/// Drives the TLS accept loop, spawning a task per incoming connection.
async fn run_dot(
    listener: TcpListener,
    acceptor: Arc<TlsAcceptor>,
    pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
) -> Result<(), DotListenerError> {
    loop {
        let (stream, peer) = listener.accept().await.map_err(DotListenerError::Runtime)?;
        let acceptor = Arc::clone(&acceptor);
        let pipeline_slot = Arc::clone(&pipeline_slot);

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(peer = %peer, error = %e, "DoT TLS handshake failed");
                    return;
                }
            };

            if let Err(e) = handle_dot_conn(tls_stream, &pipeline_slot).await {
                tracing::debug!(peer = %peer, error = %e, "DoT connection error");
            }
        });
    }
}

/// Handles a single DoT connection: reads RFC 7766 length-prefixed DNS messages
/// over TLS and writes corresponding responses until the client closes the connection.
async fn handle_dot_conn(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    pipeline_slot: &Arc<Mutex<Arc<DnsRequestPipeline>>>,
) -> io::Result<()> {
    loop {
        // Read 2-byte length prefix (RFC 7766).
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            continue;
        }

        let mut query = vec![0u8; msg_len];
        stream.read_exact(&mut query).await?;

        let response = forward_query(pipeline_slot, &query).await;
        let write_len = response.len().min(u16::MAX as usize);
        stream.write_all(&(write_len as u16).to_be_bytes()).await?;
        stream.write_all(&response[..write_len]).await?;
    }
}

/// Forwards a raw DNS query wire buffer through the request pipeline.
/// Returns a SERVFAIL response if pipeline resolution fails.
async fn forward_query(
    pipeline_slot: &Arc<Mutex<Arc<DnsRequestPipeline>>>,
    query: &[u8],
) -> Vec<u8> {
    let pipeline = Arc::clone(&*pipeline_slot.lock().await);

    let (domain, qtype) = Message::from_vec(query)
        .ok()
        .and_then(|msg| {
            msg.queries
                .first()
                .map(|q| (q.name().to_ascii(), q.query_type().to_string()))
        })
        .unwrap_or_else(|| ("<unparseable>".to_string(), "<unknown>".to_string()));

    tracing::debug!(domain = %domain, qtype = %qtype, "DoT query received");

    let request = DnsPipelineRequest::new(query.to_vec());
    match pipeline.handle_request(&request).await {
        Ok(Some(response)) => response.into_bytes(),
        Ok(None) => {
            tracing::warn!(domain = %domain, qtype = %qtype, "DoT pipeline returned no response; returning SERVFAIL");
            build_servfail_response(query)
        }
        Err(error) => {
            tracing::warn!(domain = %domain, qtype = %qtype, error = %error, "DoT pipeline failed; returning SERVFAIL");
            build_servfail_response(query)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use async_trait::async_trait;
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, RecordType};
    use tokio::sync::Mutex;

    use crate::entities::filter::FilterDecision;
    use crate::use_cases::config_bootstrap::build_dns_request_pipeline;
    use crate::use_cases::filtering::DomainFilter;
    use crate::use_cases::request_pipeline::{AnyQueryPolicy, DnsRequestPipeline};
    use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};

    use super::*;

    // ── Mock resolvers ───────────────────────────────────────────────────────

    struct FixedResponseResolver(Vec<u8>);

    #[async_trait]
    impl UpstreamResolver for FixedResponseResolver {
        async fn resolve(&self, _query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
            Ok(self.0.clone())
        }
    }

    struct AlwaysFailResolver;

    #[async_trait]
    impl UpstreamResolver for AlwaysFailResolver {
        async fn resolve(&self, _query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
            Err(UpstreamResolveError::AllFailed)
        }
    }

    struct TestDomainFilter {
        decision: FilterDecision,
    }

    impl DomainFilter for TestDomainFilter {
        fn decide(&self, _domain: &str) -> FilterDecision {
            self.decision
        }

        fn sinkhole_ipv4(&self) -> Ipv4Addr {
            Ipv4Addr::new(0, 0, 0, 0)
        }

        fn sinkhole_ipv6(&self) -> Ipv6Addr {
            Ipv6Addr::UNSPECIFIED
        }

        fn start_background_refresh(self: Arc<Self>) {}

        fn list_names(&self) -> Vec<crate::use_cases::filtering::ListInfo> {
            Vec::new()
        }

        fn disable_list(&self, _name: &str) -> bool {
            false
        }

        fn enable_list(&self, _name: &str) -> bool {
            false
        }

        fn refresh_list(&self, _name: &str) -> bool {
            false
        }

        fn refresh_all_lists(&self) -> Vec<String> {
            Vec::new()
        }
    }

    fn make_query(domain: &str) -> Vec<u8> {
        let mut msg = Message::new(42, MessageType::Query, hickory_proto::op::OpCode::Query);
        msg.metadata.recursion_desired = true;
        let mut q = Query::new();
        q.set_name(domain.parse().unwrap());
        q.set_query_type(RecordType::A);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
        msg.to_vec().unwrap()
    }

    fn make_noerror_response(id: u16) -> Vec<u8> {
        let mut msg = Message::new(id, MessageType::Response, hickory_proto::op::OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.to_vec().unwrap()
    }

    fn neutral_filter() -> Arc<dyn DomainFilter> {
        Arc::new(TestDomainFilter {
            decision: FilterDecision::Neutral,
        })
    }

    fn pipeline_slot(
        resolver: Arc<dyn UpstreamResolver>,
        filter: Arc<dyn DomainFilter>,
    ) -> Arc<Mutex<Arc<DnsRequestPipeline>>> {
        Arc::new(Mutex::new(Arc::new(build_dns_request_pipeline(
            resolver,
            filter,
            AnyQueryPolicy::Passthrough,
        ))))
    }

    // ── Adapter tests ────────────────────────────────────────────────────────

    #[test]
    fn dot_adapter_protocol_name() {
        assert_eq!(DotAdapter.protocol_name(), "dot");
    }

    // ── forward_query tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn forward_query_returns_upstream_response() {
        let expected = make_noerror_response(42);
        let slot = pipeline_slot(
            Arc::new(FixedResponseResolver(expected.clone())),
            neutral_filter(),
        );
        let result = forward_query(&slot, &make_query("example.com.")).await;
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn forward_query_returns_servfail_on_upstream_error() {
        let slot = pipeline_slot(Arc::new(AlwaysFailResolver), neutral_filter());
        let result = forward_query(&slot, &make_query("example.com.")).await;
        let msg = Message::from_vec(&result).expect("valid DNS message");
        assert_eq!(msg.response_code, ResponseCode::ServFail);
        assert_eq!(msg.id, 42);
    }

    // NOTE: handle_dot_conn requires a TlsStream<TcpStream> which cannot be
    // easily mocked without a real TLS handshake. The RFC 7766 length-prefix
    // framing logic is identical to dns.rs handle_tcp_conn which has full
    // integration tests. The forward_query tests above validate the pipeline
    // integration path.

    // ── Address validation ───────────────────────────────────────────────────

    #[test]
    fn new_rejects_invalid_address() {
        use crate::frameworks::config::schema::{TlsConfig, TlsSocketConfig};

        let config = TlsSocketConfig {
            enabled: true,
            addresses: vec!["not_an_ip".to_string()],
            port: 853,
            tls: TlsConfig {
                cert_path: "/tmp/cert.pem".to_string(),
                key_path: "/tmp/key.pem".to_string(),
                autogenerate: Some(false),
            },
            auth_token: None,
        };

        let slot: Arc<Mutex<Arc<DnsRequestPipeline>>> =
            pipeline_slot(Arc::new(FixedResponseResolver(vec![])), neutral_filter());

        let result = DotServer::new(&config, slot);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error for invalid address"),
        };
        assert!(err.to_string().contains("invalid bind address"));
    }

    #[test]
    fn new_rejects_missing_tls_cert() {
        use crate::frameworks::config::schema::{TlsConfig, TlsSocketConfig};

        let config = TlsSocketConfig {
            enabled: true,
            addresses: vec!["127.0.0.1".to_string()],
            port: 853,
            tls: TlsConfig {
                cert_path: "/nonexistent/cert.pem".to_string(),
                key_path: "/nonexistent/key.pem".to_string(),
                autogenerate: Some(false),
            },
            auth_token: None,
        };

        let slot: Arc<Mutex<Arc<DnsRequestPipeline>>> =
            pipeline_slot(Arc::new(FixedResponseResolver(vec![])), neutral_filter());

        let result = DotServer::new(&config, slot);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error for missing TLS cert"),
        };
        assert!(err.to_string().contains("TLS"));
    }
}
