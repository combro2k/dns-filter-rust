use std::net::SocketAddr;
use std::sync::Arc;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

use hickory_client::proto::op::Message;

use crate::frameworks::config::schema::SocketConfig;
use crate::use_cases::request_pipeline::{
    build_servfail_response, DnsPipelineRequest, DnsRequestPipeline,
};

/// Maximum size of a single UDP DNS datagram accepted by the listener.
/// 4096 bytes covers EDNS0 responses without excessive allocation.
const UDP_RECV_BUF: usize = 4096;

/// Errors that can occur when creating or running a [`DnsServer`].
#[derive(Debug, Error)]
pub enum DnsListenerError {
    #[error("invalid bind address '{addr}': {source}")]
    InvalidAddress {
        addr: String,
        source: std::net::AddrParseError,
    },
    #[error("failed to bind {proto} on {addr}: {source}")]
    BindFailed {
        proto: &'static str,
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("listener runtime error: {0}")]
    Runtime(std::io::Error),
}

/// Protocol adapter identification stub.
#[derive(Debug, Clone)]
pub struct DnsAdapter;

impl DnsAdapter {
    pub fn protocol_name(&self) -> &'static str {
        "dns"
    }
}

/// DNS server that accepts queries over UDP and TCP (RFC 7766).
///
/// UDP uses standard datagram exchange.
/// TCP uses the 2-byte length-prefix framing defined in RFC 7766.
pub struct DnsServer {
    bind_addrs: Vec<SocketAddr>,
    pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
}

/// A DNS server with all sockets already bound, ready to serve queries.
///
/// Created by [`DnsServer::bind`]. The separation allows callers to drop
/// privileges between binding (which may require root for privileged ports)
/// and serving (which runs as an unprivileged user).
pub struct BoundDnsServer {
    sockets: Vec<(UdpSocket, TcpListener)>,
    pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
}

impl DnsServer {
    /// Creates a new `DnsServer` from a `SocketConfig` and request pipeline slot.
    ///
    /// The pipeline is wrapped in a Mutex to allow atomic state swapping on reload.
    /// Validates the bind addresses but does not open sockets until [`run`](DnsServer::run) is called.
    pub fn new(
        config: &SocketConfig,
        pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
    ) -> Result<Self, DnsListenerError> {
        let mut bind_addrs = Vec::with_capacity(config.addresses.len());
        for addr in &config.addresses {
            let raw = if addr.contains(':') {
                format!("[{addr}]:{}", config.port)
            } else {
                format!("{addr}:{}", config.port)
            };
            let parsed =
                raw.parse::<SocketAddr>()
                    .map_err(|e| DnsListenerError::InvalidAddress {
                        addr: raw,
                        source: e,
                    })?;
            bind_addrs.push(parsed);
        }
        Ok(Self {
            bind_addrs,
            pipeline_slot,
        })
    }

    /// Binds UDP and TCP sockets on all configured addresses.
    ///
    /// Returns a [`BoundDnsServer`] that can be used to start serving queries.
    /// This separation allows the caller to drop privileges between binding
    /// (which may require root) and serving.
    pub async fn bind(self) -> Result<BoundDnsServer, DnsListenerError> {
        let mut sockets = Vec::with_capacity(self.bind_addrs.len());

        for bind_addr in &self.bind_addrs {
            let udp =
                UdpSocket::bind(bind_addr)
                    .await
                    .map_err(|e| DnsListenerError::BindFailed {
                        proto: "UDP",
                        addr: *bind_addr,
                        source: e,
                    })?;
            let tcp =
                TcpListener::bind(bind_addr)
                    .await
                    .map_err(|e| DnsListenerError::BindFailed {
                        proto: "TCP",
                        addr: *bind_addr,
                        source: e,
                    })?;

            tracing::info!(addr = %bind_addr, "DNS listener bound (UDP + TCP)");
            sockets.push((udp, tcp));
        }

        Ok(BoundDnsServer {
            sockets,
            pipeline_slot: self.pipeline_slot,
        })
    }
}

impl BoundDnsServer {
    /// Serves DNS queries on the previously bound sockets until a fatal error occurs.
    pub async fn serve(self) -> Result<(), DnsListenerError> {
        let mut tasks = Vec::new();

        for (udp, tcp) in self.sockets {
            let pipeline_udp = Arc::clone(&self.pipeline_slot);
            let pipeline_tcp = Arc::clone(&self.pipeline_slot);
            tasks.push(tokio::spawn(run_udp(udp, pipeline_udp)));
            tasks.push(tokio::spawn(run_tcp(tcp, pipeline_tcp)));
        }

        // Wait for the first task to exit (which signals a fatal error).
        let (result, _idx, _remaining) = futures::future::select_all(tasks).await;
        flatten_join(result)
    }
}

fn flatten_join(
    result: Result<Result<(), DnsListenerError>, tokio::task::JoinError>,
) -> Result<(), DnsListenerError> {
    match result {
        Ok(inner) => inner,
        Err(e) => Err(DnsListenerError::Runtime(std::io::Error::other(
            e.to_string(),
        ))),
    }
}

/// Drives the UDP receive loop, spawning a task per incoming datagram.
async fn run_udp(
    socket: UdpSocket,
    pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
) -> Result<(), DnsListenerError> {
    let socket = Arc::new(socket);
    let mut buf = [0u8; UDP_RECV_BUF];
    tracing::debug!("UDP receive loop started");

    loop {
        let (len, src) = socket
            .recv_from(&mut buf)
            .await
            .map_err(DnsListenerError::Runtime)?;

        tracing::debug!(peer = %src, query_len = len, "DNS UDP query received");
        let query = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        let pipeline_slot = Arc::clone(&pipeline_slot);

        tokio::spawn(async move {
            tracing::debug!(peer = %src, "forwarding query to upstream");
            let response = forward_query(&pipeline_slot, &query).await;
            tracing::debug!(peer = %src, response_len = response.len(), "sending DNS response");
            if let Err(e) = socket.send_to(&response, src).await {
                tracing::warn!(peer = %src, error = %e, "failed to send UDP DNS response");
            }
        });
    }
}

/// Drives the TCP accept loop, spawning a task per incoming connection.
async fn run_tcp(
    listener: TcpListener,
    pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
) -> Result<(), DnsListenerError> {
    loop {
        let (stream, src) = listener.accept().await.map_err(DnsListenerError::Runtime)?;
        let pipeline_slot = Arc::clone(&pipeline_slot);

        tokio::spawn(async move {
            if let Err(e) = handle_tcp_conn(stream, &pipeline_slot).await {
                tracing::warn!(peer = %src, error = %e, "DNS TCP connection error");
            }
        });
    }
}

/// Handles a single TCP connection: reads RFC 7766 length-prefixed DNS messages and
/// writes corresponding responses until the client closes the connection.
async fn handle_tcp_conn(
    mut stream: TcpStream,
    pipeline_slot: &Arc<Mutex<Arc<DnsRequestPipeline>>>,
) -> std::io::Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
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

/// Forwards a raw DNS query wire buffer to the upstream resolver.
/// Returns a SERVFAIL response if resolution fails.
/// Preserves the original query ID from the client in the response.
async fn forward_query(
    pipeline_slot: &Arc<Mutex<Arc<DnsRequestPipeline>>>,
    query: &[u8],
) -> Vec<u8> {
    tracing::debug!(query_len = query.len(), "calling request pipeline");
    let pipeline = Arc::clone(&*pipeline_slot.lock().await);

    let (domain, qtype) = Message::from_vec(query)
        .ok()
        .and_then(|msg| {
            msg.queries()
                .first()
                .map(|q| (q.name().to_ascii(), q.query_type().to_string()))
        })
        .unwrap_or_else(|| ("<unparseable>".to_string(), "<unknown>".to_string()));

    let request = DnsPipelineRequest::new(query.to_vec());
    match pipeline.handle_request(&request).await {
        Ok(Some(response)) => response.into_bytes(),
        Ok(None) => {
            tracing::warn!(domain = %domain, qtype = %qtype, "pipeline returned no response; returning SERVFAIL");
            build_servfail_response(query)
        }
        Err(error) => {
            tracing::warn!(domain = %domain, qtype = %qtype, error = %error, "pipeline failed; returning SERVFAIL");
            build_servfail_response(query)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use async_trait::async_trait;
    use hickory_client::proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_client::proto::rr::{DNSClass, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    use crate::entities::filter::FilterDecision;
    use crate::frameworks::config::schema::SocketConfig;
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
        let mut msg = Message::new();
        msg.set_id(42);
        msg.set_recursion_desired(true);
        let mut q = Query::new();
        q.set_name(domain.parse().unwrap());
        q.set_query_type(RecordType::A);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
        msg.to_vec().unwrap()
    }

    fn make_noerror_response(id: u16) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(id);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        msg.to_vec().unwrap()
    }

    fn neutral_filter() -> Arc<dyn DomainFilter> {
        Arc::new(TestDomainFilter {
            decision: FilterDecision::Neutral,
        })
    }

    fn blocking_filter() -> Arc<dyn DomainFilter> {
        Arc::new(TestDomainFilter {
            decision: FilterDecision::Block,
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

    // ── build_servfail ───────────────────────────────────────────────────────

    #[test]
    fn build_servfail_copies_query_id_and_question() {
        let query = make_query("example.com.");
        let servfail = build_servfail_response(&query);

        let response = Message::from_vec(&servfail).expect("valid DNS message");
        assert_eq!(response.id(), 42);
        assert_eq!(response.response_code(), ResponseCode::ServFail);
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.queries().len(), 1);
        assert_eq!(response.queries()[0].name().to_ascii(), "example.com.");
    }

    #[test]
    fn build_servfail_on_empty_input_returns_id_zero() {
        let servfail = build_servfail_response(&[]);

        let response = Message::from_vec(&servfail).expect("valid DNS message");
        assert_eq!(response.id(), 0);
        assert_eq!(response.response_code(), ResponseCode::ServFail);
        assert_eq!(response.message_type(), MessageType::Response);
    }

    // ── DnsServer::new ───────────────────────────────────────────────────────

    #[test]
    fn dns_server_new_accepts_valid_address() {
        let cfg = SocketConfig {
            enabled: true,
            addresses: vec!["127.0.0.1".into()],
            port: 5353,
        };
        let pipeline = pipeline_slot(Arc::new(AlwaysFailResolver), neutral_filter());
        assert!(DnsServer::new(&cfg, pipeline).is_ok());
    }

    #[test]
    fn dns_server_new_accepts_dual_stack_addresses() {
        let cfg = SocketConfig {
            enabled: true,
            addresses: vec!["0.0.0.0".into(), "::".into()],
            port: 5353,
        };
        let pipeline = pipeline_slot(Arc::new(AlwaysFailResolver), neutral_filter());
        let server = DnsServer::new(&cfg, pipeline).unwrap();
        assert_eq!(server.bind_addrs.len(), 2);
    }

    #[test]
    fn dns_server_new_rejects_invalid_address() {
        let cfg = SocketConfig {
            enabled: true,
            addresses: vec!["not-an-ip".into()],
            port: 5353,
        };
        let pipeline = pipeline_slot(Arc::new(AlwaysFailResolver), neutral_filter());
        let err = match DnsServer::new(&cfg, pipeline) {
            Err(e) => e,
            Ok(_) => panic!("expected an error for invalid address"),
        };
        assert!(err.to_string().contains("invalid bind address"));
    }

    // ── forward_query ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn forward_query_returns_upstream_response() {
        let expected = make_noerror_response(42);
        let pipeline = pipeline_slot(
            Arc::new(FixedResponseResolver(expected.clone())),
            neutral_filter(),
        );
        let result = forward_query(&pipeline, &make_query("example.com.")).await;
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn forward_query_returns_servfail_on_upstream_error() {
        let pipeline = pipeline_slot(Arc::new(AlwaysFailResolver), neutral_filter());
        let result = forward_query(&pipeline, &make_query("example.com.")).await;
        let msg = Message::from_vec(&result).expect("valid DNS message");
        assert_eq!(msg.response_code(), ResponseCode::ServFail);
        assert_eq!(msg.id(), 42);
    }

    #[tokio::test]
    async fn forward_query_returns_sinkhole_response_when_blocked() {
        let pipeline = pipeline_slot(Arc::new(AlwaysFailResolver), blocking_filter());
        let result = forward_query(&pipeline, &make_query("example.com.")).await;
        let msg = Message::from_vec(&result).expect("valid DNS message");
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.id(), 42);
        assert_eq!(msg.answers().len(), 1);
        assert_eq!(msg.answers()[0].record_type(), RecordType::A);
    }

    // ── TCP framing ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn handle_tcp_conn_processes_length_prefixed_query_and_responds() {
        let query = make_query("example.com.");
        let expected_response = make_noerror_response(42);
        let pipeline = pipeline_slot(
            Arc::new(FixedResponseResolver(expected_response.clone())),
            neutral_filter(),
        );

        // Bind to an ephemeral port for an in-process TCP round-trip.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_pipeline = Arc::clone(&pipeline);
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_tcp_conn(stream, &server_pipeline).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&query).await.unwrap();
        // Shut down the write side so the server sees EOF and exits cleanly.
        client.shutdown().await.unwrap();

        let mut resp_len_buf = [0u8; 2];
        client.read_exact(&mut resp_len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();

        server_task.await.unwrap();
        assert_eq!(resp_buf, expected_response);
    }
}
