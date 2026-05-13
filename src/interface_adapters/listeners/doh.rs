use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use super::tls::{autogenerate_tls_cert_if_missing, build_tls_server_config};

use hickory_proto::op::Message;

use super::bind_tcp_tokio;
use crate::frameworks::config::schema::TlsSocketConfig;
use crate::use_cases::request_pipeline::{
    build_servfail_response, DnsPipelineRequest, DnsRequestPipeline,
};

/// Maximum accepted DNS wire payload size for inbound DoH requests (bytes).
/// Aligned with the UDP receive buffer used by the DNS listener and conservative
/// per RFC 8484 to limit resource consumption from untrusted clients.
const MAX_DNS_PAYLOAD: usize = 4096;

/// The only URI path accepted by this DoH listener.
const DOH_PATH: &str = "/dns-query";

/// Expected and returned content type for DNS wire-format messages (RFC 8484 §6).
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// Errors that can occur when creating or running a [`DohServer`].
#[derive(Debug, Error)]
pub enum DohListenerError {
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
pub struct DohAdapter;

impl DohAdapter {
    pub fn protocol_name(&self) -> &'static str {
        "doh"
    }
}

/// DNS-over-HTTPS server (RFC 8484).
///
/// Accepts DNS queries as `application/dns-message` payloads over HTTPS
/// on the `/dns-query` endpoint. Supports both POST (body) and GET
/// (`?dns=<base64url>`) methods.
pub struct DohServer {
    bind_addrs: Vec<SocketAddr>,
    tls_acceptor: Arc<TlsAcceptor>,
    pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
    auth_token: Option<String>,
}

/// A DoH server with all sockets already bound, ready to serve queries.
///
/// Created by [`DohServer::bind`]. The separation allows callers to drop
/// privileges between binding (which may require root for port 443) and
/// serving (which runs as an unprivileged user).
pub struct BoundDohServer {
    listeners: Vec<TcpListener>,
    tls_acceptor: Arc<TlsAcceptor>,
    pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
    auth_token: Option<String>,
}

impl DohServer {
    /// Creates a new `DohServer` from a [`TlsSocketConfig`] and request pipeline slot.
    ///
    /// Validates bind addresses and loads the TLS certificate and key. Returns an
    /// error immediately if the TLS material is invalid or addresses are unparseable.
    pub fn new(
        config: &TlsSocketConfig,
        pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
        auth_token: Option<String>,
    ) -> Result<Self, DohListenerError> {
        let mut bind_addrs = Vec::with_capacity(config.addresses.len());
        for addr in &config.addresses {
            let raw = if addr.contains(':') {
                format!("[{addr}]:{}", config.port)
            } else {
                format!("{addr}:{}", config.port)
            };
            let parsed =
                raw.parse::<SocketAddr>()
                    .map_err(|e| DohListenerError::InvalidAddress {
                        addr: raw,
                        source: e,
                    })?;
            bind_addrs.push(parsed);
        }

        let tls = &config.tls;
        let autogenerate = tls.autogenerate.unwrap_or(false);
        if autogenerate {
            autogenerate_tls_cert_if_missing(&tls.cert_path, &tls.key_path, &config.addresses)
                .map_err(|e| DohListenerError::Tls(e.to_string()))?;
        }
        let tls_config = build_tls_server_config(&tls.cert_path, &tls.key_path)
            .map_err(|e| DohListenerError::Tls(e.to_string()))?;
        let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(tls_config)));

        Ok(Self {
            bind_addrs,
            tls_acceptor,
            pipeline_slot,
            auth_token,
        })
    }

    /// Binds TCP listeners on all configured addresses.
    ///
    /// Returns a [`BoundDohServer`] that can be used to start serving queries.
    /// This separation allows the caller to drop privileges between binding
    /// (which may require root) and serving.
    pub async fn bind(self) -> Result<BoundDohServer, DohListenerError> {
        let mut listeners = Vec::with_capacity(self.bind_addrs.len());

        for bind_addr in &self.bind_addrs {
            let tcp = bind_tcp_tokio(*bind_addr).map_err(|e| DohListenerError::BindFailed {
                addr: *bind_addr,
                source: e,
            })?;

            tracing::info!(addr = %bind_addr, "DoH listener bound (HTTPS)");
            listeners.push(tcp);
        }

        Ok(BoundDohServer {
            listeners,
            tls_acceptor: self.tls_acceptor,
            pipeline_slot: self.pipeline_slot,
            auth_token: self.auth_token,
        })
    }
}

impl BoundDohServer {
    /// Serves DoH queries on the previously bound sockets until a fatal error occurs.
    pub async fn serve(self) -> Result<(), DohListenerError> {
        let mut tasks = Vec::new();
        let auth_token = self.auth_token.map(Arc::new);

        for listener in self.listeners {
            let acceptor = Arc::clone(&self.tls_acceptor);
            let pipeline = Arc::clone(&self.pipeline_slot);
            let token = auth_token.clone();
            tasks.push(tokio::spawn(run_https(listener, acceptor, pipeline, token)));
        }

        // Wait for the first task to exit (which signals a fatal error).
        let (result, _idx, _remaining) = futures::future::select_all(tasks).await;
        flatten_join(result)
    }
}

fn flatten_join(
    result: Result<Result<(), DohListenerError>, tokio::task::JoinError>,
) -> Result<(), DohListenerError> {
    match result {
        Ok(inner) => inner,
        Err(e) => Err(DohListenerError::Runtime(io::Error::other(e.to_string()))),
    }
}

/// Drives the HTTPS accept loop, spawning a task per incoming connection.
async fn run_https(
    listener: TcpListener,
    acceptor: Arc<TlsAcceptor>,
    pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
    auth_token: Option<Arc<String>>,
) -> Result<(), DohListenerError> {
    loop {
        let (stream, peer) = listener.accept().await.map_err(DohListenerError::Runtime)?;
        let acceptor = Arc::clone(&acceptor);
        let pipeline_slot = Arc::clone(&pipeline_slot);
        let auth_token = auth_token.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(peer = %peer, error = %e, "DoH TLS handshake failed");
                    return;
                }
            };

            let pipeline_slot = pipeline_slot.clone();
            let auth_token = auth_token.clone();
            let service = service_fn(move |req| {
                let pipeline_slot = pipeline_slot.clone();
                let auth_token = auth_token.clone();
                async move {
                    Ok::<_, hyper::Error>(
                        handle_doh_request(
                            req,
                            &pipeline_slot,
                            auth_token.as_deref().map(|s| s.as_str()),
                        )
                        .await,
                    )
                }
            });

            if let Err(e) = Http::new().serve_connection(tls_stream, service).await {
                // Connection-level HTTP errors (client closed early, protocol
                // violations) are expected and should not bubble up.
                tracing::debug!(peer = %peer, error = %e, "DoH HTTP connection error");
            }
        });
    }
}

/// Handles a single DoH HTTP request: validates method, path, content type,
/// auth, and payload size, then forwards the DNS query to the pipeline and
/// returns the response.
async fn handle_doh_request(
    req: Request<Body>,
    pipeline_slot: &Arc<Mutex<Arc<DnsRequestPipeline>>>,
    auth_token: Option<&str>,
) -> Response<Body> {
    // --- Authentication ---
    if let Some(expected) = auth_token {
        match req.headers().get("authorization") {
            Some(value) => {
                let value = value.to_str().unwrap_or("");
                let expected_header = format!("Bearer {expected}");
                if !constant_time_eq(value.as_bytes(), expected_header.as_bytes()) {
                    return error_response(StatusCode::UNAUTHORIZED, "invalid authorization token");
                }
            }
            None => {
                return error_response(StatusCode::UNAUTHORIZED, "authorization header required");
            }
        }
    }

    // --- Path validation ---
    if req.uri().path() != DOH_PATH {
        return error_response(StatusCode::NOT_FOUND, "not found");
    }

    // --- Extract DNS payload based on method ---
    let dns_payload = match *req.method() {
        Method::POST => {
            // Validate Content-Type
            let ct = req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ct.starts_with(DNS_MESSAGE_CONTENT_TYPE) {
                return error_response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Content-Type must be application/dns-message",
                );
            }

            let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error = %e, "DoH failed to read request body");
                    return error_response(StatusCode::BAD_REQUEST, "failed to read request body");
                }
            };

            if body_bytes.is_empty() {
                return error_response(StatusCode::BAD_REQUEST, "empty DNS payload");
            }
            if body_bytes.len() > MAX_DNS_PAYLOAD {
                return error_response(StatusCode::PAYLOAD_TOO_LARGE, "DNS payload too large");
            }

            body_bytes.to_vec()
        }
        Method::GET => {
            let query_string = req.uri().query().unwrap_or("");
            let dns_param = query_string.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                if key == "dns" {
                    Some(value)
                } else {
                    None
                }
            });

            let encoded = match dns_param {
                Some(v) if !v.is_empty() => v,
                _ => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "missing 'dns' query parameter",
                    );
                }
            };

            match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(bytes) if bytes.is_empty() => {
                    return error_response(StatusCode::BAD_REQUEST, "empty DNS payload");
                }
                Ok(bytes) if bytes.len() > MAX_DNS_PAYLOAD => {
                    return error_response(StatusCode::PAYLOAD_TOO_LARGE, "DNS payload too large");
                }
                Ok(bytes) => bytes,
                Err(_) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid base64url in 'dns' parameter",
                    );
                }
            }
        }
        _ => {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header("Allow", "GET, POST")
                .body(Body::from("method not allowed"))
                .expect("static response must be valid");
        }
    };

    // --- Forward to DNS pipeline ---
    let response_bytes = forward_query(pipeline_slot, &dns_payload).await;

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", DNS_MESSAGE_CONTENT_TYPE)
        .body(Body::from(response_bytes))
        .expect("DNS response must be valid")
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

    tracing::debug!(domain = %domain, qtype = %qtype, "DoH query received");

    let request = DnsPipelineRequest::new(query.to_vec());
    match pipeline.handle_request(&request).await {
        Ok(Some(response)) => response.into_bytes(),
        Ok(None) => {
            tracing::warn!(domain = %domain, qtype = %qtype, "DoH pipeline returned no response; returning SERVFAIL");
            build_servfail_response(query)
        }
        Err(error) => {
            tracing::warn!(domain = %domain, qtype = %qtype, error = %error, "DoH pipeline failed; returning SERVFAIL");
            build_servfail_response(query)
        }
    }
}

/// Constant-time comparison to prevent timing side-channel attacks on token
/// validation. Returns `true` when both slices are equal.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Builds an HTTP error response with a plain-text body.
fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(message.to_string()))
        .expect("error response must be valid")
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use async_trait::async_trait;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, RecordType};
    use hyper::{Body, Method, Request, StatusCode};
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

    fn success_pipeline() -> Arc<Mutex<Arc<DnsRequestPipeline>>> {
        let response = make_noerror_response(42);
        pipeline_slot(Arc::new(FixedResponseResolver(response)), neutral_filter())
    }

    fn post_request(path: &str, content_type: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(format!("https://localhost{path}"))
            .header("content-type", content_type)
            .body(Body::from(body))
            .unwrap()
    }

    fn get_request(path: &str, query_string: &str) -> Request<Body> {
        let uri = if query_string.is_empty() {
            format!("https://localhost{path}")
        } else {
            format!("https://localhost{path}?{query_string}")
        };
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    fn authed_post_request(
        path: &str,
        content_type: &str,
        body: Vec<u8>,
        token: &str,
    ) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(format!("https://localhost{path}"))
            .header("content-type", content_type)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body))
            .unwrap()
    }

    // ── Basic helpers ────────────────────────────────────────────────────────

    #[test]
    fn doh_adapter_protocol_name() {
        assert_eq!(DohAdapter.protocol_name(), "doh");
    }

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq(b"token123", b"token123"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"token123", b"token456"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longtoken"));
    }

    #[test]
    fn error_response_returns_correct_status_and_body() {
        let resp = error_response(StatusCode::BAD_REQUEST, "test error");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── POST happy path ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn post_valid_dns_query_returns_200_with_dns_response() {
        let pipeline = success_pipeline();
        let query = make_query("example.com.");
        let req = post_request("/dns-query", "application/dns-message", query);

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/dns-message"
        );

        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let msg = Message::from_vec(&body).expect("valid DNS message");
        assert_eq!(msg.response_code, ResponseCode::NoError);
    }

    // ── GET happy path ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_valid_dns_query_returns_200_with_dns_response() {
        let pipeline = success_pipeline();
        let query = make_query("example.com.");
        let encoded = URL_SAFE_NO_PAD.encode(&query);
        let req = get_request("/dns-query", &format!("dns={encoded}"));

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/dns-message"
        );
    }

    // ── Path validation ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn wrong_path_returns_404() {
        let pipeline = success_pipeline();
        let query = make_query("example.com.");
        let req = post_request("/wrong-path", "application/dns-message", query);

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Method validation ────────────────────────────────────────────────────

    #[tokio::test]
    async fn put_method_returns_405() {
        let pipeline = success_pipeline();
        let req = Request::builder()
            .method(Method::PUT)
            .uri("https://localhost/dns-query")
            .body(Body::empty())
            .unwrap();

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp.headers().get("allow").unwrap(), "GET, POST");
    }

    // ── Content-Type validation ──────────────────────────────────────────────

    #[tokio::test]
    async fn post_wrong_content_type_returns_415() {
        let pipeline = success_pipeline();
        let query = make_query("example.com.");
        let req = post_request("/dns-query", "text/plain", query);

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // ── Empty/oversized payload ──────────────────────────────────────────────

    #[tokio::test]
    async fn post_empty_body_returns_400() {
        let pipeline = success_pipeline();
        let req = post_request("/dns-query", "application/dns-message", vec![]);

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_oversized_body_returns_413() {
        let pipeline = success_pipeline();
        let big = vec![0u8; MAX_DNS_PAYLOAD + 1];
        let req = post_request("/dns-query", "application/dns-message", big);

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ── GET parameter validation ─────────────────────────────────────────────

    #[tokio::test]
    async fn get_missing_dns_param_returns_400() {
        let pipeline = success_pipeline();
        let req = get_request("/dns-query", "");

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_empty_dns_param_returns_400() {
        let pipeline = success_pipeline();
        let req = get_request("/dns-query", "dns=");

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_invalid_base64_returns_400() {
        let pipeline = success_pipeline();
        let req = get_request("/dns-query", "dns=!!!invalid!!!");

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_oversized_decoded_payload_returns_413() {
        let pipeline = success_pipeline();
        let big = vec![0u8; MAX_DNS_PAYLOAD + 1];
        let encoded = URL_SAFE_NO_PAD.encode(&big);
        let req = get_request("/dns-query", &format!("dns={encoded}"));

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ── Auth checks ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn auth_required_missing_header_returns_401() {
        let pipeline = success_pipeline();
        let query = make_query("example.com.");
        let req = post_request("/dns-query", "application/dns-message", query);

        let resp = handle_doh_request(req, &pipeline, Some("secret-token")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_required_wrong_token_returns_401() {
        let pipeline = success_pipeline();
        let query = make_query("example.com.");
        let req = authed_post_request("/dns-query", "application/dns-message", query, "wrong");

        let resp = handle_doh_request(req, &pipeline, Some("secret-token")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_required_correct_token_returns_200() {
        let pipeline = success_pipeline();
        let query = make_query("example.com.");
        let req = authed_post_request(
            "/dns-query",
            "application/dns-message",
            query,
            "secret-token",
        );

        let resp = handle_doh_request(req, &pipeline, Some("secret-token")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn no_auth_configured_skips_check() {
        let pipeline = success_pipeline();
        let query = make_query("example.com.");
        let req = post_request("/dns-query", "application/dns-message", query);

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── Pipeline error fallback ──────────────────────────────────────────────

    #[tokio::test]
    async fn pipeline_failure_returns_servfail_in_200() {
        let pipeline = pipeline_slot(Arc::new(AlwaysFailResolver), neutral_filter());
        let query = make_query("example.com.");
        let req = post_request("/dns-query", "application/dns-message", query);

        let resp = handle_doh_request(req, &pipeline, None).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let msg = Message::from_vec(&body).expect("valid DNS message");
        assert_eq!(msg.response_code, ResponseCode::ServFail);
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
        assert_eq!(msg.response_code, ResponseCode::ServFail);
        assert_eq!(msg.id, 42);
    }

    // ── TLS config loading ───────────────────────────────────────────────────

    #[test]
    fn build_tls_server_config_rejects_missing_cert() {
        let err = build_tls_server_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("certificate file"));
    }
}
