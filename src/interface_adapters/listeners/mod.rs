#[cfg(feature = "http-api")]
pub mod admin;
#[cfg(any(feature = "http-api", feature = "mcp"))]
pub mod auth;
pub mod dns;
#[cfg(feature = "doh")]
pub mod doh;
#[cfg(feature = "doq")]
pub mod doq;
#[cfg(feature = "dot")]
pub mod dot;
pub mod handler;
#[cfg(feature = "http-api")]
pub mod http;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod metrics;
#[cfg(any(
    feature = "dot",
    feature = "doh",
    feature = "doq",
    feature = "http-api"
))]
pub mod tls;

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};

#[cfg(any(
    feature = "dot",
    feature = "doh",
    feature = "doq",
    feature = "http-api"
))]
use rustls::ServerConfig;
#[cfg(any(
    feature = "dot",
    feature = "doh",
    feature = "doq",
    feature = "http-api"
))]
use std::sync::Arc;

#[cfg(any(
    feature = "dot",
    feature = "doh",
    feature = "doq",
    feature = "http-api"
))]
use self::tls::{autogenerate_tls_cert_if_missing, build_tls_server_config, TlsSetupError};
#[cfg(any(
    feature = "dot",
    feature = "doh",
    feature = "doq",
    feature = "http-api"
))]
use crate::frameworks::config::schema::TlsConfig;

/// Errors that can occur when setting up listeners.
#[derive(Debug, thiserror::Error)]
pub enum ListenerSetupError {
    #[error("invalid bind address '{addr}': {source}")]
    InvalidAddress {
        addr: String,
        source: std::net::AddrParseError,
    },
    #[error("failed to bind {proto} on {addr}: {source}")]
    BindFailed {
        proto: &'static str,
        addr: SocketAddr,
        source: io::Error,
    },
    #[cfg(any(
        feature = "dot",
        feature = "doh",
        feature = "doq",
        feature = "http-api"
    ))]
    #[error("TLS configuration error: {0}")]
    Tls(#[from] TlsSetupError),
    #[error("listener registration error: {0}")]
    Registration(String),
}

/// Parses address strings and a port into a list of [`SocketAddr`]s.
///
/// IPv6 addresses are automatically wrapped in brackets before parsing.
pub fn parse_bind_addrs(
    addresses: &[String],
    port: u16,
) -> Result<Vec<SocketAddr>, ListenerSetupError> {
    let mut result = Vec::with_capacity(addresses.len());
    for addr in addresses {
        let raw = if addr.contains(':') {
            format!("[{addr}]:{port}")
        } else {
            format!("{addr}:{port}")
        };
        let parsed = raw
            .parse::<SocketAddr>()
            .map_err(|e| ListenerSetupError::InvalidAddress {
                addr: raw,
                source: e,
            })?;
        result.push(parsed);
    }
    Ok(result)
}

/// Builds a [`rustls::ServerConfig`] with the given ALPN protocol for use with
/// hickory-server listeners. Optionally auto-generates a self-signed certificate.
#[cfg(any(feature = "dot", feature = "doh", feature = "doq"))]
pub fn build_tls_config_with_alpn(
    tls: &TlsConfig,
    extra_sans: &[String],
    alpn: &[u8],
) -> Result<Arc<ServerConfig>, ListenerSetupError> {
    if tls.autogenerate.unwrap_or(false) {
        autogenerate_tls_cert_if_missing(&tls.cert_path, &tls.key_path, extra_sans)?;
    }
    let mut config = build_tls_server_config(&tls.cert_path, &tls.key_path)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(config))
}

/// Builds a [`rustls::ServerConfig`] with HTTP/1.1 and HTTP/2 ALPN negotiation.
/// Optionally auto-generates a self-signed certificate when `autogenerate` is set.
#[cfg(feature = "http-api")]
pub fn build_tls_config_for_https(
    tls: &TlsConfig,
    extra_sans: &[String],
) -> Result<Arc<ServerConfig>, ListenerSetupError> {
    if tls.autogenerate.unwrap_or(false) {
        autogenerate_tls_cert_if_missing(&tls.cert_path, &tls.key_path, extra_sans)?;
    }
    let mut config = build_tls_server_config(&tls.cert_path, &tls.key_path)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Builds a plain [`rustls::ServerConfig`] without ALPN for raw-TCP TLS servers
/// (e.g. metrics). Optionally auto-generates a self-signed certificate.
#[cfg(any(
    feature = "dot",
    feature = "doh",
    feature = "doq",
    feature = "http-api"
))]
pub fn build_tls_config_plain(
    tls: &TlsConfig,
    extra_sans: &[String],
) -> Result<Arc<ServerConfig>, ListenerSetupError> {
    if tls.autogenerate.unwrap_or(false) {
        autogenerate_tls_cert_if_missing(&tls.cert_path, &tls.key_path, extra_sans)?;
    }
    let config = build_tls_server_config(&tls.cert_path, &tls.key_path)?;
    Ok(Arc::new(config))
}

/// Builds a [`rustls::ServerConfig`] backed by a shared cert resolver for ACME.
/// The resolver enables hot-reload of certificates without restarting listeners.
/// Sets the given ALPN protocol.
#[cfg(feature = "acme")]
pub fn build_tls_config_with_resolver_alpn(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    alpn: &[u8],
) -> Result<Arc<ServerConfig>, ListenerSetupError> {
    let mut config = self::tls::build_tls_server_config_with_resolver(resolver)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(config))
}

/// Builds a [`rustls::ServerConfig`] backed by a shared cert resolver for ACME.
/// Configures HTTP/2 and HTTP/1.1 ALPN for HTTPS listeners.
#[cfg(feature = "acme")]
pub fn build_tls_config_with_resolver_https(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
) -> Result<Arc<ServerConfig>, ListenerSetupError> {
    let mut config = self::tls::build_tls_server_config_with_resolver(resolver)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Builds a plain [`rustls::ServerConfig`] backed by a shared cert resolver for ACME.
/// No ALPN is set.
#[cfg(feature = "acme")]
pub fn build_tls_config_with_resolver_plain(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
) -> Result<Arc<ServerConfig>, ListenerSetupError> {
    let config = self::tls::build_tls_server_config_with_resolver(resolver)?;
    Ok(Arc::new(config))
}

/// Creates and binds a UDP socket with proper dual-stack handling.
///
/// For IPv6 addresses, sets `IPV6_V6ONLY` to prevent the socket from
/// also capturing IPv4 traffic, which would cause subsequent IPv4 binds
/// to fail with `EADDRINUSE`.
pub fn bind_udp(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    configure_socket(&socket, addr)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Creates and binds a TCP listener with proper dual-stack handling.
///
/// For IPv6 addresses, sets `IPV6_V6ONLY` to prevent the socket from
/// also capturing IPv4 traffic. Sets `SO_REUSEADDR` and starts
/// listening with a backlog of 1024.
pub fn bind_tcp(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    configure_socket(&socket, addr)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

/// Converts a pre-configured std UDP socket into a non-blocking tokio socket.
pub async fn bind_udp_tokio(addr: SocketAddr) -> io::Result<UdpSocket> {
    let std_socket = bind_udp(addr)?;
    std_socket.set_nonblocking(true)?;
    UdpSocket::from_std(std_socket)
}

/// Converts a pre-configured std TCP listener into a non-blocking tokio listener.
pub fn bind_tcp_tokio(addr: SocketAddr) -> io::Result<TcpListener> {
    let std_listener = bind_tcp(addr)?;
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

/// Applies common socket options before binding.
fn configure_socket(socket: &Socket, addr: SocketAddr) -> io::Result<()> {
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    Ok(())
}
