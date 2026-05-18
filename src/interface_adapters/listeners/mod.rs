pub mod auth;
pub mod dns;
pub mod doh;
pub mod doq;
pub mod dot;
pub mod handler;
pub mod http;
pub mod mcp;
pub mod tls;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::ServerConfig;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};

use self::tls::{autogenerate_tls_cert_if_missing, build_tls_server_config, TlsSetupError};
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
