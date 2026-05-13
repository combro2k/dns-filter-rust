pub mod dns;
pub mod doh;
pub mod doq;
pub mod dot;
pub mod http;
pub mod tls;

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};

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
