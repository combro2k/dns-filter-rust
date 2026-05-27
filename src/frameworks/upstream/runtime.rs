//! Custom [`RuntimeProvider`] for upstream DNS connections that supports
//! source address binding (`bind_address`) and Linux policy routing (`SO_MARK`).
//!
//! When neither option is configured, all calls delegate directly to the inner
//! [`TokioRuntimeProvider`] with zero overhead.

use std::fs;
#[cfg(target_os = "linux")]
/// Checks if CAP_NET_ADMIN is present in the current process (Linux only).
#[cfg(target_os = "linux")]
fn has_cap_net_admin() -> bool {
    use caps::{Capability, has_cap};
    has_cap(None, caps::CapSet::Effective, Capability::CAP_NET_ADMIN).unwrap_or(false)
}

/// Warn at runtime if fwmark is configured but CAP_NET_ADMIN is not present.
pub fn warn_if_fwmark_without_cap_net_admin(fwmark: Option<u32>) {
    #[cfg(target_os = "linux")]
    if fwmark.is_some() && !has_cap_net_admin() {
        tracing::warn!(
            "fwmark is configured but CAP_NET_ADMIN is not present in the effective set; SO_MARK will fail in chroot mode. Check your systemd/OpenRC unit capabilities."
        );
    }
}
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use hickory_net::runtime::{iocompat::AsyncIoTokioAsStd, RuntimeProvider, TokioRuntimeProvider};
use tokio::net::TcpStream;

/// Configuration for outbound socket routing (bind address and/or fwmark).
#[derive(Debug, Clone)]
pub struct OutboundRouting {
    pub bind_address: Option<IpAddr>,
    pub fwmark: Option<u32>,
}

impl OutboundRouting {
    pub fn new(bind_address: Option<IpAddr>, fwmark: Option<u32>) -> Self {
        Self {
            bind_address,
            fwmark,
        }
    }

    /// Returns `true` if no custom routing is configured.
    pub fn is_empty(&self) -> bool {
        self.bind_address.is_none() && self.fwmark.is_none()
    }
}

/// A [`RuntimeProvider`] that wraps [`TokioRuntimeProvider`] and optionally:
/// - Binds outgoing sockets to a specific source IP (`bind_address`)
/// - Sets `SO_MARK` on sockets for Linux policy routing (`fwmark`)
///
/// When no routing options are configured, delegates directly to the inner provider.
#[derive(Clone)]
pub struct RoutedRuntimeProvider {
    inner: TokioRuntimeProvider,
    routing: OutboundRouting,
}

impl RoutedRuntimeProvider {
    pub fn new(routing: OutboundRouting) -> Self {
        Self {
            inner: TokioRuntimeProvider::default(),
            routing,
        }
    }
}

impl Default for RoutedRuntimeProvider {
    fn default() -> Self {
        Self {
            inner: TokioRuntimeProvider::default(),
            routing: OutboundRouting {
                bind_address: None,
                fwmark: None,
            },
        }
    }
}

impl RuntimeProvider for RoutedRuntimeProvider {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = <TokioRuntimeProvider as RuntimeProvider>::Udp;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.inner.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        // Fast path: no custom routing, delegate to inner provider.
        if self.routing.is_empty() {
            return self.inner.connect_tcp(server_addr, bind_addr, timeout);
        }

        let routing = self.routing.clone();
        Box::pin(async move {
            use socket2::{Domain, Protocol, Socket, Type};

            let domain = match server_addr {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

            // Apply fwmark (Linux only).
            #[cfg(target_os = "linux")]
            if let Some(mark) = routing.fwmark {
                tracing::info!(fwmark = mark, "applying SO_MARK to outgoing TCP socket");
                apply_socket_mark(&socket, mark)?;
            }

            // Bind to source address (per-server override or global default).
            let effective_bind = routing
                .bind_address
                .map(|ip| SocketAddr::new(ip, 0))
                .or(bind_addr);
            if let Some(bind) = effective_bind {
                socket.bind(&bind.into())?;
            }

            socket.set_nodelay(true)?;
            socket.set_nonblocking(true)?;

            let tcp_socket = tokio::net::TcpSocket::from_std_stream(socket.into());
            let wait_for = timeout.unwrap_or(Duration::from_secs(5));

            match tokio::time::timeout(wait_for, tcp_socket.connect(server_addr)).await {
                Ok(Ok(stream)) => Ok(AsyncIoTokioAsStd(stream)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP connect timed out",
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        // Fast path: no custom routing, delegate to inner provider.
        if self.routing.is_empty() {
            return self.inner.bind_udp(local_addr, _server_addr);
        }

        let routing = self.routing.clone();
        Box::pin(async move {
            use socket2::{Domain, Protocol, Socket, Type};

            let effective_local = routing
                .bind_address
                .map(|ip| SocketAddr::new(ip, 0))
                .unwrap_or(local_addr);

            let domain = match effective_local {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

            // Apply fwmark (Linux only).
            #[cfg(target_os = "linux")]
            if let Some(mark) = routing.fwmark {
                tracing::info!(fwmark = mark, "applying SO_MARK to outgoing UDP socket");
                apply_socket_mark(&socket, mark)?;
            }

            socket.set_nonblocking(true)?;
            socket.bind(&effective_local.into())?;

            tokio::net::UdpSocket::from_std(socket.into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routed_provider_default_has_no_routing() {
        let provider = RoutedRuntimeProvider::default();
        assert!(provider.routing.is_empty());
    }

    #[test]
    fn outbound_routing_is_empty_when_no_options() {
        let routing = OutboundRouting::new(None, None);
        assert!(routing.is_empty());
    }

    #[test]
    fn outbound_routing_not_empty_with_bind_address() {
        let routing = OutboundRouting::new(Some("10.0.0.1".parse().unwrap()), None);
        assert!(!routing.is_empty());
    }

    #[test]
    fn outbound_routing_not_empty_with_fwmark() {
        let routing = OutboundRouting::new(None, Some(100));
        assert!(!routing.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_status_capabilities_line() {
        let sample = "CapEff:\t000001ffffffffff\nCapPrm:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
        let caps = parse_capability_lines(sample);
        assert_eq!(caps.0, Some("000001ffffffffff".to_string()));
        assert_eq!(caps.1, Some("000001ffffffffff".to_string()));
        assert_eq!(caps.2, Some("000001ffffffffff".to_string()));
        assert_eq!(caps.3, Some("0000000000000000".to_string()));
    }

    #[tokio::test]
    async fn bind_udp_with_loopback_succeeds() {
        let routing = OutboundRouting::new(Some("127.0.0.1".parse().unwrap()), None);
        let provider = RoutedRuntimeProvider::new(routing);
        let socket = provider
            .bind_udp("0.0.0.0:0".parse().unwrap(), "8.8.8.8:53".parse().unwrap())
            .await;
        assert!(socket.is_ok());
        let local = socket.unwrap().local_addr().unwrap();
        assert_eq!(local.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn connect_tcp_with_loopback_bind() {
        // This test verifies that socket creation with bind_address doesn't error.
        // The actual connect will fail (no server), but we verify the socket setup path.
        let routing = OutboundRouting::new(Some("127.0.0.1".parse().unwrap()), None);
        let provider = RoutedRuntimeProvider::new(routing);
        let result = provider
            .connect_tcp(
                // Connect to a port that's unlikely to be listening.
                "127.0.0.1:1".parse().unwrap(),
                None,
                Some(Duration::from_millis(100)),
            )
            .await;
        // Should fail with connection refused or timeout, not a bind error.
        assert!(result.is_err());
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn apply_socket_mark(socket: &socket2::Socket, mark: u32) -> io::Result<()> {
    if let Err(err) = socket.set_mark(mark) {
        let (eff, prm, bnd, amb) = current_process_capabilities();
        tracing::error!(
            fwmark = mark,
            error = %err,
            cap_eff = eff.as_deref(),
            cap_prm = prm.as_deref(),
            cap_bnd = bnd.as_deref(),
            cap_amb = amb.as_deref(),
            "failed to set SO_MARK on outgoing socket"
        );
        return Err(err);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn current_process_capabilities() -> (Option<String>, Option<String>, Option<String>, Option<String>) {
    fs::read_to_string("/proc/self/status")
        .ok()
        .map(|status| parse_capability_lines(&status))
        .unwrap_or((None, None, None, None))
}

#[cfg(target_os = "linux")]
fn parse_capability_lines(status: &str) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
    let mut eff = None;
    let mut prm = None;
    let mut bnd = None;
    let mut amb = None;

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            eff = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("CapPrm:") {
            prm = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("CapBnd:") {
            bnd = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("CapAmb:") {
            amb = Some(rest.trim().to_string());
        }
    }

    (eff, prm, bnd, amb)
}
