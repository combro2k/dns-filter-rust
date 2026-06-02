use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_net::client::{ClientHandle, DnssecClient};
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::DnsMultiplexer;
use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, Name, RecordType};

use tokio::sync::Mutex;

use super::runtime::{OutboundRouting, RoutedRuntimeProvider};
use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};

const UDP_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_TIMEOUT: Duration = Duration::from_secs(10);

/// A cached TCP DNS client connection shared across queries.
///
/// `DnssecClient` does not implement `Debug`, so we wrap the cache in a newtype
/// that provides a no-op `Debug` impl so that `DnsUdpTcpClient` can still derive it.
#[derive(Clone, Default)]
struct TcpClientCache(Arc<Mutex<Option<DnssecClient>>>);

impl fmt::Debug for TcpClientCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpClientCache").finish_non_exhaustive()
    }
}

/// DNS resolver that sends queries over UDP and falls back to TCP when the response
/// is truncated (TC bit set), per RFC 5966.
#[derive(Debug, Clone)]
pub struct DnsUdpTcpClient {
    address: SocketAddr,
    tcp_cache: TcpClientCache,
    routing: OutboundRouting,
    label: String,
}

impl DnsUdpTcpClient {
    pub fn new(address: SocketAddr) -> Self {
        let label = format!("dns://{address}");
        Self {
            address,
            tcp_cache: TcpClientCache::default(),
            routing: OutboundRouting::new(None, None),
            label,
        }
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

    async fn resolve_udp(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamResolveError> {
        let (name, query_class, query_type) = Self::extract_question(query)?;
        let provider = RoutedRuntimeProvider::new(self.routing.clone());
        let conn = UdpClientStream::builder(self.address, provider)
            .with_timeout(Some(UDP_TIMEOUT))
            .build();
        let (mut client, background) = DnssecClient::connect(std::future::ready(Ok(conn)))
            .await
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

        tokio::spawn(background);

        let response =
            tokio::time::timeout(UDP_TIMEOUT, client.query(name, query_class, query_type))
                .await
                .map_err(|_| UpstreamResolveError::Timeout)?
                .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

        response
            .to_vec()
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))
    }

    async fn resolve_tcp(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamResolveError> {
        let (name, query_class, query_type) = Self::extract_question(query)?;

        // Try the cached TCP connection first (clone to release the lock before I/O).
        let cached = self.tcp_cache.0.lock().await.clone();
        if let Some(mut client) = cached {
            match tokio::time::timeout(
                TCP_TIMEOUT,
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
                    *self.tcp_cache.0.lock().await = None;
                }
            }
        }

        // Establish a fresh TCP connection.
        let provider = RoutedRuntimeProvider::new(self.routing.clone());
        let (tcp_connect, sender) =
            TcpClientStream::new(self.address, None, Some(TCP_TIMEOUT), provider);
        let tcp_stream = tcp_connect
            .await
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;
        let multiplexer = DnsMultiplexer::new(tcp_stream, sender);
        let (mut client, background) = DnssecClient::connect(std::future::ready(Ok(multiplexer)))
            .await
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

        tokio::spawn(background);

        let response =
            tokio::time::timeout(TCP_TIMEOUT, client.query(name, query_class, query_type))
                .await
                .map_err(|_| UpstreamResolveError::Timeout)?
                .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

        // Cache the connection for subsequent queries.
        *self.tcp_cache.0.lock().await = Some(client.clone());

        response
            .to_vec()
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))
    }
}

#[async_trait]
impl UpstreamResolver for DnsUdpTcpClient {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
        let response = self.resolve_udp(&query).await?;

        let msg = Message::from_vec(&response)
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

        if msg.truncation {
            self.resolve_tcp(&query).await
        } else {
            Ok(response)
        }
    }

    fn label(&self) -> &str {
        &self.label
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::ResponseCode;

    fn build_query(domain: &str) -> Vec<u8> {
        let mut msg = Message::new(
            1,
            hickory_proto::op::MessageType::Query,
            hickory_proto::op::OpCode::Query,
        );
        msg.metadata.recursion_desired = true;
        msg.add_query({
            let mut q = hickory_proto::op::Query::new();
            q.set_name(domain.parse().unwrap());
            q.set_query_type(RecordType::A);
            q.set_query_class(DNSClass::IN);
            q
        });
        msg.to_vec().unwrap()
    }

    /// Hand-crafted standard query for `sigok.verteiltesysteme.net` type A, class IN (RFC 1035).
    ///
    /// Bytes:
    ///   0x00 0x01          — Message ID
    ///   0x01 0x00          — Flags: QR=0 RD=1
    ///   0x00 0x01          — QDCOUNT = 1
    ///   0x00 0x00 * 3      — ANCOUNT / NSCOUNT / ARCOUNT = 0
    ///   0x05 "sigok"       — label (5 chars)
    ///   0x10 "verteiltesysteme" — label (16 chars)
    ///   0x03 "net"         — label (3 chars)
    ///   0x00 0x01 0x00 0x01 — QTYPE=A, QCLASS=IN
    #[rustfmt::skip]
    const SIGOK_VERTEILTESYSTEME_NET_A_QUERY: &[u8] = &[
        0x00, 0x01,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x05, b's', b'i', b'g', b'o', b'k',
        0x10, b'v', b'e', b'r', b't', b'e', b'i', b'l', b't', b'e', b's', b'y', b's', b't', b'e', b'm', b'e',
        0x03, b'n', b'e', b't',
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    ];

    #[test]
    fn test_extract_question_parses_name_class_and_type() {
        let (name, query_class, query_type) =
            DnsUdpTcpClient::extract_question(SIGOK_VERTEILTESYSTEME_NET_A_QUERY)
                .expect("failed to parse question");

        assert_eq!(name.to_ascii(), "sigok.verteiltesysteme.net.");
        assert_eq!(query_class, DNSClass::IN);
        assert_eq!(query_type, RecordType::A);
    }

    #[test]
    fn test_extract_question_rejects_empty_query() {
        let error = DnsUdpTcpClient::extract_question(&[0u8; 12]).unwrap_err();
        assert!(matches!(error, UpstreamResolveError::Protocol(_)));
    }

    #[tokio::test]
    #[ignore = "requires network access to 8.8.8.8:53"]
    async fn test_resolve_sigok_verteiltesysteme_net_a_over_udp() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let client = DnsUdpTcpClient::new(addr);
        let response = client
            .resolve(SIGOK_VERTEILTESYSTEME_NET_A_QUERY.to_vec())
            .await
            .expect("resolution failed");

        let msg = Message::from_vec(&response).expect("failed to parse response");
        assert_eq!(msg.response_code, ResponseCode::NoError);
        assert!(
            !msg.answers.is_empty(),
            "expected at least one answer record"
        );
    }

    #[tokio::test]
    #[ignore = "requires network access to 8.8.8.8:53"]
    async fn test_resolve_sigok_verteiltesysteme_net_a_over_tcp() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let client = DnsUdpTcpClient::new(addr);
        let response = client
            .resolve_tcp(SIGOK_VERTEILTESYSTEME_NET_A_QUERY)
            .await
            .expect("TCP resolution failed");

        let msg = Message::from_vec(&response).expect("failed to parse response");
        assert_eq!(msg.response_code, ResponseCode::NoError);
        assert!(!msg.answers.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access to 8.8.8.8:53"]
    async fn test_dnssec_validation_rejects_broken_chain() {
        // dnssec-failed.org is intentionally configured with broken DNSSEC signatures
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let client = DnsUdpTcpClient::new(addr);
        let query = build_query("dnssec-failed.org.");
        let result = client.resolve(query).await;

        assert!(
            result.is_err(),
            "expected DNSSEC validation to reject broken chain"
        );
    }
}
