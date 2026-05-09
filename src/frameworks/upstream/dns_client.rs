use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use trust_dns_client::client::{AsyncDnssecClient, ClientConnection, ClientHandle};
use trust_dns_client::tcp::TcpClientConnection;
use trust_dns_client::udp::UdpClientConnection;
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::{DNSClass, Name, RecordType};

use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};

const UDP_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_TIMEOUT: Duration = Duration::from_secs(10);

/// DNS resolver that sends queries over UDP and falls back to TCP when the response
/// is truncated (TC bit set), per RFC 5966.
#[derive(Debug, Clone, Copy)]
pub struct DnsUdpTcpClient {
    address: SocketAddr,
}

impl DnsUdpTcpClient {
    pub fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    fn extract_question(
        query: &[u8],
    ) -> Result<(Name, DNSClass, RecordType), UpstreamResolveError> {
        let message =
            Message::from_vec(query).map_err(|e| UpstreamResolveError::Protocol(e.to_string()))?;
        let question = message
            .queries()
            .first()
            .ok_or_else(|| UpstreamResolveError::Protocol("query contains no questions".into()))?;

        Ok((
            question.name().clone(),
            question.query_class(),
            question.query_type(),
        ))
    }

    async fn resolve_with_connection<C>(
        &self,
        query: &[u8],
        connection: C,
    ) -> Result<Vec<u8>, UpstreamResolveError>
    where
        C: ClientConnection + Send + Sync + 'static,
        C::SenderFuture: Send + 'static,
    {
        let (name, query_class, query_type) = Self::extract_question(query)?;
        let (mut client, background) = AsyncDnssecClient::connect(connection.new_stream(None))
            .await
            .map_err(|e| UpstreamResolveError::Protocol(e.to_string()))?;

        tokio::spawn(background);

        let response = client
            .query(name, query_class, query_type)
            .await
            .map_err(|e| UpstreamResolveError::Protocol(e.to_string()))?;

        response
            .to_vec()
            .map_err(|e| UpstreamResolveError::Protocol(e.to_string()))
    }
}

#[async_trait]
impl UpstreamResolver for DnsUdpTcpClient {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
        let udp_connection = UdpClientConnection::with_timeout(self.address, UDP_TIMEOUT)
            .map_err(|error| UpstreamResolveError::Protocol(error.to_string()))?;
        let response = self.resolve_with_connection(&query, udp_connection).await?;

        let msg = Message::from_vec(&response)
            .map_err(|e| UpstreamResolveError::Protocol(e.to_string()))?;

        if msg.truncated() {
            let tcp_connection = TcpClientConnection::with_timeout(self.address, TCP_TIMEOUT)
                .map_err(|error| UpstreamResolveError::Protocol(error.to_string()))?;
            self.resolve_with_connection(&query, tcp_connection).await
        } else {
            Ok(response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_proto::op::ResponseCode;
    use trust_dns_proto::rr::RecordType;

    /// Hand-crafted standard query for `example.com` type A, class IN (RFC 1035).
    ///
    /// Bytes:
    ///   0x00 0x01          — Message ID
    ///   0x01 0x00          — Flags: QR=0 RD=1
    ///   0x00 0x01          — QDCOUNT = 1
    ///   0x00 0x00 * 3      — ANCOUNT / NSCOUNT / ARCOUNT = 0
    ///   0x07 "example"     — label (7 chars)
    ///   0x03 "com" 0x00    — label (3 chars) + root
    ///   0x00 0x01 0x00 0x01 — QTYPE=A, QCLASS=IN
    #[rustfmt::skip]
    const EXAMPLE_COM_A_QUERY: &[u8] = &[
        0x00, 0x01,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    ];

    #[test]
    fn test_extract_question_parses_name_class_and_type() {
        let (name, query_class, query_type) =
            DnsUdpTcpClient::extract_question(EXAMPLE_COM_A_QUERY)
                .expect("failed to parse question");

        assert_eq!(name.to_ascii(), "example.com.");
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
    async fn test_resolve_example_com_a_over_udp() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let client = DnsUdpTcpClient::new(addr);
        let response = client
            .resolve(EXAMPLE_COM_A_QUERY.to_vec())
            .await
            .expect("resolution failed");

        let msg = Message::from_vec(&response).expect("failed to parse response");
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert!(
            !msg.answers().is_empty(),
            "expected at least one answer record"
        );
    }

    #[tokio::test]
    #[ignore = "requires network access to 8.8.8.8:53"]
    async fn test_resolve_example_com_a_over_tcp() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let client = DnsUdpTcpClient::new(addr);
        let connection = TcpClientConnection::with_timeout(addr, TCP_TIMEOUT).unwrap();
        let response = client
            .resolve_with_connection(EXAMPLE_COM_A_QUERY, connection)
            .await
            .expect("TCP resolution failed");

        let msg = Message::from_vec(&response).expect("failed to parse response");
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert!(!msg.answers().is_empty());
    }
}
