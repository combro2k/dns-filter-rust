use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use futures::future::BoxFuture;
use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::op::{Message, ResponseCode};
use hickory_client::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::tcp::TcpClientStream;
use hickory_client::proto::udp::UdpClientStream;
use hickory_client::proto::xfer::DnsMultiplexer;

use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};

const UDP_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of nameservers to query concurrently during each
/// referral step.  Keeps resource usage bounded while still avoiding
/// head-of-line blocking from a single unresponsive server.
const CONCURRENT_NS_QUERIES: usize = 3;

/// Default maximum number of referral hops before the resolver gives up.
pub const DEFAULT_MAX_HOPS: u8 = 12;

/// Controls the preferred ordering of nameserver addresses when both IPv4
/// and IPv6 glue records are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpPreference {
    /// Sort IPv4 addresses before IPv6 (default).
    #[default]
    PreferIpv4,
    /// Sort IPv6 addresses before IPv4.
    PreferIpv6,
}

/// Well-known paths where the OS may ship a `root.hints` file.
const DEFAULT_ROOT_HINTS_PATHS: &[&str] = &[
    "/usr/share/dns/root.hints",
    "/usr/share/dns-root-data/root.hints",
    "/var/named/root.hints",
];

/// IPv4 addresses of the 13 IANA root nameservers (a–m.root-servers.net).
///
/// Used as compiled-in fallback when no `root.hints` file is found.
/// Published at <https://www.iana.org/domains/root/servers>.
const ROOT_HINTS_V4: &[Ipv4Addr] = &[
    Ipv4Addr::new(198, 41, 0, 4),     // a.root-servers.net
    Ipv4Addr::new(199, 9, 14, 201),   // b.root-servers.net
    Ipv4Addr::new(192, 33, 4, 12),    // c.root-servers.net
    Ipv4Addr::new(199, 7, 91, 13),    // d.root-servers.net
    Ipv4Addr::new(192, 203, 230, 10), // e.root-servers.net
    Ipv4Addr::new(192, 5, 5, 241),    // f.root-servers.net
    Ipv4Addr::new(192, 112, 36, 4),   // g.root-servers.net
    Ipv4Addr::new(198, 97, 190, 53),  // h.root-servers.net
    Ipv4Addr::new(192, 36, 148, 17),  // i.root-servers.net
    Ipv4Addr::new(192, 58, 128, 30),  // j.root-servers.net
    Ipv4Addr::new(193, 0, 14, 129),   // k.root-servers.net
    Ipv4Addr::new(199, 7, 83, 42),    // l.root-servers.net
    Ipv4Addr::new(202, 12, 27, 33),   // m.root-servers.net
];

/// IPv6 addresses of the 13 IANA root nameservers.
const ROOT_HINTS_V6: &[Ipv6Addr] = &[
    Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30), // a.root-servers.net
    Ipv6Addr::new(0x2001, 0x500, 0x200, 0, 0, 0, 0, 0xb),     // b.root-servers.net
    Ipv6Addr::new(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc),       // c.root-servers.net
    Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd),      // d.root-servers.net
    Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe),      // e.root-servers.net
    Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf),      // f.root-servers.net
    Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d),    // g.root-servers.net
    Ipv6Addr::new(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53),      // h.root-servers.net
    Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53),        // i.root-servers.net
    Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 0x2, 0x30),  // j.root-servers.net
    Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 1),           // k.root-servers.net
    Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42),     // l.root-servers.net
    Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35),        // m.root-servers.net
];

/// Parses a `root.hints` file (RFC 1035 zone-file subset) and returns the
/// socket addresses (port 53) found in A and AAAA records.
fn parse_root_hints(content: &str) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        // Tokenise: fields are whitespace-separated.
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Typical line: "A.ROOT-SERVERS.NET. 3600000 A 198.41.0.4"
        // or with class:  "A.ROOT-SERVERS.NET. 3600000 IN A 198.41.0.4"
        let (rtype, rdata) = match fields.len() {
            4 => (fields[2], fields[3]),
            5 => (fields[3], fields[4]),
            _ => continue,
        };
        match rtype {
            "A" => {
                if let Ok(ip) = rdata.parse::<Ipv4Addr>() {
                    addrs.push(SocketAddr::new(IpAddr::V4(ip), 53));
                }
            }
            "AAAA" => {
                if let Ok(ip) = rdata.parse::<Ipv6Addr>() {
                    addrs.push(SocketAddr::new(IpAddr::V6(ip), 53));
                }
            }
            _ => {}
        }
    }
    addrs
}

/// Loads root-server addresses for iterative resolution.
///
/// Resolution order:
/// 1. Explicit `root_hints_path` from config (error if unreadable).
/// 2. Well-known OS paths (`/usr/share/dns/root.hints`, etc.).
/// 3. Compiled-in IANA addresses (IPv4 + IPv6).
pub fn load_root_hints(root_hints_path: Option<&str>) -> Vec<SocketAddr> {
    // 1. Explicit path from config.
    if let Some(path) = root_hints_path {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let addrs = parse_root_hints(&content);
                if addrs.is_empty() {
                    tracing::warn!(
                        "root hints file {path} contained no addresses; using compiled-in defaults"
                    );
                } else {
                    tracing::info!("loaded {} root hint addresses from {path}", addrs.len());
                    return addrs;
                }
            }
            Err(e) => {
                tracing::warn!(
                    "failed to read root hints file {path}: {e}; using compiled-in defaults"
                );
            }
        }
    } else {
        // 2. Probe well-known OS paths.
        for path in DEFAULT_ROOT_HINTS_PATHS {
            if let Ok(content) = std::fs::read_to_string(path) {
                let addrs = parse_root_hints(&content);
                if !addrs.is_empty() {
                    tracing::info!("loaded {} root hint addresses from {path}", addrs.len());
                    return addrs;
                }
            }
        }
    }

    // 3. Compiled-in fallback.
    tracing::info!("using compiled-in root hint addresses");
    builtin_root_hints()
}

/// Returns the compiled-in root-server addresses (IPv4 + IPv6).
fn builtin_root_hints() -> Vec<SocketAddr> {
    let mut addrs: Vec<SocketAddr> = ROOT_HINTS_V4
        .iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 53))
        .collect();
    addrs.extend(
        ROOT_HINTS_V6
            .iter()
            .map(|ip| SocketAddr::new(IpAddr::V6(*ip), 53)),
    );
    addrs
}

/// DNS resolver that performs iterative resolution starting from IANA root hints.
///
/// Resolves DNS queries without a configured upstream by following NS referrals
/// from the root servers down to the authoritative nameserver for the queried
/// name. Glue records in the ADDITIONAL section are used where available;
/// otherwise the NS hostname is resolved via a recursive sub-lookup that
/// consumes from the same hop budget.
#[derive(Debug, Clone)]
pub struct RecursiveResolver {
    max_hops: u8,
    ip_preference: IpPreference,
    root_hints: Vec<SocketAddr>,
}

impl RecursiveResolver {
    /// Creates a new `RecursiveResolver` with the given root hints, maximum
    /// hop count, and IP version preference.
    ///
    /// `root_hints` should be obtained via [`load_root_hints`].
    pub fn new(root_hints: Vec<SocketAddr>, max_hops: u8, ip_preference: IpPreference) -> Self {
        Self {
            max_hops,
            ip_preference,
            root_hints,
        }
    }

    /// Sends a single query to `addr` over UDP, falling back to TCP when the
    /// response has the truncation (TC) bit set.
    async fn query_nameserver(
        addr: SocketAddr,
        name: Name,
        qtype: RecordType,
    ) -> Result<Vec<u8>, UpstreamResolveError> {
        let provider = TokioRuntimeProvider::default();
        let conn = UdpClientStream::builder(addr, provider)
            .with_timeout(Some(UDP_TIMEOUT))
            .build();
        let (mut client, bg) = Client::connect(conn)
            .await
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;
        tokio::spawn(bg);

        let response =
            tokio::time::timeout(UDP_TIMEOUT, client.query(name.clone(), DNSClass::IN, qtype))
                .await
                .map_err(|_| UpstreamResolveError::Timeout)?
                .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

        let bytes = response
            .to_vec()
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

        // TCP fallback on truncation.
        let msg = Message::from_vec(&bytes)
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;
        if msg.truncated() {
            return Self::query_nameserver_tcp(addr, name, qtype).await;
        }

        Ok(bytes)
    }

    async fn query_nameserver_tcp(
        addr: SocketAddr,
        name: Name,
        qtype: RecordType,
    ) -> Result<Vec<u8>, UpstreamResolveError> {
        let provider = TokioRuntimeProvider::default();
        let (tcp_stream, sender) = TcpClientStream::new(addr, None, Some(TCP_TIMEOUT), provider);
        let mux = DnsMultiplexer::new(tcp_stream, sender, None);
        let (mut client, bg) = Client::connect(mux)
            .await
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;
        tokio::spawn(bg);

        let response = tokio::time::timeout(TCP_TIMEOUT, client.query(name, DNSClass::IN, qtype))
            .await
            .map_err(|_| UpstreamResolveError::Timeout)?
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

        response
            .to_vec()
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))
    }

    /// Queries up to [`CONCURRENT_NS_QUERIES`] nameservers concurrently,
    /// returning the first successful response.
    async fn try_nameservers(
        &self,
        nameservers: &[SocketAddr],
        name: &Name,
        qtype: RecordType,
    ) -> Result<Vec<u8>, UpstreamResolveError> {
        use futures::future::select_ok;

        let futs: Vec<_> = nameservers
            .iter()
            .take(CONCURRENT_NS_QUERIES)
            .map(|&addr| {
                let n = name.clone();
                Box::pin(Self::query_nameserver(addr, n, qtype))
            })
            .collect();

        if futs.is_empty() {
            return Err(UpstreamResolveError::AllFailed);
        }

        select_ok(futs)
            .await
            .map(|(bytes, _remaining)| bytes)
            .map_err(|_| UpstreamResolveError::AllFailed)
    }

    /// Iteratively resolves `name`/`qtype`, starting from the root hints.
    ///
    /// `depth` tracks the sub-lookup nesting level (used when no glue records
    /// are present) and is checked against `max_hops` to prevent unbounded
    /// recursion.
    fn resolve_iterative(
        &self,
        name: Name,
        qtype: RecordType,
        depth: u8,
    ) -> BoxFuture<'_, Result<Vec<u8>, UpstreamResolveError>> {
        Box::pin(async move {
            if depth > self.max_hops {
                return Err(UpstreamResolveError::Protocol(
                    "max recursion depth exceeded".into(),
                ));
            }

            let mut nameservers: Vec<SocketAddr> = self.root_hints.clone();

            for _ in 0..self.max_hops {
                let response_bytes = self.try_nameservers(&nameservers, &name, qtype).await?;
                let msg = Message::from_vec(&response_bytes)
                    .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

                // Authoritative answer (AA bit), NXDOMAIN, or non-empty answer section
                // all mean we have reached the end of the referral chain.
                if msg.header().authoritative()
                    || msg.response_code() == ResponseCode::NXDomain
                    || !msg.answers().is_empty()
                {
                    return Ok(response_bytes);
                }

                if msg.response_code() != ResponseCode::NoError {
                    return Err(UpstreamResolveError::Protocol(format!(
                        "unexpected rcode from nameserver: {}",
                        msg.response_code()
                    )));
                }

                // Collect NS names from the AUTHORITY section.
                let ns_names: Vec<Name> = msg
                    .name_servers()
                    .iter()
                    .filter_map(|r| {
                        if r.record_type() == RecordType::NS {
                            if let RData::NS(ns) = r.data() {
                                return Some(ns.0.clone());
                            }
                        }
                        None
                    })
                    .collect();

                if ns_names.is_empty() {
                    return Err(UpstreamResolveError::AllFailed);
                }

                // Prefer glue records from the ADDITIONAL section.
                // Sort addresses according to the configured IP preference so
                // that the preferred address family is tried first.
                let mut next_servers: Vec<SocketAddr> = msg
                    .additionals()
                    .iter()
                    .filter_map(|r| {
                        if !ns_names.contains(r.name()) {
                            return None;
                        }
                        match r.data() {
                            RData::A(a) => Some(SocketAddr::new(IpAddr::V4(a.0), 53)),
                            RData::AAAA(aaaa) => Some(SocketAddr::new(IpAddr::V6(aaaa.0), 53)),
                            _ => None,
                        }
                    })
                    .collect();
                match self.ip_preference {
                    IpPreference::PreferIpv4 => next_servers.sort_by_key(|a| a.is_ipv6()),
                    IpPreference::PreferIpv6 => next_servers.sort_by_key(|a| a.is_ipv4()),
                }

                if !next_servers.is_empty() {
                    nameservers = next_servers;
                    continue;
                }

                // No glue — resolve each NS name until we get at least one address.
                for ns_name in &ns_names {
                    if let Ok(ns_bytes) = self
                        .resolve_iterative(ns_name.clone(), RecordType::A, depth + 1)
                        .await
                    {
                        if let Ok(ns_msg) = Message::from_vec(&ns_bytes) {
                            let addrs: Vec<SocketAddr> = ns_msg
                                .answers()
                                .iter()
                                .filter_map(|r| {
                                    if let RData::A(a) = r.data() {
                                        Some(SocketAddr::new(IpAddr::V4(a.0), 53))
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            if !addrs.is_empty() {
                                next_servers.extend(addrs);
                                break;
                            }
                        }
                    }
                }

                if next_servers.is_empty() {
                    return Err(UpstreamResolveError::AllFailed);
                }

                nameservers = next_servers;
            }

            Err(UpstreamResolveError::Protocol("max hops exceeded".into()))
        })
    }
}

#[async_trait]
impl UpstreamResolver for RecursiveResolver {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
        let msg = Message::from_vec(&query)
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))?;

        let question = msg
            .queries()
            .first()
            .ok_or_else(|| UpstreamResolveError::Protocol("query contains no questions".into()))?;

        let name = question.name().clone();
        let qtype = question.query_type();

        self.resolve_iterative(name, qtype, 0).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_resolver_stores_max_hops() {
        let resolver = RecursiveResolver::new(builtin_root_hints(), 8, IpPreference::default());
        assert_eq!(resolver.max_hops, 8);
    }

    #[test]
    fn new_resolver_stores_ip_preference() {
        let resolver = RecursiveResolver::new(builtin_root_hints(), 12, IpPreference::PreferIpv6);
        assert_eq!(resolver.ip_preference, IpPreference::PreferIpv6);
    }

    #[test]
    fn default_ip_preference_is_ipv4() {
        assert_eq!(IpPreference::default(), IpPreference::PreferIpv4);
    }

    #[test]
    fn default_max_hops_is_within_expected_range() {
        assert!(
            DEFAULT_MAX_HOPS >= 8,
            "DEFAULT_MAX_HOPS should be at least 8"
        );
        assert!(
            DEFAULT_MAX_HOPS <= 20,
            "DEFAULT_MAX_HOPS should be at most 20"
        );
    }

    #[test]
    fn root_hints_v4_cover_all_thirteen_servers() {
        assert_eq!(ROOT_HINTS_V4.len(), 13, "should have all 13 root servers");
    }

    #[test]
    fn root_hints_v6_cover_all_thirteen_servers() {
        assert_eq!(ROOT_HINTS_V6.len(), 13, "should have all 13 root servers");
    }

    #[test]
    fn root_hints_are_not_loopback_or_unspecified() {
        for ip in ROOT_HINTS_V4 {
            assert!(!ip.is_loopback(), "{ip} should not be loopback");
            assert!(!ip.is_unspecified(), "{ip} should not be unspecified");
        }
        for ip in ROOT_HINTS_V6 {
            assert!(!ip.is_loopback(), "{ip} should not be loopback");
            assert!(!ip.is_unspecified(), "{ip} should not be unspecified");
        }
    }

    #[test]
    fn builtin_root_hints_contains_both_families() {
        let hints = builtin_root_hints();
        assert!(hints.iter().any(|a| a.is_ipv4()), "should contain IPv4");
        assert!(hints.iter().any(|a| a.is_ipv6()), "should contain IPv6");
        assert_eq!(hints.len(), 26, "13 IPv4 + 13 IPv6");
    }

    #[test]
    fn parse_root_hints_extracts_addresses() {
        let content = "\
;       This file holds the information on root name servers
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
";
        let addrs = parse_root_hints(content);
        assert_eq!(addrs.len(), 2);
        assert_eq!(
            addrs[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 53)
        );
        assert!(addrs[1].is_ipv6());
    }

    #[test]
    fn parse_root_hints_skips_comments_and_ns() {
        let content = "\
; comment line
.  3600000  NS  A.ROOT-SERVERS.NET.
";
        let addrs = parse_root_hints(content);
        assert!(addrs.is_empty());
    }

    #[test]
    fn parse_root_hints_handles_class_field() {
        let content = "A.ROOT-SERVERS.NET.  3600000  IN  A  198.41.0.4\n";
        let addrs = parse_root_hints(content);
        assert_eq!(addrs.len(), 1);
        assert_eq!(
            addrs[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 53)
        );
    }

    #[test]
    fn load_root_hints_returns_builtins_when_no_file() {
        let hints = load_root_hints(Some("/nonexistent/path/root.hints"));
        assert_eq!(hints.len(), 26, "should fall back to compiled-in hints");
    }

    #[test]
    fn resolve_iterative_returns_error_when_depth_exceeds_max_hops() {
        let resolver = RecursiveResolver::new(builtin_root_hints(), 0, IpPreference::default());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let name: Name = "example.com.".parse().unwrap();
        let result = rt.block_on(resolver.resolve_iterative(name, RecordType::A, 1));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, UpstreamResolveError::Protocol(ref msg) if msg.contains("max recursion depth exceeded")),
            "unexpected error: {err}"
        );
    }
}
