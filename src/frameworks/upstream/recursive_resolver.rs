use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use hickory_client::proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_client::proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::dnssec::{Proof, TrustAnchors};
use hickory_proto::ProtoErrorKind;
use hickory_recursor::{DnssecPolicy, ErrorKind, NameServerConfigGroup, Recursor};
use ipnet::IpNet;

use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};

/// Maximum number of CNAME hops to follow before returning what we have.
/// Prevents infinite loops from circular CNAME chains.
const MAX_CNAME_HOPS: u8 = 10;

/// SOA + authority records extracted from a negative DNS response.
type NegativeRecords = (
    Option<Box<hickory_client::proto::rr::resource::Record<hickory_client::proto::rr::rdata::SOA>>>,
    Option<Arc<[hickory_client::proto::rr::resource::Record]>>,
);

/// Default maximum number of referral hops before the resolver gives up.
pub const DEFAULT_MAX_HOPS: u8 = 12;

/// Controls which address families the recursive resolver may query.
///
/// Applied via `hickory-recursor`'s `nameserver_filter` to block the
/// non-preferred family entirely during iterative resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NameserverIpFamily {
    /// Allow both IPv4 and IPv6 nameservers (default).
    #[default]
    Both,
    /// Only query IPv4 nameservers; all IPv6 addresses are denied.
    Ipv4Only,
    /// Only query IPv6 nameservers; all IPv4 addresses are denied.
    Ipv6Only,
}

/// Well-known paths where the OS may ship a `root.hints` file.
const DEFAULT_ROOT_HINTS_PATHS: &[&str] = &[
    "/usr/share/dns/root.hints",
    "/usr/share/dns-root-data/root.hints",
    "/var/named/root.hints",
];

/// Well-known paths where the OS may ship a `root.key` file containing
/// DNSKEY records for the DNS root zone.
const DEFAULT_ROOT_KEY_PATHS: &[&str] = &[
    "/usr/share/dns/root.key",
    "/usr/share/dns-root-data/root.key",
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

/// Loads DNSSEC root trust anchors from a `root.key` file.
///
/// Resolution order:
/// 1. Explicit `root_key_path` from config (warn and fall back on error).
/// 2. Well-known OS paths (`/usr/share/dns/root.key`, etc.).
/// 3. `None` – let hickory use its compiled-in IANA trust anchors.
pub fn load_root_key(root_key_path: Option<&str>) -> Option<Arc<TrustAnchors>> {
    // 1. Explicit path from config.
    if let Some(path) = root_key_path {
        match TrustAnchors::from_file(std::path::Path::new(path)) {
            Ok(anchors) if anchors.is_empty() => {
                tracing::warn!(
                    "root key file {path} contained no DNSKEY records; using compiled-in defaults"
                );
            }
            Ok(anchors) => {
                tracing::info!("loaded {} root trust anchors from {path}", anchors.len());
                return Some(Arc::new(anchors));
            }
            Err(e) => {
                tracing::warn!(
                    "failed to parse root key file {path}: {e}; using compiled-in defaults"
                );
            }
        }
    } else {
        // 2. Probe well-known OS paths.
        for path in DEFAULT_ROOT_KEY_PATHS {
            match TrustAnchors::from_file(std::path::Path::new(path)) {
                Ok(anchors) if !anchors.is_empty() => {
                    tracing::info!("loaded {} root trust anchors from {path}", anchors.len());
                    return Some(Arc::new(anchors));
                }
                _ => {}
            }
        }
    }

    // 3. Fall back to compiled-in defaults (None tells hickory to use its own).
    tracing::info!("using compiled-in root trust anchors");
    None
}

/// DNS resolver that performs iterative resolution starting from IANA root hints,
/// backed by `hickory-recursor` with optional DNSSEC chain-of-trust validation.
///
/// When DNSSEC is enabled (the default), the resolver validates the full
/// chain of trust from the IANA root KSK down to the queried domain. Queries
/// for domains with broken or missing DNSSEC signatures will return SERVFAIL.
#[derive(Clone)]
pub struct RecursiveResolver {
    recursor: Arc<Recursor>,
}

impl std::fmt::Debug for RecursiveResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecursiveResolver").finish()
    }
}

impl RecursiveResolver {
    /// Creates a new `RecursiveResolver` with the given root hints, maximum
    /// hop count, and DNSSEC configuration.
    ///
    /// `root_hints` should be obtained via [`load_root_hints`].
    /// `trust_anchor` should be obtained via [`load_root_key`]; when `None`
    /// the resolver uses hickory's compiled-in IANA trust anchors.
    pub fn new(
        root_hints: Vec<SocketAddr>,
        max_hops: u8,
        nameserver_ip_family: NameserverIpFamily,
        dnssec: bool,
        trust_anchor: Option<Arc<TrustAnchors>>,
    ) -> Self {
        // Filter root hints to match the requested IP family.
        let filtered_ips: Vec<IpAddr> = root_hints
            .iter()
            .map(|s| s.ip())
            .filter(|ip| match nameserver_ip_family {
                NameserverIpFamily::Both => true,
                NameserverIpFamily::Ipv4Only => ip.is_ipv4(),
                NameserverIpFamily::Ipv6Only => ip.is_ipv6(),
            })
            .collect();
        let roots = NameServerConfigGroup::from_ips_clear(&filtered_ips, 53, true);

        let dnssec_policy = if dnssec {
            DnssecPolicy::ValidateWithStaticKey { trust_anchor }
        } else {
            DnssecPolicy::SecurityUnaware
        };

        // Build the deny list so the recursor never queries nameservers
        // of the blocked address family during referral hops.
        let deny_nets: Vec<IpNet> = match nameserver_ip_family {
            NameserverIpFamily::Both => vec![],
            NameserverIpFamily::Ipv4Only => vec!["::/0".parse().unwrap()],
            NameserverIpFamily::Ipv6Only => vec!["0.0.0.0/0".parse().unwrap()],
        };

        let mut builder = Recursor::builder()
            .dnssec_policy(dnssec_policy)
            .recursion_limit(Some(max_hops));

        if !deny_nets.is_empty() {
            let allow_nets: Vec<IpNet> = vec![];
            builder = builder.nameserver_filter(allow_nets.iter(), deny_nets.iter());
        }

        let recursor = builder
            .build(roots)
            .expect("failed to build recursive resolver");

        Self {
            recursor: Arc::new(recursor),
        }
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

        let name: Name = question.name().clone();
        let qtype: RecordType = question.query_type();
        let query_id = msg.id();

        // Check if the client set the DO (DNSSEC OK) bit
        let do_bit = msg
            .extensions()
            .as_ref()
            .map(|edns| edns.flags().dnssec_ok)
            .unwrap_or(false);

        let query = hickory_client::proto::op::Query::query(name, qtype);

        let lookup_result = self.recursor.resolve(query, Instant::now(), do_bit).await;

        // Build a DNS response message from the Lookup result
        let mut response = Message::new();
        response.set_id(query_id);
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_recursion_desired(true);
        response.set_recursion_available(true);

        // Copy the original question
        if let Some(q) = msg.queries().first() {
            response.add_query(q.clone());
        }

        // Echo EDNS OPT back when the client sent one
        if let Some(client_edns) = msg.extensions() {
            let mut edns = hickory_client::proto::op::Edns::new();
            edns.set_dnssec_ok(do_bit);
            edns.set_max_payload(client_edns.max_payload().max(512));
            edns.set_version(0);
            response.set_edns(edns);
        }

        match lookup_result {
            Ok(lookup) => {
                // Set AD only when validating and every answer record was DNSSEC-verified.
                // Unsigned delegations (e.g. google.com) carry Proof::Insecure and must NOT
                // get the AD flag, otherwise downstream validators like `delv` see a bogus
                // trust chain.
                let mut all_secure = self.recursor.is_validating()
                    && !lookup.records().is_empty()
                    && lookup.records().iter().all(|r| r.proof() == Proof::Secure);

                // Collect answer records and follow CNAME chain if needed.
                let mut answer_records: Vec<Record> = lookup.records().to_vec();

                // Follow CNAME chain: if all answers are CNAME records and the
                // original query type is not CNAME, resolve the CNAME target
                // with the original query type to get the final answer.
                if qtype != RecordType::CNAME {
                    let mut hops: u8 = 0;
                    while hops < MAX_CNAME_HOPS {
                        // Check if the current answers are CNAME-only (no record
                        // of the originally queried type).
                        let has_queried_type =
                            answer_records.iter().any(|r| r.record_type() == qtype);
                        if has_queried_type {
                            break;
                        }

                        // Find the last CNAME target to follow.
                        let cname_target = answer_records
                            .iter()
                            .rev()
                            .find(|r| r.record_type() == RecordType::CNAME)
                            .and_then(|r| match r.data() {
                                RData::CNAME(cname) => Some(cname.0.clone()),
                                _ => None,
                            });

                        let Some(target) = cname_target else {
                            break;
                        };

                        // Issue a follow-up query for the CNAME target.
                        let follow_query = hickory_client::proto::op::Query::query(target, qtype);
                        match self
                            .recursor
                            .resolve(follow_query, Instant::now(), do_bit)
                            .await
                        {
                            Ok(follow_lookup) => {
                                // Track AD across the chain.
                                if all_secure {
                                    all_secure = !follow_lookup.records().is_empty()
                                        && follow_lookup
                                            .records()
                                            .iter()
                                            .all(|r| r.proof() == Proof::Secure);
                                }
                                answer_records.extend(follow_lookup.records().iter().cloned());
                            }
                            Err(e) if e.is_nx_domain() || e.is_no_records_found() => {
                                // CNAME target doesn't resolve; return what we have.
                                break;
                            }
                            Err(_) => {
                                // Upstream error on follow-up; return partial chain.
                                break;
                            }
                        }
                        hops += 1;
                    }
                }

                if all_secure {
                    response.set_authentic_data(true);
                }

                for record in &answer_records {
                    response.add_answer(record.clone());
                }
            }
            Err(e) if e.is_nx_domain() || e.is_no_records_found() => {
                // Extract response code, SOA, and authority records (NSEC/NSEC3 +
                // RRSIG) from the error.  These proof records are essential for
                // DNSSEC validators like `delv` that need to verify insecure
                // delegations (e.g. google.com has no DS record).
                let is_nx = e.is_nx_domain();
                let (soa, authorities) = extract_negative_records(e);

                if is_nx {
                    response.set_response_code(ResponseCode::NXDomain);
                } else {
                    response.set_response_code(ResponseCode::NoError);
                }

                if let Some(soa) = soa {
                    response.add_name_server(soa.into_record_of_rdata());
                }
                if let Some(auths) = authorities {
                    for record in auths.iter() {
                        response.add_name_server(record.clone());
                    }
                }
            }
            Err(e) => {
                return Err(UpstreamResolveError::Protocol(format!("{e}")));
            }
        }

        response
            .to_vec()
            .map_err(|e| UpstreamResolveError::Protocol(format!("{e:?}")))
    }
}

/// Extract the SOA record and authority records (NSEC/NSEC3 + RRSIG) from
/// a hickory-recursor error.  The recursor wraps negative responses in
/// `ErrorKind::Proto(ProtoErrorKind::NoRecordsFound { .. })` or
/// `ErrorKind::Forward(ForwardData { .. })`.  We destructure both variants
/// so that the caller can include the full proof chain in the DNS response.
fn extract_negative_records(err: hickory_recursor::Error) -> NegativeRecords {
    match err.into_kind() {
        ErrorKind::Proto(proto) => match *proto.kind {
            ProtoErrorKind::NoRecordsFound {
                soa, authorities, ..
            } => (soa, authorities),
            _ => (None, None),
        },
        ErrorKind::Forward(fwd) => (Some(fwd.soa), fwd.authorities),
        ErrorKind::Resolve(resolve) => match resolve.kind() {
            hickory_recursor::resolver::ResolveErrorKind::Proto(proto) => match proto.kind() {
                ProtoErrorKind::NoRecordsFound {
                    soa, authorities, ..
                } => (soa.clone(), authorities.clone()),
                _ => (None, None),
            },
            _ => (None, None),
        },
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_nameserver_ip_family_is_both() {
        assert_eq!(NameserverIpFamily::default(), NameserverIpFamily::Both);
    }

    #[test]
    fn default_max_hops_is_within_expected_range() {
        let default_max_hops = std::hint::black_box(DEFAULT_MAX_HOPS);
        assert!(
            default_max_hops >= 8,
            "DEFAULT_MAX_HOPS should be at least 8"
        );
        assert!(
            default_max_hops <= 20,
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
    fn new_resolver_with_dnssec_enabled() {
        let resolver = RecursiveResolver::new(
            builtin_root_hints(),
            12,
            NameserverIpFamily::default(),
            true,
            None,
        );
        // Should construct without panic
        assert!(Arc::strong_count(&resolver.recursor) >= 1);
    }

    #[test]
    fn new_resolver_with_dnssec_disabled() {
        let resolver = RecursiveResolver::new(
            builtin_root_hints(),
            8,
            NameserverIpFamily::Ipv6Only,
            false,
            None,
        );
        assert!(Arc::strong_count(&resolver.recursor) >= 1);
    }

    #[test]
    fn resolver_is_clone() {
        let resolver = RecursiveResolver::new(
            builtin_root_hints(),
            12,
            NameserverIpFamily::default(),
            true,
            None,
        );
        let cloned = resolver.clone();
        // Both should share the same Arc
        assert_eq!(
            Arc::strong_count(&resolver.recursor),
            Arc::strong_count(&cloned.recursor)
        );
    }

    #[test]
    fn max_cname_hops_is_reasonable() {
        let max_cname_hops = std::hint::black_box(MAX_CNAME_HOPS);
        assert!(
            max_cname_hops >= 5,
            "MAX_CNAME_HOPS should be at least 5 to handle real-world chains"
        );
        assert!(
            max_cname_hops <= 20,
            "MAX_CNAME_HOPS should be at most 20 to prevent excessive recursion"
        );
    }

    /// Helper to build a CNAME record for testing.
    fn make_cname_record(owner: &str, target: &str) -> Record {
        let owner_name = Name::from_ascii(owner).unwrap();
        let target_name = Name::from_ascii(target).unwrap();
        Record::from_rdata(
            owner_name,
            300,
            RData::CNAME(hickory_client::proto::rr::rdata::CNAME(target_name)),
        )
    }

    /// Helper to build an A record for testing.
    fn make_a_record(owner: &str, ip: Ipv4Addr) -> Record {
        let owner_name = Name::from_ascii(owner).unwrap();
        Record::from_rdata(
            owner_name,
            300,
            RData::A(hickory_client::proto::rr::rdata::A(ip)),
        )
    }

    #[test]
    fn cname_target_extracted_from_records() {
        let records = [make_cname_record("www.example.com.", "alias.example.com.")];
        let target = records
            .iter()
            .rev()
            .find(|r| r.record_type() == RecordType::CNAME)
            .and_then(|r| match r.data() {
                RData::CNAME(cname) => Some(cname.0.clone()),
                _ => None,
            });
        assert_eq!(
            target.unwrap(),
            Name::from_ascii("alias.example.com.").unwrap()
        );
    }

    #[test]
    fn cname_chain_last_target_used() {
        let records = [
            make_cname_record("www.example.com.", "alias1.example.com."),
            make_cname_record("alias1.example.com.", "alias2.example.com."),
        ];
        // The logic picks the last CNAME record (rev iterator).
        let target = records
            .iter()
            .rev()
            .find(|r| r.record_type() == RecordType::CNAME)
            .and_then(|r| match r.data() {
                RData::CNAME(cname) => Some(cname.0.clone()),
                _ => None,
            });
        assert_eq!(
            target.unwrap(),
            Name::from_ascii("alias2.example.com.").unwrap()
        );
    }

    #[test]
    fn no_cname_following_when_queried_type_present() {
        let records = [
            make_cname_record("www.example.com.", "alias.example.com."),
            make_a_record("alias.example.com.", Ipv4Addr::new(93, 184, 216, 34)),
        ];
        // If the queried type (A) is already present, no following needed.
        let has_a = records.iter().any(|r| r.record_type() == RecordType::A);
        assert!(has_a, "should detect that A record is present");
    }

    #[test]
    fn no_cname_target_when_no_cname_records() {
        let records = [make_a_record(
            "example.com.",
            Ipv4Addr::new(93, 184, 216, 34),
        )];
        let target = records
            .iter()
            .rev()
            .find(|r| r.record_type() == RecordType::CNAME)
            .and_then(|r| match r.data() {
                RData::CNAME(cname) => Some(cname.0.clone()),
                _ => None,
            });
        assert!(target.is_none());
    }
}
