#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::de;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DnsFilterConfig {
    pub listen: ListenConfig,
    pub blocklists: Vec<NamedList>,
    pub allowlists: Vec<NamedList>,
    pub filtering: Option<FilteringConfig>,
    pub resolvers: ResolversConfig,
    pub logging: LoggingConfig,
    pub security: Option<SecurityConfig>,
}

#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    pub user: Option<String>,
    pub group: Option<String>,
    pub chroot_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub dns: Option<SocketConfig>,
    pub dot: Option<TlsSocketConfig>,
    pub doh: Option<TlsSocketConfig>,
    pub doq: Option<TlsSocketConfig>,
    pub http: Option<SocketConfig>,
    pub metrics: Option<MetricsConfig>,
}

#[derive(Debug, Deserialize)]
pub struct SocketConfig {
    pub enabled: bool,
    #[serde(
        alias = "address",
        deserialize_with = "deserialize_addresses",
        default = "default_public_addresses"
    )]
    pub addresses: Vec<String>,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct TlsSocketConfig {
    pub enabled: bool,
    #[serde(
        alias = "address",
        deserialize_with = "deserialize_addresses",
        default = "default_public_addresses"
    )]
    pub addresses: Vec<String>,
    pub port: u16,
    pub tls: TlsConfig,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub autogenerate: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    #[serde(
        alias = "address",
        deserialize_with = "deserialize_addresses",
        default = "default_loopback_addresses"
    )]
    pub addresses: Vec<String>,
    pub port: u16,
}

fn default_public_addresses() -> Vec<String> {
    vec!["0.0.0.0".to_string(), "::".to_string()]
}

fn default_loopback_addresses() -> Vec<String> {
    vec!["127.0.0.1".to_string(), "::1".to_string()]
}

/// Accepts either a single string `"0.0.0.0"` or a list `["0.0.0.0", "::"]`.
fn deserialize_addresses<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: de::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(s) => Ok(vec![s]),
        OneOrMany::Many(v) => Ok(v),
    }
}

#[derive(Debug)]
pub struct NamedList {
    pub name: String,
    pub url: String,
    pub interval: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct NamedListEntry {
    url: String,
    interval: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NamedListRepr {
    Explicit {
        name: String,
        url: String,
        interval: Option<String>,
        enabled: Option<bool>,
    },
    Nested(BTreeMap<String, NamedListEntry>),
}

impl<'de> Deserialize<'de> for NamedList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let repr = NamedListRepr::deserialize(deserializer)?;

        match repr {
            NamedListRepr::Explicit {
                name,
                url,
                interval,
                enabled,
            } => Ok(Self {
                name,
                url,
                interval,
                enabled,
            }),
            NamedListRepr::Nested(map) => {
                let mut iter = map.into_iter();
                match (iter.next(), iter.next()) {
                    (Some((name, entry)), None) => Ok(Self {
                        name,
                        url: entry.url,
                        interval: entry.interval,
                        enabled: entry.enabled,
                    }),
                    _ => Err(serde::de::Error::custom(
                        "named list map must contain exactly one item",
                    )),
                }
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct FilteringConfig {
    pub sinkhole_ipv4: Option<String>,
    pub sinkhole_ipv6: Option<String>,
    pub any_query_policy: Option<String>,
    pub cache: Option<FilteringCacheConfig>,
}

#[derive(Debug, Deserialize)]
pub struct FilteringCacheConfig {
    pub mode: Option<String>,
    pub document_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResolversConfig {
    pub strategy: String,
    #[serde(default = "default_bootstrap_resolvers")]
    pub bootstrap_resolvers: Vec<String>,
    pub servers: Vec<UpstreamServer>,
}

fn default_bootstrap_resolvers() -> Vec<String> {
    vec!["1.1.1.1".to_string()]
}

#[derive(Debug, Default, Deserialize)]
pub struct UpstreamServer {
    pub enabled: bool,
    pub protocol: String,
    #[serde(default)]
    pub address: String,
    pub max_hops: Option<u8>,
    /// IP family restriction for iterative resolution: `"ipv4"` (IPv4 only),
    /// `"ipv6"` (IPv6 only), or omit for both families (default).
    /// Uses `nameserver_filter` to block the non-selected family entirely.
    pub nameserver_ip_family: Option<String>,
    /// Path to a `root.hints` file for iterative resolution.  When omitted the
    /// resolver probes well-known OS paths and falls back to compiled-in IANA
    /// addresses.
    pub root_hints_path: Option<String>,
    /// Path to a DNSSEC `root.key` file containing root DNSKEY records.
    /// When omitted the resolver probes well-known OS paths
    /// (`/usr/share/dns/root.key`) and falls back to compiled-in IANA trust
    /// anchors.
    pub root_key_path: Option<String>,
    /// Enable DNSSEC validation for the recursive resolver.  Defaults to `true`.
    /// When enabled, the resolver validates the full chain of trust from the
    /// IANA root KSK.  Set to `false` to disable validation.
    pub dnssec: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub syslog: Option<SyslogConfig>,
    pub file: Option<FileLogConfig>,
    pub stdout: Option<StdoutLogConfig>,
}

#[derive(Debug, Deserialize)]
pub struct SyslogConfig {
    pub enabled: bool,
    pub facility: String,
    pub level: String,
    /// Syslog transport: "unix" (default), "udp", "tcp", or "tls".
    pub transport: Option<String>,
    /// Syslog server address.
    /// - For "unix": path (default: "/dev/log")
    /// - For "udp", "tcp", "tls": host:port (default: "127.0.0.1:514")
    pub server: Option<String>,
    /// Syslog message format: "rfc3164" (default) or "rfc5424".
    pub format: Option<String>,
    /// TLS configuration (only for transport="tls").
    pub tls: Option<SyslogTlsConfig>,
}

#[derive(Debug, Deserialize)]
pub struct SyslogTlsConfig {
    /// Path to CA certificate file for TLS verification.
    pub ca_cert_path: Option<String>,
    /// Whether to verify the hostname (default: true).
    pub verify_hostname: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct FileLogConfig {
    pub enabled: bool,
    pub location: String,
    pub level: String,
}

#[derive(Debug, Deserialize)]
pub struct StdoutLogConfig {
    pub enabled: bool,
    pub level: String,
}
