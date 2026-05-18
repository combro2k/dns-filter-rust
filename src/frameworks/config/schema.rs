#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::de;
use serde::Deserialize;

pub const DEFAULT_CONTROL_SOCKET_PATH: &str = "/run/dns-filter/dns-filter.sock";

#[derive(Debug, Deserialize)]
pub struct DnsFilterConfig {
    pub listen: ListenConfig,
    pub blocklists: Vec<NamedList>,
    pub allowlists: Vec<NamedList>,
    pub filtering: Option<FilteringConfig>,
    pub resolvers: ResolversConfig,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    pub logging: LoggingConfig,
    pub security: Option<SecurityConfig>,
    pub api: Option<ApiConfig>,
    pub control: Option<ControlConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    pub path: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

impl DnsFilterConfig {
    /// Returns the configured control socket path, or the default.
    pub fn socket_path(&self) -> &str {
        self.control
            .as_ref()
            .and_then(|c| c.socket_path.as_deref())
            .unwrap_or(DEFAULT_CONTROL_SOCKET_PATH)
    }
}

#[derive(Debug, Deserialize)]
pub struct ControlConfig {
    #[serde(default = "default_control_socket_path")]
    pub socket_path: Option<String>,
}

fn default_control_socket_path() -> Option<String> {
    Some(DEFAULT_CONTROL_SOCKET_PATH.to_string())
}

#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    pub enabled: bool,
    #[serde(default = "default_api_address")]
    pub address: String,
    #[serde(default = "default_api_port")]
    pub port: u16,
    pub api_token: Option<String>,
    #[serde(default)]
    pub query_logging: Option<QueryLoggingConfig>,
}

#[derive(Debug, Deserialize)]
pub struct QueryLoggingConfig {
    #[serde(default = "default_query_logging_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_log_entries")]
    pub max_entries: usize,
}

fn default_api_address() -> String {
    "0.0.0.0".to_string()
}

fn default_api_port() -> u16 {
    8000
}

fn default_query_logging_enabled() -> bool {
    false
}

fn default_max_log_entries() -> usize {
    10_000
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
    #[serde(default)]
    pub zones: Vec<ResolverZoneConfig>,
    #[serde(default)]
    pub zone_discovery: Vec<ZoneDiscoveryConfig>,
    pub servers: Vec<UpstreamServer>,
}

/// Configuration for automatic zone discovery from a JSON index endpoint.
///
/// The endpoint must return a JSON object with a `zones` array, where each
/// entry has `href`, `name`, and `type` fields.  Each discovered zone's `href`
/// is resolved relative to the index URL and fetched as a standard zone JSON
/// document.
#[derive(Debug, Deserialize)]
pub struct ZoneDiscoveryConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// URL of the zone index endpoint (must be `https://` or `http://`).
    pub address: String,
    /// How often to re-fetch the index and zone data (e.g. `"15m"`).
    pub check_interval: Option<String>,
    /// Only zones with a `type` field matching one of these values will be
    /// imported.  Supported values: `"reverse"`, `"forward"`, `"reverse-aggregate"`.
    #[serde(default)]
    pub allowed_types: Vec<String>,
    /// Whether discovered zones bypass the blocklist/allowlist filter stage.
    #[serde(default)]
    pub bypass_filter: bool,
    /// If the zone's resolver fails, fall back to the global upstream resolvers.
    #[serde(default)]
    pub fallback_to_default_resolvers: bool,
    /// Optional authentication for the index URL and all zone href fetches.
    pub authentication: Option<ZoneServerAuthenticationConfig>,
}

fn default_bootstrap_resolvers() -> Vec<String> {
    vec!["1.1.1.1".to_string()]
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct ResolverZoneConfig {
    pub zone: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub bypass_filter: bool,
    #[serde(default)]
    pub fallback_to_default_resolvers: bool,
    pub strategy: Option<String>,
    #[serde(default)]
    pub servers: Vec<ZoneServerConfig>,
}

/// Per-server authentication credentials for HTTP(S)-based zone server protocols.
/// Use either `token` (Bearer) OR `username`+`password` (Basic), not both.
#[derive(Debug, Deserialize)]
pub struct ZoneServerAuthenticationConfig {
    pub token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// A single zone server entry. The `protocol` field controls interpretation:
/// - `"dns"` — plain DNS over UDP/TCP; `address` is `<ip>:<port>`.
/// - `"dot"` — DNS-over-TLS; `address` is `tls://<host>[:<port>]` or `<ip>[:<port>]`.
/// - `"doh"` — DNS-over-HTTPS upstream; `address` is an `https://…` URL.
///   Supports `authentication` (Bearer or Basic).
/// - `"recursive"` — iterative resolver.
/// - `"json"` — authoritative JSON zone source; `address` is `file:///…`, `http://…`,
///   or `https://…`. Supports `check_interval` (URL sources only) and `authentication`.
#[derive(Debug, Default, Deserialize)]
pub struct ZoneServerConfig {
    pub enabled: bool,
    pub protocol: String,
    #[serde(default)]
    pub address: String,
    pub authentication: Option<ZoneServerAuthenticationConfig>,
    /// Refresh interval for `protocol: "json"` URL sources (e.g. `"15m"`).
    /// Rejected for `file://` sources.
    pub check_interval: Option<String>,
    pub max_hops: Option<u8>,
    /// IP family restriction for iterative resolution: `"ipv4"`, `"ipv6"`, or omit for both.
    pub nameserver_ip_family: Option<String>,
    /// Path to a `root.hints` file for iterative resolution.
    pub root_hints_path: Option<String>,
    /// Path to a DNSSEC `root.key` file for iterative resolution.
    pub root_key_path: Option<String>,
    /// Enable DNSSEC validation for the recursive resolver. Defaults to `true`.
    pub dnssec: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UpstreamServer {
    pub enabled: bool,
    pub protocol: String,
    #[serde(default)]
    pub address: String,
    /// HTTP authentication for `protocol: "doh"` upstream servers.
    /// Supports Bearer token (`token`) or Basic (`username` + `password`).
    pub authentication: Option<ZoneServerAuthenticationConfig>,
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
