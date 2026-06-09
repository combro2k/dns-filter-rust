#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::de;
use serde::Deserialize;

pub const DEFAULT_CONTROL_SOCKET_PATH: &str = "run/dns-filter.sock";

#[derive(Debug, Deserialize)]
pub struct DnsFilterConfig {
    pub listen: ListenConfig,
    #[serde(default)]
    pub blocklists: Vec<NamedList>,
    #[serde(default)]
    pub allowlists: Vec<NamedList>,
    pub filtering: Option<FilteringConfig>,
    pub resolvers: ResolversConfig,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    pub logging: LoggingConfig,
    pub security: Option<SecurityConfig>,
    pub api: Option<ApiConfig>,
    pub control: Option<ControlConfig>,
    pub mcp: Option<McpConfig>,
    pub database: Option<DatabaseConfig>,
    pub outbound: Option<OutboundConfig>,
}

/// Global defaults for outbound upstream DNS connections.
///
/// These values apply to all upstream servers unless overridden per-server.
/// Use `bind_address` to route traffic through a specific network interface
/// (e.g. WireGuard) and `fwmark` for Linux policy-based routing via `SO_MARK`.
#[derive(Debug, Clone, Deserialize)]
pub struct OutboundConfig {
    /// Source IP address to bind upstream sockets to (e.g. a WireGuard interface IP).
    pub bind_address: Option<String>,
    /// Linux `SO_MARK` value for policy routing. Requires `CAP_NET_ADMIN`.
    pub fwmark: Option<u32>,
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

pub const DEFAULT_DATABASE_URL: &str = "sqlite://db/dns-filter.db";

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_database_url")]
    pub url: String,
}

fn default_database_url() -> String {
    DEFAULT_DATABASE_URL.to_string()
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
    pub tls: Option<TlsConfig>,
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

#[derive(Debug, Clone, Deserialize)]
pub struct McpConfig {
    pub enabled: bool,
    #[serde(
        alias = "address",
        deserialize_with = "deserialize_addresses",
        default = "default_public_addresses"
    )]
    pub addresses: Vec<String>,
    #[serde(default = "default_mcp_port")]
    pub port: u16,
    pub api_token: Option<String>,
    pub sse_keep_alive: Option<u64>,
    #[serde(default = "default_mcp_stateful_mode")]
    pub stateful_mode: bool,
    #[serde(default)]
    pub json_response: bool,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
}

fn default_mcp_port() -> u16 {
    8953
}

fn default_mcp_stateful_mode() -> bool {
    true
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
    pub admin: Option<AdminConfig>,
    pub metrics: Option<MetricsConfig>,
}

#[derive(Debug)]
pub struct SocketConfig {
    pub enabled: bool,
    pub addresses: Vec<String>,
    pub port: u16,
}

#[derive(Debug)]
pub struct TlsSocketConfig {
    pub enabled: bool,
    pub addresses: Vec<String>,
    pub port: u16,
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub autogenerate: Option<bool>,
}

#[derive(Debug)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub addresses: Vec<String>,
    pub port: u16,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Deserialize)]
struct SocketConfigRaw {
    enabled: bool,
    #[serde(
        alias = "address",
        deserialize_with = "deserialize_addresses",
        default = "default_public_addresses"
    )]
    addresses: Vec<String>,
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct TlsSocketConfigRaw {
    enabled: bool,
    #[serde(
        alias = "address",
        deserialize_with = "deserialize_addresses",
        default = "default_public_addresses"
    )]
    addresses: Vec<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    tls: Option<TlsConfig>,
}

#[derive(Debug, Deserialize)]
struct MetricsConfigRaw {
    enabled: bool,
    #[serde(
        alias = "address",
        deserialize_with = "deserialize_addresses",
        default = "default_loopback_addresses"
    )]
    addresses: Vec<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    tls: Option<TlsConfig>,
}

impl<'de> Deserialize<'de> for SocketConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let raw = SocketConfigRaw::deserialize(deserializer)?;

        if raw.enabled {
            Ok(Self {
                enabled: true,
                addresses: raw.addresses,
                port: raw.port.ok_or_else(|| de::Error::missing_field("port"))?,
            })
        } else {
            Ok(Self {
                enabled: false,
                addresses: Vec::new(),
                port: 0,
            })
        }
    }
}

impl<'de> Deserialize<'de> for TlsSocketConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let raw = TlsSocketConfigRaw::deserialize(deserializer)?;

        if raw.enabled {
            Ok(Self {
                enabled: true,
                addresses: raw.addresses,
                port: raw.port.ok_or_else(|| de::Error::missing_field("port"))?,
                tls: raw.tls.ok_or_else(|| de::Error::missing_field("tls"))?,
            })
        } else {
            Ok(Self {
                enabled: false,
                addresses: Vec::new(),
                port: 0,
                tls: TlsConfig {
                    cert_path: String::new(),
                    key_path: String::new(),
                    autogenerate: None,
                },
            })
        }
    }
}

impl<'de> Deserialize<'de> for MetricsConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let raw = MetricsConfigRaw::deserialize(deserializer)?;

        if raw.enabled {
            Ok(Self {
                enabled: true,
                addresses: raw.addresses,
                port: raw.port.ok_or_else(|| de::Error::missing_field("port"))?,
                tls: raw.tls,
            })
        } else {
            Ok(Self {
                enabled: false,
                addresses: Vec::new(),
                port: 0,
                tls: None,
            })
        }
    }
}

/// Admin UI listener with dual-port support: HTTP (plain or redirect) + HTTPS.
///
/// When `tls` is configured, `tls_port` serves the admin UI over HTTPS and
/// `port` responds with 301 redirects to the HTTPS endpoint. When `tls` is
/// absent, `port` serves the admin UI over plain HTTP.
#[derive(Debug)]
pub struct AdminConfig {
    pub enabled: bool,
    pub addresses: Vec<String>,
    /// HTTP port. Serves the UI directly when TLS is absent, or redirects to
    /// `tls_port` when TLS is configured.
    pub port: u16,
    /// HTTPS port. Only active when `tls` is configured.
    pub tls_port: u16,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Deserialize)]
struct AdminConfigRaw {
    enabled: bool,
    #[serde(
        alias = "address",
        deserialize_with = "deserialize_addresses",
        default = "default_public_addresses"
    )]
    addresses: Vec<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default = "default_admin_tls_port")]
    tls_port: u16,
    #[serde(default)]
    tls: Option<TlsConfig>,
}

fn default_admin_port() -> u16 {
    80
}

fn default_admin_tls_port() -> u16 {
    8443
}

impl<'de> Deserialize<'de> for AdminConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let raw = AdminConfigRaw::deserialize(deserializer)?;

        if raw.enabled {
            Ok(Self {
                enabled: true,
                addresses: raw.addresses,
                port: raw.port.unwrap_or_else(default_admin_port),
                tls_port: raw.tls_port,
                tls: raw.tls,
            })
        } else {
            Ok(Self {
                enabled: false,
                addresses: Vec::new(),
                port: 0,
                tls_port: 0,
                tls: None,
            })
        }
    }
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
    pub list_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NamedListEntry {
    url: String,
    interval: Option<String>,
    enabled: Option<bool>,
    list_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NamedListRepr {
    Explicit {
        name: String,
        url: String,
        interval: Option<String>,
        enabled: Option<bool>,
        list_type: Option<String>,
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
                list_type,
            } => Ok(Self {
                name,
                url,
                interval,
                enabled,
                list_type,
            }),
            NamedListRepr::Nested(map) => {
                let mut iter = map.into_iter();
                match (iter.next(), iter.next()) {
                    (Some((name, entry)), None) => Ok(Self {
                        name,
                        url: entry.url,
                        interval: entry.interval,
                        enabled: entry.enabled,
                        list_type: entry.list_type,
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

#[derive(Debug, Clone, Deserialize)]
pub struct FilteringCacheConfig {
    pub mode: Option<String>,
    pub document_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResolversConfig {
    pub strategy: String,
    #[serde(default = "default_bootstrap_resolvers")]
    pub bootstrap_resolvers: Vec<String>,
    pub cache: Option<ResolverCacheConfig>,
    #[serde(default)]
    pub zones: Vec<ResolverZoneConfig>,
    #[serde(default)]
    pub zone_discovery: Vec<ZoneDiscoveryConfig>,
    pub servers: Vec<UpstreamServer>,
}

fn default_min_ttl() -> Option<String> {
    Some("60s".to_string())
}
fn default_max_ttl() -> Option<String> {
    Some("1h".to_string())
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResolverCacheConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_min_ttl")]
    pub min_ttl: Option<String>,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: Option<String>,
    pub max_entries: Option<usize>,
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
    vec!["194.242.2.2".to_string(), "2a07:e340::2".to_string()]
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
    /// Source IP address to bind upstream sockets to. Overrides `outbound.bind_address`.
    pub bind_address: Option<String>,
    /// Linux `SO_MARK` value for policy routing. Overrides `outbound.fwmark`.
    /// Requires `CAP_NET_ADMIN`.
    pub fwmark: Option<u32>,
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
