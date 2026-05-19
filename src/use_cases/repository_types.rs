//! Framework-free record types for database repositories.
//!
//! These types map 1:1 to database rows and live in the use-case layer so that
//! the repository traits stay independent of any specific database framework.

/// A blocklist or allowlist entry stored in the database.
#[derive(Debug, Clone)]
pub struct FilterListRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub url: String,
    pub interval_seconds: i64,
    pub enabled: bool,
    pub list_type: String,
}

/// A cached, parsed filter list document.
#[derive(Debug, Clone)]
pub struct FilterCacheDocumentRecord {
    pub key: String,
    pub value: String,
}

/// Singleton filtering behaviour settings.
#[derive(Debug, Clone)]
pub struct FilteringConfigRecord {
    pub sinkhole_ipv4: String,
    pub sinkhole_ipv6: String,
    pub any_query_policy: String,
}

/// Singleton global resolver configuration.
#[derive(Debug, Clone)]
pub struct ResolverConfigRecord {
    pub strategy: String,
    /// JSON-encoded array of bootstrap resolver IP addresses.
    pub bootstrap_resolvers: String,
}

/// An upstream DNS server entry.
#[derive(Debug, Clone)]
pub struct UpstreamServerRecord {
    pub id: String,
    pub enabled: bool,
    pub protocol: String,
    pub address: String,
    pub auth_token: Option<String>,
    pub auth_username: Option<String>,
    pub auth_password: Option<String>,
    pub max_hops: Option<i32>,
    pub nameserver_ip_family: Option<String>,
    pub root_hints_path: Option<String>,
    pub root_key_path: Option<String>,
    pub dnssec: bool,
    pub sort_order: i32,
}

/// A DNS zone forwarding/authority entry.
#[derive(Debug, Clone)]
pub struct ZoneRecord {
    pub id: String,
    pub zone: String,
    pub enabled: bool,
    pub bypass_filter: bool,
    pub fallback_to_default_resolvers: bool,
    pub strategy: Option<String>,
    pub servers: Vec<ZoneServerRecord>,
}

/// A single server backing a zone.
#[derive(Debug, Clone)]
pub struct ZoneServerRecord {
    pub id: String,
    pub zone_id: String,
    pub enabled: bool,
    pub protocol: String,
    pub address: String,
    pub auth_token: Option<String>,
    pub auth_username: Option<String>,
    pub auth_password: Option<String>,
    pub check_interval: Option<String>,
    pub max_hops: Option<i32>,
    pub nameserver_ip_family: Option<String>,
    pub root_hints_path: Option<String>,
    pub root_key_path: Option<String>,
    pub dnssec: bool,
    pub sort_order: i32,
}

/// A zone-discovery endpoint entry.
#[derive(Debug, Clone)]
pub struct ZoneDiscoveryRecord {
    pub id: String,
    pub enabled: bool,
    pub address: String,
    pub check_interval: Option<String>,
    /// JSON-encoded array of allowed zone types.
    pub allowed_types: String,
    pub bypass_filter: bool,
    pub fallback_to_default_resolvers: bool,
    pub auth_token: Option<String>,
    pub auth_username: Option<String>,
    pub auth_password: Option<String>,
}
