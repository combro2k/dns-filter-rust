//! Bridge layer: loads operational config from database repositories and
//! overwrites the operational fields of a `DnsFilterConfig` that was loaded
//! from YAML.
//!
//! This keeps the existing `build_*` functions in `config_bootstrap` completely
//! unchanged – they still consume `&DnsFilterConfig`.  The YAML provides
//! infrastructure fields (listen, logging, etc.) and the DB provides
//! operational fields (filter lists, resolvers, zones, etc.).

use anyhow::{Context, Result};
use std::sync::Arc;

use crate::frameworks::config::schema::{
    DnsFilterConfig, FilteringConfig, NamedList, ResolverZoneConfig, ResolversConfig,
    UpstreamServer, ZoneDiscoveryConfig, ZoneServerAuthenticationConfig, ZoneServerConfig,
};
use crate::use_cases::repositories::{
    FilterCacheRepository, FilterListRepository, FilteringConfigRepository,
    UpstreamConfigRepository, ZoneDiscoveryRepository, ZoneRepository,
};

/// Container for all repository trait objects used to load operational config.
pub struct Repositories {
    pub filter_lists: Box<dyn FilterListRepository>,
    pub filter_cache: Arc<dyn FilterCacheRepository>,
    pub filtering_config: Box<dyn FilteringConfigRepository>,
    pub upstream_config: Box<dyn UpstreamConfigRepository>,
    pub zones: Box<dyn ZoneRepository>,
    pub zone_discovery: Box<dyn ZoneDiscoveryRepository>,
}

/// Loads all operational config from the database and overwrites the
/// corresponding fields in `config`.
///
/// Infrastructure fields (listen, logging, security, api, control, mcp,
/// plugins, database) are left untouched.
pub async fn apply_db_config(config: &mut DnsFilterConfig, repos: &Repositories) -> Result<()> {
    // -- Filter lists --
    let filter_list_records = repos
        .filter_lists
        .get_all()
        .await
        .context("loading filter lists from DB")?;

    let mut blocklists = Vec::new();
    let mut allowlists = Vec::new();
    for record in &filter_list_records {
        let named = NamedList {
            name: record.name.clone(),
            url: record.url.clone(),
            interval: Some(format!("{}s", record.interval_seconds)),
            enabled: Some(record.enabled),
            list_type: Some(record.list_type.clone()),
        };
        match record.kind.as_str() {
            "block" => blocklists.push(named),
            "allow" => allowlists.push(named),
            other => {
                tracing::warn!(kind = %other, name = %record.name, "unknown filter list kind, skipping")
            }
        }
    }
    config.blocklists = blocklists;
    config.allowlists = allowlists;

    // -- Filtering settings --
    let filtering_record = repos
        .filtering_config
        .get()
        .await
        .context("loading filtering config from DB")?;

    // Preserve the cache sub-section from YAML (controls whether document
    // caching is enabled), but replace the operational fields from DB.
    let cache = config.filtering.as_ref().and_then(|f| f.cache.clone());
    config.filtering = Some(FilteringConfig {
        sinkhole_ipv4: Some(filtering_record.sinkhole_ipv4),
        sinkhole_ipv6: Some(filtering_record.sinkhole_ipv6),
        any_query_policy: Some(filtering_record.any_query_policy),
        cache,
    });

    // -- Upstream resolver config --
    let resolver_record = repos
        .upstream_config
        .get_resolver_config()
        .await
        .context("loading resolver config from DB")?;

    let bootstrap_resolvers = resolver_record.bootstrap_resolvers;

    let upstream_servers = repos
        .upstream_config
        .get_all_servers()
        .await
        .context("loading upstream servers from DB")?;

    let servers: Vec<UpstreamServer> = upstream_servers
        .into_iter()
        .map(|s| UpstreamServer {
            enabled: s.enabled,
            protocol: s.protocol,
            address: s.address,
            authentication: build_auth(s.auth_token, s.auth_username, s.auth_password),
            max_hops: s.max_hops.map(|v| v as u8),
            nameserver_ip_family: s.nameserver_ip_family,
            root_hints_path: s.root_hints_path,
            root_key_path: s.root_key_path,
            dnssec: Some(s.dnssec),
        })
        .collect();

    // -- Zones --
    let zone_records = repos
        .zones
        .get_all_with_servers()
        .await
        .context("loading zones from DB")?;

    let zones: Vec<ResolverZoneConfig> = zone_records
        .into_iter()
        .map(|z| ResolverZoneConfig {
            zone: z.zone,
            enabled: z.enabled,
            bypass_filter: z.bypass_filter,
            fallback_to_default_resolvers: z.fallback_to_default_resolvers,
            strategy: z.strategy,
            servers: z
                .servers
                .into_iter()
                .map(|s| ZoneServerConfig {
                    enabled: s.enabled,
                    protocol: s.protocol,
                    address: s.address,
                    authentication: build_auth(s.auth_token, s.auth_username, s.auth_password),
                    check_interval: s.check_interval,
                    max_hops: s.max_hops.map(|v| v as u8),
                    nameserver_ip_family: s.nameserver_ip_family,
                    root_hints_path: s.root_hints_path,
                    root_key_path: s.root_key_path,
                    dnssec: Some(s.dnssec),
                })
                .collect(),
        })
        .collect();

    // -- Zone discovery --
    let discovery_records = repos
        .zone_discovery
        .get_all()
        .await
        .context("loading zone discovery from DB")?;

    let zone_discovery: Vec<ZoneDiscoveryConfig> = discovery_records
        .into_iter()
        .map(|d| ZoneDiscoveryConfig {
            enabled: d.enabled,
            address: d.address,
            check_interval: d.check_interval,
            allowed_types: d.allowed_types,
            bypass_filter: d.bypass_filter,
            fallback_to_default_resolvers: d.fallback_to_default_resolvers,
            authentication: build_auth(d.auth_token, d.auth_username, d.auth_password),
        })
        .collect();

    config.resolvers = ResolversConfig {
        strategy: resolver_record.strategy,
        bootstrap_resolvers,
        servers,
        zones,
        zone_discovery,
    };

    Ok(())
}

/// Builds an optional `ZoneServerAuthenticationConfig` from nullable DB fields.
fn build_auth(
    token: Option<String>,
    username: Option<String>,
    password: Option<String>,
) -> Option<ZoneServerAuthenticationConfig> {
    if token.is_some() || username.is_some() || password.is_some() {
        Some(ZoneServerAuthenticationConfig {
            token,
            username,
            password,
        })
    } else {
        None
    }
}
