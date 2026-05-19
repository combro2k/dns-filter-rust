use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};

use crate::entities::resolution::UpstreamStrategy;
use crate::frameworks::config::schema::{
    DnsFilterConfig, ResolverZoneConfig, UpstreamServer, ZoneServerAuthenticationConfig,
    ZoneServerConfig,
};
use crate::frameworks::upstream::recursive_resolver::{
    load_root_hints, load_root_key, NameserverIpFamily, DEFAULT_MAX_HOPS,
};
use crate::frameworks::upstream::{
    DnsHttpsClient, DnsTlsClient, DnsUdpTcpClient, RecursiveResolver,
};
use crate::use_cases::filtering::{parse_interval, DomainFilter, ListFilterEngine};
use crate::use_cases::request_pipeline::{
    AnyQueryPolicy, DnsAnyQueryPolicyStage, DnsFilterStage, DnsRequestPipeline,
    DnsServfailFallbackStage, DnsUpstreamStage,
};
use crate::use_cases::upstream_resolver::{StrategyUpstreamResolver, UpstreamResolver};
use crate::use_cases::zone_authority::{ZoneAuthorityResolver, ZoneSourceAuth};
use crate::use_cases::zone_discovery::build_zone_discovery_entries;
use crate::use_cases::zone_forwarding::{ZoneEntry, ZoneForwardingStage};

use std::sync::atomic::AtomicBool;

pub fn validate_config(config: DnsFilterConfig) -> DnsFilterConfig {
    // Keep validation simple for the first migration step.
    config
}

pub fn build_upstream_resolver(config: &DnsFilterConfig) -> Result<Arc<dyn UpstreamResolver>> {
    build_upstream_resolver_group(
        &config.resolvers.strategy,
        &config.resolvers.bootstrap_resolvers,
        &config.resolvers.servers,
    )
}

pub fn build_zone_entries(config: &DnsFilterConfig) -> Result<Vec<ZoneEntry>> {
    let mut entries: Vec<ZoneEntry> = config
        .resolvers
        .zones
        .iter()
        .filter(|zone| zone.enabled)
        .map(|zone| build_zone_entry(zone, &config.resolvers.bootstrap_resolvers))
        .collect::<Result<Vec<_>>>()?;

    // Collect zone names from manual config (used to skip conflicts in discovery)
    let manual_zone_names: Vec<String> = config
        .resolvers
        .zones
        .iter()
        .filter(|zone| zone.enabled)
        .map(|zone| zone.zone.clone())
        .collect();

    // Process zone_discovery entries
    for discovery in &config.resolvers.zone_discovery {
        if !discovery.enabled {
            continue;
        }

        let check_interval = discovery
            .check_interval
            .as_deref()
            .map(|v| {
                parse_interval(v).map_err(|error| {
                    anyhow!(
                        "invalid check_interval for zone_discovery '{}': {} ({error})",
                        discovery.address,
                        v
                    )
                })
            })
            .transpose()?;

        match build_zone_discovery_entries(discovery, &manual_zone_names, check_interval) {
            Ok(discovered) => entries.extend(discovered),
            Err(error) => {
                tracing::warn!(
                    source = %discovery.address,
                    error = %error,
                    "zone_discovery: failed to load zones, skipping source"
                );
            }
        }
    }

    Ok(entries)
}

pub fn build_domain_filter(config: &DnsFilterConfig) -> Result<Arc<dyn DomainFilter>> {
    for list in config.blocklists.iter().chain(config.allowlists.iter()) {
        if let Some(interval) = &list.interval {
            parse_interval(interval).map_err(|error| {
                anyhow!(
                    "invalid interval for list '{}': {} ({error})",
                    list.name,
                    interval
                )
            })?;
        }
    }

    let engine = ListFilterEngine::from_config(config)?;
    Ok(Arc::new(engine))
}

pub fn build_any_query_policy(config: &DnsFilterConfig) -> Result<AnyQueryPolicy> {
    let Some(policy) = config
        .filtering
        .as_ref()
        .and_then(|filtering| filtering.any_query_policy.as_deref())
    else {
        return Ok(AnyQueryPolicy::NotImp);
    };

    match policy.trim().to_ascii_lowercase().as_str() {
        "passthrough" => Ok(AnyQueryPolicy::Passthrough),
        "refused" => Ok(AnyQueryPolicy::Refused),
        "notimp" | "not_imp" => Ok(AnyQueryPolicy::NotImp),
        other => bail!(
            "invalid filtering.any_query_policy: {other}; supported values are: passthrough, refused, notimp"
        ),
    }
}

pub fn build_dns_request_pipeline(
    resolver: Arc<dyn UpstreamResolver>,
    filter: Arc<dyn DomainFilter>,
    any_query_policy: AnyQueryPolicy,
) -> DnsRequestPipeline {
    build_dns_request_pipeline_with_zone_entries(resolver, filter, any_query_policy, Vec::new())
}

pub fn build_dns_request_pipeline_with_zone_entries(
    resolver: Arc<dyn UpstreamResolver>,
    filter: Arc<dyn DomainFilter>,
    any_query_policy: AnyQueryPolicy,
    zone_entries: Vec<ZoneEntry>,
) -> DnsRequestPipeline {
    build_dns_request_pipeline_full(resolver, filter, any_query_policy, zone_entries, None)
}

pub fn build_dns_request_pipeline_full(
    resolver: Arc<dyn UpstreamResolver>,
    filter: Arc<dyn DomainFilter>,
    any_query_policy: AnyQueryPolicy,
    zone_entries: Vec<ZoneEntry>,
    filtering_enabled: Option<Arc<AtomicBool>>,
) -> DnsRequestPipeline {
    let bypass_stage = ZoneForwardingStage::bypass_only(zone_entries.clone());
    let filtered_stage = ZoneForwardingStage::non_bypass(zone_entries);

    let filter_stage = DnsFilterStage::new(filter);
    let filter_stage = match filtering_enabled {
        Some(flag) => filter_stage.with_filtering_enabled(flag),
        None => filter_stage,
    };

    DnsRequestPipeline::default()
        .add_stage(bypass_stage)
        .add_stage(filter_stage)
        .add_stage(DnsAnyQueryPolicyStage::new(any_query_policy))
        .add_stage(filtered_stage)
        .add_stage(DnsUpstreamStage::new(resolver))
        .add_stage(DnsServfailFallbackStage)
}

fn build_zone_entry(
    zone: &ResolverZoneConfig,
    bootstrap_resolvers: &[String],
) -> Result<ZoneEntry> {
    let enabled_servers: Vec<&ZoneServerConfig> =
        zone.servers.iter().filter(|s| s.enabled).collect();

    if enabled_servers.is_empty() {
        bail!(
            "zone '{}' has no enabled servers; add at least one enabled servers entry",
            zone.zone
        );
    }

    let json_servers: Vec<&ZoneServerConfig> = enabled_servers
        .iter()
        .copied()
        .filter(|s| s.protocol == "json")
        .collect();
    let upstream_servers: Vec<&ZoneServerConfig> = enabled_servers
        .iter()
        .copied()
        .filter(|s| s.protocol != "json")
        .collect();

    match (json_servers.is_empty(), upstream_servers.is_empty()) {
        // Only json entries — build authority resolver(s).
        (false, true) => {
            // Multiple json entries are supported; first one wins (primary authority).
            // For now we validate all and use the first enabled one.
            if json_servers.len() > 1 {
                bail!(
                    "zone '{}' has {} enabled json servers; only one json authority entry is supported per zone",
                    zone.zone,
                    json_servers.len()
                );
            }
            let resolver = build_zone_json_resolver(zone, json_servers[0])?;
            let resolver = Arc::new(resolver);
            let searchable: Arc<dyn crate::use_cases::zone_authority::ZoneSearchable> =
                Arc::clone(&resolver) as Arc<dyn crate::use_cases::zone_authority::ZoneSearchable>;
            ZoneEntry::new(
                zone.zone.clone(),
                zone.bypass_filter,
                zone.fallback_to_default_resolvers,
                resolver,
            )
            .map(|entry| entry.with_searchable(searchable))
        }
        // Only upstream entries — build forwarding resolver.
        (true, false) => {
            let strategy = zone.strategy.as_deref().unwrap_or("failover");
            let resolver = build_zone_upstream_resolver_group(
                strategy,
                bootstrap_resolvers,
                &upstream_servers,
            )
            .map_err(|error| anyhow!("invalid resolver zone '{}': {error}", zone.zone))?;
            ZoneEntry::new(
                zone.zone.clone(),
                zone.bypass_filter,
                zone.fallback_to_default_resolvers,
                resolver,
            )
        }
        // Mixed json + upstream — not yet supported.
        (false, false) => {
            bail!(
                "zone '{}' mixes 'json' and upstream server entries; mixed mode is not yet supported",
                zone.zone
            );
        }
        (true, true) => unreachable!("filtered non-empty list above"),
    }
}

fn build_zone_json_resolver(
    zone: &ResolverZoneConfig,
    server: &ZoneServerConfig,
) -> Result<ZoneAuthorityResolver> {
    let address = server.address.trim();
    if address.is_empty() {
        bail!(
            "zone '{}' json server has an empty address; expected file://, http://, or https:// URI",
            zone.zone
        );
    }

    let is_url = address.starts_with("http://") || address.starts_with("https://");

    if !is_url && server.check_interval.is_some() {
        bail!(
            "zone '{}' json server sets check_interval but address is not an HTTP(S) URL",
            zone.zone
        );
    }

    let auth = validate_server_auth(
        &zone.zone,
        &server.protocol,
        is_url,
        server.authentication.as_ref(),
    )?;

    let check_interval = match (is_url, server.check_interval.as_deref()) {
        (true, Some(value)) => Some(parse_interval(value).map_err(|error| {
            anyhow!(
                "invalid check_interval for zone '{}' json server: {} ({error})",
                zone.zone,
                value
            )
        })?),
        _ => None,
    };

    ZoneAuthorityResolver::from_source(&zone.zone, address, check_interval, auth)
        .map_err(|error| anyhow!("invalid resolver zone '{}': {error}", zone.zone))
}

fn validate_server_auth(
    zone: &str,
    protocol: &str,
    is_url: bool,
    auth_config: Option<&ZoneServerAuthenticationConfig>,
) -> Result<Option<ZoneSourceAuth>> {
    let config = match auth_config {
        Some(c) => c,
        None => return Ok(None),
    };

    let has_token = config
        .token
        .as_ref()
        .is_some_and(|value| !value.trim().is_empty());
    let has_username = config
        .username
        .as_ref()
        .is_some_and(|value| !value.trim().is_empty());
    let has_password = config
        .password
        .as_ref()
        .is_some_and(|value| !value.trim().is_empty());

    // If all fields are blank treat as no auth.
    if !has_token && !has_username && !has_password {
        return Ok(None);
    }

    // Only json and doh support authentication.
    if protocol != "json" && protocol != "doh" {
        bail!(
            "zone '{}' server with protocol '{}' sets authentication; authentication is only supported for 'json' and 'doh' servers",
            zone,
            protocol
        );
    }

    if has_token && (has_username || has_password) {
        bail!(
            "zone '{}' {} server authentication must use either 'token' (Bearer) or 'username'/'password' (Basic), not both",
            zone,
            protocol
        );
    }

    if has_username != has_password {
        bail!(
            "zone '{}' {} server authentication requires both 'username' and 'password' for Basic authentication",
            zone,
            protocol
        );
    }

    if !is_url {
        bail!(
            "zone '{}' {} server sets authentication but address is not an HTTP(S) URL",
            zone,
            protocol
        );
    }

    if has_token {
        Ok(Some(ZoneSourceAuth::Bearer(
            config.token.as_ref().unwrap().trim().to_string(),
        )))
    } else {
        Ok(Some(ZoneSourceAuth::Basic {
            username: config.username.as_ref().unwrap().trim().to_string(),
            password: config.password.as_ref().unwrap().trim().to_string(),
        }))
    }
}

fn build_zone_upstream_resolver_group(
    strategy: &str,
    bootstrap_resolvers: &[String],
    servers: &[&ZoneServerConfig],
) -> Result<Arc<dyn UpstreamResolver>> {
    let strategy = UpstreamStrategy::from_str(strategy)
        .map_err(|_| anyhow!("invalid upstream strategy: {strategy}"))?;

    if servers.is_empty() {
        bail!("at least one enabled upstream server is required");
    }

    let needs_bootstrap = servers
        .iter()
        .any(|s| s.protocol == "dot" || s.protocol == "doh");
    let bootstrap_addrs = if needs_bootstrap {
        parse_bootstrap_resolvers(bootstrap_resolvers)?
    } else {
        vec![]
    };

    let resolvers = servers
        .iter()
        .map(|server| build_single_zone_upstream_resolver(server, &bootstrap_addrs))
        .collect::<Result<Vec<_>>>()?;

    Ok(Arc::new(StrategyUpstreamResolver::new(resolvers, strategy)))
}

fn build_single_zone_upstream_resolver(
    server: &ZoneServerConfig,
    bootstrap_resolvers: &[SocketAddr],
) -> Result<Arc<dyn UpstreamResolver>> {
    match server.protocol.as_str() {
        "dns" => {
            let address = parse_dns_address(&server.address)?;
            Ok(Arc::new(DnsUdpTcpClient::new(address)))
        }
        "dot" => {
            let client = DnsTlsClient::parse_endpoint(&server.address)
                .map_err(|e| anyhow!("invalid DoT upstream '{}': {e}", server.address))?;
            Ok(Arc::new(
                client.with_bootstrap_resolvers(bootstrap_resolvers.to_vec()),
            ))
        }
        "doh" => {
            let auth = validate_server_auth(
                "zone",
                "doh",
                true,
                server.authentication.as_ref(),
            )?;
            let client =
                DnsHttpsClient::new(server.address.clone(), auth)
                    .map_err(|e| anyhow!("invalid DoH zone server '{}': {e}", server.address))?;
            Ok(Arc::new(
                client.with_bootstrap_resolvers(bootstrap_resolvers.to_vec()),
            ))
        }
        "recursive" => {
            let max_hops = server.max_hops.unwrap_or(DEFAULT_MAX_HOPS);
            let nameserver_ip_family = match server.nameserver_ip_family.as_deref() {
                Some("ipv4") => NameserverIpFamily::Ipv4Only,
                Some("ipv6") => NameserverIpFamily::Ipv6Only,
                _ => NameserverIpFamily::Both,
            };
            let dnssec = server.dnssec.unwrap_or(true);
            let root_hints = load_root_hints(server.root_hints_path.as_deref());
            let trust_anchor = if dnssec {
                load_root_key(server.root_key_path.as_deref())
            } else {
                None
            };
            Ok(Arc::new(RecursiveResolver::new(
                root_hints,
                max_hops,
                nameserver_ip_family,
                dnssec,
                trust_anchor,
            )))
        }
        other => bail!(
            "unsupported zone server protocol: '{other}'; supported values are: dns, dot, doh, recursive, json"
        ),
    }
}

fn build_upstream_resolver_group(
    strategy: &str,
    bootstrap_resolvers: &[String],
    servers: &[UpstreamServer],
) -> Result<Arc<dyn UpstreamResolver>> {
    let strategy = UpstreamStrategy::from_str(strategy)
        .map_err(|_| anyhow!("invalid upstream strategy: {strategy}"))?;

    let enabled_servers = servers
        .iter()
        .filter(|server| server.enabled)
        .collect::<Vec<_>>();

    if enabled_servers.is_empty() {
        bail!("at least one enabled upstream server is required");
    }

    let needs_bootstrap = enabled_servers
        .iter()
        .any(|s| s.protocol == "dot" || s.protocol == "doh");
    let bootstrap_resolvers = if needs_bootstrap {
        parse_bootstrap_resolvers(bootstrap_resolvers)?
    } else {
        vec![]
    };

    let resolvers = enabled_servers
        .into_iter()
        .map(|server| build_single_upstream_resolver(server, &bootstrap_resolvers))
        .collect::<Result<Vec<_>>>()?;

    Ok(Arc::new(StrategyUpstreamResolver::new(resolvers, strategy)))
}

fn build_single_upstream_resolver(
    server: &UpstreamServer,
    bootstrap_resolvers: &[SocketAddr],
) -> Result<Arc<dyn UpstreamResolver>> {
    match server.protocol.as_str() {
        "dns" => {
            let address = parse_dns_address(&server.address)?;
            Ok(Arc::new(DnsUdpTcpClient::new(address)))
        }
        "dot" => {
            let client = DnsTlsClient::parse_endpoint(&server.address)
                .map_err(|e| anyhow!("invalid DoT upstream '{}': {e}", server.address))?;
            Ok(Arc::new(
                client.with_bootstrap_resolvers(bootstrap_resolvers.to_vec()),
            ))
        }
        "doh" => {
            let auth =
                validate_server_auth("upstream", "doh", true, server.authentication.as_ref())?;
            let client = DnsHttpsClient::new(server.address.clone(), auth)
                .map_err(|e| anyhow!("invalid DoH upstream '{}': {e}", server.address))?;
            Ok(Arc::new(
                client.with_bootstrap_resolvers(bootstrap_resolvers.to_vec()),
            ))
        }
        "recursive" => {
            let max_hops = server.max_hops.unwrap_or(DEFAULT_MAX_HOPS);
            let nameserver_ip_family = match server.nameserver_ip_family.as_deref() {
                Some("ipv4") => NameserverIpFamily::Ipv4Only,
                Some("ipv6") => NameserverIpFamily::Ipv6Only,
                _ => NameserverIpFamily::Both,
            };
            let dnssec = server.dnssec.unwrap_or(true);
            let root_hints = load_root_hints(server.root_hints_path.as_deref());
            let trust_anchor = if dnssec {
                load_root_key(server.root_key_path.as_deref())
            } else {
                None
            };
            Ok(Arc::new(RecursiveResolver::new(
                root_hints,
                max_hops,
                nameserver_ip_family,
                dnssec,
                trust_anchor,
            )))
        }
        other => bail!(
            "unsupported upstream protocol: {other}; supported values are: dns, dot, doh, recursive"
        ),
    }
}

fn parse_dns_address(value: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .map_err(|e| anyhow!("invalid DNS upstream address '{value}': {e}"))
}

fn parse_bootstrap_resolvers(values: &[String]) -> Result<Vec<SocketAddr>> {
    if values.is_empty() {
        bail!("at least one bootstrap resolver is required");
    }

    values
        .iter()
        .map(|value| {
            if let Ok(addr) = value.parse::<SocketAddr>() {
                return Ok(addr);
            }

            if let Ok(ip) = value.parse::<IpAddr>() {
                return Ok(SocketAddr::new(ip, 53));
            }

            Err(anyhow!(
                "invalid bootstrap resolver address '{value}'; expected <ip> or <ip>:port"
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::frameworks::config::schema::{
        DnsFilterConfig, FilteringConfig, ListenConfig, LoggingConfig, NamedList,
        ResolverZoneConfig, ResolversConfig, SocketConfig, StdoutLogConfig, UpstreamServer,
        ZoneServerAuthenticationConfig, ZoneServerConfig,
    };

    use super::*;

    fn create_temp_zone_json(content: &str) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dns-filter-zone-source-{}-{id}.json",
            std::process::id()
        ));
        fs::write(&path, content).expect("failed to write zone source file");
        path.to_string_lossy().to_string()
    }

    fn base_config(servers: Vec<UpstreamServer>) -> DnsFilterConfig {
        DnsFilterConfig {
            listen: ListenConfig {
                dns: Some(SocketConfig {
                    enabled: true,
                    addresses: vec!["127.0.0.1".into()],
                    port: 5353,
                }),
                dot: None,
                doh: None,
                doq: None,
                http: None,
                metrics: None,
            },
            blocklists: Vec::<NamedList>::new(),
            allowlists: Vec::<NamedList>::new(),
            filtering: None,
            resolvers: ResolversConfig {
                strategy: "round_robin".into(),
                bootstrap_resolvers: vec!["1.1.1.1".into()],
                zones: Vec::new(),
                zone_discovery: Vec::new(),
                servers,
            },
            logging: LoggingConfig {
                syslog: None,
                file: None,
                stdout: Some(StdoutLogConfig {
                    enabled: true,
                    level: "info".into(),
                }),
            },
            security: None,
            api: None,
            control: None,
            plugins: Vec::new(),
            mcp: None,
        }
    }

    fn dns_zone_server(address: &str) -> ZoneServerConfig {
        ZoneServerConfig {
            enabled: true,
            protocol: "dns".into(),
            address: address.into(),
            ..Default::default()
        }
    }

    fn json_zone_server(address: &str) -> ZoneServerConfig {
        ZoneServerConfig {
            enabled: true,
            protocol: "json".into(),
            address: address.into(),
            ..Default::default()
        }
    }

    fn zone_config(zone: &str, servers: Vec<ZoneServerConfig>) -> ResolverZoneConfig {
        ResolverZoneConfig {
            zone: zone.into(),
            enabled: true,
            bypass_filter: false,
            fallback_to_default_resolvers: false,
            strategy: None,
            servers,
        }
    }

    // ── Global upstream resolver tests ────────────────────────────────────────

    #[test]
    fn build_upstream_resolver_accepts_dot_server() {
        let config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dot".into(),
            address: "tls://1.1.1.1".into(),
            ..Default::default()
        }]);

        let resolver = build_upstream_resolver(&config);
        assert!(resolver.is_ok());
    }

    #[test]
    fn build_upstream_resolver_rejects_unknown_protocol() {
        let config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "quic".into(),
            address: "quic://dns.example.com".into(),
            ..Default::default()
        }]);

        let result = build_upstream_resolver(&config);
        assert!(result.is_err());
        let error = result.err().expect("expected error");
        assert!(error.to_string().contains("unsupported upstream protocol"));
    }

    #[test]
    fn build_upstream_resolver_accepts_doh_server() {
        let config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "doh".into(),
            address: "https://dns.example.com/dns-query".into(),
            ..Default::default()
        }]);

        let result = build_upstream_resolver(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn build_upstream_resolver_accepts_doh_server_with_bearer_auth() {
        let config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "doh".into(),
            address: "https://dns.example.com/dns-query".into(),
            authentication: Some(ZoneServerAuthenticationConfig {
                token: Some("secret-token".into()),
                username: None,
                password: None,
            }),
            ..Default::default()
        }]);

        let result = build_upstream_resolver(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn build_upstream_resolver_rejects_doh_with_bad_url() {
        let config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "doh".into(),
            address: "http://not-https.example.com/dns-query".into(),
            ..Default::default()
        }]);

        let result = build_upstream_resolver(&config);
        assert!(result.is_err());
        let error = result.err().expect("expected error");
        assert!(error.to_string().contains("invalid DoH upstream"));
    }

    #[test]
    fn build_upstream_resolver_rejects_malformed_dot_address() {
        let config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dot".into(),
            address: "tls://dns_example.com".into(),
            ..Default::default()
        }]);

        let result = build_upstream_resolver(&config);
        assert!(result.is_err());
        let error = result.err().expect("expected error");
        assert!(error.to_string().contains("invalid DoT upstream"));
    }

    #[test]
    fn build_upstream_resolver_accepts_dot_hostname_server() {
        let config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dot".into(),
            address: "tls://dns.example.com:853".into(),
            ..Default::default()
        }]);

        let resolver = build_upstream_resolver(&config);
        assert!(resolver.is_ok());
    }

    #[test]
    fn build_upstream_resolver_rejects_empty_upstream_list() {
        let config = base_config(vec![]);

        let result = build_upstream_resolver(&config);
        assert!(result.is_err());
        let error = result.err().expect("expected error");
        assert!(error
            .to_string()
            .contains("at least one enabled upstream server is required"));
    }

    #[test]
    fn build_upstream_resolver_ignores_disabled_servers() {
        let config = base_config(vec![
            UpstreamServer {
                enabled: false,
                protocol: "doh".into(),
                address: "https://dns.example.com/dns-query".into(),
                ..Default::default()
            },
            UpstreamServer {
                enabled: true,
                protocol: "dns".into(),
                address: "8.8.8.8:53".into(),
                ..Default::default()
            },
        ]);

        let resolver = build_upstream_resolver(&config);
        assert!(resolver.is_ok());
    }

    #[test]
    fn build_upstream_resolver_rejects_all_disabled_servers() {
        let config = base_config(vec![UpstreamServer {
            enabled: false,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);

        let result = build_upstream_resolver(&config);
        assert!(result.is_err());
        let error = result.err().expect("expected error");
        assert!(error
            .to_string()
            .contains("at least one enabled upstream server is required"));
    }

    #[test]
    fn build_upstream_resolver_rejects_invalid_bootstrap_resolver() {
        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dot".into(),
            address: "tls://dns.example.com:853".into(),
            ..Default::default()
        }]);
        config.resolvers.bootstrap_resolvers = vec!["not-an-ip".into()];

        let result = build_upstream_resolver(&config);
        assert!(result.is_err());
        let error = result.err().expect("expected error");
        assert!(error
            .to_string()
            .contains("invalid bootstrap resolver address"));
    }

    #[test]
    fn build_domain_filter_accepts_missing_interval_and_uses_defaults() {
        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.blocklists = vec![NamedList {
            name: "ads".into(),
            url: "https://example.com/ads.txt".into(),
            interval: None,
            enabled: None,
        }];

        let filter = build_domain_filter(&config).expect("domain filter should build");
        assert_eq!(filter.sinkhole_ipv4().to_string(), "0.0.0.0");
        assert_eq!(filter.sinkhole_ipv6().to_string(), "::");
    }

    #[test]
    fn build_domain_filter_rejects_invalid_list_interval() {
        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.blocklists = vec![NamedList {
            name: "ads".into(),
            url: "https://example.com/ads.txt".into(),
            interval: Some("99w".into()),
            enabled: None,
        }];

        let result = build_domain_filter(&config);
        assert!(result.is_err());
        let error = result.err().expect("expected error");
        assert!(error
            .to_string()
            .contains("invalid interval for list 'ads'"));
    }

    #[test]
    fn build_domain_filter_uses_configured_sinkhole_addresses() {
        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.filtering = Some(FilteringConfig {
            sinkhole_ipv4: Some("10.10.10.10".into()),
            sinkhole_ipv6: Some("fd00::1".into()),
            any_query_policy: None,
            cache: None,
        });

        let filter = build_domain_filter(&config).expect("domain filter should build");
        assert_eq!(filter.sinkhole_ipv4().to_string(), "10.10.10.10");
        assert_eq!(filter.sinkhole_ipv6().to_string(), "fd00::1");
    }

    #[test]
    fn build_any_query_policy_defaults_to_notimp() {
        let config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);

        let policy = build_any_query_policy(&config).expect("policy should parse");
        assert_eq!(policy, AnyQueryPolicy::NotImp);
    }

    #[test]
    fn build_any_query_policy_accepts_refused_and_notimp() {
        let mut refused_config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        refused_config.filtering = Some(FilteringConfig {
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
            any_query_policy: Some("refused".into()),
            cache: None,
        });

        let refused = build_any_query_policy(&refused_config).expect("policy should parse");
        assert_eq!(refused, AnyQueryPolicy::Refused);

        let mut notimp_config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        notimp_config.filtering = Some(FilteringConfig {
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
            any_query_policy: Some("notimp".into()),
            cache: None,
        });

        let notimp = build_any_query_policy(&notimp_config).expect("policy should parse");
        assert_eq!(notimp, AnyQueryPolicy::NotImp);
    }

    #[test]
    fn build_any_query_policy_rejects_invalid_value() {
        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.filtering = Some(FilteringConfig {
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
            any_query_policy: Some("bad-value".into()),
            cache: None,
        });

        let result = build_any_query_policy(&config);
        assert!(result.is_err());
    }

    // ── Zone entry builder tests ───────────────────────────────────────────────

    #[test]
    fn build_zone_entries_defaults_zone_strategy_to_failover() {
        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.resolvers.zones = vec![ResolverZoneConfig {
            zone: "home.arpa".into(),
            enabled: true,
            bypass_filter: true,
            fallback_to_default_resolvers: false,
            strategy: None,
            servers: vec![dns_zone_server("192.168.1.1:53")],
        }];

        let zones = build_zone_entries(&config).expect("zone entries should build");
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].zone(), "home.arpa");
        assert!(zones[0].bypass_filter());
        assert!(!zones[0].fallback_to_default_resolvers());
    }

    #[test]
    fn build_zone_entries_skips_disabled_zones() {
        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.resolvers.zones = vec![ResolverZoneConfig {
            zone: "home.arpa".into(),
            enabled: false,
            bypass_filter: true,
            fallback_to_default_resolvers: false,
            strategy: Some("failover".into()),
            servers: vec![dns_zone_server("192.168.1.1:53")],
        }];

        let zones = build_zone_entries(&config).expect("zone entries should build");
        assert!(zones.is_empty());
    }

    #[test]
    fn build_zone_entries_rejects_empty_servers() {
        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.resolvers.zones = vec![zone_config("home.arpa", vec![])];

        let result = build_zone_entries(&config);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("no enabled servers"));
    }

    #[test]
    fn build_zone_entries_rejects_all_disabled_zone_servers() {
        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.resolvers.zones = vec![zone_config(
            "home.arpa",
            vec![ZoneServerConfig {
                enabled: false,
                protocol: "dns".into(),
                address: "192.168.1.1:53".into(),
                ..Default::default()
            }],
        )];

        let result = build_zone_entries(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no enabled servers"));
    }

    #[test]
    fn build_zone_entries_accepts_dns_forwarding() {
        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.resolvers.zones = vec![zone_config(
            "home.arpa",
            vec![dns_zone_server("192.168.1.1:53")],
        )];

        let zones = build_zone_entries(&config).expect("zone entries should build");
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].zone(), "home.arpa");
    }

    #[test]
    fn build_zone_entries_accepts_json_file_source() {
        let zone_file = create_temp_zone_json(
            r#"{
                "zone":"home.arpa",
                "ttl_default":300,
                "records":[
                    {"name":"@","type":"A","ttl":300,"data":{"address":"192.168.1.50"}}
                ]
            }"#,
        );

        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.resolvers.zones = vec![zone_config(
            "home.arpa",
            vec![json_zone_server(&format!("file://{zone_file}"))],
        )];

        let zones = build_zone_entries(&config).expect("zone entries should build");
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].zone(), "home.arpa");

        let _ = fs::remove_file(zone_file);
    }

    #[test]
    fn build_zone_entries_accepts_json_plain_path() {
        let zone_file =
            create_temp_zone_json(r#"{"zone":"home.arpa","ttl_default":300,"records":[]}"#);

        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.resolvers.zones = vec![zone_config("home.arpa", vec![json_zone_server(&zone_file)])];

        let zones = build_zone_entries(&config).expect("zone entries should build");
        assert_eq!(zones.len(), 1);

        let _ = fs::remove_file(zone_file);
    }

    #[test]
    fn build_zone_entries_rejects_json_check_interval_on_file() {
        let zone_file =
            create_temp_zone_json(r#"{"zone":"home.arpa","ttl_default":300,"records":[]}"#);

        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.resolvers.zones = vec![zone_config(
            "home.arpa",
            vec![ZoneServerConfig {
                enabled: true,
                protocol: "json".into(),
                address: format!("file://{zone_file}"),
                check_interval: Some("15m".into()),
                ..Default::default()
            }],
        )];

        let result = build_zone_entries(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("check_interval"));

        let _ = fs::remove_file(zone_file);
    }

    #[test]
    fn build_zone_entries_rejects_multiple_json_servers() {
        let zone_file1 =
            create_temp_zone_json(r#"{"zone":"home.arpa","ttl_default":300,"records":[]}"#);
        let zone_file2 =
            create_temp_zone_json(r#"{"zone":"home.arpa","ttl_default":300,"records":[]}"#);

        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.resolvers.zones = vec![zone_config(
            "home.arpa",
            vec![
                json_zone_server(&format!("file://{zone_file1}")),
                json_zone_server(&format!("file://{zone_file2}")),
            ],
        )];

        let result = build_zone_entries(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only one json authority entry"));

        let _ = fs::remove_file(&zone_file1);
        let _ = fs::remove_file(&zone_file2);
    }

    #[test]
    fn build_zone_entries_rejects_mixed_json_and_upstream() {
        let zone_file =
            create_temp_zone_json(r#"{"zone":"home.arpa","ttl_default":300,"records":[]}"#);

        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.resolvers.zones = vec![zone_config(
            "home.arpa",
            vec![
                json_zone_server(&format!("file://{zone_file}")),
                dns_zone_server("192.168.1.1:53"),
            ],
        )];

        let result = build_zone_entries(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("mixed mode is not yet supported"));

        let _ = fs::remove_file(zone_file);
    }

    #[test]
    fn build_zone_entries_rejects_unsupported_zone_protocol() {
        let mut config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dns".into(),
            address: "8.8.8.8:53".into(),
            ..Default::default()
        }]);
        config.resolvers.zones = vec![zone_config(
            "home.arpa",
            vec![ZoneServerConfig {
                enabled: true,
                protocol: "quic".into(),
                address: "192.168.1.1:853".into(),
                ..Default::default()
            }],
        )];

        let result = build_zone_entries(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported zone server protocol"));
    }

    // ── Authentication tests ───────────────────────────────────────────────────

    #[test]
    fn validate_server_auth_rejects_both_token_and_basic() {
        let result = validate_server_auth(
            "test.zone",
            "json",
            true,
            Some(&ZoneServerAuthenticationConfig {
                token: Some("my-token".into()),
                username: Some("user".into()),
                password: Some("pass".into()),
            }),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not both"));
    }

    #[test]
    fn validate_server_auth_rejects_username_without_password() {
        let result = validate_server_auth(
            "test.zone",
            "json",
            true,
            Some(&ZoneServerAuthenticationConfig {
                token: None,
                username: Some("user".into()),
                password: None,
            }),
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("both 'username' and 'password'"));
    }

    #[test]
    fn validate_server_auth_rejects_password_without_username() {
        let result = validate_server_auth(
            "test.zone",
            "json",
            true,
            Some(&ZoneServerAuthenticationConfig {
                token: None,
                username: None,
                password: Some("pass".into()),
            }),
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("both 'username' and 'password'"));
    }

    #[test]
    fn validate_server_auth_rejects_auth_on_file_source() {
        let result = validate_server_auth(
            "test.zone",
            "json",
            false,
            Some(&ZoneServerAuthenticationConfig {
                token: Some("my-token".into()),
                username: None,
                password: None,
            }),
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not an HTTP(S) URL"));
    }

    #[test]
    fn validate_server_auth_rejects_auth_on_non_http_protocol() {
        let result = validate_server_auth(
            "test.zone",
            "dns",
            false,
            Some(&ZoneServerAuthenticationConfig {
                token: Some("my-token".into()),
                username: None,
                password: None,
            }),
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only supported for 'json' and 'doh'"));
    }

    #[test]
    fn validate_server_auth_accepts_bearer_token_for_json() {
        let result = validate_server_auth(
            "test.zone",
            "json",
            true,
            Some(&ZoneServerAuthenticationConfig {
                token: Some("my-token".into()),
                username: None,
                password: None,
            }),
        );
        assert!(result.is_ok());
        let auth = result.unwrap();
        assert!(matches!(auth, Some(ZoneSourceAuth::Bearer(ref t)) if t == "my-token"));
    }

    #[test]
    fn validate_server_auth_accepts_bearer_token_for_doh() {
        let result = validate_server_auth(
            "test.zone",
            "doh",
            true,
            Some(&ZoneServerAuthenticationConfig {
                token: Some("doh-token".into()),
                username: None,
                password: None,
            }),
        );
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Some(ZoneSourceAuth::Bearer(_))));
    }

    #[test]
    fn validate_server_auth_accepts_basic_auth() {
        let result = validate_server_auth(
            "test.zone",
            "json",
            true,
            Some(&ZoneServerAuthenticationConfig {
                token: None,
                username: Some("user".into()),
                password: Some("pass".into()),
            }),
        );
        assert!(result.is_ok());
        let auth = result.unwrap();
        assert!(
            matches!(auth, Some(ZoneSourceAuth::Basic { ref username, ref password }) if username == "user" && password == "pass")
        );
    }

    #[test]
    fn validate_server_auth_accepts_no_auth() {
        let result = validate_server_auth("test.zone", "json", true, None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn validate_server_auth_treats_empty_fields_as_absent() {
        let result = validate_server_auth(
            "test.zone",
            "json",
            true,
            Some(&ZoneServerAuthenticationConfig {
                token: Some("  ".into()),
                username: Some("".into()),
                password: None,
            }),
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
