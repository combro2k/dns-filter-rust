use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};

use crate::entities::resolution::UpstreamStrategy;
use crate::frameworks::config::schema::{DnsFilterConfig, UpstreamServer};
use crate::frameworks::upstream::{DnsTlsClient, DnsUdpTcpClient};
use crate::use_cases::filtering::{parse_interval, DomainFilter, ListFilterEngine};
use crate::use_cases::request_pipeline::{
    DnsFilterStage, DnsRequestPipeline, DnsServfailFallbackStage, DnsUpstreamStage,
};
use crate::use_cases::upstream_resolver::{StrategyUpstreamResolver, UpstreamResolver};

pub fn validate_config(config: DnsFilterConfig) -> DnsFilterConfig {
    // Keep validation simple for the first migration step.
    config
}

pub fn build_upstream_resolver(config: &DnsFilterConfig) -> Result<Arc<dyn UpstreamResolver>> {
    let strategy = UpstreamStrategy::from_str(&config.upstreams.strategy)
        .map_err(|_| anyhow!("invalid upstream strategy: {}", config.upstreams.strategy))?;

    let enabled_servers = config
        .upstreams
        .servers
        .iter()
        .filter(|server| server.enabled)
        .collect::<Vec<_>>();

    if enabled_servers.is_empty() {
        bail!("at least one enabled upstream server is required");
    }

    let bootstrap_resolvers = parse_bootstrap_resolvers(&config.upstreams.bootstrap_resolvers)?;

    let resolvers = enabled_servers
        .into_iter()
        .map(|server| build_single_upstream_resolver(server, &bootstrap_resolvers))
        .collect::<Result<Vec<_>>>()?;

    Ok(Arc::new(StrategyUpstreamResolver::new(resolvers, strategy)))
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

pub fn build_dns_request_pipeline(
    resolver: Arc<dyn UpstreamResolver>,
    filter: Arc<dyn DomainFilter>,
) -> DnsRequestPipeline {
    DnsRequestPipeline::default()
        .add_stage(DnsFilterStage::new(filter))
        .add_stage(DnsUpstreamStage::new(resolver))
        .add_stage(DnsServfailFallbackStage)
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
        other => bail!("unsupported upstream protocol: {other}; supported values are: dns, dot"),
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
    use crate::frameworks::config::schema::{
        DnsFilterConfig, FilteringConfig, ListenConfig, LoggingConfig, NamedList, SocketConfig,
        StdoutLogConfig, UpstreamServer, UpstreamsConfig,
    };

    use super::*;

    fn base_config(servers: Vec<UpstreamServer>) -> DnsFilterConfig {
        DnsFilterConfig {
            listen: ListenConfig {
                dns: Some(SocketConfig {
                    enabled: true,
                    address: "127.0.0.1".into(),
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
            upstreams: UpstreamsConfig {
                strategy: "round_robin".into(),
                bootstrap_resolvers: vec!["1.1.1.1".into()],
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
        }
    }

    #[test]
    fn build_upstream_resolver_accepts_dot_server() {
        let config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dot".into(),
            address: "tls://1.1.1.1".into(),
        }]);

        let resolver = build_upstream_resolver(&config);
        assert!(resolver.is_ok());
    }

    #[test]
    fn build_upstream_resolver_rejects_unknown_protocol() {
        let config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "doh".into(),
            address: "https://dns.example.com/dns-query".into(),
        }]);

        let result = build_upstream_resolver(&config);
        assert!(result.is_err());
        let error = result.err().expect("expected error");
        assert!(error.to_string().contains("unsupported upstream protocol"));
    }

    #[test]
    fn build_upstream_resolver_rejects_malformed_dot_address() {
        let config = base_config(vec![UpstreamServer {
            enabled: true,
            protocol: "dot".into(),
            address: "tls://dns_example.com".into(),
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
            },
            UpstreamServer {
                enabled: true,
                protocol: "dns".into(),
                address: "8.8.8.8:53".into(),
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
        }]);
        config.upstreams.bootstrap_resolvers = vec!["not-an-ip".into()];

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
        }]);
        config.filtering = Some(FilteringConfig {
            sinkhole_ipv4: Some("10.10.10.10".into()),
            sinkhole_ipv6: Some("fd00::1".into()),
            cache: None,
        });

        let filter = build_domain_filter(&config).expect("domain filter should build");
        assert_eq!(filter.sinkhole_ipv4().to_string(), "10.10.10.10");
        assert_eq!(filter.sinkhole_ipv6().to_string(), "fd00::1");
    }
}
