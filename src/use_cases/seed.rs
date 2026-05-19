//! YAML-to-database seed logic.
//!
//! On first start (empty DB), operational config from the YAML file is
//! imported into the database so the DB becomes the authoritative source.

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::frameworks::config::schema::DnsFilterConfig;
use crate::use_cases::config_from_db::Repositories;
use crate::use_cases::repository_types::{
    FilterListRecord, FilteringConfigRecord, ResolverConfigRecord, UpstreamServerRecord,
    ZoneDiscoveryRecord, ZoneRecord, ZoneServerRecord,
};

const DEFAULT_INTERVAL_SECS: i64 = 12 * 60 * 60;

/// Seeds the database from the YAML config if the DB is empty.
///
/// Returns `true` if seeding was performed, `false` if the DB already
/// contained data.
pub async fn seed_if_empty(config: &DnsFilterConfig, repos: &Repositories) -> Result<bool> {
    let count = repos
        .filter_lists
        .count()
        .await
        .context("checking if DB is seeded")?;

    // Use filter_lists count as proxy — if any rows exist, assume DB is seeded.
    // Also check upstream servers count to handle configs with no filter lists.
    let upstream_count = repos
        .upstream_config
        .get_all_servers()
        .await
        .map(|s| s.len() as i64)
        .unwrap_or(0);

    if count > 0 || upstream_count > 0 {
        tracing::debug!("database already seeded, skipping YAML import");
        return Ok(false);
    }

    tracing::info!("database is empty, seeding from YAML config");

    seed_filter_lists(config, repos).await?;
    seed_filtering_config(config, repos).await?;
    seed_resolver_config(config, repos).await?;
    seed_upstream_servers(config, repos).await?;
    seed_zones(config, repos).await?;
    seed_zone_discovery(config, repos).await?;

    tracing::info!("database seeded successfully from YAML config");
    Ok(true)
}

async fn seed_filter_lists(config: &DnsFilterConfig, repos: &Repositories) -> Result<()> {
    for list in &config.blocklists {
        let interval = parse_interval_secs(list.interval.as_deref());
        repos
            .filter_lists
            .create(&FilterListRecord {
                id: Uuid::new_v4().to_string(),
                name: list.name.clone(),
                kind: "block".to_string(),
                url: list.url.clone(),
                interval_seconds: interval,
                enabled: list.enabled.unwrap_or(true),
                list_type: list
                    .list_type
                    .clone()
                    .unwrap_or_else(|| "adguard".to_string()),
            })
            .await
            .with_context(|| format!("seeding blocklist '{}'", list.name))?;
    }

    for list in &config.allowlists {
        let interval = parse_interval_secs(list.interval.as_deref());
        repos
            .filter_lists
            .create(&FilterListRecord {
                id: Uuid::new_v4().to_string(),
                name: list.name.clone(),
                kind: "allow".to_string(),
                url: list.url.clone(),
                interval_seconds: interval,
                enabled: list.enabled.unwrap_or(true),
                list_type: list
                    .list_type
                    .clone()
                    .unwrap_or_else(|| "adguard".to_string()),
            })
            .await
            .with_context(|| format!("seeding allowlist '{}'", list.name))?;
    }

    Ok(())
}

async fn seed_filtering_config(config: &DnsFilterConfig, repos: &Repositories) -> Result<()> {
    let filtering = config.filtering.as_ref();
    repos
        .filtering_config
        .update(&FilteringConfigRecord {
            sinkhole_ipv4: filtering
                .and_then(|f| f.sinkhole_ipv4.clone())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            sinkhole_ipv6: filtering
                .and_then(|f| f.sinkhole_ipv6.clone())
                .unwrap_or_else(|| "::".to_string()),
            any_query_policy: filtering
                .and_then(|f| f.any_query_policy.clone())
                .unwrap_or_else(|| "notimp".to_string()),
        })
        .await
        .context("seeding filtering config")?;

    Ok(())
}

async fn seed_resolver_config(config: &DnsFilterConfig, repos: &Repositories) -> Result<()> {
    repos
        .upstream_config
        .update_resolver_config(&ResolverConfigRecord {
            strategy: config.resolvers.strategy.clone(),
            bootstrap_resolvers: config.resolvers.bootstrap_resolvers.clone(),
        })
        .await
        .context("seeding resolver config")?;

    Ok(())
}

async fn seed_upstream_servers(config: &DnsFilterConfig, repos: &Repositories) -> Result<()> {
    for (i, server) in config.resolvers.servers.iter().enumerate() {
        let auth = server.authentication.as_ref();
        repos
            .upstream_config
            .create_server(&UpstreamServerRecord {
                id: Uuid::new_v4().to_string(),
                enabled: server.enabled,
                protocol: server.protocol.clone(),
                address: server.address.clone(),
                auth_token: auth.and_then(|a| a.token.clone()),
                auth_username: auth.and_then(|a| a.username.clone()),
                auth_password: auth.and_then(|a| a.password.clone()),
                max_hops: server.max_hops.map(|v| v as i32),
                nameserver_ip_family: server.nameserver_ip_family.clone(),
                root_hints_path: server.root_hints_path.clone(),
                root_key_path: server.root_key_path.clone(),
                dnssec: server.dnssec.unwrap_or(true),
                sort_order: i as i32,
                bind_address: server.bind_address.clone(),
                fwmark: server.fwmark.map(|v| v as i32),
            })
            .await
            .with_context(|| format!("seeding upstream server #{}", i))?;
    }

    Ok(())
}

async fn seed_zones(config: &DnsFilterConfig, repos: &Repositories) -> Result<()> {
    for zone_config in &config.resolvers.zones {
        let zone_id = Uuid::new_v4().to_string();

        repos
            .zones
            .create_zone(&ZoneRecord {
                id: zone_id.clone(),
                zone: zone_config.zone.clone(),
                enabled: zone_config.enabled,
                bypass_filter: zone_config.bypass_filter,
                fallback_to_default_resolvers: zone_config.fallback_to_default_resolvers,
                strategy: zone_config.strategy.clone(),
                servers: Vec::new(),
            })
            .await
            .with_context(|| format!("seeding zone '{}'", zone_config.zone))?;

        for (i, server) in zone_config.servers.iter().enumerate() {
            let auth = server.authentication.as_ref();
            repos
                .zones
                .create_zone_server(&ZoneServerRecord {
                    id: Uuid::new_v4().to_string(),
                    zone_id: zone_id.clone(),
                    enabled: server.enabled,
                    protocol: server.protocol.clone(),
                    address: server.address.clone(),
                    auth_token: auth.and_then(|a| a.token.clone()),
                    auth_username: auth.and_then(|a| a.username.clone()),
                    auth_password: auth.and_then(|a| a.password.clone()),
                    check_interval: server.check_interval.clone(),
                    max_hops: server.max_hops.map(|v| v as i32),
                    nameserver_ip_family: server.nameserver_ip_family.clone(),
                    root_hints_path: server.root_hints_path.clone(),
                    root_key_path: server.root_key_path.clone(),
                    dnssec: server.dnssec.unwrap_or(true),
                    sort_order: i as i32,
                })
                .await
                .with_context(|| {
                    format!("seeding zone server #{} for zone '{}'", i, zone_config.zone)
                })?;
        }
    }

    Ok(())
}

async fn seed_zone_discovery(config: &DnsFilterConfig, repos: &Repositories) -> Result<()> {
    for discovery in &config.resolvers.zone_discovery {
        let auth = discovery.authentication.as_ref();

        repos
            .zone_discovery
            .create(&ZoneDiscoveryRecord {
                id: Uuid::new_v4().to_string(),
                enabled: discovery.enabled,
                address: discovery.address.clone(),
                check_interval: discovery.check_interval.clone(),
                allowed_types: discovery.allowed_types.clone(),
                bypass_filter: discovery.bypass_filter,
                fallback_to_default_resolvers: discovery.fallback_to_default_resolvers,
                auth_token: auth.and_then(|a| a.token.clone()),
                auth_username: auth.and_then(|a| a.username.clone()),
                auth_password: auth.and_then(|a| a.password.clone()),
            })
            .await
            .context("seeding zone discovery entry")?;
    }

    Ok(())
}

/// Parses a human-readable interval string (e.g. "12h", "30m", "3600s") into
/// seconds.  Returns the default interval if the input is `None` or
/// unparseable.
fn parse_interval_secs(interval: Option<&str>) -> i64 {
    let Some(s) = interval else {
        return DEFAULT_INTERVAL_SECS;
    };
    let s = s.trim();
    if s.is_empty() {
        return DEFAULT_INTERVAL_SECS;
    }

    if let Some(hours) = s.strip_suffix('h') {
        if let Ok(h) = hours.parse::<i64>() {
            return h * 3600;
        }
    }
    if let Some(mins) = s.strip_suffix('m') {
        if let Ok(m) = mins.parse::<i64>() {
            return m * 60;
        }
    }
    if let Some(secs) = s.strip_suffix('s') {
        if let Ok(sec) = secs.parse::<i64>() {
            return sec;
        }
    }
    // Try bare number as seconds
    s.parse::<i64>().unwrap_or(DEFAULT_INTERVAL_SECS)
}
