//! Config reload orchestration for SIGHUP signals.
//!
//! This module handles loading and validating configuration for the reload flow,
//! reusing the same logic as the initial bootstrap but in a reloadable context.

use anyhow::Result;
use std::sync::Arc;

use crate::frameworks::config::loader::load_config;
use crate::use_cases::config_bootstrap::{
    build_any_query_policy, build_domain_filter, build_domain_filter_with_cache,
    build_upstream_resolver, build_zone_entries, validate_config,
};
use crate::use_cases::config_from_db::{apply_db_config, Repositories};
use crate::use_cases::filtering::DomainFilter;
use crate::use_cases::request_pipeline::AnyQueryPolicy;
use crate::use_cases::upstream_resolver::UpstreamResolver;
use crate::use_cases::zone_forwarding::ZoneEntry;

pub type ReloadedConfig = (
    Arc<dyn UpstreamResolver>,
    Arc<dyn DomainFilter>,
    AnyQueryPolicy,
    Vec<ZoneEntry>,
);

/// Reloads the configuration from disk and rebuilds the resolver and filter.
///
/// This function:
/// 1. Loads the configuration file from the given path
/// 2. Validates the configuration
/// 3. Builds a new upstream resolver
/// 4. Builds a new domain filter
///
/// On any error, the old state is retained (the caller is responsible for
/// swapping on success and keeping the old state on error).
///
/// # Returns
/// A tuple of `(Arc<dyn UpstreamResolver>, Arc<dyn DomainFilter>, AnyQueryPolicy, Vec<ZoneEntry>)` if all steps succeed,
/// or an error if any step fails.
pub fn reload_config(config_path: &str) -> Result<ReloadedConfig> {
    tracing::info!(path = %config_path, "reloading configuration");

    let config = load_config(config_path)?;
    let config = validate_config(config);

    let resolver = build_upstream_resolver(&config)?;
    let filter = build_domain_filter(&config)?;
    let any_query_policy = build_any_query_policy(&config)?;
    let zone_entries = build_zone_entries(&config)?;

    tracing::info!("configuration reloaded successfully");

    Ok((resolver, filter, any_query_policy, zone_entries))
}

/// Reloads configuration using the database as the source of truth for
/// operational config, with infrastructure config loaded from the YAML file.
///
/// This is the database-aware counterpart of [`reload_config`].  The YAML file
/// is still loaded for infrastructure fields (listen, logging, etc.), but
/// operational fields (filter lists, resolvers, zones) come from the database.
pub async fn reload_config_from_db(
    config_path: &str,
    repos: &Repositories,
) -> Result<ReloadedConfig> {
    tracing::info!(path = %config_path, "reloading configuration (DB-backed)");

    let config = load_config(config_path)?;
    let mut config = validate_config(config);
    apply_db_config(&mut config, repos).await?;

    let resolver = build_upstream_resolver(&config)?;
    let filter = build_domain_filter_with_cache(&config, Some(Arc::clone(&repos.filter_cache)))?;
    let any_query_policy = build_any_query_policy(&config)?;

    // `build_zone_entries` may use `reqwest::blocking` internally (zone
    // discovery fetches). Running it on a blocking thread avoids the Tokio
    // panic that occurs when a blocking runtime is dropped inside an async
    // context.
    let zone_entries = tokio::task::spawn_blocking(move || build_zone_entries(&config))
        .await
        .map_err(|e| anyhow::anyhow!("zone entry build task panicked: {e}"))??;

    tracing::info!("configuration reloaded successfully (DB-backed)");

    Ok((resolver, filter, any_query_policy, zone_entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn create_temp_config(content: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!("dns-filter-test-{}-{id}.yaml", std::process::id()));
        let mut file = fs::File::create(&path).expect("failed to create temp file");
        file.write_all(content.as_bytes())
            .expect("failed to write to temp file");
        path
    }

    #[test]
    fn reload_config_fails_on_nonexistent_file() {
        let result = reload_config("/this/path/does/not/exist.yaml");
        assert!(result.is_err());
    }

    #[test]
    fn reload_config_fails_on_invalid_yaml() {
        let path = create_temp_config("{{ invalid: yaml: syntax");
        let result = reload_config(path.to_str().unwrap());
        assert!(result.is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn reload_config_fails_on_missing_upstreams() {
        let content = r#"
listen:
  dns:
    enabled: true
    address: "127.0.0.1"
    port: 53
resolvers:
  strategy: round_robin
  servers: []
blocklists: []
allowlists: []
"#;
        let path = create_temp_config(content);
        let result = reload_config(path.to_str().unwrap());
        assert!(
            result.is_err(),
            "should fail with no enabled upstream servers"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn reload_config_succeeds_with_valid_config() {
        let content = r#"
listen:
  dns:
    enabled: true
    address: "127.0.0.1"
    port: 53
  dot: null
  doh: null
  doq: null
  http: null
  metrics: null
resolvers:
  strategy: round_robin
  servers:
    - protocol: dns
      address: "1.1.1.1:53"
      enabled: true
blocklists: []
allowlists: []
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;
        let path = create_temp_config(content);
        let result = reload_config(path.to_str().unwrap());
        if let Err(e) = &result {
            eprintln!("Reload failed: {:#}", e);
        }
        assert!(result.is_ok(), "should succeed with valid config");

        let (resolver, filter, _policy, zone_entries) = result.expect("unwrap result");
        // Verify we got valid instances by checking they are not null
        let resolver_ptr = &*resolver as *const _ as *const ();
        let filter_ptr = &*filter as *const _ as *const ();
        assert!(!resolver_ptr.is_null());
        assert!(!filter_ptr.is_null());
        assert!(zone_entries.is_empty());
        let _ = fs::remove_file(path);
    }
}
