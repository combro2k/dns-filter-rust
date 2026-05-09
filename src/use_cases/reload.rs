//! Config reload orchestration for SIGHUP signals.
//!
//! This module handles loading and validating configuration for the reload flow,
//! reusing the same logic as the initial bootstrap but in a reloadable context.

use anyhow::Result;
use std::sync::Arc;

use crate::frameworks::config::loader::load_config;
use crate::use_cases::config_bootstrap::{
    build_domain_filter, build_upstream_resolver, validate_config,
};
use crate::use_cases::filtering::DomainFilter;
use crate::use_cases::upstream_resolver::UpstreamResolver;

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
/// A tuple of `(Arc<dyn UpstreamResolver>, Arc<dyn DomainFilter>)` if all steps succeed,
/// or an error if any step fails.
pub fn reload_config(
    config_path: &str,
) -> Result<(Arc<dyn UpstreamResolver>, Arc<dyn DomainFilter>)> {
    tracing::info!(path = %config_path, "reloading configuration");

    let config = load_config(config_path)?;
    let config = validate_config(config);

    let resolver = build_upstream_resolver(&config)?;
    let filter = build_domain_filter(&config)?;

    tracing::info!("configuration reloaded successfully");

    Ok((resolver, filter))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_config_returns_error_on_missing_file() {
        let result = reload_config("/nonexistent/file.yaml");
        assert!(result.is_err());
    }
}
