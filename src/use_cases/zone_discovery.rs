use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use url::Url;

use crate::frameworks::config::schema::ZoneDiscoveryConfig;
use crate::use_cases::zone_authority::{ZoneAuthorityResolver, ZoneSearchable, ZoneSourceAuth};
use crate::use_cases::zone_forwarding::ZoneEntry;

const HTTP_TIMEOUT_SECS: u64 = 30;
const MAX_INDEX_BYTES: usize = 512 * 1024;
const VALID_ZONE_TYPES: &[&str] = &["reverse", "forward", "reverse-aggregate"];

/// The JSON structure returned by a zone discovery index endpoint.
#[derive(Debug, Deserialize)]
pub struct ZoneIndexDocument {
    pub zones: Vec<ZoneIndexEntry>,
}

/// A single zone entry within the discovery index.
#[derive(Debug, Clone, Deserialize)]
pub struct ZoneIndexEntry {
    pub href: String,
    pub name: String,
    #[serde(rename = "type")]
    pub zone_type: String,
}

/// Build zone entries from a single zone discovery config.
///
/// Fetches the index, filters by `allowed_types`, resolves hrefs relative to
/// the index URL, and creates a `ZoneEntry` for each matched zone backed by a
/// `ZoneAuthorityResolver`.
///
/// Zones whose names already appear in `existing_zone_names` are skipped
/// (manual zones take priority).
pub fn build_zone_discovery_entries(
    discovery: &ZoneDiscoveryConfig,
    existing_zone_names: &[String],
    check_interval: Option<Duration>,
) -> Result<Vec<ZoneEntry>> {
    let address = discovery.address.trim();
    if address.is_empty() {
        bail!("zone_discovery entry has an empty address");
    }

    if !address.starts_with("http://") && !address.starts_with("https://") {
        bail!(
            "zone_discovery address must be an HTTP(S) URL, got: {}",
            address
        );
    }

    let auth = build_discovery_auth(&discovery.authentication)?;

    // Validate allowed_types
    for t in &discovery.allowed_types {
        if !VALID_ZONE_TYPES.contains(&t.as_str()) {
            bail!(
                "zone_discovery: invalid allowed_type '{}'; supported values: {:?}",
                t,
                VALID_ZONE_TYPES
            );
        }
    }

    let index = fetch_zone_index(address, &auth)?;
    let base_url = Url::parse(address)
        .with_context(|| format!("zone_discovery: failed to parse base URL: {address}"))?;

    let mut entries = Vec::new();

    for zone_item in &index.zones {
        // Filter by allowed types (if empty, accept all)
        if !discovery.allowed_types.is_empty()
            && !discovery
                .allowed_types
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&zone_item.zone_type))
        {
            tracing::debug!(
                zone = %zone_item.name,
                zone_type = %zone_item.zone_type,
                "zone_discovery: skipping zone (type not in allowed_types)"
            );
            continue;
        }

        // Skip zones that are already manually configured
        let normalized = normalize_discovery_zone(&zone_item.name);
        if existing_zone_names
            .iter()
            .any(|existing| normalize_discovery_zone(existing) == normalized)
        {
            tracing::debug!(
                zone = %zone_item.name,
                "zone_discovery: skipping zone (already defined in zones config)"
            );
            continue;
        }

        let resolved_href = resolve_href(&base_url, &zone_item.href).with_context(|| {
            format!(
                "zone_discovery: failed to resolve href '{}' for zone '{}'",
                zone_item.href, zone_item.name
            )
        })?;

        let resolver = ZoneAuthorityResolver::from_source(
            &zone_item.name,
            &resolved_href,
            check_interval,
            auth.clone(),
        )
        .with_context(|| {
            format!(
                "zone_discovery: failed to load zone '{}' from {}",
                zone_item.name, resolved_href
            )
        })?;

        let resolver = Arc::new(resolver);
        let searchable: Arc<dyn ZoneSearchable> = Arc::clone(&resolver) as Arc<dyn ZoneSearchable>;

        let entry = ZoneEntry::new(
            zone_item.name.clone(),
            discovery.bypass_filter,
            discovery.fallback_to_default_resolvers,
            resolver,
        )
        .map(|entry| entry.with_searchable(searchable))
        .with_context(|| {
            format!(
                "zone_discovery: failed to create zone entry for '{}'",
                zone_item.name
            )
        })?;

        entries.push(entry);
    }

    tracing::info!(
        source = %address,
        total_in_index = index.zones.len(),
        imported = entries.len(),
        "zone_discovery: loaded zones"
    );

    Ok(entries)
}

/// Fetch and parse the zone index document from the given URL.
fn fetch_zone_index(url: &str, auth: &Option<ZoneSourceAuth>) -> Result<ZoneIndexDocument> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()
        .context("zone_discovery: failed to initialize HTTP client")?;

    let mut request = client.get(url);

    if let Some(zone_auth) = auth {
        request = match zone_auth {
            ZoneSourceAuth::Bearer(token) => request.bearer_auth(token),
            ZoneSourceAuth::Basic { username, password } => {
                request.basic_auth(username, Some(password))
            }
        };
    }

    let response = request
        .send()
        .with_context(|| format!("zone_discovery: failed to fetch index from {url}"))?
        .error_for_status()
        .with_context(|| format!("zone_discovery: index endpoint returned error status: {url}"))?;

    if let Some(content_len) = response.content_length() {
        if content_len as usize > MAX_INDEX_BYTES {
            bail!(
                "zone_discovery: index response too large: {} bytes exceeds limit {}",
                content_len,
                MAX_INDEX_BYTES
            );
        }
    }

    let body = response
        .text()
        .with_context(|| format!("zone_discovery: failed to read index response from {url}"))?;

    if body.len() > MAX_INDEX_BYTES {
        bail!(
            "zone_discovery: index response too large: {} bytes exceeds limit {}",
            body.len(),
            MAX_INDEX_BYTES
        );
    }

    serde_json::from_str(&body)
        .with_context(|| format!("zone_discovery: failed to parse index JSON from {url}"))
}

/// Resolve an href (potentially relative) against a base URL.
fn resolve_href(base_url: &Url, href: &str) -> Result<String> {
    // If href is already an absolute URL, use it as-is
    if href.starts_with("http://") || href.starts_with("https://") {
        return Ok(href.to_string());
    }

    // Resolve relative to the base URL
    let resolved = base_url
        .join(href)
        .map_err(|e| anyhow!("cannot resolve href '{}': {}", href, e))?;

    Ok(resolved.to_string())
}

/// Build authentication from the discovery config.
fn build_discovery_auth(
    auth_config: &Option<crate::frameworks::config::schema::ZoneServerAuthenticationConfig>,
) -> Result<Option<ZoneSourceAuth>> {
    let config = match auth_config {
        Some(c) => c,
        None => return Ok(None),
    };

    let has_token = config.token.as_ref().is_some_and(|v| !v.trim().is_empty());
    let has_username = config
        .username
        .as_ref()
        .is_some_and(|v| !v.trim().is_empty());
    let has_password = config
        .password
        .as_ref()
        .is_some_and(|v| !v.trim().is_empty());

    if !has_token && !has_username && !has_password {
        return Ok(None);
    }

    if has_token && (has_username || has_password) {
        bail!("zone_discovery authentication must use either 'token' (Bearer) or 'username'/'password' (Basic), not both");
    }

    if has_username != has_password {
        bail!(
            "zone_discovery authentication requires both 'username' and 'password' for Basic auth"
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

/// Normalize a zone name for comparison (lowercase, strip trailing dot).
fn normalize_discovery_zone(name: &str) -> String {
    let s = name.trim().to_ascii_lowercase();
    s.strip_suffix('.').unwrap_or(&s).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_index_document_deserialization() {
        let json = r#"{
            "zones": [
                {"href": "/zone/home.arpa", "name": "home.arpa", "type": "forward"},
                {"href": "/zone/168.192.in-addr.arpa", "name": "168.192.in-addr.arpa", "type": "reverse"}
            ]
        }"#;
        let doc: ZoneIndexDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.zones.len(), 2);
        assert_eq!(doc.zones[0].name, "home.arpa");
        assert_eq!(doc.zones[0].zone_type, "forward");
        assert_eq!(doc.zones[0].href, "/zone/home.arpa");
        assert_eq!(doc.zones[1].zone_type, "reverse");
    }

    #[test]
    fn test_zone_index_document_empty_zones() {
        let json = r#"{"zones": []}"#;
        let doc: ZoneIndexDocument = serde_json::from_str(json).unwrap();
        assert!(doc.zones.is_empty());
    }

    #[test]
    fn test_zone_index_document_missing_zones_key() {
        let json = r#"{"other": "value"}"#;
        let result: Result<ZoneIndexDocument, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_href_relative_path() {
        let base = Url::parse("https://router.home.arpa/zones").unwrap();
        let resolved = resolve_href(&base, "/zone/home.arpa").unwrap();
        assert_eq!(resolved, "https://router.home.arpa/zone/home.arpa");
    }

    #[test]
    fn test_resolve_href_relative_without_leading_slash() {
        let base = Url::parse("https://router.home.arpa/api/zones").unwrap();
        let resolved = resolve_href(&base, "zone/home.arpa").unwrap();
        assert_eq!(resolved, "https://router.home.arpa/api/zone/home.arpa");
    }

    #[test]
    fn test_resolve_href_absolute_url() {
        let base = Url::parse("https://router.home.arpa/zones").unwrap();
        let resolved = resolve_href(&base, "https://other.host/zone/example.com").unwrap();
        assert_eq!(resolved, "https://other.host/zone/example.com");
    }

    #[test]
    fn test_normalize_discovery_zone() {
        assert_eq!(normalize_discovery_zone("Home.Arpa."), "home.arpa");
        assert_eq!(normalize_discovery_zone("home.arpa"), "home.arpa");
        assert_eq!(normalize_discovery_zone("  FOO.bar  "), "foo.bar");
    }

    #[test]
    fn test_build_discovery_auth_none() {
        let result = build_discovery_auth(&None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_build_discovery_auth_bearer() {
        use crate::frameworks::config::schema::ZoneServerAuthenticationConfig;
        let config = ZoneServerAuthenticationConfig {
            token: Some("my-token".to_string()),
            username: None,
            password: None,
        };
        let result = build_discovery_auth(&Some(config)).unwrap();
        assert!(matches!(result, Some(ZoneSourceAuth::Bearer(ref t)) if t == "my-token"));
    }

    #[test]
    fn test_build_discovery_auth_basic() {
        use crate::frameworks::config::schema::ZoneServerAuthenticationConfig;
        let config = ZoneServerAuthenticationConfig {
            token: None,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
        };
        let result = build_discovery_auth(&Some(config)).unwrap();
        assert!(
            matches!(result, Some(ZoneSourceAuth::Basic { ref username, ref password }) if username == "user" && password == "pass")
        );
    }

    #[test]
    fn test_build_discovery_auth_both_fails() {
        use crate::frameworks::config::schema::ZoneServerAuthenticationConfig;
        let config = ZoneServerAuthenticationConfig {
            token: Some("tok".to_string()),
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
        };
        let result = build_discovery_auth(&Some(config));
        assert!(result.is_err());
    }

    #[test]
    fn test_build_discovery_auth_missing_password_fails() {
        use crate::frameworks::config::schema::ZoneServerAuthenticationConfig;
        let config = ZoneServerAuthenticationConfig {
            token: None,
            username: Some("user".to_string()),
            password: None,
        };
        let result = build_discovery_auth(&Some(config));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_allowed_type() {
        let discovery = ZoneDiscoveryConfig {
            enabled: true,
            address: "https://example.com/zones".to_string(),
            check_interval: None,
            allowed_types: vec!["invalid-type".to_string()],
            bypass_filter: false,
            fallback_to_default_resolvers: false,
            authentication: None,
        };
        let result = build_zone_discovery_entries(&discovery, &[], None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid allowed_type"));
    }

    #[test]
    fn test_empty_address_fails() {
        let discovery = ZoneDiscoveryConfig {
            enabled: true,
            address: "".to_string(),
            check_interval: None,
            allowed_types: vec![],
            bypass_filter: false,
            fallback_to_default_resolvers: false,
            authentication: None,
        };
        let result = build_zone_discovery_entries(&discovery, &[], None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty address"));
    }

    #[test]
    fn test_non_http_address_fails() {
        let discovery = ZoneDiscoveryConfig {
            enabled: true,
            address: "file:///etc/zones.json".to_string(),
            check_interval: None,
            allowed_types: vec![],
            bypass_filter: false,
            fallback_to_default_resolvers: false,
            authentication: None,
        };
        let result = build_zone_discovery_entries(&discovery, &[], None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTP(S) URL"));
    }
}
