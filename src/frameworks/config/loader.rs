use std::fs;

use anyhow::{anyhow, Result};

use crate::frameworks::config::schema::DnsFilterConfig;

pub fn load_config(path: &str) -> Result<DnsFilterConfig> {
    let content = fs::read_to_string(path).map_err(|error| {
    anyhow!(
      "Could not read the config file.\n  File: {path}\n  Reason: {error}\n  Hint: Check that the file exists and that this process has read permissions."
    )
  })?;

    parse_config(path, &content)
}

/// Parses a `DnsFilterConfig` from an in-memory YAML string.
///
/// Used during reload when the original YAML content has been cached in memory
/// (e.g. because the filesystem is no longer accessible after chroot).
pub fn load_config_from_str(content: &str) -> Result<DnsFilterConfig> {
    parse_config("<cached>", content)
}

fn parse_config(path: &str, content: &str) -> Result<DnsFilterConfig> {
    let deserializer = serde_yaml::Deserializer::from_str(content);
    serde_path_to_error::deserialize::<_, DnsFilterConfig>(deserializer).map_err(|error| {
    let field_path = error.path().to_string();
    let inner = error.inner();
    let specific_hint = hint_for_path(&field_path);

    if let Some(location) = inner.location() {
      anyhow!(
        "Could not parse the config file.\n  File: {path}\n  Location: line {}, column {}\n  Field: {}\n  Reason: {}\n  Hint: {}",
        location.line(),
        location.column(),
        field_path,
        inner,
        specific_hint
      )
    } else {
      anyhow!(
        "Could not parse the config file.\n  File: {path}\n  Field: {}\n  Reason: {}\n  Hint: {}",
        field_path,
        inner,
        specific_hint
      )
    }
  })
}

fn hint_for_path(field_path: &str) -> &'static str {
    if field_path.starts_with("blocklists") || field_path.starts_with("allowlists") {
        "Use either '- name: my_list\\n  url: https://...\\n  interval: 12h' or '- my_list:\\n    url: https://...\\n    interval: 12h' for each list item."
    } else if field_path.starts_with("listen") {
        "Check listener fields and types (for example, ports must be numbers and TLS sections must be nested under 'tls')."
    } else if field_path.starts_with("resolvers.zones") {
        "Check each zone includes 'zone' and at least one enabled entry in 'servers[]'. Each server requires 'enabled', 'protocol', and 'address'. Protocols: 'dns' (<ip>:<port>), 'dot' (tls://<host>[:port]), 'doh' (https://...), 'recursive', 'json' (file://, http://, or https:// address). The 'json' protocol accepts 'check_interval' for URL sources. Both 'json' and 'doh' accept nested 'authentication' with 'token' (Bearer) or 'username'+'password' (Basic). Zone-level 'strategy' supports round_robin, random, or failover."
    } else if field_path.starts_with("resolvers") {
        "Check that 'strategy' is valid, each server includes 'protocol'/'address', and optional 'bootstrap_resolvers' values are IP or IP:port (default: 194.242.2.2; protocol support: dns, dot, recursive; DoT examples: tls://1.1.1.1, tls://dns.example.com:853, or 1.1.1.1:853)."
    } else if field_path.starts_with("logging") {
        "Check each logging target uses the expected keys (enabled/level and location for file logging)."
    } else if field_path.starts_with("filtering") {
        "Check filtering fields (sinkhole_ipv4/sinkhole_ipv6), optional any_query_policy ('passthrough', 'refused', or 'notimp'), and optional cache config: mode is 'memory' or 'sqlite', with optional document_path."
    } else {
        "Check YAML indentation and value types in this section."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let yaml = r#"
listen:
  dns:
    enabled: true
    address: "127.0.0.1"
    port: 5353
  dot: null
  doh: null
  doq: null
  http: null
  metrics: null
blocklists: []
allowlists: []
resolvers:
  strategy: "round_robin"
  servers: []
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let parsed = parse_config("minimal.yaml", yaml);
        assert!(parsed.is_ok());
    }

    #[test]
    fn parses_named_map_list_format() {
        let yaml = r#"
listen:
  dns:
    enabled: true
    address: "0.0.0.0"
    port: 53
  dot: null
  doh: null
  doq: null
  http: null
  metrics: null
blocklists:
  - adguard_base:
      url: "https://example.com/blocklist.txt"
      interval: "6h"
      enabled: true
allowlists:
  - local_allow:
      url: "/etc/dns-filter/allowlist.txt"
      interval: "45m"
      enabled: false
resolvers:
  strategy: "round_robin"
  servers: []
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let parsed = parse_config("named-map.yaml", yaml).expect("config should parse");
        assert_eq!(parsed.blocklists[0].name, "adguard_base");
        assert_eq!(parsed.blocklists[0].interval.as_deref(), Some("6h"));
        assert_eq!(parsed.blocklists[0].enabled, Some(true));
        assert_eq!(parsed.allowlists[0].name, "local_allow");
        assert_eq!(parsed.allowlists[0].interval.as_deref(), Some("45m"));
        assert_eq!(parsed.allowlists[0].enabled, Some(false));
    }

    #[test]
    fn parses_explicit_list_format_with_optional_enabled() {
        let yaml = r#"
listen:
  dns:
    enabled: true
    address: "127.0.0.1"
    port: 5353
  dot: null
  doh: null
  doq: null
  http: null
  metrics: null
blocklists:
  - name: "adguard_base"
    url: "https://example.com/blocklist.txt"
    interval: "6h"
    enabled: false
allowlists:
  - name: "local_allow"
    url: "/etc/dns-filter/allowlist.txt"
resolvers:
  strategy: "round_robin"
  servers: []
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let parsed = parse_config("explicit-enabled.yaml", yaml).expect("config should parse");
        assert_eq!(parsed.blocklists[0].enabled, Some(false));
        assert_eq!(parsed.allowlists[0].enabled, None);
    }

    #[test]
    fn reports_missing_enabled_for_listener() {
        let yaml = r#"
listen:
  dns:
    address: "127.0.0.1"
    port: 5353
  dot: null
  doh: null
  doq: null
  http: null
  metrics: null
blocklists: []
allowlists: []
resolvers:
  strategy: "round_robin"
  servers: []
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let error = parse_config("missing-enabled.yaml", yaml).expect_err("parse should fail");
        let message = format!("{error:#}");
        assert!(message.contains("listen.dns"));
        assert!(message.contains("missing field `enabled`"));
    }

    #[test]
    fn reports_missing_enabled_for_upstream_server() {
        let yaml = r#"
listen:
  dns:
    enabled: true
    address: "127.0.0.1"
    port: 5353
  dot: null
  doh: null
  doq: null
  http: null
  metrics: null
blocklists: []
allowlists: []
resolvers:
  strategy: "round_robin"
  servers:
    - protocol: "dns"
      address: "8.8.8.8:53"
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let error =
            parse_config("missing-upstream-enabled.yaml", yaml).expect_err("parse should fail");
        let message = format!("{error:#}");
        assert!(message.contains("resolvers.servers[0]"));
        assert!(message.contains("missing field `enabled`"));
    }

    #[test]
    fn reports_line_column_and_field_path_on_parse_errors() {
        let yaml = r#"
listen:
  dns:
    enabled: true
    address: "127.0.0.1"
    port: "not-a-number"
  dot: null
  doh: null
  doq: null
  http: null
  metrics: null
blocklists: []
allowlists: []
resolvers:
  strategy: "round_robin"
  servers: []
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let error = parse_config("broken.yaml", yaml).expect_err("parse should fail");
        let message = format!("{error:#}");

        assert!(message.contains("Could not parse the config file"));
        assert!(message.contains("broken.yaml"));
        assert!(message.contains("line"));
        assert!(message.contains("column"));
        assert!(message.contains("listen.dns.port"));
        assert!(message.contains("Hint:"));
    }

    #[test]
    fn parses_filtering_cache_sqlite_settings() {
        let yaml = r#"
listen:
  dns:
    enabled: true
    address: "127.0.0.1"
    port: 5353
  dot: null
  doh: null
  doq: null
  http: null
  metrics: null
blocklists: []
allowlists: []
filtering:
  sinkhole_ipv4: "0.0.0.0"
  sinkhole_ipv6: "::"
  any_query_policy: "refused"
  cache:
    mode: "sqlite"
    document_path: "/var/lib/dns-filter/filter-cache.db"
resolvers:
  strategy: "round_robin"
  servers: []
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let parsed = parse_config("filtering-cache.yaml", yaml).expect("config should parse");
        let filtering = parsed.filtering.expect("filtering config should exist");
        assert_eq!(filtering.any_query_policy.as_deref(), Some("refused"));
        let cache = filtering.cache.expect("cache config should exist");
        assert_eq!(cache.mode.as_deref(), Some("sqlite"));
        assert_eq!(
            cache.document_path.as_deref(),
            Some("/var/lib/dns-filter/filter-cache.db")
        );
    }

    #[test]
    fn parses_zone_resolver_configuration() {
        let yaml = r#"
listen:
  dns:
    enabled: true
    address: "127.0.0.1"
    port: 5353
  dot: null
  doh: null
  doq: null
  http: null
  metrics: null
blocklists: []
allowlists: []
resolvers:
  strategy: "round_robin"
  servers:
    - enabled: true
      protocol: "dns"
      address: "1.1.1.1:53"
  zones:
    - zone: "home.arpa"
      enabled: true
      bypass_filter: true
      fallback_to_default_resolvers: false
      strategy: "failover"
      servers:
        - enabled: true
          protocol: "dns"
          address: "192.168.1.1:53"
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let parsed = parse_config("zones.yaml", yaml).expect("config should parse");
        assert_eq!(parsed.resolvers.zones.len(), 1);
        let zone = &parsed.resolvers.zones[0];
        assert_eq!(zone.zone, "home.arpa");
        assert!(zone.enabled);
        assert!(zone.bypass_filter);
        assert!(!zone.fallback_to_default_resolvers);
        assert_eq!(zone.strategy.as_deref(), Some("failover"));
        assert_eq!(zone.servers.len(), 1);
    }

    #[test]
    fn parses_addresses_as_list_for_dual_stack() {
        let yaml = r#"
listen:
  dns:
    enabled: true
    addresses: ["0.0.0.0", "::"]
    port: 5353
  dot: null
  doh: null
  doq: null
  http: null
  metrics: null
blocklists: []
allowlists: []
resolvers:
  strategy: "round_robin"
  servers: []
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let parsed = parse_config("dual-stack.yaml", yaml).expect("config should parse");
        let dns = parsed.listen.dns.expect("dns config should exist");
        assert_eq!(dns.addresses, vec!["0.0.0.0", "::"]);
    }

    #[test]
    fn parses_single_address_string_via_alias() {
        let yaml = r#"
listen:
  dns:
    enabled: true
    address: "127.0.0.1"
    port: 5353
  dot: null
  doh: null
  doq: null
  http: null
  metrics: null
blocklists: []
allowlists: []
resolvers:
  strategy: "round_robin"
  servers: []
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let parsed = parse_config("single-addr.yaml", yaml).expect("config should parse");
        let dns = parsed.listen.dns.expect("dns config should exist");
        assert_eq!(dns.addresses, vec!["127.0.0.1"]);
    }

    #[test]
    fn parses_disabled_listeners_without_optional_fields() {
        let yaml = r#"
listen:
  dns:
    enabled: false
  dot:
    enabled: false
  doh:
    enabled: false
  doq:
    enabled: false
  http:
    enabled: false
  metrics:
    enabled: false
blocklists: []
allowlists: []
resolvers:
  strategy: "round_robin"
  servers: []
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let parsed = parse_config("disabled-listeners.yaml", yaml)
            .expect("disabled listeners should parse");

        let dns = parsed.listen.dns.expect("dns config should exist");
        assert!(!dns.enabled);

        let dot = parsed.listen.dot.expect("dot config should exist");
        assert!(!dot.enabled);

        let doh = parsed.listen.doh.expect("doh config should exist");
        assert!(!doh.enabled);

        let doq = parsed.listen.doq.expect("doq config should exist");
        assert!(!doq.enabled);

        let http = parsed.listen.http.expect("http config should exist");
        assert!(!http.enabled);

        let metrics = parsed.listen.metrics.expect("metrics config should exist");
        assert!(!metrics.enabled);
    }
}
