use std::fs;

use anyhow::{Context, Result};

use crate::frameworks::config::schema::DnsFilterConfig;

pub fn load_config(path: &str) -> Result<DnsFilterConfig> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read config file: {path}"))?;
    let config = serde_yaml::from_str::<DnsFilterConfig>(&content)
        .with_context(|| format!("failed to parse config file: {path}"))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
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
upstreams:
  strategy: "round_robin"
  servers: []
logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
"#;

        let parsed = serde_yaml::from_str::<DnsFilterConfig>(yaml);
        assert!(parsed.is_ok());
    }
}
