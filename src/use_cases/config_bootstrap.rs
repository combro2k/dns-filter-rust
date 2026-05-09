use crate::frameworks::config::schema::DnsFilterConfig;

pub fn validate_config(config: DnsFilterConfig) -> DnsFilterConfig {
    // Keep validation simple for the first migration step.
    config
}
