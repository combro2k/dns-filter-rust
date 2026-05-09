use dns_filter::frameworks::config::loader::load_config;
use dns_filter::use_cases::config_bootstrap::{build_upstream_resolver, validate_config};

#[tokio::main]
async fn main() {
    // Load config from /etc/dns-filter/config.yaml by default
    // For development, use filter/config.yaml; for production, use /etc/dns-filter/config.yaml
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "package/config.example.yaml".to_string());
    let config = match load_config(&config_path) {
        Ok(cfg) => validate_config(cfg),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let _upstream_resolver = match build_upstream_resolver(&config) {
        Ok(resolver) => resolver,
        Err(e) => {
            eprintln!("invalid upstream configuration: {e:#}");
            std::process::exit(1);
        }
    };

    println!("Loaded config: {:?}", config);
    // TODO: Initialize logging, metrics, filter, upstream, and start listeners
}
