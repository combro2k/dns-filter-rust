use dns_filter::frameworks::config::loader::load_config;
use dns_filter::interface_adapters::listeners::dns::DnsServer;
use dns_filter::use_cases::config_bootstrap::{build_upstream_resolver, validate_config};

#[tokio::main]
async fn main() {
    // Load config from /etc/dns-filter/config.yaml by default.
    // Override by passing the path as the first argument.
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

    let upstream_resolver = match build_upstream_resolver(&config) {
        Ok(resolver) => resolver,
        Err(e) => {
            eprintln!("invalid upstream configuration: {e:#}");
            std::process::exit(1);
        }
    };

    let Some(dns_config) = config.listen.dns.as_ref().filter(|cfg| cfg.enabled) else {
        eprintln!(
            "listen.dns must be configured with enabled: true (only DNS listener startup is supported right now)"
        );
        std::process::exit(1);
    };

    let server = match DnsServer::new(dns_config, upstream_resolver) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to initialise DNS server: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = server.run().await {
        eprintln!("DNS server exited with error: {e}");
        std::process::exit(1);
    }
}
