// filter logic is now in the filter crate
mod logging;
mod metrics;
mod upstream;

mod config; // Declare config module so use config::DnsFilterConfig works
use config::DnsFilterConfig;
use std::fs;
use std::path::Path;

#[tokio::main]
async fn main() {
    // Load config from /etc/dns-filter/config.yaml by default
    // For development, use filter/config.yaml; for production, use /etc/dns-filter/config.yaml
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "package/config.example.yaml".to_string());
    let config = match fs::read_to_string(&config_path) {
        Ok(content) => match serde_yaml::from_str::<DnsFilterConfig>(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Failed to parse config: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Failed to read config file {}: {}", config_path, e);
            std::process::exit(1);
        }
    };
    println!("Loaded config: {:?}", config);
    // TODO: Initialize logging, metrics, filter, upstream, and start listeners
}
