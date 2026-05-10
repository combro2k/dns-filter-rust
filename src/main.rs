use clap::Parser;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use dns_filter::frameworks::config::loader::load_config;
use dns_filter::frameworks::privileges::{
    drop_privileges, PrivilegeDropConfig, DEFAULT_CHROOT_DIR, DEFAULT_GROUP, DEFAULT_USER,
};
use dns_filter::frameworks::signal_handler::setup_sighup_handler;
use dns_filter::interface_adapters::listeners::dns::DnsServer;
use dns_filter::use_cases::config_bootstrap::{
    build_any_query_policy, build_dns_request_pipeline, build_domain_filter,
    build_upstream_resolver, validate_config,
};
use dns_filter::use_cases::reload::reload_config;

const DEFAULT_CONFIG_PATH: &str = "/etc/dns-filter/config.yaml";

#[derive(Debug, PartialEq, Eq)]
enum CliAction {
    Run(CliOptions),
    Version,
}

#[derive(Debug, PartialEq, Eq)]
struct CliOptions {
    config_path: String,
    debug: bool,
}

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(name = "dns-filter", disable_version_flag = true)]
struct CliArgs {
    #[arg(
        long = "config",
        value_name = "path",
        default_value = DEFAULT_CONFIG_PATH
    )]
    config_path: String,

    #[arg(long = "debug")]
    debug: bool,

    #[arg(long = "version", short = 'V')]
    version: bool,
}

fn parse_cli_args<I, S>(args: I) -> Result<CliAction, String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let parsed = CliArgs::try_parse_from(args).map_err(|e| e.to_string())?;

    if parsed.version {
        return Ok(CliAction::Version);
    }

    Ok(CliAction::Run(CliOptions {
        config_path: parsed.config_path,
        debug: parsed.debug,
    }))
}

#[tokio::main]
async fn main() {
    let cli_action = match parse_cli_args(std::env::args()) {
        Ok(action) => action,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    if cli_action == CliAction::Version {
        println!("dns-filter {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let CliAction::Run(cli_options) = cli_action else {
        unreachable!("version action is handled above");
    };

    // Initialize tracing/logging
    tracing_subscriber::fmt()
        .with_max_level(if cli_options.debug {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .with_target(true)
        .with_thread_ids(true)
        .init();

    let config_path = cli_options.config_path;

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

    let domain_filter = match build_domain_filter(&config) {
        Ok(filter) => filter,
        Err(e) => {
            eprintln!("invalid filtering configuration: {e:#}");
            std::process::exit(1);
        }
    };
    domain_filter.clone().start_background_refresh();

    let any_query_policy = match build_any_query_policy(&config) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("invalid filtering configuration: {e:#}");
            std::process::exit(1);
        }
    };

    let request_pipeline = build_dns_request_pipeline(
        Arc::clone(&upstream_resolver),
        Arc::clone(&domain_filter),
        any_query_policy,
    );

    let Some(dns_config) = config.listen.dns.as_ref().filter(|cfg| cfg.enabled) else {
        eprintln!(
            "listen.dns must be configured with enabled: true (only DNS listener startup is supported right now)"
        );
        std::process::exit(1);
    };

    // Wrap pipeline in Arc<Mutex<Arc<>>> to allow atomic state swapping on reload.
    let request_pipeline_slot = Arc::new(Mutex::new(Arc::new(request_pipeline)));

    let server = match DnsServer::new(dns_config, Arc::clone(&request_pipeline_slot)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to initialise DNS server: {e}");
            std::process::exit(1);
        }
    };

    // Bind sockets while still running as root (for privileged ports).
    let bound_server = match server.bind().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to bind DNS sockets: {e}");
            std::process::exit(1);
        }
    };

    // Drop privileges: chroot + setgid + setuid + retain CAP_NET_BIND_SERVICE.
    let security = config.security.as_ref();
    let priv_user = security
        .and_then(|s| s.user.as_deref())
        .unwrap_or(DEFAULT_USER);
    let priv_group = security
        .and_then(|s| s.group.as_deref())
        .unwrap_or(DEFAULT_GROUP);
    let priv_chroot = security
        .and_then(|s| s.chroot_dir.as_deref())
        .unwrap_or(DEFAULT_CHROOT_DIR);
    let priv_config = PrivilegeDropConfig {
        user: priv_user,
        group: priv_group,
        chroot_dir: Some(Path::new(priv_chroot)),
    };
    if let Err(e) = drop_privileges(&priv_config) {
        eprintln!("failed to drop privileges: {e:#}");
        std::process::exit(1);
    }

    // Set up SIGHUP signal handler for graceful reload
    let mut sighup_rx = match setup_sighup_handler() {
        Ok(rx) => rx,
        Err(e) => {
            eprintln!("failed to set up signal handler: {e}");
            std::process::exit(1);
        }
    };

    let server_task = tokio::spawn(bound_server.serve());
    let config_path_for_reload = config_path.clone();
    let pipeline_slot_for_reload = Arc::clone(&request_pipeline_slot);

    let reload_task = tokio::spawn(async move {
        while sighup_rx.recv().await.is_some() {
            match reload_config(&config_path_for_reload) {
                Ok((new_resolver, new_filter, new_any_query_policy)) => {
                    new_filter.clone().start_background_refresh();
                    let new_pipeline = Arc::new(build_dns_request_pipeline(
                        new_resolver,
                        new_filter,
                        new_any_query_policy,
                    ));
                    let mut pipeline_lock = pipeline_slot_for_reload.lock().await;
                    *pipeline_lock = new_pipeline;
                    tracing::info!("Configuration reloaded successfully");
                }
                Err(e) => {
                    tracing::warn!("Configuration reload failed, keeping previous config: {e:#}");
                }
            }
        }
    });

    // Wait for either the server or reload task to exit (server should run forever)
    tokio::select! {
        result = server_task => {
            if let Err(e) = result {
                eprintln!("DNS server task panicked: {e}");
                std::process::exit(1);
            }
            if let Err(e) = result.unwrap() {
                eprintln!("DNS server exited with error: {e}");
                std::process::exit(1);
            }
        }
        _ = reload_task => {
            eprintln!("Reload task exited unexpectedly");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_cli_args, CliAction, CliOptions, DEFAULT_CONFIG_PATH};

    #[test]
    fn parses_version_flag() {
        let parsed = parse_cli_args(["dns-filter", "--version"]).expect("parse should succeed");
        assert_eq!(parsed, CliAction::Version);
    }

    #[test]
    fn parses_debug_and_config_flags() {
        let parsed = parse_cli_args(["dns-filter", "--debug", "--config", "/tmp/test.yaml"])
            .expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Run(CliOptions {
                config_path: "/tmp/test.yaml".to_string(),
                debug: true,
            })
        );
    }

    #[test]
    fn uses_default_config_when_omitted() {
        let parsed = parse_cli_args(["dns-filter"]).expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Run(CliOptions {
                config_path: DEFAULT_CONFIG_PATH.to_string(),
                debug: false,
            })
        );
    }

    #[test]
    fn rejects_missing_config_value() {
        let err = parse_cli_args(["dns-filter", "--config"]).expect_err("parse should fail");
        assert!(err.contains("--config"));
    }

    #[test]
    fn rejects_unknown_flag() {
        let err = parse_cli_args(["dns-filter", "--wat"]).expect_err("parse should fail");
        assert!(err.contains("unexpected argument '--wat'"));
    }

    #[test]
    fn rejects_positional_argument() {
        let err = parse_cli_args(["dns-filter", "/etc/dns-filter/config.yaml"])
            .expect_err("parse should fail");
        assert!(err.contains("unexpected argument '/etc/dns-filter/config.yaml'"));
    }
}
