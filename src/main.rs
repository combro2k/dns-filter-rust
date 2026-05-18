use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use dns_filter::entities::query_log::QueryLog;
use dns_filter::frameworks::config::loader::load_config;
use dns_filter::frameworks::config::merger::merge_with_example;
use dns_filter::frameworks::config::schema::{ApiConfig, DEFAULT_CONTROL_SOCKET_PATH};
use dns_filter::frameworks::control_client;
use dns_filter::frameworks::control_socket::ControlServer;
use dns_filter::frameworks::logging;
use dns_filter::frameworks::privileges::{
    drop_privileges, PrivilegeDropConfig, DEFAULT_CHROOT_DIR, DEFAULT_GROUP, DEFAULT_USER,
};
use dns_filter::frameworks::signal_handler::{setup_shutdown_signals, setup_sighup_handler};
use dns_filter::interface_adapters::listeners::handler::HickoryRequestHandler;
use dns_filter::interface_adapters::listeners::http::{start_api_server, ApiState, ApiStats};
use dns_filter::interface_adapters::listeners::{
    bind_tcp_tokio, bind_udp_tokio, build_tls_config_with_alpn, parse_bind_addrs,
};
use dns_filter::use_cases::config_bootstrap::{
    build_any_query_policy, build_dns_request_pipeline_full, build_domain_filter,
    build_upstream_resolver, build_zone_entries, validate_config,
};
use dns_filter::use_cases::reload::reload_config;

const DEFAULT_CONFIG_PATH: &str = "/etc/dns-filter/config.yaml";

#[derive(Debug, PartialEq, Eq)]
enum CliAction {
    Start {
        config_path: String,
        debug: bool,
    },
    Stop {
        config_path: String,
    },
    Reload {
        config_path: String,
    },
    MergeConfig {
        config_path: String,
        overwrite: bool,
    },
    Version,
}

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(name = "dns-filter", disable_version_flag = true)]
struct CliArgs {
    #[arg(long = "version", short = 'V')]
    version: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
enum Commands {
    /// Start the DNS filter daemon (foreground)
    Start {
        #[arg(
            long = "config",
            value_name = "path",
            default_value = DEFAULT_CONFIG_PATH
        )]
        config_path: String,

        #[arg(long = "debug")]
        debug: bool,
    },
    /// Stop the running daemon via control socket
    Stop {
        #[arg(
            long = "config",
            value_name = "path",
            default_value = DEFAULT_CONFIG_PATH
        )]
        config_path: String,
    },
    /// Reload the running daemon's configuration via control socket
    Reload {
        #[arg(
            long = "config",
            value_name = "path",
            default_value = DEFAULT_CONFIG_PATH
        )]
        config_path: String,
    },
    /// Merge config with built-in defaults (missing sections filled from example)
    MergeConfig {
        #[arg(
            long = "config",
            value_name = "path",
            default_value = DEFAULT_CONFIG_PATH
        )]
        config_path: String,

        /// Overwrite the config file in-place with the merged result
        #[arg(long = "overwrite")]
        overwrite: bool,
    },
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

    match parsed.command {
        Some(Commands::Start { config_path, debug }) => Ok(CliAction::Start { config_path, debug }),
        Some(Commands::Stop { config_path }) => Ok(CliAction::Stop { config_path }),
        Some(Commands::Reload { config_path }) => Ok(CliAction::Reload { config_path }),
        Some(Commands::MergeConfig {
            config_path,
            overwrite,
        }) => Ok(CliAction::MergeConfig {
            config_path,
            overwrite,
        }),
        None => Err(
            "no subcommand provided. Usage: dns-filter <start|stop|reload|merge-config> [OPTIONS]"
                .to_string(),
        ),
    }
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

    match cli_action {
        CliAction::Version => {
            println!("dns-filter {}", env!("CARGO_PKG_VERSION"));
        }
        CliAction::Start { config_path, debug } => {
            run_daemon(config_path, debug).await;
        }
        CliAction::Stop { config_path } => {
            run_control_command(&config_path, "stop");
        }
        CliAction::Reload { config_path } => {
            run_control_command(&config_path, "reload");
        }
        CliAction::MergeConfig {
            config_path,
            overwrite,
        } => {
            run_merge_config(&config_path, overwrite);
        }
    }
}

/// Send a control command (stop/reload) to the running daemon.
fn run_control_command(config_path: &str, command: &str) {
    let socket_path = match load_config(config_path) {
        Ok(cfg) => cfg.socket_path().to_string(),
        Err(e) => {
            eprintln!("failed to load config: {e}");
            eprintln!("using default control socket path");
            DEFAULT_CONTROL_SOCKET_PATH.to_string()
        }
    };

    match control_client::send_command(&socket_path, command) {
        Ok(resp) => {
            if resp.status == "ok" {
                if let Some(msg) = resp.message {
                    println!("{msg}");
                } else {
                    println!("{command} command sent successfully");
                }
            } else {
                eprintln!(
                    "daemon returned error: {}",
                    resp.message.unwrap_or_default()
                );
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// Merge the user's config file with the built-in example defaults.
fn run_merge_config(config_path: &str, overwrite: bool) {
    let user_config = match std::fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("failed to read config file {config_path}: {e}");
            std::process::exit(1);
        }
    };

    let merged = match merge_with_example(&user_config) {
        Ok(yaml) => yaml,
        Err(e) => {
            eprintln!("failed to merge config: {e}");
            std::process::exit(1);
        }
    };

    if overwrite {
        if let Err(e) = std::fs::write(config_path, &merged) {
            eprintln!("failed to write merged config to {config_path}: {e}");
            std::process::exit(1);
        }
        eprintln!("merged config written to {config_path}");
    } else {
        print!("{merged}");
    }
}

/// Main daemon entry point.
async fn run_daemon(config_path: String, debug: bool) {
    let config = match load_config(&config_path) {
        Ok(cfg) => validate_config(cfg),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    // Initialize logging from configuration.
    // Must be done BEFORE drop_privileges() so syslog can access /dev/log.
    let _logging_guard = match logging::init_logging(&config, debug) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("failed to initialize logging: {e:#}");
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

    let zone_entries = match build_zone_entries(&config) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("invalid zone forwarding configuration: {e:#}");
            std::process::exit(1);
        }
    };

    // Global filtering toggle shared with the API and filter pipeline stage.
    let filtering_enabled = Arc::new(AtomicBool::new(true));

    let request_pipeline = build_dns_request_pipeline_full(
        Arc::clone(&upstream_resolver),
        Arc::clone(&domain_filter),
        any_query_policy,
        zone_entries,
        Some(Arc::clone(&filtering_enabled)),
    );

    let Some(dns_config) = config.listen.dns.as_ref().filter(|cfg| cfg.enabled) else {
        eprintln!("listen.dns must be configured with enabled: true");
        std::process::exit(1);
    };

    // Wrap pipeline in Arc<Mutex<Arc<>>> to allow atomic state swapping on reload.
    let request_pipeline_slot = Arc::new(Mutex::new(Arc::new(request_pipeline)));

    // Create the unified hickory-server with a single request handler.
    let handler = HickoryRequestHandler::new(Arc::clone(&request_pipeline_slot));
    let mut server = hickory_server::server::Server::new(handler);

    // Default timeout for all protocol handshakes.
    let handshake_timeout = Duration::from_secs(5);
    // Response buffer size for TCP connections.
    let tcp_response_buffer_size = 65535;

    // --- Register DNS (UDP + TCP) listeners ---
    let dns_addrs = match parse_bind_addrs(&dns_config.addresses, dns_config.port) {
        Ok(addrs) => addrs,
        Err(e) => {
            eprintln!("failed to parse DNS bind addresses: {e}");
            std::process::exit(1);
        }
    };
    for addr in &dns_addrs {
        let udp = match bind_udp_tokio(*addr).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to bind UDP on {addr}: {e}");
                std::process::exit(1);
            }
        };
        tracing::info!(addr = %addr, "DNS UDP listener bound");
        server.register_socket(udp);

        let tcp = match bind_tcp_tokio(*addr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to bind TCP on {addr}: {e}");
                std::process::exit(1);
            }
        };
        tracing::info!(addr = %addr, "DNS TCP listener bound");
        server.register_listener(tcp, handshake_timeout, tcp_response_buffer_size);
    }

    // --- Register DoT listeners ---
    if let Some(dot_config) = config.listen.dot.as_ref().filter(|cfg| cfg.enabled) {
        let dot_addrs = match parse_bind_addrs(&dot_config.addresses, dot_config.port) {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("failed to parse DoT bind addresses: {e}");
                std::process::exit(1);
            }
        };
        let tls_config =
            match build_tls_config_with_alpn(&dot_config.tls, &dot_config.addresses, b"dot") {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("failed to configure DoT TLS: {e}");
                    std::process::exit(1);
                }
            };
        for addr in &dot_addrs {
            let tcp = match bind_tcp_tokio(*addr) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("failed to bind DoT on {addr}: {e}");
                    std::process::exit(1);
                }
            };
            tracing::info!(addr = %addr, "DoT listener bound");
            if let Err(e) = server.register_tls_listener_with_tls_config(
                tcp,
                handshake_timeout,
                Arc::clone(&tls_config),
            ) {
                eprintln!("failed to register DoT listener on {addr}: {e}");
                std::process::exit(1);
            }
        }
    }

    // --- Register DoH listeners ---
    if let Some(doh_config) = config.listen.doh.as_ref().filter(|cfg| cfg.enabled) {
        let doh_addrs = match parse_bind_addrs(&doh_config.addresses, doh_config.port) {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("failed to parse DoH bind addresses: {e}");
                std::process::exit(1);
            }
        };
        let tls_config =
            match build_tls_config_with_alpn(&doh_config.tls, &doh_config.addresses, b"h2") {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("failed to configure DoH TLS: {e}");
                    std::process::exit(1);
                }
            };
        for addr in &doh_addrs {
            let tcp = match bind_tcp_tokio(*addr) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("failed to bind DoH on {addr}: {e}");
                    std::process::exit(1);
                }
            };
            tracing::info!(addr = %addr, "DoH listener bound");
            if let Err(e) = server.register_https_listener_with_tls_config(
                tcp,
                handshake_timeout,
                Arc::clone(&tls_config),
                None,
                "/dns-query".to_string(),
            ) {
                eprintln!("failed to register DoH listener on {addr}: {e}");
                std::process::exit(1);
            }
        }
    }

    // --- Register DoQ listeners ---
    if let Some(doq_config) = config.listen.doq.as_ref().filter(|cfg| cfg.enabled) {
        let doq_addrs = match parse_bind_addrs(&doq_config.addresses, doq_config.port) {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("failed to parse DoQ bind addresses: {e}");
                std::process::exit(1);
            }
        };
        let tls_config =
            match build_tls_config_with_alpn(&doq_config.tls, &doq_config.addresses, b"doq") {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("failed to configure DoQ TLS: {e}");
                    std::process::exit(1);
                }
            };
        for addr in &doq_addrs {
            let udp = match bind_udp_tokio(*addr).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("failed to bind DoQ on {addr}: {e}");
                    std::process::exit(1);
                }
            };
            tracing::info!(addr = %addr, "DoQ listener bound");
            if let Err(e) = server.register_quic_listener_and_tls_config(
                udp,
                handshake_timeout,
                Arc::clone(&tls_config),
            ) {
                eprintln!("failed to register DoQ listener on {addr}: {e}");
                std::process::exit(1);
            }
        }
    }

    // Bind control socket while still running as root (before chroot).
    // The fd survives chroot so the accept loop continues to work.
    let control_socket_path = config.socket_path().to_string();
    let control_server = match ControlServer::bind(&control_socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to bind control socket: {e:#}");
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

    // Use the hickory-server's built-in shutdown token for unified lifecycle.
    let shutdown = server.shutdown_token().clone();

    // Set up SIGTERM/SIGINT handlers for graceful shutdown.
    if let Err(e) = setup_shutdown_signals(shutdown.clone()) {
        eprintln!("failed to set up shutdown signal handlers: {e}");
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

    let config_path_for_reload = config_path.clone();
    let pipeline_slot_for_reload = Arc::clone(&request_pipeline_slot);
    let filtering_enabled_for_reload = Arc::clone(&filtering_enabled);

    // Create a channel so SIGHUP, the API, and the control socket can trigger reloads.
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(4);

    // Forward SIGHUP signals into the reload channel.
    let sighup_reload_tx = reload_tx.clone();
    tokio::spawn(async move {
        while sighup_rx.recv().await.is_some() {
            let _ = sighup_reload_tx.send(()).await;
        }
    });

    let reload_task = tokio::spawn(async move {
        while reload_rx.recv().await.is_some() {
            match reload_config(&config_path_for_reload) {
                Ok((new_resolver, new_filter, new_any_query_policy, new_zone_entries)) => {
                    new_filter.clone().start_background_refresh();
                    let new_pipeline = Arc::new(build_dns_request_pipeline_full(
                        new_resolver,
                        new_filter,
                        new_any_query_policy,
                        new_zone_entries,
                        Some(Arc::clone(&filtering_enabled_for_reload)),
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

    // Start the control socket server.
    let control_reload_tx = reload_tx.clone();
    let control_shutdown = shutdown.clone();
    let control_task = tokio::spawn(async move {
        control_server
            .serve(control_reload_tx, control_shutdown)
            .await;
    });

    // Start the HTTP API server if configured.
    let mcp_domain_filter = Arc::clone(&domain_filter);
    let mcp_filtering_enabled = Arc::clone(&filtering_enabled);
    let mcp_reload_tx = reload_tx.clone();

    let api_task = spawn_api_server(
        &config.api,
        domain_filter,
        filtering_enabled,
        reload_tx,
        shutdown.clone(),
    );

    // Start the MCP server if configured.
    let mcp_task = spawn_mcp_server(
        &config.mcp,
        mcp_domain_filter,
        mcp_filtering_enabled,
        mcp_reload_tx,
        shutdown.clone(),
    );

    // Wait for shutdown or unexpected task exit.
    tokio::select! {
        _ = shutdown.cancelled() => {
            tracing::info!("shutdown signal received, exiting");
        }
        _ = server.block_until_done() => {
            tracing::warn!("DNS server exited unexpectedly");
        }
        _ = reload_task => {
            eprintln!("Reload task exited unexpectedly");
            std::process::exit(1);
        }
        _ = control_task => {
            // Control task exits on stop command — this is normal.
            tracing::info!("control socket task exited");
        }
        _ = async {
            if let Some(task) = api_task {
                if let Err(e) = task.await {
                    tracing::error!("HTTP API server task panicked: {e}");
                }
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::warn!("HTTP API server exited unexpectedly");
        }
        _ = async {
            if let Some(task) = mcp_task {
                if let Err(e) = task.await {
                    tracing::error!("MCP server task panicked: {e}");
                }
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::warn!("MCP server exited unexpectedly");
        }
    }
}

fn spawn_api_server(
    api_config: &Option<ApiConfig>,
    domain_filter: Arc<dyn dns_filter::use_cases::filtering::DomainFilter>,
    filtering_enabled: Arc<AtomicBool>,
    reload_tx: tokio::sync::mpsc::Sender<()>,
    shutdown: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let api_config = api_config.as_ref().filter(|c| c.enabled)?;

    let addr: SocketAddr = format!("{}:{}", api_config.address, api_config.port)
        .parse()
        .unwrap_or_else(|e| {
            eprintln!("invalid API bind address: {e}");
            std::process::exit(1);
        });

    let query_log = api_config
        .query_logging
        .as_ref()
        .filter(|ql| ql.enabled)
        .map(|ql| Arc::new(StdMutex::new(QueryLog::new(ql.max_entries))));

    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let state = Arc::new(ApiState {
        domain_filter,
        filtering_enabled,
        query_log,
        reload_tx,
        api_token: api_config.api_token.clone(),
        start_time,
        stats: Arc::new(ApiStats::new()),
        shutdown,
    });

    Some(tokio::spawn(async move {
        if let Err(e) = start_api_server(addr, state).await {
            tracing::error!(error = %e, "HTTP API server failed");
        }
    }))
}

fn spawn_mcp_server(
    mcp_config: &Option<dns_filter::frameworks::config::schema::McpConfig>,
    domain_filter: Arc<dyn dns_filter::use_cases::filtering::DomainFilter>,
    filtering_enabled: Arc<AtomicBool>,
    reload_tx: tokio::sync::mpsc::Sender<()>,
    shutdown: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    use dns_filter::interface_adapters::listeners::mcp::{start_mcp_server, McpServerState};

    let mcp_config = mcp_config.as_ref().filter(|c| c.enabled)?;

    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let state = Arc::new(McpServerState {
        domain_filter,
        filtering_enabled,
        query_log: None,
        reload_tx,
        start_time,
        stats: Arc::new(ApiStats::new()),
        shutdown,
    });

    let mcp_config = mcp_config.clone();
    Some(tokio::spawn(async move {
        if let Err(e) = start_mcp_server(&mcp_config, state).await {
            tracing::error!(error = %e, "MCP server failed");
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::{parse_cli_args, CliAction, DEFAULT_CONFIG_PATH};

    #[test]
    fn parses_version_flag() {
        let parsed = parse_cli_args(["dns-filter", "--version"]).expect("parse should succeed");
        assert_eq!(parsed, CliAction::Version);
    }

    #[test]
    fn parses_version_short_flag() {
        let parsed = parse_cli_args(["dns-filter", "-V"]).expect("parse should succeed");
        assert_eq!(parsed, CliAction::Version);
    }

    #[test]
    fn parses_start_with_debug_and_config() {
        let parsed = parse_cli_args([
            "dns-filter",
            "start",
            "--debug",
            "--config",
            "/tmp/test.yaml",
        ])
        .expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Start {
                config_path: "/tmp/test.yaml".to_string(),
                debug: true,
            }
        );
    }

    #[test]
    fn parses_start_with_defaults() {
        let parsed = parse_cli_args(["dns-filter", "start"]).expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Start {
                config_path: DEFAULT_CONFIG_PATH.to_string(),
                debug: false,
            }
        );
    }

    #[test]
    fn parses_stop_subcommand() {
        let parsed = parse_cli_args(["dns-filter", "stop", "--config", "/tmp/test.yaml"])
            .expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Stop {
                config_path: "/tmp/test.yaml".to_string(),
            }
        );
    }

    #[test]
    fn parses_reload_subcommand() {
        let parsed = parse_cli_args(["dns-filter", "reload"]).expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Reload {
                config_path: DEFAULT_CONFIG_PATH.to_string(),
            }
        );
    }

    #[test]
    fn parses_merge_config_subcommand() {
        let parsed = parse_cli_args(["dns-filter", "merge-config", "--config", "/tmp/test.yaml"])
            .expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::MergeConfig {
                config_path: "/tmp/test.yaml".to_string(),
                overwrite: false,
            }
        );
    }

    #[test]
    fn parses_merge_config_with_overwrite() {
        let parsed = parse_cli_args([
            "dns-filter",
            "merge-config",
            "--config",
            "/tmp/test.yaml",
            "--overwrite",
        ])
        .expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::MergeConfig {
                config_path: "/tmp/test.yaml".to_string(),
                overwrite: true,
            }
        );
    }

    #[test]
    fn rejects_no_subcommand() {
        let err = parse_cli_args(["dns-filter"]).expect_err("parse should fail");
        assert!(err.contains("no subcommand"));
    }

    #[test]
    fn rejects_unknown_subcommand() {
        let err = parse_cli_args(["dns-filter", "explode"]).expect_err("parse should fail");
        assert!(!err.is_empty());
    }

    #[test]
    fn rejects_missing_config_value() {
        let err =
            parse_cli_args(["dns-filter", "start", "--config"]).expect_err("parse should fail");
        assert!(err.contains("--config"));
    }
}
