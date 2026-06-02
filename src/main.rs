use clap::{Parser, Subcommand};
use nix::unistd;
use serde::Deserialize;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
#[cfg(any(feature = "http-api", feature = "mcp"))]
use tokio_util::sync::CancellationToken;

#[cfg(feature = "http-api")]
use dns_filter::entities::query_log::QueryLog;
use dns_filter::frameworks::config::loader::load_config;
use dns_filter::frameworks::config::merger::merge_with_example;
#[cfg(feature = "http-api")]
use dns_filter::frameworks::config::schema::ApiConfig;
use dns_filter::frameworks::config::schema::{
    MetricsConfig, DEFAULT_CONTROL_SOCKET_PATH, DEFAULT_DATABASE_URL,
};
use dns_filter::frameworks::control_client;
use dns_filter::frameworks::control_socket::ControlServer;
use dns_filter::frameworks::database;
use dns_filter::frameworks::database::{
    SqlxFilterCacheRepository, SqlxFilterListRepository, SqlxFilteringConfigRepository,
    SqlxUpstreamConfigRepository, SqlxZoneDiscoveryRepository, SqlxZoneRepository,
};
use dns_filter::frameworks::logging;
use dns_filter::frameworks::metrics::{init_prometheus_metrics, snapshot as metrics_snapshot};
use dns_filter::frameworks::privileges::{
    drop_privileges, PrivilegeDropConfig, DEFAULT_CHROOT_DIR, DEFAULT_GROUP, DEFAULT_USER,
};
use dns_filter::frameworks::signal_handler::{setup_shutdown_signals, setup_sighup_handler};
#[cfg(any(feature = "dot", feature = "doh", feature = "doq"))]
use dns_filter::interface_adapters::listeners::build_tls_config_with_alpn;
use dns_filter::interface_adapters::listeners::handler::HickoryRequestHandler;
#[cfg(feature = "http-api")]
use dns_filter::interface_adapters::listeners::http::{start_api_server, ApiState};
use dns_filter::interface_adapters::listeners::metrics::start_metrics_server;
use dns_filter::interface_adapters::listeners::{bind_tcp_tokio, bind_udp_tokio, parse_bind_addrs};
use dns_filter::use_cases::config_bootstrap::{
    build_any_query_policy, build_dns_request_pipeline_full, build_domain_filter_with_cache,
    build_upstream_resolver, build_zone_entries, resolve_path_for_chroot_host,
    resolve_path_for_chroot_runtime, sqlite_url_for_chroot_host, sqlite_url_for_chroot_runtime,
    validate_config,
};
use dns_filter::use_cases::config_from_db::{apply_db_config, Repositories};
use dns_filter::use_cases::reload::reload_config_from_db_cached;
use dns_filter::use_cases::seed;
#[cfg(any(feature = "http-api", feature = "mcp"))]
use dns_filter::use_cases::server_operations::ServerOperations;
#[cfg(feature = "http-api")]
use std::net::SocketAddr;
#[cfg(feature = "http-api")]
use std::sync::Mutex as StdMutex;

const DEFAULT_CONFIG_PATH: &str = "/etc/dns-filter/config.yaml";

#[derive(Debug, PartialEq, Eq)]
enum CliAction {
    Start {
        config_path: String,
        debug: bool,
        direct: bool,
    },
    Stop {
        config_path: String,
        socket_path: Option<String>,
        direct: bool,
    },
    Reload {
        config_path: String,
        socket_path: Option<String>,
    },
    Status {
        config_path: String,
        socket_path: Option<String>,
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

        /// Run the daemon directly instead of delegating to systemd/OpenRC.
        #[arg(long = "direct")]
        direct: bool,
    },
    /// Stop the running daemon via control socket
    Stop {
        #[arg(
            long = "config",
            value_name = "path",
            default_value = DEFAULT_CONFIG_PATH
        )]
        config_path: String,

        #[arg(long = "socket", value_name = "path")]
        socket_path: Option<String>,

        /// Send stop directly to the control socket instead of delegating to systemd/OpenRC.
        #[arg(long = "direct")]
        direct: bool,
    },
    /// Reload the running daemon's configuration via control socket
    Reload {
        #[arg(
            long = "config",
            value_name = "path",
            default_value = DEFAULT_CONFIG_PATH
        )]
        config_path: String,

        #[arg(long = "socket", value_name = "path")]
        socket_path: Option<String>,
    },
    /// Show daemon status and runtime statistics via control socket
    Status {
        #[arg(
            long = "config",
            value_name = "path",
            default_value = DEFAULT_CONFIG_PATH
        )]
        config_path: String,

        #[arg(long = "socket", value_name = "path")]
        socket_path: Option<String>,
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
        Some(Commands::Start {
            config_path,
            debug,
            direct,
        }) => Ok(CliAction::Start {
            config_path,
            debug,
            direct,
        }),
        Some(Commands::Stop {
            config_path,
            socket_path,
            direct,
        }) => Ok(CliAction::Stop {
            config_path,
            socket_path,
            direct,
        }),
        Some(Commands::Reload {
            config_path,
            socket_path,
        }) => Ok(CliAction::Reload {
            config_path,
            socket_path,
        }),
        Some(Commands::Status {
            config_path,
            socket_path,
        }) => Ok(CliAction::Status {
            config_path,
            socket_path,
        }),
        Some(Commands::MergeConfig {
            config_path,
            overwrite,
        }) => Ok(CliAction::MergeConfig {
            config_path,
            overwrite,
        }),
        None => Err(
            "no subcommand provided. Usage: dns-filter <start|stop|reload|status|merge-config> [OPTIONS]"
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
        CliAction::Start {
            config_path,
            debug,
            direct,
        } => {
            run_start_command(config_path, debug, direct).await;
        }
        CliAction::Stop {
            config_path,
            socket_path,
            direct,
        } => {
            run_stop_command(&config_path, socket_path.as_deref(), direct);
        }
        CliAction::Reload {
            config_path,
            socket_path,
        } => {
            run_control_command(&config_path, socket_path.as_deref(), "reload");
        }
        CliAction::Status {
            config_path,
            socket_path,
        } => {
            run_status_command(&config_path, socket_path.as_deref());
        }
        CliAction::MergeConfig {
            config_path,
            overwrite,
        } => {
            run_merge_config(&config_path, overwrite);
        }
    }
}

async fn run_start_command(config_path: String, debug: bool, _direct: bool) {
    run_daemon(config_path, debug).await;
}

fn run_stop_command(config_path: &str, socket_override: Option<&str>, _direct: bool) {
    run_control_command(config_path, socket_override, "stop");
}

fn resolve_control_socket_path(config_path: &str, socket_override: Option<&str>) -> String {
    if let Some(path) = socket_override {
        return path.to_string();
    }

    match load_config(config_path) {
        Ok(cfg) => {
            let chroot_dir = cfg
                .security
                .as_ref()
                .and_then(|s| s.chroot_dir.as_deref())
                .unwrap_or(DEFAULT_CHROOT_DIR);
            match resolve_path_for_chroot_host(cfg.socket_path(), chroot_dir) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("invalid control socket path in config: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("failed to load config: {e}");
            eprintln!("using default control socket path");
            resolve_path_for_chroot_host(DEFAULT_CONTROL_SOCKET_PATH, DEFAULT_CHROOT_DIR)
                .unwrap_or_else(|_| DEFAULT_CONTROL_SOCKET_PATH.to_string())
        }
    }
}

/// Send a control command (stop/reload) to the running daemon.
fn run_control_command(config_path: &str, socket_override: Option<&str>, command: &str) {
    let socket_path = resolve_control_socket_path(config_path, socket_override);

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

#[derive(Debug, Deserialize)]
struct StatusListInfo {
    name: String,
}

#[derive(Debug, Deserialize)]
struct StatusPayload {
    uptime_seconds: u64,
    filtering_enabled: bool,
    queries_total: u64,
    queries_blocked: u64,
    queries_allowed: u64,
    queries_passthrough: u64,
    lists: Vec<StatusListInfo>,
}

fn run_status_command(config_path: &str, socket_override: Option<&str>) {
    let socket_path = resolve_control_socket_path(config_path, socket_override);

    let resp = match control_client::send_command(&socket_path, "status") {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    if resp.status != "ok" {
        eprintln!(
            "daemon returned error: {}",
            resp.message.unwrap_or_default()
        );
        std::process::exit(1);
    }

    let Some(data) = resp.data else {
        eprintln!("daemon did not return status data");
        std::process::exit(1);
    };

    let payload: StatusPayload = match serde_json::from_value(data) {
        Ok(payload) => payload,
        Err(e) => {
            eprintln!("failed to decode status payload: {e}");
            std::process::exit(1);
        }
    };

    println!("Daemon status: healthy");
    println!("Uptime (s): {}", payload.uptime_seconds);
    println!("Filtering enabled: {}", payload.filtering_enabled);
    println!("Queries total: {}", payload.queries_total);
    println!("Queries blocked: {}", payload.queries_blocked);
    println!("Queries allowed: {}", payload.queries_allowed);
    println!("Queries passthrough: {}", payload.queries_passthrough);
    println!("Filter lists: {}", payload.lists.len());
    if payload.lists.is_empty() {
        println!("List names: (none)");
    } else {
        let names = payload
            .lists
            .iter()
            .map(|list| list.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        println!("List names: {names}");
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
    // Read the raw YAML content before chroot — the file will be inaccessible
    // after chroot, but we need it for reload (infrastructure settings).
    let cached_yaml = match std::fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Could not read the config file.\n  File: {config_path}\n  Reason: {e}");
            std::process::exit(1);
        }
    };

    let mut config = match load_config(&config_path) {
        Ok(cfg) => match validate_config(cfg) {
            Ok(validated) => validated,
            Err(e) => {
                eprintln!("invalid configuration: {e:#}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let security = config.security.as_ref();
    let priv_user = security
        .and_then(|s| s.user.as_deref())
        .unwrap_or(DEFAULT_USER);
    let priv_group = security
        .and_then(|s| s.group.as_deref())
        .unwrap_or(DEFAULT_GROUP);
    let priv_chroot = security
        .and_then(|s| s.chroot_dir.as_deref())
        .unwrap_or(DEFAULT_CHROOT_DIR)
        .to_string();

    // Initialize logging from configuration.
    // Must be done BEFORE drop_privileges() so syslog can access /dev/log.
    let _logging_guard = match logging::init_logging(&config, debug) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("failed to initialize logging: {e:#}");
            std::process::exit(1);
        }
    };

    // Drop privileges early so database and TLS/control files are opened in chroot context.
    let will_chroot = unistd::getuid().is_root();

    let priv_config = PrivilegeDropConfig {
        user: priv_user,
        group: priv_group,
        chroot_dir: Some(Path::new(&priv_chroot)),
    };
    if let Err(e) = drop_privileges(&priv_config) {
        eprintln!("failed to drop privileges: {e:#}");
        std::process::exit(1);
    }

    // --- Initialize database ---
    let db_url = config
        .database
        .as_ref()
        .map(|d| d.url.as_str())
        .unwrap_or(DEFAULT_DATABASE_URL);

    let runtime_db_url = match if will_chroot {
        sqlite_url_for_chroot_runtime(db_url, &priv_chroot)
    } else {
        sqlite_url_for_chroot_host(db_url, &priv_chroot)
    } {
        Ok(url) => url,
        Err(e) => {
            eprintln!("invalid database.url for chroot runtime: {e:#}");
            std::process::exit(1);
        }
    };

    let db_pool = match database::pool::init_pool(&runtime_db_url).await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("failed to initialize database: {e:#}");
            std::process::exit(1);
        }
    };

    let filter_cache: Arc<dyn dns_filter::use_cases::repositories::FilterCacheRepository> =
        Arc::new(SqlxFilterCacheRepository::new(db_pool.clone()));

    let repos = Arc::new(Repositories {
        filter_lists: Box::new(SqlxFilterListRepository::new(db_pool.clone())),
        filter_cache: Arc::clone(&filter_cache),
        filtering_config: Box::new(SqlxFilteringConfigRepository::new(db_pool.clone())),
        upstream_config: Box::new(SqlxUpstreamConfigRepository::new(db_pool.clone())),
        zones: Box::new(SqlxZoneRepository::new(db_pool.clone())),
        zone_discovery: Box::new(SqlxZoneDiscoveryRepository::new(db_pool.clone())),
    });

    // Seed the database from YAML config if the DB is empty.
    match seed::seed_if_empty(&config, &repos).await {
        Ok(true) => tracing::info!("database seeded from YAML configuration"),
        Ok(false) => {}
        Err(e) => {
            eprintln!("failed to seed database: {e:#}");
            std::process::exit(1);
        }
    }

    // Load operational config from the database (source of truth).
    if let Err(e) = apply_db_config(&mut config, &repos).await {
        eprintln!("failed to load operational config from database: {e:#}");
        std::process::exit(1);
    }

    let upstream_resolver = match build_upstream_resolver(&config) {
        Ok(resolver) => resolver,
        Err(e) => {
            eprintln!("invalid upstream configuration: {e:#}");
            std::process::exit(1);
        }
    };

    let domain_filter =
        match build_domain_filter_with_cache(&config, Some(Arc::clone(&filter_cache))) {
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

    // Build the zone registry from searchable zone entries (for MCP/API zone search).
    #[cfg(feature = "mcp")]
    let zone_registry = {
        use dns_filter::use_cases::zone_registry::{ZoneMetadata, ZoneRegistry};
        let searchable_zones: Vec<_> = zone_entries
            .iter()
            .filter_map(|entry| {
                entry.searchable().map(|s| {
                    (
                        Arc::clone(s),
                        ZoneMetadata {
                            bypass_filter: entry.bypass_filter(),
                            fallback_to_default_resolvers: entry.fallback_to_default_resolvers(),
                        },
                    )
                })
            })
            .collect();
        Arc::new(ZoneRegistry::new(searchable_zones))
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
    #[cfg(feature = "dot")]
    if let Some(dot_config) = config.listen.dot.as_ref().filter(|cfg| cfg.enabled) {
        let dot_addrs = match parse_bind_addrs(&dot_config.addresses, dot_config.port) {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("failed to parse DoT bind addresses: {e}");
                std::process::exit(1);
            }
        };
        let mut runtime_tls = dot_config.tls.clone();
        runtime_tls.cert_path = match if will_chroot {
            resolve_path_for_chroot_runtime(&runtime_tls.cert_path, &priv_chroot)
        } else {
            resolve_path_for_chroot_host(&runtime_tls.cert_path, &priv_chroot)
        } {
            Ok(path) => path,
            Err(e) => {
                eprintln!("invalid DoT tls.cert_path: {e:#}");
                std::process::exit(1);
            }
        };
        runtime_tls.key_path = match if will_chroot {
            resolve_path_for_chroot_runtime(&runtime_tls.key_path, &priv_chroot)
        } else {
            resolve_path_for_chroot_host(&runtime_tls.key_path, &priv_chroot)
        } {
            Ok(path) => path,
            Err(e) => {
                eprintln!("invalid DoT tls.key_path: {e:#}");
                std::process::exit(1);
            }
        };

        let tls_config =
            match build_tls_config_with_alpn(&runtime_tls, &dot_config.addresses, b"dot") {
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
    #[cfg(feature = "doh")]
    if let Some(doh_config) = config.listen.doh.as_ref().filter(|cfg| cfg.enabled) {
        let doh_addrs = match parse_bind_addrs(&doh_config.addresses, doh_config.port) {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("failed to parse DoH bind addresses: {e}");
                std::process::exit(1);
            }
        };
        let mut runtime_tls = doh_config.tls.clone();
        runtime_tls.cert_path = match if will_chroot {
            resolve_path_for_chroot_runtime(&runtime_tls.cert_path, &priv_chroot)
        } else {
            resolve_path_for_chroot_host(&runtime_tls.cert_path, &priv_chroot)
        } {
            Ok(path) => path,
            Err(e) => {
                eprintln!("invalid DoH tls.cert_path: {e:#}");
                std::process::exit(1);
            }
        };
        runtime_tls.key_path = match if will_chroot {
            resolve_path_for_chroot_runtime(&runtime_tls.key_path, &priv_chroot)
        } else {
            resolve_path_for_chroot_host(&runtime_tls.key_path, &priv_chroot)
        } {
            Ok(path) => path,
            Err(e) => {
                eprintln!("invalid DoH tls.key_path: {e:#}");
                std::process::exit(1);
            }
        };

        let tls_config =
            match build_tls_config_with_alpn(&runtime_tls, &doh_config.addresses, b"h2") {
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
    #[cfg(feature = "doq")]
    if let Some(doq_config) = config.listen.doq.as_ref().filter(|cfg| cfg.enabled) {
        let doq_addrs = match parse_bind_addrs(&doq_config.addresses, doq_config.port) {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("failed to parse DoQ bind addresses: {e}");
                std::process::exit(1);
            }
        };
        let mut runtime_tls = doq_config.tls.clone();
        runtime_tls.cert_path = match if will_chroot {
            resolve_path_for_chroot_runtime(&runtime_tls.cert_path, &priv_chroot)
        } else {
            resolve_path_for_chroot_host(&runtime_tls.cert_path, &priv_chroot)
        } {
            Ok(path) => path,
            Err(e) => {
                eprintln!("invalid DoQ tls.cert_path: {e:#}");
                std::process::exit(1);
            }
        };
        runtime_tls.key_path = match if will_chroot {
            resolve_path_for_chroot_runtime(&runtime_tls.key_path, &priv_chroot)
        } else {
            resolve_path_for_chroot_host(&runtime_tls.key_path, &priv_chroot)
        } {
            Ok(path) => path,
            Err(e) => {
                eprintln!("invalid DoQ tls.key_path: {e:#}");
                std::process::exit(1);
            }
        };

        let tls_config =
            match build_tls_config_with_alpn(&runtime_tls, &doq_config.addresses, b"doq") {
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

    // Bind control socket inside the chroot runtime filesystem.
    let control_socket_path = match if will_chroot {
        resolve_path_for_chroot_runtime(config.socket_path(), &priv_chroot)
    } else {
        resolve_path_for_chroot_host(config.socket_path(), &priv_chroot)
    } {
        Ok(path) => path,
        Err(e) => {
            eprintln!("invalid control.socket_path for chroot runtime: {e:#}");
            std::process::exit(1);
        }
    };
    let control_server = match ControlServer::bind(&control_socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to bind control socket: {e:#}");
            std::process::exit(1);
        }
    };

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

    let cached_yaml_for_reload = cached_yaml.clone();
    let pipeline_slot_for_reload = Arc::clone(&request_pipeline_slot);
    let filtering_enabled_for_reload = Arc::clone(&filtering_enabled);
    let repos_for_reload = Arc::clone(&repos);

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
            match reload_config_from_db_cached(&cached_yaml_for_reload, &repos_for_reload).await {
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

    // Runtime stats for control status/API/MCP responses.
    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let status_filtering_enabled = Arc::clone(&filtering_enabled);
    let status_domain_filter = Arc::clone(&domain_filter);
    let status_provider = Arc::new(move || {
        let snapshot = metrics_snapshot();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        serde_json::json!({
            "uptime_seconds": now.saturating_sub(start_time),
            "filtering_enabled": status_filtering_enabled.load(Ordering::Relaxed),
            "queries_total": snapshot.queries_total,
            "queries_blocked": snapshot.queries_blocked,
            "queries_allowed": snapshot.queries_allowed,
            "queries_passthrough": snapshot.queries_passthrough,
            "blocklist_hits_total": snapshot.blocklist_hits_total,
            "cache_hits_total": snapshot.cache_hits_total,
            "cache_misses_total": snapshot.cache_misses_total,
            "upstreams": snapshot.upstreams,
            "lists": status_domain_filter.list_names(),
        })
    });

    // Start the control socket server.
    let control_reload_tx = reload_tx.clone();
    let control_shutdown = shutdown.clone();
    let control_task = tokio::spawn(async move {
        control_server
            .serve(control_reload_tx, control_shutdown, Some(status_provider))
            .await;
    });

    // Start the HTTP API server if configured.
    // Clone state for MCP before API takes ownership.

    #[cfg(any(feature = "http-api", feature = "mcp"))]
    let query_log = {
        #[cfg(feature = "http-api")]
        {
            config
                .api
                .as_ref()
                .and_then(|api| api.query_logging.as_ref())
                .filter(|ql| ql.enabled)
                .map(|ql| Arc::new(StdMutex::new(QueryLog::new(ql.max_entries))))
        }
        #[cfg(not(feature = "http-api"))]
        {
            None
        }
    };

    #[cfg(any(feature = "http-api", feature = "mcp"))]
    let server_ops = {
        let ops = ServerOperations::new(
            Arc::clone(&domain_filter),
            Arc::clone(&filtering_enabled),
            query_log,
            reload_tx.clone(),
            start_time,
        )
        .with_repositories(Arc::clone(&repos));
        #[cfg(feature = "mcp")]
        let ops = ops.with_zone_registry(zone_registry);
        Arc::new(ops)
    };

    #[cfg(feature = "http-api")]
    let api_task = spawn_api_server(&config.api, Arc::clone(&server_ops), shutdown.clone());
    #[cfg(not(feature = "http-api"))]
    let api_task: Option<tokio::task::JoinHandle<()>> = None;

    if let Err(error) = init_prometheus_metrics() {
        eprintln!("failed to initialize metrics: {error:#}");
        std::process::exit(1);
    }

    if config
        .listen
        .metrics
        .as_ref()
        .is_some_and(|cfg| cfg.enabled)
    {
        spawn_metrics_servers(&config.listen.metrics);
    }

    // Start the MCP server if configured.
    #[cfg(feature = "mcp")]
    let mcp_task = spawn_mcp_server(&config.mcp, Arc::clone(&server_ops), shutdown.clone());
    #[cfg(not(feature = "mcp"))]
    let mcp_task: Option<tokio::task::JoinHandle<()>> = None;

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

fn spawn_metrics_servers(metrics_config: &Option<MetricsConfig>) {
    let Some(metrics_config) = metrics_config.as_ref().filter(|c| c.enabled) else {
        return;
    };

    let addrs = match parse_bind_addrs(&metrics_config.addresses, metrics_config.port) {
        Ok(addrs) => addrs,
        Err(error) => {
            eprintln!("failed to parse metrics bind addresses: {error}");
            std::process::exit(1);
        }
    };

    for addr in addrs {
        tokio::spawn(async move {
            if let Err(error) = start_metrics_server(addr).await {
                tracing::error!(error = %error, addr = %addr, "metrics server failed");
            }
        });
    }
}

#[cfg(feature = "http-api")]
fn spawn_api_server(
    api_config: &Option<ApiConfig>,
    ops: Arc<ServerOperations>,
    shutdown: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let api_config = api_config.as_ref().filter(|c| c.enabled)?;

    let addr: SocketAddr = format!("{}:{}", api_config.address, api_config.port)
        .parse()
        .unwrap_or_else(|e| {
            eprintln!("invalid API bind address: {e}");
            std::process::exit(1);
        });

    let state = Arc::new(ApiState {
        ops,
        api_token: api_config.api_token.clone(),
        shutdown,
    });

    Some(tokio::spawn(async move {
        if let Err(e) = start_api_server(addr, state).await {
            tracing::error!(error = %e, "HTTP API server failed");
        }
    }))
}

#[cfg(feature = "mcp")]
fn spawn_mcp_server(
    mcp_config: &Option<dns_filter::frameworks::config::schema::McpConfig>,
    ops: Arc<ServerOperations>,
    shutdown: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    use dns_filter::interface_adapters::listeners::mcp::{start_mcp_server, McpServerState};

    let mcp_config = mcp_config.as_ref().filter(|c| c.enabled)?;

    let state = Arc::new(McpServerState { ops, shutdown });

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
                direct: false,
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
                direct: false,
            }
        );
    }

    #[test]
    fn parses_start_with_direct_flag() {
        let parsed =
            parse_cli_args(["dns-filter", "start", "--direct"]).expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Start {
                config_path: DEFAULT_CONFIG_PATH.to_string(),
                debug: false,
                direct: true,
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
                socket_path: None,
                direct: false,
            }
        );
    }

    #[test]
    fn parses_stop_with_socket_override() {
        let parsed = parse_cli_args(["dns-filter", "stop", "--socket", "/tmp/custom.sock"])
            .expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Stop {
                config_path: DEFAULT_CONFIG_PATH.to_string(),
                socket_path: Some("/tmp/custom.sock".to_string()),
                direct: false,
            }
        );
    }

    #[test]
    fn parses_stop_with_direct_flag() {
        let parsed =
            parse_cli_args(["dns-filter", "stop", "--direct"]).expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Stop {
                config_path: DEFAULT_CONFIG_PATH.to_string(),
                socket_path: None,
                direct: true,
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
                socket_path: None,
            }
        );
    }

    #[test]
    fn parses_reload_with_socket_override() {
        let parsed = parse_cli_args(["dns-filter", "reload", "--socket", "/tmp/custom.sock"])
            .expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Reload {
                config_path: DEFAULT_CONFIG_PATH.to_string(),
                socket_path: Some("/tmp/custom.sock".to_string()),
            }
        );
    }

    #[test]
    fn parses_status_subcommand() {
        let parsed = parse_cli_args(["dns-filter", "status"]).expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Status {
                config_path: DEFAULT_CONFIG_PATH.to_string(),
                socket_path: None,
            }
        );
    }

    #[test]
    fn parses_status_with_socket_override() {
        let parsed = parse_cli_args([
            "dns-filter",
            "status",
            "--config",
            "/tmp/test.yaml",
            "--socket",
            "/tmp/custom.sock",
        ])
        .expect("parse should succeed");
        assert_eq!(
            parsed,
            CliAction::Status {
                config_path: "/tmp/test.yaml".to_string(),
                socket_path: Some("/tmp/custom.sock".to_string()),
            }
        );
    }

    #[test]
    fn rejects_status_direct_flag() {
        let err =
            parse_cli_args(["dns-filter", "status", "--direct"]).expect_err("parse should fail");
        assert!(err.contains("--direct"));
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
