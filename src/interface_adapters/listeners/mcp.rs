use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{middleware, Router};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::tool;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::entities::filter::FilterDecision;
use crate::entities::query_log::QueryLog;
use crate::frameworks::config::schema::McpConfig;
use crate::interface_adapters::listeners::auth::bearer_auth_middleware;
use crate::interface_adapters::listeners::ApiStats;
use crate::use_cases::filtering::DomainFilter;

use super::{bind_tcp, parse_bind_addrs};

/// Shared runtime state accessible by all MCP tool handlers.
pub struct McpServerState {
    pub domain_filter: Arc<dyn DomainFilter>,
    pub filtering_enabled: Arc<AtomicBool>,
    pub query_log: Option<Arc<Mutex<QueryLog>>>,
    pub reload_tx: mpsc::Sender<()>,
    pub start_time: u64,
    pub stats: Arc<ApiStats>,
    pub shutdown: CancellationToken,
}

/// The MCP tool handler. Cloneable wrapper around shared state.
#[derive(Clone)]
struct McpHandler {
    state: Arc<McpServerState>,
}

// --- Tool parameter types ---

#[derive(Debug, Deserialize, JsonSchema)]
struct DnsLookupParams {
    /// The domain name to look up (e.g. "example.com")
    domain: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FilterToggleParams {
    /// Set to true to enable filtering, false to disable
    enabled: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListActionParams {
    /// The name of the filter list
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct OptionalListActionParams {
    /// Optional list name. If omitted, applies to all lists.
    name: Option<String>,
}

// --- Tool implementations ---

#[tool_router]
impl McpHandler {
    #[tool(
        description = "Look up a domain against the DNS filter and return whether it is allowed, blocked, or neutral"
    )]
    async fn dns_lookup(&self, Parameters(params): Parameters<DnsLookupParams>) -> String {
        let decision = self.state.domain_filter.decide(&params.domain);
        let status = match decision {
            FilterDecision::Allow => "allowed",
            FilterDecision::Block => "blocked",
            FilterDecision::Neutral => "neutral (passthrough)",
        };
        serde_json::json!({
            "domain": params.domain,
            "decision": status,
            "filtering_enabled": self.state.filtering_enabled.load(Ordering::Relaxed),
        })
        .to_string()
    }

    #[tool(description = "Get the current filtering status (enabled or disabled)")]
    async fn filter_status(&self) -> String {
        let enabled = self.state.filtering_enabled.load(Ordering::Relaxed);
        serde_json::json!({ "filtering_enabled": enabled }).to_string()
    }

    #[tool(description = "Enable or disable global DNS filtering")]
    async fn filter_toggle(&self, Parameters(params): Parameters<FilterToggleParams>) -> String {
        self.state
            .filtering_enabled
            .store(params.enabled, Ordering::Relaxed);
        let action = if params.enabled {
            "enabled"
        } else {
            "disabled"
        };
        tracing::info!(source = "mcp", "global filtering {action} via MCP");
        serde_json::json!({
            "filtering_enabled": params.enabled,
            "message": format!("filtering {action}"),
        })
        .to_string()
    }

    #[tool(
        description = "List all configured filter lists with their status, domain counts, and configuration"
    )]
    async fn list_filters(&self) -> String {
        let lists = self.state.domain_filter.list_names();
        serde_json::to_string(&lists).unwrap_or_else(|_| "[]".to_string())
    }

    #[tool(
        description = "Trigger a refresh of filter lists. Optionally specify a list name to refresh only that list."
    )]
    async fn refresh_lists(
        &self,
        Parameters(params): Parameters<OptionalListActionParams>,
    ) -> String {
        if let Some(name) = &params.name {
            if self.state.domain_filter.refresh_list(name) {
                tracing::info!(source = "mcp", list = %name, "list refresh triggered via MCP");
                serde_json::json!({
                    "list": name,
                    "status": "refreshing",
                })
                .to_string()
            } else {
                serde_json::json!({
                    "error": format!("list '{}' not found", name),
                })
                .to_string()
            }
        } else {
            let refreshed = self.state.domain_filter.refresh_all_lists();
            tracing::info!(source = "mcp", lists = ?refreshed, "all lists refresh triggered via MCP");
            serde_json::json!({
                "lists_refreshing": refreshed,
            })
            .to_string()
        }
    }

    #[tool(
        description = "Get query statistics including total queries, blocked, allowed, passthrough counts, and uptime"
    )]
    async fn get_stats(&self) -> String {
        let uptime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.state.start_time);

        let lists = self.state.domain_filter.list_names();

        #[derive(Serialize)]
        struct Stats {
            uptime_seconds: u64,
            filtering_enabled: bool,
            queries_total: u64,
            queries_blocked: u64,
            queries_allowed: u64,
            queries_passthrough: u64,
            lists: Vec<crate::use_cases::filtering::ListInfo>,
        }

        let stats = Stats {
            uptime_seconds: uptime,
            filtering_enabled: self.state.filtering_enabled.load(Ordering::Relaxed),
            queries_total: self.state.stats.queries_total.load(Ordering::Relaxed),
            queries_blocked: self.state.stats.queries_blocked.load(Ordering::Relaxed),
            queries_allowed: self.state.stats.queries_allowed.load(Ordering::Relaxed),
            queries_passthrough: self.state.stats.queries_passthrough.load(Ordering::Relaxed),
            lists,
        };
        serde_json::to_string(&stats)
            .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
    }

    #[tool(
        description = "Get the recent DNS query log. Requires query logging to be enabled in config."
    )]
    async fn get_query_log(&self) -> String {
        let Some(ref query_log) = self.state.query_log else {
            return serde_json::json!({
                "error": "query logging is not enabled; set api.query_logging.enabled = true in config",
            })
            .to_string();
        };

        let log = query_log
            .lock()
            .expect("query log lock poisoned while reading");

        #[derive(Serialize)]
        struct QueryLogResponse {
            total: usize,
            max_entries: usize,
            entries: std::collections::VecDeque<crate::entities::query_log::QueryLogEntry>,
        }

        let resp = QueryLogResponse {
            total: log.len(),
            max_entries: log.max_entries(),
            entries: log.entries().clone(),
        };
        serde_json::to_string(&resp)
            .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
    }

    #[tool(description = "Trigger a configuration reload from disk")]
    async fn reload_config(&self) -> String {
        match self.state.reload_tx.send(()).await {
            Ok(()) => {
                tracing::info!(source = "mcp", "configuration reload triggered via MCP");
                serde_json::json!({
                    "status": "triggered",
                    "message": "configuration reload initiated",
                })
                .to_string()
            }
            Err(_) => serde_json::json!({
                "error": "reload channel closed; reload handler not running",
            })
            .to_string(),
        }
    }

    #[tool(description = "Get server health status including version and uptime")]
    async fn server_health(&self) -> String {
        let uptime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.state.start_time);

        serde_json::json!({
            "status": "healthy",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_seconds": uptime,
            "filtering_enabled": self.state.filtering_enabled.load(Ordering::Relaxed),
        })
        .to_string()
    }

    #[tool(description = "Enable a specific filter list by name")]
    async fn enable_list(&self, Parameters(params): Parameters<ListActionParams>) -> String {
        if self.state.domain_filter.enable_list(&params.name) {
            tracing::info!(source = "mcp", list = %params.name, "list enabled via MCP");
            serde_json::json!({
                "list": params.name,
                "enabled": true,
            })
            .to_string()
        } else {
            serde_json::json!({
                "error": format!("list '{}' not found", params.name),
            })
            .to_string()
        }
    }

    #[tool(description = "Disable a specific filter list by name")]
    async fn disable_list(&self, Parameters(params): Parameters<ListActionParams>) -> String {
        if self.state.domain_filter.disable_list(&params.name) {
            tracing::info!(source = "mcp", list = %params.name, "list disabled via MCP");
            serde_json::json!({
                "list": params.name,
                "enabled": false,
            })
            .to_string()
        } else {
            serde_json::json!({
                "error": format!("list '{}' not found", params.name),
            })
            .to_string()
        }
    }
}

#[tool_handler(
    name = "dns-filter",
    instructions = "dns-filter MCP server — manage DNS filtering, view stats, query logs, and perform domain lookups."
)]
impl rmcp::ServerHandler for McpHandler {}

/// Starts the MCP server on the configured addresses. Returns when the server shuts down.
pub async fn start_mcp_server(
    config: &McpConfig,
    state: Arc<McpServerState>,
) -> anyhow::Result<()> {
    let addrs = parse_bind_addrs(&config.addresses, config.port)?;
    let token = Arc::new(config.api_token.clone());
    let shutdown = state.shutdown.clone();

    // Build StreamableHttpServerConfig from McpConfig values.
    let mut server_config = StreamableHttpServerConfig::default()
        .with_stateful_mode(config.stateful_mode)
        .with_json_response(config.json_response)
        .with_cancellation_token(shutdown.clone());

    if let Some(secs) = config.sse_keep_alive {
        server_config = server_config.with_sse_keep_alive(Some(Duration::from_secs(secs)));
    }

    // allowed_hosts: use configured list, or derive from bind addresses + localhost.
    let allowed_hosts: Vec<String> = if let Some(ref hosts) = config.allowed_hosts {
        hosts.clone()
    } else {
        let mut hosts: Vec<String> = config
            .addresses
            .iter()
            .filter(|a| *a != "0.0.0.0" && *a != "::")
            .map(|a| format!("{a}:{}", config.port))
            .collect();
        hosts.push(format!("localhost:{}", config.port));
        hosts.push(format!("127.0.0.1:{}", config.port));
        hosts.push(format!("[::1]:{}", config.port));
        hosts
    };
    server_config = server_config.with_allowed_hosts(allowed_hosts);

    if !config.allowed_origins.is_empty() {
        server_config = server_config.with_allowed_origins(config.allowed_origins.clone());
    }

    let config_for_service = Arc::new(server_config);

    // For each bind address, spawn a server task.
    let mut tasks = Vec::new();

    for addr in &addrs {
        let handler = McpHandler {
            state: Arc::clone(&state),
        };
        let session_manager = Arc::new(LocalSessionManager::default());
        let service_config = (*config_for_service).clone();

        let mcp_service = StreamableHttpService::new(
            move || Ok(handler.clone()),
            session_manager,
            service_config,
        );

        let token_clone = Arc::clone(&token);
        let app = Router::new()
            .nest_service("/mcp", mcp_service)
            .layer(middleware::from_fn(move |req, next| {
                let token = Arc::clone(&token_clone);
                bearer_auth_middleware(req, next, token)
            }));

        let std_listener = bind_tcp(*addr).unwrap_or_else(|e| {
            eprintln!("failed to bind MCP server on {addr}: {e}");
            std::process::exit(1);
        });
        std_listener.set_nonblocking(true).unwrap_or_else(|e| {
            eprintln!("failed to set non-blocking on MCP socket: {e}");
            std::process::exit(1);
        });

        let listener = tokio::net::TcpListener::from_std(std_listener).unwrap_or_else(|e| {
            eprintln!("failed to create tokio listener for MCP on {addr}: {e}");
            std::process::exit(1);
        });

        tracing::info!(address = %addr, "MCP server started");

        let shutdown = shutdown.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    shutdown.cancelled().await;
                })
                .await
            {
                tracing::error!(error = %e, "MCP server failed");
            }
        }));
    }

    // Wait for all listener tasks.
    for task in tasks {
        let _ = task.await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_handler_is_clone() {
        // Verify McpHandler satisfies Clone (required by rmcp)
        fn assert_clone<T: Clone>() {}
        assert_clone::<McpHandler>();
    }
}
