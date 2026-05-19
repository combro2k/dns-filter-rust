use std::sync::Arc;
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
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::frameworks::config::schema::McpConfig;
use crate::interface_adapters::listeners::auth::bearer_auth_middleware;
use crate::use_cases::server_operations::ServerOperations;

use super::{bind_tcp, parse_bind_addrs};

/// MCP-specific server state: shared operations + adapter-only concerns.
pub struct McpServerState {
    pub ops: Arc<ServerOperations>,
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

#[derive(Debug, Deserialize, JsonSchema)]
struct ZoneSearchParams {
    /// Search query to fuzzy-match against domain names in zones
    query: String,
    /// Optional zone name to limit the search to a specific zone
    zone: Option<String>,
    /// Optional record type filter (e.g. "A", "AAAA", "CNAME", "MX")
    record_type: Option<String>,
    /// Maximum number of results to return (default: 50, max: 500)
    limit: Option<usize>,
}

// --- Tool implementations ---

#[tool_router]
impl McpHandler {
    #[tool(
        description = "Look up a domain against the DNS filter and return whether it is allowed, blocked, or neutral"
    )]
    async fn dns_lookup(&self, Parameters(params): Parameters<DnsLookupParams>) -> String {
        let result = self.state.ops.dns_lookup(&params.domain);
        serde_json::to_string(&result)
            .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
    }

    #[tool(description = "Get the current filtering status (enabled or disabled)")]
    async fn filter_status(&self) -> String {
        let result = self.state.ops.filter_status();
        serde_json::to_string(&result)
            .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
    }

    #[tool(description = "Enable or disable global DNS filtering")]
    async fn filter_toggle(&self, Parameters(params): Parameters<FilterToggleParams>) -> String {
        let result = self.state.ops.set_filtering(params.enabled);
        tracing::info!(
            source = "mcp",
            "global filtering {} via MCP",
            if params.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        serde_json::to_string(&result)
            .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
    }

    #[tool(
        description = "List all configured filter lists with their status, domain counts, and configuration"
    )]
    async fn list_filters(&self) -> String {
        let lists = self.state.ops.list_filters();
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
            match self.state.ops.refresh_list(name) {
                Ok(result) => {
                    tracing::info!(source = "mcp", list = %name, "list refresh triggered via MCP");
                    serde_json::to_string(&result)
                        .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
                }
                Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
            }
        } else {
            let result = self.state.ops.refresh_all_lists();
            tracing::info!(source = "mcp", lists = ?result.lists_refreshing, "all lists refresh triggered via MCP");
            serde_json::to_string(&result)
                .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
        }
    }

    #[tool(
        description = "Get query statistics including total queries, blocked, allowed, passthrough counts, and uptime"
    )]
    async fn get_stats(&self) -> String {
        let result = self.state.ops.get_stats();
        serde_json::to_string(&result)
            .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
    }

    #[tool(
        description = "Get the recent DNS query log. Requires query logging to be enabled in config."
    )]
    async fn get_query_log(&self) -> String {
        match self.state.ops.get_query_log() {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string()),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Trigger a configuration reload from disk")]
    async fn reload_config(&self) -> String {
        match self.state.ops.trigger_reload().await {
            Ok(result) => {
                tracing::info!(source = "mcp", "configuration reload triggered via MCP");
                serde_json::to_string(&result)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Get server health status including version and uptime")]
    async fn server_health(&self) -> String {
        let result = self.state.ops.server_health();
        serde_json::to_string(&result)
            .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
    }

    #[tool(description = "Enable a specific filter list by name")]
    async fn enable_list(&self, Parameters(params): Parameters<ListActionParams>) -> String {
        match self.state.ops.enable_list(&params.name) {
            Ok(result) => {
                tracing::info!(source = "mcp", list = %params.name, "list enabled via MCP");
                serde_json::to_string(&result)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Disable a specific filter list by name")]
    async fn disable_list(&self, Parameters(params): Parameters<ListActionParams>) -> String {
        match self.state.ops.disable_list(&params.name) {
            Ok(result) => {
                tracing::info!(source = "mcp", list = %params.name, "list disabled via MCP");
                serde_json::to_string(&result)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "List all configured DNS zones with record counts and metadata")]
    async fn list_zones(&self) -> String {
        match self.state.ops.list_zones() {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string()),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(
        description = "Search for DNS records across zones using fuzzy domain name matching. Supports filtering by zone, record type, and result limit."
    )]
    async fn search_zone_records(
        &self,
        Parameters(params): Parameters<ZoneSearchParams>,
    ) -> String {
        match self.state.ops.search_zone_records(
            &params.query,
            params.zone.as_deref(),
            params.record_type.as_deref(),
            params.limit,
        ) {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string()),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
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
