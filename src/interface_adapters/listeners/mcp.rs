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
use serde::{Deserialize, Deserializer};
use tokio_util::sync::CancellationToken;

use crate::frameworks::config::schema::McpConfig;
use crate::interface_adapters::listeners::auth::bearer_auth_middleware;
use crate::use_cases::server_operations::{
    deserialize_optional_field, AuthenticationInput, CreateFilterListInput,
    CreateUpstreamServerInput, CreateZoneDiscoveryInput, CreateZoneInput, CreateZoneServerInput,
    ServerOperations, UpdateFilterListInput, UpdateUpstreamServerInput, UpdateZoneDiscoveryInput,
    UpdateZoneInput,
};

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

#[derive(Debug, Deserialize, JsonSchema)]
struct AddFilterListParams {
    /// A unique name for the filter list (alphanumeric, hyphens, underscores)
    name: String,
    /// The URL of the filter list (http://, https://, or file://)
    url: String,
    /// Refresh interval (e.g. "12h", "30m", "3600s"). Default: 12h
    interval: Option<String>,
    /// Whether the list is enabled. Default: true
    enabled: Option<bool>,
    /// List format: adguard, hosts, rpz, domains, or wildcard. Default: adguard
    list_type: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct UpdateFilterListParams {
    /// The name of the filter list to update
    name: String,
    /// New URL for the list
    url: Option<String>,
    /// New refresh interval
    interval: Option<String>,
    /// Enable or disable the list
    enabled: Option<bool>,
    /// New list format
    list_type: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AddUpstreamServerParams {
    /// Whether the upstream server is enabled. Default: true
    enabled: Option<bool>,
    /// Protocol: dns, dot, doh, or recursive
    protocol: String,
    /// Server address (protocol-specific)
    address: String,
    /// Bearer token for DoH authentication
    auth_token: Option<String>,
    /// Username for basic authentication
    auth_username: Option<String>,
    /// Password for basic authentication
    auth_password: Option<String>,
    /// Max hops for recursive resolver
    max_hops: Option<u8>,
    /// IP family for nameserver resolution: ipv4 or ipv6
    nameserver_ip_family: Option<String>,
    /// Path to root hints file (recursive resolver)
    root_hints_path: Option<String>,
    /// Path to root key file (recursive resolver)
    root_key_path: Option<String>,
    /// Enable DNSSEC validation. Default: true
    dnssec: Option<bool>,
    /// Source IP address to bind upstream sockets to
    bind_address: Option<String>,
    /// Linux SO_MARK value for policy routing
    fwmark: Option<u32>,
    /// Optional sort order. If omitted, appends to the end.
    sort_order: Option<i32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct UpdateUpstreamServerParams {
    /// The ID of the upstream server to update
    id: String,
    /// Enable or disable the upstream server
    enabled: Option<bool>,
    /// New protocol
    protocol: Option<String>,
    /// New server address
    address: Option<String>,
    /// Bearer token for DoH authentication
    auth_token: Option<String>,
    /// Username for basic authentication
    auth_username: Option<String>,
    /// Password for basic authentication
    auth_password: Option<String>,
    /// Max hops for recursive resolver
    max_hops: Option<u8>,
    /// IP family for nameserver resolution: ipv4 or ipv6
    nameserver_ip_family: Option<String>,
    /// Path to root hints file (recursive resolver)
    root_hints_path: Option<String>,
    /// Path to root key file (recursive resolver)
    root_key_path: Option<String>,
    /// Enable or disable DNSSEC validation
    dnssec: Option<bool>,
    /// Source IP address to bind upstream sockets to. Pass JSON `null` to
    /// clear the existing value; omit the field to leave it unchanged.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    bind_address: Option<Option<String>>,
    /// Linux SO_MARK value for policy routing. Pass JSON `null` to clear the
    /// existing value; omit the field to leave it unchanged. MCP clients may
    /// also pass string "None" to clear.
    #[serde(default, deserialize_with = "deserialize_optional_fwmark_field")]
    fwmark: Option<Option<u32>>,
    /// New sort order
    sort_order: Option<i32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AddZoneParams {
    /// The zone FQDN (e.g. "home.arpa", "example.com")
    zone: String,
    /// Whether the zone is enabled. Default: true
    enabled: Option<bool>,
    /// Skip blocklist/allowlist filtering for this zone. Default: false
    bypass_filter: Option<bool>,
    /// Fall back to default resolvers on failure. Default: false
    fallback_to_default_resolvers: Option<bool>,
    /// Multi-server strategy (e.g. "failover", "round_robin")
    strategy: Option<String>,
    /// Servers backing this zone (JSON array of server objects)
    servers: Option<Vec<McpZoneServerInput>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct McpZoneServerInput {
    /// Whether this server is enabled. Default: true
    enabled: Option<bool>,
    /// Protocol: dns, dot, doh, recursive, or json
    protocol: String,
    /// Server address (protocol-specific)
    address: String,
    /// Bearer token for authentication
    auth_token: Option<String>,
    /// Username for basic authentication
    auth_username: Option<String>,
    /// Password for basic authentication
    auth_password: Option<String>,
    /// Refresh interval for json protocol (e.g. "15m")
    check_interval: Option<String>,
    /// Max hops for recursive resolver
    max_hops: Option<u8>,
    /// IP family for nameserver resolution: ipv4 or ipv6
    nameserver_ip_family: Option<String>,
    /// Path to root hints file (recursive resolver)
    root_hints_path: Option<String>,
    /// Path to root key file (recursive resolver)
    root_key_path: Option<String>,
    /// Enable DNSSEC validation. Default: true
    dnssec: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct UpdateZoneParams {
    /// The zone FQDN to update
    zone: String,
    /// Enable or disable the zone
    enabled: Option<bool>,
    /// Skip blocklist/allowlist filtering for this zone
    bypass_filter: Option<bool>,
    /// Fall back to default resolvers on failure
    fallback_to_default_resolvers: Option<bool>,
    /// Multi-server strategy
    strategy: Option<String>,
    /// Replace servers (JSON array of server objects). If provided, replaces all existing servers.
    servers: Option<Vec<McpZoneServerInput>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteByNameParams {
    /// The name to delete
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteZoneParams {
    /// The zone FQDN to delete
    zone: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AddZoneDiscoveryParams {
    /// The URL of the zone index endpoint (http:// or https://)
    address: String,
    /// Whether this discovery endpoint is enabled. Default: true
    enabled: Option<bool>,
    /// How often to re-check the index (e.g. "15m", "1h")
    check_interval: Option<String>,
    /// Allowed zone types: forward, reverse, reverse-aggregate. Default: ["forward", "reverse"]
    allowed_types: Option<Vec<String>>,
    /// Skip blocklist/allowlist filtering for discovered zones. Default: false
    bypass_filter: Option<bool>,
    /// Fall back to default resolvers on failure. Default: false
    fallback_to_default_resolvers: Option<bool>,
    /// Bearer token for authentication
    auth_token: Option<String>,
    /// Username for basic authentication
    auth_username: Option<String>,
    /// Password for basic authentication
    auth_password: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct UpdateZoneDiscoveryParams {
    /// The ID of the zone discovery entry to update
    id: String,
    /// New URL for the zone index endpoint
    address: Option<String>,
    /// Enable or disable this discovery endpoint
    enabled: Option<bool>,
    /// New check interval
    check_interval: Option<String>,
    /// New allowed zone types
    allowed_types: Option<Vec<String>>,
    /// Skip blocklist/allowlist filtering for discovered zones
    bypass_filter: Option<bool>,
    /// Fall back to default resolvers on failure
    fallback_to_default_resolvers: Option<bool>,
    /// Bearer token for authentication
    auth_token: Option<String>,
    /// Username for basic authentication
    auth_username: Option<String>,
    /// Password for basic authentication
    auth_password: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteByIdParams {
    /// The ID of the entry to delete
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FwmarkFieldInput {
    Number(u32),
    String(String),
}

/// Serde helper for MCP fwmark updates.
///
/// Accepts omitted (unchanged), null (clear), integer (set),
/// and string "none"/"null" (clear).
fn deserialize_optional_fwmark_field<'de, D>(
    deserializer: D,
) -> Result<Option<Option<u32>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<FwmarkFieldInput>::deserialize(deserializer)?;
    let parsed = match value {
        None => None,
        Some(FwmarkFieldInput::Number(v)) => Some(v),
        Some(FwmarkFieldInput::String(s)) => {
            let trimmed = s.trim();
            if trimmed.eq_ignore_ascii_case("none") || trimmed.eq_ignore_ascii_case("null") {
                None
            } else {
                return Err(serde::de::Error::custom(
                    "fwmark must be an integer, null, or the string 'None'",
                ));
            }
        }
    };
    Ok(Some(parsed))
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

    // --- Blocklist CRUD tools ---

    #[tool(description = "List all configured blocklists with their database configuration")]
    async fn list_blocklists(&self) -> String {
        match self.state.ops.list_filter_lists("block").await {
            Ok(lists) => serde_json::to_string(&lists)
                .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string()),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(
        description = "Add a new blocklist. Requires a unique name and a URL. After adding, a config reload is triggered automatically."
    )]
    async fn add_blocklist(&self, Parameters(params): Parameters<AddFilterListParams>) -> String {
        let input = CreateFilterListInput {
            name: params.name,
            url: params.url,
            interval: params.interval,
            enabled: params.enabled,
            list_type: params.list_type,
        };
        match self.state.ops.add_filter_list("block", input).await {
            Ok(record) => {
                tracing::info!(source = "mcp", name = %record.name, "blocklist added via MCP");
                serde_json::to_string(&record)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(
        description = "Update an existing blocklist by name. Only provided fields are changed. Triggers a config reload."
    )]
    async fn update_blocklist(
        &self,
        Parameters(params): Parameters<UpdateFilterListParams>,
    ) -> String {
        let input = UpdateFilterListInput {
            url: params.url,
            interval: params.interval,
            enabled: params.enabled,
            list_type: params.list_type,
        };
        match self.state.ops.update_filter_list(&params.name, input).await {
            Ok(record) => {
                tracing::info!(source = "mcp", name = %record.name, "blocklist updated via MCP");
                serde_json::to_string(&record)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Delete a blocklist by name. Triggers a config reload.")]
    async fn delete_blocklist(&self, Parameters(params): Parameters<DeleteByNameParams>) -> String {
        match self.state.ops.delete_filter_list(&params.name).await {
            Ok(result) => {
                tracing::info!(source = "mcp", name = %params.name, "blocklist deleted via MCP");
                serde_json::to_string(&result)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    // --- Allowlist CRUD tools ---

    #[tool(description = "List all configured allowlists with their database configuration")]
    async fn list_allowlists(&self) -> String {
        match self.state.ops.list_filter_lists("allow").await {
            Ok(lists) => serde_json::to_string(&lists)
                .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string()),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(
        description = "Add a new allowlist. Requires a unique name and a URL. After adding, a config reload is triggered automatically."
    )]
    async fn add_allowlist(&self, Parameters(params): Parameters<AddFilterListParams>) -> String {
        let input = CreateFilterListInput {
            name: params.name,
            url: params.url,
            interval: params.interval,
            enabled: params.enabled,
            list_type: params.list_type,
        };
        match self.state.ops.add_filter_list("allow", input).await {
            Ok(record) => {
                tracing::info!(source = "mcp", name = %record.name, "allowlist added via MCP");
                serde_json::to_string(&record)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(
        description = "Update an existing allowlist by name. Only provided fields are changed. Triggers a config reload."
    )]
    async fn update_allowlist(
        &self,
        Parameters(params): Parameters<UpdateFilterListParams>,
    ) -> String {
        let input = UpdateFilterListInput {
            url: params.url,
            interval: params.interval,
            enabled: params.enabled,
            list_type: params.list_type,
        };
        match self.state.ops.update_filter_list(&params.name, input).await {
            Ok(record) => {
                tracing::info!(source = "mcp", name = %record.name, "allowlist updated via MCP");
                serde_json::to_string(&record)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Delete an allowlist by name. Triggers a config reload.")]
    async fn delete_allowlist(&self, Parameters(params): Parameters<DeleteByNameParams>) -> String {
        match self.state.ops.delete_filter_list(&params.name).await {
            Ok(result) => {
                tracing::info!(source = "mcp", name = %params.name, "allowlist deleted via MCP");
                serde_json::to_string(&result)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    // --- Upstream server CRUD tools ---

    #[tool(
        description = "List all configured upstream resolver servers with their database configuration"
    )]
    async fn list_upstreams(&self) -> String {
        match self.state.ops.list_upstream_servers().await {
            Ok(servers) => serde_json::to_string(&servers)
                .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string()),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(
        description = "Add a new upstream resolver server. Supports bind_address and fwmark for outbound routing. Triggers a config reload."
    )]
    async fn add_upstream(
        &self,
        Parameters(params): Parameters<AddUpstreamServerParams>,
    ) -> String {
        let input = CreateUpstreamServerInput {
            enabled: params.enabled,
            protocol: params.protocol,
            address: params.address,
            authentication: build_mcp_auth(
                params.auth_token,
                params.auth_username,
                params.auth_password,
            ),
            max_hops: params.max_hops,
            nameserver_ip_family: params.nameserver_ip_family,
            root_hints_path: params.root_hints_path,
            root_key_path: params.root_key_path,
            dnssec: params.dnssec,
            bind_address: params.bind_address,
            fwmark: params.fwmark,
            sort_order: params.sort_order,
        };
        match self.state.ops.add_upstream_server(input).await {
            Ok(record) => {
                tracing::info!(source = "mcp", id = %record.id, "upstream server added via MCP");
                serde_json::to_string(&record)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(
        description = "Update an existing upstream resolver server by ID. Supports bind_address and fwmark changes; pass null for either to clear the stored value. Triggers a config reload."
    )]
    async fn update_upstream(
        &self,
        Parameters(params): Parameters<UpdateUpstreamServerParams>,
    ) -> String {
        let input = UpdateUpstreamServerInput {
            enabled: params.enabled,
            protocol: params.protocol,
            address: params.address,
            authentication: build_mcp_auth(
                params.auth_token,
                params.auth_username,
                params.auth_password,
            ),
            max_hops: params.max_hops,
            nameserver_ip_family: params.nameserver_ip_family,
            root_hints_path: params.root_hints_path,
            root_key_path: params.root_key_path,
            dnssec: params.dnssec,
            bind_address: params.bind_address,
            fwmark: params.fwmark,
            sort_order: params.sort_order,
        };
        match self
            .state
            .ops
            .update_upstream_server(&params.id, input)
            .await
        {
            Ok(record) => {
                tracing::info!(source = "mcp", id = %record.id, "upstream server updated via MCP");
                serde_json::to_string(&record)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Delete an upstream resolver server by ID. Triggers a config reload.")]
    async fn delete_upstream(&self, Parameters(params): Parameters<DeleteByIdParams>) -> String {
        match self.state.ops.delete_upstream_server(&params.id).await {
            Ok(result) => {
                tracing::info!(source = "mcp", id = %params.id, "upstream server deleted via MCP");
                serde_json::to_string(&result)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    // --- Zone CRUD tools ---

    #[tool(
        description = "List all configured zones from the database with their servers and settings"
    )]
    async fn list_zone_configs(&self) -> String {
        match self.state.ops.list_zone_configs().await {
            Ok(zones) => serde_json::to_string(&zones)
                .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string()),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Add a new DNS zone with optional servers. Triggers a config reload.")]
    async fn add_zone(&self, Parameters(params): Parameters<AddZoneParams>) -> String {
        let servers = params
            .servers
            .map(|svrs| svrs.into_iter().map(mcp_server_to_input).collect());
        let input = CreateZoneInput {
            zone: params.zone,
            enabled: params.enabled,
            bypass_filter: params.bypass_filter,
            fallback_to_default_resolvers: params.fallback_to_default_resolvers,
            strategy: params.strategy,
            servers,
        };
        match self.state.ops.add_zone(input).await {
            Ok(record) => {
                tracing::info!(source = "mcp", zone = %record.zone, "zone added via MCP");
                serde_json::to_string(&record)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(
        description = "Update an existing DNS zone by FQDN. Only provided fields are changed. If servers are provided, they replace all existing servers. Triggers a config reload."
    )]
    async fn update_zone(&self, Parameters(params): Parameters<UpdateZoneParams>) -> String {
        let servers = params
            .servers
            .map(|svrs| svrs.into_iter().map(mcp_server_to_input).collect());
        let input = UpdateZoneInput {
            enabled: params.enabled,
            bypass_filter: params.bypass_filter,
            fallback_to_default_resolvers: params.fallback_to_default_resolvers,
            strategy: params.strategy,
            servers,
        };
        match self.state.ops.update_zone(&params.zone, input).await {
            Ok(record) => {
                tracing::info!(source = "mcp", zone = %record.zone, "zone updated via MCP");
                serde_json::to_string(&record)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Delete a DNS zone by FQDN. Triggers a config reload.")]
    async fn delete_zone(&self, Parameters(params): Parameters<DeleteZoneParams>) -> String {
        match self.state.ops.delete_zone(&params.zone).await {
            Ok(result) => {
                tracing::info!(source = "mcp", zone = %params.zone, "zone deleted via MCP");
                serde_json::to_string(&result)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    // --- Zone discovery CRUD tools ---

    #[tool(description = "List all configured zone discovery endpoints from the database")]
    async fn list_zone_discovery(&self) -> String {
        match self.state.ops.list_zone_discovery().await {
            Ok(entries) => serde_json::to_string(&entries)
                .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string()),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(
        description = "Add a new zone discovery endpoint. Requires an address (URL). Triggers a config reload."
    )]
    async fn add_zone_discovery(
        &self,
        Parameters(params): Parameters<AddZoneDiscoveryParams>,
    ) -> String {
        let auth = build_mcp_auth(
            params.auth_token,
            params.auth_username,
            params.auth_password,
        );
        let input = CreateZoneDiscoveryInput {
            enabled: params.enabled,
            address: params.address,
            check_interval: params.check_interval,
            allowed_types: params.allowed_types,
            bypass_filter: params.bypass_filter,
            fallback_to_default_resolvers: params.fallback_to_default_resolvers,
            authentication: auth,
        };
        match self.state.ops.add_zone_discovery(input).await {
            Ok(record) => {
                tracing::info!(source = "mcp", id = %record.id, "zone discovery added via MCP");
                serde_json::to_string(&record)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(
        description = "Update an existing zone discovery endpoint by ID. Only provided fields are changed. Triggers a config reload."
    )]
    async fn update_zone_discovery(
        &self,
        Parameters(params): Parameters<UpdateZoneDiscoveryParams>,
    ) -> String {
        let auth = build_mcp_auth(
            params.auth_token,
            params.auth_username,
            params.auth_password,
        );
        let input = UpdateZoneDiscoveryInput {
            enabled: params.enabled,
            address: params.address,
            check_interval: params.check_interval,
            allowed_types: params.allowed_types,
            bypass_filter: params.bypass_filter,
            fallback_to_default_resolvers: params.fallback_to_default_resolvers,
            authentication: auth,
        };
        match self
            .state
            .ops
            .update_zone_discovery(&params.id, input)
            .await
        {
            Ok(record) => {
                tracing::info!(source = "mcp", id = %record.id, "zone discovery updated via MCP");
                serde_json::to_string(&record)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Delete a zone discovery endpoint by ID. Triggers a config reload.")]
    async fn delete_zone_discovery(
        &self,
        Parameters(params): Parameters<DeleteByIdParams>,
    ) -> String {
        match self.state.ops.delete_zone_discovery(&params.id).await {
            Ok(result) => {
                tracing::info!(source = "mcp", id = %params.id, "zone discovery deleted via MCP");
                serde_json::to_string(&result)
                    .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string())
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }
}

/// Convert MCP zone server input to the use-case input type.
fn mcp_server_to_input(s: McpZoneServerInput) -> CreateZoneServerInput {
    let auth = build_mcp_auth(s.auth_token, s.auth_username, s.auth_password);
    CreateZoneServerInput {
        enabled: s.enabled,
        protocol: s.protocol,
        address: s.address,
        authentication: auth,
        check_interval: s.check_interval,
        max_hops: s.max_hops,
        nameserver_ip_family: s.nameserver_ip_family,
        root_hints_path: s.root_hints_path,
        root_key_path: s.root_key_path,
        dnssec: s.dnssec,
    }
}

/// Build an `AuthenticationInput` from flat MCP fields, returning `None` if all empty.
fn build_mcp_auth(
    token: Option<String>,
    username: Option<String>,
    password: Option<String>,
) -> Option<AuthenticationInput> {
    if token.is_some() || username.is_some() || password.is_some() {
        Some(AuthenticationInput {
            token,
            username,
            password,
        })
    } else {
        None
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

    #[test]
    fn mcp_update_upstream_fwmark_none_string_clears_value() {
        let input: UpdateUpstreamServerParams =
            serde_json::from_str(r#"{"id":"u1","fwmark":"None"}"#).unwrap();
        assert_eq!(input.fwmark, Some(None));
    }

    #[test]
    fn mcp_update_upstream_fwmark_integer_sets_value() {
        let input: UpdateUpstreamServerParams =
            serde_json::from_str(r#"{"id":"u1","fwmark":42}"#).unwrap();
        assert_eq!(input.fwmark, Some(Some(42)));
    }

    #[test]
    fn mcp_update_upstream_fwmark_null_clears_value() {
        let input: UpdateUpstreamServerParams =
            serde_json::from_str(r#"{"id":"u1","fwmark":null}"#).unwrap();
        assert_eq!(input.fwmark, Some(None));
    }
}
