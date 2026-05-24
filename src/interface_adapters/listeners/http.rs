use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{middleware, Json, Router};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use utoipa::OpenApi;

use crate::use_cases::filtering::ListInfo;
use crate::use_cases::repository_types::{
    FilterListRecord, ResolverConfigRecord, UpstreamServerRecord, ZoneDiscoveryRecord, ZoneRecord,
};
use crate::use_cases::server_operations::{
    CreateFilterListInput, CreateUpstreamServerInput, CreateZoneDiscoveryInput, CreateZoneInput,
    DeleteResult, FilterStatusResult, FilterToggleResult, HealthResult, ListActionResult,
    QueryLogResult, RefreshAllResult, RefreshResult, ReloadResult, ServerOperationError,
    ServerOperations, StatsResult, UpdateFilterListInput, UpdateResolverConfigInput,
    UpdateUpstreamServerInput, UpdateZoneDiscoveryInput, UpdateZoneInput,
};

use super::auth::bearer_auth_middleware;
use super::bind_tcp;

/// HTTP API-specific server state: shared operations + adapter-only concerns.
pub struct ApiState {
    pub ops: Arc<ServerOperations>,
    pub api_token: Option<String>,
    pub shutdown: CancellationToken,
}

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    timestamp: u64,
}

#[derive(Serialize, utoipa::ToSchema)]
struct StopResponse {
    status: &'static str,
    message: &'static str,
}

#[derive(Serialize, utoipa::ToSchema)]
struct ErrorResponse {
    success: bool,
    error: String,
    timestamp: u64,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn json_ok<T: Serialize>(data: T) -> Response {
    let body = ApiResponse {
        success: true,
        data: Some(data),
        error: None,
        timestamp: now_unix(),
    };
    (StatusCode::OK, Json(body)).into_response()
}

fn json_error(status: StatusCode, message: &str) -> Response {
    let body = ApiResponse::<()> {
        success: false,
        data: None,
        error: Some(message.to_string()),
        timestamp: now_unix(),
    };
    (status, Json(body)).into_response()
}

const ADMIN_PAGE_TEMPLATE: &str = include_str!("../../../templates/admin.html");

fn render_admin_page() -> Html<&'static str> {
    Html(ADMIN_PAGE_TEMPLATE)
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "dns-filter API",
        version = env!("CARGO_PKG_VERSION"),
        description = "DNS filter management API. All responses (except errors) are wrapped in an ApiResponse envelope with `success`, `data`, `error`, and `timestamp` fields.",
    ),
    paths(
        handle_health,
        handle_reload,
        handle_stop,
        handle_filtering_disable,
        handle_filtering_enable,
        handle_filtering_status,
        handle_list_all,
        handle_refresh_all,
        handle_refresh_single,
        handle_disable_list,
        handle_enable_list,
        handle_stats,
        handle_query_log,
        handle_list_blocklists,
        handle_add_blocklist,
        handle_update_blocklist,
        handle_delete_blocklist,
        handle_list_allowlists,
        handle_add_allowlist,
        handle_update_allowlist,
        handle_delete_allowlist,
        handle_get_resolver_config,
        handle_update_resolver_config,
        handle_list_upstreams,
        handle_add_upstream,
        handle_update_upstream,
        handle_delete_upstream,
        handle_list_zone_configs,
        handle_add_zone,
        handle_update_zone,
        handle_delete_zone,
        handle_list_zone_discovery,
        handle_add_zone_discovery,
        handle_update_zone_discovery,
        handle_delete_zone_discovery,
    ),
    components(schemas(
        StopResponse, ErrorResponse,
        HealthResult, ReloadResult, StatsResult,
        FilterStatusResult, FilterToggleResult,
        QueryLogResult, ListActionResult,
        RefreshResult, RefreshAllResult, DeleteResult,
        ListInfo, FilterListRecord, UpstreamServerRecord, ZoneRecord,
        ResolverConfigRecord,
        crate::use_cases::repository_types::ZoneServerRecord,
        ZoneDiscoveryRecord,
        CreateFilterListInput, UpdateFilterListInput,
        UpdateResolverConfigInput,
        CreateUpstreamServerInput, UpdateUpstreamServerInput,
        CreateZoneInput, UpdateZoneInput,
        crate::use_cases::server_operations::CreateZoneServerInput,
        crate::use_cases::server_operations::AuthenticationInput,
        CreateZoneDiscoveryInput, UpdateZoneDiscoveryInput,
        crate::entities::query_log::QueryLogEntry,
        crate::entities::query_log::QueryDecision,
    )),
    security(("bearer_auth" = [])),
    modifiers(&SecurityAddon),
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::Http::new(
                        utoipa::openapi::security::HttpAuthScheme::Bearer,
                    ),
                ),
            );
        }
    }
}

/// Starts the HTTP API server. Returns when the server shuts down.
pub async fn start_api_server(addr: SocketAddr, state: Arc<ApiState>) -> anyhow::Result<()> {
    let token = Arc::new(state.api_token.clone());
    let shutdown = state.shutdown.clone();

    // Authenticated routes
    let api_routes = Router::new()
        .route("/api/v1/reload", post(handle_reload))
        .route("/api/v1/stop", post(handle_stop))
        .route("/api/v1/filtering/disable", post(handle_filtering_disable))
        .route("/api/v1/filtering/enable", post(handle_filtering_enable))
        .route("/api/v1/filtering/status", get(handle_filtering_status))
        .route("/api/v1/lists", get(handle_list_all))
        .route("/api/v1/lists/refresh", post(handle_refresh_all))
        .route("/api/v1/lists/{name}/refresh", post(handle_refresh_single))
        .route("/api/v1/lists/{name}/disable", post(handle_disable_list))
        .route("/api/v1/lists/{name}/enable", post(handle_enable_list))
        .route("/api/v1/stats", get(handle_stats))
        .route("/api/v1/query-log", get(handle_query_log))
        // Blocklist CRUD
        .route("/api/v1/blocklists", get(handle_list_blocklists))
        .route("/api/v1/blocklists", post(handle_add_blocklist))
        .route("/api/v1/blocklists/{name}", put(handle_update_blocklist))
        .route("/api/v1/blocklists/{name}", delete(handle_delete_blocklist))
        // Allowlist CRUD
        .route("/api/v1/allowlists", get(handle_list_allowlists))
        .route("/api/v1/allowlists", post(handle_add_allowlist))
        .route("/api/v1/allowlists/{name}", put(handle_update_allowlist))
        .route("/api/v1/allowlists/{name}", delete(handle_delete_allowlist))
        // Upstream server CRUD
        .route("/api/v1/resolver-config", get(handle_get_resolver_config))
        .route(
            "/api/v1/resolver-config",
            put(handle_update_resolver_config),
        )
        .route("/api/v1/upstreams", get(handle_list_upstreams))
        .route("/api/v1/upstreams", post(handle_add_upstream))
        .route("/api/v1/upstreams/{id}", put(handle_update_upstream))
        .route("/api/v1/upstreams/{id}", delete(handle_delete_upstream))
        // Zone CRUD
        .route("/api/v1/zones", get(handle_list_zone_configs))
        .route("/api/v1/zones", post(handle_add_zone))
        .route("/api/v1/zones/{zone}", put(handle_update_zone))
        .route("/api/v1/zones/{zone}", delete(handle_delete_zone))
        // Zone discovery CRUD
        .route("/api/v1/zone-discovery", get(handle_list_zone_discovery))
        .route("/api/v1/zone-discovery", post(handle_add_zone_discovery))
        .route(
            "/api/v1/zone-discovery/{id}",
            put(handle_update_zone_discovery),
        )
        .route(
            "/api/v1/zone-discovery/{id}",
            delete(handle_delete_zone_discovery),
        )
        // OpenAPI spec
        .route("/api/v1/openapi.json", get(handle_openapi))
        .layer(middleware::from_fn(move |req, next| {
            let token = Arc::clone(&token);
            bearer_auth_middleware(req, next, token)
        }));

    // Unauthenticated routes + merge with authenticated routes
    let app = Router::new()
        .route("/", get(handle_admin_page))
        .route("/admin", get(handle_admin_page))
        .route("/health", get(handle_health))
        .merge(api_routes)
        .with_state(state);

    let std_listener = bind_tcp(addr).unwrap_or_else(|e| {
        eprintln!("failed to bind HTTP API on {addr}: {e}");
        std::process::exit(1);
    });
    std_listener.set_nonblocking(true).unwrap_or_else(|e| {
        eprintln!("failed to set non-blocking on HTTP socket: {e}");
        std::process::exit(1);
    });

    let listener = tokio::net::TcpListener::from_std(std_listener).unwrap_or_else(|e| {
        eprintln!("failed to create tokio listener from socket: {e}");
        std::process::exit(1);
    });

    tracing::info!(address = %addr, "HTTP API server started");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        })
        .await?;
    Ok(())
}

// --- Handler implementations ---

#[utoipa::path(
    get,
    path = "/health",
    tag = "System",
    summary = "Health check",
    responses(
        (status = 200, description = "Server health information", body = HealthResult),
    ),
)]
async fn handle_health(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.server_health();
    json_ok(result)
}

async fn handle_admin_page() -> Html<&'static str> {
    render_admin_page()
}

#[utoipa::path(
    post,
    path = "/api/v1/reload",
    tag = "System",
    summary = "Trigger configuration reload",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Reload triggered", body = ReloadResult),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_reload(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.trigger_reload().await {
        Ok(result) => {
            tracing::info!(source = "api", "configuration reload triggered via API");
            json_ok(result)
        }
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/stop",
    tag = "System",
    summary = "Initiate server shutdown",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Shutdown initiated", body = StopResponse),
    ),
)]
async fn handle_stop(State(state): State<Arc<ApiState>>) -> Response {
    tracing::info!(source = "api", "shutdown requested via API");
    state.shutdown.cancel();
    json_ok(StopResponse {
        status: "ok",
        message: "shutdown initiated",
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/filtering/disable",
    tag = "Filtering",
    summary = "Disable global filtering",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Filtering disabled", body = FilterToggleResult),
    ),
)]
async fn handle_filtering_disable(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.set_filtering(false);
    tracing::info!(source = "api", "global filtering disabled via API");
    json_ok(result)
}

#[utoipa::path(
    post,
    path = "/api/v1/filtering/enable",
    tag = "Filtering",
    summary = "Enable global filtering",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Filtering enabled", body = FilterToggleResult),
    ),
)]
async fn handle_filtering_enable(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.set_filtering(true);
    tracing::info!(source = "api", "global filtering enabled via API");
    json_ok(result)
}

#[utoipa::path(
    get,
    path = "/api/v1/filtering/status",
    tag = "Filtering",
    summary = "Get filtering status",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current filtering status", body = FilterStatusResult),
    ),
)]
async fn handle_filtering_status(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.filter_status();
    json_ok(result)
}

#[utoipa::path(
    get,
    path = "/api/v1/lists",
    tag = "Filter Lists",
    summary = "List all filter lists",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "All filter lists", body = Vec<ListInfo>),
    ),
)]
async fn handle_list_all(State(state): State<Arc<ApiState>>) -> Response {
    let lists = state.ops.list_filters();
    json_ok(lists)
}

#[utoipa::path(
    post,
    path = "/api/v1/lists/refresh",
    tag = "Filter Lists",
    summary = "Refresh all filter lists",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Refresh triggered for all lists", body = RefreshAllResult),
    ),
)]
async fn handle_refresh_all(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.refresh_all_lists();
    tracing::info!(
        source = "api",
        lists = ?result.lists_refreshing,
        "all lists refresh triggered via API"
    );
    json_ok(result)
}

#[utoipa::path(
    post,
    path = "/api/v1/lists/{name}/refresh",
    tag = "Filter Lists",
    summary = "Refresh a specific filter list",
    security(("bearer_auth" = [])),
    params(("name" = String, Path, description = "Filter list name")),
    responses(
        (status = 200, description = "Refresh triggered", body = RefreshResult),
        (status = 404, description = "List not found", body = ErrorResponse),
    ),
)]
async fn handle_refresh_single(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Response {
    match state.ops.refresh_list(&name) {
        Ok(result) => {
            tracing::info!(source = "api", list = %name, "list refresh triggered via API");
            json_ok(result)
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/lists/{name}/disable",
    tag = "Filter Lists",
    summary = "Disable a filter list",
    security(("bearer_auth" = [])),
    params(("name" = String, Path, description = "Filter list name")),
    responses(
        (status = 200, description = "List disabled", body = ListActionResult),
        (status = 404, description = "List not found", body = ErrorResponse),
    ),
)]
async fn handle_disable_list(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Response {
    match state.ops.disable_list(&name) {
        Ok(result) => json_ok(result),
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/lists/{name}/enable",
    tag = "Filter Lists",
    summary = "Enable a filter list",
    security(("bearer_auth" = [])),
    params(("name" = String, Path, description = "Filter list name")),
    responses(
        (status = 200, description = "List enabled", body = ListActionResult),
        (status = 404, description = "List not found", body = ErrorResponse),
    ),
)]
async fn handle_enable_list(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Response {
    match state.ops.enable_list(&name) {
        Ok(result) => json_ok(result),
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/stats",
    tag = "System",
    summary = "Get server statistics",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Server statistics", body = StatsResult),
    ),
)]
async fn handle_stats(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.get_stats();
    json_ok(result)
}

#[utoipa::path(
    get,
    path = "/api/v1/query-log",
    tag = "System",
    summary = "Get DNS query log",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Query log entries", body = QueryLogResult),
        (status = 404, description = "Query log not enabled", body = ErrorResponse),
    ),
)]
async fn handle_query_log(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.get_query_log() {
        Ok(result) => json_ok(result),
        Err(e) => op_error_to_response(e),
    }
}

// --- Blocklist CRUD handlers ---

#[utoipa::path(
    get,
    path = "/api/v1/blocklists",
    tag = "Blocklists",
    summary = "List all blocklists",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "All blocklists", body = Vec<FilterListRecord>),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_list_blocklists(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.list_filter_lists("block").await {
        Ok(lists) => json_ok(lists),
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/blocklists",
    tag = "Blocklists",
    summary = "Add a blocklist",
    security(("bearer_auth" = [])),
    request_body = CreateFilterListInput,
    responses(
        (status = 201, description = "Blocklist created", body = FilterListRecord),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_add_blocklist(
    State(state): State<Arc<ApiState>>,
    Json(input): Json<CreateFilterListInput>,
) -> Response {
    match state.ops.add_filter_list("block", input).await {
        Ok(record) => {
            tracing::info!(source = "api", name = %record.name, "blocklist added via API");
            (
                StatusCode::CREATED,
                Json(ApiResponse {
                    success: true,
                    data: Some(record),
                    error: None,
                    timestamp: now_unix(),
                }),
            )
                .into_response()
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/blocklists/{name}",
    tag = "Blocklists",
    summary = "Update a blocklist",
    security(("bearer_auth" = [])),
    params(("name" = String, Path, description = "Blocklist name")),
    request_body = UpdateFilterListInput,
    responses(
        (status = 200, description = "Blocklist updated", body = FilterListRecord),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
async fn handle_update_blocklist(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(input): Json<UpdateFilterListInput>,
) -> Response {
    match state.ops.update_filter_list(&name, input).await {
        Ok(record) => {
            tracing::info!(source = "api", name = %record.name, "blocklist updated via API");
            json_ok(record)
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/blocklists/{name}",
    tag = "Blocklists",
    summary = "Delete a blocklist",
    security(("bearer_auth" = [])),
    params(("name" = String, Path, description = "Blocklist name")),
    responses(
        (status = 200, description = "Blocklist deleted", body = DeleteResult),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
async fn handle_delete_blocklist(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Response {
    match state.ops.delete_filter_list(&name).await {
        Ok(result) => {
            tracing::info!(source = "api", name = %name, "blocklist deleted via API");
            json_ok(result)
        }
        Err(e) => op_error_to_response(e),
    }
}

// --- Allowlist CRUD handlers ---

#[utoipa::path(
    get,
    path = "/api/v1/allowlists",
    tag = "Allowlists",
    summary = "List all allowlists",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "All allowlists", body = Vec<FilterListRecord>),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_list_allowlists(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.list_filter_lists("allow").await {
        Ok(lists) => json_ok(lists),
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/allowlists",
    tag = "Allowlists",
    summary = "Add an allowlist",
    security(("bearer_auth" = [])),
    request_body = CreateFilterListInput,
    responses(
        (status = 201, description = "Allowlist created", body = FilterListRecord),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_add_allowlist(
    State(state): State<Arc<ApiState>>,
    Json(input): Json<CreateFilterListInput>,
) -> Response {
    match state.ops.add_filter_list("allow", input).await {
        Ok(record) => {
            tracing::info!(source = "api", name = %record.name, "allowlist added via API");
            (
                StatusCode::CREATED,
                Json(ApiResponse {
                    success: true,
                    data: Some(record),
                    error: None,
                    timestamp: now_unix(),
                }),
            )
                .into_response()
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/allowlists/{name}",
    tag = "Allowlists",
    summary = "Update an allowlist",
    security(("bearer_auth" = [])),
    params(("name" = String, Path, description = "Allowlist name")),
    request_body = UpdateFilterListInput,
    responses(
        (status = 200, description = "Allowlist updated", body = FilterListRecord),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
async fn handle_update_allowlist(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(input): Json<UpdateFilterListInput>,
) -> Response {
    match state.ops.update_filter_list(&name, input).await {
        Ok(record) => {
            tracing::info!(source = "api", name = %record.name, "allowlist updated via API");
            json_ok(record)
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/allowlists/{name}",
    tag = "Allowlists",
    summary = "Delete an allowlist",
    security(("bearer_auth" = [])),
    params(("name" = String, Path, description = "Allowlist name")),
    responses(
        (status = 200, description = "Allowlist deleted", body = DeleteResult),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
async fn handle_delete_allowlist(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Response {
    match state.ops.delete_filter_list(&name).await {
        Ok(result) => {
            tracing::info!(source = "api", name = %name, "allowlist deleted via API");
            json_ok(result)
        }
        Err(e) => op_error_to_response(e),
    }
}

// --- Upstream server CRUD handlers ---

#[utoipa::path(
    get,
    path = "/api/v1/resolver-config",
    tag = "Upstreams",
    summary = "Get global resolver configuration",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Resolver config", body = ResolverConfigRecord),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_get_resolver_config(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.get_resolver_config().await {
        Ok(config) => json_ok(config),
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/resolver-config",
    tag = "Upstreams",
    summary = "Update global resolver configuration",
    security(("bearer_auth" = [])),
    request_body = UpdateResolverConfigInput,
    responses(
        (status = 200, description = "Resolver config updated", body = ResolverConfigRecord),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_update_resolver_config(
    State(state): State<Arc<ApiState>>,
    Json(input): Json<UpdateResolverConfigInput>,
) -> Response {
    match state.ops.update_resolver_config(input).await {
        Ok(config) => {
            tracing::info!(source = "api", "resolver config updated via API");
            json_ok(config)
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/upstreams",
    tag = "Upstreams",
    summary = "List all upstream servers",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "All upstream servers", body = Vec<UpstreamServerRecord>),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_list_upstreams(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.list_upstream_servers().await {
        Ok(servers) => json_ok(servers),
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/upstreams",
    tag = "Upstreams",
    summary = "Add an upstream server",
    security(("bearer_auth" = [])),
    request_body = CreateUpstreamServerInput,
    responses(
        (status = 201, description = "Upstream server created", body = UpstreamServerRecord),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_add_upstream(
    State(state): State<Arc<ApiState>>,
    Json(input): Json<CreateUpstreamServerInput>,
) -> Response {
    match state.ops.add_upstream_server(input).await {
        Ok(record) => {
            tracing::info!(source = "api", id = %record.id, "upstream server added via API");
            (
                StatusCode::CREATED,
                Json(ApiResponse {
                    success: true,
                    data: Some(record),
                    error: None,
                    timestamp: now_unix(),
                }),
            )
                .into_response()
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/upstreams/{id}",
    tag = "Upstreams",
    summary = "Update an upstream server",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Upstream server ID")),
    request_body = UpdateUpstreamServerInput,
    responses(
        (status = 200, description = "Upstream server updated", body = UpstreamServerRecord),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
async fn handle_update_upstream(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Json(input): Json<UpdateUpstreamServerInput>,
) -> Response {
    match state.ops.update_upstream_server(&id, input).await {
        Ok(record) => {
            tracing::info!(source = "api", id = %record.id, "upstream server updated via API");
            json_ok(record)
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/upstreams/{id}",
    tag = "Upstreams",
    summary = "Delete an upstream server",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Upstream server ID")),
    responses(
        (status = 200, description = "Upstream server deleted", body = DeleteResult),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
async fn handle_delete_upstream(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Response {
    match state.ops.delete_upstream_server(&id).await {
        Ok(result) => {
            tracing::info!(source = "api", id = %id, "upstream server deleted via API");
            json_ok(result)
        }
        Err(e) => op_error_to_response(e),
    }
}

// --- Zone CRUD handlers ---

#[utoipa::path(
    get,
    path = "/api/v1/zones",
    tag = "Zones",
    summary = "List all zone configurations",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "All zone configurations", body = Vec<ZoneRecord>),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_list_zone_configs(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.list_zone_configs().await {
        Ok(zones) => json_ok(zones),
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/zones",
    tag = "Zones",
    summary = "Add a zone",
    security(("bearer_auth" = [])),
    request_body = CreateZoneInput,
    responses(
        (status = 201, description = "Zone created", body = ZoneRecord),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_add_zone(
    State(state): State<Arc<ApiState>>,
    Json(input): Json<CreateZoneInput>,
) -> Response {
    match state.ops.add_zone(input).await {
        Ok(record) => {
            tracing::info!(source = "api", zone = %record.zone, "zone added via API");
            (
                StatusCode::CREATED,
                Json(ApiResponse {
                    success: true,
                    data: Some(record),
                    error: None,
                    timestamp: now_unix(),
                }),
            )
                .into_response()
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/zones/{zone}",
    tag = "Zones",
    summary = "Update a zone",
    security(("bearer_auth" = [])),
    params(("zone" = String, Path, description = "Zone FQDN")),
    request_body = UpdateZoneInput,
    responses(
        (status = 200, description = "Zone updated", body = ZoneRecord),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
async fn handle_update_zone(
    State(state): State<Arc<ApiState>>,
    Path(zone): Path<String>,
    Json(input): Json<UpdateZoneInput>,
) -> Response {
    match state.ops.update_zone(&zone, input).await {
        Ok(record) => {
            tracing::info!(source = "api", zone = %record.zone, "zone updated via API");
            json_ok(record)
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/zones/{zone}",
    tag = "Zones",
    summary = "Delete a zone",
    security(("bearer_auth" = [])),
    params(("zone" = String, Path, description = "Zone FQDN")),
    responses(
        (status = 200, description = "Zone deleted", body = DeleteResult),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
async fn handle_delete_zone(
    State(state): State<Arc<ApiState>>,
    Path(zone): Path<String>,
) -> Response {
    match state.ops.delete_zone(&zone).await {
        Ok(result) => {
            tracing::info!(source = "api", zone = %zone, "zone deleted via API");
            json_ok(result)
        }
        Err(e) => op_error_to_response(e),
    }
}

// --- Zone discovery CRUD handlers ---

#[utoipa::path(
    get,
    path = "/api/v1/zone-discovery",
    tag = "Zone Discovery",
    summary = "List all zone discovery entries",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "All zone discovery entries", body = Vec<ZoneDiscoveryRecord>),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_list_zone_discovery(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.list_zone_discovery().await {
        Ok(entries) => json_ok(entries),
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/zone-discovery",
    tag = "Zone Discovery",
    summary = "Add a zone discovery entry",
    security(("bearer_auth" = [])),
    request_body = CreateZoneDiscoveryInput,
    responses(
        (status = 201, description = "Zone discovery entry created", body = ZoneDiscoveryRecord),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
)]
async fn handle_add_zone_discovery(
    State(state): State<Arc<ApiState>>,
    Json(input): Json<CreateZoneDiscoveryInput>,
) -> Response {
    match state.ops.add_zone_discovery(input).await {
        Ok(record) => {
            tracing::info!(source = "api", id = %record.id, "zone discovery added via API");
            (
                StatusCode::CREATED,
                Json(ApiResponse {
                    success: true,
                    data: Some(record),
                    error: None,
                    timestamp: now_unix(),
                }),
            )
                .into_response()
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/zone-discovery/{id}",
    tag = "Zone Discovery",
    summary = "Update a zone discovery entry",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Zone discovery entry ID")),
    request_body = UpdateZoneDiscoveryInput,
    responses(
        (status = 200, description = "Zone discovery entry updated", body = ZoneDiscoveryRecord),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
async fn handle_update_zone_discovery(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Json(input): Json<UpdateZoneDiscoveryInput>,
) -> Response {
    match state.ops.update_zone_discovery(&id, input).await {
        Ok(record) => {
            tracing::info!(source = "api", id = %record.id, "zone discovery updated via API");
            json_ok(record)
        }
        Err(e) => op_error_to_response(e),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/zone-discovery/{id}",
    tag = "Zone Discovery",
    summary = "Delete a zone discovery entry",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Zone discovery entry ID")),
    responses(
        (status = 200, description = "Zone discovery entry deleted", body = DeleteResult),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
async fn handle_delete_zone_discovery(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Response {
    match state.ops.delete_zone_discovery(&id).await {
        Ok(result) => {
            tracing::info!(source = "api", id = %id, "zone discovery deleted via API");
            json_ok(result)
        }
        Err(e) => op_error_to_response(e),
    }
}

// --- OpenAPI spec handler ---

async fn handle_openapi() -> Response {
    let spec = ApiDoc::openapi().to_json().unwrap_or_default();
    (StatusCode::OK, [("content-type", "application/json")], spec).into_response()
}

fn op_error_to_response(e: ServerOperationError) -> Response {
    let status = match &e {
        ServerOperationError::NotFound(_) => StatusCode::NOT_FOUND,
        ServerOperationError::Unavailable(_) => StatusCode::NOT_FOUND,
        ServerOperationError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        ServerOperationError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        ServerOperationError::ChannelClosed => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_error(status, &e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_ok_produces_valid_response() {
        let resp = json_ok("hello");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn json_error_produces_error_response() {
        let resp = json_error(StatusCode::NOT_FOUND, "not found");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn op_error_not_found_maps_to_404() {
        let resp = op_error_to_response(ServerOperationError::NotFound("test".to_string()));
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn op_error_channel_closed_maps_to_500() {
        let resp = op_error_to_response(ServerOperationError::ChannelClosed);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn openapi_includes_resolver_config_paths_and_schema() {
        let spec = ApiDoc::openapi().to_json().unwrap();
        assert!(spec.contains("/api/v1/resolver-config"));
        assert!(spec.contains("UpdateResolverConfigInput"));
        assert!(spec.contains("ResolverConfigRecord"));
    }

    #[test]
    fn admin_page_template_contains_tailwind_and_dashboard_bindings() {
        assert!(ADMIN_PAGE_TEMPLATE.contains("https://cdn.tailwindcss.com"));
        assert!(ADMIN_PAGE_TEMPLATE.contains("loadDashboard"));
        assert!(ADMIN_PAGE_TEMPLATE.contains("sessionStorage"));
        assert!(ADMIN_PAGE_TEMPLATE.contains("/api/v1/stats"));
    }
}
