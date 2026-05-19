use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{middleware, Json, Router};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::use_cases::server_operations::{
    CreateFilterListInput, CreateZoneDiscoveryInput, CreateZoneInput, ServerOperationError,
    ServerOperations, UpdateFilterListInput, UpdateZoneDiscoveryInput, UpdateZoneInput,
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
        .layer(middleware::from_fn(move |req, next| {
            let token = Arc::clone(&token);
            bearer_auth_middleware(req, next, token)
        }));

    // Unauthenticated routes + merge with authenticated routes
    let app = Router::new()
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

async fn handle_health(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.server_health();
    json_ok(result)
}

async fn handle_reload(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.trigger_reload().await {
        Ok(result) => {
            tracing::info!(source = "api", "configuration reload triggered via API");
            json_ok(result)
        }
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn handle_stop(State(state): State<Arc<ApiState>>) -> Response {
    tracing::info!(source = "api", "shutdown requested via API");
    state.shutdown.cancel();

    #[derive(Serialize)]
    struct StopResponse {
        status: &'static str,
        message: &'static str,
    }
    json_ok(StopResponse {
        status: "ok",
        message: "shutdown initiated",
    })
}

async fn handle_filtering_disable(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.set_filtering(false);
    tracing::info!(source = "api", "global filtering disabled via API");
    json_ok(result)
}

async fn handle_filtering_enable(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.set_filtering(true);
    tracing::info!(source = "api", "global filtering enabled via API");
    json_ok(result)
}

async fn handle_filtering_status(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.filter_status();
    json_ok(result)
}

async fn handle_list_all(State(state): State<Arc<ApiState>>) -> Response {
    let lists = state.ops.list_filters();
    json_ok(lists)
}

async fn handle_refresh_all(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.refresh_all_lists();
    tracing::info!(
        source = "api",
        lists = ?result.lists_refreshing,
        "all lists refresh triggered via API"
    );
    json_ok(result)
}

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

async fn handle_disable_list(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Response {
    match state.ops.disable_list(&name) {
        Ok(result) => json_ok(result),
        Err(e) => op_error_to_response(e),
    }
}

async fn handle_enable_list(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Response {
    match state.ops.enable_list(&name) {
        Ok(result) => json_ok(result),
        Err(e) => op_error_to_response(e),
    }
}

async fn handle_stats(State(state): State<Arc<ApiState>>) -> Response {
    let result = state.ops.get_stats();
    json_ok(result)
}

async fn handle_query_log(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.get_query_log() {
        Ok(result) => json_ok(result),
        Err(e) => op_error_to_response(e),
    }
}

// --- Blocklist CRUD handlers ---

async fn handle_list_blocklists(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.list_filter_lists("block").await {
        Ok(lists) => json_ok(lists),
        Err(e) => op_error_to_response(e),
    }
}

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

async fn handle_list_allowlists(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.list_filter_lists("allow").await {
        Ok(lists) => json_ok(lists),
        Err(e) => op_error_to_response(e),
    }
}

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

// --- Zone CRUD handlers ---

async fn handle_list_zone_configs(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.list_zone_configs().await {
        Ok(zones) => json_ok(zones),
        Err(e) => op_error_to_response(e),
    }
}

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

async fn handle_list_zone_discovery(State(state): State<Arc<ApiState>>) -> Response {
    match state.ops.list_zone_discovery().await {
        Ok(entries) => json_ok(entries),
        Err(e) => op_error_to_response(e),
    }
}

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
}
