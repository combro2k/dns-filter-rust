use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use serde::Serialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::entities::query_log::{QueryLog, QueryLogEntry};
use crate::use_cases::filtering::DomainFilter;

use super::auth::bearer_auth_middleware;
use super::bind_tcp;
pub use super::ApiStats;

/// Shared runtime state accessible by all API handlers.
pub struct ApiState {
    pub domain_filter: Arc<dyn DomainFilter>,
    pub filtering_enabled: Arc<AtomicBool>,
    pub query_log: Option<Arc<Mutex<QueryLog>>>,
    pub reload_tx: mpsc::Sender<()>,
    pub api_token: Option<String>,
    pub start_time: u64,
    pub stats: Arc<ApiStats>,
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
    #[derive(Serialize)]
    struct HealthResponse {
        status: &'static str,
        uptime_seconds: u64,
    }

    let uptime = now_unix().saturating_sub(state.start_time);
    json_ok(HealthResponse {
        status: "healthy",
        uptime_seconds: uptime,
    })
}

async fn handle_reload(State(state): State<Arc<ApiState>>) -> Response {
    #[derive(Serialize)]
    struct ReloadResponse {
        reload_status: &'static str,
    }

    match state.reload_tx.send(()).await {
        Ok(()) => {
            tracing::info!(source = "api", "configuration reload triggered via API");
            json_ok(ReloadResponse {
                reload_status: "triggered",
            })
        }
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "reload channel closed; reload handler not running",
        ),
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
    state.filtering_enabled.store(false, Ordering::Relaxed);
    tracing::info!(source = "api", "global filtering disabled via API");

    #[derive(Serialize)]
    struct FilteringState {
        enabled: bool,
    }
    json_ok(FilteringState { enabled: false })
}

async fn handle_filtering_enable(State(state): State<Arc<ApiState>>) -> Response {
    state.filtering_enabled.store(true, Ordering::Relaxed);
    tracing::info!(source = "api", "global filtering enabled via API");

    #[derive(Serialize)]
    struct FilteringState {
        enabled: bool,
    }
    json_ok(FilteringState { enabled: true })
}

async fn handle_filtering_status(State(state): State<Arc<ApiState>>) -> Response {
    #[derive(Serialize)]
    struct FilteringState {
        enabled: bool,
    }
    json_ok(FilteringState {
        enabled: state.filtering_enabled.load(Ordering::Relaxed),
    })
}

async fn handle_list_all(State(state): State<Arc<ApiState>>) -> Response {
    let lists = state.domain_filter.list_names();
    json_ok(lists)
}

async fn handle_refresh_all(State(state): State<Arc<ApiState>>) -> Response {
    let refreshed = state.domain_filter.refresh_all_lists();
    tracing::info!(
        source = "api",
        lists = ?refreshed,
        "all lists refresh triggered via API"
    );

    #[derive(Serialize)]
    struct RefreshAllResponse {
        lists_refreshing: Vec<String>,
    }
    json_ok(RefreshAllResponse {
        lists_refreshing: refreshed,
    })
}

async fn handle_refresh_single(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Response {
    if state.domain_filter.refresh_list(&name) {
        tracing::info!(
            source = "api",
            list = %name,
            "list refresh triggered via API"
        );

        #[derive(Serialize)]
        struct RefreshResponse {
            list: String,
            status: &'static str,
        }
        json_ok(RefreshResponse {
            list: name,
            status: "refreshing",
        })
    } else {
        json_error(StatusCode::NOT_FOUND, &format!("list '{name}' not found"))
    }
}

async fn handle_disable_list(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Response {
    if state.domain_filter.disable_list(&name) {
        #[derive(Serialize)]
        struct ListState {
            list: String,
            enabled: bool,
        }
        json_ok(ListState {
            list: name,
            enabled: false,
        })
    } else {
        json_error(StatusCode::NOT_FOUND, &format!("list '{name}' not found"))
    }
}

async fn handle_enable_list(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Response {
    if state.domain_filter.enable_list(&name) {
        #[derive(Serialize)]
        struct ListState {
            list: String,
            enabled: bool,
        }
        json_ok(ListState {
            list: name,
            enabled: true,
        })
    } else {
        json_error(StatusCode::NOT_FOUND, &format!("list '{name}' not found"))
    }
}

async fn handle_stats(State(state): State<Arc<ApiState>>) -> Response {
    #[derive(Serialize)]
    struct StatsResponse {
        uptime_seconds: u64,
        filtering_enabled: bool,
        queries_total: u64,
        queries_blocked: u64,
        queries_allowed: u64,
        queries_passthrough: u64,
        lists: Vec<crate::use_cases::filtering::ListInfo>,
    }

    let uptime = now_unix().saturating_sub(state.start_time);
    let lists = state.domain_filter.list_names();

    json_ok(StatsResponse {
        uptime_seconds: uptime,
        filtering_enabled: state.filtering_enabled.load(Ordering::Relaxed),
        queries_total: state.stats.queries_total.load(Ordering::Relaxed),
        queries_blocked: state.stats.queries_blocked.load(Ordering::Relaxed),
        queries_allowed: state.stats.queries_allowed.load(Ordering::Relaxed),
        queries_passthrough: state.stats.queries_passthrough.load(Ordering::Relaxed),
        lists,
    })
}

async fn handle_query_log(State(state): State<Arc<ApiState>>) -> Response {
    let Some(ref query_log) = state.query_log else {
        return json_error(
            StatusCode::NOT_FOUND,
            "query logging is not enabled; set api.query_logging.enabled = true in config",
        );
    };

    #[derive(Serialize)]
    struct QueryLogResponse {
        total: usize,
        max_entries: usize,
        entries: VecDeque<QueryLogEntry>,
    }

    let log = query_log
        .lock()
        .expect("query log lock poisoned while reading");

    json_ok(QueryLogResponse {
        total: log.len(),
        max_entries: log.max_entries(),
        entries: log.entries().clone(),
    })
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
    fn api_stats_starts_at_zero() {
        use std::sync::atomic::Ordering;
        let stats = ApiStats::new();
        assert_eq!(stats.queries_total.load(Ordering::Relaxed), 0);
        assert_eq!(stats.queries_blocked.load(Ordering::Relaxed), 0);
    }
}
