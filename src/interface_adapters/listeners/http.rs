use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::Serialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::entities::query_log::{QueryLog, QueryLogEntry};
use crate::use_cases::filtering::DomainFilter;

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

/// Atomic query counters for stats endpoint.
pub struct ApiStats {
    pub queries_total: AtomicU64,
    pub queries_blocked: AtomicU64,
    pub queries_allowed: AtomicU64,
    pub queries_passthrough: AtomicU64,
}

impl Default for ApiStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiStats {
    pub fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            queries_blocked: AtomicU64::new(0),
            queries_allowed: AtomicU64::new(0),
            queries_passthrough: AtomicU64::new(0),
        }
    }
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

fn json_ok<T: Serialize>(data: T) -> Response<Body> {
    let body = ApiResponse {
        success: true,
        data: Some(data),
        error: None,
        timestamp: now_unix(),
    };
    json_response(StatusCode::OK, &body)
}

fn json_error(status: StatusCode, message: &str) -> Response<Body> {
    let body = ApiResponse::<()> {
        success: false,
        data: None,
        error: Some(message.to_string()),
        timestamp: now_unix(),
    };
    json_response(status, &body)
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<Body> {
    let json = serde_json::to_string(body).unwrap_or_else(|_| r#"{"success":false}"#.to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(json))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .expect("fallback response must be valid")
        })
}

/// Starts the HTTP API server. Returns a handle that resolves when the server shuts down.
pub async fn start_api_server(addr: SocketAddr, state: Arc<ApiState>) -> Result<(), hyper::Error> {
    let make_svc = make_service_fn(move |_conn| {
        let state = Arc::clone(&state);
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(handle_request(req, &state).await) }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    tracing::info!(address = %addr, "HTTP API server started");
    server.await
}

async fn handle_request(req: Request<Body>, state: &ApiState) -> Response<Body> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // Health endpoint — no auth required
    if path == "/health" && method == Method::GET {
        return handle_health(state);
    }

    // All /api/* routes require auth if configured
    if path.starts_with("/api/") {
        if let Some(ref token) = state.api_token {
            match req.headers().get("authorization") {
                Some(value) => {
                    let value = value.to_str().unwrap_or("");
                    let expected = format!("Bearer {token}");
                    if !constant_time_eq(value.as_bytes(), expected.as_bytes()) {
                        return json_error(StatusCode::UNAUTHORIZED, "invalid authorization token");
                    }
                }
                None => {
                    return json_error(StatusCode::UNAUTHORIZED, "authorization header required");
                }
            }
        }
    }

    route(method, &path, state).await
}

/// Constant-time comparison to prevent timing side-channel attacks on token
/// validation. Returns `true` when both slices are equal.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

async fn route(method: Method, path: &str, state: &ApiState) -> Response<Body> {
    match (method.clone(), path) {
        // Reload / Stop
        (Method::POST, "/api/v1/reload") => handle_reload(state).await,
        (Method::POST, "/api/v1/stop") => handle_stop(state),

        // Global filtering
        (Method::POST, "/api/v1/filtering/disable") => handle_filtering_disable(state),
        (Method::POST, "/api/v1/filtering/enable") => handle_filtering_enable(state),
        (Method::GET, "/api/v1/filtering/status") => handle_filtering_status(state),

        // Lists
        (Method::GET, "/api/v1/lists") => handle_list_all(state),
        (Method::POST, "/api/v1/lists/refresh") => handle_refresh_all(state),

        // Stats
        (Method::GET, "/api/v1/stats") => handle_stats(state),

        // Query log
        (Method::GET, "/api/v1/query-log") => handle_query_log(state),

        _ => {
            // Dynamic list routes: /api/v1/lists/{name}/{action}
            if let Some(rest) = path.strip_prefix("/api/v1/lists/") {
                return route_list_action(method, rest, state);
            }
            json_error(StatusCode::NOT_FOUND, "not found")
        }
    }
}

fn route_list_action(method: Method, rest: &str, state: &ApiState) -> Response<Body> {
    let parts: Vec<&str> = rest.splitn(2, '/').collect();
    let name = parts[0];

    if name.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "list name required");
    }

    let action = parts.get(1).copied().unwrap_or("");

    match (method, action) {
        (Method::POST, "refresh") => handle_refresh_single(state, name),
        (Method::POST, "disable") => handle_disable_list(state, name),
        (Method::POST, "enable") => handle_enable_list(state, name),
        _ => json_error(
            StatusCode::NOT_FOUND,
            "unknown list action; supported: refresh, disable, enable",
        ),
    }
}

// --- Handler implementations ---

fn handle_health(state: &ApiState) -> Response<Body> {
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

async fn handle_reload(state: &ApiState) -> Response<Body> {
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

fn handle_stop(state: &ApiState) -> Response<Body> {
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

fn handle_filtering_disable(state: &ApiState) -> Response<Body> {
    state.filtering_enabled.store(false, Ordering::Relaxed);
    tracing::info!(source = "api", "global filtering disabled via API");

    #[derive(Serialize)]
    struct FilteringState {
        enabled: bool,
    }
    json_ok(FilteringState { enabled: false })
}

fn handle_filtering_enable(state: &ApiState) -> Response<Body> {
    state.filtering_enabled.store(true, Ordering::Relaxed);
    tracing::info!(source = "api", "global filtering enabled via API");

    #[derive(Serialize)]
    struct FilteringState {
        enabled: bool,
    }
    json_ok(FilteringState { enabled: true })
}

fn handle_filtering_status(state: &ApiState) -> Response<Body> {
    #[derive(Serialize)]
    struct FilteringState {
        enabled: bool,
    }
    json_ok(FilteringState {
        enabled: state.filtering_enabled.load(Ordering::Relaxed),
    })
}

fn handle_list_all(state: &ApiState) -> Response<Body> {
    let lists = state.domain_filter.list_names();
    json_ok(lists)
}

fn handle_refresh_all(state: &ApiState) -> Response<Body> {
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

fn handle_refresh_single(state: &ApiState, name: &str) -> Response<Body> {
    if state.domain_filter.refresh_list(name) {
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
            list: name.to_string(),
            status: "refreshing",
        })
    } else {
        json_error(StatusCode::NOT_FOUND, &format!("list '{name}' not found"))
    }
}

fn handle_disable_list(state: &ApiState, name: &str) -> Response<Body> {
    if state.domain_filter.disable_list(name) {
        #[derive(Serialize)]
        struct ListState {
            list: String,
            enabled: bool,
        }
        json_ok(ListState {
            list: name.to_string(),
            enabled: false,
        })
    } else {
        json_error(StatusCode::NOT_FOUND, &format!("list '{name}' not found"))
    }
}

fn handle_enable_list(state: &ApiState, name: &str) -> Response<Body> {
    if state.domain_filter.enable_list(name) {
        #[derive(Serialize)]
        struct ListState {
            list: String,
            enabled: bool,
        }
        json_ok(ListState {
            list: name.to_string(),
            enabled: true,
        })
    } else {
        json_error(StatusCode::NOT_FOUND, &format!("list '{name}' not found"))
    }
}

fn handle_stats(state: &ApiState) -> Response<Body> {
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

fn handle_query_log(state: &ApiState) -> Response<Body> {
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
            resp.headers().get("Content-Type").unwrap(),
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
        let stats = ApiStats::new();
        assert_eq!(stats.queries_total.load(Ordering::Relaxed), 0);
        assert_eq!(stats.queries_blocked.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn constant_time_eq_matches_equal_slices() {
        assert!(constant_time_eq(b"secret", b"secret"));
    }

    #[test]
    fn constant_time_eq_rejects_unequal_slices() {
        assert!(!constant_time_eq(b"secret", b"wrong!"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
