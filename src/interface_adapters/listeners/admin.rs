use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio_util::sync::CancellationToken;

use super::bind_tcp;
use super::http::{api_router, ApiState};
use crate::use_cases::server_operations::ServerOperations;

/// Shared state for the admin UI server.
pub struct AdminState {
    pub ops: Arc<ServerOperations>,
    /// Pre-rendered admin HTML.
    pub admin_html: String,
    /// Optional Bearer token for API authentication (shared with embedded API routes).
    pub api_token: Option<String>,
    pub shutdown: CancellationToken,
}

/// Shared redirect state for the HTTP→HTTPS redirect server.
struct RedirectState {
    tls_port: u16,
    shutdown: CancellationToken,
}

pub const ADMIN_PAGE_TEMPLATE: &str = include_str!("../../../templates/admin.html");

/// Renders the admin page with API_BASE_URL set to empty (same-origin).
fn render_admin_html() -> String {
    ADMIN_PAGE_TEMPLATE.replace("{{API_BASE_URL}}", "")
}

/// Starts the admin UI server(s) with embedded API routes.
///
/// When `tls_config` is provided:
/// - HTTPS server runs on `tls_addr` serving the admin UI + API.
/// - HTTP server runs on `http_addr` issuing 301 redirects to HTTPS.
///
/// When `tls_config` is `None`:
/// - HTTP server runs on `http_addr` serving the admin UI + API directly.
pub async fn start_admin_servers(
    http_addr: SocketAddr,
    tls_addr: Option<SocketAddr>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    tls_port: u16,
    api_token: Option<String>,
    ops: Arc<ServerOperations>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let admin_html = render_admin_html();

    match tls_config {
        Some(tls_cfg) => {
            let tls_addr = tls_addr.expect("tls_addr required when tls_config is provided");

            // Spawn the HTTP→HTTPS redirect server.
            let redirect_shutdown = shutdown.clone();
            let redirect_handle = tokio::spawn(start_redirect_server(
                http_addr,
                tls_port,
                redirect_shutdown,
            ));

            // Run the HTTPS admin server on the current task.
            let https_result =
                start_https_admin_server(tls_addr, tls_cfg, admin_html, api_token, ops, shutdown)
                    .await;

            // If HTTPS exits, cancel the redirect server too.
            redirect_handle.abort();

            https_result
        }
        None => {
            // No TLS — serve admin UI + API over plain HTTP.
            start_http_admin_server(http_addr, admin_html, api_token, ops, shutdown).await
        }
    }
}

/// HTTP admin server serving the admin UI + embedded API over plain HTTP.
async fn start_http_admin_server(
    addr: SocketAddr,
    admin_html: String,
    api_token: Option<String>,
    ops: Arc<ServerOperations>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let state = Arc::new(AdminState {
        ops,
        admin_html,
        api_token,
        shutdown: shutdown.clone(),
    });

    let app = admin_router(state);

    let std_listener = bind_tcp(addr).unwrap_or_else(|e| {
        eprintln!("failed to bind admin HTTP on {addr}: {e}");
        std::process::exit(1);
    });
    std_listener.set_nonblocking(true).unwrap_or_else(|e| {
        eprintln!("failed to set non-blocking on admin HTTP socket: {e}");
        std::process::exit(1);
    });

    let listener = tokio::net::TcpListener::from_std(std_listener).unwrap_or_else(|e| {
        eprintln!("failed to create tokio listener for admin HTTP: {e}");
        std::process::exit(1);
    });

    tracing::info!(address = %addr, "Admin HTTP server started");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        })
        .await?;
    Ok(())
}

/// HTTPS admin server using `tokio-rustls` for TLS termination.
async fn start_https_admin_server(
    addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    admin_html: String,
    api_token: Option<String>,
    ops: Arc<ServerOperations>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let state = Arc::new(AdminState {
        ops,
        admin_html,
        api_token,
        shutdown: shutdown.clone(),
    });

    let app = admin_router(state);
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    let std_listener = bind_tcp(addr).unwrap_or_else(|e| {
        eprintln!("failed to bind admin HTTPS on {addr}: {e}");
        std::process::exit(1);
    });
    std_listener.set_nonblocking(true).unwrap_or_else(|e| {
        eprintln!("failed to set non-blocking on admin HTTPS socket: {e}");
        std::process::exit(1);
    });

    let listener = tokio::net::TcpListener::from_std(std_listener).unwrap_or_else(|e| {
        eprintln!("failed to create tokio listener for admin HTTPS: {e}");
        std::process::exit(1);
    });

    tracing::info!(address = %addr, "Admin HTTPS server started");

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(error = %e, "admin HTTPS accept error");
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                let app = app.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!(peer = %peer, error = %e, "admin TLS handshake failed");
                            return;
                        }
                    };

                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper_util::service::TowerToHyperService::new(app);

                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, service)
                    .await
                    {
                        tracing::debug!(peer = %peer, error = %e, "admin HTTPS connection error");
                    }
                });
            }
            _ = shutdown.cancelled() => {
                tracing::info!("admin HTTPS server shutting down");
                break;
            }
        }
    }
    Ok(())
}

/// HTTP server that redirects all requests to HTTPS with 301 Moved Permanently.
async fn start_redirect_server(
    addr: SocketAddr,
    tls_port: u16,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let state = Arc::new(RedirectState {
        tls_port,
        shutdown: shutdown.clone(),
    });

    let app = Router::new().fallback(handle_redirect).with_state(state);

    let std_listener = bind_tcp(addr).unwrap_or_else(|e| {
        eprintln!("failed to bind admin HTTP redirect on {addr}: {e}");
        std::process::exit(1);
    });
    std_listener.set_nonblocking(true).unwrap_or_else(|e| {
        eprintln!("failed to set non-blocking on admin HTTP redirect socket: {e}");
        std::process::exit(1);
    });

    let listener = tokio::net::TcpListener::from_std(std_listener).unwrap_or_else(|e| {
        eprintln!("failed to create tokio listener for admin HTTP redirect: {e}");
        std::process::exit(1);
    });

    tracing::info!(address = %addr, "Admin HTTP→HTTPS redirect server started");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        })
        .await?;
    Ok(())
}

/// Builds the admin UI router with embedded API routes.
///
/// The admin listener serves the UI pages, the health endpoint, and all
/// `/api/v1/*` routes on the same origin so the browser never needs
/// cross-origin requests.
fn admin_router(state: Arc<AdminState>) -> Router {
    // Build an ApiState from the AdminState for the embedded API routes.
    let api_state = Arc::new(ApiState {
        ops: Arc::clone(&state.ops),
        api_token: state.api_token.clone(),
        shutdown: state.shutdown.clone(),
    });
    let api = api_router(&api_state.api_token).with_state(api_state);

    Router::new()
        .route("/", get(handle_admin_page))
        .route("/admin", get(handle_admin_page))
        .route("/health", get(handle_health))
        .merge(api)
        .with_state(state)
}

async fn handle_admin_page(State(state): State<Arc<AdminState>>) -> Html<String> {
    Html(state.admin_html.clone())
}

async fn handle_health(State(state): State<Arc<AdminState>>) -> Response {
    let result = state.ops.server_health();
    let body = serde_json::to_string(&result).unwrap_or_else(|_| r#"{"status":"error"}"#.into());
    (StatusCode::OK, [("content-type", "application/json")], body).into_response()
}

/// Redirects any request to the HTTPS equivalent using 301 Moved Permanently.
async fn handle_redirect(
    State(state): State<Arc<RedirectState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    // Strip the port from the Host header (if present) to replace with TLS port.
    let hostname = host.split(':').next().unwrap_or(host);

    let location = if state.tls_port == 443 {
        format!("https://{hostname}{}", uri.path())
    } else {
        format!("https://{hostname}:{}{}", state.tls_port, uri.path())
    };

    (StatusCode::MOVED_PERMANENTLY, [("location", location)]).into_response()
}
