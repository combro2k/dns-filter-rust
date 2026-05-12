use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const MAX_MESSAGE_BYTES: usize = 1024;
const CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Deserialize)]
struct ControlRequest {
    command: String,
}

#[derive(Debug, Serialize)]
struct ControlResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl ControlResponse {
    fn ok_with_message(msg: &str) -> Self {
        Self {
            status: "ok",
            message: Some(msg.to_string()),
        }
    }

    fn error(msg: &str) -> Self {
        Self {
            status: "error",
            message: Some(msg.to_string()),
        }
    }
}

#[derive(Debug)]
pub struct ControlServer {
    listener: UnixListener,
    socket_path: String,
}

impl ControlServer {
    /// Bind the control socket at `path`.
    ///
    /// Creates the parent directory if needed.  Detects and removes stale
    /// sockets from previous crashed runs.  Fails if a live daemon is already
    /// listening on the socket.
    ///
    /// **Must be called before `drop_privileges()`** because the socket path
    /// (e.g. `/run/dns-filter/`) is typically outside the chroot.  The open
    /// file descriptor survives chroot, so `serve()` continues to work.
    pub fn bind(path: &str) -> Result<Self> {
        // Ensure parent directory exists.
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create control socket directory: {}",
                    parent.display()
                )
            })?;
        }

        // Handle existing socket file (stale detection).
        if Path::new(path).exists() {
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(anyhow!(
                        "another dns-filter daemon is already running (control socket {} is alive)",
                        path
                    ));
                }
                Err(_) => {
                    // Stale socket — remove it.
                    tracing::info!(path = %path, "removing stale control socket");
                    fs::remove_file(path).with_context(|| {
                        format!("failed to remove stale control socket: {path}")
                    })?;
                }
            }
        }

        let listener = UnixListener::bind(path)
            .with_context(|| format!("failed to bind control socket: {path}"))?;

        // Restrict permissions: only root / daemon user+group.
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))
            .with_context(|| format!("failed to set control socket permissions: {path}"))?;

        tracing::info!(path = %path, "control socket bound");

        Ok(Self {
            listener,
            socket_path: path.to_string(),
        })
    }

    /// Accept loop: dispatches `reload` and `stop` commands.
    ///
    /// Runs until a `stop` command is received or the `shutdown` token is
    /// cancelled (e.g. by SIGTERM).  On exit the socket file is removed.
    pub async fn serve(self, reload_tx: mpsc::Sender<()>, shutdown: CancellationToken) {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    tracing::info!("control socket shutting down");
                    break;
                }
                accept_result = self.listener.accept() => {
                    let (stream, _addr) = match accept_result {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!(error = %e, "control socket accept error");
                            continue;
                        }
                    };

                    let result = tokio::time::timeout(
                        CONNECTION_TIMEOUT,
                        Self::handle_connection(stream, &reload_tx, &shutdown),
                    ).await;

                    match result {
                        Ok(Ok(should_stop)) => {
                            if should_stop {
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "control socket connection error");
                        }
                        Err(_) => {
                            tracing::warn!("control socket connection timed out");
                        }
                    }
                }
            }
        }

        self.cleanup();
    }

    async fn handle_connection(
        stream: tokio::net::UnixStream,
        reload_tx: &mpsc::Sender<()>,
        shutdown: &CancellationToken,
    ) -> Result<bool> {
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        let bytes_read = buf_reader
            .read_line(&mut line)
            .await
            .context("failed to read from control socket")?;

        if bytes_read == 0 {
            return Ok(false);
        }

        if bytes_read > MAX_MESSAGE_BYTES {
            let resp = ControlResponse::error("message too large");
            let json = serde_json::to_string(&resp).unwrap_or_default();
            let _ = writer.write_all(format!("{json}\n").as_bytes()).await;
            return Ok(false);
        }

        let request: ControlRequest =
            serde_json::from_str(line.trim()).context("invalid control message JSON")?;

        let (response, should_stop) = match request.command.as_str() {
            "reload" => match reload_tx.send(()).await {
                Ok(()) => {
                    tracing::info!(source = "control_socket", "configuration reload triggered");
                    (ControlResponse::ok_with_message("reload triggered"), false)
                }
                Err(_) => (ControlResponse::error("reload channel closed"), false),
            },
            "stop" => {
                tracing::info!(source = "control_socket", "shutdown requested");
                shutdown.cancel();
                (ControlResponse::ok_with_message("shutdown initiated"), true)
            }
            other => (
                ControlResponse::error(&format!("unknown command: {other}")),
                false,
            ),
        };

        let json = serde_json::to_string(&response).unwrap_or_default();
        let _ = writer.write_all(format!("{json}\n").as_bytes()).await;

        Ok(should_stop)
    }

    fn cleanup(&self) {
        if let Err(e) = fs::remove_file(&self.socket_path) {
            tracing::warn!(
                path = %self.socket_path,
                error = %e,
                "failed to remove control socket on shutdown"
            );
        } else {
            tracing::info!(path = %self.socket_path, "control socket removed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn test_socket_path() -> String {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        format!("/tmp/dns-filter-test-{pid}-{id}.sock")
    }

    #[tokio::test]
    async fn reload_command_sends_to_channel() {
        let path = test_socket_path();
        let server = ControlServer::bind(&path).expect("bind should succeed");
        let (reload_tx, mut reload_rx) = mpsc::channel::<()>(4);
        let shutdown = CancellationToken::new();

        let serve_shutdown = shutdown.clone();
        let serve_handle = tokio::spawn(async move {
            server.serve(reload_tx, serve_shutdown).await;
        });

        // Give server time to start accepting.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connect");
        let (reader, mut writer) = stream.into_split();
        writer
            .write_all(b"{\"command\":\"reload\"}\n")
            .await
            .expect("write");
        let mut buf = BufReader::new(reader);
        let mut resp = String::new();
        buf.read_line(&mut resp).await.expect("read");
        assert!(resp.contains("\"status\":\"ok\""));

        // Reload channel should have received a message.
        let received = reload_rx.try_recv();
        assert!(received.is_ok());

        shutdown.cancel();
        serve_handle.await.expect("serve task");
    }

    #[tokio::test]
    async fn stop_command_shuts_down_server() {
        let path = test_socket_path();
        let server = ControlServer::bind(&path).expect("bind should succeed");
        let (reload_tx, _reload_rx) = mpsc::channel::<()>(4);
        let shutdown = CancellationToken::new();

        let serve_shutdown = shutdown.clone();
        let serve_handle = tokio::spawn(async move {
            server.serve(reload_tx, serve_shutdown).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connect");
        let (reader, mut writer) = stream.into_split();
        writer
            .write_all(b"{\"command\":\"stop\"}\n")
            .await
            .expect("write");
        let mut buf = BufReader::new(reader);
        let mut resp = String::new();
        buf.read_line(&mut resp).await.expect("read");
        assert!(resp.contains("\"status\":\"ok\""));
        assert!(resp.contains("shutdown initiated"));

        // Server should exit.
        tokio::time::timeout(std::time::Duration::from_secs(2), serve_handle)
            .await
            .expect("serve should exit within timeout")
            .expect("serve task");

        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn unknown_command_returns_error() {
        let path = test_socket_path();
        let server = ControlServer::bind(&path).expect("bind should succeed");
        let (reload_tx, _reload_rx) = mpsc::channel::<()>(4);
        let shutdown = CancellationToken::new();

        let serve_shutdown = shutdown.clone();
        let serve_handle = tokio::spawn(async move {
            server.serve(reload_tx, serve_shutdown).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connect");
        let (reader, mut writer) = stream.into_split();
        writer
            .write_all(b"{\"command\":\"explode\"}\n")
            .await
            .expect("write");
        let mut buf = BufReader::new(reader);
        let mut resp = String::new();
        buf.read_line(&mut resp).await.expect("read");
        assert!(resp.contains("\"status\":\"error\""));
        assert!(resp.contains("unknown command"));

        shutdown.cancel();
        serve_handle.await.expect("serve task");
    }

    #[tokio::test]
    async fn stale_socket_is_replaced() {
        let path = test_socket_path();
        // Create a stale socket file.
        let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind std");
        drop(_listener);
        // File exists but nobody is listening.

        let server = ControlServer::bind(&path);
        assert!(server.is_ok(), "should detect stale socket and rebind");
        // Clean up.
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn duplicate_bind_fails() {
        let path = test_socket_path();
        let _server = ControlServer::bind(&path).expect("first bind should succeed");
        // Try binding again while first is alive.
        // The first server is holding the listener, so connecting should succeed
        // and the second bind should fail.

        // We need the server to be actually serving for the connect check to work,
        // but the bind() method uses std::os::unix::net::UnixStream::connect which
        // will succeed as long as the UnixListener fd is open. Drop to simulate
        // a running server by keeping the listener open via _server.
        let result = ControlServer::bind(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already running"));
        let _ = fs::remove_file(&path);
    }
}
