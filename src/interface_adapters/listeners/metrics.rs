use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::frameworks::metrics::collect_metrics;

const READ_LIMIT: usize = 4096;

pub async fn start_metrics_server(addr: SocketAddr) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "Metrics listener bound");

    loop {
        let (stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream).await {
                tracing::debug!(peer = %peer, error = %error, "metrics connection failed");
            }
        });
    }
}

/// Starts a metrics server with optional TLS.
pub async fn start_metrics_server_tls(
    addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    tracing::info!(addr = %addr, "Metrics HTTPS listener bound");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(error) = handle_tls_connection(tls_stream).await {
                        tracing::debug!(peer = %peer, error = %error, "metrics TLS connection failed");
                    }
                }
                Err(error) => {
                    tracing::debug!(peer = %peer, error = %error, "metrics TLS handshake failed");
                }
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    let mut buf = [0u8; READ_LIMIT];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let req = String::from_utf8_lossy(&buf[..n]);
    let first_line = req.lines().next().unwrap_or_default();

    let response = build_response(first_line);
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

async fn handle_tls_connection(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
) -> io::Result<()> {
    let mut buf = [0u8; READ_LIMIT];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let req = String::from_utf8_lossy(&buf[..n]);
    let first_line = req.lines().next().unwrap_or_default();

    let response = build_response(first_line);
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

fn build_response(first_line: &str) -> String {
    if first_line.starts_with("GET /metrics ") || first_line == "GET /metrics" {
        let body = collect_metrics().unwrap_or_else(|_| "".to_string());
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    } else {
        let body = "Not Found";
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }
}
