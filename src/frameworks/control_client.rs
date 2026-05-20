use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
pub struct ControlResponse {
    pub status: String,
    pub message: Option<String>,
    pub data: Option<serde_json::Value>,
}

/// Send a control command to the running daemon via Unix socket.
///
/// Returns the parsed response on success, or a descriptive error if the
/// daemon is unreachable or responds with an error status.
pub fn send_command(socket_path: &str, command: &str) -> Result<ControlResponse> {
    let stream = UnixStream::connect_addr(
        &std::os::unix::net::SocketAddr::from_pathname(socket_path)
            .context("invalid control socket path")?,
    )
    .map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => anyhow!(
            "control socket not found at {socket_path}\n\
             Hint: is the dns-filter daemon running? Start it with: dns-filter start"
        ),
        io::ErrorKind::ConnectionRefused => anyhow!(
            "connection refused at {socket_path}\n\
             Hint: the daemon may have crashed. Check logs and restart."
        ),
        io::ErrorKind::PermissionDenied => anyhow!(
            "permission denied connecting to {socket_path}\n\
             Hint: the control socket is restricted. Try running as root or the daemon's user/group."
        ),
        _ => anyhow!("failed to connect to control socket {socket_path}: {e}"),
    })?;

    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .context("failed to set read timeout on control socket")?;
    stream
        .set_write_timeout(Some(CONNECT_TIMEOUT))
        .context("failed to set write timeout on control socket")?;

    let request = format!("{{\"command\":\"{command}\"}}\n");

    let mut writer = io::BufWriter::new(&stream);
    writer
        .write_all(request.as_bytes())
        .context("failed to send command to daemon")?;
    writer
        .flush()
        .context("failed to flush command to daemon")?;

    let mut reader = io::BufReader::new(&stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .context("failed to read response from daemon (timed out?)")?;

    if response_line.is_empty() {
        return Err(anyhow!("daemon closed connection without responding"));
    }

    let response: ControlResponse =
        serde_json::from_str(response_line.trim()).context("failed to parse daemon response")?;

    Ok(response)
}
