//! Unix signal handling for graceful reloads and shutdowns.

use std::io;

/// Set up a listener for SIGHUP signal that triggers configuration reload.
///
/// Returns a receiver that emits `()` each time SIGHUP is received.
/// This is used by the main event loop to trigger configuration reload.
///
/// # Errors
/// Returns an error if the signal handler cannot be installed (e.g., on non-Unix platforms).
pub fn setup_sighup_handler() -> io::Result<tokio::sync::mpsc::Receiver<()>> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);

    let mut signal_stream = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    tokio::spawn(async move {
        while signal_stream.recv().await.is_some() {
            tracing::info!("SIGHUP received, triggering configuration reload");
            // If the receiver is closed (channel full or app shutting down), stop trying to send
            if tx.send(()).await.is_err() {
                break;
            }
        }
    });

    Ok(rx)
}
