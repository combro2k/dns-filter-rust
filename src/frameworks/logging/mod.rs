pub mod syslog;

use anyhow::Context;
use std::io;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, Layer, Registry};

use crate::frameworks::config::schema::DnsFilterConfig;

/// Guard to keep background logging tasks alive.
pub struct LoggingGuard {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    _syslog_task: Option<tokio::task::JoinHandle<()>>,
}

/// Initialize logging from configuration.
///
/// This must be called:
/// 1. AFTER config is loaded
/// 2. BEFORE drop_privileges() (so syslog can access /dev/log)
/// 3. Replaces any previous tracing subscriber initialization
pub fn init_logging(config: &DnsFilterConfig, debug: bool) -> anyhow::Result<LoggingGuard> {
    let logging_config = &config.logging;

    // Parse log levels from config, with defaults
    let stdout_level = logging_config
        .stdout
        .as_ref()
        .and_then(|s| syslog::level_from_str(&s.level))
        .unwrap_or(tracing::Level::INFO);

    let file_level = logging_config
        .file
        .as_ref()
        .and_then(|f| syslog::level_from_str(&f.level))
        .unwrap_or(tracing::Level::DEBUG);

    let syslog_level = logging_config
        .syslog
        .as_ref()
        .and_then(|s| syslog::level_from_str(&s.level))
        .unwrap_or(tracing::Level::INFO);

    let mut file_guard = None;
    let mut syslog_task = None;

    // Check if we have any enabled logging targets
    let has_stdout = logging_config
        .stdout
        .as_ref()
        .map(|c| c.enabled)
        .unwrap_or(false);
    let has_file = logging_config
        .file
        .as_ref()
        .map(|c| c.enabled)
        .unwrap_or(false);
    let has_syslog = logging_config
        .syslog
        .as_ref()
        .map(|c| c.enabled)
        .unwrap_or(false);

    let fallback_level = if debug {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    let stdout_layer = if has_stdout {
        Some(
            fmt::layer()
                .with_writer(io::stdout)
                .with_target(true)
                .with_thread_ids(true)
                .with_span_events(FmtSpan::CLOSE)
                .with_filter(build_env_filter(stdout_level, debug)),
        )
    } else {
        None
    };

    let file_layer = if has_file {
        let file_cfg = logging_config.file.as_ref().expect("checked enabled above");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_cfg.location)
            .with_context(|| format!("opening log file {}", file_cfg.location))?;
        let file_appender = file;
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        file_guard = Some(guard);

        Some(
            fmt::layer()
                .with_writer(non_blocking)
                .with_target(true)
                .with_thread_ids(true)
                .with_span_events(FmtSpan::CLOSE)
                .with_ansi(false)
                .with_filter(build_env_filter(file_level, debug)),
        )
    } else {
        None
    };

    let syslog_layer = if has_syslog {
        let syslog_cfg = logging_config.syslog.as_ref().unwrap();
        let transport = syslog::SyslogTransport::from_config(
            syslog_cfg.transport.as_deref(),
            syslog_cfg.server.as_deref(),
            syslog_cfg
                .tls
                .as_ref()
                .and_then(|t| t.ca_cert_path.as_deref()),
        )
        .context("building syslog transport")?;

        let facility =
            syslog::facility_from_str(&syslog_cfg.facility).context("parsing syslog facility")?;

        let format = syslog_cfg
            .format
            .as_deref()
            .unwrap_or("rfc3164")
            .to_string();

        let (sender, task) = syslog::SyslogSender::new(transport, facility, format.clone());
        syslog_task = Some(task);

        Some(SyslogLayer { sender }.with_filter(build_env_filter(
            if debug {
                tracing::Level::DEBUG
            } else {
                syslog_level
            },
            debug,
        )))
    } else {
        None
    };

    if !has_stdout && !has_file && !has_syslog {
        Registry::default()
            .with(
                fmt::layer()
                    .with_writer(io::stderr)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_filter(build_env_filter(fallback_level, debug)),
            )
            .init();
    } else {
        Registry::default()
            .with(stdout_layer)
            .with(file_layer)
            .with(syslog_layer)
            .init();
    }

    Ok(LoggingGuard {
        _file_guard: file_guard,
        _syslog_task: syslog_task,
    })
}

/// Build an `EnvFilter` for the given base level.
///
/// In normal mode, suppresses noisy third-party crate modules (hickory DNSSEC
/// validation warnings such as "response does not contain NSEC or NSEC3 records")
/// to ERROR-only.  In debug mode all messages pass through unfiltered.
fn build_env_filter(level: tracing::Level, debug: bool) -> EnvFilter {
    if debug {
        EnvFilter::new(format!("{level}"))
    } else {
        EnvFilter::new(format!(
            "{level},hickory_proto=error,hickory_resolver=error"
        ))
    }
}

/// Custom tracing layer for syslog output.
struct SyslogLayer {
    sender: syslog::SyslogSender,
}

impl<S> Layer<S> for SyslogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let metadata = event.metadata();

        // Format the event message
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let msg = syslog::SyslogMessage {
            level: *metadata.level(),
            msg: visitor.message,
        };

        self.sender.send(msg);
    }
}

/// Helper to extract the formatted message from a tracing event.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_stdout_level() {
        let level = "info";
        let parsed = syslog::level_from_str(level);
        assert_eq!(parsed, Some(tracing::Level::INFO));
    }

    #[test]
    fn facility_local0() {
        let code = syslog::facility_code("local0").unwrap();
        assert_eq!(code, 16);
    }
}
