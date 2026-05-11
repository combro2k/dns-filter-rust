use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use syslog::{Facility, Formatter3164, Formatter5424, Logger, LoggerBackend};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Syslog facility codes (RFC 5424).
pub fn facility_code(facility: &str) -> Result<u8> {
    Ok(match facility.to_ascii_lowercase().as_str() {
        "kern" => 0,
        "user" => 1,
        "mail" => 2,
        "daemon" => 3,
        "auth" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "authpriv" => 10,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        _ => return Err(anyhow!("unknown syslog facility: {}", facility)),
    })
}

pub fn facility_from_str(facility: &str) -> Result<Facility> {
    Ok(match facility.to_ascii_lowercase().as_str() {
        "kern" => Facility::LOG_KERN,
        "user" => Facility::LOG_USER,
        "mail" => Facility::LOG_MAIL,
        "daemon" => Facility::LOG_DAEMON,
        "auth" => Facility::LOG_AUTH,
        "syslog" => Facility::LOG_SYSLOG,
        "lpr" => Facility::LOG_LPR,
        "news" => Facility::LOG_NEWS,
        "uucp" => Facility::LOG_UUCP,
        "cron" => Facility::LOG_CRON,
        "authpriv" => Facility::LOG_AUTHPRIV,
        "local0" => Facility::LOG_LOCAL0,
        "local1" => Facility::LOG_LOCAL1,
        "local2" => Facility::LOG_LOCAL2,
        "local3" => Facility::LOG_LOCAL3,
        "local4" => Facility::LOG_LOCAL4,
        "local5" => Facility::LOG_LOCAL5,
        "local6" => Facility::LOG_LOCAL6,
        "local7" => Facility::LOG_LOCAL7,
        _ => return Err(anyhow!("unknown syslog facility: {}", facility)),
    })
}

/// Syslog severity levels (RFC 5424).
pub fn severity_code(level: &tracing::Level) -> u8 {
    match *level {
        tracing::Level::ERROR => 3, // ERROR
        tracing::Level::WARN => 4,  // WARNING
        tracing::Level::INFO => 6,  // INFORMATIONAL
        tracing::Level::DEBUG => 7, // DEBUG
        tracing::Level::TRACE => 7, // DEBUG
    }
}

/// Log level from string: "error", "warn", "info", "debug", "trace".
pub fn level_from_str(s: &str) -> Option<tracing::Level> {
    match s.to_lowercase().as_str() {
        "error" => Some(tracing::Level::ERROR),
        "warn" | "warning" => Some(tracing::Level::WARN),
        "info" => Some(tracing::Level::INFO),
        "debug" => Some(tracing::Level::DEBUG),
        "trace" => Some(tracing::Level::TRACE),
        _ => None,
    }
}

/// Syslog transport variant.
#[derive(Debug, Clone)]
pub enum SyslogTransport {
    Unix(String),        // Unix socket path
    Udp(String),         // host:port
    Tcp(String),         // host:port
    Tls(String, String), // host:port, ca_cert_path
}

impl SyslogTransport {
    pub fn from_config(
        transport_opt: Option<&str>,
        server_opt: Option<&str>,
        tls_cert_path: Option<&str>,
    ) -> Result<Self> {
        let transport = transport_opt.unwrap_or("unix");
        match transport {
            "unix" => {
                let path = server_opt.unwrap_or("/dev/log");
                Ok(SyslogTransport::Unix(path.to_string()))
            }
            "udp" => {
                let server = server_opt.unwrap_or("127.0.0.1:514");
                Ok(SyslogTransport::Udp(server.to_string()))
            }
            "tcp" => {
                let server = server_opt.unwrap_or("127.0.0.1:514");
                Ok(SyslogTransport::Tcp(server.to_string()))
            }
            "tls" => {
                let server = server_opt.unwrap_or("127.0.0.1:601");
                let ca_path = tls_cert_path.ok_or_else(|| {
                    anyhow!("tls transport requires ca_cert_path in syslog config")
                })?;
                Ok(SyslogTransport::Tls(
                    server.to_string(),
                    ca_path.to_string(),
                ))
            }
            _ => Err(anyhow!("unknown syslog transport: {}", transport)),
        }
    }
}

/// Syslog message to be sent.
#[derive(Debug, Clone)]
pub struct SyslogMessage {
    pub level: tracing::Level,
    pub msg: String,
}

enum SyslogClient {
    Native3164(Logger<LoggerBackend, Formatter3164>),
    Native5424(Logger<LoggerBackend, Formatter5424>),
}

impl SyslogClient {
    fn send(&mut self, level: &tracing::Level, msg: &str) -> Result<()> {
        match self {
            SyslogClient::Native3164(logger) => send_3164(logger, level, msg),
            SyslogClient::Native5424(logger) => send_5424(logger, level, msg),
        }
    }
}

fn send_3164(
    logger: &mut Logger<LoggerBackend, Formatter3164>,
    level: &tracing::Level,
    msg: &str,
) -> Result<()> {
    match *level {
        tracing::Level::ERROR => logger.err(msg),
        tracing::Level::WARN => logger.warning(msg),
        tracing::Level::INFO => logger.info(msg),
        tracing::Level::DEBUG | tracing::Level::TRACE => logger.debug(msg),
    }
    .map_err(|e| anyhow!(e.to_string()))
}

fn send_5424(
    logger: &mut Logger<LoggerBackend, Formatter5424>,
    level: &tracing::Level,
    msg: &str,
) -> Result<()> {
    let payload = (1_u32, HashMap::new(), msg);
    match *level {
        tracing::Level::ERROR => logger.err(payload),
        tracing::Level::WARN => logger.warning(payload),
        tracing::Level::INFO => logger.info(payload),
        tracing::Level::DEBUG | tracing::Level::TRACE => logger.debug(payload),
    }
    .map_err(|e| anyhow!(e.to_string()))
}

/// Background syslog sender task.
pub struct SyslogSender {
    tx: mpsc::UnboundedSender<SyslogMessage>,
}

impl SyslogSender {
    pub fn new(
        transport: SyslogTransport,
        facility: Facility,
        format: String,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::unbounded_channel();

        let task = tokio::spawn(async move {
            SyslogSender::sender_loop(rx, transport, facility, format).await;
        });

        (SyslogSender { tx }, task)
    }

    pub fn send(&self, msg: SyslogMessage) {
        let _ = self.tx.send(msg);
    }

    async fn sender_loop(
        mut rx: mpsc::UnboundedReceiver<SyslogMessage>,
        transport: SyslogTransport,
        facility: Facility,
        format: String,
    ) {
        loop {
            match &transport {
                SyslogTransport::Unix(path) => {
                    if let Err(e) = Self::unix_sender_loop(&mut rx, path, facility, &format).await {
                        tracing::warn!("syslog unix sender error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
                SyslogTransport::Udp(addr) => {
                    if let Err(e) = Self::udp_sender_loop(&mut rx, addr, facility, &format).await {
                        tracing::warn!("syslog udp sender error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
                SyslogTransport::Tcp(addr) => {
                    if let Err(e) = Self::tcp_sender_loop(&mut rx, addr, facility, &format).await {
                        tracing::warn!("syslog tcp sender error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
                SyslogTransport::Tls(addr, ca_path) => {
                    if let Err(e) = Self::tls_sender_loop(&mut rx, addr, ca_path).await {
                        tracing::warn!("syslog tls sender error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
            }
        }
    }

    async fn unix_sender_loop(
        rx: &mut mpsc::UnboundedReceiver<SyslogMessage>,
        path: &str,
        facility: Facility,
        format: &str,
    ) -> Result<()> {
        let mut client = Self::native_client_unix(path, facility, format)?;

        while let Some(msg) = rx.recv().await {
            let _ = client.send(&msg.level, &msg.msg);
        }
        Ok(())
    }

    async fn udp_sender_loop(
        rx: &mut mpsc::UnboundedReceiver<SyslogMessage>,
        addr: &str,
        facility: Facility,
        format: &str,
    ) -> Result<()> {
        let mut client = Self::native_client_udp(addr, facility, format)?;

        while let Some(msg) = rx.recv().await {
            let _ = client.send(&msg.level, &msg.msg);
        }
        Ok(())
    }

    async fn tcp_sender_loop(
        rx: &mut mpsc::UnboundedReceiver<SyslogMessage>,
        addr: &str,
        facility: Facility,
        format: &str,
    ) -> Result<()> {
        let mut client = Self::native_client_tcp(addr, facility, format)?;

        while let Some(msg) = rx.recv().await {
            let _ = client.send(&msg.level, &msg.msg);
        }
        Ok(())
    }

    async fn tls_sender_loop(
        rx: &mut mpsc::UnboundedReceiver<SyslogMessage>,
        addr: &str,
        ca_path: &str,
    ) -> Result<()> {
        use rustls_pemfile::certs;
        use std::fs::File;
        use std::io::BufReader;
        use tokio_rustls::TlsConnector;

        // Load CA cert
        let mut root_store = rustls::RootCertStore::empty();
        let ca_file = File::open(ca_path).context("opening CA cert file")?;
        let mut reader = BufReader::new(ca_file);
        let certs = certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
        for cert in certs {
            root_store.add(cert).context("adding cert to root store")?;
        }

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        // Parse server name once before loop to avoid lifetime issues.
        let server_name_str = addr
            .split(':')
            .next()
            .ok_or_else(|| anyhow!("invalid syslog tls address"))?
            .to_string();

        loop {
            let tcp_stream = match TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("syslog tls tcp connect failed: {}", e);
                    return Err(e.into());
                }
            };

            let server_name = rustls::pki_types::ServerName::try_from(server_name_str.clone())
                .context("parsing server name")?;

            let mut tls_stream = match connector.connect(server_name, tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("syslog tls handshake failed: {}", e);
                    return Err(e.into());
                }
            };

            while let Some(msg) = rx.recv().await {
                let mut encoded = msg.msg;
                encoded.push('\n');
                if let Err(e) = tls_stream.write_all(encoded.as_bytes()).await {
                    tracing::debug!("syslog tls write failed: {}", e);
                    return Err(e.into());
                }
            }
        }
    }

    fn native_client_unix(path: &str, facility: Facility, format: &str) -> Result<SyslogClient> {
        let process = "dns-filter".to_string();
        if format.eq_ignore_ascii_case("rfc5424") {
            let formatter = Formatter5424 {
                facility,
                hostname: None,
                process,
                pid: std::process::id(),
            };
            let logger =
                syslog::unix_custom(formatter, path).map_err(|e| anyhow!(e.to_string()))?;
            Ok(SyslogClient::Native5424(logger))
        } else {
            let formatter = Formatter3164 {
                facility,
                hostname: None,
                process,
                pid: std::process::id(),
            };
            let logger =
                syslog::unix_custom(formatter, path).map_err(|e| anyhow!(e.to_string()))?;
            Ok(SyslogClient::Native3164(logger))
        }
    }

    fn native_client_udp(addr: &str, facility: Facility, format: &str) -> Result<SyslogClient> {
        let process = "dns-filter".to_string();
        let hostname = std::env::var("HOSTNAME").ok();
        if format.eq_ignore_ascii_case("rfc5424") {
            let formatter = Formatter5424 {
                facility,
                hostname,
                process,
                pid: std::process::id(),
            };
            let logger =
                syslog::udp(formatter, "0.0.0.0:0", addr).map_err(|e| anyhow!(e.to_string()))?;
            Ok(SyslogClient::Native5424(logger))
        } else {
            let formatter = Formatter3164 {
                facility,
                hostname,
                process,
                pid: std::process::id(),
            };
            let logger =
                syslog::udp(formatter, "0.0.0.0:0", addr).map_err(|e| anyhow!(e.to_string()))?;
            Ok(SyslogClient::Native3164(logger))
        }
    }

    fn native_client_tcp(addr: &str, facility: Facility, format: &str) -> Result<SyslogClient> {
        let process = "dns-filter".to_string();
        let hostname = std::env::var("HOSTNAME").ok();
        if format.eq_ignore_ascii_case("rfc5424") {
            let formatter = Formatter5424 {
                facility,
                hostname,
                process,
                pid: std::process::id(),
            };
            let logger = syslog::tcp(formatter, addr).map_err(|e| anyhow!(e.to_string()))?;
            Ok(SyslogClient::Native5424(logger))
        } else {
            let formatter = Formatter3164 {
                facility,
                hostname,
                process,
                pid: std::process::id(),
            };
            let logger = syslog::tcp(formatter, addr).map_err(|e| anyhow!(e.to_string()))?;
            Ok(SyslogClient::Native3164(logger))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facility_code_all_valid() {
        let facilities = [
            "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
            "authpriv", "local0", "local1", "local2", "local3", "local4", "local5", "local6",
            "local7",
        ];
        for f in &facilities {
            assert!(facility_code(f).is_ok(), "failed for {}", f);
        }
    }

    #[test]
    fn facility_code_invalid() {
        assert!(facility_code("invalid").is_err());
    }

    #[test]
    fn severity_maps_correctly() {
        assert_eq!(severity_code(&tracing::Level::ERROR), 3);
        assert_eq!(severity_code(&tracing::Level::WARN), 4);
        assert_eq!(severity_code(&tracing::Level::INFO), 6);
        assert_eq!(severity_code(&tracing::Level::DEBUG), 7);
        assert_eq!(severity_code(&tracing::Level::TRACE), 7);
    }

    #[test]
    fn level_from_str_all_valid() {
        assert_eq!(level_from_str("error"), Some(tracing::Level::ERROR));
        assert_eq!(level_from_str("warn"), Some(tracing::Level::WARN));
        assert_eq!(level_from_str("warning"), Some(tracing::Level::WARN));
        assert_eq!(level_from_str("info"), Some(tracing::Level::INFO));
        assert_eq!(level_from_str("debug"), Some(tracing::Level::DEBUG));
        assert_eq!(level_from_str("trace"), Some(tracing::Level::TRACE));
    }

    #[test]
    fn level_from_str_invalid() {
        assert_eq!(level_from_str("invalid"), None);
    }

    #[test]
    fn facility_from_str_valid() {
        assert!(facility_from_str("local0").is_ok());
        assert!(facility_from_str("LOCAL7").is_ok());
        assert!(facility_from_str("authpriv").is_ok());
    }

    #[test]
    fn priority_calculation() {
        // facility 16 (local0) + severity 6 (info) = priority 134
        let facility = facility_code("local0").unwrap();
        let severity = severity_code(&tracing::Level::INFO);
        let priority = (facility * 8) + severity;
        assert_eq!(priority, 134);
    }
}
