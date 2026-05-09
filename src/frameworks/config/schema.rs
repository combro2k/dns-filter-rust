#![allow(dead_code)]

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DnsFilterConfig {
    pub listen: ListenConfig,
    pub blocklists: Vec<NamedList>,
    pub allowlists: Vec<NamedList>,
    pub upstreams: UpstreamsConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub dns: Option<SocketConfig>,
    pub dot: Option<TlsSocketConfig>,
    pub doh: Option<TlsSocketConfig>,
    pub doq: Option<TlsSocketConfig>,
    pub http: Option<SocketConfig>,
    pub metrics: Option<MetricsConfig>,
}

#[derive(Debug, Deserialize)]
pub struct SocketConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct TlsSocketConfig {
    pub address: String,
    pub port: u16,
    pub tls: TlsConfig,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub autogenerate: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct NamedList {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamsConfig {
    pub strategy: String,
    pub servers: Vec<UpstreamServer>,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamServer {
    pub protocol: String,
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub syslog: Option<SyslogConfig>,
    pub file: Option<FileLogConfig>,
    pub stdout: Option<StdoutLogConfig>,
}

#[derive(Debug, Deserialize)]
pub struct SyslogConfig {
    pub enabled: bool,
    pub facility: String,
    pub level: String,
}

#[derive(Debug, Deserialize)]
pub struct FileLogConfig {
    pub enabled: bool,
    pub location: String,
    pub level: String,
}

#[derive(Debug, Deserialize)]
pub struct StdoutLogConfig {
    pub enabled: bool,
    pub level: String,
}
