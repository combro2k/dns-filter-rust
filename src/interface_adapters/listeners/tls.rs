use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use thiserror::Error;

/// Errors that can occur during TLS certificate generation or loading.
///
/// This type is intentionally protocol-agnostic so that each listener
/// (DoH, DoT, DoQ) can map it to its own error type.
#[derive(Debug, Error)]
pub enum TlsSetupError {
    #[error("certificate generation failed: {0}")]
    CertGeneration(String),
    #[error("certificate loading failed: {0}")]
    CertLoad(String),
    #[error("TLS configuration error: {0}")]
    Config(String),
}

/// Generates a self-signed TLS certificate and private key at the given paths
/// if neither file exists. This is intended for testing and development only.
///
/// The generated certificate includes SANs for:
/// - `localhost`, `127.0.0.1`, `::1` (always)
/// - the system hostname (best-effort)
/// - non-loopback network interface IP addresses (best-effort)
/// - any entries from `extra_sans` (e.g. configured bind addresses)
///
/// Wildcard/unspecified addresses (`0.0.0.0`, `::`) are filtered out.
/// If either file already exists, this function does nothing (no overwrite).
pub fn autogenerate_tls_cert_if_missing(
    cert_path: &str,
    key_path: &str,
    extra_sans: &[String],
) -> Result<(), TlsSetupError> {
    use std::path::Path;

    if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        tracing::debug!(
            cert_path,
            key_path,
            "TLS cert and key already exist, skipping auto-generation"
        );
        return Ok(());
    }

    let sans = collect_sans(extra_sans);

    tracing::info!(
        cert_path,
        key_path,
        sans = ?sans.iter().map(san_display).collect::<Vec<_>>(),
        "auto-generating self-signed TLS certificate (testing/development only)"
    );

    let mut params = CertificateParams::default();
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "dns-filter self-signed cert");
        dn
    };
    params.subject_alt_names = sans;

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| TlsSetupError::CertGeneration(format!("failed to generate key pair: {e}")))?;

    let cert = params.self_signed(&key_pair).map_err(|e| {
        TlsSetupError::CertGeneration(format!("failed to generate self-signed certificate: {e}"))
    })?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Ensure parent directories exist.
    if let Some(parent) = Path::new(cert_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            TlsSetupError::CertGeneration(format!("failed to create directory for cert: {e}"))
        })?;
    }
    if let Some(parent) = Path::new(key_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            TlsSetupError::CertGeneration(format!("failed to create directory for key: {e}"))
        })?;
    }

    std::fs::write(cert_path, cert_pem).map_err(|e| {
        TlsSetupError::CertGeneration(format!("failed to write certificate to '{cert_path}': {e}"))
    })?;
    std::fs::write(key_path, &key_pem).map_err(|e| {
        TlsSetupError::CertGeneration(format!("failed to write key to '{key_path}': {e}"))
    })?;

    Ok(())
}

/// Loads the TLS certificate chain and private key from PEM files and builds
/// a [`rustls::ServerConfig`] suitable for serving HTTPS/DoT/DoQ.
pub fn build_tls_server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<ServerConfig, TlsSetupError> {
    let cert_file = std::fs::File::open(cert_path).map_err(|e| {
        TlsSetupError::CertLoad(format!(
            "failed to open certificate file '{cert_path}': {e}"
        ))
    })?;
    let key_file = std::fs::File::open(key_path).map_err(|e| {
        TlsSetupError::CertLoad(format!("failed to open key file '{key_path}': {e}"))
    })?;

    let cert_chain: Vec<_> = certs(&mut io::BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsSetupError::CertLoad(format!("failed to parse certificate PEM: {e}")))?;

    if cert_chain.is_empty() {
        return Err(TlsSetupError::CertLoad(
            "certificate file contains no certificates".into(),
        ));
    }

    let key = private_key(&mut io::BufReader::new(key_file))
        .map_err(|e| TlsSetupError::CertLoad(format!("failed to parse key PEM: {e}")))?
        .ok_or_else(|| TlsSetupError::CertLoad("key file contains no private key".into()))?;

    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsSetupError::Config(format!("TLS protocol version error: {e}")))?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| TlsSetupError::Config(format!("TLS configuration error: {e}")))?;

    Ok(config)
}

/// Collects Subject Alternative Names from multiple sources:
/// 1. Always: `localhost`, `127.0.0.1`, `::1`
/// 2. System hostname (best-effort)
/// 3. Non-loopback network interface IPs (best-effort)
/// 4. Extra SANs from caller (e.g. configured bind addresses)
///
/// Wildcard/unspecified addresses are filtered and entries are deduplicated.
fn collect_sans(extra_sans: &[String]) -> Vec<SanType> {
    let mut seen_ips = HashSet::new();
    let mut seen_dns = HashSet::new();
    let mut sans = Vec::new();

    // 1. Always include localhost, 127.0.0.1, ::1
    add_dns(&mut sans, &mut seen_dns, "localhost");
    add_ip(
        &mut sans,
        &mut seen_ips,
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    );
    add_ip(
        &mut sans,
        &mut seen_ips,
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    );

    // 2. System hostname
    match hostname::get() {
        Ok(name) => {
            if let Some(name_str) = name.to_str() {
                if !name_str.is_empty() {
                    add_dns(&mut sans, &mut seen_dns, name_str);
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to get system hostname for TLS SAN");
        }
    }

    // 3. Non-loopback network interface IPs
    match nix::ifaddrs::getifaddrs() {
        Ok(ifaddrs) => {
            for ifaddr in ifaddrs {
                if ifaddr
                    .flags
                    .contains(nix::net::if_::InterfaceFlags::IFF_LOOPBACK)
                {
                    continue;
                }
                if let Some(addr) = ifaddr.address {
                    if let Some(sin) = addr.as_sockaddr_in() {
                        add_ip(&mut sans, &mut seen_ips, IpAddr::V4(sin.ip()));
                    } else if let Some(sin6) = addr.as_sockaddr_in6() {
                        add_ip(&mut sans, &mut seen_ips, IpAddr::V6(sin6.ip()));
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to enumerate network interfaces for TLS SAN");
        }
    }

    // 4. Extra SANs from caller (e.g. configured bind addresses)
    for s in extra_sans {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            add_ip(&mut sans, &mut seen_ips, ip);
        } else {
            add_dns(&mut sans, &mut seen_dns, trimmed);
        }
    }

    sans
}

/// Adds an IP SAN, filtering unspecified addresses and deduplicating.
fn add_ip(sans: &mut Vec<SanType>, seen: &mut HashSet<IpAddr>, ip: IpAddr) {
    if ip.is_unspecified() {
        return;
    }
    if seen.insert(ip) {
        sans.push(SanType::IpAddress(ip));
    }
}

/// Adds a DNS name SAN, deduplicating.
fn add_dns(sans: &mut Vec<SanType>, seen: &mut HashSet<String>, name: &str) {
    if seen.insert(name.to_lowercase()) {
        if let Ok(ia5) = Ia5String::try_from(name) {
            sans.push(SanType::DnsName(ia5));
        } else {
            tracing::warn!(name, "skipping DNS SAN: not a valid IA5 string");
        }
    }
}

/// Returns a human-readable representation of a SAN for logging.
fn san_display(san: &SanType) -> String {
    match san {
        SanType::DnsName(name) => format!("DNS:{}", name.as_str()),
        SanType::IpAddress(ip) => format!("IP:{ip}"),
        SanType::Rfc822Name(name) => format!("Email:{}", name.as_str()),
        SanType::URI(uri) => format!("URI:{}", uri.as_str()),
        _ => format!("{san:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn collect_sans_includes_defaults() {
        let sans = collect_sans(&[]);
        let ips: Vec<_> = sans
            .iter()
            .filter_map(|s| match s {
                SanType::IpAddress(ip) => Some(*ip),
                _ => None,
            })
            .collect();
        let dns: Vec<_> = sans
            .iter()
            .filter_map(|s| match s {
                SanType::DnsName(name) => Some(name.as_str().to_string()),
                _ => None,
            })
            .collect();
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(dns.contains(&"localhost".to_string()));
    }

    #[test]
    fn collect_sans_filters_unspecified() {
        let sans = collect_sans(&["0.0.0.0".into(), "::".into()]);
        let ips: Vec<_> = sans
            .iter()
            .filter_map(|s| match s {
                SanType::IpAddress(ip) => Some(*ip),
                _ => None,
            })
            .collect();
        assert!(!ips.contains(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!ips.contains(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn collect_sans_deduplicates() {
        let sans = collect_sans(&["localhost".into(), "127.0.0.1".into(), "::1".into()]);
        let dns_count = sans
            .iter()
            .filter(|s| matches!(s, SanType::DnsName(n) if n.as_str() == "localhost"))
            .count();
        let ipv4_count = sans
            .iter()
            .filter(
                |s| matches!(s, SanType::IpAddress(IpAddr::V4(ip)) if *ip == Ipv4Addr::LOCALHOST),
            )
            .count();
        assert_eq!(dns_count, 1);
        assert_eq!(ipv4_count, 1);
    }

    #[test]
    fn collect_sans_includes_extra_ip() {
        let sans = collect_sans(&["192.168.1.100".into()]);
        let ips: Vec<_> = sans
            .iter()
            .filter_map(|s| match s {
                SanType::IpAddress(ip) => Some(*ip),
                _ => None,
            })
            .collect();
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
    }

    #[test]
    fn collect_sans_includes_extra_dns() {
        let sans = collect_sans(&["myhost.example.com".into()]);
        let dns: Vec<_> = sans
            .iter()
            .filter_map(|s| match s {
                SanType::DnsName(name) => Some(name.as_str().to_string()),
                _ => None,
            })
            .collect();
        assert!(dns.contains(&"myhost.example.com".to_string()));
    }

    #[test]
    fn collect_sans_includes_interface_ips() {
        let sans = collect_sans(&[]);
        // We should have at least the defaults (localhost, 127.0.0.1, ::1).
        // On most systems there will also be non-loopback interface IPs.
        assert!(sans.len() >= 3);
    }

    #[test]
    fn autogenerate_creates_cert_and_key() {
        let dir = std::env::temp_dir().join("dns-filter-tls-test-autogen");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");

        autogenerate_tls_cert_if_missing(
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            &["10.0.0.1".into()],
        )
        .unwrap();

        assert!(cert.exists());
        assert!(key.exists());

        // Verify the generated cert can be loaded.
        let config = build_tls_server_config(cert.to_str().unwrap(), key.to_str().unwrap());
        assert!(config.is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn autogenerate_does_not_overwrite() {
        let dir = std::env::temp_dir().join("dns-filter-tls-test-no-overwrite");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");

        // Create initial files.
        autogenerate_tls_cert_if_missing(cert.to_str().unwrap(), key.to_str().unwrap(), &[])
            .unwrap();

        let cert_contents = std::fs::read_to_string(&cert).unwrap();
        let key_contents = std::fs::read_to_string(&key).unwrap();

        // Call again — should not overwrite.
        autogenerate_tls_cert_if_missing(
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            &["10.0.0.1".into()],
        )
        .unwrap();

        assert_eq!(cert_contents, std::fs::read_to_string(&cert).unwrap());
        assert_eq!(key_contents, std::fs::read_to_string(&key).unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
