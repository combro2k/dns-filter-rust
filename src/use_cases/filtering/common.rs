use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::rr::Name;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedLine {
    Block(String),
    Allow(String),
}

pub(crate) enum ParseDomainLineResult {
    Parsed(ParsedLine),
    Skipped,
}

/// Supported blocklist / allowlist formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListFormat {
    /// AdGuard / ABP syntax (`||domain^$modifiers`).
    /// Also accepts hosts-file and plain-domain lines as a fallback.
    Adguard,
    /// Hosts file (`<IP> domain1 [domain2 …]`), including compressed
    /// multi-hostname lines.
    Hosts,
    /// Response Policy Zone format (`domain CNAME .` / `rpz-passthru.`).
    Rpz,
    /// Flat domain list — one domain or subdomain per line.
    Domains,
    /// Wildcard domain list — `*.example.com` per line.
    Wildcard,
}

impl ListFormat {
    /// Parses a user-supplied `list_type` string into a [`ListFormat`].
    /// Defaults to [`ListFormat::Adguard`] when `input` is `None`.
    pub(crate) fn from_option(input: Option<&str>) -> Result<Self, String> {
        match input.unwrap_or("adguard") {
            "adguard" => Ok(Self::Adguard),
            "hosts" => Ok(Self::Hosts),
            "rpz" => Ok(Self::Rpz),
            "domains" => Ok(Self::Domains),
            "wildcard" => Ok(Self::Wildcard),
            other => Err(format!(
                "unsupported list_type '{other}'; valid values are: adguard, hosts, rpz, domains, wildcard"
            )),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Adguard => "adguard",
            Self::Hosts => "hosts",
            Self::Rpz => "rpz",
            Self::Domains => "domains",
            Self::Wildcard => "wildcard",
        }
    }
}

pub(crate) fn normalize_domain_opt(input: &str) -> Option<String> {
    let normalized = normalize_domain(input);
    if normalized.is_empty() {
        return None;
    }

    Name::from_ascii(&normalized).ok()?;
    Some(normalized)
}

pub(crate) fn normalize_domain(input: &str) -> String {
    input
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .trim_start_matches("*.")
        .to_string()
}

pub(crate) fn is_ip_like(value: &str) -> bool {
    value.parse::<Ipv4Addr>().is_ok() || value.parse::<Ipv6Addr>().is_ok()
}

pub(crate) fn matches_any(set: &HashSet<String>, domain: &str) -> bool {
    let labels = domain.split('.').collect::<Vec<_>>();
    for idx in 0..labels.len() {
        let candidate = labels[idx..].join(".");
        if set.contains(&candidate) {
            return true;
        }
    }

    false
}

/// Skips empty lines, `#` comments, and `!` comments.
/// Returns `Some(trimmed)` for non-comment, non-empty lines.
pub(crate) fn skip_comment_line(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return None;
    }
    Some(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_format_from_option_defaults_to_adguard() {
        assert_eq!(ListFormat::from_option(None).unwrap(), ListFormat::Adguard);
    }

    #[test]
    fn list_format_from_option_accepts_all_variants() {
        assert_eq!(
            ListFormat::from_option(Some("adguard")).unwrap(),
            ListFormat::Adguard
        );
        assert_eq!(
            ListFormat::from_option(Some("hosts")).unwrap(),
            ListFormat::Hosts
        );
        assert_eq!(
            ListFormat::from_option(Some("rpz")).unwrap(),
            ListFormat::Rpz
        );
        assert_eq!(
            ListFormat::from_option(Some("domains")).unwrap(),
            ListFormat::Domains
        );
        assert_eq!(
            ListFormat::from_option(Some("wildcard")).unwrap(),
            ListFormat::Wildcard
        );
    }

    #[test]
    fn list_format_from_option_rejects_unknown() {
        assert!(ListFormat::from_option(Some("bad")).is_err());
    }

    #[test]
    fn matching_checks_parent_domains() {
        let mut set = HashSet::new();
        set.insert("example.com".to_string());
        assert!(matches_any(&set, "a.b.example.com"));
    }

    #[test]
    fn normalize_domain_handles_trailing_dot_and_wildcard() {
        assert_eq!(normalize_domain("Example.COM."), "example.com");
        assert_eq!(normalize_domain("*.ads.example.com"), "ads.example.com");
    }
}
