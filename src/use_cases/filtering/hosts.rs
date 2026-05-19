use super::common::{is_ip_like, normalize_domain_opt, ParseDomainLineResult, ParsedLine};

/// Parses a single line in hosts-file format.
///
/// Recognised patterns:
/// - `<IP> domain1 [domain2] [domain3] …` — one or more domains per line
/// - `domain` — plain domain (no IP prefix)
/// - Inline `#` comments after entries are stripped
///
/// Returns a `Vec` because a single hosts line can contain multiple domains
/// (compressed format).
///
/// Returns an empty vec for comment and blank lines.
pub(crate) fn parse_hosts_line(line: &str) -> Vec<ParseDomainLineResult> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return Vec::new();
    }

    // Strip inline comments
    let without_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
    if without_comment.is_empty() {
        return Vec::new();
    }

    let mut parts = without_comment.split_whitespace();
    let first = match parts.next() {
        Some(f) => f,
        None => return Vec::new(),
    };

    // If first token is an IP address, remaining tokens are domains
    if is_ip_like(first) {
        let mut results = Vec::new();
        for token in parts {
            match normalize_domain_opt(token) {
                Some(d) => results.push(ParseDomainLineResult::Parsed(ParsedLine::Block(d))),
                None => results.push(ParseDomainLineResult::Skipped),
            }
        }
        // A line with only an IP and no domains is skipped
        if results.is_empty() {
            results.push(ParseDomainLineResult::Skipped);
        }
        return results;
    }

    // No IP prefix — treat remaining tokens as plain domains too
    let mut results = Vec::new();
    match normalize_domain_opt(first) {
        Some(d) => results.push(ParseDomainLineResult::Parsed(ParsedLine::Block(d))),
        None => results.push(ParseDomainLineResult::Skipped),
    }
    for token in parts {
        match normalize_domain_opt(token) {
            Some(d) => results.push(ParseDomainLineResult::Parsed(ParsedLine::Block(d))),
            None => results.push(ParseDomainLineResult::Skipped),
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_domains(line: &str) -> Vec<String> {
        parse_hosts_line(line)
            .into_iter()
            .filter_map(|r| match r {
                ParseDomainLineResult::Parsed(ParsedLine::Block(d)) => Some(d),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn single_host_entry() {
        assert_eq!(
            parsed_domains("0.0.0.0 ads.example.com"),
            vec!["ads.example.com"]
        );
    }

    #[test]
    fn multi_host_compressed() {
        assert_eq!(
            parsed_domains("0.0.0.0 ads.example.com tracker.example.com analytics.example.com"),
            vec![
                "ads.example.com",
                "tracker.example.com",
                "analytics.example.com"
            ]
        );
    }

    #[test]
    fn ipv6_prefix() {
        assert_eq!(
            parsed_domains("::1 ads.example.com"),
            vec!["ads.example.com"]
        );
        assert_eq!(
            parsed_domains(":: ads.example.com tracker.example.com"),
            vec!["ads.example.com", "tracker.example.com"]
        );
    }

    #[test]
    fn inline_comment_stripped() {
        assert_eq!(
            parsed_domains("0.0.0.0 ads.example.com # ad server"),
            vec!["ads.example.com"]
        );
    }

    #[test]
    fn plain_domain_no_ip() {
        assert_eq!(parsed_domains("ads.example.com"), vec!["ads.example.com"]);
    }

    #[test]
    fn skips_comment_lines() {
        assert!(parsed_domains("# this is a comment").is_empty());
        assert!(parsed_domains("! another comment").is_empty());
        assert!(parsed_domains("").is_empty());
    }

    #[test]
    fn ip_only_line_skipped() {
        let results = parse_hosts_line("0.0.0.0");
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], ParseDomainLineResult::Skipped));
    }

    #[test]
    fn localhost_entry_skipped() {
        // localhost is a valid domain but typically filtered by consumers
        assert_eq!(parsed_domains("127.0.0.1 localhost"), vec!["localhost"]);
    }

    #[test]
    fn trailing_dot_normalized() {
        assert_eq!(
            parsed_domains("0.0.0.0 ads.example.com."),
            vec!["ads.example.com"]
        );
    }
}
