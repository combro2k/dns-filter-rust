use super::common::{normalize_domain_opt, skip_comment_line, ParseDomainLineResult, ParsedLine};

/// Parses a single line from a wildcard domain list.
///
/// Expects entries like `*.example.com` — one per line.
/// Also accepts bare `example.com` (treated the same way).
/// The `*.` prefix is stripped and the base domain is normalised.
///
/// Lines starting with `#` or `!` are comments and are skipped.
/// Inline `#` comments after a domain are stripped.
///
/// Returns `None` for comment and blank lines.
pub(crate) fn parse_wildcard_line(line: &str) -> Option<ParseDomainLineResult> {
    let trimmed = skip_comment_line(line)?;

    // Strip inline comments
    let without_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
    if without_comment.is_empty() {
        return None;
    }

    // Take only the first whitespace-separated token
    let entry = without_comment.split_whitespace().next()?;

    // normalize_domain already strips `*.` prefix
    normalize_domain_opt(entry)
        .map(|d| ParseDomainLineResult::Parsed(ParsedLine::Block(d)))
        .or(Some(ParseDomainLineResult::Skipped))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_line(line: &str) -> Option<ParsedLine> {
        parse_wildcard_line(line).and_then(|r| match r {
            ParseDomainLineResult::Parsed(p) => Some(p),
            ParseDomainLineResult::Skipped => None,
        })
    }

    #[test]
    fn wildcard_entry() {
        assert_eq!(
            parse_line("*.ads.example.com"),
            Some(ParsedLine::Block("ads.example.com".into()))
        );
    }

    #[test]
    fn bare_domain_accepted() {
        assert_eq!(
            parse_line("ads.example.com"),
            Some(ParsedLine::Block("ads.example.com".into()))
        );
    }

    #[test]
    fn trailing_dot_normalized() {
        assert_eq!(
            parse_line("*.ads.example.com."),
            Some(ParsedLine::Block("ads.example.com".into()))
        );
    }

    #[test]
    fn uppercase_normalized() {
        assert_eq!(
            parse_line("*.ADS.Example.COM"),
            Some(ParsedLine::Block("ads.example.com".into()))
        );
    }

    #[test]
    fn inline_comment_stripped() {
        assert_eq!(
            parse_line("*.ads.example.com # ad wildcard"),
            Some(ParsedLine::Block("ads.example.com".into()))
        );
    }

    #[test]
    fn skips_comment_lines() {
        assert!(parse_line("# this is a comment").is_none());
        assert!(parse_line("! another comment").is_none());
    }

    #[test]
    fn skips_blank_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("   ").is_none());
    }
}
