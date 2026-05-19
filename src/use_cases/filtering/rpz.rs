use super::common::{normalize_domain_opt, ParseDomainLineResult, ParsedLine};

/// Parses a single line in Response Policy Zone (RPZ) format.
///
/// Recognised patterns:
/// - `domain CNAME .` — block (NXDOMAIN policy)
/// - `domain CNAME *.` — block (NODATA policy)
/// - `*.domain CNAME .` — wildcard block
/// - `domain CNAME rpz-passthru.` — allow (passthrough)
/// - `domain A <ip>` / `domain AAAA <ip>` — block (walled garden)
///
/// Skipped:
/// - SOA, NS records (zone infrastructure)
/// - `$TTL`, `$ORIGIN` directives
/// - `;` comment lines and blank lines
///
/// Returns `None` for comment, blank, and infrastructure lines.
pub(crate) fn parse_rpz_line(line: &str) -> Option<ParseDomainLineResult> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with(';') {
        return None;
    }

    // Skip zone-file directives
    if trimmed.starts_with("$TTL")
        || trimmed.starts_with("$ORIGIN")
        || trimmed.starts_with("$INCLUDE")
    {
        return None;
    }

    // Tokenize
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 2 {
        return Some(ParseDomainLineResult::Skipped);
    }

    // Find the owner name and record type.
    // RPZ lines can be:
    //   owner [TTL] [CLASS] TYPE RDATA
    //   owner IN TYPE RDATA
    let (owner, rtype_idx) = find_rtype_index(&tokens)?;

    let rtype = tokens[rtype_idx].to_ascii_uppercase();

    // Skip SOA and NS records (zone infrastructure)
    if rtype == "SOA" || rtype == "NS" {
        return None;
    }

    match rtype.as_str() {
        "CNAME" => {
            let rdata = tokens.get(rtype_idx + 1).map(|s| s.trim_end_matches('.'));
            match rdata {
                // NXDOMAIN / NODATA policy — block
                Some("") | Some(".") | Some("*") => normalize_domain_opt(owner)
                    .map(|d| ParseDomainLineResult::Parsed(ParsedLine::Block(d)))
                    .or(Some(ParseDomainLineResult::Skipped)),
                // Passthrough — allow
                Some(target) if target.eq_ignore_ascii_case("rpz-passthru") => {
                    normalize_domain_opt(owner)
                        .map(|d| ParseDomainLineResult::Parsed(ParsedLine::Allow(d)))
                        .or(Some(ParseDomainLineResult::Skipped))
                }
                // CNAME to another domain (walled garden redirect) — treat as block
                Some(_) => normalize_domain_opt(owner)
                    .map(|d| ParseDomainLineResult::Parsed(ParsedLine::Block(d)))
                    .or(Some(ParseDomainLineResult::Skipped)),
                None => Some(ParseDomainLineResult::Skipped),
            }
        }
        // A / AAAA records (walled garden) — treat as block
        "A" | "AAAA" => normalize_domain_opt(owner)
            .map(|d| ParseDomainLineResult::Parsed(ParsedLine::Block(d)))
            .or(Some(ParseDomainLineResult::Skipped)),
        _ => Some(ParseDomainLineResult::Skipped),
    }
}

/// Locates the record type token, skipping optional TTL and CLASS fields.
/// Returns `(owner, rtype_index)`.
fn find_rtype_index<'a>(tokens: &[&'a str]) -> Option<(&'a str, usize)> {
    let owner = tokens[0];

    // Skip `@` owner (zone origin — infrastructure)
    if owner == "@" {
        return None;
    }

    // tokens[1..] may contain optional TTL (numeric) and/or CLASS (IN/CH/HS)
    for (idx, t) in tokens.iter().enumerate().skip(1) {
        // Skip numeric TTL values
        if t.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // Skip DNS class identifiers
        if t.eq_ignore_ascii_case("IN")
            || t.eq_ignore_ascii_case("CH")
            || t.eq_ignore_ascii_case("HS")
        {
            continue;
        }
        // This must be the record type
        return Some((owner, idx));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_line(line: &str) -> Option<ParsedLine> {
        parse_rpz_line(line).and_then(|r| match r {
            ParseDomainLineResult::Parsed(p) => Some(p),
            ParseDomainLineResult::Skipped => None,
        })
    }

    #[test]
    fn cname_dot_blocks() {
        assert_eq!(
            parse_line("bad.example.com CNAME ."),
            Some(ParsedLine::Block("bad.example.com".into()))
        );
    }

    #[test]
    fn cname_star_dot_blocks() {
        assert_eq!(
            parse_line("bad.example.com CNAME *."),
            Some(ParsedLine::Block("bad.example.com".into()))
        );
    }

    #[test]
    fn wildcard_owner_blocks() {
        assert_eq!(
            parse_line("*.bad.example.com CNAME ."),
            Some(ParsedLine::Block("bad.example.com".into()))
        );
    }

    #[test]
    fn cname_passthru_allows() {
        assert_eq!(
            parse_line("good.example.com CNAME rpz-passthru."),
            Some(ParsedLine::Allow("good.example.com".into()))
        );
    }

    #[test]
    fn a_record_blocks() {
        assert_eq!(
            parse_line("bad.example.com A 0.0.0.0"),
            Some(ParsedLine::Block("bad.example.com".into()))
        );
    }

    #[test]
    fn aaaa_record_blocks() {
        assert_eq!(
            parse_line("bad.example.com AAAA ::"),
            Some(ParsedLine::Block("bad.example.com".into()))
        );
    }

    #[test]
    fn with_ttl_and_class() {
        assert_eq!(
            parse_line("bad.example.com 300 IN CNAME ."),
            Some(ParsedLine::Block("bad.example.com".into()))
        );
    }

    #[test]
    fn with_class_only() {
        assert_eq!(
            parse_line("bad.example.com IN CNAME ."),
            Some(ParsedLine::Block("bad.example.com".into()))
        );
    }

    #[test]
    fn skips_soa() {
        assert!(parse_line("@ IN SOA localhost. root.localhost. 1 3600 300 604800 300").is_none());
    }

    #[test]
    fn skips_ns() {
        assert!(parse_line("@ IN NS localhost.").is_none());
    }

    #[test]
    fn skips_ttl_directive() {
        assert!(parse_rpz_line("$TTL 300").is_none());
    }

    #[test]
    fn skips_origin_directive() {
        assert!(parse_rpz_line("$ORIGIN rpz.example.com.").is_none());
    }

    #[test]
    fn skips_semicolon_comments() {
        assert!(parse_rpz_line("; this is a comment").is_none());
    }

    #[test]
    fn skips_blank_lines() {
        assert!(parse_rpz_line("").is_none());
        assert!(parse_rpz_line("   ").is_none());
    }

    #[test]
    fn cname_redirect_treated_as_block() {
        assert_eq!(
            parse_line("bad.example.com CNAME walled-garden.example.com."),
            Some(ParsedLine::Block("bad.example.com".into()))
        );
    }
}
