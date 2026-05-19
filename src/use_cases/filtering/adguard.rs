use super::common::{
    is_ip_like, normalize_domain_opt, skip_comment_line, ParseDomainLineResult, ParsedLine,
};

/// Parses a single line in AdGuard / ABP filter-list syntax.
///
/// Recognised patterns:
/// - `||domain[^][$modifiers]` — network block rule
/// - `@@||domain[^][$modifiers]` — exception (allow) rule
/// - Cosmetic / scriptlet / CSS / HTML rules — skipped
/// - Hosts-file and plain-domain lines — accepted as fallback
///
/// Returns `None` for comment and blank lines.
pub(crate) fn parse_adguard_line(line: &str) -> Option<ParseDomainLineResult> {
    let trimmed = skip_comment_line(line)?;

    // Skip non-network rules: cosmetic, CSS injection, scriptlet, HTML filter.
    const COSMETIC_MARKERS: &[&str] = &[
        "#@$?#", // Extended CSS + CSS injection exception
        "#$?#",  // Extended CSS + CSS injection
        "#@?#",  // Extended CSS element hiding exception
        "#?#",   // Extended CSS element hiding
        "#@$#",  // CSS injection exception
        "#@%#",  // JavaScript injection exception
        "#@#",   // Element hiding exception
        "##",    // Element hiding
        "#$#",   // CSS injection / scriptlet injection
        "#%#",   // JavaScript injection (AdGuard)
        "$@$",   // HTML filtering exception
        "$$",    // HTML filtering
    ];
    if COSMETIC_MARKERS.iter().any(|m| trimmed.contains(m)) {
        return Some(ParseDomainLineResult::Skipped);
    }

    // Detect exception (`@@`) prefix
    let (is_exception, rule) = if let Some(rest) = trimmed.strip_prefix("@@") {
        (true, rest)
    } else {
        (false, trimmed)
    };

    // Handle `||domain[^][$modifiers]` AdGuard/ABP network rules
    if let Some(stripped) = rule.strip_prefix("||") {
        let (domain_part, modifiers) = split_domain_and_modifiers(stripped);
        if let Some(reason) = restricting_modifier(modifiers) {
            tracing::debug!(
                rule = %trimmed,
                reason = %reason,
                "filter rule skipped: modifier not applicable at DNS level"
            );
            return Some(ParseDomainLineResult::Skipped);
        }
        return normalize_domain_opt(domain_part)
            .map(|d| {
                if is_exception {
                    ParseDomainLineResult::Parsed(ParsedLine::Allow(d))
                } else {
                    ParseDomainLineResult::Parsed(ParsedLine::Block(d))
                }
            })
            .or(Some(ParseDomainLineResult::Skipped));
    }

    // Exception rules without `||` prefix are too specific to evaluate at DNS level
    if is_exception {
        return Some(ParseDomainLineResult::Skipped);
    }

    // HOSTS-file format and plain domain fallback
    let without_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
    if without_comment.is_empty() {
        return None;
    }

    let mut parts = without_comment.split_whitespace();
    let first = parts.next()?;
    let second = parts.next();

    let domain = match second {
        Some(d) if is_ip_like(first) => d,
        _ => first,
    };

    normalize_domain_opt(domain)
        .map(|d| ParseDomainLineResult::Parsed(ParsedLine::Block(d)))
        .or(Some(ParseDomainLineResult::Skipped))
}

/// Splits `||`-stripped pattern into `(domain, modifiers)`.
/// Handles both `example.com^$mod` and `example.com$mod` forms.
fn split_domain_and_modifiers(stripped: &str) -> (&str, &str) {
    if let Some(caret_pos) = stripped.find('^') {
        let domain = &stripped[..caret_pos];
        let after_caret = &stripped[caret_pos + 1..];
        let modifiers = after_caret.strip_prefix('$').unwrap_or("");
        return (domain, modifiers);
    }
    if let Some(dollar_pos) = stripped.find('$') {
        return (&stripped[..dollar_pos], &stripped[dollar_pos + 1..]);
    }
    (stripped, "")
}

/// Returns the first modifier that is NOT applicable at DNS level, or `None`
/// if all modifiers are DNS-safe. Uses an allowlist approach (fail-closed):
/// only known DNS-safe modifiers are permitted; any unknown or
/// response-modification modifier causes the rule to be skipped.
fn restricting_modifier(modifiers: &str) -> Option<&str> {
    for raw in modifiers.split(',') {
        let m = raw.trim();
        if m.is_empty() {
            continue;
        }
        let key = m
            .trim_start_matches('~')
            .split('=')
            .next()
            .unwrap_or("")
            .trim();
        match key {
            // DNS-safe modifiers — these do not restrict applicability at DNS level
            "important" | "match-case" | "all" => {}
            // AdGuard noop modifier (one or more underscores)
            k if !k.is_empty() && k.chars().all(|c| c == '_') => {}
            // Empty key (e.g. trailing comma) — ignore
            "" => {}
            // Everything else is not evaluable at DNS level — skip the rule
            _ => return Some(key),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_line(line: &str) -> Option<ParsedLine> {
        parse_adguard_line(line).and_then(|result| match result {
            ParseDomainLineResult::Parsed(parsed) => Some(parsed),
            ParseDomainLineResult::Skipped => None,
        })
    }

    #[test]
    fn supports_hosts_and_adblock_formats() {
        assert_eq!(
            parse_line("0.0.0.0 ads.example.com"),
            Some(ParsedLine::Block("ads.example.com".into()))
        );
        assert_eq!(
            parse_line("||tracker.example.org^"),
            Some(ParsedLine::Block("tracker.example.org".into()))
        );
        assert_eq!(
            parse_line("plain.example.net"),
            Some(ParsedLine::Block("plain.example.net".into()))
        );
    }

    #[test]
    fn handles_exceptions_and_modifiers() {
        // Plain exception → Allow
        assert_eq!(
            parse_line("@@||example.com^"),
            Some(ParsedLine::Allow("example.com".into()))
        );
        // Behavior-only modifier $important → Block
        assert_eq!(
            parse_line("||example.com^$important"),
            Some(ParsedLine::Block("example.com".into()))
        );
        // $all means all types → Block
        assert_eq!(
            parse_line("||example.com^$all"),
            Some(ParsedLine::Block("example.com".into()))
        );
        // Content-type restrictor → skip
        assert_eq!(parse_line("||example.com^$script"), None);
        // Context restrictor → skip
        assert_eq!(parse_line("||example.com^$third-party"), None);
        // Multiple modifiers with a restrictor → skip
        assert_eq!(parse_line("||example.com^$image,third-party"), None);
        // No `^` but has context modifier → skip
        assert_eq!(parse_line("||example.com$third-party"), None);
        // Exception with narrowing modifier → skip
        assert_eq!(parse_line("@@||example.com^$script"), None);
        // Response-modification modifiers → skip (fail-closed allowlist)
        assert_eq!(parse_line("||example.com^$csp=script-src 'self'"), None);
        assert_eq!(parse_line("||example.com^$redirect=noopjs"), None);
        assert_eq!(parse_line("||example.com^$removeparam=utm_source"), None);
        assert_eq!(parse_line("||example.com^$removeheader=refresh"), None);
        assert_eq!(parse_line("||example.com^$cookie"), None);
        assert_eq!(parse_line("||example.com^$stealth"), None);
        assert_eq!(parse_line("||example.com^$badfilter"), None);
        assert_eq!(parse_line("||example.com^$replace=/test/test2/"), None);
        // Noop modifier (underscores) should still be DNS-safe → Block
        assert_eq!(
            parse_line("||example.com^$_____,important"),
            Some(ParsedLine::Block("example.com".into()))
        );
    }

    #[test]
    fn skips_cosmetic_rules() {
        // Original markers
        assert_eq!(parse_line("example.com##.advertisement"), None);
        assert_eq!(parse_line("example.com#@#.selector"), None);
        assert_eq!(parse_line("example.com#$#body { color: red }"), None);
        assert_eq!(
            parse_line("example.com#%#//scriptlet(abort-on-property-read, alert)"),
            None
        );
        assert_eq!(parse_line("example.com$$script[data-src]"), None);

        // Extended CSS markers
        assert_eq!(
            parse_line("imdb.com#$?#.interstitial-adWrapper { remove: true; }"),
            None
        );
        assert_eq!(
            parse_line("example.com#?#.banner:matches-css(width: 360px)"),
            None
        );
        assert_eq!(parse_line("example.com#@?#.banner"), None);
        assert_eq!(parse_line("example.com#@$?#div { remove: true; }"), None);

        // Exception markers for injection rules
        assert_eq!(
            parse_line("example.com#@$#.textad { visibility: hidden; }"),
            None
        );
        assert_eq!(parse_line("example.com#@%#window.__gaq = undefined;"), None);

        // HTML filtering exception
        assert_eq!(
            parse_line("example.com$@$script[tag-content=\"banner\"]"),
            None
        );
    }
}
