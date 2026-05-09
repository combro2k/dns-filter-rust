use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use crate::entities::filter::FilterDecision;
use crate::frameworks::config::schema::{DnsFilterConfig, FilteringConfig, NamedList};
use anyhow::{anyhow, Context, Result};
use hickory_client::proto::rr::Name;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

const DEFAULT_LIST_INTERVAL_SECS: u64 = 12 * 60 * 60;
const DEFAULT_DOCUMENT_CACHE_PATH: &str = "package/cache/filter-cache.db";
const SQLITE_DOCS_TABLE: &str = "filter_cache_documents";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListKind {
    Block,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedLine {
    Block(String),
    Allow(String),
}

#[derive(Debug, Clone)]
struct ListRuntime {
    key: String,
    name: String,
    url: String,
    interval: Duration,
    kind: ListKind,
}

#[derive(Debug, Clone)]
struct ListDomains {
    kind: ListKind,
    domains: HashSet<String>,
    exceptions: HashSet<String>,
}

#[derive(Debug, Default)]
struct FilterSnapshot {
    blocked: HashSet<String>,
    allowed: HashSet<String>,
}

#[derive(Debug, Clone)]
enum DocumentCacheMode {
    MemoryOnly,
    Sqlite { path: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CachedListKind {
    Block,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CachedListDocument {
    kind: CachedListKind,
    domains: Vec<String>,
    #[serde(default)]
    exceptions: Vec<String>,
}

pub trait DomainFilter: Send + Sync {
    fn decide(&self, domain: &str) -> FilterDecision;
    fn sinkhole_ipv4(&self) -> Ipv4Addr;
    fn sinkhole_ipv6(&self) -> Ipv6Addr;
    fn start_background_refresh(self: Arc<Self>);
}

pub struct ListFilterEngine {
    sinkhole_v4: Ipv4Addr,
    sinkhole_v6: Ipv6Addr,
    runtimes: Vec<ListRuntime>,
    document_cache: DocumentCacheMode,
    lists: Arc<RwLock<HashMap<String, ListDomains>>>,
    snapshot: Arc<RwLock<FilterSnapshot>>,
}

impl ListFilterEngine {
    pub fn from_config(config: &DnsFilterConfig) -> Result<Self> {
        let (sinkhole_v4, sinkhole_v6) = parse_sinkhole_addrs(config)?;
        let document_cache = parse_document_cache_mode(config.filtering.as_ref())?;

        let mut runtimes = Vec::new();
        runtimes.extend(build_runtimes(&config.blocklists, ListKind::Block)?);
        runtimes.extend(build_runtimes(&config.allowlists, ListKind::Allow)?);

        let engine = Self {
            sinkhole_v4,
            sinkhole_v6,
            runtimes,
            document_cache,
            lists: Arc::new(RwLock::new(HashMap::new())),
            snapshot: Arc::new(RwLock::new(FilterSnapshot::default())),
        };

        engine.try_restore_document_cache();

        Ok(engine)
    }

    async fn refresh_single_list(&self, runtime: &ListRuntime) {
        match fetch_list_content(&runtime.url).await {
            Ok(content) => {
                let (domains, exceptions) = parse_domains(&content);
                {
                    let mut lists = self
                        .lists
                        .write()
                        .expect("list cache lock poisoned while writing");
                    lists.insert(
                        runtime.key.clone(),
                        ListDomains {
                            kind: runtime.kind,
                            domains: domains.clone(),
                            exceptions: exceptions.clone(),
                        },
                    );
                }

                self.rebuild_snapshot();

                if let Err(error) = self
                    .persist_list_document(runtime, &domains, &exceptions)
                    .await
                {
                    tracing::warn!(
                        list = %runtime.name,
                        source = %runtime.url,
                        error = %error,
                        "failed to persist list document cache"
                    );
                }

                tracing::info!(
                    list = %runtime.name,
                    source = %runtime.url,
                    interval_secs = runtime.interval.as_secs(),
                    "list refreshed"
                );
            }
            Err(error) => {
                tracing::warn!(
                    list = %runtime.name,
                    source = %runtime.url,
                    error = %error,
                    "list refresh failed"
                );
            }
        }
    }

    fn rebuild_snapshot(&self) {
        let lists = self
            .lists
            .read()
            .expect("list cache lock poisoned while rebuilding snapshot");

        let mut blocked = HashSet::new();
        let mut allowed = HashSet::new();

        for list in lists.values() {
            match list.kind {
                ListKind::Block => blocked.extend(list.domains.iter().cloned()),
                ListKind::Allow => allowed.extend(list.domains.iter().cloned()),
            }
            // Inline `@@` exceptions in any list always override blocking
            allowed.extend(list.exceptions.iter().cloned());
        }

        let mut snapshot = self
            .snapshot
            .write()
            .expect("filter snapshot lock poisoned while writing");
        snapshot.blocked = blocked;
        snapshot.allowed = allowed;
    }

    async fn persist_list_document(
        &self,
        runtime: &ListRuntime,
        domains: &HashSet<String>,
        exceptions: &HashSet<String>,
    ) -> Result<()> {
        let path = match &self.document_cache {
            DocumentCacheMode::MemoryOnly => return Ok(()),
            DocumentCacheMode::Sqlite { path } => path.clone(),
        };

        let mut domain_vec = domains.iter().cloned().collect::<Vec<_>>();
        domain_vec.sort();

        let mut exception_vec = exceptions.iter().cloned().collect::<Vec<_>>();
        exception_vec.sort();

        let key = runtime.key.clone();
        let kind = CachedListKind::from(runtime.kind);

        tokio::task::spawn_blocking(move || {
            store_cached_list_document(
                &path,
                &key,
                &CachedListDocument {
                    kind,
                    domains: domain_vec,
                    exceptions: exception_vec,
                },
            )
        })
        .await
        .map_err(|error| anyhow!("document cache writer task failed: {error}"))??;

        Ok(())
    }

    fn try_restore_document_cache(&self) {
        let path = match &self.document_cache {
            DocumentCacheMode::MemoryOnly => return,
            DocumentCacheMode::Sqlite { path } => path,
        };

        let mut restored = 0usize;

        for runtime in &self.runtimes {
            match load_cached_list_document(path, &runtime.key) {
                Ok(Some(document)) => {
                    if CachedListKind::from(runtime.kind) != document.kind {
                        tracing::warn!(
                            list = %runtime.name,
                            key = %runtime.key,
                            "ignoring cached list with mismatched kind"
                        );
                        continue;
                    }

                    let mut lists = self
                        .lists
                        .write()
                        .expect("list cache lock poisoned while restoring document cache");
                    lists.insert(
                        runtime.key.clone(),
                        ListDomains {
                            kind: runtime.kind,
                            domains: document.domains.into_iter().collect(),
                            exceptions: document.exceptions.into_iter().collect(),
                        },
                    );
                    restored += 1;
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        list = %runtime.name,
                        key = %runtime.key,
                        error = %error,
                        "failed to restore cached list document"
                    );
                }
            }
        }

        if restored > 0 {
            self.rebuild_snapshot();
            tracing::info!(
                restored_lists = restored,
                "restored list cache from SQLite document store"
            );
        }
    }
}

impl DomainFilter for ListFilterEngine {
    fn decide(&self, domain: &str) -> FilterDecision {
        let normalized = normalize_domain(domain);
        if normalized.is_empty() {
            return FilterDecision::Neutral;
        }

        let snapshot = self
            .snapshot
            .read()
            .expect("filter snapshot lock poisoned while reading");

        if matches_any(&snapshot.allowed, &normalized) {
            return FilterDecision::Allow;
        }

        if matches_any(&snapshot.blocked, &normalized) {
            return FilterDecision::Block;
        }

        FilterDecision::Neutral
    }

    fn sinkhole_ipv4(&self) -> Ipv4Addr {
        self.sinkhole_v4
    }

    fn sinkhole_ipv6(&self) -> Ipv6Addr {
        self.sinkhole_v6
    }

    fn start_background_refresh(self: Arc<Self>) {
        if self.runtimes.is_empty() {
            tracing::info!(
                "no blocklists or allowlists configured; filter cache refresh loop disabled"
            );
            return;
        }

        for runtime in self.runtimes.clone() {
            let engine = Arc::clone(&self);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(runtime.interval);
                loop {
                    ticker.tick().await;
                    engine.refresh_single_list(&runtime).await;
                }
            });
        }
    }
}

impl From<ListKind> for CachedListKind {
    fn from(value: ListKind) -> Self {
        match value {
            ListKind::Block => CachedListKind::Block,
            ListKind::Allow => CachedListKind::Allow,
        }
    }
}

fn parse_document_cache_mode(filtering: Option<&FilteringConfig>) -> Result<DocumentCacheMode> {
    let cache = filtering.and_then(|cfg| cfg.cache.as_ref());
    let mode = cache
        .and_then(|cfg| cfg.mode.as_deref())
        .unwrap_or("memory");

    match mode {
        "memory" => Ok(DocumentCacheMode::MemoryOnly),
        "sqlite" => {
            let path = cache
                .and_then(|cfg| cfg.document_path.clone())
                .unwrap_or_else(|| DEFAULT_DOCUMENT_CACHE_PATH.to_string());
            Ok(DocumentCacheMode::Sqlite { path })
        }
        _ => Err(anyhow!(
            "invalid filtering.cache.mode '{mode}'; supported values are: memory, sqlite"
        )),
    }
}

fn open_cache_connection(path: &str) -> Result<Connection> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create cache directory '{}'", parent.display())
            })?;
        }
    }

    let conn = Connection::open(path)
        .with_context(|| format!("failed to open SQLite document cache at {path}"))?;

    conn.execute(
        &format!(
            "CREATE TABLE IF NOT EXISTS {SQLITE_DOCS_TABLE} (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        ),
        [],
    )
    .context("failed to create SQLite document cache schema")?;

    Ok(conn)
}

fn load_cached_list_document(path: &str, key: &str) -> Result<Option<CachedListDocument>> {
    let conn = open_cache_connection(path)?;
    let mut stmt = conn
        .prepare(&format!(
            "SELECT value FROM {SQLITE_DOCS_TABLE} WHERE key = ?1"
        ))
        .context("failed to prepare SQLite document cache lookup")?;

    let raw_value = stmt
        .query_row(params![key], |row| row.get::<_, String>(0))
        .optional()
        .context("failed to read SQLite document cache row")?;

    match raw_value {
        Some(raw) => {
            let parsed = serde_json::from_str::<CachedListDocument>(&raw)
                .with_context(|| format!("invalid JSON in cached document '{key}'"))?;
            Ok(Some(parsed))
        }
        None => Ok(None),
    }
}

fn store_cached_list_document(path: &str, key: &str, doc: &CachedListDocument) -> Result<()> {
    let conn = open_cache_connection(path)?;
    let payload = serde_json::to_string(doc)
        .with_context(|| format!("failed to serialize cached document '{key}'"))?;

    conn.execute(
        &format!(
            "INSERT INTO {SQLITE_DOCS_TABLE} (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        ),
        params![key, payload],
    )
    .with_context(|| format!("failed to upsert cached document '{key}'"))?;

    Ok(())
}

fn build_runtimes(lists: &[NamedList], kind: ListKind) -> Result<Vec<ListRuntime>> {
    lists
        .iter()
        .filter(|list| list.enabled.unwrap_or(true))
        .map(|list| {
            let interval = match &list.interval {
                Some(value) => parse_interval(value).with_context(|| {
                    format!("invalid interval for list '{}': '{}'", list.name, value)
                })?,
                None => Duration::from_secs(DEFAULT_LIST_INTERVAL_SECS),
            };

            let key = match kind {
                ListKind::Block => format!("block:{}", list.name),
                ListKind::Allow => format!("allow:{}", list.name),
            };

            Ok(ListRuntime {
                key,
                name: list.name.clone(),
                url: list.url.clone(),
                interval,
                kind,
            })
        })
        .collect()
}

fn parse_sinkhole_addrs(config: &DnsFilterConfig) -> Result<(Ipv4Addr, Ipv6Addr)> {
    let sinkhole_v4 = config
        .filtering
        .as_ref()
        .and_then(|cfg| cfg.sinkhole_ipv4.as_deref())
        .unwrap_or("0.0.0.0")
        .parse::<Ipv4Addr>()
        .context("invalid filtering.sinkhole_ipv4")?;

    let sinkhole_v6 = config
        .filtering
        .as_ref()
        .and_then(|cfg| cfg.sinkhole_ipv6.as_deref())
        .unwrap_or("::")
        .parse::<Ipv6Addr>()
        .context("invalid filtering.sinkhole_ipv6")?;

    Ok((sinkhole_v4, sinkhole_v6))
}

async fn fetch_list_content(source: &str) -> Result<String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let response = reqwest::get(source)
            .await
            .with_context(|| format!("failed to download list from {source}"))?;
        let response = response
            .error_for_status()
            .with_context(|| format!("list source returned non-success status: {source}"))?;

        return response
            .text()
            .await
            .with_context(|| format!("failed to read list body from {source}"));
    }

    tokio::fs::read_to_string(source)
        .await
        .with_context(|| format!("failed to read list file {source}"))
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

/// Returns the first modifier that restricts the rule to a specific request
/// type or context that cannot be evaluated at DNS level, or `None` if all
/// modifiers are universally applicable or purely behavioural.
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
            // Content-type restrictors — rule only applies to a specific resource type
            "script" | "stylesheet" | "css" | "image" | "media" | "font" | "object" | "xhr"
            | "xmlhttprequest" | "ping" | "websocket" | "frame" | "subdocument" | "document"
            | "doc" | "other" | "popup" | "object-subrequest" => {
                return Some(key);
            }
            // Context restrictors — rule only applies in a specific request context
            "third-party" | "3p" | "first-party" | "1p" | "domain" | "from" | "to" | "method"
            | "header" | "app" | "strict-first-party" | "strict1p" | "strict-third-party"
            | "strict3p" | "denyallow" => {
                return Some(key);
            }
            // Behaviour-only or universal modifiers — strip and continue
            _ => {}
        }
    }
    None
}

fn parse_domains(content: &str) -> (HashSet<String>, HashSet<String>) {
    let mut blocks = HashSet::new();
    let mut exceptions = HashSet::new();
    for parsed in content.lines().filter_map(parse_domain_line) {
        match parsed {
            ParsedLine::Block(d) => {
                blocks.insert(d);
            }
            ParsedLine::Allow(d) => {
                exceptions.insert(d);
            }
        }
    }
    (blocks, exceptions)
}

fn parse_domain_line(line: &str) -> Option<ParsedLine> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return None;
    }

    // Skip non-network rules: cosmetic, CSS injection, scriptlet, HTML filter
    const COSMETIC_MARKERS: &[&str] = &["##", "#@#", "#$#", "#%#", "$$"];
    if COSMETIC_MARKERS.iter().any(|m| trimmed.contains(m)) {
        return None;
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
            return None;
        }
        return normalize_domain_opt(domain_part).map(|d| {
            if is_exception {
                ParsedLine::Allow(d)
            } else {
                ParsedLine::Block(d)
            }
        });
    }

    // Exception rules without `||` prefix are too specific to evaluate at DNS level
    if is_exception {
        return None;
    }

    // HOSTS-file format and plain domain entries
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

    normalize_domain_opt(domain).map(ParsedLine::Block)
}

fn is_ip_like(value: &str) -> bool {
    value.parse::<Ipv4Addr>().is_ok() || value.parse::<Ipv6Addr>().is_ok()
}

fn normalize_domain_opt(input: &str) -> Option<String> {
    let normalized = normalize_domain(input);
    if normalized.is_empty() {
        return None;
    }

    Name::from_ascii(&normalized).ok()?;
    Some(normalized)
}

fn normalize_domain(input: &str) -> String {
    input
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .trim_start_matches("*.")
        .to_string()
}

fn matches_any(set: &HashSet<String>, domain: &str) -> bool {
    let labels = domain.split('.').collect::<Vec<_>>();
    for idx in 0..labels.len() {
        let candidate = labels[idx..].join(".");
        if set.contains(&candidate) {
            return true;
        }
    }

    false
}

pub fn parse_interval(input: &str) -> Result<Duration> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("interval cannot be empty"));
    }

    let unit = trimmed
        .chars()
        .last()
        .ok_or_else(|| anyhow!("interval cannot be empty"))?;

    let value_text = &trimmed[..trimmed.len() - unit.len_utf8()];
    if value_text.is_empty() {
        return Err(anyhow!("interval is missing its numeric value"));
    }

    let value = value_text
        .parse::<u64>()
        .with_context(|| format!("invalid interval number: {value_text}"))?;

    match unit {
        's' => Ok(Duration::from_secs(value)),
        'm' => Ok(Duration::from_secs(value * 60)),
        'h' => Ok(Duration::from_secs(value * 60 * 60)),
        'd' => Ok(Duration::from_secs(value * 24 * 60 * 60)),
        _ => Err(anyhow!(
            "unsupported interval suffix '{unit}'; use one of: s, m, h, d"
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::frameworks::config::schema::{FilteringCacheConfig, FilteringConfig};

    use super::*;

    #[test]
    fn parse_interval_supports_duration_suffixes() {
        assert_eq!(parse_interval("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_interval("12h").unwrap(), Duration::from_secs(43200));
        assert_eq!(parse_interval("1d").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn parse_interval_rejects_invalid_values() {
        assert!(parse_interval("abc").is_err());
        assert!(parse_interval("10w").is_err());
    }

    #[test]
    fn parse_domain_line_supports_hosts_and_adblock_formats() {
        assert_eq!(
            parse_domain_line("0.0.0.0 ads.example.com"),
            Some(ParsedLine::Block("ads.example.com".into()))
        );
        assert_eq!(
            parse_domain_line("||tracker.example.org^"),
            Some(ParsedLine::Block("tracker.example.org".into()))
        );
        assert_eq!(
            parse_domain_line("plain.example.net"),
            Some(ParsedLine::Block("plain.example.net".into()))
        );
    }

    #[test]
    fn matching_checks_parent_domains() {
        let mut set = HashSet::new();
        set.insert("example.com".to_string());
        assert!(matches_any(&set, "a.b.example.com"));
    }

    #[test]
    fn parse_document_cache_mode_defaults_to_memory() {
        let mode = parse_document_cache_mode(None).unwrap();
        assert!(matches!(mode, DocumentCacheMode::MemoryOnly));
    }

    #[test]
    fn parse_document_cache_mode_supports_sqlite() {
        let filtering = FilteringConfig {
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
            cache: Some(FilteringCacheConfig {
                mode: Some("sqlite".into()),
                document_path: Some("/tmp/dns-filter-cache.db".into()),
            }),
        };

        let mode = parse_document_cache_mode(Some(&filtering)).unwrap();
        match mode {
            DocumentCacheMode::Sqlite { path } => {
                assert_eq!(path, "/tmp/dns-filter-cache.db");
            }
            DocumentCacheMode::MemoryOnly => panic!("expected sqlite cache mode"),
        }
    }

    #[test]
    fn parse_document_cache_mode_rejects_unknown_value() {
        let filtering = FilteringConfig {
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
            cache: Some(FilteringCacheConfig {
                mode: Some("bad-mode".into()),
                document_path: None,
            }),
        };

        let result = parse_document_cache_mode(Some(&filtering));
        assert!(result.is_err());
    }

    #[test]
    fn sqlite_document_round_trip_works() {
        let mut path = std::env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("dns-filter-cache-{unique}.db"));
        let path_str = path.to_string_lossy().to_string();

        let key = "block:ads";
        let expected = CachedListDocument {
            kind: CachedListKind::Block,
            domains: vec!["ads.example.com".into(), "tracker.example.com".into()],
            exceptions: vec![],
        };

        store_cached_list_document(&path_str, key, &expected).unwrap();
        let loaded = load_cached_list_document(&path_str, key)
            .unwrap()
            .expect("document should exist");
        assert_eq!(loaded, expected);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn parse_domain_line_handles_exceptions_and_modifiers() {
        // Plain exception → Allow
        assert_eq!(
            parse_domain_line("@@||example.com^"),
            Some(ParsedLine::Allow("example.com".into()))
        );
        // Behavior-only modifier $important → Block
        assert_eq!(
            parse_domain_line("||example.com^$important"),
            Some(ParsedLine::Block("example.com".into()))
        );
        // $all means all types → Block
        assert_eq!(
            parse_domain_line("||example.com^$all"),
            Some(ParsedLine::Block("example.com".into()))
        );
        // Content-type restrictor → skip
        assert_eq!(parse_domain_line("||example.com^$script"), None);
        // Context restrictor → skip
        assert_eq!(parse_domain_line("||example.com^$third-party"), None);
        // Multiple modifiers with a restrictor → skip
        assert_eq!(parse_domain_line("||example.com^$image,third-party"), None);
        // No `^` but has context modifier → skip
        assert_eq!(parse_domain_line("||example.com$third-party"), None);
        // Exception with narrowing modifier → skip
        assert_eq!(parse_domain_line("@@||example.com^$script"), None);
    }

    #[test]
    fn parse_domain_line_skips_cosmetic_rules() {
        assert_eq!(parse_domain_line("example.com##.advertisement"), None);
        assert_eq!(parse_domain_line("example.com#@#.selector"), None);
        assert_eq!(parse_domain_line("example.com#$#body { color: red }"), None);
        assert_eq!(
            parse_domain_line("example.com#%#//scriptlet(abort-on-property-read, alert)"),
            None
        );
        assert_eq!(parse_domain_line("example.com$$script[data-src]"), None);
    }

    #[test]
    fn parse_domains_separates_blocks_and_exceptions() {
        let content = "||ads.example.com^\n@@||safe.example.com^\n||tracker.org^$third-party\n";
        let (blocks, exceptions) = parse_domains(content);
        assert!(
            blocks.contains("ads.example.com"),
            "should block ads.example.com"
        );
        assert!(
            !blocks.contains("safe.example.com"),
            "safe domain must not be blocked"
        );
        assert!(
            exceptions.contains("safe.example.com"),
            "safe domain should be in exceptions"
        );
        assert!(
            !blocks.contains("tracker.org"),
            "third-party-only rule should be skipped"
        );
    }

    #[test]
    fn build_runtimes_skips_disabled_lists() {
        let lists = vec![
            NamedList {
                name: "enabled".into(),
                url: "https://example.com/1".into(),
                interval: Some("12h".into()),
                enabled: Some(true),
            },
            NamedList {
                name: "disabled".into(),
                url: "https://example.com/2".into(),
                interval: Some("12h".into()),
                enabled: Some(false),
            },
            NamedList {
                name: "default".into(),
                url: "https://example.com/3".into(),
                interval: None,
                enabled: None,
            },
        ];

        let runtimes = build_runtimes(&lists, ListKind::Block).expect("runtimes should build");
        assert_eq!(runtimes.len(), 2);
        assert_eq!(runtimes[0].name, "enabled");
        assert_eq!(runtimes[1].name, "default");
    }
}
