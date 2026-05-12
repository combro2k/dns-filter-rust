use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use crate::entities::filter::FilterDecision;
use crate::frameworks::config::schema::{DnsFilterConfig, FilteringConfig, NamedList};
use anyhow::{anyhow, Context, Result};
use hickory_proto::rr::Name;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

const DEFAULT_LIST_INTERVAL_SECS: u64 = 12 * 60 * 60;
const DEFAULT_DOCUMENT_CACHE_PATH: &str = "/var/lib/dns-filter/filter-cache.db";
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

enum ParseDomainLineResult {
    Parsed(ParsedLine),
    Skipped,
}

#[derive(Debug, Clone)]
struct ListRuntime {
    key: String,
    name: String,
    url: String,
    interval: Duration,
    kind: ListKind,
    runtime_disabled: Arc<AtomicBool>,
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
    fn list_names(&self) -> Vec<ListInfo>;
    fn disable_list(&self, name: &str) -> bool;
    fn enable_list(&self, name: &str) -> bool;
    fn refresh_list(&self, name: &str) -> bool;
    fn refresh_all_lists(&self) -> Vec<String>;
}

#[derive(Debug, Clone, Serialize)]
pub struct ListInfo {
    pub name: String,
    pub url: String,
    pub kind: &'static str,
    pub enabled: bool,
    pub interval_secs: u64,
    pub domain_count: usize,
    pub exception_count: usize,
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

    fn clone_refresh_handle(&self) -> Self {
        Self {
            sinkhole_v4: self.sinkhole_v4,
            sinkhole_v6: self.sinkhole_v6,
            runtimes: self.runtimes.clone(),
            document_cache: self.document_cache.clone(),
            lists: Arc::clone(&self.lists),
            snapshot: Arc::clone(&self.snapshot),
        }
    }

    async fn refresh_single_list(&self, runtime: &ListRuntime) {
        match fetch_list_content(&runtime.url).await {
            Ok(content) => {
                let (domains, exceptions, skipped_entries_added) = parse_domains(&content);
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
                    block_entries_added = domains.len(),
                    whitelist_entries_added = exceptions.len(),
                    skipped_entries_added,
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

        let disabled_keys: HashSet<String> = self
            .runtimes
            .iter()
            .filter(|rt| rt.runtime_disabled.load(Ordering::Relaxed))
            .map(|rt| rt.key.clone())
            .collect();

        let mut blocked = HashSet::new();
        let mut allowed = HashSet::new();

        for (key, list) in lists.iter() {
            if disabled_keys.contains(key) {
                continue;
            }
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

    fn list_names(&self) -> Vec<ListInfo> {
        let lists = self
            .lists
            .read()
            .expect("list cache lock poisoned while reading list names");

        self.runtimes
            .iter()
            .map(|rt| {
                let (domain_count, exception_count) = lists
                    .get(&rt.key)
                    .map(|ld| (ld.domains.len(), ld.exceptions.len()))
                    .unwrap_or((0, 0));
                ListInfo {
                    name: rt.name.clone(),
                    url: rt.url.clone(),
                    kind: match rt.kind {
                        ListKind::Block => "blocklist",
                        ListKind::Allow => "allowlist",
                    },
                    enabled: !rt.runtime_disabled.load(Ordering::Relaxed),
                    interval_secs: rt.interval.as_secs(),
                    domain_count,
                    exception_count,
                }
            })
            .collect()
    }

    fn disable_list(&self, name: &str) -> bool {
        if let Some(rt) = self.runtimes.iter().find(|rt| rt.name == name) {
            rt.runtime_disabled.store(true, Ordering::Relaxed);
            self.rebuild_snapshot();
            tracing::info!(list = %name, "list disabled at runtime via API");
            true
        } else {
            false
        }
    }

    fn enable_list(&self, name: &str) -> bool {
        if let Some(rt) = self.runtimes.iter().find(|rt| rt.name == name) {
            rt.runtime_disabled.store(false, Ordering::Relaxed);
            self.rebuild_snapshot();
            tracing::info!(list = %name, "list enabled at runtime via API");
            true
        } else {
            false
        }
    }

    fn refresh_list(&self, name: &str) -> bool {
        let runtime = self.runtimes.iter().find(|rt| rt.name == name);
        match runtime {
            Some(rt) => {
                let engine = Arc::new(self.clone_refresh_handle());
                let rt = rt.clone();
                tokio::spawn(async move {
                    engine.refresh_single_list(&rt).await;
                });
                true
            }
            None => false,
        }
    }

    fn refresh_all_lists(&self) -> Vec<String> {
        let names: Vec<String> = self.runtimes.iter().map(|rt| rt.name.clone()).collect();
        let engine = Arc::new(self.clone_refresh_handle());
        for runtime in self.runtimes.clone() {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move {
                engine.refresh_single_list(&runtime).await;
            });
        }
        names
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
                runtime_disabled: Arc::new(AtomicBool::new(false)),
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

fn parse_domains(content: &str) -> (HashSet<String>, HashSet<String>, usize) {
    let mut blocks = HashSet::new();
    let mut exceptions = HashSet::new();
    let mut skipped_entries = 0usize;

    for parsed in content.lines().filter_map(parse_domain_line_with_status) {
        match parsed {
            ParseDomainLineResult::Parsed(ParsedLine::Block(d)) => {
                blocks.insert(d);
            }
            ParseDomainLineResult::Parsed(ParsedLine::Allow(d)) => {
                exceptions.insert(d);
            }
            ParseDomainLineResult::Skipped => skipped_entries += 1,
        }
    }
    (blocks, exceptions, skipped_entries)
}

#[cfg(test)]
fn parse_domain_line(line: &str) -> Option<ParsedLine> {
    parse_domain_line_with_status(line).and_then(|result| match result {
        ParseDomainLineResult::Parsed(parsed) => Some(parsed),
        ParseDomainLineResult::Skipped => None,
    })
}

fn parse_domain_line_with_status(line: &str) -> Option<ParseDomainLineResult> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return None;
    }

    // Skip non-network rules: cosmetic, CSS injection, scriptlet, HTML filter.
    // Longer markers must be listed before shorter ones that are substrings,
    // although `contains()` makes order irrelevant for correctness.
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

    normalize_domain_opt(domain)
        .map(|d| ParseDomainLineResult::Parsed(ParsedLine::Block(d)))
        .or(Some(ParseDomainLineResult::Skipped))
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
            any_query_policy: None,
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
            any_query_policy: None,
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
        // Response-modification modifiers → skip (fail-closed allowlist)
        assert_eq!(
            parse_domain_line("||example.com^$csp=script-src 'self'"),
            None
        );
        assert_eq!(parse_domain_line("||example.com^$redirect=noopjs"), None);
        assert_eq!(
            parse_domain_line("||example.com^$removeparam=utm_source"),
            None
        );
        assert_eq!(
            parse_domain_line("||example.com^$removeheader=refresh"),
            None
        );
        assert_eq!(parse_domain_line("||example.com^$cookie"), None);
        assert_eq!(parse_domain_line("||example.com^$stealth"), None);
        assert_eq!(parse_domain_line("||example.com^$badfilter"), None);
        assert_eq!(
            parse_domain_line("||example.com^$replace=/test/test2/"),
            None
        );
        // Noop modifier (underscores) should still be DNS-safe → Block
        assert_eq!(
            parse_domain_line("||example.com^$_____,important"),
            Some(ParsedLine::Block("example.com".into()))
        );
    }

    #[test]
    fn parse_domain_line_skips_cosmetic_rules() {
        // Original markers
        assert_eq!(parse_domain_line("example.com##.advertisement"), None);
        assert_eq!(parse_domain_line("example.com#@#.selector"), None);
        assert_eq!(parse_domain_line("example.com#$#body { color: red }"), None);
        assert_eq!(
            parse_domain_line("example.com#%#//scriptlet(abort-on-property-read, alert)"),
            None
        );
        assert_eq!(parse_domain_line("example.com$$script[data-src]"), None);

        // Extended CSS markers
        assert_eq!(
            parse_domain_line("imdb.com#$?#.interstitial-adWrapper { remove: true; }"),
            None
        );
        assert_eq!(
            parse_domain_line("example.com#?#.banner:matches-css(width: 360px)"),
            None
        );
        assert_eq!(parse_domain_line("example.com#@?#.banner"), None);
        assert_eq!(
            parse_domain_line("example.com#@$?#div { remove: true; }"),
            None
        );

        // Exception markers for injection rules
        assert_eq!(
            parse_domain_line("example.com#@$#.textad { visibility: hidden; }"),
            None
        );
        assert_eq!(
            parse_domain_line("example.com#@%#window.__gaq = undefined;"),
            None
        );

        // HTML filtering exception
        assert_eq!(
            parse_domain_line("example.com$@$script[tag-content=\"banner\"]"),
            None
        );
    }

    #[test]
    fn parse_domains_separates_blocks_and_exceptions() {
        let content =
            "||ads.example.com^\n@@||safe.example.com^\n||tracker.org^$third-party\n!comment\n";
        let (blocks, exceptions, skipped_entries) = parse_domains(content);
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
        assert_eq!(
            skipped_entries, 1,
            "only non-empty non-comment skipped rules should be counted"
        );
    }

    #[test]
    fn parse_domains_counts_multiple_skipped_rule_kinds() {
        let content =
            "||ok.example^\n||skip-modifier.example^$script\n@@plain-exception.example.com\nhttp://not-a-domain/\n# comment\n";
        let (blocks, exceptions, skipped_entries) = parse_domains(content);

        assert!(
            blocks.contains("ok.example"),
            "block domain should be parsed"
        );
        assert!(exceptions.is_empty(), "no allow domains expected");
        assert_eq!(
            skipped_entries, 3,
            "modifier-based, unsupported exception, and invalid domain should be skipped"
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
