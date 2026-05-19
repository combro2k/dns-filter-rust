mod adguard;
mod common;
mod domains;
mod hosts;
mod rpz;
mod wildcard;

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use crate::entities::filter::FilterDecision;
use crate::frameworks::config::schema::{DnsFilterConfig, NamedList};
use crate::use_cases::repositories::FilterCacheRepository;
use crate::use_cases::repository_types::FilterCacheDocumentRecord;
use anyhow::{anyhow, Context, Result};
use common::{matches_any, normalize_domain, ListFormat, ParseDomainLineResult, ParsedLine};
use serde::{Deserialize, Serialize};

const DEFAULT_LIST_INTERVAL_SECS: u64 = 12 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListKind {
    Block,
    Allow,
}

#[derive(Debug, Clone)]
struct ListRuntime {
    key: String,
    name: String,
    url: String,
    interval: Duration,
    kind: ListKind,
    format: ListFormat,
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
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct ListInfo {
    pub name: String,
    pub url: String,
    pub kind: &'static str,
    pub list_type: &'static str,
    pub enabled: bool,
    pub interval_secs: u64,
    pub domain_count: usize,
    pub exception_count: usize,
}

pub struct ListFilterEngine {
    sinkhole_v4: Ipv4Addr,
    sinkhole_v6: Ipv6Addr,
    runtimes: Vec<ListRuntime>,
    cache_repo: Option<Arc<dyn FilterCacheRepository>>,
    lists: Arc<RwLock<HashMap<String, ListDomains>>>,
    snapshot: Arc<RwLock<FilterSnapshot>>,
}

impl ListFilterEngine {
    pub fn from_config(config: &DnsFilterConfig) -> Result<Self> {
        Self::from_config_with_cache(config, None)
    }

    pub fn from_config_with_cache(
        config: &DnsFilterConfig,
        cache_repo: Option<Arc<dyn FilterCacheRepository>>,
    ) -> Result<Self> {
        let (sinkhole_v4, sinkhole_v6) = parse_sinkhole_addrs(config)?;

        let mut runtimes = Vec::new();
        runtimes.extend(build_runtimes(&config.blocklists, ListKind::Block)?);
        runtimes.extend(build_runtimes(&config.allowlists, ListKind::Allow)?);

        let engine = Self {
            sinkhole_v4,
            sinkhole_v6,
            runtimes,
            cache_repo,
            lists: Arc::new(RwLock::new(HashMap::new())),
            snapshot: Arc::new(RwLock::new(FilterSnapshot::default())),
        };

        // Synchronous restore from cache at startup.
        // We use `block_in_place` + `block_on` because the engine is constructed
        // inside an async context and we need to call async cache repo methods.
        if engine.cache_repo.is_some() {
            tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(engine.try_restore_document_cache());
            });
        }

        Ok(engine)
    }

    fn clone_refresh_handle(&self) -> Self {
        Self {
            sinkhole_v4: self.sinkhole_v4,
            sinkhole_v6: self.sinkhole_v6,
            runtimes: self.runtimes.clone(),
            cache_repo: self.cache_repo.clone(),
            lists: Arc::clone(&self.lists),
            snapshot: Arc::clone(&self.snapshot),
        }
    }

    async fn refresh_single_list(&self, runtime: &ListRuntime) {
        match fetch_list_content(&runtime.url).await {
            Ok(content) => {
                let (domains, exceptions, skipped_entries_added) =
                    parse_list_content(&content, runtime.format);
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
        let Some(cache_repo) = &self.cache_repo else {
            return Ok(());
        };

        let mut domain_vec = domains.iter().cloned().collect::<Vec<_>>();
        domain_vec.sort();

        let mut exception_vec = exceptions.iter().cloned().collect::<Vec<_>>();
        exception_vec.sort();

        let key = runtime.key.clone();
        let kind = CachedListKind::from(runtime.kind);

        let doc = CachedListDocument {
            kind,
            domains: domain_vec,
            exceptions: exception_vec,
        };
        let payload = serde_json::to_string(&doc)
            .with_context(|| format!("failed to serialize cached document '{}'", key))?;

        cache_repo
            .store(&FilterCacheDocumentRecord {
                key,
                value: payload,
            })
            .await
            .context("failed to store cached list document")?;

        Ok(())
    }

    async fn try_restore_document_cache(&self) {
        let Some(cache_repo) = &self.cache_repo else {
            return;
        };

        let mut restored = 0usize;

        for runtime in &self.runtimes {
            match cache_repo.load(&runtime.key).await {
                Ok(Some(record)) => {
                    let document = match serde_json::from_str::<CachedListDocument>(&record.value) {
                        Ok(doc) => doc,
                        Err(e) => {
                            tracing::warn!(
                                list = %runtime.name,
                                key = %runtime.key,
                                error = %e,
                                "invalid JSON in cached list document"
                            );
                            continue;
                        }
                    };

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
                    list_type: rt.format.as_str(),
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

            let format = ListFormat::from_option(list.list_type.as_deref())
                .map_err(|e| anyhow!("invalid list_type for list '{}': {}", list.name, e))?;

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
                format,
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

/// Parses list content using the specified format and returns
/// `(blocked_domains, exception_domains, skipped_count)`.
fn parse_list_content(
    content: &str,
    format: ListFormat,
) -> (HashSet<String>, HashSet<String>, usize) {
    let mut blocks = HashSet::new();
    let mut exceptions = HashSet::new();
    let mut skipped_entries = 0usize;

    let mut collect = |result: ParseDomainLineResult| match result {
        ParseDomainLineResult::Parsed(ParsedLine::Block(d)) => {
            blocks.insert(d);
        }
        ParseDomainLineResult::Parsed(ParsedLine::Allow(d)) => {
            exceptions.insert(d);
        }
        ParseDomainLineResult::Skipped => skipped_entries += 1,
    };

    match format {
        ListFormat::Adguard => {
            for parsed in content.lines().filter_map(adguard::parse_adguard_line) {
                collect(parsed);
            }
        }
        ListFormat::Hosts => {
            for line in content.lines() {
                for parsed in hosts::parse_hosts_line(line) {
                    collect(parsed);
                }
            }
        }
        ListFormat::Rpz => {
            for parsed in content.lines().filter_map(rpz::parse_rpz_line) {
                collect(parsed);
            }
        }
        ListFormat::Domains => {
            for parsed in content.lines().filter_map(domains::parse_domain_list_line) {
                collect(parsed);
            }
        }
        ListFormat::Wildcard => {
            for parsed in content.lines().filter_map(wildcard::parse_wildcard_line) {
                collect(parsed);
            }
        }
    }

    (blocks, exceptions, skipped_entries)
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
    fn parse_list_content_adguard_separates_blocks_and_exceptions() {
        let content =
            "||ads.example.com^\n@@||safe.example.com^\n||tracker.org^$third-party\n!comment\n";
        let (blocks, exceptions, skipped_entries) =
            parse_list_content(content, ListFormat::Adguard);
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
    fn parse_list_content_adguard_counts_multiple_skipped() {
        let content =
            "||ok.example^\n||skip-modifier.example^$script\n@@plain-exception.example.com\nhttp://not-a-domain/\n# comment\n";
        let (blocks, exceptions, skipped_entries) =
            parse_list_content(content, ListFormat::Adguard);

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
    fn parse_list_content_hosts_multi_domain() {
        let content = "0.0.0.0 ads.example.com tracker.example.com\n127.0.0.1 malware.example.com\n# comment\n";
        let (blocks, exceptions, skipped) = parse_list_content(content, ListFormat::Hosts);
        assert_eq!(blocks.len(), 3);
        assert!(blocks.contains("ads.example.com"));
        assert!(blocks.contains("tracker.example.com"));
        assert!(blocks.contains("malware.example.com"));
        assert!(exceptions.is_empty());
        assert_eq!(skipped, 0);
    }

    #[test]
    fn parse_list_content_rpz_blocks_and_allows() {
        let content = "bad.example.com CNAME .\ngood.example.com CNAME rpz-passthru.\n; comment\n";
        let (blocks, exceptions, skipped) = parse_list_content(content, ListFormat::Rpz);
        assert!(blocks.contains("bad.example.com"));
        assert!(exceptions.contains("good.example.com"));
        assert_eq!(skipped, 0);
    }

    #[test]
    fn parse_list_content_domains_flat() {
        let content = "ads.example.com\ntracker.example.com\n# comment\n";
        let (blocks, exceptions, skipped) = parse_list_content(content, ListFormat::Domains);
        assert_eq!(blocks.len(), 2);
        assert!(blocks.contains("ads.example.com"));
        assert!(blocks.contains("tracker.example.com"));
        assert!(exceptions.is_empty());
        assert_eq!(skipped, 0);
    }

    #[test]
    fn parse_list_content_wildcard() {
        let content = "*.ads.example.com\ntracker.example.com\n# comment\n";
        let (blocks, exceptions, skipped) = parse_list_content(content, ListFormat::Wildcard);
        assert_eq!(blocks.len(), 2);
        assert!(blocks.contains("ads.example.com"));
        assert!(blocks.contains("tracker.example.com"));
        assert!(exceptions.is_empty());
        assert_eq!(skipped, 0);
    }

    #[test]
    fn build_runtimes_skips_disabled_lists() {
        let lists = vec![
            NamedList {
                name: "enabled".into(),
                url: "https://example.com/1".into(),
                interval: Some("12h".into()),
                enabled: Some(true),
                list_type: None,
            },
            NamedList {
                name: "disabled".into(),
                url: "https://example.com/2".into(),
                interval: Some("12h".into()),
                enabled: Some(false),
                list_type: None,
            },
            NamedList {
                name: "default".into(),
                url: "https://example.com/3".into(),
                interval: None,
                enabled: None,
                list_type: None,
            },
        ];

        let runtimes = build_runtimes(&lists, ListKind::Block).expect("runtimes should build");
        assert_eq!(runtimes.len(), 2);
        assert_eq!(runtimes[0].name, "enabled");
        assert_eq!(runtimes[1].name, "default");
    }

    #[test]
    fn build_runtimes_parses_list_type() {
        let lists = vec![
            NamedList {
                name: "hosts_list".into(),
                url: "https://example.com/hosts".into(),
                interval: None,
                enabled: Some(true),
                list_type: Some("hosts".into()),
            },
            NamedList {
                name: "rpz_list".into(),
                url: "https://example.com/rpz".into(),
                interval: None,
                enabled: Some(true),
                list_type: Some("rpz".into()),
            },
            NamedList {
                name: "default_type".into(),
                url: "https://example.com/default".into(),
                interval: None,
                enabled: Some(true),
                list_type: None,
            },
        ];

        let runtimes = build_runtimes(&lists, ListKind::Block).expect("runtimes should build");
        assert_eq!(runtimes[0].format, ListFormat::Hosts);
        assert_eq!(runtimes[1].format, ListFormat::Rpz);
        assert_eq!(runtimes[2].format, ListFormat::Adguard);
    }

    #[test]
    fn build_runtimes_rejects_invalid_list_type() {
        let lists = vec![NamedList {
            name: "bad".into(),
            url: "https://example.com/bad".into(),
            interval: None,
            enabled: Some(true),
            list_type: Some("invalid-format".into()),
        }];

        assert!(build_runtimes(&lists, ListKind::Block).is_err());
    }
}
