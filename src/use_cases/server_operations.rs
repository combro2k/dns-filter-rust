use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use thiserror::Error;
use tokio::sync::mpsc;

use crate::entities::filter::FilterDecision;
use crate::entities::query_log::{QueryLog, QueryLogEntry};
use crate::use_cases::filtering::{DomainFilter, ListInfo};
use crate::use_cases::zone_registry::{ZoneInfo, ZoneRegistry, ZoneSearchResult};

/// Atomic query counters shared across the application.
pub struct QueryStats {
    pub queries_total: AtomicU64,
    pub queries_blocked: AtomicU64,
    pub queries_allowed: AtomicU64,
    pub queries_passthrough: AtomicU64,
}

impl Default for QueryStats {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryStats {
    pub fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            queries_blocked: AtomicU64::new(0),
            queries_allowed: AtomicU64::new(0),
            queries_passthrough: AtomicU64::new(0),
        }
    }
}

/// Errors from server operation calls.
#[derive(Debug, Error)]
pub enum ServerOperationError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("reload channel closed; reload handler not running")]
    ChannelClosed,
}

/// Shared business logic for all management interfaces (MCP, HTTP API, control socket).
pub struct ServerOperations {
    pub(crate) domain_filter: Arc<dyn DomainFilter>,
    pub(crate) filtering_enabled: Arc<AtomicBool>,
    pub(crate) query_log: Option<Arc<Mutex<QueryLog>>>,
    pub(crate) reload_tx: mpsc::Sender<()>,
    pub(crate) start_time: u64,
    pub(crate) stats: Arc<QueryStats>,
    pub(crate) zone_registry: Option<Arc<ZoneRegistry>>,
}

const DEFAULT_SEARCH_LIMIT: usize = 50;
const MAX_SEARCH_LIMIT: usize = 500;

impl ServerOperations {
    pub fn new(
        domain_filter: Arc<dyn DomainFilter>,
        filtering_enabled: Arc<AtomicBool>,
        query_log: Option<Arc<Mutex<QueryLog>>>,
        reload_tx: mpsc::Sender<()>,
        start_time: u64,
        stats: Arc<QueryStats>,
    ) -> Self {
        Self {
            domain_filter,
            filtering_enabled,
            query_log,
            reload_tx,
            start_time,
            stats,
            zone_registry: None,
        }
    }

    pub fn with_zone_registry(mut self, registry: Arc<ZoneRegistry>) -> Self {
        self.zone_registry = Some(registry);
        self
    }

    pub fn stats(&self) -> &Arc<QueryStats> {
        &self.stats
    }

    pub fn domain_filter(&self) -> &Arc<dyn DomainFilter> {
        &self.domain_filter
    }

    pub fn filtering_enabled(&self) -> &Arc<AtomicBool> {
        &self.filtering_enabled
    }

    fn uptime_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.start_time)
    }

    pub fn dns_lookup(&self, domain: &str) -> DnsLookupResult {
        let decision = self.domain_filter.decide(domain);
        let status = match decision {
            FilterDecision::Allow => "allowed",
            FilterDecision::Block => "blocked",
            FilterDecision::Neutral => "neutral (passthrough)",
        };
        DnsLookupResult {
            domain: domain.to_string(),
            decision: status,
            filtering_enabled: self.filtering_enabled.load(Ordering::Relaxed),
        }
    }

    pub fn filter_status(&self) -> FilterStatusResult {
        FilterStatusResult {
            filtering_enabled: self.filtering_enabled.load(Ordering::Relaxed),
        }
    }

    pub fn set_filtering(&self, enabled: bool) -> FilterToggleResult {
        self.filtering_enabled.store(enabled, Ordering::Relaxed);
        let message = if enabled {
            "filtering enabled".to_string()
        } else {
            "filtering disabled".to_string()
        };
        FilterToggleResult {
            filtering_enabled: enabled,
            message,
        }
    }

    pub fn list_filters(&self) -> Vec<ListInfo> {
        self.domain_filter.list_names()
    }

    pub fn refresh_list(&self, name: &str) -> Result<RefreshResult, ServerOperationError> {
        if self.domain_filter.refresh_list(name) {
            Ok(RefreshResult {
                list: name.to_string(),
                status: "refreshing",
            })
        } else {
            Err(ServerOperationError::NotFound(format!(
                "list '{name}' not found"
            )))
        }
    }

    pub fn refresh_all_lists(&self) -> RefreshAllResult {
        let refreshed = self.domain_filter.refresh_all_lists();
        RefreshAllResult {
            lists_refreshing: refreshed,
        }
    }

    pub fn get_stats(&self) -> StatsResult {
        StatsResult {
            uptime_seconds: self.uptime_secs(),
            filtering_enabled: self.filtering_enabled.load(Ordering::Relaxed),
            queries_total: self.stats.queries_total.load(Ordering::Relaxed),
            queries_blocked: self.stats.queries_blocked.load(Ordering::Relaxed),
            queries_allowed: self.stats.queries_allowed.load(Ordering::Relaxed),
            queries_passthrough: self.stats.queries_passthrough.load(Ordering::Relaxed),
            lists: self.domain_filter.list_names(),
        }
    }

    pub fn get_query_log(&self) -> Result<QueryLogResult, ServerOperationError> {
        let query_log = self.query_log.as_ref().ok_or_else(|| {
            ServerOperationError::Unavailable(
                "query logging is not enabled; set api.query_logging.enabled = true in config"
                    .to_string(),
            )
        })?;

        let log = query_log
            .lock()
            .expect("query log lock poisoned while reading");

        Ok(QueryLogResult {
            total: log.len(),
            max_entries: log.max_entries(),
            entries: log.entries().clone(),
        })
    }

    pub async fn trigger_reload(&self) -> Result<ReloadResult, ServerOperationError> {
        self.reload_tx
            .send(())
            .await
            .map_err(|_| ServerOperationError::ChannelClosed)?;
        Ok(ReloadResult {
            status: "triggered",
            message: "configuration reload initiated",
        })
    }

    pub fn server_health(&self) -> HealthResult {
        HealthResult {
            status: "healthy",
            version: env!("CARGO_PKG_VERSION"),
            uptime_seconds: self.uptime_secs(),
            filtering_enabled: self.filtering_enabled.load(Ordering::Relaxed),
        }
    }

    pub fn enable_list(&self, name: &str) -> Result<ListActionResult, ServerOperationError> {
        if self.domain_filter.enable_list(name) {
            Ok(ListActionResult {
                list: name.to_string(),
                enabled: true,
            })
        } else {
            Err(ServerOperationError::NotFound(format!(
                "list '{name}' not found"
            )))
        }
    }

    pub fn disable_list(&self, name: &str) -> Result<ListActionResult, ServerOperationError> {
        if self.domain_filter.disable_list(name) {
            Ok(ListActionResult {
                list: name.to_string(),
                enabled: false,
            })
        } else {
            Err(ServerOperationError::NotFound(format!(
                "list '{name}' not found"
            )))
        }
    }

    pub fn list_zones(&self) -> Result<ZoneListResult, ServerOperationError> {
        let registry = self
            .zone_registry
            .as_ref()
            .ok_or_else(|| ServerOperationError::Internal("no zones configured".to_string()))?;
        Ok(ZoneListResult {
            zones: registry.list_zones(),
            total: registry.zone_count(),
        })
    }

    pub fn search_zone_records(
        &self,
        query: &str,
        zone: Option<&str>,
        record_type: Option<&str>,
        limit: Option<usize>,
    ) -> Result<ZoneSearchResultList, ServerOperationError> {
        let registry = self
            .zone_registry
            .as_ref()
            .ok_or_else(|| ServerOperationError::Internal("no zones configured".to_string()))?;
        let limit = limit.unwrap_or(DEFAULT_SEARCH_LIMIT).min(MAX_SEARCH_LIMIT);
        let (results, total_matches) = registry.search_records(query, zone, record_type, limit);
        Ok(ZoneSearchResultList {
            query: query.to_string(),
            results,
            total_matches,
            limit,
        })
    }
}

// --- Result types ---

#[derive(Debug, Serialize)]
pub struct DnsLookupResult {
    pub domain: String,
    pub decision: &'static str,
    pub filtering_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct FilterStatusResult {
    pub filtering_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct FilterToggleResult {
    pub filtering_enabled: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct StatsResult {
    pub uptime_seconds: u64,
    pub filtering_enabled: bool,
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub queries_allowed: u64,
    pub queries_passthrough: u64,
    pub lists: Vec<ListInfo>,
}

#[derive(Debug, Serialize)]
pub struct QueryLogResult {
    pub total: usize,
    pub max_entries: usize,
    pub entries: VecDeque<QueryLogEntry>,
}

#[derive(Debug, Serialize)]
pub struct HealthResult {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub filtering_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct ListActionResult {
    pub list: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct RefreshResult {
    pub list: String,
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct RefreshAllResult {
    pub lists_refreshing: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReloadResult {
    pub status: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ZoneListResult {
    pub zones: Vec<ZoneInfo>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct ZoneSearchResultList {
    pub query: String,
    pub results: Vec<ZoneSearchResult>,
    pub total_matches: usize,
    pub limit: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    struct MockFilter;

    impl DomainFilter for MockFilter {
        fn decide(&self, domain: &str) -> FilterDecision {
            if domain == "blocked.example.com" {
                FilterDecision::Block
            } else if domain == "allowed.example.com" {
                FilterDecision::Allow
            } else {
                FilterDecision::Neutral
            }
        }
        fn sinkhole_ipv4(&self) -> Ipv4Addr {
            Ipv4Addr::UNSPECIFIED
        }
        fn sinkhole_ipv6(&self) -> Ipv6Addr {
            Ipv6Addr::UNSPECIFIED
        }
        fn start_background_refresh(self: Arc<Self>) {}
        fn list_names(&self) -> Vec<ListInfo> {
            vec![ListInfo {
                name: "test-list".to_string(),
                url: "https://example.com/list.txt".to_string(),
                kind: "block",
                enabled: true,
                interval_secs: 3600,
                domain_count: 100,
                exception_count: 5,
            }]
        }
        fn disable_list(&self, name: &str) -> bool {
            name == "test-list"
        }
        fn enable_list(&self, name: &str) -> bool {
            name == "test-list"
        }
        fn refresh_list(&self, name: &str) -> bool {
            name == "test-list"
        }
        fn refresh_all_lists(&self) -> Vec<String> {
            vec!["test-list".to_string()]
        }
    }

    fn make_ops() -> ServerOperations {
        let (tx, _rx) = mpsc::channel(1);
        ServerOperations::new(
            Arc::new(MockFilter),
            Arc::new(AtomicBool::new(true)),
            None,
            tx,
            1000,
            Arc::new(QueryStats::new()),
        )
    }

    #[test]
    fn dns_lookup_blocked() {
        let ops = make_ops();
        let result = ops.dns_lookup("blocked.example.com");
        assert_eq!(result.decision, "blocked");
        assert!(result.filtering_enabled);
    }

    #[test]
    fn dns_lookup_allowed() {
        let ops = make_ops();
        let result = ops.dns_lookup("allowed.example.com");
        assert_eq!(result.decision, "allowed");
    }

    #[test]
    fn dns_lookup_neutral() {
        let ops = make_ops();
        let result = ops.dns_lookup("unknown.example.com");
        assert_eq!(result.decision, "neutral (passthrough)");
    }

    #[test]
    fn filter_toggle() {
        let ops = make_ops();
        let result = ops.set_filtering(false);
        assert!(!result.filtering_enabled);
        assert_eq!(result.message, "filtering disabled");

        let result = ops.set_filtering(true);
        assert!(result.filtering_enabled);
        assert_eq!(result.message, "filtering enabled");
    }

    #[test]
    fn filter_status_reads_current() {
        let ops = make_ops();
        assert!(ops.filter_status().filtering_enabled);
        ops.set_filtering(false);
        assert!(!ops.filter_status().filtering_enabled);
    }

    #[test]
    fn list_filters_returns_lists() {
        let ops = make_ops();
        let lists = ops.list_filters();
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].name, "test-list");
    }

    #[test]
    fn refresh_list_found() {
        let ops = make_ops();
        let result = ops.refresh_list("test-list");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status, "refreshing");
    }

    #[test]
    fn refresh_list_not_found() {
        let ops = make_ops();
        let result = ops.refresh_list("no-such-list");
        assert!(result.is_err());
    }

    #[test]
    fn refresh_all_lists_returns_names() {
        let ops = make_ops();
        let result = ops.refresh_all_lists();
        assert_eq!(result.lists_refreshing, vec!["test-list"]);
    }

    #[test]
    fn get_stats_returns_counters() {
        let ops = make_ops();
        ops.stats.queries_total.store(42, Ordering::Relaxed);
        ops.stats.queries_blocked.store(10, Ordering::Relaxed);
        let result = ops.get_stats();
        assert_eq!(result.queries_total, 42);
        assert_eq!(result.queries_blocked, 10);
        assert!(result.filtering_enabled);
    }

    #[test]
    fn get_query_log_unavailable() {
        let ops = make_ops();
        let result = ops.get_query_log();
        assert!(result.is_err());
    }

    #[test]
    fn get_query_log_available() {
        let (tx, _rx) = mpsc::channel(1);
        let ops = ServerOperations::new(
            Arc::new(MockFilter),
            Arc::new(AtomicBool::new(true)),
            Some(Arc::new(Mutex::new(QueryLog::new(100)))),
            tx,
            1000,
            Arc::new(QueryStats::new()),
        );
        let result = ops.get_query_log();
        assert!(result.is_ok());
        let log = result.unwrap();
        assert_eq!(log.total, 0);
        assert_eq!(log.max_entries, 100);
    }

    #[test]
    fn server_health_returns_version() {
        let ops = make_ops();
        let result = ops.server_health();
        assert_eq!(result.status, "healthy");
        assert_eq!(result.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn enable_list_found() {
        let ops = make_ops();
        let result = ops.enable_list("test-list");
        assert!(result.is_ok());
        assert!(result.unwrap().enabled);
    }

    #[test]
    fn enable_list_not_found() {
        let ops = make_ops();
        let result = ops.enable_list("no-such-list");
        assert!(result.is_err());
    }

    #[test]
    fn disable_list_found() {
        let ops = make_ops();
        let result = ops.disable_list("test-list");
        assert!(result.is_ok());
        assert!(!result.unwrap().enabled);
    }

    #[test]
    fn disable_list_not_found() {
        let ops = make_ops();
        let result = ops.disable_list("no-such-list");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn trigger_reload_succeeds() {
        let (tx, mut rx) = mpsc::channel(1);
        let ops = ServerOperations::new(
            Arc::new(MockFilter),
            Arc::new(AtomicBool::new(true)),
            None,
            tx,
            1000,
            Arc::new(QueryStats::new()),
        );
        let result = ops.trigger_reload().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status, "triggered");
        // Verify signal was sent
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn trigger_reload_channel_closed() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let ops = ServerOperations::new(
            Arc::new(MockFilter),
            Arc::new(AtomicBool::new(true)),
            None,
            tx,
            1000,
            Arc::new(QueryStats::new()),
        );
        let result = ops.trigger_reload().await;
        assert!(result.is_err());
    }
}
