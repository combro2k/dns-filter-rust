use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;
use url::Url;
use uuid::Uuid;

use crate::entities::filter::FilterDecision;
use crate::entities::query_log::{QueryLog, QueryLogEntry};
use crate::use_cases::config_from_db::Repositories;
use crate::use_cases::filtering::{DomainFilter, ListInfo};
use crate::use_cases::repository_types::{
    FilterListRecord, UpstreamServerRecord, ZoneDiscoveryRecord, ZoneRecord, ZoneServerRecord,
};
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
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("reload channel closed; reload handler not running")]
    ChannelClosed,
}

impl From<anyhow::Error> for ServerOperationError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(format!("{e:#}"))
    }
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
    pub(crate) repos: Option<Arc<Repositories>>,
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
            repos: None,
        }
    }

    pub fn with_zone_registry(mut self, registry: Arc<ZoneRegistry>) -> Self {
        self.zone_registry = Some(registry);
        self
    }

    pub fn with_repositories(mut self, repos: Arc<Repositories>) -> Self {
        self.repos = Some(repos);
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

    // --- CRUD helpers ---

    fn repos(&self) -> Result<&Repositories, ServerOperationError> {
        self.repos
            .as_deref()
            .ok_or_else(|| ServerOperationError::Unavailable("database not configured".into()))
    }

    async fn reload_after_mutation(&self) {
        if let Err(e) = self.trigger_reload().await {
            tracing::warn!(error = %e, "failed to trigger reload after mutation");
        }
    }

    // --- Filter list CRUD ---

    pub async fn list_filter_lists(
        &self,
        kind: &str,
    ) -> Result<Vec<FilterListRecord>, ServerOperationError> {
        let repos = self.repos()?;
        let all = repos
            .filter_lists
            .get_all()
            .await
            .map_err(ServerOperationError::from)?;
        Ok(all.into_iter().filter(|r| r.kind == kind).collect())
    }

    pub async fn add_filter_list(
        &self,
        kind: &str,
        input: CreateFilterListInput,
    ) -> Result<FilterListRecord, ServerOperationError> {
        validate_list_name(&input.name)?;
        validate_url(&input.url)?;
        let list_type = input.list_type.unwrap_or_else(|| "adguard".to_string());
        validate_list_type(&list_type)?;
        let interval = parse_interval_secs(input.interval.as_deref());

        let repos = self.repos()?;

        // Check name uniqueness
        if repos
            .filter_lists
            .get_by_name(&input.name)
            .await
            .map_err(ServerOperationError::from)?
            .is_some()
        {
            return Err(ServerOperationError::InvalidInput(format!(
                "a filter list named '{}' already exists",
                input.name
            )));
        }

        let record = FilterListRecord {
            id: Uuid::new_v4().to_string(),
            name: input.name,
            kind: kind.to_string(),
            url: input.url,
            interval_seconds: interval,
            enabled: input.enabled.unwrap_or(true),
            list_type,
        };

        repos
            .filter_lists
            .create(&record)
            .await
            .map_err(ServerOperationError::from)?;

        self.reload_after_mutation().await;
        Ok(record)
    }

    pub async fn update_filter_list(
        &self,
        name: &str,
        input: UpdateFilterListInput,
    ) -> Result<FilterListRecord, ServerOperationError> {
        let repos = self.repos()?;
        let mut record = repos
            .filter_lists
            .get_by_name(name)
            .await
            .map_err(ServerOperationError::from)?
            .ok_or_else(|| {
                ServerOperationError::NotFound(format!("filter list '{name}' not found"))
            })?;

        if let Some(url) = input.url {
            validate_url(&url)?;
            record.url = url;
        }
        if let Some(interval) = input.interval {
            record.interval_seconds = parse_interval_secs(Some(&interval));
        }
        if let Some(enabled) = input.enabled {
            record.enabled = enabled;
        }
        if let Some(list_type) = input.list_type {
            validate_list_type(&list_type)?;
            record.list_type = list_type;
        }

        repos
            .filter_lists
            .update(&record)
            .await
            .map_err(ServerOperationError::from)?;

        self.reload_after_mutation().await;
        Ok(record)
    }

    pub async fn delete_filter_list(
        &self,
        name: &str,
    ) -> Result<DeleteResult, ServerOperationError> {
        let repos = self.repos()?;
        let record = repos
            .filter_lists
            .get_by_name(name)
            .await
            .map_err(ServerOperationError::from)?
            .ok_or_else(|| {
                ServerOperationError::NotFound(format!("filter list '{name}' not found"))
            })?;

        repos
            .filter_lists
            .delete(&record.id)
            .await
            .map_err(ServerOperationError::from)?;

        self.reload_after_mutation().await;
        Ok(DeleteResult {
            deleted: name.to_string(),
        })
    }

    // --- Upstream server CRUD ---

    pub async fn list_upstream_servers(
        &self,
    ) -> Result<Vec<UpstreamServerRecord>, ServerOperationError> {
        let repos = self.repos()?;
        repos
            .upstream_config
            .get_all_servers()
            .await
            .map_err(ServerOperationError::from)
    }

    pub async fn add_upstream_server(
        &self,
        input: CreateUpstreamServerInput,
    ) -> Result<UpstreamServerRecord, ServerOperationError> {
        validate_upstream_protocol(&input.protocol)?;
        validate_upstream_address(&input.protocol, &input.address)?;
        validate_bind_address(input.bind_address.as_deref())?;
        let fwmark = parse_fwmark(input.fwmark)?;

        let repos = self.repos()?;
        let sort_order = match input.sort_order {
            Some(value) => validate_sort_order(value)?,
            None => repos
                .upstream_config
                .get_all_servers()
                .await
                .map_err(ServerOperationError::from)?
                .len() as i32,
        };

        let auth = input.authentication.as_ref();
        let record = UpstreamServerRecord {
            id: Uuid::new_v4().to_string(),
            enabled: input.enabled.unwrap_or(true),
            protocol: input.protocol,
            address: input.address,
            auth_token: auth.and_then(|a| a.token.clone()),
            auth_username: auth.and_then(|a| a.username.clone()),
            auth_password: auth.and_then(|a| a.password.clone()),
            max_hops: input.max_hops.map(i32::from),
            nameserver_ip_family: input.nameserver_ip_family,
            root_hints_path: input.root_hints_path,
            root_key_path: input.root_key_path,
            dnssec: input.dnssec.unwrap_or(true),
            sort_order,
            bind_address: input.bind_address,
            fwmark,
        };

        repos
            .upstream_config
            .create_server(&record)
            .await
            .map_err(ServerOperationError::from)?;

        self.reload_after_mutation().await;
        Ok(record)
    }

    pub async fn update_upstream_server(
        &self,
        id: &str,
        input: UpdateUpstreamServerInput,
    ) -> Result<UpstreamServerRecord, ServerOperationError> {
        let repos = self.repos()?;
        let mut record = repos
            .upstream_config
            .get_server_by_id(id)
            .await
            .map_err(ServerOperationError::from)?
            .ok_or_else(|| {
                ServerOperationError::NotFound(format!("upstream server '{id}' not found"))
            })?;

        if let Some(enabled) = input.enabled {
            record.enabled = enabled;
        }
        if let Some(protocol) = input.protocol {
            validate_upstream_protocol(&protocol)?;
            record.protocol = protocol;
        }
        if let Some(address) = input.address {
            validate_upstream_address(&record.protocol, &address)?;
            record.address = address;
        }
        validate_upstream_address(&record.protocol, &record.address)?;
        if let Some(authentication) = input.authentication {
            record.auth_token = authentication.token;
            record.auth_username = authentication.username;
            record.auth_password = authentication.password;
        }
        if let Some(max_hops) = input.max_hops {
            record.max_hops = Some(i32::from(max_hops));
        }
        if let Some(nameserver_ip_family) = input.nameserver_ip_family {
            record.nameserver_ip_family = Some(nameserver_ip_family);
        }
        if let Some(root_hints_path) = input.root_hints_path {
            record.root_hints_path = Some(root_hints_path);
        }
        if let Some(root_key_path) = input.root_key_path {
            record.root_key_path = Some(root_key_path);
        }
        if let Some(dnssec) = input.dnssec {
            record.dnssec = dnssec;
        }
        if let Some(bind_address) = input.bind_address {
            match bind_address {
                Some(value) => {
                    validate_bind_address(Some(&value))?;
                    record.bind_address = Some(value);
                }
                None => {
                    record.bind_address = None;
                }
            }
        }
        if let Some(fwmark) = input.fwmark {
            record.fwmark = match fwmark {
                Some(value) => Some(parse_single_fwmark(value)?),
                None => None,
            };
        }
        if let Some(sort_order) = input.sort_order {
            record.sort_order = validate_sort_order(sort_order)?;
        }

        repos
            .upstream_config
            .update_server(&record)
            .await
            .map_err(ServerOperationError::from)?;

        self.reload_after_mutation().await;
        Ok(record)
    }

    pub async fn delete_upstream_server(
        &self,
        id: &str,
    ) -> Result<DeleteResult, ServerOperationError> {
        let repos = self.repos()?;
        repos
            .upstream_config
            .get_server_by_id(id)
            .await
            .map_err(ServerOperationError::from)?
            .ok_or_else(|| {
                ServerOperationError::NotFound(format!("upstream server '{id}' not found"))
            })?;

        repos
            .upstream_config
            .delete_server(id)
            .await
            .map_err(ServerOperationError::from)?;

        self.reload_after_mutation().await;
        Ok(DeleteResult {
            deleted: id.to_string(),
        })
    }

    // --- Zone CRUD ---

    pub async fn list_zone_configs(&self) -> Result<Vec<ZoneRecord>, ServerOperationError> {
        let repos = self.repos()?;
        repos
            .zones
            .get_all_with_servers()
            .await
            .map_err(ServerOperationError::from)
    }

    pub async fn add_zone(
        &self,
        input: CreateZoneInput,
    ) -> Result<ZoneRecord, ServerOperationError> {
        validate_zone_name(&input.zone)?;

        let repos = self.repos()?;

        // Check zone uniqueness
        if repos
            .zones
            .get_by_zone(&input.zone)
            .await
            .map_err(ServerOperationError::from)?
            .is_some()
        {
            return Err(ServerOperationError::InvalidInput(format!(
                "zone '{}' already exists",
                input.zone
            )));
        }

        let zone_id = Uuid::new_v4().to_string();
        let zone_record = ZoneRecord {
            id: zone_id.clone(),
            zone: input.zone,
            enabled: input.enabled.unwrap_or(true),
            bypass_filter: input.bypass_filter.unwrap_or(false),
            fallback_to_default_resolvers: input.fallback_to_default_resolvers.unwrap_or(false),
            strategy: input.strategy,
            servers: Vec::new(),
        };

        repos
            .zones
            .create_zone(&zone_record)
            .await
            .map_err(ServerOperationError::from)?;

        let mut server_records = Vec::new();
        for (i, server) in input.servers.unwrap_or_default().into_iter().enumerate() {
            validate_protocol(&server.protocol)?;
            let auth = server.authentication.as_ref();
            let rec = ZoneServerRecord {
                id: Uuid::new_v4().to_string(),
                zone_id: zone_id.clone(),
                enabled: server.enabled.unwrap_or(true),
                protocol: server.protocol,
                address: server.address,
                auth_token: auth.and_then(|a| a.token.clone()),
                auth_username: auth.and_then(|a| a.username.clone()),
                auth_password: auth.and_then(|a| a.password.clone()),
                check_interval: server.check_interval,
                max_hops: server.max_hops.map(|v| v as i32),
                nameserver_ip_family: server.nameserver_ip_family,
                root_hints_path: server.root_hints_path,
                root_key_path: server.root_key_path,
                dnssec: server.dnssec.unwrap_or(true),
                sort_order: i as i32,
            };
            repos
                .zones
                .create_zone_server(&rec)
                .await
                .map_err(ServerOperationError::from)?;
            server_records.push(rec);
        }

        self.reload_after_mutation().await;
        Ok(ZoneRecord {
            servers: server_records,
            ..zone_record
        })
    }

    pub async fn update_zone(
        &self,
        zone_name: &str,
        input: UpdateZoneInput,
    ) -> Result<ZoneRecord, ServerOperationError> {
        let repos = self.repos()?;
        let mut record = repos
            .zones
            .get_by_zone(zone_name)
            .await
            .map_err(ServerOperationError::from)?
            .ok_or_else(|| {
                ServerOperationError::NotFound(format!("zone '{zone_name}' not found"))
            })?;

        if let Some(enabled) = input.enabled {
            record.enabled = enabled;
        }
        if let Some(bypass_filter) = input.bypass_filter {
            record.bypass_filter = bypass_filter;
        }
        if let Some(fallback) = input.fallback_to_default_resolvers {
            record.fallback_to_default_resolvers = fallback;
        }
        if let Some(strategy) = input.strategy {
            record.strategy = Some(strategy);
        }

        repos
            .zones
            .update_zone(&record)
            .await
            .map_err(ServerOperationError::from)?;

        // Replace servers if provided
        if let Some(servers) = input.servers {
            repos
                .zones
                .delete_zone_servers(&record.id)
                .await
                .map_err(ServerOperationError::from)?;

            let mut server_records = Vec::new();
            for (i, server) in servers.into_iter().enumerate() {
                validate_protocol(&server.protocol)?;
                let auth = server.authentication.as_ref();
                let rec = ZoneServerRecord {
                    id: Uuid::new_v4().to_string(),
                    zone_id: record.id.clone(),
                    enabled: server.enabled.unwrap_or(true),
                    protocol: server.protocol,
                    address: server.address,
                    auth_token: auth.and_then(|a| a.token.clone()),
                    auth_username: auth.and_then(|a| a.username.clone()),
                    auth_password: auth.and_then(|a| a.password.clone()),
                    check_interval: server.check_interval,
                    max_hops: server.max_hops.map(|v| v as i32),
                    nameserver_ip_family: server.nameserver_ip_family,
                    root_hints_path: server.root_hints_path,
                    root_key_path: server.root_key_path,
                    dnssec: server.dnssec.unwrap_or(true),
                    sort_order: i as i32,
                };
                repos
                    .zones
                    .create_zone_server(&rec)
                    .await
                    .map_err(ServerOperationError::from)?;
                server_records.push(rec);
            }
            record.servers = server_records;
        }

        self.reload_after_mutation().await;
        Ok(record)
    }

    pub async fn delete_zone(&self, zone_name: &str) -> Result<DeleteResult, ServerOperationError> {
        let repos = self.repos()?;
        let record = repos
            .zones
            .get_by_zone(zone_name)
            .await
            .map_err(ServerOperationError::from)?
            .ok_or_else(|| {
                ServerOperationError::NotFound(format!("zone '{zone_name}' not found"))
            })?;

        repos
            .zones
            .delete_zone(&record.id)
            .await
            .map_err(ServerOperationError::from)?;

        self.reload_after_mutation().await;
        Ok(DeleteResult {
            deleted: zone_name.to_string(),
        })
    }

    // --- Zone discovery CRUD ---

    pub async fn list_zone_discovery(
        &self,
    ) -> Result<Vec<ZoneDiscoveryRecord>, ServerOperationError> {
        let repos = self.repos()?;
        repos
            .zone_discovery
            .get_all()
            .await
            .map_err(ServerOperationError::from)
    }

    pub async fn add_zone_discovery(
        &self,
        input: CreateZoneDiscoveryInput,
    ) -> Result<ZoneDiscoveryRecord, ServerOperationError> {
        validate_url(&input.address)?;
        if let Some(ref types) = input.allowed_types {
            for t in types {
                validate_allowed_type(t)?;
            }
        }

        let allowed_types = input
            .allowed_types
            .unwrap_or_else(|| vec!["forward".into(), "reverse".into()]);

        let auth = input.authentication.as_ref();
        let record = ZoneDiscoveryRecord {
            id: Uuid::new_v4().to_string(),
            enabled: input.enabled.unwrap_or(true),
            address: input.address,
            check_interval: input.check_interval,
            allowed_types,
            bypass_filter: input.bypass_filter.unwrap_or(false),
            fallback_to_default_resolvers: input.fallback_to_default_resolvers.unwrap_or(false),
            auth_token: auth.and_then(|a| a.token.clone()),
            auth_username: auth.and_then(|a| a.username.clone()),
            auth_password: auth.and_then(|a| a.password.clone()),
        };

        let repos = self.repos()?;
        repos
            .zone_discovery
            .create(&record)
            .await
            .map_err(ServerOperationError::from)?;

        self.reload_after_mutation().await;
        Ok(record)
    }

    pub async fn update_zone_discovery(
        &self,
        id: &str,
        input: UpdateZoneDiscoveryInput,
    ) -> Result<ZoneDiscoveryRecord, ServerOperationError> {
        let repos = self.repos()?;
        let mut record = repos
            .zone_discovery
            .get_by_id(id)
            .await
            .map_err(ServerOperationError::from)?
            .ok_or_else(|| {
                ServerOperationError::NotFound(format!("zone discovery '{id}' not found"))
            })?;

        if let Some(address) = input.address {
            validate_url(&address)?;
            record.address = address;
        }
        if let Some(enabled) = input.enabled {
            record.enabled = enabled;
        }
        if let Some(check_interval) = input.check_interval {
            record.check_interval = Some(check_interval);
        }
        if let Some(ref types) = input.allowed_types {
            for t in types {
                validate_allowed_type(t)?;
            }
            record.allowed_types = types.clone();
        }
        if let Some(bypass_filter) = input.bypass_filter {
            record.bypass_filter = bypass_filter;
        }
        if let Some(fallback) = input.fallback_to_default_resolvers {
            record.fallback_to_default_resolvers = fallback;
        }
        if let Some(ref auth) = input.authentication {
            record.auth_token = auth.token.clone();
            record.auth_username = auth.username.clone();
            record.auth_password = auth.password.clone();
        }

        repos
            .zone_discovery
            .update(&record)
            .await
            .map_err(ServerOperationError::from)?;

        self.reload_after_mutation().await;
        Ok(record)
    }

    pub async fn delete_zone_discovery(
        &self,
        id: &str,
    ) -> Result<DeleteResult, ServerOperationError> {
        let repos = self.repos()?;

        // Verify it exists
        repos
            .zone_discovery
            .get_by_id(id)
            .await
            .map_err(ServerOperationError::from)?
            .ok_or_else(|| {
                ServerOperationError::NotFound(format!("zone discovery '{id}' not found"))
            })?;

        repos
            .zone_discovery
            .delete(id)
            .await
            .map_err(ServerOperationError::from)?;

        self.reload_after_mutation().await;
        Ok(DeleteResult {
            deleted: id.to_string(),
        })
    }
}

// --- Input types ---

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct CreateFilterListInput {
    pub name: String,
    pub url: String,
    pub interval: Option<String>,
    pub enabled: Option<bool>,
    pub list_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct UpdateFilterListInput {
    pub url: Option<String>,
    pub interval: Option<String>,
    pub enabled: Option<bool>,
    pub list_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct CreateUpstreamServerInput {
    pub enabled: Option<bool>,
    pub protocol: String,
    pub address: String,
    pub authentication: Option<AuthenticationInput>,
    pub max_hops: Option<u8>,
    pub nameserver_ip_family: Option<String>,
    pub root_hints_path: Option<String>,
    pub root_key_path: Option<String>,
    pub dnssec: Option<bool>,
    pub bind_address: Option<String>,
    pub fwmark: Option<u32>,
    pub sort_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct UpdateUpstreamServerInput {
    pub enabled: Option<bool>,
    pub protocol: Option<String>,
    pub address: Option<String>,
    pub authentication: Option<AuthenticationInput>,
    pub max_hops: Option<u8>,
    pub nameserver_ip_family: Option<String>,
    pub root_hints_path: Option<String>,
    pub root_key_path: Option<String>,
    pub dnssec: Option<bool>,
    /// Source IP address to bind upstream sockets to. Pass JSON `null` to
    /// clear any existing value; omit the field to leave it unchanged.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    #[cfg_attr(
        feature = "http-api",
        schema(value_type = Option<String>, nullable = true)
    )]
    pub bind_address: Option<Option<String>>,
    /// Linux `SO_MARK` value for policy routing. Pass JSON `null` to clear
    /// any existing value; omit the field to leave it unchanged.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    #[cfg_attr(
        feature = "http-api",
        schema(value_type = Option<u32>, nullable = true)
    )]
    pub fwmark: Option<Option<u32>>,
    pub sort_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct CreateZoneInput {
    pub zone: String,
    pub enabled: Option<bool>,
    pub bypass_filter: Option<bool>,
    pub fallback_to_default_resolvers: Option<bool>,
    pub strategy: Option<String>,
    pub servers: Option<Vec<CreateZoneServerInput>>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct UpdateZoneInput {
    pub enabled: Option<bool>,
    pub bypass_filter: Option<bool>,
    pub fallback_to_default_resolvers: Option<bool>,
    pub strategy: Option<String>,
    pub servers: Option<Vec<CreateZoneServerInput>>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct CreateZoneServerInput {
    pub enabled: Option<bool>,
    pub protocol: String,
    pub address: String,
    pub authentication: Option<AuthenticationInput>,
    pub check_interval: Option<String>,
    pub max_hops: Option<u8>,
    pub nameserver_ip_family: Option<String>,
    pub root_hints_path: Option<String>,
    pub root_key_path: Option<String>,
    pub dnssec: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct CreateZoneDiscoveryInput {
    pub enabled: Option<bool>,
    pub address: String,
    pub check_interval: Option<String>,
    pub allowed_types: Option<Vec<String>>,
    pub bypass_filter: Option<bool>,
    pub fallback_to_default_resolvers: Option<bool>,
    pub authentication: Option<AuthenticationInput>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct UpdateZoneDiscoveryInput {
    pub enabled: Option<bool>,
    pub address: Option<String>,
    pub check_interval: Option<String>,
    pub allowed_types: Option<Vec<String>>,
    pub bypass_filter: Option<bool>,
    pub fallback_to_default_resolvers: Option<bool>,
    pub authentication: Option<AuthenticationInput>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct AuthenticationInput {
    pub token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

// --- Validation helpers ---

const DEFAULT_INTERVAL_SECS: i64 = 12 * 60 * 60;

fn validate_list_name(name: &str) -> Result<(), ServerOperationError> {
    if name.is_empty() {
        return Err(ServerOperationError::InvalidInput(
            "name must not be empty".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ServerOperationError::InvalidInput(
            "name must contain only ASCII alphanumeric characters, hyphens, and underscores".into(),
        ));
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<(), ServerOperationError> {
    if url.is_empty() {
        return Err(ServerOperationError::InvalidInput(
            "url must not be empty".into(),
        ));
    }
    if !url.starts_with("http://") && !url.starts_with("https://") && !url.starts_with("file://") {
        return Err(ServerOperationError::InvalidInput(
            "url must start with http://, https://, or file://".into(),
        ));
    }
    Ok(())
}

fn validate_list_type(list_type: &str) -> Result<(), ServerOperationError> {
    match list_type {
        "adguard" | "hosts" | "rpz" | "domains" | "wildcard" => Ok(()),
        _ => Err(ServerOperationError::InvalidInput(format!(
            "invalid list_type '{list_type}'; must be one of: adguard, hosts, rpz, domains, wildcard"
        ))),
    }
}

fn validate_zone_name(zone: &str) -> Result<(), ServerOperationError> {
    if zone.is_empty() {
        return Err(ServerOperationError::InvalidInput(
            "zone name must not be empty".into(),
        ));
    }
    if !zone
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(ServerOperationError::InvalidInput(
            "zone name must contain only ASCII alphanumeric characters, dots, and hyphens".into(),
        ));
    }
    Ok(())
}

fn validate_protocol(protocol: &str) -> Result<(), ServerOperationError> {
    match protocol {
        "dns" | "dot" | "doh" | "recursive" | "json" => Ok(()),
        _ => Err(ServerOperationError::InvalidInput(format!(
            "invalid protocol '{protocol}'; must be one of: dns, dot, doh, recursive, json"
        ))),
    }
}

fn validate_upstream_protocol(protocol: &str) -> Result<(), ServerOperationError> {
    match protocol {
        "dns" | "dot" | "doh" | "recursive" => Ok(()),
        _ => Err(ServerOperationError::InvalidInput(format!(
            "invalid upstream protocol '{protocol}'; must be one of: dns, dot, doh, recursive"
        ))),
    }
}

fn validate_upstream_address(protocol: &str, address: &str) -> Result<(), ServerOperationError> {
    if address.trim().is_empty() {
        return Err(ServerOperationError::InvalidInput(
            "upstream address must not be empty".into(),
        ));
    }

    if protocol == "doh" {
        let url = Url::parse(address).map_err(|e| {
            ServerOperationError::InvalidInput(format!(
                "invalid DoH upstream address '{address}': {e}"
            ))
        })?;
        if url.scheme() != "https" {
            return Err(ServerOperationError::InvalidInput(format!(
                "DoH upstream address must use https:// scheme, got '{}': {address}",
                url.scheme()
            )));
        }
        if url.host_str().is_none() {
            return Err(ServerOperationError::InvalidInput(format!(
                "DoH upstream address must include a host: {address}"
            )));
        }
    }

    Ok(())
}

fn validate_bind_address(bind_address: Option<&str>) -> Result<(), ServerOperationError> {
    let Some(bind_address) = bind_address else {
        return Ok(());
    };
    bind_address.parse::<IpAddr>().map(|_| ()).map_err(|_| {
        ServerOperationError::InvalidInput(format!(
            "invalid bind_address '{bind_address}'; must be an IPv4 or IPv6 address"
        ))
    })
}

fn validate_sort_order(sort_order: i32) -> Result<i32, ServerOperationError> {
    if sort_order < 0 {
        return Err(ServerOperationError::InvalidInput(
            "sort_order must be zero or greater".into(),
        ));
    }
    Ok(sort_order)
}

fn parse_fwmark(fwmark: Option<u32>) -> Result<Option<i32>, ServerOperationError> {
    fwmark.map(parse_single_fwmark).transpose()
}

/// Serde helper used to distinguish "field absent" from "field present and
/// null" in JSON request bodies. Absence yields `None`; explicit `null`
/// yields `Some(None)`; a value yields `Some(Some(value))`.
pub(crate) fn deserialize_optional_field<'de, T, D>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

fn parse_single_fwmark(fwmark: u32) -> Result<i32, ServerOperationError> {
    i32::try_from(fwmark).map_err(|_| {
        ServerOperationError::InvalidInput(format!(
            "invalid fwmark '{fwmark}'; must be <= {}",
            i32::MAX
        ))
    })
}

fn validate_allowed_type(allowed_type: &str) -> Result<(), ServerOperationError> {
    match allowed_type {
        "forward" | "reverse" | "reverse-aggregate" => Ok(()),
        _ => Err(ServerOperationError::InvalidInput(format!(
            "invalid allowed_type '{allowed_type}'; must be one of: forward, reverse, reverse-aggregate"
        ))),
    }
}

fn parse_interval_secs(interval: Option<&str>) -> i64 {
    let Some(s) = interval else {
        return DEFAULT_INTERVAL_SECS;
    };
    let s = s.trim();
    if s.is_empty() {
        return DEFAULT_INTERVAL_SECS;
    }
    if let Some(hours) = s.strip_suffix('h') {
        if let Ok(h) = hours.parse::<i64>() {
            return h * 3600;
        }
    }
    if let Some(mins) = s.strip_suffix('m') {
        if let Ok(m) = mins.parse::<i64>() {
            return m * 60;
        }
    }
    if let Some(secs) = s.strip_suffix('s') {
        if let Ok(sec) = secs.parse::<i64>() {
            return sec;
        }
    }
    s.parse::<i64>().unwrap_or(DEFAULT_INTERVAL_SECS)
}

// --- Result types ---

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct DeleteResult {
    pub deleted: String,
}

#[derive(Debug, Serialize)]
pub struct DnsLookupResult {
    pub domain: String,
    pub decision: &'static str,
    pub filtering_enabled: bool,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct FilterStatusResult {
    pub filtering_enabled: bool,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct FilterToggleResult {
    pub filtering_enabled: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct QueryLogResult {
    pub total: usize,
    pub max_entries: usize,
    #[cfg_attr(feature = "http-api", schema(value_type = Vec<QueryLogEntry>))]
    pub entries: VecDeque<QueryLogEntry>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct HealthResult {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub filtering_enabled: bool,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct ListActionResult {
    pub list: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct RefreshResult {
    pub list: String,
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct RefreshAllResult {
    pub lists_refreshing: Vec<String>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
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
                list_type: "adguard",
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

    #[test]
    fn update_upstream_input_absent_fields_yield_none() {
        let input: UpdateUpstreamServerInput = serde_json::from_str("{}").unwrap();
        assert!(input.bind_address.is_none());
        assert!(input.fwmark.is_none());
    }

    #[test]
    fn update_upstream_input_null_fields_yield_some_none() {
        let input: UpdateUpstreamServerInput =
            serde_json::from_str(r#"{"bind_address": null, "fwmark": null}"#).unwrap();
        assert_eq!(input.bind_address, Some(None));
        assert_eq!(input.fwmark, Some(None));
    }

    #[test]
    fn update_upstream_input_set_fields_yield_some_some() {
        let input: UpdateUpstreamServerInput =
            serde_json::from_str(r#"{"bind_address": "10.0.0.1", "fwmark": 42}"#).unwrap();
        assert_eq!(input.bind_address, Some(Some("10.0.0.1".to_string())));
        assert_eq!(input.fwmark, Some(Some(42)));
    }

    #[test]
    fn validate_upstream_address_rejects_doh_without_scheme() {
        let result = validate_upstream_address("doh", "dns.example.com/dns-query");
        assert!(result.is_err());
        let error = result.expect_err("expected validation error").to_string();
        assert!(error.contains("invalid DoH upstream address"));
    }

    #[test]
    fn validate_upstream_address_rejects_doh_http_scheme() {
        let result = validate_upstream_address("doh", "http://dns.example.com/dns-query");
        assert!(result.is_err());
        let error = result.expect_err("expected validation error").to_string();
        assert!(error.contains("must use https://"));
    }

    #[test]
    fn validate_upstream_address_accepts_doh_https_url() {
        let result = validate_upstream_address("doh", "https://dns.example.com/dns-query");
        assert!(result.is_ok());
    }
}
