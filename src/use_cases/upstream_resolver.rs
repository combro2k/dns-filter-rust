use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, Record};
use tokio::sync::RwLock;

use crate::entities::resolution::UpstreamStrategy;
use crate::frameworks::metrics::{record_cache_operation, record_upstream_request};

/// Errors that can occur when resolving a DNS query against an upstream server.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamResolveError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("query timed out")]
    Timeout,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("all upstreams failed")]
    AllFailed,
}

/// Resolves a raw DNS wire-format query and returns a raw DNS wire-format response.
///
/// Implementors must be `Send + Sync` so they can be used from any async context,
/// including concurrent fan-out for a future `Fastest` strategy.
#[async_trait]
pub trait UpstreamResolver: Send + Sync {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError>;
}

const DEFAULT_MAX_CACHE_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverCacheSettings {
    pub enabled: bool,
    pub min_ttl: Option<Duration>,
    pub max_ttl: Option<Duration>,
    pub max_entries: usize,
}

impl Default for ResolverCacheSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            min_ttl: None,
            max_ttl: None,
            max_entries: DEFAULT_MAX_CACHE_ENTRIES,
        }
    }
}

impl ResolverCacheSettings {
    pub fn validate(&self) -> Result<(), String> {
        if let (Some(min_ttl), Some(max_ttl)) = (self.min_ttl, self.max_ttl) {
            if min_ttl > max_ttl {
                return Err(
                    "resolvers.cache.min_ttl must be less than or equal to resolvers.cache.max_ttl"
                        .to_string(),
                );
            }
        }

        Ok(())
    }

    fn clamp_ttl(&self, ttl: Duration) -> Option<Duration> {
        let ttl = match self.min_ttl {
            Some(min_ttl) => ttl.max(min_ttl),
            None => ttl,
        };
        let ttl = match self.max_ttl {
            Some(max_ttl) => ttl.min(max_ttl),
            None => ttl,
        };

        if ttl.is_zero() {
            None
        } else {
            Some(ttl)
        }
    }
}

#[derive(Debug, Clone)]
struct CachedResponse {
    response: Vec<u8>,
    stored_at: Instant,
    expires_at: Instant,
}

pub struct CachedUpstreamResolver {
    inner: Arc<dyn UpstreamResolver>,
    settings: ResolverCacheSettings,
    entries: RwLock<HashMap<Vec<u8>, CachedResponse>>,
}

impl CachedUpstreamResolver {
    pub fn new(inner: Arc<dyn UpstreamResolver>, settings: ResolverCacheSettings) -> Self {
        Self {
            inner,
            settings,
            entries: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl UpstreamResolver for CachedUpstreamResolver {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
        let key = normalize_cache_key(&query);
        let client_query_id = query_id(&query);
        let now = Instant::now();

        if let Some(entry) = self.entries.read().await.get(&key).cloned() {
            if entry.expires_at > now {
                record_cache_operation(true);
                return Ok(rehydrate_cached_response(
                    &entry.response,
                    entry.stored_at.elapsed(),
                    client_query_id,
                ));
            }
            // Expired entry — don't acquire a write lock just to remove it.
            // It will be overwritten on insert below or evicted during cleanup.
        }

        record_cache_operation(false);

        let response = self.inner.resolve(query).await?;
        if let Some(ttl) = cache_ttl(&response, &self.settings) {
            let mut entries = self.entries.write().await;
            // Evict expired entries and enforce size cap before inserting.
            if entries.len() >= self.settings.max_entries {
                entries.retain(|_, v| v.expires_at > now);
            }
            if entries.len() >= self.settings.max_entries {
                // Still over limit — evict the entries closest to expiry.
                let mut by_expiry: Vec<Vec<u8>> = entries
                    .iter()
                    .map(|(k, v)| (k.clone(), v.expires_at))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|(k, _)| k)
                    .collect();
                by_expiry.sort_by_key(|k| entries.get(k).map(|v| v.expires_at));
                let to_remove = entries.len() - self.settings.max_entries / 2;
                for k in by_expiry.into_iter().take(to_remove) {
                    entries.remove(&k);
                }
            }
            entries.insert(
                key,
                CachedResponse {
                    response: scrub_response_id(&response),
                    stored_at: now,
                    expires_at: now + ttl,
                },
            );
        }

        Ok(response)
    }
}

fn query_id(query: &[u8]) -> u16 {
    if query.len() >= 2 {
        u16::from_be_bytes([query[0], query[1]])
    } else {
        0
    }
}

fn normalize_cache_key(query: &[u8]) -> Vec<u8> {
    let mut key = query.to_vec();
    if key.len() >= 2 {
        key[0] = 0;
        key[1] = 0;
    }
    key
}

fn scrub_response_id(response: &[u8]) -> Vec<u8> {
    let mut cached = response.to_vec();
    if let Ok(mut message) = Message::from_vec(response) {
        message.metadata.id = 0;
        cached = message.to_vec().unwrap_or(cached);
    }
    cached
}

fn rehydrate_cached_response(response: &[u8], age: Duration, client_query_id: u16) -> Vec<u8> {
    let mut cached = response.to_vec();

    if let Ok(mut message) = Message::from_vec(response) {
        message.metadata.id = client_query_id;
        let age_secs = age.as_secs().min(u64::from(u32::MAX)) as u32;
        decrement_record_ttls(&mut message.answers, age_secs);
        decrement_record_ttls(&mut message.authorities, age_secs);
        decrement_record_ttls(&mut message.additionals, age_secs);
        cached = message.to_vec().unwrap_or(cached);
    }

    cached
}

fn decrement_record_ttls(records: &mut [Record], age_secs: u32) {
    for record in records {
        record.ttl = record.ttl.saturating_sub(age_secs);
    }
}

fn cache_ttl(response: &[u8], settings: &ResolverCacheSettings) -> Option<Duration> {
    if is_truncated_response(response) {
        return None;
    }

    let message = Message::from_vec(response).ok()?;

    let ttl = match message.response_code {
        ResponseCode::NoError => {
            min_record_ttl(&message.answers).or_else(|| negative_cache_ttl(&message))
        }
        ResponseCode::NXDomain => negative_cache_ttl(&message),
        _ => None,
    }?;

    settings.clamp_ttl(ttl)
}

fn is_truncated_response(response: &[u8]) -> bool {
    response
        .get(2)
        .is_some_and(|flags| flags & 0b0000_0010 != 0)
}

fn min_record_ttl(records: &[Record]) -> Option<Duration> {
    records
        .iter()
        .map(|record| Duration::from_secs(u64::from(record.ttl)))
        .min()
}

fn negative_cache_ttl(message: &Message) -> Option<Duration> {
    message
        .authorities
        .iter()
        .find_map(|record| match &record.data {
            RData::SOA(soa) => {
                let ttl = u64::from(record.ttl).min(u64::from(soa.minimum));
                Some(Duration::from_secs(ttl))
            }
            _ => None,
        })
}

/// Wraps a resolver and records per-upstream latency/error metrics.
pub struct InstrumentedUpstreamResolver {
    label: String,
    inner: Arc<dyn UpstreamResolver>,
}

impl InstrumentedUpstreamResolver {
    pub fn new(label: String, inner: Arc<dyn UpstreamResolver>) -> Self {
        Self { label, inner }
    }
}

#[async_trait]
impl UpstreamResolver for InstrumentedUpstreamResolver {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
        let started = std::time::Instant::now();
        let result = self.inner.resolve(query).await;
        let error_label = result.as_ref().err().map(|e| match e {
            UpstreamResolveError::Io(_) => "io",
            UpstreamResolveError::Timeout => "timeout",
            UpstreamResolveError::Protocol(_) => "protocol",
            UpstreamResolveError::AllFailed => "all_failed",
        });
        record_upstream_request(&self.label, started.elapsed().as_secs_f64(), error_label);
        result
    }
}

/// Dispatches DNS queries to one or more upstream resolvers according to a strategy.
///
/// # Strategies
/// - `RoundRobin` — cycles through resolvers in order, one per call.
/// - `Random` — picks a resolver at random each call.
/// - `Failover` — tries resolvers sequentially until one succeeds.
pub struct StrategyUpstreamResolver {
    resolvers: Vec<Arc<dyn UpstreamResolver>>,
    strategy: UpstreamStrategy,
    counter: AtomicUsize,
}

impl StrategyUpstreamResolver {
    pub fn new(resolvers: Vec<Arc<dyn UpstreamResolver>>, strategy: UpstreamStrategy) -> Self {
        Self {
            resolvers,
            strategy,
            counter: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl UpstreamResolver for StrategyUpstreamResolver {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
        if self.resolvers.is_empty() {
            return Err(UpstreamResolveError::AllFailed);
        }

        match self.strategy {
            UpstreamStrategy::RoundRobin => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.resolvers.len();
                self.resolvers[idx].resolve(query).await
            }

            UpstreamStrategy::Random => {
                use rand::Rng;
                let idx = rand::thread_rng().gen_range(0..self.resolvers.len());
                self.resolvers[idx].resolve(query).await
            }

            UpstreamStrategy::Failover => {
                let mut last_err = UpstreamResolveError::AllFailed;
                for resolver in &self.resolvers {
                    match resolver.resolve(query.clone()).await {
                        Ok(resp) => return Ok(resp),
                        Err(e) => last_err = e,
                    }
                }
                Err(last_err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{Name, RecordType};

    struct TrackingResolver {
        id: usize,
        calls: Arc<Mutex<Vec<usize>>>,
    }

    #[async_trait]
    impl UpstreamResolver for TrackingResolver {
        async fn resolve(&self, _query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
            self.calls.lock().unwrap().push(self.id);
            Ok(vec![self.id as u8])
        }
    }

    struct AlwaysFailResolver;

    #[derive(Clone)]
    struct StaticResolver {
        response: Vec<u8>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl UpstreamResolver for AlwaysFailResolver {
        async fn resolve(&self, _query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
            Err(UpstreamResolveError::AllFailed)
        }
    }

    #[async_trait]
    impl UpstreamResolver for StaticResolver {
        async fn resolve(&self, _query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.response.clone())
        }
    }

    fn dns_query(name: &str, record_type: RecordType, id: u16) -> Vec<u8> {
        let name = Name::from_ascii(name).expect("valid name");
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(name, record_type));
        message.to_vec().expect("query should serialize")
    }

    fn positive_response(name: &str, ttl: u32, id: u16) -> Vec<u8> {
        let name = Name::from_ascii(name).expect("valid name");
        let mut message = Message::new(id, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(name, ttl, RData::A(A::new(1, 1, 1, 1))));
        message.to_vec().expect("response should serialize")
    }

    fn negative_response(name: &str, ttl: u32, minimum: u32, id: u16) -> Vec<u8> {
        let zone = Name::from_ascii(name).expect("valid zone name");
        let mut message = Message::new(id, MessageType::Response, OpCode::Query);
        message.metadata.response_code = ResponseCode::NXDomain;
        message.add_query(Query::query(zone.clone(), RecordType::A));
        message.add_authority(Record::from_rdata(
            zone,
            ttl,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.").unwrap(),
                Name::from_ascii("hostmaster.example.").unwrap(),
                1,
                3600,
                600,
                86400,
                minimum,
            )),
        ));
        message
            .to_vec()
            .expect("negative response should serialize")
    }

    #[tokio::test]
    async fn test_round_robin_cycles_through_resolvers() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolvers: Vec<Arc<dyn UpstreamResolver>> = vec![
            Arc::new(TrackingResolver {
                id: 0,
                calls: Arc::clone(&calls),
            }),
            Arc::new(TrackingResolver {
                id: 1,
                calls: Arc::clone(&calls),
            }),
        ];
        let sr = StrategyUpstreamResolver::new(resolvers, UpstreamStrategy::RoundRobin);

        sr.resolve(vec![]).await.unwrap();
        sr.resolve(vec![]).await.unwrap();
        sr.resolve(vec![]).await.unwrap();

        assert_eq!(*calls.lock().unwrap(), vec![0, 1, 0]);
    }

    #[tokio::test]
    async fn test_failover_skips_failed_and_returns_first_ok() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolvers: Vec<Arc<dyn UpstreamResolver>> = vec![
            Arc::new(AlwaysFailResolver),
            Arc::new(TrackingResolver {
                id: 1,
                calls: Arc::clone(&calls),
            }),
        ];
        let sr = StrategyUpstreamResolver::new(resolvers, UpstreamStrategy::Failover);

        let result = sr.resolve(vec![]).await;
        assert!(result.is_ok());
        assert_eq!(*calls.lock().unwrap(), vec![1]);
    }

    #[tokio::test]
    async fn test_failover_all_fail_returns_err() {
        let resolvers: Vec<Arc<dyn UpstreamResolver>> =
            vec![Arc::new(AlwaysFailResolver), Arc::new(AlwaysFailResolver)];
        let sr = StrategyUpstreamResolver::new(resolvers, UpstreamStrategy::Failover);
        assert!(sr.resolve(vec![]).await.is_err());
    }

    #[tokio::test]
    async fn test_empty_resolvers_returns_all_failed() {
        let sr = StrategyUpstreamResolver::new(vec![], UpstreamStrategy::RoundRobin);
        assert!(sr.resolve(vec![]).await.is_err());
    }

    #[tokio::test]
    async fn cached_upstream_resolver_reuses_positive_response() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = Arc::new(StaticResolver {
            response: positive_response("example.com.", 120, 10),
            calls: Arc::clone(&calls),
        });
        let resolver = CachedUpstreamResolver::new(
            inner,
            ResolverCacheSettings {
                enabled: true,
                min_ttl: None,
                max_ttl: None,
                ..Default::default()
            },
        );

        let first = resolver
            .resolve(dns_query("example.com.", RecordType::A, 100))
            .await
            .unwrap();
        let second = resolver
            .resolve(dns_query("example.com.", RecordType::A, 200))
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let first_message = Message::from_vec(&first).expect("first response should parse");
        let second_message = Message::from_vec(&second).expect("second response should parse");
        assert_eq!(first_message.id, 10);
        assert_eq!(second_message.id, 200);
    }

    #[test]
    fn cached_upstream_resolver_uses_negative_ttl_bounds() {
        let ttl = cache_ttl(
            &negative_response("missing.example.", 600, 900, 10),
            &ResolverCacheSettings {
                enabled: true,
                min_ttl: Some(Duration::from_secs(30)),
                max_ttl: Some(Duration::from_secs(120)),
                ..Default::default()
            },
        )
        .expect("negative response should be cacheable");

        assert_eq!(ttl, Duration::from_secs(120));
    }

    #[test]
    fn resolver_cache_settings_reject_invalid_bounds() {
        let settings = ResolverCacheSettings {
            enabled: true,
            min_ttl: Some(Duration::from_secs(60)),
            max_ttl: Some(Duration::from_secs(30)),
            ..Default::default()
        };

        assert!(settings.validate().is_err());
    }

    #[tokio::test]
    async fn cached_upstream_resolver_evicts_when_over_max_entries() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = Arc::new(StaticResolver {
            response: positive_response("example.com.", 300, 10),
            calls: Arc::clone(&calls),
        });
        let resolver = CachedUpstreamResolver::new(
            inner,
            ResolverCacheSettings {
                enabled: true,
                min_ttl: None,
                max_ttl: None,
                max_entries: 3,
            },
        );

        // Fill the cache with 3 unique queries.
        for i in 0u16..3 {
            let name = format!("host{i}.example.com.");
            resolver
                .resolve(dns_query(&name, RecordType::A, i))
                .await
                .unwrap();
        }
        assert_eq!(calls.load(Ordering::Relaxed), 3);

        // A 4th unique query triggers eviction — cache should not grow unbounded.
        resolver
            .resolve(dns_query("host3.example.com.", RecordType::A, 3))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 4);

        let entries = resolver.entries.read().await;
        assert!(
            entries.len() <= 3,
            "cache should not exceed max_entries, got {}",
            entries.len()
        );
    }
}
