use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;

use crate::entities::resolution::UpstreamStrategy;

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

    #[async_trait]
    impl UpstreamResolver for AlwaysFailResolver {
        async fn resolve(&self, _query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
            Err(UpstreamResolveError::AllFailed)
        }
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
}
