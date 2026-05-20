//! Prometheus metrics provider and exporter.

use std::sync::{Arc, OnceLock};

use prometheus::{
    Counter, CounterVec, Encoder, HistogramOpts, HistogramVec, Registry, TextEncoder,
};

/// Global Prometheus registry for application metrics.
fn get_registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::new)
}

/// All Prometheus metric instruments used in the application.
pub struct MetricsState {
    pub dns_queries_total: Counter,
    pub dns_queries_blocked: Counter,
    pub dns_queries_allowed: Counter,
    pub dns_queries_passthrough: Counter,
    pub blocklist_hits_total: Counter,
    pub cache_hits_total: Counter,
    pub cache_misses_total: Counter,
    pub upstream_request_duration_seconds: HistogramVec,
    pub upstream_errors_total: CounterVec,
}

impl MetricsState {
    /// Create all metric instruments and register them.
    pub fn new() -> Result<Self, prometheus::Error> {
        let dns_queries_total =
            Counter::new("dns_queries_total", "Total number of DNS queries received")?;
        let dns_queries_blocked = Counter::new(
            "dns_queries_blocked",
            "Total number of DNS queries blocked by blocklists",
        )?;
        let dns_queries_allowed = Counter::new(
            "dns_queries_allowed",
            "Total number of DNS queries allowed by allowlists",
        )?;
        let dns_queries_passthrough = Counter::new(
            "dns_queries_passthrough",
            "Total number of DNS queries processed without filtering",
        )?;
        let blocklist_hits_total =
            Counter::new("blocklist_hits_total", "Total number of blocklist hits")?;
        let cache_hits_total = Counter::new("cache_hits_total", "Total number of DNS cache hits")?;
        let cache_misses_total =
            Counter::new("cache_misses_total", "Total number of DNS cache misses")?;
        let upstream_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "upstream_request_duration_seconds",
                "Upstream resolver request latency in seconds",
            ),
            &["upstream"],
        )?;
        let upstream_errors_total = CounterVec::new(
            prometheus::Opts::new(
                "upstream_errors_total",
                "Total number of upstream resolver errors",
            ),
            &["upstream", "error"],
        )?;

        // Register all metrics
        get_registry().register(Box::new(dns_queries_total.clone()))?;
        get_registry().register(Box::new(dns_queries_blocked.clone()))?;
        get_registry().register(Box::new(dns_queries_allowed.clone()))?;
        get_registry().register(Box::new(dns_queries_passthrough.clone()))?;
        get_registry().register(Box::new(blocklist_hits_total.clone()))?;
        get_registry().register(Box::new(cache_hits_total.clone()))?;
        get_registry().register(Box::new(cache_misses_total.clone()))?;
        get_registry().register(Box::new(upstream_request_duration_seconds.clone()))?;
        get_registry().register(Box::new(upstream_errors_total.clone()))?;

        Ok(Self {
            dns_queries_total,
            dns_queries_blocked,
            dns_queries_allowed,
            dns_queries_passthrough,
            blocklist_hits_total,
            cache_hits_total,
            cache_misses_total,
            upstream_request_duration_seconds,
            upstream_errors_total,
        })
    }
}

/// Global metrics state, initialized once at startup.
static METRICS_STATE: OnceLock<Arc<MetricsState>> = OnceLock::new();

/// Initialize the Prometheus metrics provider.
///
/// Must be called once at application startup, before any metrics are recorded.
pub fn init_prometheus_metrics() -> Result<(), Box<dyn std::error::Error>> {
    if METRICS_STATE.get().is_none() {
        let state = Arc::new(MetricsState::new()?);
        let _ = METRICS_STATE.set(state);
    }
    Ok(())
}

/// Get the Prometheus text format metrics output.
///
/// This should be called from the `/metrics` HTTP endpoint to return current metrics.
pub fn collect_metrics() -> Result<String, Box<dyn std::error::Error>> {
    let encoder = TextEncoder::new();
    let metric_families = get_registry().gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}

/// Get a reference to the global metrics state.
///
/// Panics if called before `init_prometheus_metrics()`.
pub fn get_metrics() -> Arc<MetricsState> {
    METRICS_STATE
        .get()
        .expect("metrics not initialized")
        .clone()
}

fn try_get_metrics() -> Option<Arc<MetricsState>> {
    METRICS_STATE.get().cloned()
}

/// Record a DNS query with the given decision outcome.
///
/// Increments appropriate counter based on the decision:
/// - `queries_blocked` if decision indicates blocking
/// - `queries_allowed` if decision indicates allowlisting
/// - `queries_passthrough` for queries with no filtering decision
/// - `queries_total` in all cases
pub fn record_dns_query(protocol: &str, decision: QueryDecision) {
    let _ = protocol;
    let Some(metrics) = try_get_metrics() else {
        return;
    };

    metrics.dns_queries_total.inc();

    match decision {
        QueryDecision::Blocked => {
            metrics.dns_queries_blocked.inc();
        }
        QueryDecision::Allowed => {
            metrics.dns_queries_allowed.inc();
        }
        QueryDecision::Passthrough => {
            metrics.dns_queries_passthrough.inc();
        }
    }
}

/// DNS query decision outcomes for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryDecision {
    /// Query was blocked by a blocklist.
    Blocked,
    /// Query was allowed by an allowlist.
    Allowed,
    /// Query was processed without a blocking/allowing decision.
    Passthrough,
}

/// Record a blocklist hit with optional metadata.
pub fn record_blocklist_hit(_blocklist_name: Option<&str>) {
    let Some(metrics) = try_get_metrics() else {
        return;
    };
    metrics.blocklist_hits_total.inc();
}

/// Record a DNS cache operation.
pub fn record_cache_operation(hit: bool) {
    let Some(metrics) = try_get_metrics() else {
        return;
    };

    if hit {
        metrics.cache_hits_total.inc();
    } else {
        metrics.cache_misses_total.inc();
    }
}

/// Record upstream resolver latency in seconds and optional error by upstream label.
pub fn record_upstream_request(upstream: &str, duration_seconds: f64, error: Option<&str>) {
    let Some(metrics) = try_get_metrics() else {
        return;
    };

    metrics
        .upstream_request_duration_seconds
        .with_label_values(&[upstream])
        .observe(duration_seconds);

    if let Some(error) = error {
        metrics
            .upstream_errors_total
            .with_label_values(&[upstream, error])
            .inc();
    }
}

/// Returns true when metrics have been initialized.
pub fn metrics_enabled() -> bool {
    METRICS_STATE.get().is_some()
}

/// In-memory snapshot of all counters, used to serve both `/metrics` and
/// `/api/v1/stats` from a single source of truth.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub queries_allowed: u64,
    pub queries_passthrough: u64,
    pub blocklist_hits_total: u64,
    pub cache_hits_total: u64,
    pub cache_misses_total: u64,
    pub upstreams: Vec<UpstreamSnapshot>,
}

/// Per-upstream counters and latency aggregates derived from the same
/// in-memory prometheus primitives that back `/metrics`.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct UpstreamSnapshot {
    pub upstream: String,
    pub requests_total: u64,
    pub errors_total: u64,
    pub latency_count: u64,
    pub latency_sum_seconds: f64,
}

/// Reads the current values from the global metrics primitives.
///
/// Returns an empty snapshot when metrics have not been initialized.
pub fn snapshot() -> MetricsSnapshot {
    let Some(metrics) = try_get_metrics() else {
        return MetricsSnapshot::default();
    };

    use prometheus::core::Collector;
    use std::collections::BTreeMap;

    let mut upstreams: BTreeMap<String, UpstreamSnapshot> = BTreeMap::new();

    for family in metrics.upstream_request_duration_seconds.collect() {
        for metric in family.get_metric() {
            let label = metric
                .get_label()
                .iter()
                .find(|l| l.get_name() == "upstream")
                .map(|l| l.get_value().to_string())
                .unwrap_or_default();
            let histogram = metric.get_histogram();
            let entry = upstreams.entry(label.clone()).or_default();
            entry.upstream = label;
            entry.requests_total = histogram.get_sample_count();
            entry.latency_count = histogram.get_sample_count();
            entry.latency_sum_seconds = histogram.get_sample_sum();
        }
    }

    for family in metrics.upstream_errors_total.collect() {
        for metric in family.get_metric() {
            let label = metric
                .get_label()
                .iter()
                .find(|l| l.get_name() == "upstream")
                .map(|l| l.get_value().to_string())
                .unwrap_or_default();
            let value = metric.get_counter().get_value() as u64;
            let entry = upstreams.entry(label.clone()).or_default();
            if entry.upstream.is_empty() {
                entry.upstream = label;
            }
            entry.errors_total += value;
        }
    }

    MetricsSnapshot {
        queries_total: metrics.dns_queries_total.get() as u64,
        queries_blocked: metrics.dns_queries_blocked.get() as u64,
        queries_allowed: metrics.dns_queries_allowed.get() as u64,
        queries_passthrough: metrics.dns_queries_passthrough.get() as u64,
        blocklist_hits_total: metrics.blocklist_hits_total.get() as u64,
        cache_hits_total: metrics.cache_hits_total.get() as u64,
        cache_misses_total: metrics.cache_misses_total.get() as u64,
        upstreams: upstreams.into_values().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric_value(output: &str, metric_prefix: &str) -> f64 {
        output
            .lines()
            .find_map(|line| {
                if !line.starts_with(metric_prefix) {
                    return None;
                }
                if line.starts_with('#') {
                    return None;
                }
                line.split_whitespace().nth(1)?.parse::<f64>().ok()
            })
            .expect("metric must exist in exposition output")
    }

    #[test]
    fn test_query_decision_enum() {
        assert_eq!(QueryDecision::Blocked, QueryDecision::Blocked);
        assert_ne!(QueryDecision::Blocked, QueryDecision::Allowed);
        assert_ne!(QueryDecision::Allowed, QueryDecision::Passthrough);
    }

    #[test]
    fn test_metrics_recording_and_collection() {
        init_prometheus_metrics().expect("metrics init should succeed");

        record_dns_query("dns", QueryDecision::Blocked);
        record_blocklist_hit(None);
        record_cache_operation(true);
        record_upstream_request("udp://1.1.1.1:53", 0.005, None);

        let output = collect_metrics().expect("metrics collection should succeed");
        assert!(output.contains("dns_queries_total"));
        assert!(output.contains("dns_queries_blocked"));
        assert!(output.contains("blocklist_hits_total"));
        assert!(output.contains("cache_hits_total"));
        assert!(output.contains("upstream_request_duration_seconds"));
        assert!(output.contains("upstream=\"udp://1.1.1.1:53\""));
    }

    #[test]
    fn snapshot_matches_prometheus_output() {
        init_prometheus_metrics().expect("metrics init should succeed");

        record_dns_query("dns", QueryDecision::Passthrough);
        record_dns_query("dns", QueryDecision::Blocked);
        record_blocklist_hit(None);
        record_cache_operation(true);
        record_cache_operation(false);
        record_upstream_request("udp://9.9.9.9:53", 0.01, Some("timeout"));

        let snapshot = snapshot();
        let output = collect_metrics().expect("metrics collection should succeed");

        assert_eq!(
            snapshot.queries_total as f64,
            metric_value(&output, "dns_queries_total ")
        );
        assert_eq!(
            snapshot.queries_blocked as f64,
            metric_value(&output, "dns_queries_blocked ")
        );
        assert_eq!(
            snapshot.blocklist_hits_total as f64,
            metric_value(&output, "blocklist_hits_total ")
        );
        assert_eq!(
            snapshot.cache_hits_total as f64,
            metric_value(&output, "cache_hits_total ")
        );
        assert_eq!(
            snapshot.cache_misses_total as f64,
            metric_value(&output, "cache_misses_total ")
        );

        let upstream = snapshot
            .upstreams
            .iter()
            .find(|u| u.upstream == "udp://9.9.9.9:53")
            .expect("snapshot upstream must exist");

        assert_eq!(
            upstream.latency_count as f64,
            metric_value(
                &output,
                "upstream_request_duration_seconds_count{upstream=\"udp://9.9.9.9:53\"}"
            )
        );
        assert_eq!(
            upstream.latency_sum_seconds,
            metric_value(
                &output,
                "upstream_request_duration_seconds_sum{upstream=\"udp://9.9.9.9:53\"}"
            )
        );
        assert_eq!(
            upstream.errors_total as f64,
            metric_value(
                &output,
                "upstream_errors_total{error=\"timeout\",upstream=\"udp://9.9.9.9:53\"}"
            )
        );
    }
}
