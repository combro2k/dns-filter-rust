use std::collections::VecDeque;

use serde::Serialize;

use crate::entities::filter::FilterDecision;

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
pub struct QueryLogEntry {
    pub timestamp: u64,
    pub domain: String,
    pub qtype: String,
    pub decision: QueryDecision,
    pub source_ip: String,
    pub response_time_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "http-api", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum QueryDecision {
    Allowed,
    Blocked,
    Passthrough,
}

impl From<FilterDecision> for QueryDecision {
    fn from(decision: FilterDecision) -> Self {
        match decision {
            FilterDecision::Allow => QueryDecision::Allowed,
            FilterDecision::Block => QueryDecision::Blocked,
            FilterDecision::Neutral => QueryDecision::Passthrough,
        }
    }
}

pub struct QueryLog {
    entries: VecDeque<QueryLogEntry>,
    max_entries: usize,
}

impl QueryLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries.min(1024)),
            max_entries,
        }
    }

    pub fn push(&mut self, entry: QueryLogEntry) {
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    pub fn entries(&self) -> &VecDeque<QueryLogEntry> {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_respects_max_entries() {
        let mut log = QueryLog::new(3);
        for i in 0..5 {
            log.push(QueryLogEntry {
                timestamp: i,
                domain: format!("domain{i}.example.com"),
                qtype: "A".to_string(),
                decision: QueryDecision::Passthrough,
                source_ip: "127.0.0.1".to_string(),
                response_time_ms: 1,
            });
        }
        assert_eq!(log.len(), 3);
        assert_eq!(log.entries()[0].timestamp, 2);
        assert_eq!(log.entries()[2].timestamp, 4);
    }

    #[test]
    fn empty_log_returns_zero_entries() {
        let log = QueryLog::new(100);
        assert_eq!(log.len(), 0);
        assert!(log.entries().is_empty());
    }

    #[test]
    fn push_within_capacity_retains_all() {
        let mut log = QueryLog::new(10);
        for i in 0..5 {
            log.push(QueryLogEntry {
                timestamp: i,
                domain: format!("domain{i}.example.com"),
                qtype: "AAAA".to_string(),
                decision: QueryDecision::Blocked,
                source_ip: "::1".to_string(),
                response_time_ms: 2,
            });
        }
        assert_eq!(log.len(), 5);
        assert_eq!(log.entries()[0].timestamp, 0);
        assert_eq!(log.entries()[4].timestamp, 4);
    }
}
