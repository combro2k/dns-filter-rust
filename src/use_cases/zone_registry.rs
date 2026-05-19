use std::sync::Arc;

use serde::Serialize;

use crate::use_cases::zone_authority::{ZoneRecord, ZoneSearchable};

/// Metadata about a zone entry's configuration.
#[derive(Debug, Clone, Serialize)]
pub struct ZoneMetadata {
    pub bypass_filter: bool,
    pub fallback_to_default_resolvers: bool,
}

/// Summary of a zone for listing.
#[derive(Debug, Clone, Serialize)]
pub struct ZoneInfo {
    pub name: String,
    pub record_count: usize,
    pub bypass_filter: bool,
    pub fallback_to_default_resolvers: bool,
}

/// Search result entry with score.
#[derive(Debug, Clone, Serialize)]
pub struct ZoneSearchResult {
    #[serde(flatten)]
    pub record: ZoneRecord,
    pub score: i64,
}

/// Registry of all zones, providing search and listing.
pub struct ZoneRegistry {
    zones: Vec<(Arc<dyn ZoneSearchable>, ZoneMetadata)>,
}

impl ZoneRegistry {
    pub fn new(zones: Vec<(Arc<dyn ZoneSearchable>, ZoneMetadata)>) -> Self {
        Self { zones }
    }

    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }

    pub fn list_zones(&self) -> Vec<ZoneInfo> {
        self.zones
            .iter()
            .map(|(searchable, meta)| ZoneInfo {
                name: searchable.zone_name(),
                record_count: searchable.record_count(),
                bypass_filter: meta.bypass_filter,
                fallback_to_default_resolvers: meta.fallback_to_default_resolvers,
            })
            .collect()
    }

    pub fn search_records(
        &self,
        query: &str,
        zone_filter: Option<&str>,
        record_type: Option<&str>,
        limit: usize,
    ) -> (Vec<ZoneSearchResult>, usize) {
        let limit = limit.min(500);

        let mut all_results: Vec<ZoneSearchResult> = Vec::new();

        for (searchable, _meta) in &self.zones {
            if let Some(zf) = zone_filter {
                if searchable.zone_name() != zf {
                    continue;
                }
            }

            let scored = searchable.search_records(query, record_type, limit);
            all_results.extend(
                scored
                    .into_iter()
                    .map(|(record, score)| ZoneSearchResult { record, score }),
            );
        }

        // Sort globally by score descending.
        all_results.sort_by_key(|b| std::cmp::Reverse(b.score));
        let total = all_results.len();
        all_results.truncate(limit);
        (all_results, total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockZone {
        zone: String,
        records: Vec<ZoneRecord>,
    }

    impl ZoneSearchable for MockZone {
        fn zone_name(&self) -> String {
            self.zone.clone()
        }

        fn record_count(&self) -> usize {
            self.records.len()
        }

        fn list_records(&self, record_type: Option<&str>) -> Vec<ZoneRecord> {
            self.records
                .iter()
                .filter(|r| match record_type {
                    Some(rt) => r.record_type == rt,
                    None => true,
                })
                .cloned()
                .collect()
        }

        fn search_records(
            &self,
            query: &str,
            record_type: Option<&str>,
            limit: usize,
        ) -> Vec<(ZoneRecord, i64)> {
            use fuzzy_matcher::skim::SkimMatcherV2;
            use fuzzy_matcher::FuzzyMatcher;

            let matcher = SkimMatcherV2::default();
            let mut results: Vec<(ZoneRecord, i64)> = self
                .records
                .iter()
                .filter(|r| match record_type {
                    Some(rt) => r.record_type == rt,
                    None => true,
                })
                .filter_map(|r| {
                    matcher
                        .fuzzy_match(&r.name, query)
                        .map(|score| (r.clone(), score))
                })
                .collect();
            results.sort_by_key(|b| std::cmp::Reverse(b.1));
            results.truncate(limit);
            results
        }
    }

    fn make_record(name: &str, rtype: &str, data: &str, zone: &str) -> ZoneRecord {
        ZoneRecord {
            name: name.to_string(),
            record_type: rtype.to_string(),
            ttl: 300,
            data: data.to_string(),
            zone: zone.to_string(),
        }
    }

    fn make_registry() -> ZoneRegistry {
        let zone1 = Arc::new(MockZone {
            zone: "home.arpa".to_string(),
            records: vec![
                make_record("server1.home.arpa", "A", "192.168.1.10", "home.arpa"),
                make_record("server2.home.arpa", "A", "192.168.1.11", "home.arpa"),
                make_record("nas.home.arpa", "AAAA", "fd00::10", "home.arpa"),
                make_record("mail.home.arpa", "MX", "10 server1.home.arpa", "home.arpa"),
            ],
        }) as Arc<dyn ZoneSearchable>;

        let zone2 = Arc::new(MockZone {
            zone: "example.com".to_string(),
            records: vec![
                make_record("www.example.com", "A", "203.0.113.10", "example.com"),
                make_record("api.example.com", "A", "203.0.113.20", "example.com"),
                make_record("server.example.com", "AAAA", "2001:db8::1", "example.com"),
            ],
        }) as Arc<dyn ZoneSearchable>;

        ZoneRegistry::new(vec![
            (
                zone1,
                ZoneMetadata {
                    bypass_filter: true,
                    fallback_to_default_resolvers: false,
                },
            ),
            (
                zone2,
                ZoneMetadata {
                    bypass_filter: false,
                    fallback_to_default_resolvers: true,
                },
            ),
        ])
    }

    #[test]
    fn list_zones_returns_all() {
        let registry = make_registry();
        let zones = registry.list_zones();
        assert_eq!(zones.len(), 2);
        assert_eq!(zones[0].name, "home.arpa");
        assert_eq!(zones[0].record_count, 4);
        assert!(zones[0].bypass_filter);
        assert_eq!(zones[1].name, "example.com");
        assert_eq!(zones[1].record_count, 3);
        assert!(!zones[1].bypass_filter);
    }

    #[test]
    fn search_fuzzy_matches_across_zones() {
        let registry = make_registry();
        let (results, total) = registry.search_records("server", None, None, 50);
        assert!(total > 0);
        // "server" should match server1, server2 in home.arpa and server.example.com
        assert!(results.len() >= 3);
        // Results should be sorted by score descending
        for pair in results.windows(2) {
            assert!(pair[0].score >= pair[1].score);
        }
    }

    #[test]
    fn search_with_zone_filter() {
        let registry = make_registry();
        let (results, _) = registry.search_records("server", Some("home.arpa"), None, 50);
        assert!(!results.is_empty());
        for result in &results {
            assert_eq!(result.record.zone, "home.arpa");
        }
    }

    #[test]
    fn search_with_type_filter() {
        let registry = make_registry();
        let (results, _) = registry.search_records("server", None, Some("AAAA"), 50);
        assert!(!results.is_empty());
        for result in &results {
            assert_eq!(result.record.record_type, "AAAA");
        }
    }

    #[test]
    fn search_respects_limit() {
        let registry = make_registry();
        let (results, total) = registry.search_records("server", None, None, 2);
        assert!(results.len() <= 2);
        assert!(total >= results.len());
    }

    #[test]
    fn search_caps_at_500() {
        let registry = make_registry();
        let (results, _) = registry.search_records("server", None, None, 10000);
        assert!(results.len() <= 500);
    }

    #[test]
    fn search_no_match_returns_empty() {
        let registry = make_registry();
        let (results, total) = registry.search_records("zzzzzzz", None, None, 50);
        assert!(results.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn empty_registry() {
        let registry = ZoneRegistry::new(Vec::new());
        assert_eq!(registry.zone_count(), 0);
        assert!(registry.list_zones().is_empty());
        let (results, total) = registry.search_records("test", None, None, 50);
        assert!(results.is_empty());
        assert_eq!(total, 0);
    }
}
