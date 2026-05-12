use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::Message;
use std::fmt;

use crate::use_cases::request_pipeline::{
    AsyncRequestStage, DnsPipelineError, DnsPipelineRequest, DnsPipelineResponse,
};
use crate::use_cases::upstream_resolver::UpstreamResolver;

#[derive(Clone)]
pub struct ZoneEntry {
    zone: String,
    bypass_filter: bool,
    fallback_to_default_resolvers: bool,
    resolver: Arc<dyn UpstreamResolver>,
}

impl fmt::Debug for ZoneEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneEntry")
            .field("zone", &self.zone)
            .field("bypass_filter", &self.bypass_filter)
            .field(
                "fallback_to_default_resolvers",
                &self.fallback_to_default_resolvers,
            )
            .finish_non_exhaustive()
    }
}

impl ZoneEntry {
    pub fn new(
        zone: String,
        bypass_filter: bool,
        fallback_to_default_resolvers: bool,
        resolver: Arc<dyn UpstreamResolver>,
    ) -> Result<Self> {
        let zone = normalize_zone(&zone).ok_or_else(|| anyhow!("zone name must not be empty"))?;

        Ok(Self {
            zone,
            bypass_filter,
            fallback_to_default_resolvers,
            resolver,
        })
    }

    pub fn zone(&self) -> &str {
        &self.zone
    }

    pub fn bypass_filter(&self) -> bool {
        self.bypass_filter
    }

    pub fn fallback_to_default_resolvers(&self) -> bool {
        self.fallback_to_default_resolvers
    }
}

pub struct ZoneForwardingStage {
    entries: Vec<ZoneEntry>,
}

impl ZoneForwardingStage {
    pub fn bypass_only(mut entries: Vec<ZoneEntry>) -> Self {
        entries.retain(|entry| entry.bypass_filter);
        sort_entries(&mut entries);
        Self { entries }
    }

    pub fn non_bypass(mut entries: Vec<ZoneEntry>) -> Self {
        entries.retain(|entry| !entry.bypass_filter);
        sort_entries(&mut entries);
        Self { entries }
    }

    fn matching_entry(&self, domain: &str) -> Option<&ZoneEntry> {
        let normalized_domain = normalize_zone(domain)?;
        self.entries
            .iter()
            .find(|entry| domain_matches_zone(&normalized_domain, &entry.zone))
    }
}

#[async_trait]
impl AsyncRequestStage<DnsPipelineRequest, DnsPipelineResponse, DnsPipelineError>
    for ZoneForwardingStage
{
    async fn handle(
        &self,
        request: &DnsPipelineRequest,
    ) -> Result<Option<DnsPipelineResponse>, DnsPipelineError> {
        let Some(domain) = extract_query_name(&request.query) else {
            return Ok(None);
        };

        let Some(entry) = self.matching_entry(&domain) else {
            return Ok(None);
        };

        match entry.resolver.resolve(request.query.clone()).await {
            Ok(response) => {
                tracing::debug!(
                    domain = %domain,
                    zone = %entry.zone,
                    bypass_filter = entry.bypass_filter,
                    fallback_to_default_resolvers = entry.fallback_to_default_resolvers,
                    "forwarded query through zone-specific resolver"
                );
                Ok(Some(DnsPipelineResponse::new(fix_response_id(
                    response,
                    request.client_query_id,
                ))))
            }
            Err(error) if entry.fallback_to_default_resolvers => {
                tracing::warn!(
                    domain = %domain,
                    zone = %entry.zone,
                    error = %error,
                    "zone-specific resolver failed, falling back to default resolvers"
                );
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
}

fn sort_entries(entries: &mut [ZoneEntry]) {
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.zone.len()));
}

fn extract_query_name(query: &[u8]) -> Option<String> {
    let message = Message::from_vec(query).ok()?;
    let query = message.queries.first()?;
    Some(query.name().to_ascii())
}

fn fix_response_id(response: Vec<u8>, client_query_id: u16) -> Vec<u8> {
    if let Ok(mut message) = Message::from_vec(&response) {
        message.metadata.id = client_query_id;
        return message.to_vec().unwrap_or(response);
    }

    tracing::warn!("failed to parse zone upstream response, returning as-is");
    response
}

fn normalize_zone(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        if value.trim() == "." {
            return Some(".".to_string());
        }

        return None;
    }

    Some(trimmed.to_ascii_lowercase())
}

fn domain_matches_zone(domain: &str, zone: &str) -> bool {
    if zone == "." {
        return true;
    }

    domain == zone
        || domain
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, RecordType};

    use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};

    use super::*;

    struct FixedResponseResolver {
        response: Vec<u8>,
    }

    #[async_trait]
    impl UpstreamResolver for FixedResponseResolver {
        async fn resolve(&self, _query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
            Ok(self.response.clone())
        }
    }

    struct AlwaysFailResolver;

    #[async_trait]
    impl UpstreamResolver for AlwaysFailResolver {
        async fn resolve(&self, _query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
            Err(UpstreamResolveError::AllFailed)
        }
    }

    fn zone_entry(
        zone: &str,
        bypass_filter: bool,
        fallback_to_default_resolvers: bool,
        resolver: Arc<dyn UpstreamResolver>,
    ) -> ZoneEntry {
        ZoneEntry::new(
            zone.to_string(),
            bypass_filter,
            fallback_to_default_resolvers,
            resolver,
        )
        .expect("zone entry should build")
    }

    fn make_query(name: &str) -> DnsPipelineRequest {
        let mut message = Message::new(42, MessageType::Query, hickory_proto::op::OpCode::Query);
        let mut query = Query::new();
        query.set_name(name.parse().unwrap());
        query.set_query_type(RecordType::A);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);
        DnsPipelineRequest::new(message.to_vec().unwrap())
    }

    fn make_response(id: u16) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Response, hickory_proto::op::OpCode::Query);
        message.metadata.response_code = ResponseCode::NoError;
        message.to_vec().unwrap()
    }

    #[test]
    fn zone_entry_normalizes_zone_name() {
        let entry = zone_entry("HOME.ARPA.", true, false, Arc::new(AlwaysFailResolver));

        assert_eq!(entry.zone(), "home.arpa");
    }

    #[test]
    fn longest_zone_match_wins() {
        let entries = vec![
            zone_entry("arpa", false, false, Arc::new(AlwaysFailResolver)),
            zone_entry("home.arpa", false, false, Arc::new(AlwaysFailResolver)),
        ];
        let stage = ZoneForwardingStage::non_bypass(entries);

        let matched = stage
            .matching_entry("printer.home.arpa.")
            .expect("matching zone should exist");

        assert_eq!(matched.zone(), "home.arpa");
    }

    #[test]
    fn root_zone_matches_any_domain() {
        assert!(domain_matches_zone("example.com", "."));
    }

    #[tokio::test]
    async fn bypass_stage_ignores_non_bypass_entries() {
        let stage = ZoneForwardingStage::bypass_only(vec![zone_entry(
            "home.arpa",
            false,
            false,
            Arc::new(FixedResponseResolver {
                response: make_response(9),
            }),
        )]);

        let response = stage
            .handle(&make_query("printer.home.arpa."))
            .await
            .expect("stage should not error");

        assert!(response.is_none());
    }

    #[tokio::test]
    async fn forwards_matching_zone_and_rewrites_response_id() {
        let stage = ZoneForwardingStage::bypass_only(vec![zone_entry(
            "home.arpa",
            true,
            false,
            Arc::new(FixedResponseResolver {
                response: make_response(9),
            }),
        )]);

        let response = stage
            .handle(&make_query("printer.home.arpa."))
            .await
            .expect("stage should not error")
            .expect("query should be handled");

        let message = Message::from_vec(&response.into_bytes()).expect("response should parse");
        assert_eq!(message.id, 42);
    }

    #[tokio::test]
    async fn returns_none_when_zone_failure_falls_back_to_default_resolvers() {
        let stage = ZoneForwardingStage::non_bypass(vec![zone_entry(
            "home.arpa",
            false,
            true,
            Arc::new(AlwaysFailResolver),
        )]);

        let response = stage
            .handle(&make_query("printer.home.arpa."))
            .await
            .expect("stage should not error");

        assert!(response.is_none());
    }

    #[tokio::test]
    async fn returns_error_when_zone_failure_cannot_fall_back() {
        let stage = ZoneForwardingStage::non_bypass(vec![zone_entry(
            "home.arpa",
            false,
            false,
            Arc::new(AlwaysFailResolver),
        )]);

        let error = stage
            .handle(&make_query("printer.home.arpa."))
            .await
            .expect_err("stage should error");

        assert!(matches!(
            error,
            DnsPipelineError::Upstream(UpstreamResolveError::AllFailed)
        ));
    }
}
