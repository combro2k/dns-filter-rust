use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_client::proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_client::proto::rr::rdata::{A, AAAA};
use hickory_client::proto::rr::{RData, Record, RecordType};

use crate::entities::filter::FilterDecision;
use crate::use_cases::filtering::DomainFilter;
use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};

/// A single stage in the request pipeline.
///
/// Returning `Some(Response)` means the stage handled the request and the
/// pipeline should short-circuit. Returning `None` passes the request to the
/// next stage.
pub trait RequestStage<Request, Response>: Send + Sync {
    fn handle(&self, request: &Request) -> Option<Response>;
}

/// A composable Chain of Responsibility pipeline.
pub struct PipelineHandler<Request, Response> {
    stages: Vec<Box<dyn RequestStage<Request, Response>>>,
}

impl<Request, Response> PipelineHandler<Request, Response> {
    pub fn new(stages: Vec<Box<dyn RequestStage<Request, Response>>>) -> Self {
        Self { stages }
    }

    pub fn add_stage(mut self, stage: impl RequestStage<Request, Response> + 'static) -> Self {
        self.stages.push(Box::new(stage));
        self
    }

    pub fn handle_request(&self, request: &Request) -> Option<Response> {
        for stage in &self.stages {
            if let Some(response) = stage.handle(request) {
                return Some(response);
            }
        }

        None
    }
}

impl<Request, Response> Default for PipelineHandler<Request, Response> {
    fn default() -> Self {
        Self { stages: Vec::new() }
    }
}

/// Async stage in a request pipeline with explicit error propagation.
#[async_trait]
pub trait AsyncRequestStage<Request, Response, Error>: Send + Sync {
    async fn handle(&self, request: &Request) -> Result<Option<Response>, Error>;
}

/// Async Chain of Responsibility pipeline.
pub struct AsyncPipelineHandler<Request, Response, Error> {
    stages: Vec<Box<dyn AsyncRequestStage<Request, Response, Error>>>,
}

impl<Request, Response, Error> AsyncPipelineHandler<Request, Response, Error> {
    pub fn new(stages: Vec<Box<dyn AsyncRequestStage<Request, Response, Error>>>) -> Self {
        Self { stages }
    }

    pub fn add_stage(
        mut self,
        stage: impl AsyncRequestStage<Request, Response, Error> + 'static,
    ) -> Self {
        self.stages.push(Box::new(stage));
        self
    }

    pub async fn handle_request(&self, request: &Request) -> Result<Option<Response>, Error> {
        for stage in &self.stages {
            if let Some(response) = stage.handle(request).await? {
                return Ok(Some(response));
            }
        }

        Ok(None)
    }
}

impl<Request, Response, Error> Default for AsyncPipelineHandler<Request, Response, Error> {
    fn default() -> Self {
        Self { stages: Vec::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPipelineRequest {
    pub query: Vec<u8>,
    pub client_query_id: u16,
}

impl DnsPipelineRequest {
    pub fn new(query: Vec<u8>) -> Self {
        let client_query_id = if query.len() >= 2 {
            u16::from_be_bytes([query[0], query[1]])
        } else {
            0
        };

        Self {
            query,
            client_query_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPipelineResponse {
    response: Vec<u8>,
}

impl DnsPipelineResponse {
    pub fn new(response: Vec<u8>) -> Self {
        Self { response }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.response
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DnsPipelineError {
    #[error("upstream resolution failed: {0}")]
    Upstream(#[from] UpstreamResolveError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnyQueryPolicy {
    Passthrough,
    Refused,
    #[default]
    NotImp,
}

pub type DnsRequestPipeline =
    AsyncPipelineHandler<DnsPipelineRequest, DnsPipelineResponse, DnsPipelineError>;

pub struct DnsFilterStage {
    domain_filter: Arc<dyn DomainFilter>,
    filtering_enabled: Arc<AtomicBool>,
}

impl DnsFilterStage {
    pub fn new(domain_filter: Arc<dyn DomainFilter>) -> Self {
        Self {
            domain_filter,
            filtering_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn with_filtering_enabled(mut self, flag: Arc<AtomicBool>) -> Self {
        self.filtering_enabled = flag;
        self
    }

    pub fn filtering_enabled_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.filtering_enabled)
    }
}

#[async_trait]
impl AsyncRequestStage<DnsPipelineRequest, DnsPipelineResponse, DnsPipelineError>
    for DnsFilterStage
{
    async fn handle(
        &self,
        request: &DnsPipelineRequest,
    ) -> Result<Option<DnsPipelineResponse>, DnsPipelineError> {
        if !self.filtering_enabled.load(Ordering::Relaxed) {
            return Ok(None);
        }

        let Ok(message) = Message::from_vec(&request.query) else {
            return Ok(None);
        };

        let Some(first_query) = message.queries().first() else {
            return Ok(None);
        };

        let domain = first_query.name().to_ascii();
        match self.domain_filter.decide(&domain) {
            FilterDecision::Allow | FilterDecision::Neutral => Ok(None),
            FilterDecision::Block => {
                tracing::info!(domain = %domain, "query blocked by filter policy");
                let response = build_sinkhole_response(
                    &message,
                    self.domain_filter.sinkhole_ipv4(),
                    self.domain_filter.sinkhole_ipv6(),
                );
                Ok(Some(DnsPipelineResponse::new(response)))
            }
        }
    }
}

pub struct DnsUpstreamStage {
    upstream_resolver: Arc<dyn UpstreamResolver>,
}

impl DnsUpstreamStage {
    pub fn new(upstream_resolver: Arc<dyn UpstreamResolver>) -> Self {
        Self { upstream_resolver }
    }
}

#[async_trait]
impl AsyncRequestStage<DnsPipelineRequest, DnsPipelineResponse, DnsPipelineError>
    for DnsUpstreamStage
{
    async fn handle(
        &self,
        request: &DnsPipelineRequest,
    ) -> Result<Option<DnsPipelineResponse>, DnsPipelineError> {
        let response = self
            .upstream_resolver
            .resolve(request.query.clone())
            .await?;

        if let Ok(mut msg) = Message::from_vec(&response) {
            msg.set_id(request.client_query_id);
            let fixed_response = msg.to_vec().unwrap_or(response);
            return Ok(Some(DnsPipelineResponse::new(fixed_response)));
        }

        tracing::warn!("failed to parse upstream response, returning as-is");
        Ok(Some(DnsPipelineResponse::new(response)))
    }
}

pub struct DnsAnyQueryPolicyStage {
    policy: AnyQueryPolicy,
}

impl DnsAnyQueryPolicyStage {
    pub fn new(policy: AnyQueryPolicy) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl AsyncRequestStage<DnsPipelineRequest, DnsPipelineResponse, DnsPipelineError>
    for DnsAnyQueryPolicyStage
{
    async fn handle(
        &self,
        request: &DnsPipelineRequest,
    ) -> Result<Option<DnsPipelineResponse>, DnsPipelineError> {
        if matches!(self.policy, AnyQueryPolicy::Passthrough) {
            return Ok(None);
        }

        let Ok(message) = Message::from_vec(&request.query) else {
            return Ok(None);
        };

        let Some(first_query) = message.queries().first() else {
            return Ok(None);
        };

        if first_query.query_type() != RecordType::ANY {
            return Ok(None);
        }

        let response_code = match self.policy {
            AnyQueryPolicy::Passthrough => return Ok(None),
            AnyQueryPolicy::Refused => ResponseCode::Refused,
            AnyQueryPolicy::NotImp => ResponseCode::NotImp,
        };

        tracing::info!(
            domain = %first_query.name().to_ascii(),
            policy = ?self.policy,
            response_code = ?response_code,
            "ANY query handled by policy"
        );

        Ok(Some(DnsPipelineResponse::new(build_error_response(
            &request.query,
            response_code,
        ))))
    }
}

pub struct DnsServfailFallbackStage;

#[async_trait]
impl AsyncRequestStage<DnsPipelineRequest, DnsPipelineResponse, DnsPipelineError>
    for DnsServfailFallbackStage
{
    async fn handle(
        &self,
        request: &DnsPipelineRequest,
    ) -> Result<Option<DnsPipelineResponse>, DnsPipelineError> {
        Ok(Some(DnsPipelineResponse::new(build_servfail_response(
            &request.query,
        ))))
    }
}

pub fn build_sinkhole_response(
    query: &Message,
    sinkhole_v4: Ipv4Addr,
    sinkhole_v6: Ipv6Addr,
) -> Vec<u8> {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);
    response.set_response_code(ResponseCode::NoError);

    for q in query.queries() {
        response.add_query(q.clone());
    }

    if let Some(question) = query.queries().first() {
        let name = question.name().clone();
        match question.query_type() {
            RecordType::A => {
                response.add_answer(make_a_record(name, sinkhole_v4));
            }
            RecordType::AAAA => {
                response.add_answer(make_aaaa_record(name, sinkhole_v6));
            }
            RecordType::ANY => {
                response.add_answer(make_a_record(name.clone(), sinkhole_v4));
                response.add_answer(make_aaaa_record(name, sinkhole_v6));
            }
            _ => {}
        }
    }

    response.to_vec().unwrap_or_default()
}

fn make_a_record(name: hickory_client::proto::rr::Name, addr: Ipv4Addr) -> Record {
    Record::from_rdata(name, 60, RData::A(A(addr)))
}

fn make_aaaa_record(name: hickory_client::proto::rr::Name, addr: Ipv6Addr) -> Record {
    Record::from_rdata(name, 60, RData::AAAA(AAAA(addr)))
}

pub fn build_servfail_response(query_bytes: &[u8]) -> Vec<u8> {
    build_error_response(query_bytes, ResponseCode::ServFail)
}

fn build_error_response(query_bytes: &[u8], response_code: ResponseCode) -> Vec<u8> {
    let mut response = Message::new();
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_available(true);
    response.set_response_code(response_code);

    if let Ok(query) = Message::from_vec(query_bytes) {
        response.set_id(query.id());
        response.set_recursion_desired(query.recursion_desired());
        for q in query.queries() {
            response.add_query(q.clone());
        }
    }

    response.to_vec().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use async_trait::async_trait;
    use hickory_client::proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_client::proto::rr::{DNSClass, RecordType};

    use crate::entities::filter::FilterDecision;
    use crate::use_cases::filtering::DomainFilter;
    use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};

    use super::*;

    struct PrefixMatchStage {
        prefix: &'static str,
        response: Option<&'static str>,
        calls: Arc<AtomicUsize>,
    }

    impl PrefixMatchStage {
        fn new(
            prefix: &'static str,
            response: Option<&'static str>,
            calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                prefix,
                response,
                calls,
            }
        }
    }

    impl RequestStage<String, String> for PrefixMatchStage {
        fn handle(&self, request: &String) -> Option<String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if request.starts_with(self.prefix) {
                return self.response.map(str::to_string);
            }

            None
        }
    }

    #[test]
    fn passes_request_to_later_stage_when_unhandled() {
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));

        let pipeline = PipelineHandler::default()
            .add_stage(PrefixMatchStage::new(
                "allow:",
                None,
                Arc::clone(&first_calls),
            ))
            .add_stage(PrefixMatchStage::new(
                "allow:",
                Some("allowed"),
                Arc::clone(&second_calls),
            ));

        let response = pipeline.handle_request(&"allow:example.org".to_string());

        assert_eq!(response, Some("allowed".to_string()));
        assert_eq!(first_calls.load(Ordering::Relaxed), 1);
        assert_eq!(second_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn short_circuits_after_first_matching_stage() {
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));

        let pipeline = PipelineHandler::default()
            .add_stage(PrefixMatchStage::new(
                "block:",
                Some("blocked"),
                Arc::clone(&first_calls),
            ))
            .add_stage(PrefixMatchStage::new(
                "block:",
                Some("should-not-run"),
                Arc::clone(&second_calls),
            ));

        let response = pipeline.handle_request(&"block:example.org".to_string());
        assert_eq!(response, Some("blocked".to_string()));
        assert_eq!(first_calls.load(Ordering::Relaxed), 1);
        assert_eq!(second_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn returns_none_when_no_stage_handles_request() {
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));

        let pipeline = PipelineHandler::default()
            .add_stage(PrefixMatchStage::new(
                "allow:",
                None,
                Arc::clone(&first_calls),
            ))
            .add_stage(PrefixMatchStage::new(
                "block:",
                Some("blocked"),
                Arc::clone(&second_calls),
            ));

        let response = pipeline.handle_request(&"unknown:example.org".to_string());
        assert_eq!(response, None);
        assert_eq!(first_calls.load(Ordering::Relaxed), 1);
        assert_eq!(second_calls.load(Ordering::Relaxed), 1);
    }

    struct UpstreamTerminalStage {
        calls: Arc<AtomicUsize>,
    }

    impl RequestStage<String, String> for UpstreamTerminalStage {
        fn handle(&self, _request: &String) -> Option<String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Some("upstream-response".to_string())
        }
    }

    #[test]
    fn chain_short_circuit_skips_upstream_terminal_stage() {
        let policy_calls = Arc::new(AtomicUsize::new(0));
        let upstream_calls = Arc::new(AtomicUsize::new(0));

        let pipeline = PipelineHandler::default()
            .add_stage(PrefixMatchStage::new(
                "block:",
                Some("blocked"),
                Arc::clone(&policy_calls),
            ))
            .add_stage(UpstreamTerminalStage {
                calls: Arc::clone(&upstream_calls),
            });

        let response = pipeline.handle_request(&"block:example.org".to_string());

        assert_eq!(response, Some("blocked".to_string()));
        assert_eq!(policy_calls.load(Ordering::Relaxed), 1);
        assert_eq!(upstream_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn chain_pass_through_reaches_upstream_terminal_stage() {
        let policy_calls = Arc::new(AtomicUsize::new(0));
        let upstream_calls = Arc::new(AtomicUsize::new(0));

        let pipeline = PipelineHandler::default()
            .add_stage(PrefixMatchStage::new(
                "block:",
                Some("blocked"),
                Arc::clone(&policy_calls),
            ))
            .add_stage(UpstreamTerminalStage {
                calls: Arc::clone(&upstream_calls),
            });

        let response = pipeline.handle_request(&"allow:example.org".to_string());

        assert_eq!(response, Some("upstream-response".to_string()));
        assert_eq!(policy_calls.load(Ordering::Relaxed), 1);
        assert_eq!(upstream_calls.load(Ordering::Relaxed), 1);
    }

    struct AsyncPrefixMatchStage {
        prefix: &'static str,
        response: Option<&'static str>,
    }

    #[async_trait]
    impl AsyncRequestStage<String, String, DnsPipelineError> for AsyncPrefixMatchStage {
        async fn handle(&self, request: &String) -> Result<Option<String>, DnsPipelineError> {
            if request.starts_with(self.prefix) {
                return Ok(self.response.map(str::to_string));
            }

            Ok(None)
        }
    }

    #[tokio::test]
    async fn async_pipeline_short_circuits_after_first_match() {
        let pipeline = AsyncPipelineHandler::default()
            .add_stage(AsyncPrefixMatchStage {
                prefix: "block:",
                response: Some("blocked"),
            })
            .add_stage(AsyncPrefixMatchStage {
                prefix: "block:",
                response: Some("should-not-run"),
            });

        let response = pipeline
            .handle_request(&"block:example.org".to_string())
            .await
            .expect("pipeline should not error");

        assert_eq!(response, Some("blocked".to_string()));
    }

    struct FixedResponseResolver(Vec<u8>);

    #[async_trait]
    impl UpstreamResolver for FixedResponseResolver {
        async fn resolve(&self, _query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
            Ok(self.0.clone())
        }
    }

    struct AlwaysFailResolver;

    #[async_trait]
    impl UpstreamResolver for AlwaysFailResolver {
        async fn resolve(&self, _query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
            Err(UpstreamResolveError::AllFailed)
        }
    }

    struct TestDomainFilter {
        decision: FilterDecision,
    }

    impl DomainFilter for TestDomainFilter {
        fn decide(&self, _domain: &str) -> FilterDecision {
            self.decision
        }

        fn sinkhole_ipv4(&self) -> std::net::Ipv4Addr {
            std::net::Ipv4Addr::new(0, 0, 0, 0)
        }

        fn sinkhole_ipv6(&self) -> std::net::Ipv6Addr {
            std::net::Ipv6Addr::UNSPECIFIED
        }

        fn start_background_refresh(self: Arc<Self>) {}

        fn list_names(&self) -> Vec<crate::use_cases::filtering::ListInfo> {
            Vec::new()
        }

        fn disable_list(&self, _name: &str) -> bool {
            false
        }

        fn enable_list(&self, _name: &str) -> bool {
            false
        }

        fn refresh_list(&self, _name: &str) -> bool {
            false
        }

        fn refresh_all_lists(&self) -> Vec<String> {
            Vec::new()
        }
    }

    fn make_query_with_type(domain: &str, record_type: RecordType) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(42);
        msg.set_recursion_desired(true);
        let mut q = Query::new();
        q.set_name(domain.parse().unwrap());
        q.set_query_type(record_type);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
        msg.to_vec().unwrap()
    }

    fn make_query(domain: &str) -> Vec<u8> {
        make_query_with_type(domain, RecordType::A)
    }

    fn make_noerror_response(id: u16) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(id);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        msg.to_vec().unwrap()
    }

    #[tokio::test]
    async fn dns_pipeline_blocks_query_before_upstream() {
        let filter: Arc<dyn DomainFilter> = Arc::new(TestDomainFilter {
            decision: FilterDecision::Block,
        });
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(AlwaysFailResolver);

        let pipeline = DnsRequestPipeline::default()
            .add_stage(DnsFilterStage::new(filter))
            .add_stage(DnsAnyQueryPolicyStage::new(AnyQueryPolicy::Passthrough))
            .add_stage(DnsUpstreamStage::new(resolver))
            .add_stage(DnsServfailFallbackStage);

        let response = pipeline
            .handle_request(&DnsPipelineRequest::new(make_query("example.com.")))
            .await
            .expect("pipeline should not error")
            .expect("pipeline should return a response")
            .into_bytes();

        let message = Message::from_vec(&response).expect("valid DNS message");
        assert_eq!(message.response_code(), ResponseCode::NoError);
        assert_eq!(message.answers().len(), 1);
    }

    #[tokio::test]
    async fn dns_pipeline_preserves_client_id_for_upstream_response() {
        let filter: Arc<dyn DomainFilter> = Arc::new(TestDomainFilter {
            decision: FilterDecision::Neutral,
        });
        let resolver: Arc<dyn UpstreamResolver> =
            Arc::new(FixedResponseResolver(make_noerror_response(9999)));

        let pipeline = DnsRequestPipeline::default()
            .add_stage(DnsFilterStage::new(filter))
            .add_stage(DnsAnyQueryPolicyStage::new(AnyQueryPolicy::Passthrough))
            .add_stage(DnsUpstreamStage::new(resolver))
            .add_stage(DnsServfailFallbackStage);

        let response = pipeline
            .handle_request(&DnsPipelineRequest::new(make_query("example.com.")))
            .await
            .expect("pipeline should not error")
            .expect("pipeline should return a response")
            .into_bytes();

        let message = Message::from_vec(&response).expect("valid DNS message");
        assert_eq!(message.id(), 42);
        assert_eq!(message.response_code(), ResponseCode::NoError);
    }

    #[tokio::test]
    async fn dns_pipeline_returns_error_when_upstream_fails_without_fallback() {
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(AlwaysFailResolver);
        let pipeline = DnsRequestPipeline::default()
            .add_stage(DnsAnyQueryPolicyStage::new(AnyQueryPolicy::Passthrough))
            .add_stage(DnsUpstreamStage::new(resolver));

        let result = pipeline
            .handle_request(&DnsPipelineRequest::new(make_query("example.com.")))
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dns_pipeline_refuses_any_query_before_upstream() {
        let filter: Arc<dyn DomainFilter> = Arc::new(TestDomainFilter {
            decision: FilterDecision::Neutral,
        });
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(AlwaysFailResolver);

        let pipeline = DnsRequestPipeline::default()
            .add_stage(DnsFilterStage::new(filter))
            .add_stage(DnsAnyQueryPolicyStage::new(AnyQueryPolicy::Refused))
            .add_stage(DnsUpstreamStage::new(resolver))
            .add_stage(DnsServfailFallbackStage);

        let response = pipeline
            .handle_request(&DnsPipelineRequest::new(make_query_with_type(
                "example.com.",
                RecordType::ANY,
            )))
            .await
            .expect("pipeline should not error")
            .expect("pipeline should return a response")
            .into_bytes();

        let message = Message::from_vec(&response).expect("valid DNS message");
        assert_eq!(message.id(), 42);
        assert_eq!(message.response_code(), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn dns_pipeline_notimp_any_query_before_upstream() {
        let filter: Arc<dyn DomainFilter> = Arc::new(TestDomainFilter {
            decision: FilterDecision::Neutral,
        });
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(AlwaysFailResolver);

        let pipeline = DnsRequestPipeline::default()
            .add_stage(DnsFilterStage::new(filter))
            .add_stage(DnsAnyQueryPolicyStage::new(AnyQueryPolicy::NotImp))
            .add_stage(DnsUpstreamStage::new(resolver))
            .add_stage(DnsServfailFallbackStage);

        let response = pipeline
            .handle_request(&DnsPipelineRequest::new(make_query_with_type(
                "example.com.",
                RecordType::ANY,
            )))
            .await
            .expect("pipeline should not error")
            .expect("pipeline should return a response")
            .into_bytes();

        let message = Message::from_vec(&response).expect("valid DNS message");
        assert_eq!(message.id(), 42);
        assert_eq!(message.response_code(), ResponseCode::NotImp);
    }
}
