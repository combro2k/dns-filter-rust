use std::sync::Arc;

use hickory_proto::op::{Header, HeaderCounts, Message, MessageType, Metadata, ResponseCode};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::sync::Mutex;

use crate::use_cases::request_pipeline::{
    build_servfail_response, DnsPipelineRequest, DnsRequestPipeline,
};

/// Bridges hickory-server's request/response model to the existing `DnsRequestPipeline`.
///
/// Receives parsed DNS requests from hickory-server, forwards raw bytes through
/// the pipeline, and translates the response back into hickory's `MessageResponse`
/// for serialization and sending.
pub struct HickoryRequestHandler {
    pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>,
}

impl HickoryRequestHandler {
    pub fn new(pipeline_slot: Arc<Mutex<Arc<DnsRequestPipeline>>>) -> Self {
        Self { pipeline_slot }
    }
}

#[async_trait::async_trait]
impl RequestHandler for HickoryRequestHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let query_bytes = request.as_slice();
        let pipeline = Arc::clone(&*self.pipeline_slot.lock().await);
        let dns_request = DnsPipelineRequest::new(query_bytes.to_vec());

        let response_bytes = match pipeline.handle_request(&dns_request).await {
            Ok(Some(response)) => response.into_bytes(),
            Ok(None) => {
                tracing::warn!("pipeline returned no response; returning SERVFAIL");
                build_servfail_response(query_bytes)
            }
            Err(error) => {
                tracing::warn!(%error, "pipeline failed; returning SERVFAIL");
                build_servfail_response(query_bytes)
            }
        };

        match build_response(request, &mut response_handle, &response_bytes).await {
            Ok(info) => info,
            Err(error) => {
                tracing::error!(%error, "failed to send DNS response");
                serve_failed_info(request)
            }
        }
    }
}

/// Parses pipeline response bytes into a `MessageResponse` and sends it via
/// the hickory `ResponseHandler`.
async fn build_response<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    response_bytes: &[u8],
) -> Result<ResponseInfo, hickory_server::net::NetError> {
    let response_msg = match Message::from_vec(response_bytes) {
        Ok(msg) => msg,
        Err(_) => {
            tracing::warn!("failed to parse pipeline response; sending SERVFAIL");
            let builder = MessageResponseBuilder::from_message_request(request);
            let msg_response = builder.error_msg(&request.metadata, ResponseCode::ServFail);
            return response_handle.send_response(msg_response).await;
        }
    };

    let mut metadata = hickory_proto::op::Metadata::response_from_request(&request.metadata);
    metadata.response_code = response_msg.response_code;
    metadata.authoritative = response_msg.authoritative;
    metadata.recursion_available = response_msg.recursion_available;
    metadata.authentic_data = response_msg.authentic_data;
    metadata.checking_disabled = response_msg.checking_disabled;

    let builder = MessageResponseBuilder::from_message_request(request);
    let msg_response = builder.build(
        metadata,
        &response_msg.answers,
        &response_msg.authorities,
        Vec::<&hickory_proto::rr::Record>::new(), // SOA already in authorities
        &response_msg.additionals,
    );

    response_handle.send_response(msg_response).await
}

/// Constructs a SERVFAIL `ResponseInfo` when the response handler itself fails.
fn serve_failed_info(request: &Request) -> ResponseInfo {
    let mut metadata = Metadata::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    metadata.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_is_send_sync_unpin() {
        fn assert_bounds<T: Send + Sync + Unpin + 'static>() {}
        assert_bounds::<HickoryRequestHandler>();
    }
}
