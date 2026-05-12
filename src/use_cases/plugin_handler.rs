use async_trait::async_trait;

use crate::use_cases::request_pipeline::{
    AsyncRequestStage, DnsPipelineError, DnsPipelineRequest, DnsPipelineResponse,
};

/// Pipeline stage that delegates to loaded WASM plugins.
///
/// This is a scaffold: the stage always passes through (`Ok(None)`) until the
/// WASM runtime is wired in behind the `plugins` cargo feature.
pub struct WasmPluginStage {
    _private: (),
}

impl WasmPluginStage {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for WasmPluginStage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AsyncRequestStage<DnsPipelineRequest, DnsPipelineResponse, DnsPipelineError>
    for WasmPluginStage
{
    async fn handle(
        &self,
        _request: &DnsPipelineRequest,
    ) -> Result<Option<DnsPipelineResponse>, DnsPipelineError> {
        // Stub: pass through to next stage.
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::plugin::{PluginQuery, PluginVerdict};

    #[test]
    fn plugin_verdict_variants_are_constructible() {
        let _ = PluginVerdict::Pass;
        let _ = PluginVerdict::Block;
        let _ = PluginVerdict::Allow;
        let _ = PluginVerdict::Rewrite {
            target: "example.com".to_string(),
        };
    }

    #[test]
    fn plugin_query_holds_fields() {
        let q = PluginQuery {
            domain: "example.com".to_string(),
            qtype: 1,
            client_ip: "127.0.0.1".to_string(),
        };
        assert_eq!(q.domain, "example.com");
        assert_eq!(q.qtype, 1);
        assert_eq!(q.client_ip, "127.0.0.1");
    }

    #[tokio::test]
    async fn wasm_plugin_stage_passes_through() {
        let stage = WasmPluginStage::new();
        let request = DnsPipelineRequest::new(vec![0; 12]);
        let result = stage.handle(&request).await;
        assert!(result.unwrap().is_none());
    }
}
