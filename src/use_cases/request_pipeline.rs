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

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

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
}
