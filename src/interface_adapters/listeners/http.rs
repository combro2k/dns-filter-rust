#[derive(Debug, Clone)]
pub struct HttpAdapter;

impl HttpAdapter {
    pub fn protocol_name(&self) -> &'static str {
        "http"
    }
}
