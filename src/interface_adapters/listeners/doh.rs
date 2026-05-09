#[derive(Debug, Clone)]
pub struct DohAdapter;

impl DohAdapter {
    pub fn protocol_name(&self) -> &'static str {
        "doh"
    }
}
