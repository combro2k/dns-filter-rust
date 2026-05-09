#[derive(Debug, Clone)]
pub struct DotAdapter;

impl DotAdapter {
    pub fn protocol_name(&self) -> &'static str {
        "dot"
    }
}
