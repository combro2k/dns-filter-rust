#[derive(Debug, Clone)]
pub struct DoqAdapter;

impl DoqAdapter {
    pub fn protocol_name(&self) -> &'static str {
        "doq"
    }
}
