/// Protocol adapter identification stub.
#[derive(Debug, Clone)]
pub struct DnsAdapter;

impl DnsAdapter {
    pub fn protocol_name(&self) -> &'static str {
        "dns"
    }
}
