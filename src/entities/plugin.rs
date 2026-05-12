/// Verdict returned by a WASM plugin after inspecting a DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginVerdict {
    /// Continue to the next pipeline stage.
    Pass,
    /// Block the query (return sinkhole response).
    Block,
    /// Allow the query unconditionally (bypass remaining filters).
    Allow,
    /// Rewrite the query target to a different domain.
    Rewrite { target: String },
}

/// Minimal query context passed to a WASM plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginQuery {
    pub domain: String,
    pub qtype: u16,
    pub client_ip: String,
}
