#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    Allow,
    Block,
    Neutral,
}
