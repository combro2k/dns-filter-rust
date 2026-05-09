use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamStrategy {
    RoundRobin,
    Random,
    Failover,
}

impl FromStr for UpstreamStrategy {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let strategy = match value {
            "random" => Self::Random,
            "failover" => Self::Failover,
            "round_robin" => Self::RoundRobin,
            _ => return Err(()),
        };

        Ok(strategy)
    }
}
