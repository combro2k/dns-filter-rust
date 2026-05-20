pub mod dns_client;
pub mod doh_client;
#[cfg(feature = "doq")]
pub mod doq_client;
pub mod dot_client;
pub mod recursive_resolver;
pub mod runtime;

pub use dns_client::DnsUdpTcpClient;
pub use doh_client::DnsHttpsClient;
#[cfg(feature = "doq")]
pub use doq_client::DnsQuicClient;
pub use dot_client::DnsTlsClient;
pub use recursive_resolver::RecursiveResolver;
pub use runtime::{OutboundRouting, RoutedRuntimeProvider};
