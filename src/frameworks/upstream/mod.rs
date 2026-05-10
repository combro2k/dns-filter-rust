pub mod dns_client;
pub mod dot_client;
pub mod recursive_resolver;

pub use dns_client::DnsUdpTcpClient;
pub use dot_client::DnsTlsClient;
pub use recursive_resolver::RecursiveResolver;
