# CHANGELOG

All notable changes to this project will be documented in this file.

## [Unreleased]
- Added `tokio::time::timeout` guard to `DnsUdpTcpClient::resolve_udp` and `resolve_tcp` so that a hung hickory background task can no longer stall the caller indefinitely
- Added TLS connection caching to `DnsTlsClient`: TLS handshake is performed once and the resulting `DnssecClient` handle is reused across queries; stale connections are evicted on error and re-established transparently
- Added TCP connection caching to `DnsUdpTcpClient::resolve_tcp`: TCP session is reused across truncated-response fallbacks; stale connections are evicted on error and re-established transparently
- Added `upstreams.bootstrap_resolvers` config (default: `1.1.1.1`) to bootstrap DoT hostname resolution when OS DNS is unavailable
- Implemented DoT hostname resolution fallback in `DnsTlsClient`: tries OS lookup first, then queries configured bootstrap resolvers for A/AAAA records
- Extended DoT upstream parsing to support hostname endpoints (for example `tls://dns.example.com:853`) with hostname-based SNI and runtime hostname resolution
- Added DNS-over-TLS upstream resolver support via new `DnsTlsClient` in `src/frameworks/upstream/dot_client.rs`
- Enabled Hickory TLS features in `Cargo.toml` (`tls-ring`, `webpki-roots`) to support DoT client connectivity
- Added upstream bootstrap construction in `src/use_cases/config_bootstrap.rs` to build `Arc<dyn UpstreamResolver>` from config (`dns` and `dot`), including validation for strategy, protocol, address format, and empty upstream list
- Wired upstream resolver construction into composition root startup in `src/main.rs` so invalid upstream configuration fails fast
- Improved upstream parse hints in `src/frameworks/config/loader.rs` to include supported protocols and DoT address examples
- Added Chain of Responsibility-focused tests in `src/use_cases/request_pipeline.rs` to verify upstream terminal stage is skipped on short-circuit and reached on pass-through
- Implemented use-case Chain of Responsibility core in `src/use_cases/request_pipeline.rs`: added `RequestStage` pass/short-circuit contract with `Option<Response>`, `PipelineHandler` stage composition, and execution short-circuiting
- Added unit tests for request pipeline pass-through, short-circuit, and unhandled request behavior
- **Migrated from `trust-dns` 0.22 to `hickory-client` 0.25 (Hickory DNS)**: fixes broken DNSSEC validation, adds native DoT/DoH/DoQ/DoH3 protocol support via feature flags
- Replaced `trust-dns-server`, `trust-dns-proto`, and `trust-dns-client` with `hickory-client` (features: `dnssec-ring`)
- Rewrote `DnsUdpTcpClient` to use Hickory's `DnssecClient`, `UdpClientStream`, `TcpClientStream` + `DnsMultiplexer`
- DNSSEC validation now works correctly against real-world signed domains (previously broken with trust-dns 0.22)
- Replaced empty-trust-anchor negative test with `dnssec-failed.org` broken-chain validation test
- Added `UpstreamProtocol` enum and `ResolvedUpstream` value object to `entities/resolution.rs`
- Added `Copy` derive to `UpstreamStrategy`
- Added `use_cases/upstream_resolver.rs`: `UpstreamResolver` async trait, `UpstreamResolveError`, and `StrategyUpstreamResolver` implementing round-robin, random, and failover dispatch strategies
- Added `frameworks/upstream/dns_client.rs`: `DnsUdpTcpClient` now uses Trust-DNS DNSSEC-aware clients for UDP-first resolution with automatic TCP fallback on truncation (RFC 5966)
- Updated upstream network tests to use the standard DNSSEC test domain (`sigok.verteiltesysteme.net`) against public resolvers
- Added a DNSSEC-specific negative test that uses an empty trust anchor to confirm validation failure on signed data
- Enabled DNSSEC features on `trust-dns-client` and `trust-dns-proto` in `Cargo.toml`
- Added `async-trait`, `rand`, and `futures` dependencies to `Cargo.toml`
- Initial creation of AGENTS.md and CHANGELOG.md
- Documented DDD and chain of responsibility patterns
- Established project rules: always update CHANGELOG.md and add cargo tests for new features
- Started Clean Architecture implementation with new module skeleton under `src/entities`, `src/use_cases`, `src/interface_adapters`, and `src/frameworks`
- Split configuration into framework modules (`src/frameworks/config/schema.rs`, `src/frameworks/config/loader.rs`)
- Refactored `src/main.rs` into a composition-root style entrypoint using framework loader + use-case validation
- Added initial protocol adapter skeletons for DNS, DoT, DoH, DoQ, and HTTP under `src/interface_adapters/listeners/`
- Removed legacy flat placeholder modules (`src/config.rs`, `src/filter.rs`, `src/upstream.rs`, `src/logging.rs`, `src/metrics.rs`)
- Added crate library root (`src/lib.rs`) to formalize architectural boundaries
- Updated `AGENTS.md` with concrete architecture, dependency rules, and protocol scope
- Fixed YAML compatibility for blocklists/allowlists by supporting named-map list entries and explicit `name`/`url` entries in `src/frameworks/config/schema.rs`
- Added parser regression test for named-map list format in `src/frameworks/config/loader.rs`
- Improved config parse errors to include file path, line/column, and field path via `serde_path_to_error`
- Added regression test to verify diagnostic parse error details for invalid config values
- Made config error output more human-friendly with structured `File/Location/Field/Reason/Hint` messages and field-specific guidance
