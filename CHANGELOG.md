# CHANGELOG

All notable changes to this project will be documented in this file.

## [Unreleased]
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
