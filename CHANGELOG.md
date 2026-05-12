# CHANGELOG

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-05-12

### Breaking
- **CLI restructured to subcommand-based architecture**: `dns-filter` no longer starts the daemon directly; use `dns-filter start [--config <path>] [--debug]` instead. New subcommands: `start`, `stop`, `reload`, `merge-config`
- Updated systemd `ExecStart`, `ExecReload`, `ExecStop` directives to use the new subcommand syntax
- Updated OpenRC `command_args` and `reload()` to use the new subcommand syntax
- Updated `tests/listener_batch_test.sh` to use `dns-filter start` subcommand

### Added
- `make install` now auto-detects the init system (systemd or OpenRC) and installs the corresponding service file; override with `INIT_SYSTEM=systemd|openrc|none`
- On upgrade installs (existing `config.yaml` detected), `make install` now prints a hint to run `dns-filter merge-config --overwrite --config /etc/dns-filter/config.yaml`
- Added Unix domain control socket for daemon management: the running daemon listens on a JSON-over-Unix-socket control channel (default: `/run/dns-filter/dns-filter.sock`, configurable via `control.socket_path` in config)
- Added `dns-filter stop` subcommand: sends a stop command to the running daemon via the control socket for graceful shutdown
- Added `dns-filter reload` subcommand: sends a reload command to the running daemon via the control socket to reload configuration
- Added `dns-filter merge-config` subcommand: deep-merges the user's config file with the built-in example defaults; missing sections are filled from the example config, user values always win; supports `--overwrite` to write back in-place or stdout (default) for piping
- Added `POST /api/v1/stop` REST API endpoint (Bearer-token guarded) for triggering graceful shutdown via HTTP
- Added graceful shutdown on SIGTERM and SIGINT signals via `CancellationToken`, replacing the previous abrupt termination behavior; all tasks wind down cleanly and the control socket is removed
- Added stale control socket detection on startup: if a socket file exists from a previous crashed run, it is detected and replaced; if a live daemon is already listening, startup fails with a clear error
- Added `control` config section with `socket_path` option (default: `/run/dns-filter/dns-filter.sock`)
- Added `RuntimeDirectory=dns-filter` to systemd service for `/run/dns-filter/` creation
- Added `tokio-util` dependency (v0.7, `rt` feature) for `CancellationToken`
- Added control socket permission restriction (`0o660`) so only root or the daemon's user/group can issue commands
- SIGHUP reload preserved alongside new control socket and API reload paths (defense in depth)

## [1.0.2] - 2026-05-12

### Fixed
- Fixed false-positive DNS blocks caused by missing AdGuard cosmetic rule markers (`#?#`, `#@?#`, `#$?#`, `#@$?#`, `#@$#`, `#@%#`, `$@$`) in the filter parser — rules using these markers (e.g. `imdb.com#$?#...`) were incorrectly treated as domain blocks
- Fixed fail-open modifier logic in `restricting_modifier`: inverted to a DNS-safe allowlist (`important`, `match-case`, `all`, noop) so that unknown or response-modification modifiers (`$csp`, `$redirect`, `$removeparam`, `$cookie`, `$stealth`, `$badfilter`, etc.) correctly cause rules to be skipped at DNS level
- Fixed log spam from hickory DNSSEC validation warnings (e.g. "response does not contain NSEC or NSEC3 records") flooding INFO-level output: `hickory_proto` and `hickory_resolver` modules are now filtered to ERROR-only in normal mode (all messages shown in `--debug` mode)

## [1.0.1] - 2026-05-12
- Added per-zone authoritative JSON source mode with `resolvers.zones[*].zone_source` (local file, `http://`, or `https://`) and strict XOR validation against forwarding `servers[]` mode
- Added optional per-zone `resolvers.zones[*].zone_source_check_interval` for URL-backed authoritative zones, including background refresh that keeps the last good snapshot on refresh failure
- Added startup/reload validation for zone-source mode combinations and zone consistency (`resolvers.zones[*].zone` must match JSON `zone`)
- Added initial authoritative JSON zone resolver implementation (`src/use_cases/zone_authority.rs`) with DNS answer synthesis for `A`, `AAAA`, `SOA`, `NS`, `MX`, `TXT`, `SRV`, `CNAME`, `PTR`, `CAA`, `TLSA`, and `NAPTR` records
- Added NS glue synthesis for authoritative JSON zones: `NS` answers now include in-zone `A`/`AAAA` host records in the DNS additional section when available
- Added authoritative JSON fallback synthesis for missing apex records: when JSON omits apex `NS` or `SOA`, the resolver now auto-generates defaults (`NS ns1.<zone>`, `SOA ns1.<zone> hostmaster.<zone>`) so authority responses remain valid
- Updated config parse guidance and example configuration to document `zone_source` mode and URL check interval behavior
- Added unit tests covering zone mode XOR validation, file source acceptance, and file-source interval rejection
- Added authoritative-zone tests covering NS glue, auto-generated apex NS/SOA fallback records, and JSON parsing for `CAA`, `TLSA`, and `NAPTR`

## [1.0.0] - 2026-05-11
- Expanded `tests/release-check.sh` to run the required release gates: `gitleaks`, `cargo fmt --all -- --check`, `cargo test --all-targets --all-features`, and `cargo clippy --all-targets --all-features -- -D warnings`
- Added bash-only zone-forwarding smoke coverage to `tests/listener_batch_test.sh`, including `resolvers.zones[*].enabled` on/off behavior
- Added optional `resolvers.zones[*].enabled` flag so zone-forwarding entries can be kept in config but turned on/off without removal; omitted `enabled` defaults to `true`
- Added zone-based forwarding under `resolvers.zones[]`: queries matching configured suffixes can use dedicated zone-specific upstream resolvers, optionally bypass blocklist filtering, and optionally fall back to the default resolver set when all zone resolvers fail
- Consolidated duplicated governance rules in `AGENTS.md` by making `Project Rules` the single source of truth and simplifying/reordering the AI role and security sections
- Documented the coding agent role in `AGENTS.md` as a security-first engineer responsible for flaw/race-condition review and required quality-gate checks
- Added explicit security-first engineering requirements to `AGENTS.md`, including a mandatory security review checklist and concurrency/race-condition review requirements
- Implemented configuration-driven logging initialization with support for syslog, file, and stdout targets; logging now initializes after config load and before privilege drop/chroot
- Implemented syslog transport support with local unix socket defaults and remote endpoints: `transport` (`unix`/`udp`/`tcp`/`tls`), `server`, and `format` (`rfc3164`/`rfc5424`) under `logging.syslog`
- Integrated `syslog` crate for unix/udp/tcp client transports and kept custom TLS transport path for remote TLS syslog
- Updated example config with syslog transport/format/TLS options and chroot notes for `/dev/log` bind-mount requirements
- Updated OpenRC script to bind-mount `/dev/log` into `/var/lib/dns-filter/dev/log` during start (for chrooted local syslog) and unmount on stop
- Added domain name and query type to SERVFAIL log messages in the DNS pipeline (`forward_query`), making it easier to diagnose upstream failures
- Fixed chroot breaking user/group resolution: moved name→uid/gid lookup before `chroot()` so `/etc/passwd` and `/etc/group` are still accessible from the real root filesystem
- Extended hickory log filtering: in normal mode `hickory_recursor` is now also filtered to ERROR-only (in addition to `hickory_proto::dnssec`), suppressing expected WARN-level "no records found for DS" messages during unsigned delegation probing; all messages remain visible in `--debug` mode
- Changed hickory DNSSEC warnings (e.g. "response does not contain NSEC or NSEC3 records" for missing DS/NSEC/NSEC3) from WARN to effectively DEBUG level: in normal mode the `hickory_proto::dnssec` module is filtered to ERROR-only; in `--debug` mode all messages are shown; switched `tracing-subscriber` from `with_max_level` to `EnvFilter` and added the `env-filter` feature
- Added privilege dropping after socket bind: the process now starts as root to bind privileged ports, then performs chroot + setgroups + setgid + setuid to an unprivileged user; on Linux, `CAP_NET_BIND_SERVICE` is retained via `prctl(PR_SET_KEEPCAPS)` + capability manipulation for potential rebinds on config reload
- Added `security` config section with `user` (default: `"nobody"`), `group` (default: `"nogroup"`), and `chroot_dir` (default: `"/var/lib/dns-filter"`) fields
- Split `DnsServer::run()` into `DnsServer::bind()` + `BoundDnsServer::serve()` to allow privilege dropping between socket binding and request serving
- Added `nix` (v0.29, features: user/fs/process) and `caps` (v0.5) dependencies for Unix privilege management and Linux capability manipulation
- Updated systemd unit with `AmbientCapabilities`, `CapabilityBoundingSet`, and filesystem hardening directives (`ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`)
- Updated OpenRC init script with ownership checks for the chroot directory
- Added dual-stack (IPv4+IPv6) listening support: listener `address` field is now `addresses` accepting a list of bind addresses (e.g. `["0.0.0.0", "::"]`); the old single-string `address` key remains supported for backward compatibility; default is dual-stack `["0.0.0.0", "::"]` for public listeners and `["127.0.0.1", "::1"]` for metrics
- Added CNAME chain following to the recursive resolver: when the initial lookup returns only CNAME records and the queried type is not CNAME itself, the resolver now issues follow-up queries for the CNAME target until the final answer (A/AAAA/etc.) is obtained, matching public resolver behavior; limited to 10 hops to prevent infinite loops from circular CNAME chains
- Fixed `reload_config_succeeds_with_valid_config` test flaking due to parallel tests sharing the same temp file path; each test now gets a unique file via an atomic counter
- Fixed recursive resolver returning SERVFAIL for NXDOMAIN and NODATA responses (e.g. DS queries for unsigned domains like `google.com`): the recursor's "no records found" errors are now translated into proper DNS NODATA (NOERROR + SOA + NSEC/NSEC3 proof records) or NXDOMAIN responses instead of propagating as pipeline failures, fixing `delv` "broken trust chain" errors for unsigned delegations
- Fixed AD (Authenticated Data) flag being set unconditionally for all recursive responses when DNSSEC validation is enabled; the flag is now only set when every answer record carries `Proof::Secure`, so unsigned delegations (e.g. `google.com`) no longer cause `delv` to report "broken trust chain"
- Fixed DNSSEC-aware clients (`delv +noroot`, `dig +dnssec`) seeing "answer not validated" / missing AD flag: recursive resolver responses now set the AD (Authenticated Data) flag when DNSSEC validation succeeded, and echo back an EDNS OPT record with the DO bit when the client sends one
- Changed `ip_preference` to `nameserver_ip_family` for the recursive resolver; now an enforced constraint using `hickory-recursor`'s `nameserver_filter`: `"ipv4"` blocks all IPv6 nameservers, `"ipv6"` blocks all IPv4 nameservers, and omitting the option (new default) allows both families; added `ipnet` dependency
- Replaced custom iterative `RecursiveResolver` with `hickory-recursor` crate, gaining built-in DNSSEC chain-of-trust validation from the IANA root KSK; queries like `delv @127.0.0.1 cloudflare.com A` now validate successfully instead of reporting "broken trust chain"
- Added `dnssec` config option for the recursive resolver (default `true`): when enabled, the resolver validates DNSSEC signatures; set `dnssec: false` to disable validation
- Added `hickory-recursor` v0.25.2 dependency with `dnssec-ring` feature
- Recursive resolver now loads root-server addresses from `/usr/share/dns/root.hints` (or other well-known OS paths) at startup, falling back to compiled-in IANA addresses when the file is absent; added optional `root_hints_path` config field for explicit override
- Added compiled-in IPv6 root-server addresses (`ROOT_HINTS_V6`) alongside the existing IPv4 set, so iterative resolution uses both address families by default
- Fixed `RecursiveResolver` failing with DNSSEC validation errors ("could not validate negative response missing SOA") and timeouts during iterative resolution by replacing `DnssecClient` with plain `Client` — referral responses are not authoritative and cannot pass DNSSEC validation
- Fixed slow iterative resolution for domains whose glue records list AAAA (IPv6) addresses before A (IPv4): glue addresses are now sorted IPv4-first, and `try_nameservers` races up to 3 candidates concurrently via `select_ok` instead of trying each sequentially
- Added `ip_preference` config option (now `nameserver_ip_family`) for the recursive resolver (`"ipv4"` default, `"ipv6"`): controls whether IPv4 or IPv6 glue addresses are tried first during iterative resolution
- Added iterative recursive DNS resolver (`RecursiveResolver`) in [src/frameworks/upstream/recursive_resolver.rs](src/frameworks/upstream/recursive_resolver.rs): resolves queries from IANA root hints without a configured upstream, following NS referrals and using glue records where available; no-glue NS names are resolved via sub-lookups bounded by a configurable `max_hops` limit (default 12)
- Renamed config section `upstreams:` to `resolvers:` in all configs and the `UpstreamsConfig` struct to `ResolversConfig` in [src/frameworks/config/schema.rs](src/frameworks/config/schema.rs) to reflect that the section now covers both forwarding and recursive resolvers
- Added `protocol: "recursive"` as a valid resolver protocol; `address` is optional for this protocol and `max_hops` (optional `u8`) controls the referral hop limit
- Bootstrap resolvers are now only parsed when at least one `dot` server is configured, removing a spurious validation error for purely recursive setups
- Added listener batch smoke-test script at [tests/listener_batch_test.sh](tests/listener_batch_test.sh) to start a local instance on non-default loopback ports, probe DNS UDP/TCP end-to-end, and report DoT/DoH/DoQ/HTTP/metrics checks as pass/fail/skip with optional strict mode
- Aligned `hickory-client` dependency to latest stable `0.25.2` while keeping existing DNSSEC/TLS feature flags
- Started one-shot Chain of Responsibility compliance migration for request handling: added async, explicit-error CoR support in [src/use_cases/request_pipeline.rs](src/use_cases/request_pipeline.rs) with `AsyncRequestStage` + `AsyncPipelineHandler` (`Result<Option<Response>, Error>` contract)
- Added concrete DNS pipeline stages in use-cases (`DnsFilterStage`, `DnsUpstreamStage`, `DnsServfailFallbackStage`) and moved sinkhole/SERVFAIL response construction helpers to use-case orchestration
- Added `build_dns_request_pipeline()` in [src/use_cases/config_bootstrap.rs](src/use_cases/config_bootstrap.rs) to compose canonical stage order (filter -> upstream -> fallback)
- Refactored DNS listener adapter in [src/interface_adapters/listeners/dns.rs](src/interface_adapters/listeners/dns.rs) to delegate query processing to the use-case pipeline instead of inline filter/upstream branching
- Updated composition and reload flow in [src/main.rs](src/main.rs) to maintain an atomically swappable pipeline slot (`Arc<Mutex<Arc<...>>>`) rebuilt on SIGHUP reload
- Added/updated pipeline-focused tests in [src/use_cases/request_pipeline.rs](src/use_cases/request_pipeline.rs) and adapted DNS listener tests to the new pipeline wiring
- Implemented SIGHUP signal handler for graceful zero-downtime configuration reload: signal triggers config file re-read and atomic state swap without interrupting in-flight DNS queries; on reload error, the service continues with previous config and logs a warning
- Refactored state management to use `Arc<Mutex<Arc<>>>` pattern for atomic swappable resolver and filter instances, enabling safe concurrent access from reload handler and DNS listeners
- Updated systemd service file with `ExecReload=/bin/kill -HUP $MAINPID` to support `systemctl reload dns-filter`
- Added `reload()` function to OpenRC init script to support `rc-service dns-filter reload`
- Added integration tests for config reload validation, error handling, and successful reloads with valid configurations
- Added `src/use_cases/reload.rs` module with `reload_config()` function that orchestrates configuration reload by reusing bootstrap logic from `config_bootstrap.rs`
- Added `src/frameworks/signal_handler.rs` module with `setup_sighup_handler()` for Unix SIGHUP signal listening via `tokio::signal::unix`
- Added CLI flags documentation and CHANGELOG.md
- Updated packaged service launch arguments to pass config via `--config /etc/dns-filter/config.yaml` in both systemd and OpenRC files
- Reorganized packaging artifacts by role: configuration templates now live under `package/config/`, systemd units under `package/systemd/`, and OpenRC scripts under `package/openrc/`
- Added packaging helpers: a root `Makefile`, a systemd unit, and an OpenRC init script that install `dns-filter` to `/usr/bin/dns-filter`, the config to `/etc/dns-filter/config.yaml`, and data under `/var/lib/dns-filter`
- Extended `list refreshed` logs to include parsed added-entry counters: `block_entries_added`, `whitelist_entries_added`, and `skipped_entries_added`
- Improved filter list parser to correctly handle AdGuard/uBlock Origin syntax: cosmetic rules (`##`, `#@#`, `#$#`, `#%#`, `$$`) are now skipped; `@@||domain^` exception rules are treated as inline allowlist entries; rules with content-type (`$script`, `$image`, etc.) or context (`$third-party`, `$domain=`, etc.) modifiers are skipped with a `debug`-level log since DNS cannot evaluate those restrictions; `$all` and behaviour-only modifiers (`$important`, `$match-case`) are stripped and the rule is applied
- Added optional `enabled` flag support for `blocklists`/`allowlists` entries; disabled lists are excluded from runtime refresh scheduling while omitted `enabled` defaults to active behavior
- Updated example config list entries so only `blocklists.adguard_base` is enabled and all other blocklist/allowlist entries are disabled by default
- Added optional SQLite-backed document cache for filter lists (`filtering.cache.mode: sqlite`) to support warm-start restoration while keeping in-memory cache as runtime source of truth
- Added optional `filtering.cache.document_path` config for SQLite cache file location (default: `/var/lib/dns-filter/filter-cache.db` when sqlite mode is enabled)
- Started filtering implementation with interval-based list cache refresh: added per-list `interval` support on `blocklists`/`allowlists` (for example `blocklists.adguard_base.interval`) with runtime default of `12h` when omitted
- Added `filtering.sinkhole_ipv4` and `filtering.sinkhole_ipv6` config options (defaults: `0.0.0.0` and `::`) and wired sinkhole responses for blocked DNS queries
- Added `ListFilterEngine` use-case with background per-list refresh workers for HTTP(S)/file-backed sources and allowlist-over-blocklist decision precedence
- Wired DNS listener filtering path before upstream resolution so blocked domains short-circuit to synthetic responses
- Added explicit `enabled` flags for listener sockets (`listen.dns|dot|doh|doq|http`) and upstream servers (`upstreams.servers[*]`), with runtime gating so disabled entries are not started/used
- Updated composition root and upstream bootstrap behavior: DNS listener now requires `listen.dns.enabled: true`, and resolver construction now requires at least one enabled upstream server
- Updated example configuration to set `enabled` on each listener and upstream entry, with only DNS listener and DNS upstream enabled for now
- Added/updated tests for missing `enabled` parse failures, disabled-upstream filtering, and all-disabled upstream validation errors
- Implemented default DNS UDP/TCP server in `src/interface_adapters/listeners/dns.rs`: `DnsServer` binds both a UDP socket and a TCP listener on the configured address/port, serves DNS queries concurrently, and maps upstream failures to SERVFAIL responses (RFC 2308)
- TCP transport uses RFC 7766 2-byte length-prefix framing; each connection is handled in an isolated task so a single bad stream cannot stall the accept loop
- Wired `DnsServer` startup into composition root (`src/main.rs`): validates that `listen.dns` is present and exits with a clear error message if it is not configured
- Added unit tests for SERVFAIL construction, address validation, `forward_query` success/failure paths, and end-to-end TCP framing round-trip
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
