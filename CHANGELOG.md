# CHANGELOG

## [Unreleased]

### Added
- **ACME certificate management** (feature: `acme`): Automatic TLS certificate provisioning via ACME (Let's Encrypt or any RFC 8555 provider) using DNS-01 challenges with Cloudflare DNS API. Supports background auto-renewal, zero-downtime certificate hot-reload across all TLS listeners (DoT, DoH, DoQ), persistent account credentials, and configurable renewal threshold. Enable with `--features acme`.
- **Embedded API routes in admin listener**: the admin UI server now serves all `/api/v1/*` routes directly on the same origin, eliminating the need for a separate API listener or cross-origin requests. The standalone `api:` listener remains available for headless/API-only deployments.
- **Separate admin UI listener with dual-port HTTP/HTTPS support**: the admin dashboard is now served from its own `listen.admin` listener, separate from the API. Supports a dual-port setup: when TLS is configured, port 80 issues 301 redirects to the HTTPS port (default 8443); when TLS is absent, port 80 serves the admin UI directly over plain HTTP.
- **Optional TLS for the REST API**: `api.tls` configuration enables HTTPS on the API listener with certificate auto-generation support (`autogenerate: true`).
- **Optional TLS for the metrics listener**: `listen.metrics.tls` configuration enables HTTPS on the Prometheus metrics endpoint.
- **CORS support on the API**: the API server now includes CORS headers to allow cross-origin requests from the admin UI when served on a separate port/origin.
- **Blocklist attribution on blocked queries**: when a DNS query is blocked, the system now identifies which blocklist(s) contain the matching domain. The `blocked_by` field is included in `QueryLogEntry` (visible in the `/api/v1/query-log` API response and admin UI). The `blocklist_hits_total` Prometheus metric now uses a `list` label for per-list hit tracking.
- **Upstream resolver identity in error logs**: the `DnsUpstreamStage` now includes an `upstream=` field in DNSSEC NSEC/NODATA and SERVFAIL log messages, identifying which resolver produced the error. Errors from instrumented resolvers also carry the specific resolver label (e.g. `[dns://1.1.1.1:53]`) so that strategy groups (failover/round-robin) show exactly which sub-resolver failed.
- **`UpstreamResolver::label()` trait method**: all resolver implementations now expose a human-readable label via the `label()` method (e.g. `dns://1.1.1.1:53`, `dot://dns.google`, `doh://dns.google/dns-query`, `doq://dns.adguard.com`, `recursive`, `zone:example.com`, `strategy:failover[3]`).
- **Embedded Tailwind admin UI**: added a browser-facing administration dashboard at `/` and `/admin` that uses the existing authenticated API, stores the bearer token in session storage, and exposes runtime status, filtering controls, query log, and quick-action buttons.
- **Alpine-based container support**: added an Alpine Dockerfile and a container-specific `docker/config.yaml` so the admin UI and HTTP API are available by default in Docker builds.

### Fixed
- **Config schema robustness**: Added `#[serde(default)]` to `allowed_hosts` in `McpConfig` to ensure it is always present and defaults to `None` if not set. This prevents deserialization errors and makes config handling more robust.
- **Disabled listeners can omit listener-specific config**: `listen.dns`, `listen.admin`, `listen.metrics`, and TLS listeners now accept `enabled: false` without requiring `port`, `addresses`, or TLS settings. Enabled listeners still keep the strict validation path.
 - **Preserve `CAP_NET_ADMIN` during privilege drop**: the daemon now retains `CAP_NET_ADMIN` in addition to `CAP_NET_BIND_SERVICE` when dropping privileges so Linux `SO_MARK` (`outbound.fwmark`) can be applied when the init system grants it.
- **Admin UI health badge showed "degraded" when healthy**: the admin dashboard compared the health status against `"ok"` but the backend returns `"healthy"`, causing the badge to always show "degraded". Fixed the comparison to match the actual status string.

### Changed
- **Admin UI moved to dedicated listener**: the `/` and `/admin` routes are no longer served by the API server. They are now served by the new `listen.admin` listener with its own port configuration. The admin HTML template uses a server-injected API base URL instead of `window.location.origin`.
- **`listen.http` renamed to `listen.admin`**: the dead `listen.http` config field has been replaced with the fully-wired `listen.admin` config that supports dual-port HTTP/HTTPS, TLS certificate auto-generation, and separate port configuration.
- **RoundRobin and Random strategies now fail over on error**: when the initially selected upstream resolver fails (e.g. timeout), the remaining resolvers are tried in rotation order before returning SERVFAIL. Previously a single resolver failure caused an immediate SERVFAIL even when other healthy resolvers were available.
- **Config example documents cache max_entries**: The example config (`package/config/config.example.yaml`) now documents and sets `max_entries` in the `resolvers.cache` section, making the default cache size limit explicit and user-visible.
- **CLI start/stop behavior**: `dns-filter start` now always starts the daemon in the foreground, and `dns-filter stop` always contacts the control socket instead of delegating to systemd/OpenRC.

All notable changes to this project will be documented in this file.


## [3.0.0] - 2026-05-21

### Fixed
- **DNS resolution stalls from unbounded response cache**: the in-memory resolver cache (`CachedUpstreamResolver`) had no size limit and removed expired entries via a separate write-lock acquisition. Under sustained load this caused unbounded memory growth and RwLock contention that could stall all DNS queries. Added a configurable `max_entries` cap (default 10,000) with automatic eviction of expired and soonest-to-expire entries when the limit is reached, and eliminated the unnecessary write-lock on expired-entry removal.

### Added
- **Opt-out DNS response cache settings**: added global `resolvers.cache` configuration plumbing with database-backed persistence for `enabled`, `min_ttl`, and `max_ttl`. DNS response caching is on by default and can be disabled explicitly with `resolvers.cache.enabled: false`.
- **Runtime resolver-config management (API + MCP)**: added DB-backed global resolver configuration endpoints/tools to read and update `strategy`, `bootstrap_resolvers`, and DNS cache settings (`dns_cache_enabled`, `dns_cache_min_ttl`, `dns_cache_max_ttl`) with validation and reload-on-change behavior.
- **Outbound and zone-forwarded DoQ support**: added a DNS-over-QUIC upstream client with hostname parsing, bootstrap A/AAAA resolution, QUIC/TLS connection reuse, and outbound routing support including source-IP binding and Linux `SO_MARK` for fwmark-based policy routing. Global upstream resolvers and zone-forwarding servers now accept `protocol: doq`.
- **Prometheus metrics listener and instrumentation**: implemented `listen.metrics` as a dedicated HTTP listener exposing `/metrics` in Prometheus text format. Added counters and histogram for DNS query outcomes (blocked/allowed/passthrough), blocklist hits, filter-document cache restore hits/misses, upstream request latency, and upstream errors.

### Changed
- **Config example now reflects strict struct defaults**: `package/config/config.example.yaml` rewritten to only contain active values matching runtime/struct defaults. All `Option<T>` sections (`filtering`, `security`, `api`, `control`, `database`, `outbound`, non-DNS listeners) are now commented out with their effective defaults documented. Active values: `listen.dns` (port 53), `resolvers` (round_robin, cache enabled, recursive server), `logging.stdout` (info), and empty lists for `blocklists`, `allowlists`, `zones`, `zone_discovery`, `plugins`.
- **Dependency pruning**: removed unused direct dependencies `chrono`, `opentelemetry`, and `opentelemetry-prometheus` from Cargo manifest to reduce build graph size and maintenance surface.
- **Metrics test determinism hardening**: stabilized `snapshot_matches_prometheus_output` by making Prometheus metric lookup label-order-agnostic and asserting snapshot/exposition deltas instead of absolute values, avoiding flaky failures from shared global metric state across tests.
- **Init scripts now preserve TLS trust roots inside chroot**: packaged systemd and OpenRC service definitions now project host CA trust roots into the chroot jail at `/etc/ssl`, preventing upstream DoH/DoT/DoQ certificate validation failures (`UnknownIssuer`) after privilege drop/chroot.
- **Systemd capability set includes `CAP_NET_ADMIN` for fwmark routing**: the packaged systemd unit now retains `CAP_NET_ADMIN` in ambient and bounding sets so Linux `SO_MARK` (`outbound.fwmark`) can be applied without repeated `PermissionDenied` upstream failures.
- **MCP presentation-enabled tool variants**: added additive MCP tools `get_stats_presented` and `list_upstreams_presented`, plus optional `include_presentation` support on `search_zone_records`, to return a structured envelope with canonical `data` and a human-readable markdown `display` layout. Existing MCP tools keep their previous raw JSON responses for backward compatibility.
- **Unified in-memory metrics source for Prometheus and API stats**: `/metrics` and `/api/v1/stats` now read from the same Prometheus-backed in-memory primitives, ensuring equal totals and per-upstream aggregates (requests, errors, latency count/sum) across both outputs.

## [2.5.1] - 2026-05-20
- **DNSSEC NSEC/NODATA fallback handling in request pipeline**: when an upstream resolver surfaces DNSSEC NSEC-based proof-of-nonexistence as a protocol error string (for example from recursive resolution of signed CNAME chains with no requested RRset), the DNS pipeline now returns a `NOERROR` empty-answer response instead of `SERVFAIL`. This reduces false SERVFAIL responses for valid NODATA outcomes.
- **Listener batch test no longer probes dead `listen.http` wiring**: removed the temporary `listen.http` section and its `127.0.0.1:18080` reachability check from `tests/listener_batch_test.sh`. The code serves the Axum HTTP API from `api.port`, not `listen.http.port`, so the old strict-mode failure was a test bug rather than a product bug.
- **Per-upstream Prometheus latency/error metrics**: upstream resolver timing and error counters are now labeled by configured upstream target (`upstream="<protocol>://<address>"`) instead of a single global aggregate, enabling per-upstream SLO dashboards and alerting.
- **Init-system wiring for `start`/`stop`**: `dns-filter start` and `dns-filter stop` now delegate to systemd (`systemctl`) or OpenRC (`rc-service`) when run with default settings, so service-managed installs use the init system by default. Added `--direct` to both commands to force direct daemon/control-socket behavior. Packaged systemd/OpenRC service definitions now use `--direct` internally to avoid recursion.
- **Direct control-socket status only**: `dns-filter status` now always queries daemon runtime statistics via the control socket and no longer delegates to systemd/OpenRC. Removed `--direct` from the `status` subcommand.
- **OpenRC `status()` function**: added a `status()` hook to `dns-filter.openrc` so `rc-service dns-filter status` calls `dns-filter status` directly via the control socket.
- **Control socket CLI enhancements**: added `dns-filter status` to query daemon runtime statistics via the control socket, and added `--socket <path>` override support to `dns-filter stop`, `dns-filter reload`, and `dns-filter status`. When `--socket` is not provided, these commands now consistently default to the socket path resolved from the selected config file (`control.socket_path`) with existing chroot-aware path handling.
- **Chroot-scoped runtime paths for DB/TLS/control socket**: startup now validates that SQLite database file paths, enabled listener TLS `cert_path`/`key_path`, and `control.socket_path` resolve inside `security.chroot_dir`; startup fails fast if any path escapes chroot. Relative paths are supported and resolved from chroot root.
- **Database initialization moved after chroot**: SQLite is now opened after privilege drop/chroot, preventing post-chroot pool connections from targeting host filesystem paths.
- **Control socket default moved to chroot context**: default `control.socket_path` changed from `/run/dns-filter/dns-filter.sock` to `run/dns-filter.sock` (resolved within chroot).
- **Protocol-aware upstream address validation for DoH**: upstream CRUD mutations now reject `protocol: doh` addresses that are missing a URL scheme or do not use `https://`. This prevents invalid DoH endpoints from being persisted and later failing during restart/reload.
- **MCP `fwmark` clear sentinel compatibility**: the MCP `update_upstream` tool now accepts string `"None"` (case-insensitive) for `fwmark` in addition to JSON `null`, allowing clients that cannot emit null literals to clear the stored mark.
- **DoQ listener test wording**: removed stale "currently expected until listener startup is wired" language from the listener batch test script now that DoQ listener startup is wired and outbound DoQ is implemented.

## [2.5.1] - 2026-05-20

### Changed
- **Clear `bind_address` / `fwmark` on upstream servers via API and MCP**: PATCHing an upstream server with `{"bind_address": null}` or `{"fwmark": null}` (HTTP API) — or passing `null` to the equivalent fields of the MCP `update_upstream` tool — now clears the stored value. Omitting the field continues to leave the existing value unchanged. Previously there was no way to remove these once set without editing the database directly.

## [2.5.0] - 2026-05-20

### Added
- **Upstream server management via HTTP API and MCP**: added list/add/update/delete operations for DB-backed upstream resolver servers. Both surfaces now expose the full per-server routing fields `bind_address` and `fwmark`, along with protocol, address, authentication, recursive resolver settings, DNSSEC, and sort order. Mutations trigger a config reload so changes take effect without YAML edits.
- **Outbound routing for upstream DNS connections**: per-server `bind_address` and `fwmark` (Linux `SO_MARK`) support for policy-based routing of upstream queries through specific network interfaces (e.g. WireGuard). Includes global defaults via a new `outbound` config section, with per-server overrides. Requires `CAP_NET_ADMIN` for fwmark usage.
- **`RoutedRuntimeProvider`**: custom hickory-net `RuntimeProvider` that applies bind address and fwmark to UDP and TCP sockets used for upstream resolution.
- **Database migration 003**: adds `bind_address` and `fwmark` columns to `upstream_servers` table (SQLite, MySQL, PostgreSQL).

## [2.4.1] - 2026-05-20

### Fixed
- **OpenRC service fails to start (exit 32)**: the init script lacked a `directory` directive, so `start-stop-daemon` launched the daemon with CWD `/` where migration files could not be found. Added `directory="/var/lib/dns-filter"` to match systemd's `WorkingDirectory`. Also added `output_log`/`error_log` so startup errors are no longer silently lost.
- **Migrations not found when started by init system**: migration SQL files were loaded from the filesystem relative to CWD, which broke when OpenRC or systemd launched the binary from `/`. Migrations are now embedded in the binary at compile time via `sqlx::migrate!()`, eliminating runtime filesystem dependency. Removed the `install-migrations` Makefile target as it is no longer needed.
- **MCP/API CRUD operations fail with opaque "internal error"**: database errors during CRUD mutations (insert, update, delete) were reported as just the outermost context message (e.g. "failed to insert filter list") because `anyhow::Error.to_string()` discards the root cause chain. Switched to `format!("{e:#}")` so the full error chain (including the underlying SQLite/database error) is now visible in error responses.
- **SQLite concurrent access errors (SQLITE_BUSY)**: the connection pool was created without explicit WAL journal mode, causing write operations to fail when concurrent reads (e.g. from a config reload) held shared locks. The pool now explicitly sets `journal_mode=WAL` and `busy_timeout=5s`, allowing concurrent readers and writers without lock contention.
- **Config reload fails after chroot, breaking CRUD-triggered blocklist updates**: `reload_config_from_db` re-read the YAML config file from disk on every reload, but after the daemon chroots to `/var/lib/dns-filter/` the original path (`/etc/dns-filter/config.yaml`) is inaccessible, causing every reload to silently fail. Blocklists, allowlists, zones, and other changes made via MCP or the HTTP API were written to the database but never took effect because the pipeline was never rebuilt. The YAML content is now cached in memory before chroot and reused on reload, eliminating the filesystem dependency.

### Changed
- **Normalized list columns in database schema**: replaced JSON-encoded TEXT columns (`resolver_config.bootstrap_resolvers` and `zone_discovery.allowed_types`) with proper relational tables (`bootstrap_resolvers` and `zone_discovery_allowed_types`). Existing JSON data is automatically migrated. This eliminates JSON serialization/deserialization in application code and makes the schema consistent with how other collections (upstream servers, zone servers) are stored.

## [2.4.0] - 2026-05-19

### Added
- **OpenAPI documentation**: auto-generated OpenAPI 3.1 spec served at `GET /api/v1/openapi.json`, derived from endpoint annotations using `utoipa`. The endpoint is gated behind bearer token authentication when `api_token` is configured (same auth as all other `/api/v1` routes).
- **CRUD management API**: full create/read/update/delete endpoints for blocklists, allowlists, zones, and zone discovery via both HTTP API and MCP.
  - **HTTP API endpoints** (all under `/api/v1/`, authenticated with bearer token):
    - `GET/POST /api/v1/blocklists`, `PUT/DELETE /api/v1/blocklists/{name}`
    - `GET/POST /api/v1/allowlists`, `PUT/DELETE /api/v1/allowlists/{name}`
    - `GET/POST /api/v1/zones`, `PUT/DELETE /api/v1/zones/{zone}`
    - `GET/POST /api/v1/zone-discovery`, `PUT/DELETE /api/v1/zone-discovery/{id}`
  - **MCP tools**: `add_blocklist`, `update_blocklist`, `delete_blocklist`, `list_blocklists`, `add_allowlist`, `update_allowlist`, `delete_allowlist`, `list_allowlists`, `add_zone`, `update_zone`, `delete_zone`, `list_zone_configs`, `add_zone_discovery`, `update_zone_discovery`, `delete_zone_discovery`, `list_zone_discovery`.
  - All mutations write to the database and automatically trigger a config reload so changes take effect immediately.
  - Input validation for list names, URLs, list types, zone FQDNs, protocols, and allowed discovery types.
  - Optional authentication details (token, username, password) supported on zone servers and zone discovery endpoints.
- **`InvalidInput` error variant**: new `ServerOperationError::InvalidInput` mapped to HTTP 400 Bad Request for validation failures.
- **Extended repository traits**: added `get_by_zone`, `update_zone`, `delete_zone`, `delete_zone_servers` to `ZoneRepository`; added `get_by_id`, `update`, `delete` to `ZoneDiscoveryRepository`.
- **API CRUD integration tests**: comprehensive `listener_batch_test.sh` coverage for all CRUD endpoints including blocklists, allowlists, zones, zone discovery, authentication enforcement, duplicate-name rejection, not-found handling, and input validation (invalid names, URLs, list types).

### Fixed
- **Blocking reqwest panic during async reload**: wrapped `build_zone_entries` in `tokio::task::spawn_blocking` inside the DB-backed reload path to prevent the `reqwest::blocking::Client` from panicking when dropped inside an async context. This crash was triggered when zone discovery entries existed in the database.

### Changed
- **`ServerOperations` extended with repository access**: accepts an optional `Arc<Repositories>` via `.with_repositories()` builder method, enabling CRUD operations from any management interface (HTTP API, MCP, control socket).
- **Repository record types now `Serialize`**: `FilterListRecord`, `ZoneRecord`, `ZoneServerRecord`, `ZoneDiscoveryRecord` derive `Serialize` for direct JSON responses.
- **Optional blocklists/allowlists config**: `blocklists` and `allowlists` fields are now optional in the YAML config, defaulting to empty arrays when omitted.

## [2.3.0] - 2026-05-19

### Added
- **Database-backed operational config**: migrated blocklists, allowlists, filtering settings, upstream resolvers, zones, and zone discovery from static YAML to a database-backed configuration store using sqlx. Supports SQLite (default), MySQL, and PostgreSQL via compile-time feature flags (`db-sqlite`, `db-mysql`, `db-postgres`).
- **Repository pattern**: async repository traits in `use_cases/repositories.rs` with sqlx implementations in `frameworks/database/` for all operational config (filter lists, filter cache, filtering config, upstream config, zones, zone discovery).
- **Database migrations**: SQL migration files for all three backends under `migrations/sqlite/`, `migrations/mysql/`, and `migrations/postgres/`.
- **YAML-to-DB seed**: on first start with an empty database, operational config from the YAML file is automatically imported so the DB becomes the authoritative source (`use_cases/seed.rs`).
- **DB-to-config bridge**: `apply_db_config()` loads operational config from DB repositories and overwrites the corresponding fields of the in-memory config, keeping infrastructure settings (listen, logging, security) in YAML (`use_cases/config_from_db.rs`).
- **Database config section**: new `database:` section in YAML config with `url` field (defaults to `sqlite:///var/lib/dns-filter/dns-filter.db`).
- **DB-aware config reload**: SIGHUP reload now loads infrastructure from YAML and operational config from the database via `reload_config_from_db()`.

### Fixed
- **Suppress noisy hickory-server query logs at info level**: added `hickory_server=error` to the tracing `EnvFilter`, preventing per-query log lines (e.g. `query:example.com.:AAAA:IN`) from flooding syslog when running at info level.

### Changed
- **Filter cache backend**: replaced rusqlite-based document cache with the `FilterCacheRepository` trait, using the same sqlx database pool as other operational config.
- **Removed rusqlite dependency**: all SQLite operations now go through sqlx; the `rusqlite` crate is no longer a dependency.

- **Multi-format blocklist/allowlist support**: added `list_type` configuration option per blocklist/allowlist entry. Supported formats:
  - `adguard` (default) — AdGuard/ABP filter syntax with cosmetic rule filtering, modifier validation, and `@@` exception support. Also accepts hosts-file and plain-domain lines as fallback.
  - `hosts` — hosts file format (`<IP> domain1 [domain2 …]`), including compressed multi-hostname lines with multiple domains per line.
  - `rpz` — Response Policy Zone format (`domain CNAME .` for block, `CNAME rpz-passthru.` for allow). Handles wildcard owners, TTL/CLASS fields, and A/AAAA walled-garden records.
  - `domains` — flat domain list with one domain or subdomain per line.
  - `wildcard` — wildcard domain list (`*.example.com` per line); strips `*.` prefix and normalises to base domain.

### Changed
- **Refactored filtering module**: restructured `src/use_cases/filtering.rs` into a module directory (`src/use_cases/filtering/`) with dedicated parser files per format (`adguard.rs`, `hosts.rs`, `rpz.rs`, `domains.rs`, `wildcard.rs`) and shared utilities (`common.rs`).

## [2.2.1] - 2026-05-19

### Added
- **Feature-gated listeners**: all non-DNS listeners are now behind Cargo feature flags (`dot`, `doh`, `doq`, `http-api`, `mcp`). All features are enabled by default preserving current behavior. Building with `--no-default-features` produces a DNS-only binary. Dependencies like `axum`, `rmcp`, `schemars`, `rcgen`, and `hostname` are now optional and only compiled when their associated features are enabled.
- **MCP (Model Context Protocol) server**: built-in MCP server listener using the `rmcp` crate with Streamable HTTP transport. Exposes DNS filter management tools to AI/LLM clients: `dns_lookup`, `filter_status`, `filter_toggle`, `list_filters`, `refresh_lists`, `enable_list`, `disable_list`, `get_stats`, `get_query_log`, `reload_config`, and `server_health`. Configurable via `mcp:` config section with port (default 8953), bearer token auth, SSE keep-alive, stateful/stateless mode, CORS origins, and DNS rebinding protection (`allowed_hosts`). Endpoint fixed at `/mcp`.
- **Shared authentication middleware**: extracted bearer token validation into a reusable `auth` module (`interface_adapters::listeners::auth`) with constant-time comparison, shared by both the HTTP API and MCP servers.
- **MCP zone search tools**: new `list_zones` and `search_zone_records` MCP tools for browsing and fuzzy-searching DNS records across authoritative JSON zones. `search_zone_records` supports filtering by zone name, record type, and configurable result limits (default 50, max 500). Uses `fuzzy-matcher` crate for fuzzy domain name matching with relevance scoring.
- **Shared server operations layer**: extracted all MCP and HTTP API business logic into a shared `ServerOperations` use-case (`use_cases::server_operations`), eliminating duplicated logic between the two interfaces. Both MCP tools and HTTP API handlers are now thin wrappers that delegate to `ServerOperations`.
- **Zone registry**: new `ZoneRegistry` use-case (`use_cases::zone_registry`) that aggregates all searchable zones and provides cross-zone record listing and fuzzy search capabilities.
- **Zone searchable trait**: `ZoneSearchable` trait on `ZoneAuthorityResolver` enabling record introspection and fuzzy search without exposing internal zone data structures.

### Changed
- **Migrated HTTP API from hyper 0.14 to axum**: replaced raw hyper service with axum `Router`, typed extractors (`State`, `Path`, `Json`), and `axum::serve()` with graceful shutdown. All API endpoints and behavior remain unchanged.

## [2.2.2] - 2026-05-19

### Changed
- **Moved error-to-SERVFAIL policy from adapter to use-case layer**: `DnsUpstreamStage` and `ZoneForwardingStage` now return SERVFAIL responses directly on failure instead of propagating errors. This removes the business policy decision from `HickoryRequestHandler` (interface adapter) and keeps it in the use-case pipeline where it belongs per Clean Architecture.

## [2.2.0] - 2026-05-18

### Added
- **DNS-over-TLS (DoT) inbound listener**: DNS-over-TLS server (RFC 7858) accepting queries on TCP port 853 (configurable) with mandatory TLS. Uses RFC 7766 length-prefix framing over TLS — no HTTP layer. Enabled via `listen.dot` with TLS certificate/key configuration and optional auto-generation. Supports multiple bind addresses, privilege separation (bind as root, serve as unprivileged), and the shared request pipeline.
- **Zone discovery**: new `resolvers.zone_discovery` config section that fetches a JSON index endpoint returning `{"zones": [...]}`, filters zones by allowed types (`reverse`, `forward`, `reverse-aggregate`), resolves each zone's `href` relative to the index URL, and loads zone records as authoritative JSON zones. Supports periodic refresh of both index and zone data, Bearer/Basic authentication (reused for all href fetches), and manual zone priority (zones defined in `resolvers.zones` override discovered ones with the same name).
- **DNS-over-QUIC (DoQ) inbound listener**: DNS-over-QUIC server (RFC 9250) accepting queries on UDP (configurable port). Enabled via `listen.doq` with TLS certificate/key configuration and optional auto-generation.
- **Unified hickory-server request handling**: all DNS protocol listeners (UDP, TCP, DoT, DoH, DoQ) now use a single `hickory-server::Server` instance with a shared `HickoryRequestHandler`, replacing per-protocol accept loops and manual framing.

### Changed
- **Replaced manual protocol implementations with hickory-server**: DNS UDP/TCP, DoT, DoH, and DoQ listeners are now registered on a single `hickory-server::Server` instead of using custom accept loops, RFC 7766 framing, and hyper HTTP service handling.
- **Removed DoH authentication**: the `auth_token` field has been removed from `TlsSocketConfig` and DoH configuration. DoH authentication should be handled by a reverse proxy.

### Removed
- **`auth_token` config option**: removed from DoH listener configuration (`listen.doh.auth_token`) and `TlsSocketConfig` schema. Use a reverse proxy for authentication.
- **Manual protocol implementations**: removed custom UDP/TCP accept loops, RFC 7766 framing, hyper HTTP service, TLS accept handling, and `forward_query` functions from `dns.rs`, `doh.rs`, and `dot.rs`. Replaced by hickory-server.
- **`futures` dependency**: no longer needed after removing manual listener implementations.

## [2.0.8] - 2026-05-13

### Fixed
- **Zone authority JSON format documentation**: corrected the README example and reference table to match the actual parser format — `records` is a flat array of objects with `type` and structured `data` fields, not a map grouped by record type with plain `value` strings.

### Changed
- **Shared TLS certificate utilities**: extracted `autogenerate_tls_cert_if_missing()` and `build_tls_server_config()` from the DoH listener into a shared `interface_adapters::listeners::tls` module, ready for reuse by DoT and DoQ listeners.
- **Enhanced auto-generated certificate SANs**: self-signed certificates now include the system hostname, all non-loopback network interface IP addresses, and any configured bind addresses as Subject Alternative Names (in addition to `localhost`, `127.0.0.1`, `::1`). Wildcard/unspecified addresses (`0.0.0.0`, `::`) are filtered out.
- **Certificate issuer**: auto-generated certificates now use `CN=dns-filter self-signed cert` instead of the default `CN=rcgen self signed cert`.

### Dependencies
- Added `hostname` crate for system hostname discovery in TLS SAN generation.
- Added `"net"` feature to existing `nix` dependency for network interface enumeration via `getifaddrs()`.

## [2.0.7] - 2026-05-13

### Fixed
- **Dual-stack socket binding conflict**: on Linux, binding `["0.0.0.0", "::"]` would fail with `EADDRINUSE` because the IPv6 socket defaulted to dual-stack mode (`IPV6_V6ONLY=0`), capturing both IPv4 and IPv6 traffic. All listener sockets (DNS, DoH, HTTP API) now explicitly set `IPV6_V6ONLY=1` on IPv6 sockets via `socket2`, so IPv4 and IPv6 bind independently.

### Added
- **DoH inbound listener**: DNS-over-HTTPS server (RFC 8484) accepting queries on `/dns-query` over HTTPS. Supports POST (`application/dns-message` body) and GET (`?dns=<base64url>`) methods. Accepts both HTTP/1.1 and HTTP/2. Enabled via `listen.doh` with TLS certificate/key configuration.
- Optional `auth_token` on `listen.doh` (and `TlsSocketConfig` generally): when set, inbound DoH requests must include a `Authorization: Bearer <token>` header. Constant-time token comparison prevents timing side-channel attacks.
- `protocol: "doh"` support in the generic upstream resolver path (`resolvers.upstream.servers[]`), including bootstrap-aware hostname resolution behavior consistent with DoT.
- Optional `authentication` on global upstream `protocol: "doh"` servers (Bearer token or HTTP Basic).

### Changed
- Migrated DoH upstream transport from `reqwest` flow to hickory-native HTTP/2 transport using `hickory_net::h2::HttpsClientStream`.
- DoH upstream now uses connection caching/reuse for the H2 stream and reconnect-on-failure behavior.
- Enabled Hickory HTTPS feature flags required for native DoH transport (`https-ring`).

### Dependencies
- Added direct `http` dependency for typed HTTP header construction used by DoH auth injection.
- Added direct `base64` dependency for Basic authentication header encoding.

## [2.0.6] - 2026-05-13

### Breaking
- **Zone configuration schema redesigned**: the per-zone `zone_source`, `zone_source_check_interval`, and `source_auth` fields have been removed. Zone authority mode is now expressed as `protocol: "json"` inside the same `servers[]` list used for forwarding.
- Zone `servers[]` entries now use `ZoneServerConfig` (separate from the global `UpstreamServer` type). Existing zone configs using the old fields must be migrated.

### Added
- `protocol: "json"` zone server: authoritative JSON zone source as a `servers[]` entry. `address` accepts `file:///…`, `http://…`, and `https://…` URIs.
- `check_interval` on `protocol: "json"` server entries (URL sources only): enables periodic background refresh of the zone snapshot.
- `authentication` on `protocol: "json"` and `protocol: "doh"` zone server entries: supports Bearer token (`token`) or HTTP Basic (`username` + `password`), mutually exclusive (same XOR semantics as removed `source_auth`).
- `protocol: "doh"` zone server: DNS-over-HTTPS upstream for zone forwarding (RFC 8484 POST). Supports `authentication`.
- New `DnsHttpsClient` upstream resolver (`src/frameworks/upstream/doh_client.rs`).
- `file://` URI prefix now accepted in `protocol: "json"` `address` values.

### Changed
- All zone examples in `config.example.yaml` and `README.md` now use `enabled: false` by default.
- Error hint for `resolvers.zones` config parse failures updated.
- `parse_zone_source` now accepts `file://` URIs explicitly.

## [2.0.5] - 2026-05-12

### Added
- Optional `source_auth` for HTTP(S) zone sources: supports Bearer token or Basic (username + password) authentication, enforced as mutually exclusive (one or neither)
- `LICENSE` file (MIT) — previously declared in Cargo.toml but file was missing

## [2.0.4] - 2026-05-12

### Added
- REST API for runtime administration (disabled by default, enable with `api.enabled: true` in config)
  - `GET /health` — unauthenticated health/liveness probe with uptime
  - `POST /api/v1/reload` — trigger configuration reload (same as SIGHUP)
  - `POST /api/v1/filtering/disable` / `POST /api/v1/filtering/enable` — global filtering toggle (in-memory, resets on restart)
  - `GET /api/v1/filtering/status` — current global filtering state
  - `GET /api/v1/lists` — list all configured blocklists/allowlists with status
  - `POST /api/v1/lists/refresh` — refresh all lists
  - `POST /api/v1/lists/{name}/refresh` — refresh a specific list
  - `POST /api/v1/lists/{name}/disable` / `POST /api/v1/lists/{name}/enable` — temporarily disable/enable a specific list (in-memory, resets on restart)
  - `GET /api/v1/stats` — query counters, uptime, per-list stats
  - `GET /api/v1/query-log` — recent query log entries (when query logging enabled)
  - Optional Bearer token authentication for all `/api/*` endpoints (constant-time comparison)
  - Configurable query logging with bounded ring buffer (default 10,000 entries)
  - New `api` section in config schema: `enabled`, `address`, `port`, `api_token`, `query_logging`
- WASM plugin system scaffolding behind `plugins` cargo feature flag: `PluginVerdict`/`PluginQuery` entity types, `WasmPluginStage` pipeline handler stub, `WasmPluginRuntime` framework scaffold, `PluginConfig` config schema, and optional `wasmtime` dependency (not yet functional — draft/placeholder only)
### Changed
- Updated README.md: version badge to 2.0.4, added WASM Plugins section, updated architecture pipeline diagram with Plugin Handler stage, updated Key Features, Layer Responsibilities, Key Files, and footer metadata
## [2.0.3] - 2026-05-12

### Fixed
- Suppressed verbose DNS response dumps from `hickory_net` and `hickory_recursor` crates that leaked into info-level logs; added missing `hickory_net=error` and `hickory_recursor=error` tracing filters in non-debug mode

## [2.0.2] - 2026-05-12

### Fixed
- Fixed recursive resolver responses missing the DNS question section (RFC 1035 §4.1.2): `Recursor::resolve()` returns a `Message` without a question section, which caused `host`/`dig` to warn `;; missing question section`; the original query's question is now copied into the success-path response
- Fixed `merge-config` producing both `address` and `addresses` keys under `listen.*` when the user config uses the legacy singular `address` format: both base and overlay are now normalized to the canonical `addresses` list before merging, so the user's value wins and no stale `address` key appears in the output

### Changed
- Removed `/dev/log` bind-mount from OpenRC init script, config example, and README; the syslog socket is opened before chroot so the file descriptor survives privilege drop

## [2.0.1] - 2026-05-12

### Security
- **Migrated hickory DNS crates from 0.25.2 to 0.26.1** to resolve 3 CVEs:
  - RUSTSEC-2026-0106: cache poisoning via cross-zone NS injection (hickory-recursor)
  - RUSTSEC-2026-0118: NSEC3 closest-encloser proof unbounded loop / OOM (hickory-proto)
  - RUSTSEC-2026-0119: O(n²) name compression CPU exhaustion (hickory-proto)

### Changed
- Replaced `hickory-client` (removed upstream) with `hickory-net` 0.26.1 for DNS client/transport functionality
- Replaced `hickory-recursor` (merged upstream) with `hickory-resolver` 0.26.1 `recursor` feature
- Upgraded `hickory-proto` from 0.25.2 to 0.26.1
- Simplified recursive resolver: `Recursor::resolve()` now returns `Message` directly, removing manual CNAME chain following and `Proof`-based AD bit tracking
- Replaced `Recursor::builder()` pattern with `Recursor::new()` direct construction using `RecursorOptions`
- Replaced `extract_negative_records()` error destructuring with `RecursorError::Negative(AuthorityData)` pattern matching
- Removed 3 hickory CVE ignore entries from `deny.toml`

## [2.0.0] - 2026-05-12

### Breaking
- **CLI restructured to subcommand-based architecture**: `dns-filter` no longer starts the daemon directly; use `dns-filter start [--config <path>] [--debug]` instead. New subcommands: `start`, `stop`, `reload`, `merge-config`
- Updated systemd `ExecStart`, `ExecReload`, `ExecStop` directives to use the new subcommand syntax
- Updated OpenRC `command_args` and `reload()` to use the new subcommand syntax
- Updated `tests/listener_batch_test.sh` to use `dns-filter start` subcommand

### Added
- Added supply-chain security policy via `cargo-deny` — CVE/advisory scanning (RustSec), license compliance, dependency source verification, duplicate crate detection, and banned crate enforcement; enforced as a hard-fail gate in `tests/release-check.sh`
- Committed `Cargo.lock` for reproducible builds and `cargo-deny` compatibility (binary crate)
- Added `license = "MIT"` to `Cargo.toml`
- Removed unused `prometheus` dependency (eliminates transitive `protobuf` v2.28.0 CVE RUSTSEC-2024-0437)
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
