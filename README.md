# dns-filter

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://www.rust-lang.org/) [![License](https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-blue)](#license) [![Version](https://img.shields.io/badge/version-2.2.0-green)](./CHANGELOG.md)

**dns-filter** is a high-performance, security-first DNS filtering service written in Rust. It acts as a sophisticated intermediary DNS server that filters queries against blocklists and allowlists, routes requests to zone-specific resolvers, serves authoritative DNS for local zones, and provides recursive DNS resolution with DNSSEC validation.

## Key Features

- **Multi-Protocol Support**: DNS (UDP/TCP), DoT (DNS over TLS), DoH (DNS over HTTPS), DoQ (DNS over QUIC), and HTTP admin/metrics
- **Advanced Filtering**: Blocklists and allowlists with automatic refresh, configurable sinkhole responses, persistent caching
- **Intelligent Routing**: Zone-based forwarding to route queries by domain suffix to dedicated resolvers
- **Authoritative Zones** *(Experimental)*: Serve authoritative DNS answers from local JSON zone files with optional URL-based refresh
- **Zone Discovery**: Automatically import zones from a JSON index endpoint, filtered by type (forward, reverse, reverse-aggregate)
- **Recursive Resolution**: Full DNS recursion with DNSSEC chain-of-trust validation from IANA root
- **Load-Balancing**: Multiple upstream resolver strategies (round-robin, random, failover)
- **Daemon Management**: Subcommand-based CLI (`start`, `stop`, `reload`, `merge-config`) with Unix domain control socket
- **Graceful Shutdown**: Clean shutdown via `dns-filter stop`, `SIGTERM`/`SIGINT`, or REST API (`POST /api/v1/stop`)
- **Graceful Reload**: SIGHUP, `dns-filter reload`, or REST API-triggered zero-downtime configuration reload
- **Config Merging**: `dns-filter merge-config` deep-merges user config with built-in defaults, filling missing sections automatically
- **Comprehensive Logging**: Syslog (local/remote), file, and stdout with configurable transports (unix, udp, tcp, tls)
- **Security-First**: Privilege dropping, chroot sandboxing, Linux capabilities, hardened systemd unit
- **WASM Plugin System** *(Draft)*: Extensible plugin architecture using sandboxed WebAssembly modules (behind `plugins` cargo feature flag)
- **Observability**: Prometheus-compatible metrics endpoint
- **Production-Ready**: Systemd and OpenRC init system support with hardening best practices

## Supported DNS Protocols

| Protocol | Port | Status | Notes |
|----------|------|--------|-------|
| **DNS** (UDP/TCP) | 53 | ✅ Production | Standard plain DNS protocol |
| **DoT** | 853 | ✅ Production | DNS over TLS with certificate validation |
| **DoH** | 443 | ✅ Production | DNS over HTTPS with certificate validation |
| **DoQ** | 8853 | ✅ Production | DNS over QUIC with certificate validation |
| **HTTP** | 8080 | ✅ Production | Admin API and metrics |

## Quick Start

### 1. Install from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/dns-filter-rust.git
cd dns-filter-rust

# Build release binary
cargo build --release

# Binary will be at target/release/dns-filter
sudo cp target/release/dns-filter /usr/local/bin/
```

### 2. Create Minimal Configuration

```bash
# Create config directory
sudo mkdir -p /etc/dns-filter

# Create a minimal config
sudo tee /etc/dns-filter/config.yaml > /dev/null <<'EOF'
listen:
  dns:
    enabled: true
    addresses: ["0.0.0.0", "::"]
    port: 53

blocklists: []
allowlists: []

filtering:
  sinkhole_ipv4: "0.0.0.0"
  sinkhole_ipv6: "::"

resolvers:
  strategy: "round_robin"
  servers:
    - enabled: true
      protocol: "dns"
      address: "1.1.1.1:53"
    - enabled: true
      protocol: "dns"
      address: "8.8.8.8:53"

logging:
  stdout:
    enabled: true
    level: "info"

security:
  user: "nobody"
  group: "nogroup"
  chroot_dir: "/var/lib/dns-filter"
EOF
```

### 3. Run the Service

```bash
# As root (needed for privilege dropping and port 53 binding)
sudo dns-filter start --config /etc/dns-filter/config.yaml

# In another terminal, test it
dig @127.0.0.1 example.com
```

### Next Steps

- Read the **[Installation](#installation)** section for distro-specific setup and systemd integration
- Configure **[Filtering](#filtering)** with your preferred blocklists
- Set up **[Upstream Resolvers](#upstream-resolvers)** for your preferred DNS providers
- Review **[Security Best Practices](#security-best-practices)** for hardened deployment
- Check **[Troubleshooting](#troubleshooting)** if you encounter issues

---

## Installation

### From Source

**Prerequisites:**
- Rust 1.75 or later
- OpenSSL development headers

**On Ubuntu/Debian:**
```bash
sudo apt-get install -y build-essential libssl-dev

git clone https://github.com/yourusername/dns-filter-rust.git
cd dns-filter-rust
cargo build --release
sudo cp target/release/dns-filter /usr/local/bin/
```

**On Fedora/RHEL:**
```bash
sudo dnf install -y openssl-devel

git clone https://github.com/yourusername/dns-filter-rust.git
cd dns-filter-rust
cargo build --release
sudo cp target/release/dns-filter /usr/local/bin/
```

### Setup Directories and Permissions

```bash
# Create necessary directories
sudo mkdir -p /etc/dns-filter
sudo mkdir -p /var/lib/dns-filter
sudo mkdir -p /var/log/dns-filter

# Create dns-filter user and group (if using privilege dropping)
sudo useradd -r -s /bin/false dns-filter 2>/dev/null || true

# Set permissions (adjust if using different user)
sudo chown -R nobody:nogroup /var/lib/dns-filter
sudo chmod 755 /var/lib/dns-filter

# Copy example config
sudo cp package/config/config.example.yaml /etc/dns-filter/config.yaml
sudo chmod 644 /etc/dns-filter/config.yaml
```

### Using `make install`

`make install` auto-detects the init system (systemd or OpenRC) and installs the binary, config, and service file:

```bash
# Build and install (auto-detects init system)
sudo make install

# Override init system detection
sudo make install INIT_SYSTEM=systemd
sudo make install INIT_SYSTEM=openrc
sudo make install INIT_SYSTEM=none   # skip service file
```

On upgrade installs (when `config.yaml` already exists), the new example config is installed as `config.yaml.dist` and a hint is printed to merge new defaults:

```bash
dns-filter merge-config --overwrite --config /etc/dns-filter/config.yaml
```

### Systemd Integration

```bash
# Copy systemd unit (or use `make install` which does this automatically)
sudo cp package/systemd/dns-filter.service /etc/systemd/system/

# Reload systemd daemon
sudo systemctl daemon-reload

# Enable and start the service
sudo systemctl enable dns-filter
sudo systemctl start dns-filter

# Check status
sudo systemctl status dns-filter

# View logs
sudo journalctl -u dns-filter -f

# Reload configuration
sudo systemctl reload dns-filter   # via SIGHUP
dns-filter reload                  # via control socket

# Stop the daemon
sudo systemctl stop dns-filter     # via systemd
dns-filter stop                    # via control socket
```

### OpenRC Integration

```bash
# Copy init script (or use `make install` which does this automatically)
sudo cp package/openrc/dns-filter.openrc /etc/init.d/dns-filter
sudo chmod +x /etc/init.d/dns-filter

# Register service
sudo rc-update add dns-filter

# Start service
sudo rc-service dns-filter start

# Check status
sudo rc-service dns-filter status

# Reload configuration
sudo rc-service dns-filter reload  # via SIGHUP
dns-filter reload                  # via control socket

# Stop the daemon
sudo rc-service dns-filter stop    # via OpenRC
dns-filter stop                    # via control socket
```

### Verify Installation

```bash
# Check version
dns-filter --version

# Test DNS query (assuming dns-filter is running on 127.0.0.1:53)
dig @127.0.0.1 example.com

# Check response from blocklist (should return sinkhole IP)
dig @127.0.0.1 ads.example.com  # if "ads.example.com" is in a blocklist

# For DoT/DoH, use appropriate tools
# DoT with dig (if support compiled in):
dig +tls @dns-filter.example.com example.com

# DoH with kdig:
kdig +https @dns-filter.example.com -p 443 example.com A

# Check metrics
curl http://127.0.0.1:9100/metrics
```

---

## Configuration

All configuration is provided via a single YAML file (default: `/etc/dns-filter/config.yaml`). The configuration is loaded at startup and can be reloaded at runtime via SIGHUP signal, `dns-filter reload` command, or REST API.

### Configuration Structure

```yaml
listen:          # Protocol listeners and ports
  dns: {...}
  dot: {...}
  doh: {...}
  doq: {...}
  http: {...}
  metrics: {...}

blocklists:      # Downloadable block lists
  - name: {...}

allowlists:      # Downloadable allow lists (exceptions)
  - name: {...}

filtering:       # Filtering behavior and caching
  sinkhole_ipv4: "..."
  sinkhole_ipv6: "..."
  cache: {...}

resolvers:       # Upstream resolvers and zone forwarding
  strategy: "..."
  servers: [...]
  zones: [...]
  zone_discovery: [...]  # Auto-import zones from JSON index endpoints

plugins:         # WASM plugins (requires 'plugins' feature)
  - name: "..."
    path: "..."
    enabled: true

logging:         # Logging configuration
  syslog: {...}
  file: {...}
  stdout: {...}

security:        # Privilege dropping and sandboxing
  user: "..."
  group: "..."
  chroot_dir: "..."

control:         # Daemon control socket
  socket_path: "/run/dns-filter/dns-filter.sock"
```

---

## Filtering

Filtering is the core feature: dns-filter matches DNS queries against configured blocklists and allowlists, returning a sinkhole response for blocked domains.

### Configuration Reference

```yaml
filtering:
  # IPv4 address to return for blocked domains
  sinkhole_ipv4: "0.0.0.0"              # default: "0.0.0.0"
  
  # IPv6 address to return for blocked domains
  sinkhole_ipv6: "::"                   # default: "::"
  
  # How to handle ANY queries
  # Options: "notimp" (RFC 8482), "refused", "passthrough"
  any_query_policy: "notimp"            # default: "notimp"
  
  # Caching configuration
  cache:
    mode: "memory"                      # "memory" (fast, volatile) or "sqlite" (persistent)
    document_path: "/var/lib/dns-filter/cache.db"  # for sqlite mode
```

### Blocklists

Blocklists are downloadable lists of domains to block. Supported formats include AdGuard and uBlock Origin syntax.

```yaml
blocklists:
  # Simple blocklist entry
  - adguard:
      enabled: true
      url: "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt"
      interval: "12h"
  
  # Disabled blocklist (kept in config but not loaded)
  - experimental:
      enabled: false
      url: "https://example.com/experimental.txt"
      interval: "24h"
  
  # Local file blocklist (loaded from disk)
  - custom_local:
      url: "file:///etc/dns-filter/custom-blocklist.txt"
      interval: "0"  # no refresh for local files
```

**Fields:**
- `enabled` (bool, optional): Enable/disable without deleting from config (default: true)
- `url` (string, required): HTTP/HTTPS URL or file:// path to list
- `interval` (string, optional): Refresh interval in duration format: "12h", "30m", "1d", etc. (default: "12h")

**Supported Blocklist Formats:**
- AdGuard filter syntax (domain list)
- uBlock Origin syntax (domain list with cosmetic rules skipped)
- Plain text domain list (one domain per line)

### Allowlists

Allowlists (whitelists) define exceptions: domains in allowlists bypass filtering even if matched by a blocklist.

```yaml
allowlists:
  - safe_domains:
      url: "https://example.com/safe-domains.txt"
      interval: "24h"
  
  # Local allowlist
  - internal_services:
      url: "file:///etc/dns-filter/internal-domains.txt"
```

**Priority:** Allowlists take precedence over blocklists.

### Cache Modes

**Memory Cache (Default):**
```yaml
filtering:
  cache:
    mode: "memory"  # Fast, in-process, lost on restart
```
- Fastest option
- Useful for filtering and blocklist lookups
- Lost on service restart

**SQLite Cache:**
```yaml
filtering:
  cache:
    mode: "sqlite"
    document_path: "/var/lib/dns-filter/cache.db"
```
- Persistent across restarts
- Slightly slower than memory
- Useful for large blocklists (warm-start after restart)
- SSD recommended for best performance

### Examples

**Simple Blocking with AdGuard List:**
```yaml
blocklists:
  - adguard_base:
      url: "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt"
      interval: "12h"
  - adguard_mobile:
      url: "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt"
      interval: "12h"

allowlists:
  - whitelist:
      url: "https://example.com/whitelist.txt"
      interval: "24h"

filtering:
  sinkhole_ipv4: "0.0.0.0"
  sinkhole_ipv6: "::"
  cache:
    mode: "memory"
```

**Custom Blocking with Persistent Cache:**
```yaml
blocklists:
  - custom_ads:
      url: "file:///etc/dns-filter/ads.txt"
  - custom_malware:
      url: "file:///etc/dns-filter/malware.txt"

filtering:
  sinkhole_ipv4: "127.0.0.1"  # Common choice for localhost testing
  sinkhole_ipv6: "::1"
  any_query_policy: "refused"
  cache:
    mode: "sqlite"
    document_path: "/var/lib/dns-filter/cache.db"
```

**Minimal Filtering (No Blocklists):**
```yaml
blocklists: []
allowlists: []

filtering:
  sinkhole_ipv4: "0.0.0.0"
  sinkhole_ipv6: "::"
  cache:
    mode: "memory"
```

---

## Upstream Resolvers

Upstream resolvers are the DNS servers that handle queries that aren't satisfied by filtering or zone forwarding. dns-filter supports multiple upstream server strategies, multiple protocols (DNS, DoT, DoH, DoQ), and full recursive DNS resolution with DNSSEC validation.

### Configuration Reference

```yaml
resolvers:
  # Load-balancing strategy for upstream servers
  strategy: "round_robin"     # "round_robin", "random", "failover"
  
  # Optional: resolvers for resolving upstream hostnames (bootstrap)
  bootstrap_resolvers:
    - "1.1.1.1"               # default: ["1.1.1.1"]
  
  # List of upstream DNS servers
  servers:
    - enabled: true
      protocol: "dns"         # "dns", "dot", "doh", "doq", "recursive"
      address: "1.1.1.1:53"
      # ... protocol-specific options ...
  
  # Zone-specific forwarding (see Zone Forwarding section)
  zones: []
```

### Upstream Server Protocols

#### DNS (Plain DNS)

Standard DNS over UDP/TCP. Fastest but unencrypted.

```yaml
servers:
  - enabled: true
    protocol: "dns"
    address: "1.1.1.1:53"       # host:port format
```

#### DoT (DNS over TLS)

DNS queries encrypted over TLS. Requires certificate validation.

```yaml
servers:
  - enabled: true
    protocol: "dot"
    address: "dns.google:853"   # host:port format
    tls:
      # Optional: path to CA certificate for verification
      cert_path: "/etc/ssl/certs/ca-bundle.crt"
      # Optional: auto-generate certificate if missing (for testing only)
      autogenerate: false
```

#### DoH (DNS over HTTPS)

DNS queries over HTTPS with full TLS protection and certificate validation.

```yaml
servers:
  - enabled: true
    protocol: "doh"
    address: "https://cloudflare-dns.com/dns-query"  # full HTTPS URL
    tls:
      cert_path: "/etc/ssl/certs/ca-bundle.crt"
```

#### DoQ (DNS over QUIC)

DNS queries over QUIC protocol. Modern, low-latency encrypted transport.

```yaml
servers:
  - enabled: true
    protocol: "doq"
    address: "dns.adguard.com:8853"
    tls:
      cert_path: "/etc/ssl/certs/ca-bundle.crt"
```

#### Recursive Resolver

Full DNS recursion with DNSSEC validation from IANA root. Does not query upstream servers; instead, performs iterative resolution starting from the root nameservers.

```yaml
servers:
  - enabled: true
    protocol: "recursive"
    # No address needed; uses root hints from /usr/share/dns/root.hints
    
    # Optional: enable DNSSEC validation (default: true)
    dnssec: true
    
    # Optional: path to root.hints file (auto-detected if not provided)
    root_hints_path: "/usr/share/dns/root.hints"
    
    # Optional: path to DNSSEC root key (auto-detected if not provided)
    root_key_path: "/etc/dns/root.key"
    
    # Optional: filter nameservers by IP family
    # "ipv4" (IPv4-only), "ipv6" (IPv6-only), or omit for both
    nameserver_ip_family: "ipv4"
    
    # Optional: max referral hops (default: 12)
    max_hops: 12
```

### Load-Balancing Strategies

**Round-Robin** (Default)
```yaml
resolvers:
  strategy: "round_robin"
  servers:
    - enabled: true
      protocol: "dns"
      address: "1.1.1.1:53"
    - enabled: true
      protocol: "dns"
      address: "8.8.8.8:53"
```
Cycles through servers in order. Distributes load evenly across all enabled servers.

**Random**
```yaml
resolvers:
  strategy: "random"
  servers:
    - enabled: true
      protocol: "dns"
      address: "1.1.1.1:53"
    - enabled: true
      protocol: "dns"
      address: "8.8.8.8:53"
```
Randomly selects a server for each query. Provides load distribution with less predictability.

**Failover**
```yaml
resolvers:
  strategy: "failover"
  servers:
    - enabled: true
      protocol: "dns"
      address: "1.1.1.1:53"      # Primary
    - enabled: true
      protocol: "dns"
      address: "8.8.8.8:53"      # Fallback
    - enabled: true
      protocol: "dns"
      address: "9.9.9.9:53"      # Fallback
```
Uses the first available server. Falls back to the next only if the current server fails. Useful for ensuring one primary DNS provider.

### Examples

**Simple DNS Upstream:**
```yaml
resolvers:
  strategy: "round_robin"
  servers:
    - enabled: true
      protocol: "dns"
      address: "1.1.1.1:53"
    - enabled: true
      protocol: "dns"
      address: "8.8.8.8:53"
```

**DoT + DoH with TLS Verification:**
```yaml
resolvers:
  strategy: "round_robin"
  servers:
    - enabled: true
      protocol: "dot"
      address: "dns.google:853"
      tls:
        cert_path: "/etc/ssl/certs/ca-bundle.crt"
    - enabled: true
      protocol: "doh"
      address: "https://cloudflare-dns.com/dns-query"
      tls:
        cert_path: "/etc/ssl/certs/ca-bundle.crt"
```

**Recursive Resolver with DNSSEC:**
```yaml
resolvers:
  strategy: "failover"
  servers:
    # Primary: recursive resolver with full DNSSEC validation
    - enabled: true
      protocol: "recursive"
      dnssec: true
      nameserver_ip_family: "ipv4"  # IPv4 nameservers only
    # Fallback: if recursive resolver fails, use Cloudflare
    - enabled: true
      protocol: "dot"
      address: "dns.cloudflare.com:853"
      tls:
        cert_path: "/etc/ssl/certs/ca-bundle.crt"
```

**IPv4-Only Upstream (No IPv6 Nameservers):**
```yaml
resolvers:
  servers:
    - enabled: true
      protocol: "recursive"
      dnssec: true
      nameserver_ip_family: "ipv4"  # Force IPv4 nameservers only
```

---

## Zone Forwarding

Zone forwarding routes queries matching a domain suffix to dedicated zone-specific resolvers. This is useful for:
- Routing internal domain queries to internal DNS servers
- Redirecting specific domains to specialized resolvers
- Bypassing filters for trusted internal domains

### Configuration Reference

```yaml
resolvers:
  zones:
    - zone: "home.arpa"             # Domain suffix to match
      enabled: false                # Optional: enable/disable without deletion (default: true)
      bypass_filter: false          # Optional: skip blocklist filtering for this zone
      fallback_to_default_resolvers: false  # Optional: retry default resolvers if zone servers fail
      strategy: "round_robin"       # Optional: override global strategy for this zone
      servers:
        - enabled: true
          protocol: "dns"           # dns | dot | doh | recursive | json
          address: "192.168.1.1:53"
```

### Zone Server Protocols

Each zone entry has a `servers[]` list. Every server requires `enabled`, `protocol`, and `address`.

| Protocol | `address` format | Auth supported |
|---|---|---|
| `dns` | `<ip>:<port>` | No |
| `dot` | `tls://<host>[:<port>]` or `<ip>[:<port>]` | No |
| `doh` | `https://…` | Yes (Bearer or Basic) |
| `recursive` | *(no address needed)* | No |
| `json` | `file:///…`, `http://…`, or `https://…` | Yes for HTTP(S) |

**Zone Forwarding (dns/dot/doh/recursive):**
```yaml
zones:
  - zone: "home.arpa"
    enabled: false
    servers:
      - enabled: true
        protocol: "dns"
        address: "192.168.1.1:53"
```
Queries for `*.home.arpa` are forwarded to the specified upstream server(s).

**Zone Authority (json):**
```yaml
zones:
  - zone: "example.com"
    enabled: false
    servers:
      - enabled: true
        protocol: "json"
        address: "file:///etc/dns-filter/zones/example.com.json"
```
Queries for `*.example.com` are answered authoritatively from a local JSON zone file.

**Zone Source Authentication:**

Use `authentication` nested under a `json` or `doh` server entry. Use **either** `token` (Bearer) **or** `username`+`password` (Basic), never both. Authentication on file-based `json` sources is rejected at startup.

```yaml
# Bearer token authentication:
servers:
  - enabled: true
    protocol: "json"
    address: "https://zones.example.net/zone.json"
    authentication:
      token: "my-bearer-token"

# Basic authentication:
servers:
  - enabled: true
    protocol: "doh"
    address: "https://dns.example.net/dns-query"
    authentication:
      username: "user"
      password: "secret"
```

**`check_interval` for JSON URL sources:**

Add `check_interval` under a `protocol: json` server entry to enable periodic background refresh. Rejected for `file://` sources.

```yaml
servers:
  - enabled: true
    protocol: "json"
    address: "https://zones.example.net/zone.json"
    check_interval: "15m"
```

### Zone Authority JSON Format *(Experimental)*

The zone JSON file defines authoritative DNS records for the zone. Records are a flat array; each entry carries its own `type` field and a structured `data` object whose shape depends on the record type:

```json
{
  "zone": "example.com",
  "ttl_default": 3600,
  "serial": "2024050101",
  "records": [
    {"name": "@",   "type": "A",    "ttl": 300,  "data": {"address": "192.0.2.1"}},
    {"name": "www", "type": "A",    "ttl": 300,  "data": {"address": "192.0.2.2"}},
    {"name": "api", "type": "A",    "ttl": 300,  "data": {"address": "192.0.2.3"}},
    {"name": "@",   "type": "AAAA", "ttl": 300,  "data": {"address": "2001:db8::1"}},
    {"name": "@",   "type": "MX",   "ttl": 3600, "data": {"priority": 10, "exchange": "mail.example.com"}},
    {"name": "@",   "type": "TXT",  "ttl": 3600, "data": {"values": ["v=spf1 include:spf.google.com ~all"]}},
    {"name": "@",   "type": "NS",   "ttl": 3600, "data": {"target": "ns1.example.com"}},
    {"name": "@",   "type": "SOA",  "ttl": 3600, "data": {
      "mname": "ns1.example.com",
      "rname": "hostmaster.example.com",
      "serial": 2024050101,
      "refresh": 10800,
      "retry": 3600,
      "expire": 604800,
      "minimum": 3600
    }}
  ]
}
```

**Top-Level Fields:**
- `zone` (string, required): The zone name this file is authoritative for.
- `ttl_default` (u32, optional): Default TTL applied when a record omits `ttl`.
- `serial` (string, optional): Human-readable serial (informational only; the SOA serial in `records` is authoritative).
- `records` (array, required): Flat list of DNS record objects.

**Record Object Fields:**
- `name` (string): `"@"` for the zone apex, or a relative label (e.g., `"www"`).
- `type` (string): One of the supported record types below.
- `ttl` (u32, optional): Per-record TTL; falls back to `ttl_default`.
- `data` (object): Structured data whose fields depend on `type`.

**Supported Record Types and `data` Fields:**

| Type | `data` fields | Example |
|------|--------------|---------|
| `A` | `address` (IPv4 string) | `{"address": "192.0.2.1"}` |
| `AAAA` | `address` (IPv6 string) | `{"address": "2001:db8::1"}` |
| `CNAME` | `target` (FQDN) | `{"target": "www.example.com"}` |
| `NS` | `target` (FQDN) | `{"target": "ns1.example.com"}` |
| `PTR` | `target` (FQDN) | `{"target": "host.example.com"}` |
| `MX` | `priority` (u16), `exchange` (FQDN) | `{"priority": 10, "exchange": "mail.example.com"}` |
| `TXT` | `values` (array of strings) | `{"values": ["v=spf1 ..."]}` |
| `SOA` | `mname`, `rname` (strings), `serial` (u32), `refresh`, `retry`, `expire` (i32), `minimum` (u32) | See example above |
| `SRV` | `priority`, `weight`, `port` (u16), `target` (FQDN) | `{"priority": 10, "weight": 60, "port": 5060, "target": "sip.example.com"}` |
| `CAA` | `flags` (u8), `tag` (string), `value` (string) | `{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}` |
| `TLSA` | `usage`, `selector`, `matching_type` (u8), `certificate` (hex string) | `{"usage": 3, "selector": 1, "matching_type": 1, "certificate": "a1b2c3d4"}` |
| `NAPTR` | `order`, `preference` (u16), `flags`, `service`, `regexp`, `replacement` (strings) | `{"order": 100, "preference": 10, "flags": "S", "service": "SIP+D2U", "regexp": "", "replacement": "_sip._udp.example.com"}` |

**Special Behavior:**
- **NS Glue:** When a zone contains `NS` records pointing to in-zone nameservers (e.g., `ns1.example.com`), the corresponding `A`/`AAAA` records are automatically included in the DNS additional section.
- **Auto-Generated Apex Records:** If the zone is missing apex `NS` or `SOA` records, they are auto-generated with sensible defaults (e.g., `NS ns1.<zone>`, `SOA ns1.<zone> hostmaster.<zone> ...`).

### Examples

**Simple Zone Forwarding (Route Internal Domains):**
```yaml
resolvers:
  zones:
    - zone: "home.arpa"
      enabled: false
      bypass_filter: true          # Skip blocklist for internal domains
      servers:
        - enabled: true
          protocol: "dns"
          address: "192.168.1.1:53"
```

**Zone Forwarding with Failover:**
```yaml
resolvers:
  zones:
    - zone: "internal.corp"
      enabled: false
      strategy: "failover"         # Try primary, fall back to secondary
      servers:
        - enabled: true
          protocol: "dns"
          address: "10.0.0.1:53"   # Primary
        - enabled: true
          protocol: "dns"
          address: "10.0.0.2:53"   # Fallback
      fallback_to_default_resolvers: true  # If both fail, use default resolvers
```

**Zone Forwarding with DoT:**
```yaml
resolvers:
  zones:
    - zone: "example.com"
      enabled: false
      servers:
        - enabled: true
          protocol: "dot"
          address: "ns1.example.com:853"
```

**Zone Authority with Local JSON:**
```yaml
resolvers:
  zones:
    - zone: "lab.local"
      enabled: false
      servers:
        - enabled: true
          protocol: "json"
          address: "file:///etc/dns-filter/zones/lab.local.json"
```

**Zone Authority with URL Refresh:**
```yaml
resolvers:
  zones:
    - zone: "managed.example.com"
      enabled: false
      servers:
        - enabled: true
          protocol: "json"
          address: "https://zones.example.net/managed.example.com.json"
          check_interval: "15m"  # Check for updates every 15 minutes
          # Falls back to last good snapshot if URL fetch fails
```

**Zone Authority with Bearer Token Auth:**
```yaml
resolvers:
  zones:
    - zone: "secure.example.com"
      enabled: false
      servers:
        - enabled: true
          protocol: "json"
          address: "https://zones.example.net/secure.example.com.json"
          check_interval: "15m"
          authentication:
            token: "my-secret-bearer-token"
```

**Zone Authority with Basic Auth:**
```yaml
resolvers:
  zones:
    - zone: "private.example.com"
      enabled: false
      servers:
        - enabled: true
          protocol: "json"
          address: "https://zones.example.net/private.example.com.json"
          check_interval: "30m"
          authentication:
            username: "zone-reader"
            password: "s3cret"
```

**Zone Forwarding with DoH and Bearer Auth:**
```yaml
resolvers:
  zones:
    - zone: "corp.example"
      enabled: false
      servers:
        - enabled: true
          protocol: "doh"
          address: "https://dns.corp.example/dns-query"
          authentication:
            token: "my-doh-token"
```

### Zone Discovery

Zone discovery automatically imports authoritative zones from a JSON index endpoint. Instead of manually defining each zone, you point dns-filter at a URL that returns a list of available zones — each zone's data is then fetched via its `href`.

**How it works:**
1. Fetches the index URL, which returns `{"zones": [{"href": "...", "name": "...", "type": "..."}, ...]}`
2. Filters zones by `allowed_types` (if configured)
3. Resolves each zone's `href` relative to the index URL
4. Loads zone records from the resolved URL as a standard zone JSON document
5. Registers each zone as an authoritative zone entry

**Key behaviors:**
- Zones explicitly defined in `resolvers.zones` always take priority over discovered zones with the same name
- Authentication configured on the discovery entry is reused for all href fetches
- Both the index and zone data are periodically refreshed using `check_interval`
- If the index endpoint is unreachable at startup, the source is skipped with a warning (non-fatal)

**Configuration Reference:**

```yaml
resolvers:
  zone_discovery:
    - enabled: true
      address: "https://router.home.arpa/zones"   # Index endpoint URL (must be http:// or https://)
      check_interval: "15m"                        # Refresh interval for index and zone data
      allowed_types:                               # Only import zones matching these types
        - "reverse"
        - "forward"
        - "reverse-aggregate"
      bypass_filter: true                          # Skip blocklist filtering for all discovered zones
      fallback_to_default_resolvers: false         # Fall back to global resolvers on failure
      authentication:                              # Optional: reused for index and all href fetches
        token: "my-bearer-token"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable this discovery source |
| `address` | string | *(required)* | URL of the zone index endpoint |
| `check_interval` | string | — | Refresh interval (e.g. `"15m"`, `"1h"`) |
| `allowed_types` | list | `[]` (all) | Zone types to import; empty means accept all |
| `bypass_filter` | bool | `false` | Skip filtering for discovered zones |
| `fallback_to_default_resolvers` | bool | `false` | Use global resolvers as fallback |
| `authentication` | object | — | Bearer (`token`) or Basic (`username`+`password`) |

**Zone Index JSON Format:**

The index endpoint must return a JSON object with a `zones` array:

```json
{
  "zones": [
    {
      "href": "/zone/home.arpa",
      "name": "home.arpa",
      "type": "forward"
    },
    {
      "href": "/zone/168.192.in-addr.arpa",
      "name": "168.192.in-addr.arpa",
      "type": "reverse"
    },
    {
      "href": "/zone/in-addr.arpa",
      "name": "in-addr.arpa",
      "type": "reverse-aggregate"
    }
  ]
}
```

Each zone's `href` is resolved relative to the index URL. For example, with index URL `https://router.home.arpa/zones` and href `/zone/home.arpa`, the zone data is fetched from `https://router.home.arpa/zone/home.arpa`. Absolute URLs in `href` are also supported.

The zone data at each href must be in the standard [Zone Authority JSON Format](#zone-authority-json-format-experimental).

**Supported zone types:** `forward`, `reverse`, `reverse-aggregate`

**Example with Basic Auth:**
```yaml
resolvers:
  zone_discovery:
    - enabled: true
      address: "https://internal-dns.corp/api/zones"
      check_interval: "30m"
      allowed_types:
        - "forward"
        - "reverse"
      bypass_filter: true
      fallback_to_default_resolvers: false
      authentication:
        username: "dns-filter"
        password: "s3cret-token"
```

---

## WASM Plugins *(Draft)*

dns-filter supports an extensible plugin system using sandboxed WebAssembly (WASM) modules. Plugins can inspect DNS queries and return verdicts to block, allow, rewrite, or pass through requests.

> **Status:** This feature is in draft/scaffolding phase. The plugin ABI and runtime are defined but not yet functional. The scaffolding is available behind the `plugins` cargo feature flag.

### Building with Plugin Support

```bash
cargo build --release --features plugins
```

Without the `plugins` feature, the plugin runtime is excluded entirely — zero binary size impact.

### Configuration Reference

```yaml
plugins:
  - name: "parental-controls"
    path: "/etc/dns-filter/plugins/parental.wasm"
    enabled: true

  - name: "geo-routing"
    path: "/etc/dns-filter/plugins/geo.wasm"
    enabled: false  # disabled without removing from config
```

**Fields:**
- `name` (string, required): Human-readable identifier for the plugin
- `path` (string, required): Filesystem path to the `.wasm` module
- `enabled` (bool, optional): Enable/disable without deleting from config (default: true)

### Plugin Verdicts

Each plugin can return one of these verdicts for a DNS query:

| Verdict | Effect |
|---------|--------|
| **Pass** | Continue to next pipeline stage (default) |
| **Block** | Return sinkhole response |
| **Allow** | Bypass remaining filters |
| **Rewrite** | Rewrite the query target to a different domain |

### Pipeline Position

Plugins execute **after** the static blocklist/allowlist filter and **before** zone forwarding:

```
Filter → WASM Plugins → Zone Forwarding → Upstream
```

### Security Model

- Plugins run inside a WASM sandbox (wasmtime) with strict resource limits
- No filesystem, network, or system access from plugin code
- Memory and execution time are bounded per plugin invocation
- Plugin code cannot affect the host process outside the defined ABI

---

## Listening Ports and Protocols

Configure which DNS protocols and ports are exposed.

### Configuration Reference

```yaml
listen:
  dns:
    enabled: true
    addresses: ["0.0.0.0", "::"]
    port: 53
  
  dot:
    enabled: false
    addresses: ["0.0.0.0", "::"]
    port: 853
    tls:
      cert_path: "/etc/ssl/certs/dns-filter.crt"
      key_path: "/etc/ssl/private/dns-filter.key"
      autogenerate: false  # auto-generate self-signed certs if missing
  
  doh:
    enabled: false
    addresses: ["0.0.0.0", "::"]
    port: 443
    tls:
      cert_path: "/etc/ssl/certs/dns-filter.crt"
      key_path: "/etc/ssl/private/dns-filter.key"
      autogenerate: false  # auto-generate self-signed certs if missing
    # Optional: require Bearer token for inbound DoH queries
    # auth_token: "my-secret-token"
  
  doq:
    enabled: false
    addresses: ["0.0.0.0", "::"]
    port: 8853
    tls:
      cert_path: "/etc/ssl/certs/dns-filter.crt"
      key_path: "/etc/ssl/private/dns-filter.key"
  
  http:
    enabled: true
    addresses: ["0.0.0.0"]
    port: 8080
  
  metrics:
    enabled: true
    addresses: ["127.0.0.1", "::1"]  # Loopback-only by default
    port: 9100
```

### Examples

**Plain DNS Only:**
```yaml
listen:
  dns:
    enabled: true
    port: 53
  dot:
    enabled: false
  doh:
    enabled: false
  doq:
    enabled: false
```

**DNS + DoT + DoH (Full Multi-Protocol):**
```yaml
listen:
  dns:
    enabled: true
    port: 53
  dot:
    enabled: true
    port: 853
    tls:
      cert_path: "/etc/ssl/certs/dns-filter.crt"
      key_path: "/etc/ssl/private/dns-filter.key"
  doh:
    enabled: true
    port: 443
    tls:
      cert_path: "/etc/ssl/certs/dns-filter.crt"
      key_path: "/etc/ssl/private/dns-filter.key"
    # auth_token: "my-secret-token"  # Optional: require Bearer token
```

**Restricted to Loopback (Local Development):**
```yaml
listen:
  dns:
    enabled: true
    addresses: ["127.0.0.1", "::1"]
    port: 5353  # Use non-standard port to avoid permission issues
  metrics:
    enabled: true
    addresses: ["127.0.0.1"]
    port: 9100
```

---

## Logging

Configure logging output to syslog, file, or stdout.

### Configuration Reference

```yaml
logging:
  syslog:
    enabled: false
    transport: "unix"          # "unix", "udp", "tcp", "tls"
    server: "/dev/log"         # for unix; for network: "host:port"
    format: "rfc3164"          # "rfc3164" or "rfc5424"
    facility: "local0"         # syslog facility
    level: "info"              # log level: debug, info, warn, error
    tls:
      ca_cert_path: "/etc/ssl/certs/ca-bundle.crt"
      verify_hostname: true
  
  file:
    enabled: false
    location: "/var/log/dns-filter/dns-filter.log"
    level: "info"
  
  stdout:
    enabled: true
    level: "info"
```

### Log Levels

- `debug` - Very verbose; includes all hickory DNS library logs
- `info` - General information; standard operation
- `warn` - Warnings; non-fatal issues
- `error` - Errors only; critical issues

### Syslog Transports

**Local Unix Socket** (Default, fastest)
```yaml
logging:
  syslog:
    enabled: true
    transport: "unix"
    server: "/dev/log"
    facility: "local0"
    level: "info"
```
Logs to the local syslog daemon via `/dev/log` socket.

**Remote UDP**
```yaml
logging:
  syslog:
    enabled: true
    transport: "udp"
    server: "logs.example.com:514"
    facility: "local0"
    level: "info"
```
Sends logs over UDP to remote syslog server. Fast but unreliable (fire-and-forget).

**Remote TCP**
```yaml
logging:
  syslog:
    enabled: true
    transport: "tcp"
    server: "logs.example.com:514"
    facility: "local0"
    level: "info"
```
Sends logs over TCP to remote syslog server. Reliable connection but slightly slower.

**Remote TLS** (Encrypted)
```yaml
logging:
  syslog:
    enabled: true
    transport: "tls"
    server: "logs.example.com:6514"
    facility: "local0"
    level: "info"
    tls:
      ca_cert_path: "/etc/ssl/certs/ca-bundle.crt"
      verify_hostname: true
```
Sends logs over TLS to remote syslog server. Encrypted and authenticated.

### Examples

**Syslog to Local System**
```yaml
logging:
  syslog:
    enabled: true
    transport: "unix"
    server: "/dev/log"
    facility: "local0"
    level: "info"
  stdout:
    enabled: false
```

**Remote Syslog over TLS**
```yaml
logging:
  syslog:
    enabled: true
    transport: "tls"
    server: "logs.example.com:6514"
    facility: "local0"
    level: "warn"
    tls:
      ca_cert_path: "/etc/ssl/certs/ca-bundle.crt"
      verify_hostname: true
  file:
    enabled: false
  stdout:
    enabled: false
```

**Multi-Target Logging (Syslog + File + Stdout)**
```yaml
logging:
  syslog:
    enabled: true
    transport: "unix"
    server: "/dev/log"
    facility: "local0"
    level: "info"
  file:
    enabled: true
    location: "/var/log/dns-filter/dns-filter.log"
    level: "debug"
  stdout:
    enabled: true
    level: "info"
```

---

## Security

### Configuration Reference

```yaml
security:
  user: "nobody"                    # User to drop privileges to
  group: "nogroup"                  # Group to drop privileges to
  chroot_dir: "/var/lib/dns-filter" # Chroot directory for sandboxing
```

### Privilege Model

1. **Start as root** — Required to bind privileged ports (< 1024)
2. **Bind ports** — All socket binding happens as root
3. **Privilege drop** — After ports are bound:
   - Clear all groups, add target group (`setgroups`, `setgid`)
   - Change to target user (`setuid`)
   - Change root directory (`chroot`)
   - On Linux: retain `CAP_NET_BIND_SERVICE` for potential rebinds on reload
4. **Serve requests** — All DNS request handling is as the unprivileged user

### Setup for Privilege Dropping

```bash
# Create unprivileged user (already exists on most systems)
sudo useradd -r -s /bin/false dns-filter 2>/dev/null || true

# Prepare chroot directory
sudo mkdir -p /var/lib/dns-filter
sudo chown -R dns-filter:dns-filter /var/lib/dns-filter
sudo chmod 755 /var/lib/dns-filter
```

### Configuration Example

```yaml
security:
  user: "dns-filter"
  group: "dns-filter"
  chroot_dir: "/var/lib/dns-filter"
```

---

## Security Best Practices

### Privilege Management

✅ **Do:**
- Run with `security.user` set to an unprivileged account
- Use `security.chroot_dir` to sandbox the process
- Verify the unprivileged user exists before starting

❌ **Don't:**
- Run dns-filter as root without privilege dropping
- Use privilege dropping with a shell user account (non-existent user is fine, but avoid login shells)
- Disable privilege dropping in production

### TLS Certificate Management

**For DoT/DoH/DoQ Listeners:**

✅ **Do:**
- Use CA-signed certificates for production
- Use self-signed certificates for testing/development only
- Specify explicit certificate paths
- Use strong key sizes (RSA 2048+, or ECDSA P-256+)

❌ **Don't:**
- Enable `autogenerate: true` in production
- Use expired certificates
- Mix certificate formats (PEM required)

**Certificate Setup:**
```bash
# Generate self-signed cert (testing only)
openssl req -x509 -newkey rsa:2048 -keyout dns-filter.key -out dns-filter.crt \
  -days 365 -nodes -subj "/CN=dns-filter.example.com"

# Use CA-signed cert (production)
# Get cert from Let's Encrypt, commercial CA, or internal CA
```

**For Upstream DoT/DoH Verification:**

✅ **Do:**
- Provide CA certificate bundle to verify upstream certificates
- Set `tls.cert_path` to system CA bundle (e.g., `/etc/ssl/certs/ca-bundle.crt`)
- Enable `verify_hostname: true` for syslog TLS

❌ **Don't:**
- Skip TLS verification for upstream resolvers
- Use self-signed upstream certs without adding to CA bundle

### Network Isolation

✅ **Do:**
- Bind DNS to loopback (`127.0.0.1`, `::1`) for local-only access
- Bind DNS to internal network ranges for internal-only access
- Use firewall rules to restrict access by source IP
- Restrict metrics endpoint to trusted networks

Example - Local-only DNS:
```yaml
listen:
  dns:
    addresses: ["127.0.0.1", "::1"]
    port: 53
  metrics:
    addresses: ["127.0.0.1"]
    port: 9100
```

Example - Firewall rules:
```bash
# Allow DNS only from internal network
sudo ufw allow from 10.0.0.0/8 to any port 53
sudo ufw allow from 192.168.0.0/16 to any port 53

# Allow metrics only from localhost
sudo ufw allow from 127.0.0.1 to any port 9100
```

❌ **Don't:**
- Expose DNS to the public internet without rate limiting
- Bind to 0.0.0.0 without firewall restrictions
- Expose metrics endpoint to untrusted networks

### Syslog Security

✅ **Do:**
- Use TLS for remote syslog
- Verify remote syslog server certificate
- Use `verify_hostname: true`
- Restrict syslog server access by IP

❌ **Don't:**
- Send logs to remote syslog unencrypted (UDP/TCP without TLS)
- Skip certificate verification
- Log sensitive data (passwords, tokens, keys)

### Rate Limiting

For high-traffic environments, consider a reverse proxy or dedicated rate limiter:

```bash
# Example: rate-limit to 100 DNS queries/second per source IP
# Use tools like fail2ban, tc (traffic control), or nginx upstream
```

### DNSSEC Validation

✅ **Do:**
- Enable `dnssec: true` for recursive resolver (default)
- Verify DNSSEC with `delv` or other DNSSEC-aware clients

```bash
# Test DNSSEC validation
delv @127.0.0.1 +dnssec example.com
```

❌ **Don't:**
- Disable DNSSEC in production (unless unavoidable)
- Trust unsigned delegations without validation

### Configuration File Permissions

```bash
# Restrict config to root-readable only
sudo chmod 600 /etc/dns-filter/config.yaml
sudo chown root:root /etc/dns-filter/config.yaml
```

### Systemd Hardening

The provided systemd unit includes hardening directives:

```ini
# Restrict filesystem access
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

# Capabilities
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH

# Kernel hardening
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
```

These are automatically applied when using the provided systemd unit.

---

## Comprehensive Configuration Examples

### Example 1: Simple Home Setup

A basic DNS filtering setup for a home network.

```yaml
listen:
  dns:
    enabled: true
    addresses: ["0.0.0.0", "::"]
    port: 53
  dot:
    enabled: false
  doh:
    enabled: false
  doq:
    enabled: false
  metrics:
    enabled: true
    addresses: ["127.0.0.1", "::1"]
    port: 9100

blocklists:
  - adguard:
      enabled: true
      url: "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt"
      interval: "12h"

allowlists: []

filtering:
  sinkhole_ipv4: "0.0.0.0"
  sinkhole_ipv6: "::"
  cache:
    mode: "memory"

resolvers:
  strategy: "round_robin"
  servers:
    - enabled: true
      protocol: "dns"
      address: "1.1.1.1:53"
    - enabled: true
      protocol: "dns"
      address: "8.8.8.8:53"

logging:
  stdout:
    enabled: true
    level: "info"
  syslog:
    enabled: false
  file:
    enabled: false

security:
  user: "nobody"
  group: "nogroup"
  chroot_dir: "/var/lib/dns-filter"
```

### Example 2: Corporate Network with Zone Forwarding

A corporate setup with internal domain forwarding and multiple filtering lists.

```yaml
listen:
  dns:
    enabled: true
    addresses: ["0.0.0.0", "::"]
    port: 53
  metrics:
    enabled: true
    addresses: ["127.0.0.1"]
    port: 9100

blocklists:
  - adguard_base:
      url: "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt"
      interval: "12h"
  - adguard_social:
      url: "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt"
      interval: "12h"
  - custom_corporate:
      url: "file:///etc/dns-filter/corporate-blocklist.txt"

allowlists:
  - internal_safe:
      url: "file:///etc/dns-filter/internal-allowlist.txt"

filtering:
  sinkhole_ipv4: "0.0.0.0"
  sinkhole_ipv6: "::"
  cache:
    mode: "sqlite"
    document_path: "/var/lib/dns-filter/cache.db"

resolvers:
  strategy: "round_robin"
  servers:
    - enabled: true
      protocol: "dns"
      address: "8.8.8.8:53"
    - enabled: true
      protocol: "dns"
      address: "1.1.1.1:53"
  zones:
    - zone: "corp.internal"
      bypass_filter: true
      servers:
        - enabled: true
          protocol: "dns"
          address: "10.0.0.1:53"
    - zone: "internal"
      bypass_filter: true
      servers:
        - enabled: true
          protocol: "dns"
          address: "10.0.0.1:53"
        - enabled: true
          protocol: "dns"
          address: "10.0.0.2:53"
      strategy: "round_robin"

logging:
  syslog:
    enabled: true
    transport: "unix"
    server: "/dev/log"
    facility: "local0"
    level: "info"
  file:
    enabled: true
    location: "/var/log/dns-filter/dns-filter.log"
    level: "info"
  stdout:
    enabled: false

security:
  user: "nobody"
  group: "nogroup"
  chroot_dir: "/var/lib/dns-filter"
```

### Example 3: Secure Setup with DoT/DoH and Remote Syslog

A hardened setup with encrypted upstream and remote logging.

```yaml
listen:
  dns:
    enabled: true
    addresses: ["127.0.0.1", "::1"]  # Local only
    port: 53
  dot:
    enabled: true
    addresses: ["0.0.0.0", "::"]
    port: 853
    tls:
      cert_path: "/etc/ssl/certs/dns-filter.crt"
      key_path: "/etc/ssl/private/dns-filter.key"
  doh:
    enabled: true
    addresses: ["0.0.0.0", "::"]
    port: 443
    tls:
      cert_path: "/etc/ssl/certs/dns-filter.crt"
      key_path: "/etc/ssl/private/dns-filter.key"
  metrics:
    enabled: true
    addresses: ["127.0.0.1"]
    port: 9100

blocklists:
  - adguard:
      url: "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt"
      interval: "12h"
  - malware:
      url: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List.txt"
      interval: "24h"

allowlists:
  - trusted:
      url: "file:///etc/dns-filter/allowlist.txt"

filtering:
  sinkhole_ipv4: "0.0.0.0"
  sinkhole_ipv6: "::"
  cache:
    mode: "sqlite"
    document_path: "/var/lib/dns-filter/cache.db"

resolvers:
  strategy: "failover"
  servers:
    # Primary: recursive with DNSSEC
    - enabled: true
      protocol: "recursive"
      dnssec: true
    # Fallback: Cloudflare DoT
    - enabled: true
      protocol: "dot"
      address: "dns.cloudflare.com:853"
      tls:
        cert_path: "/etc/ssl/certs/ca-bundle.crt"

logging:
  syslog:
    enabled: true
    transport: "tls"
    server: "logs.example.com:6514"
    facility: "local0"
    level: "info"
    tls:
      ca_cert_path: "/etc/ssl/certs/ca-bundle.crt"
      verify_hostname: true
  file:
    enabled: true
    location: "/var/log/dns-filter/dns-filter.log"
    level: "debug"
  stdout:
    enabled: false

security:
  user: "dns-filter"
  group: "dns-filter"
  chroot_dir: "/var/lib/dns-filter"
```

### Example 4: Recursive Resolver with DNSSEC Validation

A setup using dns-filter as a local recursive resolver with full DNSSEC validation.

```yaml
listen:
  dns:
    enabled: true
    addresses: ["127.0.0.1", "::1"]
    port: 53
  metrics:
    enabled: true
    addresses: ["127.0.0.1"]
    port: 9100

# Minimal filtering (no blocklists)
blocklists: []
allowlists: []

filtering:
  cache:
    mode: "memory"

resolvers:
  servers:
    - enabled: true
      protocol: "recursive"
      dnssec: true
      nameserver_ip_family: "ipv4"
      max_hops: 12

logging:
  stdout:
    enabled: true
    level: "info"

security:
  user: "nobody"
  group: "nogroup"
  chroot_dir: "/var/lib/dns-filter"
```

Test DNSSEC validation:
```bash
delv @127.0.0.1 +dnssec example.com
```

---

## Troubleshooting

### Enable Debug Logging

The most useful troubleshooting tool is debug logging. This shows detailed information including DNS queries, responses, filter hits, and upstream resolver behavior.

```bash
# Run with debug flag
sudo dns-filter start --config /etc/dns-filter/config.yaml --debug

# Or with systemd
sudo systemctl stop dns-filter
sudo systemctl set-environment ARGS="--debug"
sudo systemctl start dns-filter
sudo journalctl -u dns-filter -f
```

In debug mode:
- All hickory DNS library logs are shown (not filtered to ERROR-only)
- DNS query/response details are visible
- Upstream resolver negotiation is logged
- Filter matching is logged in detail

### Check Systemd Logs

```bash
# View all logs for the service
sudo journalctl -u dns-filter

# Follow logs in real-time
sudo journalctl -u dns-filter -f

# Last 50 lines with verbose output
sudo journalctl -u dns-filter -n 50 -o short-precise
```

### Common Issues

#### Issue: "Permission denied" when binding to port 53

**Symptoms:**
```
Error: bind: permission denied (os error 13)
```

**Cause:** Process doesn't have permission to bind to privileged port (< 1024).

**Solutions:**
1. Run as root (if not already):
   ```bash
   sudo dns-filter --config /etc/dns-filter/config.yaml
   ```

2. Check systemd unit privileges:
   ```bash
   systemctl show -p AmbientCapabilities dns-filter
   ```

3. Verify `CAP_NET_BIND_SERVICE` capability:
   ```bash
   getcap /usr/local/bin/dns-filter
   # Should show CAP_NET_BIND_SERVICE
   ```

#### Issue: TLS certificate not found

**Symptoms:**
```
error: TLS certificate file not found: /etc/ssl/certs/dns-filter.crt
```

**Solutions:**
1. Verify certificate path in config:
   ```bash
   ls -la /etc/ssl/certs/dns-filter.crt
   ```

2. Generate self-signed certificate:
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout /etc/ssl/private/dns-filter.key \
     -out /etc/ssl/certs/dns-filter.crt -days 365 -nodes \
     -subj "/CN=dns-filter.example.com"
   sudo chmod 644 /etc/ssl/certs/dns-filter.crt
   sudo chmod 600 /etc/ssl/private/dns-filter.key
   ```

3. Or enable auto-generation (testing only):
   ```yaml
   listen:
     dot:
       tls:
         autogenerate: true
   ```

#### Issue: Upstream resolver timeout

**Symptoms:**
```
Error: upstream resolver timed out
DNS queries fail with SERVFAIL
```

**Causes:**
- Network connectivity to upstream resolver
- Bootstrap resolver misconfiguration
- Firewall blocking outbound DNS

**Solutions:**
1. Verify network connectivity:
   ```bash
   ping 1.1.1.1
   nc -zv 1.1.1.1 53
   ```

2. Test DNS query directly:
   ```bash
   dig @1.1.1.1 example.com
   ```

3. Check bootstrap resolver:
   ```yaml
   resolvers:
     bootstrap_resolvers:
       - "1.1.1.1"  # Must be reachable
   ```

4. Check firewall:
   ```bash
   sudo ufw allow out 53  # Allow outbound DNS
   ```

#### Issue: Blocklist fails to download

**Symptoms:**
```
error: failed to download blocklist "adguard": HTTP error 404
```

**Causes:**
- Invalid URL
- Network connectivity
- Rate limiting by remote server
- HTTPS certificate validation failure

**Solutions:**
1. Verify URL works:
   ```bash
   curl -v "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt" | head -20
   ```

2. Check network connectivity:
   ```bash
   ping raw.githubusercontent.com
   ```

3. Use local file instead:
   ```yaml
   blocklists:
     - local:
         url: "file:///etc/dns-filter/blocklist.txt"
   ```

4. Increase refresh interval to reduce rate-limiting:
   ```yaml
   blocklists:
     - adguard:
         interval: "24h"  # Reduce frequency
   ```

#### Issue: Privilege drop fails (chroot: permission denied)

**Symptoms:**
```
error: chroot: permission denied (os error 13)
```

**Causes:**
- Chroot directory doesn't exist
- Insufficient permissions on chroot directory
- Process doesn't have `CAP_SYS_CHROOT` capability

**Solutions:**
1. Verify chroot directory exists and has correct permissions:
   ```bash
   sudo mkdir -p /var/lib/dns-filter
   sudo chown -R nobody:nogroup /var/lib/dns-filter
   sudo chmod 755 /var/lib/dns-filter
   ls -la /var/lib/dns-filter
   ```

2. Verify capabilities:
   ```bash
   getcap /usr/local/bin/dns-filter
   # Should include CAP_SYS_CHROOT
   ```

3. Check systemd unit `CapabilityBoundingSet`:
   ```bash
   systemctl show -p CapabilityBoundingSet dns-filter
   ```

#### Issue: DNSSEC validation failures

**Symptoms:**
```
DNSSEC: broken trust chain
delv: response is INSECURE
```

**Causes:**
- Missing or incorrect root hints file
- DNSSEC validation disabled
- Upstream resolver not supporting DNSSEC
- Clock skew on system

**Solutions:**
1. Check system time is correct:
   ```bash
   date
   ntpq -p  # Check NTP sync
   ```

2. Verify root hints file:
   ```bash
   ls -la /usr/share/dns/root.hints
   cat /usr/share/dns/root.hints | head
   ```

3. Test DNSSEC validation:
   ```bash
   delv @127.0.0.1 +dnssec +trusted-key=. example.com
   ```

4. Ensure `dnssec: true` in config:
   ```yaml
   resolvers:
     servers:
       - protocol: "recursive"
         dnssec: true
   ```

#### Issue: Zone authority JSON not loading

**Symptoms:**
```
error: zone authority JSON file not found or invalid: /etc/dns-filter/zones/example.com.json
```

**Solutions:**
1. Verify JSON file path and format:
   ```bash
   cat /etc/dns-filter/zones/example.com.json | jq .
   ```

2. Check file permissions:
   ```bash
   ls -la /etc/dns-filter/zones/example.com.json
   sudo chmod 644 /etc/dns-filter/zones/example.com.json
   ```

3. Validate JSON schema:
   ```bash
   # Ensure "zone" field matches configured zone name
   cat /etc/dns-filter/zones/example.com.json | jq '.zone'
   ```

#### Issue: Config reload fails

**Symptoms:**
```
error: SIGHUP reload failed: invalid configuration
systemctl reload dns-filter: job failed
```

**Solutions:**
1. Validate new config syntax:
   ```bash
   dns-filter start --config /etc/dns-filter/config.yaml
   # If this fails, the file is invalid
   ```

2. Check systemd logs:
   ```bash
   sudo journalctl -u dns-filter -n 20
   ```

3. Previous config remains in use on reload failure (safe fallback).

### Test Queries

```bash
# Basic DNS query
dig @127.0.0.1 example.com

# Query specific record type
dig @127.0.0.1 example.com A
dig @127.0.0.1 example.com MX
dig @127.0.0.1 example.com AAAA

# Test with DNSSEC
dig @127.0.0.1 +dnssec example.com

# Test DoT (if DoT listener enabled and certificate valid)
# Requires special tools (dig +tls, or kdig, etc.)
# Most client tools don't support DoT directly

# Test DoH with curl (POST with wire-format body)
curl -sk --http2 -H 'Content-Type: application/dns-message' \
  --data-binary @<(printf '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01') \
  'https://127.0.0.1:443/dns-query' | xxd

# Test DoH with kdig
kdig +https @127.0.0.1 -p 443 example.com A

# Check metrics
curl http://127.0.0.1:9100/metrics | grep dns

# Test blocked domain (should return sinkhole IP)
dig @127.0.0.1 ads.example.com  # if ads.example.com is in blocklist
```

### Performance Checks

```bash
# Load test with many queries
# Using dnsperf tool (if available)
dnsperf -s 127.0.0.1 -d queryfile.txt -c 10 -T 30

# Monitor resource usage
sudo watch -n 1 'ps aux | grep dns-filter'
sudo top -p $(pgrep dns-filter)

# Check cache metrics
curl http://127.0.0.1:9100/metrics | grep cache
```

---

## Performance Tuning

### Cache Configuration

**Memory Cache** (Default)
- Fast, in-process caching
- Lost on restart
- Good for filtering and blocklist lookups
- Best for systems with frequent DNS queries
- Memory usage: ~100 bytes per cached entry

**SQLite Cache**
- Persistent across restarts
- Useful for large blocklists (warm-start after restart)
- Slightly slower than memory (~1-5ms additional latency per query)
- SSD recommended for optimal performance

```yaml
filtering:
  cache:
    mode: "sqlite"
    document_path: "/var/lib/dns-filter/cache.db"
```

**Cache Sizing:**
- For 10K blocklist entries: ~1-2 MB memory
- For 100K blocklist entries: ~10-20 MB memory
- For 1M blocklist entries: ~100-200 MB memory

### Upstream Resolver Strategy Impact

**Round-Robin** (Default)
- Distributes load evenly
- Minimal latency overhead
- Good for multiple similar upstreams

**Random**
- Similar to round-robin
- Less predictable (slightly reduces cache collisions at upstream)

**Failover**
- Minimizes upstream diversity
- Better for cost control (fewer upstreams in use)
- Slightly higher latency on failover events

**Recursive Resolver**
- Higher latency (~50-200ms for first query, then cached)
- CPU-intensive (iterative resolution)
- Good for maximum privacy (no upstream dependencies)
- DNSSEC validation adds ~5-10ms per query

### Resource Allocation

**CPU:**
- Single-threaded for DNS packet handling
- Tokio runtime uses available CPU cores
- Most queries complete in < 10ms
- Recursive resolver may use more CPU (iterative resolution)

**Memory:**
- Base: ~10-20 MB
- Blocklist overhead: ~100 bytes per entry
- Cache overhead: varies by mode

**Disk (SQLite Cache):**
- Cache DB grows with number of cached entries
- Typical: 100-500 bytes per entry
- Monitor with: `ls -lh /var/lib/dns-filter/cache.db`

**Network:**
- Bandwidth: varies by query rate
- Typical: 50-100 bytes per query
- For 1000 queries/second: ~50-100 Mbps

### Monitoring with Metrics

```bash
# Query Prometheus metrics endpoint
curl http://127.0.0.1:9100/metrics | grep dns

# Key metrics to monitor
# dns_filter_queries_total - total queries handled
# dns_filter_filtered_total - total queries blocked
# dns_filter_upstream_latency_seconds - upstream resolver latency
# dns_filter_cache_hits_total - cache hit count
# dns_filter_cache_misses_total - cache miss count
```

### Optimization Tips

1. **Enable SQLite cache for large blocklists:**
   ```yaml
   filtering:
     cache:
       mode: "sqlite"
   ```

2. **Use round-robin for multiple upstreams:**
   ```yaml
   resolvers:
     strategy: "round_robin"
   ```

3. **Disable DNSSEC if not needed:**
   ```yaml
   resolvers:
     servers:
       - protocol: "recursive"
         dnssec: false  # only if DNSSEC not required
   ```

4. **Use DoT/DoH for upstream to reduce latency overhead:**
   ```yaml
   servers:
     - protocol: "dot"  # faster than plain DNS
       address: "dns.cloudflare.com:853"
   ```

5. **Monitor cache hit ratio:**
   - Higher is better (indicates warm cache)
   - Goal: > 70% for blocking, > 50% for general use

6. **Tune blocklist refresh interval:**
   - More frequent = fresher rules, more bandwidth
   - Less frequent = less bandwidth, older rules
   - Typical: 12-24 hours

7. **Use zone forwarding to bypass filtering for internal zones:**
   - Reduces filter lookup overhead
   - Improves latency for internal queries

---

## Architecture Overview

### Clean Architecture

dns-filter follows a **Clean Architecture** design with **Domain-Driven Design** (DDD) principles:

```
┌────────────────────────────────────────┐
│      Frameworks & Drivers              │
│  (config, logging, metrics, I/O)       │
└────────────────────────────────────────┘
              ▲
              │ depends on
              ▼
┌────────────────────────────────────────┐
│     Interface Adapters                 │
│  (DNS, DoT, DoH, DoQ listeners)        │
└────────────────────────────────────────┘
              ▲
              │ depends on
              ▼
┌────────────────────────────────────────┐
│         Use Cases                      │
│  (filtering, resolution, zones)        │
└────────────────────────────────────────┘
              ▲
              │ depends on
              ▼
┌────────────────────────────────────────┐
│          Entities                      │
│  (domain models, business rules)       │
└────────────────────────────────────────┘
```

**Dependency Rule:** Dependencies point **inward only**. No layer depends on layers outside of it.

### Layer Responsibilities

**Entities** (`src/entities/`)
- Pure domain models: `Filter`, `Resolution`, `PluginVerdict`, `PluginQuery`
- Business rules: blocking logic, response synthesis
- Zero I/O, zero framework dependencies

**Use Cases** (`src/use_cases/`)
- Application orchestration
- Business logic: `filtering.rs`, `upstream_resolver.rs`, `zone_forwarding.rs`, `zone_authority.rs`, `plugin_handler.rs`
- Request pipeline with Chain of Responsibility pattern
- Configuration bootstrap and reload

**Interface Adapters** (`src/interface_adapters/`)
- Protocol boundaries: DNS, DoT, DoH, DoQ, HTTP
- Converts protocol packets ↔ domain entities
- Request routing to use cases
- Response formatting for clients

**Frameworks** (`src/frameworks/`)
- External systems: config loading, logging, upstream client, privilege management
- WASM plugin runtime (`plugin_runtime/`, behind `plugins` feature)
- I/O and side effects
- Isolated from core logic

### Request Processing Pipeline

Chain of Responsibility pattern for composable request handling:

```
DNS Query
    │
    ▼
┌─────────────────────┐
│  Filter Handler     │ ─→ Check blocklists/allowlists
└─────────────────────┘    ├─ Hit → return sinkhole
                           └─ Miss → pass through
    │
    ▼
┌─────────────────────┐
│  Plugin Handler     │ ─→ Execute WASM plugins (if enabled)
└─────────────────────┘    ├─ Block/Allow/Rewrite → short-circuit
                           └─ Pass → continue chain
    │
    ▼
┌─────────────────────┐
│  Zone Handler       │ ─→ Check zone forwarding
└─────────────────────┘    ├─ Zone match → forward to zone resolvers
                           └─ No match → pass through
    │
    ▼
┌─────────────────────┐
│  Upstream Handler   │ ─→ Query upstream resolver
└─────────────────────┘    ├─ Success → return response
                           └─ Failure → error handling
    │
    ▼
DNS Response
```

Each handler can:
- **Short-circuit**: Return response immediately (end chain)
- **Pass-through**: Forward to next handler
- **Error**: Propagate error or fallback behavior

### Concurrency Model

- **Async I/O**: Tokio runtime for all network operations
- **Per-request**: Each DNS query is a separate async task
- **Minimal shared state**: Configuration via `Arc<Config>` (atomic read-only)
- **Thread-safe**: All shared state uses interior mutability (`Mutex`, `RwLock`)

### Configuration Reload

```
Initial Config Load at Startup
         │
         ▼
Bind Sockets (as root)
         │
         ▼
Drop Privileges → Start Serving + Control Socket
         │
         ▼
   Reload Trigger (SIGHUP / control socket / REST API)
         │
         ▼
Validate New Config
         ├─ Valid: Swap atomically
         │         In-flight requests use old config
         │         New requests use new config
         │
         └─ Invalid: Keep old config + warn log
```

This ensures zero-downtime reloads with no query drops.

### Daemon Management

The daemon is managed via subcommands that communicate over a Unix domain control socket:

```bash
dns-filter start --config /etc/dns-filter/config.yaml   # Start daemon
dns-filter stop                                          # Graceful shutdown
dns-filter reload                                        # Reload configuration
dns-filter merge-config --config /etc/dns-filter/config.yaml  # Merge with defaults
```

The control socket defaults to `/run/dns-filter/dns-filter.sock` and is configurable via `control.socket_path`. Stale sockets from crashed runs are auto-detected and replaced on startup.

---

## Contributing / Development Setup

### Prerequisites

- Rust 1.75 or later
- OpenSSL development headers
- Git

### Clone and Build

```bash
git clone https://github.com/yourusername/dns-filter-rust.git
cd dns-filter-rust

# Build debug binary (development, faster compilation)
cargo build

# Build release binary (optimized, slower compilation)
cargo build --release

# Build with WASM plugin support (optional)
cargo build --release --features plugins

# Run tests
cargo test

# Check formatting
cargo fmt --all -- --check

# Run clippy linter
cargo clippy --all-targets --all-features -- -D warnings

# Full release validation
bash tests/release-check.sh
```

### Project Rules

**Always follow these rules before committing:**

1. **Update CHANGELOG.md** — Document all changes in the Unreleased section
2. **Add tests** — New features must include cargo tests
3. **Run release-check.sh** — Must pass without errors:
   ```bash
   bash tests/release-check.sh
   ```
   Validates:
   - `gitleaks` — no secrets committed
   - `cargo fmt` — proper formatting
   - `cargo clippy` — no linting warnings/errors
   - `cargo test` — all tests pass

4. **No formatting errors** — Run `cargo fmt --all`
5. **No clippy warnings** — Run `cargo clippy --all-targets --all-features -- -D warnings`
6. **Run integration tests** — After finishing changes:
   ```bash
   bash tests/listener_batch_test.sh
   ```

7. **Respect architectural boundaries** — Clean Architecture dependency rule must hold
8. **Keep AGENTS.md synchronized** — If module structure changes, update AGENTS.md

### Architecture Constraints

- **No circular dependencies** — Dependency graph must be acyclic
- **Entities ← use_cases ← adapters ← frameworks** — Inward dependencies only
- **No framework code in entities** — Pure domain models
- **Minimal shared state** — Prefer immutable data and message passing

### Testing

```bash
# Unit tests
cargo test

# Integration tests
bash tests/listener_batch_test.sh

# Test with debug output
RUST_LOG=debug cargo test -- --nocapture

# Test specific test
cargo test test_filtering
```

### Code Style

**Naming Conventions:**
- Modules: `snake_case` (e.g., `zone_authority`)
- Structs: `PascalCase` (e.g., `DnsFilter`)
- Functions: `snake_case` (e.g., `check_blocklist`)
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `DEFAULT_TTL`)

**Comments:**
- Document public types and functions
- Explain *why*, not *what* (code is obvious, reasoning is not)
- Link to relevant specs or issues

```rust
/// Blocks a domain against configured blocklists.
///
/// Returns true if the domain is in any enabled blocklist
/// and not in any allowlist (allowlist takes precedence).
pub fn is_blocked(domain: &str) -> bool { }
```

**Async/Await:**
- Use `async fn` and `.await` liberally
- Prefer `tokio::spawn` for background tasks
- Avoid blocking operations in async contexts

### Release Process

1. **Update Version**
   ```bash
   # Edit Cargo.toml
   # Change version to next version
   ```

2. **Update CHANGELOG.md**
   ```markdown
   ## [x.y.z] - YYYY-MM-DD
   - Fixed issue X
   - Added feature Y
   ```

3. **Commit and Tag**
   ```bash
   git add -A
   git commit -m "Release x.y.z"
   git tag -a vx.y.z -m "Release x.y.z"
   ```

4. **Run Release Check**
   ```bash
   bash tests/release-check.sh
   ```

5. **Push** (if all checks pass)
   ```bash
   git push origin main
   git push origin --tags
   ```

### Key Files

- `src/main.rs` — CLI entry point and privilege dropping
- `src/lib.rs` — Public API and module organization
- `src/entities/` — Domain models (`Filter`, `Resolution`, `PluginVerdict`, `PluginQuery`)
- `src/use_cases/` — Business logic (filtering, resolution, zones, plugin handler)
- `src/interface_adapters/listeners/` — Protocol implementations (DNS, DoT, DoH, DoQ)
- `src/frameworks/config/schema.rs` — Configuration schema definition
- `src/frameworks/plugin_runtime/` — WASM plugin runtime (behind `plugins` feature)
- `AGENTS.md` — Architecture documentation and project governance
- `CHANGELOG.md` — Version history and change log

---

## Support and Resources

### Documentation
- **CHANGELOG.md** — Complete version history and release notes
- **AGENTS.md** — Architecture documentation, project rules, and governance
- **Cargo.toml** — Dependencies and package metadata

### Debugging
- Enable debug logging with `--debug` flag
- Check systemd logs: `journalctl -u dns-filter -f`
- See **[Troubleshooting](#troubleshooting)** section above

### Community
- GitHub Issues — Report bugs or request features
- GitHub Discussions — Ask questions and discuss ideas

### Related Links
- [Hickory DNS](https://github.com/hickory-dns/hickory-dns) — Underlying DNS library
- [AdGuard Filters](https://github.com/AdguardTeam/FiltersRegistry) — Blocklist sources
- [DNSSEC Validation](https://en.wikipedia.org/wiki/DNSSEC) — About DNS security
- [DNS over HTTPS](https://tools.ietf.org/html/rfc8484) — DoH specification
- [DNS over TLS](https://tools.ietf.org/html/rfc7858) — DoT specification
- [DNS over QUIC](https://tools.ietf.org/html/rfc9250) — DoQ specification

---

## License

This project is licensed under the MIT License and/or Apache License 2.0. See the LICENSE file for details.

---

**Last Updated:** May 13, 2026  
**Current Version:** 2.2.0  
**Status:** Stable with experimental zone authority and draft WASM plugin features
