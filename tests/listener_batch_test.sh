#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${BINARY:-$ROOT_DIR/target/debug/dns-filter}"
DOMAIN="${DOMAIN:-example.com}"
STRICT=0
KEEP_ARTIFACTS=0

DNS_HOST="127.0.0.1"
DNS_PORT="15353"
DOT_PORT="1853"
DOH_PORT="1443"
DOQ_PORT="18853"
HTTP_PORT="18080"
METRICS_PORT="19100"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

TEMP_DIR=""
PID=""
LOG_FILE=""

usage() {
  cat <<'EOF'
Usage: tests/listener_batch_test.sh [options]

Options:
  --strict            Fail when non-DNS listeners are not reachable
  --keep-artifacts    Keep temp config/log directory
  --binary PATH       Path to dns-filter binary (default: target/debug/dns-filter)
  --domain NAME       Domain for DNS queries (default: example.com)
  -h, --help          Show this help

Environment overrides:
  BINARY, DOMAIN
EOF
}

note() {
  printf '[INFO] %s\n' "$1"
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[PASS] %s\n' "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '[FAIL] %s\n' "$1"
}

skip() {
  SKIP_COUNT=$((SKIP_COUNT + 1))
  printf '[SKIP] %s\n' "$1"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

has_tcp_connect() {
  local host="$1"
  local port="$2"

  if command_exists nc; then
    nc -z "$host" "$port" >/dev/null 2>&1
    return $?
  fi

  if command_exists timeout; then
    timeout 1 bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
    return $?
  fi

  bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
}

cleanup() {
  if [ -n "$PID" ] && kill -0 "$PID" >/dev/null 2>&1; then
    kill "$PID" >/dev/null 2>&1 || true
    wait "$PID" 2>/dev/null || true
  fi

  if [ "$KEEP_ARTIFACTS" -ne 1 ] && [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
    rm -rf "$TEMP_DIR"
  fi
}

trap cleanup EXIT

while [ "$#" -gt 0 ]; do
  case "$1" in
    --strict)
      STRICT=1
      ;;
    --keep-artifacts)
      KEEP_ARTIFACTS=1
      ;;
    --binary)
      shift
      BINARY="${1:-}"
      ;;
    --domain)
      shift
      DOMAIN="${1:-}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift

done

if [ -z "$BINARY" ]; then
  printf 'Binary path cannot be empty\n' >&2
  exit 2
fi

if [ ! -x "$BINARY" ]; then
  note "Building debug binary because $BINARY is missing"
  (cd "$ROOT_DIR" && cargo build) || {
    printf 'Failed to build binary\n' >&2
    exit 1
  }
fi

TEMP_DIR="$(mktemp -d)"
CONFIG_FILE="$TEMP_DIR/config.yaml"
LOG_FILE="$TEMP_DIR/dns-filter.log"

cat >"$CONFIG_FILE" <<EOF
listen:
  dns:
    enabled: true
    address: "$DNS_HOST"
    port: $DNS_PORT
  dot:
    enabled: true
    address: "$DNS_HOST"
    port: $DOT_PORT
    tls:
      cert_path: "$TEMP_DIR/cert.pem"
      key_path: "$TEMP_DIR/key.pem"
      autogenerate: true
  doh:
    enabled: true
    address: "$DNS_HOST"
    port: $DOH_PORT
    tls:
      cert_path: "$TEMP_DIR/cert.pem"
      key_path: "$TEMP_DIR/key.pem"
      autogenerate: true
  doq:
    enabled: true
    address: "$DNS_HOST"
    port: $DOQ_PORT
    tls:
      cert_path: "$TEMP_DIR/cert.pem"
      key_path: "$TEMP_DIR/key.pem"
      autogenerate: true
  http:
    enabled: true
    address: "$DNS_HOST"
    port: $HTTP_PORT
  metrics:
    enabled: true
    address: "$DNS_HOST"
    port: $METRICS_PORT

blocklists: []
allowlists: []

filtering:
  any_query_policy: "passthrough"

upstreams:
  strategy: "round_robin"
  bootstrap_resolvers:
    - "1.1.1.1"
  servers:
    - enabled: true
      protocol: "dns"
      address: "1.1.1.1:53"

logging:
  syslog: null
  file: null
  stdout:
    enabled: true
    level: "info"
EOF

note "Starting dns-filter with temporary config: $CONFIG_FILE"
"$BINARY" --config "$CONFIG_FILE" >"$LOG_FILE" 2>&1 &
PID=$!

wait_for_dns() {
  local i
  for i in $(seq 1 40); do
    if has_tcp_connect "$DNS_HOST" "$DNS_PORT"; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

if wait_for_dns; then
  pass "dns listener accepted TCP connections on ${DNS_HOST}:${DNS_PORT}"
else
  fail "dns listener did not start on ${DNS_HOST}:${DNS_PORT}"
  note "dns-filter log follows"
  sed -n '1,160p' "$LOG_FILE"
  printf '\nSummary: pass=%d fail=%d skip=%d\n' "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
  exit 1
fi

dns_query_udp() {
  local output

  if command_exists dig; then
    output="$(dig @"$DNS_HOST" -p "$DNS_PORT" "$DOMAIN" A +time=2 +tries=1 2>&1)" || return 1
    [[ "$output" == *"status:"* ]]
    return $?
  fi

  if command_exists drill; then
    output="$(drill @"$DNS_HOST" -p "$DNS_PORT" "$DOMAIN" A 2>&1)" || return 1
    [[ "$output" == *"ANSWER SECTION"* || "$output" == *"rcode:"* ]]
    return $?
  fi

  if command_exists kdig; then
    output="$(kdig @"$DNS_HOST" -p "$DNS_PORT" "$DOMAIN" A 2>&1)" || return 1
    [[ "$output" == *"status:"* ]]
    return $?
  fi

  return 2
}

dns_query_tcp() {
  local output

  if command_exists dig; then
    output="$(dig +tcp @"$DNS_HOST" -p "$DNS_PORT" "$DOMAIN" A +time=2 +tries=1 2>&1)" || return 1
    [[ "$output" == *"status:"* ]]
    return $?
  fi

  if command_exists drill; then
    output="$(drill -T @"$DNS_HOST" -p "$DNS_PORT" "$DOMAIN" A 2>&1)" || return 1
    [[ "$output" == *"ANSWER SECTION"* || "$output" == *"rcode:"* ]]
    return $?
  fi

  if command_exists kdig; then
    output="$(kdig +tcp @"$DNS_HOST" -p "$DNS_PORT" "$DOMAIN" A 2>&1)" || return 1
    [[ "$output" == *"status:"* ]]
    return $?
  fi

  return 2
}

if dns_query_udp; then
  pass "dns UDP query succeeded"
else
  rc=$?
  if [ "$rc" -eq 2 ]; then
    skip "dns UDP query skipped (install dig, drill, or kdig)"
  else
    fail "dns UDP query failed"
  fi
fi

if dns_query_tcp; then
  pass "dns TCP query succeeded"
else
  rc=$?
  if [ "$rc" -eq 2 ]; then
    skip "dns TCP query skipped (install dig, drill, or kdig)"
  else
    fail "dns TCP query failed"
  fi
fi

check_optional_listener_port() {
  local listener_name="$1"
  local port="$2"

  if has_tcp_connect "$DNS_HOST" "$port"; then
    pass "$listener_name port is reachable on ${DNS_HOST}:${port}"
    return 0
  fi

  if [ "$STRICT" -eq 1 ]; then
    fail "$listener_name port is not reachable on ${DNS_HOST}:${port}"
  else
    skip "$listener_name port is not reachable (currently expected until listener startup is wired)"
  fi

  return 1
}

if check_optional_listener_port "DoT" "$DOT_PORT"; then
  if command_exists kdig; then
    if kdig +tls @"$DNS_HOST" -p "$DOT_PORT" "$DOMAIN" A >/dev/null 2>&1; then
      pass "DoT query succeeded"
    else
      fail "DoT query failed (kdig +tls)"
    fi
  elif command_exists openssl; then
    if echo | openssl s_client -connect "$DNS_HOST:$DOT_PORT" -servername localhost -brief >/dev/null 2>&1; then
      pass "DoT TLS handshake succeeded"
    else
      fail "DoT TLS handshake failed"
    fi
  else
    skip "DoT protocol check skipped (install kdig or openssl)"
  fi
fi

if check_optional_listener_port "DoH" "$DOH_PORT"; then
  if command_exists kdig; then
    if kdig +https @"$DNS_HOST" -p "$DOH_PORT" "$DOMAIN" A >/dev/null 2>&1; then
      pass "DoH query succeeded"
    else
      fail "DoH query failed (kdig +https)"
    fi
  elif command_exists curl; then
    http_code="$(curl -skS -o /dev/null -w "%{http_code}" "https://$DNS_HOST:$DOH_PORT/dns-query" 2>/dev/null || true)"
    if [ "$http_code" != "000" ] && [ -n "$http_code" ]; then
      pass "DoH HTTP endpoint responded with code $http_code"
    else
      fail "DoH HTTP endpoint did not respond"
    fi
  else
    skip "DoH protocol check skipped (install kdig or curl)"
  fi
fi

if check_optional_listener_port "HTTP" "$HTTP_PORT"; then
  if command_exists curl; then
    http_code="$(curl -sS -o /dev/null -w "%{http_code}" "http://$DNS_HOST:$HTTP_PORT/" 2>/dev/null || true)"
    if [ "$http_code" != "000" ] && [ -n "$http_code" ]; then
      pass "HTTP listener responded with code $http_code"
    else
      fail "HTTP listener did not respond"
    fi
  else
    skip "HTTP check skipped (install curl)"
  fi
fi

if check_optional_listener_port "Metrics" "$METRICS_PORT"; then
  if command_exists curl; then
    metrics_body="$(curl -sS "http://$DNS_HOST:$METRICS_PORT/metrics" 2>/dev/null || true)"
    if [ -n "$metrics_body" ]; then
      pass "metrics endpoint returned a response body"
    else
      fail "metrics endpoint returned no body"
    fi
  else
    skip "metrics check skipped (install curl)"
  fi
fi

if command_exists kdig; then
  if kdig +quic @"$DNS_HOST" -p "$DOQ_PORT" "$DOMAIN" A >/dev/null 2>&1; then
    pass "DoQ query succeeded"
  else
    if [ "$STRICT" -eq 1 ]; then
      fail "DoQ query failed (kdig +quic)"
    else
      skip "DoQ query failed (currently expected until listener startup is wired)"
    fi
  fi
else
  skip "DoQ check skipped (install kdig)"
fi

note "listener process log: $LOG_FILE"
printf '\nSummary: pass=%d fail=%d skip=%d\n' "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"

if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi

exit 0
