#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_check() {
	local label="$1"
	shift

	printf '\n[release-check] Running %s\n' "$*"
	"$@"
	printf '[release-check] PASS %s\n' "$label"
}

if ! command -v gitleaks >/dev/null 2>&1; then
	echo "ERROR: gitleaks is required but was not found in PATH" >&2
	exit 1
fi

run_check "gitleaks" gitleaks detect --no-banner --redact
run_check "cargo fmt check" cargo fmt --all -- --check
run_check "cargo test --all-targets --all-features" cargo test --all-targets --all-features
run_check "cargo clippy --all-targets --all-features -- -D warnings" cargo clippy --all-targets --all-features -- -D warnings

