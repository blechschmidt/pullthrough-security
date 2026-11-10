#!/usr/bin/env bash
#
# run-loadtest.sh — end-to-end load test for the pull-through security proxy.
#
# Orchestrates a fully hermetic run:
#   1. builds the proxy and the stub upstream,
#   2. starts the stub upstream (deterministic package + Docker registry),
#   3. starts the proxy pointed at the stub (perf/load/config.loadtest.yaml),
#   4. drives cache-hit, cache-miss, and Docker workloads with k6,
#   5. writes a JSON summary under perf/load/results/ and tears everything down.
#
# No public registries are contacted. Requires: go, k6 (https://k6.io/docs/get-started/installation/).
#
# Usage:
#   perf/run-loadtest.sh                 # default 20 VUs x 30s per scenario
#   VUS=50 DURATION=1m perf/run-loadtest.sh
#
# Env knobs:
#   VUS, DURATION   forwarded to k6 (per-scenario virtual users / duration)
#   PROXY_PORT      proxy listen port (default 8080)
#   STUB_PORT       stub upstream port (default 9000)
#   BLOBS           number of synthetic Docker blobs (default 50)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PROXY_PORT="${PROXY_PORT:-8080}"
STUB_PORT="${STUB_PORT:-9000}"
BLOBS="${BLOBS:-50}"
VUS="${VUS:-20}"
DURATION="${DURATION:-30s}"
GO="${GO:-go}"
export PATH="/usr/local/go/bin:$PATH"

RESULTS_DIR="$REPO_ROOT/perf/load/results"
CACHE_DIR="$REPO_ROOT/.perf-cache"
BIN_DIR="$REPO_ROOT/bin"
mkdir -p "$RESULTS_DIR" "$BIN_DIR"

if ! command -v k6 >/dev/null 2>&1; then
  echo "ERROR: k6 is not installed. See https://k6.io/docs/get-started/installation/" >&2
  echo "       (e.g. 'sudo apt-get install k6' or 'brew install k6')" >&2
  exit 127
fi

echo ">> building proxy + stub upstream"
$GO build -o "$BIN_DIR/pullthrough" ./cmd/pullthrough
$GO build -o "$BIN_DIR/stubupstream" ./perf/stubupstream

STUB_PID=""
PROXY_PID=""
cleanup() {
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
  [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Start with a cold cache so the cache-miss scenario truly cold-fills.
rm -rf "$CACHE_DIR"

echo ">> starting stub upstream on :$STUB_PORT"
"$BIN_DIR/stubupstream" -addr ":$STUB_PORT" -blobs "$BLOBS" >"$RESULTS_DIR/stub.log" 2>&1 &
STUB_PID=$!

wait_ready() {
  local url="$1" name="$2"
  for _ in $(seq 1 50); do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  echo "ERROR: $name did not become ready at $url" >&2
  return 1
}

wait_ready "http://127.0.0.1:$STUB_PORT/healthz" "stub upstream"

DOCKER_BLOBS="$(curl -fsS "http://127.0.0.1:$STUB_PORT/_perf/digests?kind=blobs")"
DOCKER_MANIFESTS="$(curl -fsS "http://127.0.0.1:$STUB_PORT/_perf/digests?kind=manifests")"
export DOCKER_BLOBS DOCKER_MANIFESTS

echo ">> starting proxy on :$PROXY_PORT"
"$BIN_DIR/pullthrough" -config perf/load/config.loadtest.yaml >"$RESULTS_DIR/proxy.log" 2>&1 &
PROXY_PID=$!

wait_ready "http://127.0.0.1:$PROXY_PORT/readyz" "proxy"

STAMP="$(date +%Y%m%d-%H%M%S)"
SUMMARY="$RESULTS_DIR/summary-$STAMP.json"
echo ">> running k6 (VUS=$VUS DURATION=$DURATION per scenario)"
PROXY_URL="http://127.0.0.1:$PROXY_PORT" \
  k6 run \
  --summary-export "$SUMMARY" \
  perf/load/k6/proxy_load.js

echo
echo ">> summary written to $SUMMARY"
echo ">> proxy log: $RESULTS_DIR/proxy.log   stub log: $RESULTS_DIR/stub.log"
