#!/usr/bin/env bash
# Rebuilds the WebAssembly extension-gate fixtures from their Go sources.
#
# The fixtures are checked-in prebuilt (.wasm) so `go test ./...` needs no wasm
# toolchain; run this only after changing a guest under src/. Requires Go 1.24+
# (for //go:wasmexport and the wasip1 c-shared reactor build mode).
set -euo pipefail
cd "$(dirname "$0")"

for guest in conformance_gate sample_gate; do
  echo "building ${guest}.wasm"
  ( cd "src/${guest}" && GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o "../../${guest}.wasm" . )
done
echo "done"
