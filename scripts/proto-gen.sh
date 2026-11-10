#!/usr/bin/env bash
# Regenerate the committed Go stubs for the gRPC/Connect security API (Task 159)
# from proto/pullthrough/security/v1/security.proto.
#
# The generated code is committed under internal/grpcapi/gen so the build never
# runs protoc or fetches a codegen plugin: this script is a developer convenience
# run only when the proto changes. It pins the plugin versions to the versions
# the committed stubs were generated with, so regeneration is reproducible.
#
# Requirements: protoc on PATH (any 3.x with the well-known types) and a Go
# toolchain. The plugins are installed into $(go env GOPATH)/bin on demand.
set -euo pipefail

cd "$(dirname "$0")/.."

PROTOC_GEN_GO_VERSION="v1.36.11"
PROTOC_GEN_CONNECT_GO_VERSION="v1.18.1"

if ! command -v protoc >/dev/null 2>&1; then
  echo "proto-gen: protoc not found on PATH; install the Protocol Buffers compiler" >&2
  exit 1
fi

GOBIN="$(go env GOPATH)/bin"
export PATH="$GOBIN:$PATH"

echo "proto-gen: installing codegen plugins (pinned)"
go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
go install "connectrpc.com/connect/cmd/protoc-gen-connect-go@${PROTOC_GEN_CONNECT_GO_VERSION}"

# Resolve the protoc well-known-type include dir (google/protobuf/struct.proto).
WKT_INCLUDE=""
for d in /usr/include /usr/local/include /opt/homebrew/include; do
  if [ -f "$d/google/protobuf/struct.proto" ]; then
    WKT_INCLUDE="$d"
    break
  fi
done
if [ -z "$WKT_INCLUDE" ]; then
  echo "proto-gen: could not find google/protobuf/struct.proto in the protoc include path" >&2
  exit 1
fi

echo "proto-gen: generating stubs into internal/grpcapi/gen"
protoc \
  -I proto -I "$WKT_INCLUDE" \
  --go_out=. --go_opt=module=github.com/blechschmidt/pullthrough-security \
  --connect-go_out=. --connect-go_opt=module=github.com/blechschmidt/pullthrough-security \
  proto/pullthrough/security/v1/security.proto

echo "proto-gen: done"
