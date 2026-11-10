#!/usr/bin/env bash
#
# release-repro-check.sh — prove the release build is reproducible (Task 135).
#
# Builds the given variant twice into two separate output directories and
# compares the per-file SHA-256 digests. This is the same digest-equality
# comparison the proxy's reproducible-build verification gate (internal/
# rebuildverify) applies to third-party artifacts, turned inward on our own
# release: if the two independent builds disagree on any digest, the build is
# not reproducible and the release is aborted.
#
# Usage:
#   release-repro-check.sh <variant> <version> [platform ...]
set -euo pipefail

VARIANT="${1:?variant (standard|fips) required}"
VERSION="${2:?version required}"
shift 2
PLATFORMS=("$@")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

A="${WORK}/run-a"
B="${WORK}/run-b"

"${SCRIPT_DIR}/release-build.sh" "${VARIANT}" "${VERSION}" "${A}" "${PLATFORMS[@]}"
"${SCRIPT_DIR}/release-build.sh" "${VARIANT}" "${VERSION}" "${B}" "${PLATFORMS[@]}"

# Compare the checksum manifests (which list every built artifact's digest).
if diff -u "${A}/SHA256SUMS" "${B}/SHA256SUMS"; then
  echo "OK: ${VARIANT} release build is reproducible (identical digests across two runs)" >&2
else
  echo "FAIL: ${VARIANT} release build is NOT reproducible (digests differ across two runs)" >&2
  exit 1
fi
