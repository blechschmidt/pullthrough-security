#!/usr/bin/env bash
#
# release-build.sh — deterministic, reproducible release build of the
# pullthrough-security binaries (Task 135).
#
# This is the single source of truth for how a release binary is compiled, used
# by both `make release*` and the release CI workflow, so a locally reproduced
# build is bit-for-bit identical to the published one. Determinism is achieved
# with:
#
#   - CGO_ENABLED=0          : a pure-Go static binary, no host C toolchain.
#   - -trimpath              : strip absolute $GOPATH/module paths from the binary.
#   - -buildid=              : clear the non-deterministic build id.
#   - -buildvcs=false        : do not stamp VCS state (commit/dirty) into the
#                              binary; the version is injected explicitly below.
#   - GOFLAGS=-mod=readonly  : fail rather than mutate go.mod/go.sum.
#   - GOTOOLCHAIN (pinned)   : the exact Go toolchain is pinned by the go.mod `go`
#                              directive (CI installs it via setup-go); set
#                              GOTOOLCHAIN=local to use the installed toolchain.
#   - a fixed build order and sorted checksum manifest.
#
# Usage:
#   release-build.sh <variant> <version> <out-dir> [platform ...]
#     variant   : standard | fips
#     version   : version string stamped via -ldflags -X main.version
#     out-dir   : directory to write binaries + SHA256SUMS into (created)
#     platform  : one or more GOOS/GOARCH pairs (default: linux/amd64 linux/arm64)
#
# Environment:
#   GOFIPS140  : FIPS module selector for the `fips` variant (default: latest)
#   SELFRELEASE_LDFLAGS : extra -X overrides for internal/selfrelease identity
#                         (optional; the compile-time defaults already pin the
#                         repository's release workflow)
set -euo pipefail

VARIANT="${1:?variant (standard|fips) required}"
VERSION="${2:?version required}"
OUT_DIR="${3:?output directory required}"
shift 3
PLATFORMS=("$@")
if [ "${#PLATFORMS[@]}" -eq 0 ]; then
  PLATFORMS=(linux/amd64 linux/arm64)
fi

PKG_SERVER="./cmd/pullthrough"
PKG_CLIENT="./cmd/ptctl"
# To pin the embedded verify-self identity to a fork's release workflow, pass
# SELFRELEASE_LDFLAGS, e.g.:
#   SELFRELEASE_LDFLAGS='-X github.com/blechschmidt/pullthrough-security/internal/selfrelease.CertificateIdentityPattern=...'

# Reproducible build environment.
export CGO_ENABLED=0
export GOFLAGS="-mod=readonly"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
# SOURCE_DATE_EPOCH is honored by downstream packaging; exported for consistency.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

LDFLAGS="-s -w -buildid= -X main.version=${VERSION} ${SELFRELEASE_LDFLAGS:-}"
TAGS=""
SUFFIX=""
case "${VARIANT}" in
  standard) ;;
  fips)
    TAGS="fips"
    SUFFIX="-fips"
    export GOFIPS140="${GOFIPS140:-latest}"
    ;;
  *) echo "unknown variant: ${VARIANT}" >&2; exit 2 ;;
esac

mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"

build_one() {
  local pkg="$1" name="$2" goos="$3" goarch="$4"
  local ext=""
  [ "${goos}" = "windows" ] && ext=".exe"
  local out="${OUT_DIR}/${name}${SUFFIX}-${goos}-${goarch}${ext}"
  echo "==> building ${out} (variant=${VARIANT} tags='${TAGS}')" >&2
  GOOS="${goos}" GOARCH="${goarch}" \
    go build -trimpath -buildvcs=false \
      ${TAGS:+-tags "${TAGS}"} \
      -ldflags "${LDFLAGS}" \
      -o "${out}" "${pkg}"
}

for p in "${PLATFORMS[@]}"; do
  goos="${p%%/*}"
  goarch="${p##*/}"
  build_one "${PKG_SERVER}" "pullthrough" "${goos}" "${goarch}"
  build_one "${PKG_CLIENT}" "ptctl" "${goos}" "${goarch}"
done

# Deterministic checksum manifest (sorted by filename). Includes any SBOMs an
# earlier step already placed in the directory so the signature over SHA256SUMS
# transitively covers them. CI regenerates this after adding SBOMs via the same
# script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"${SCRIPT_DIR}/release-checksums.sh" "${OUT_DIR}"

echo "==> release build complete: ${OUT_DIR}" >&2
