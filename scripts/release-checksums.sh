#!/usr/bin/env bash
#
# release-checksums.sh — (re)generate a deterministic SHA256SUMS manifest over
# every file in a release directory (Task 135).
#
# Factored out of release-build.sh so CI can regenerate the manifest *after*
# adding SBOMs, ensuring the single cosign signature over SHA256SUMS
# transitively covers the SBOMs too. The manifest is sorted (LC_ALL=C) for
# reproducibility and excludes the manifest + its signature material.
#
# Usage: release-checksums.sh <dir>
set -euo pipefail

DIR="${1:?release directory required}"
cd "${DIR}"

files="$(find . -maxdepth 1 -type f \
  ! -name 'SHA256SUMS*' \
  -printf '%P\n' | LC_ALL=C sort)"

: > SHA256SUMS
for f in ${files}; do
  sha256sum "${f}" >> SHA256SUMS
done

echo "wrote $(pwd)/SHA256SUMS" >&2
cat SHA256SUMS >&2
