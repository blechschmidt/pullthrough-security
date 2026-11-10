#!/bin/sh
# homebrew — route the formula API and bottle downloads through the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(brew --version | awk 'NR==1 {print $2}')"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1
export HOMEBREW_NO_INSTALL_CLEANUP=1

# HOMEBREW_API_DOMAIN replaces formulae.brew.sh (the signed formula index);
# HOMEBREW_ARTIFACT_DOMAIN replaces ghcr.io for bottle manifests and blobs. Both
# are required: the index is signed and cannot be rewritten, so it is brew itself
# that redirects bottle downloads to the artifact domain.
export HOMEBREW_API_DOMAIN="$MOUNT/api"
export HOMEBREW_ARTIFACT_DOMAIN="$MOUNT"

brew fetch --force "$PKG_NAME"
