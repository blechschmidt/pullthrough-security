#!/bin/sh
# nix — use the proxy as the only binary-cache substituter.
set -eu
version=$(nix --version)
echo "ECOTEST_CLIENT_VERSION=${version##* }"

# `substituters` replaces cache.nixos.org; `trusted-public-keys` stays the
# upstream cache's key, because the proxy serves the signed narinfo unmodified
# apart from the (unsigned) NAR URL. require-sigs keeps Nix verifying every path.
# PKG_STORE_PATH is the store path to substitute.
nix-store --realise "$PKG_STORE_PATH" \
    --option substituters "$MOUNT" \
    --option trusted-public-keys "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" \
    --option require-sigs true
test -e "$PKG_STORE_PATH"
