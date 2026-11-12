#!/bin/sh
# nix — substitute store paths from cache.nixos.org, intercepted by the proxy.
set -eu
version=$(nix --version)
echo "ECOTEST_CLIENT_VERSION=${version##* }"

# The substituter and its key stay the defaults (cache.nixos.org). Nix trusts
# the proxy's CA through NIX_SSL_CERT_FILE; through a forward proxy it reads
# https_proxy. The narinfo is signed and served unmodified apart from its
# (unsigned) NAR URL, so require-sigs keeps Nix verifying every path.
# PKG_STORE_PATH is the store path to substitute.
export NIX_SSL_CERT_FILE="$PT_CA_CERT"
nix-store --realise "$PKG_STORE_PATH" --option require-sigs true
test -e "$PKG_STORE_PATH"
