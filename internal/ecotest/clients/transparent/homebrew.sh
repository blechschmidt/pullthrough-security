#!/bin/sh
# homebrew — fetch bottles with brew's built-in API and artifact domains,
# intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(brew --version | awk 'NR==1 {print $2}')"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1
export HOMEBREW_NO_INSTALL_CLEANUP=1

# No HOMEBREW_API_DOMAIN, no HOMEBREW_ARTIFACT_DOMAIN: brew keeps
# formulae.brew.sh (the signed formula index) and ghcr.io (the bottles). Its
# curl trusts the proxy's CA through a curlrc that HOMEBREW_CURLRC names;
# through a forward proxy brew passes HTTPS_PROXY on to curl.
echo "cacert = \"$PT_CA_CERT\"" > "$PWD/curlrc"
export HOMEBREW_CURLRC="$PWD/curlrc"

brew fetch --force "$PKG_NAME"
