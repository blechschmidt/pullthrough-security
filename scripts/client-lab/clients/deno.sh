#!/bin/sh
# lab: client=Deno
# lab: image=denoland/deno:debian-2.9.8
#
# Deno: JSR packages through the proxy's JSR upstream, npm packages through its
# npm upstream.
set -eu
echo "LAB_CLIENT_VERSION=$(deno --version | awk 'NR==1 {print $2}')"

export JSR_URL=https://proxy.example.com/v1/jsr
export DENO_CERT=/etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    # A bearer token per host, for JSR and for remote modules.
    export DENO_AUTH_TOKENS="${PROXY_TOKEN}@proxy.example.com"
fi

deno cache "jsr:@luca/flag@1.0.1"

mkdir app && cd app
echo '{}' > deno.json
deno add jsr:@luca/flag@1.0.1

# npm: specifiers are resolved the way npm resolves them — from .npmrc, in the
# project or in the home directory.
cat > .npmrc <<EOF
registry=https://proxy.example.com/v1/npm/
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
cat >> .npmrc <<EOF
//proxy.example.com/v1/npm/:_authToken=${PROXY_TOKEN}
EOF
fi
deno cache npm:is-number@7.0.0

# deno.lock records an integrity hash for a JSR package and nothing else; for an
# npm package from a registry other than npmjs.org it also records the tarball's
# URL — the proxy's.
grep -q '"jsr:@luca/flag@1.0.1": "1.0.1"' deno.lock
grep -q '"tarball": "https://proxy.example.com/v1/npm/is-number/-/is-number-7.0.0.tgz"' deno.lock
test "$(grep -c 'proxy.example.com' deno.lock)" = 1
