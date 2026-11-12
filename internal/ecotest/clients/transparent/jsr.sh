#!/bin/sh
# jsr — cache JSR packages from jsr.io with Deno, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(deno --version | awk 'NR==1 {print $2}')"

# JSR_URL keeps its default, jsr.io. Deno trusts the proxy's CA through
# DENO_CERT; through a forward proxy it reads HTTPS_PROXY.
export DENO_CERT="$PT_CA_CERT"

deno cache "jsr:$PKG_NAME@$PKG_VERSION"
