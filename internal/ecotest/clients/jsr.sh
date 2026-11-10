#!/bin/sh
# jsr — point Deno at the proxy's JSR upstream.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(deno --version | awk 'NR==1 {print $2}')"

# JSR_URL replaces jsr.io for package metadata and module files.
export JSR_URL="$MOUNT"

deno cache "jsr:$PKG_NAME@$PKG_VERSION"
