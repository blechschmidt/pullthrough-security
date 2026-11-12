#!/bin/sh
# generic — apk from the Alpine mirror, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(apk --version | awk '{ print $2 }' | tr -d ,)"

# /etc/apk/repositories stays as the image ships it: the main and community
# repositories on dl-cdn.alpinelinux.org. apk reads the system CA bundle, so
# the proxy's CA is appended to it; through a forward proxy it reads
# HTTPS_PROXY.
cat "$PT_CA_CERT" >> /etc/ssl/certs/ca-certificates.crt
apk add --no-cache "$PKG_NAME"
apk info -e "$PKG_NAME"
