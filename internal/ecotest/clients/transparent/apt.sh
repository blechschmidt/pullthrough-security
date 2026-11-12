#!/bin/sh
# apt — install from the image's own Debian sources, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(apt-get --version | awk 'NR==1 {print $2}')"

# The image's sources stay as they are: http://deb.debian.org/debian (and
# debian-security), over plain HTTP. There is no certificate to trust — APT
# verifies the archive's own signatures, which the proxy serves byte-exact.
# Through a forward proxy APT reads http_proxy from the environment (or
# Acquire::http::Proxy).
apt-get update
apt-get install -y --no-install-recommends "$PKG_NAME"
dpkg -s "$PKG_NAME" >/dev/null
