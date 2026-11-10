#!/bin/sh
# apt — point APT at the proxy's Debian upstream.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(apt-get --version | awk 'NR==1 {print $2}')"

# Replace the distribution's sources with the proxy. The dists/ and pool/ layout
# is preserved and InRelease is served byte-exact, so APT still verifies the
# archive signature with the keys shipped in the image.
rm -f /etc/apt/sources.list.d/*
echo "deb $MOUNT bookworm main" > /etc/apt/sources.list

apt-get update
apt-get install -y --no-install-recommends "$PKG_NAME"
dpkg -s "$PKG_NAME" >/dev/null
