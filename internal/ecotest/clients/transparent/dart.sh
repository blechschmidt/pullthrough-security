#!/bin/sh
# dart — get packages from pub.dev, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(dart --version 2>&1 | awk '{print $4}')"

# PUB_HOSTED_URL keeps its default, pub.dev. Dart reads the system trust store,
# so the proxy's CA is added to it; through a forward proxy pub reads
# HTTPS_PROXY. The proxy moves the archive URLs in the version listings onto
# pub.dev, so the archives are intercepted (and verified against the SHA-256
# pub.dev publishes) too.
cp "$PT_CA_CERT" /usr/local/share/ca-certificates/pullthrough-intercept.crt
update-ca-certificates >/dev/null
export PUB_CACHE="$PWD/pub-cache"

mkdir app
cd app
cat > pubspec.yaml <<PUBSPEC
name: ecotest
environment:
  sdk: ">=3.0.0 <4.0.0"
dependencies:
  $PKG_NAME: $PKG_VERSION
PUBSPEC
dart pub get
test -d "$PUB_CACHE/hosted"
