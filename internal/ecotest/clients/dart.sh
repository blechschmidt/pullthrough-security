#!/bin/sh
# dart — use the proxy as the hosted pub repository.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(dart --version 2>&1 | awk '{print $4}')"

# PUB_HOSTED_URL replaces pub.dev for `dart pub` and `flutter pub`. The proxy
# rewrites the archive URLs in the version listings it serves, so the package
# archives come back through it and are verified against the SHA-256 pub.dev
# publishes.
export PUB_HOSTED_URL="$MOUNT"
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
