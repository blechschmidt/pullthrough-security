#!/bin/sh
# lab: client=dart pub (an existing lock file, written against pub.dev)
# lab: image=dart:3.5
#
# Moving a project onto the proxy: its pubspec.lock names pub.dev as the hosted
# URL of every package. pub does not follow that URL; with the lock file
# enforced it refuses, and a plain `dart pub get` rewrites the lock file.
set -eu
echo "LAB_CLIENT_VERSION=$(dart --version 2>&1 | awk '{print $4}')"

export PUB_HOSTED_URL=https://proxy.example.com/v1/pub
cp /etc/ssl/corp-ca.pem /usr/local/share/ca-certificates/corp-ca.crt
update-ca-certificates >/dev/null 2>&1
if [ -n "${PROXY_TOKEN:-}" ]; then
    export PULLTHROUGH_TOKEN="${PROXY_TOKEN}"
    dart pub token add https://proxy.example.com/v1/pub --env-var PULLTHROUGH_TOKEN
fi

# A lock file as pub.dev would have produced it.
mkdir app && cd app
cat > pubspec.yaml <<EOF
name: lab
environment:
  sdk: ">=3.0.0 <4.0.0"
dependencies:
  path: 1.9.0
EOF
dart pub get >/dev/null
sed -i 's#https://proxy.example.com/v1/pub/#https://pub.dev#' pubspec.lock
grep -q 'url: "https://pub.dev"' pubspec.lock
rm -rf ~/.pub-cache .dart_tool

# With the lock file enforced, pub refuses rather than fetch from pub.dev.
if dart pub get --enforce-lockfile >enforce.log 2>&1; then
    echo "pub installed a pub.dev lock file as it is: update docs/clients/dart.md"; cat enforce.log; exit 1
fi
grep -q "Unable to satisfy" enforce.log

# A plain `dart pub get` moves the lock file onto the proxy; versions stay.
dart pub get
grep -q 'url: "https://proxy.example.com/v1/pub/"' pubspec.lock
grep -q 'version: "1.9.0"' pubspec.lock
dart pub get --enforce-lockfile
