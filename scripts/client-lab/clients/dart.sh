#!/bin/sh
# lab: client=dart pub
# lab: image=dart:3.5
set -eu
echo "LAB_CLIENT_VERSION=$(dart --version 2>&1 | awk '{print $4}')"

export PUB_HOSTED_URL=https://proxy.example.com/v1/pub
# dart pub uses the system trust store, and nothing else: neither SSL_CERT_FILE
# nor the VM's --root-certs-file reaches it. Add the CA to the store.
cp /etc/ssl/corp-ca.pem /usr/local/share/ca-certificates/corp-ca.crt
update-ca-certificates >/dev/null 2>&1

if [ -n "${PROXY_TOKEN:-}" ]; then
    # pub sends a bearer token to a hosted URL it has one for. The token is
    # read from an environment variable, so it is stored nowhere.
    export PULLTHROUGH_TOKEN="${PROXY_TOKEN}"
    dart pub token add https://proxy.example.com/v1/pub --env-var PULLTHROUGH_TOKEN
fi

mkdir app && cd app
cat > pubspec.yaml <<EOF
name: lab
environment:
  sdk: ">=3.0.0 <4.0.0"
dependencies:
  path: 1.9.0
EOF
dart pub get

# pubspec.lock records the hosted URL of every package: the proxy's.
grep -q 'url: "https://proxy.example.com/v1/pub/"' pubspec.lock

# The environment alone is not enough for the CA.
if SSL_CERT_FILE=/etc/ssl/corp-ca.pem sh -c 'rm -f /etc/ssl/certs/corp-ca.pem /usr/local/share/ca-certificates/corp-ca.crt && update-ca-certificates --fresh >/dev/null 2>&1 && rm -rf ~/.pub-cache pubspec.lock .dart_tool && dart pub get' >env.log 2>&1; then
    echo "dart pub trusted a CA named in SSL_CERT_FILE: update docs/clients/dart.md"; cat env.log; exit 1
fi
grep -q "TLS error" env.log
