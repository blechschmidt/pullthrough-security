#!/bin/sh
# go — fetch modules from proxy.golang.org, intercepted by the proxy.
set -eu
version=$(go env GOVERSION)
echo "ECOTEST_CLIENT_VERSION=${version#go}"

# GOPROXY and GOSUMDB keep their defaults (proxy.golang.org, sum.golang.org).
# The go command trusts the proxy's CA through SSL_CERT_FILE; through a forward
# proxy it reads HTTPS_PROXY. Checksum verification stays on: the go command
# asks proxy.golang.org whether it proxies the checksum database, and the proxy
# says it does — so sum.golang.org itself is never contacted.
export SSL_CERT_FILE="$PT_CA_CERT"
export GOFLAGS=-mod=mod GOTOOLCHAIN=local

mkdir app
cd app
go mod init example.com/ecotest >/dev/null 2>&1
go get "$PKG_NAME@$PKG_VERSION"
