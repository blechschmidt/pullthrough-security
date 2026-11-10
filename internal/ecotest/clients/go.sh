#!/bin/sh
# go — use the proxy as GOPROXY.
set -eu
version=$(go env GOVERSION)
echo "ECOTEST_CLIENT_VERSION=${version#go}"

# GOPROXY (or `go env -w GOPROXY=...`) replaces proxy.golang.org. Without a
# ",direct" suffix every module comes from the proxy (with it, a module the proxy
# answers 404 for would be fetched straight from its VCS host).
#
# Checksum verification stays on: the proxy also serves the checksum database
# (sum.golang.org) under $MOUNT/sumdb/, which the go command discovers by itself,
# so no GONOSUMDB / GOFLAGS=-insecure is needed even when the proxy is the only
# host the client can reach.
export GOPROXY="$MOUNT"
export GOFLAGS=-mod=mod GOTOOLCHAIN=local

mkdir app
cd app
go mod init example.com/ecotest >/dev/null 2>&1
go get "$PKG_NAME@$PKG_VERSION"
