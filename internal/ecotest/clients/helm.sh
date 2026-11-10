#!/bin/sh
# helm — add the proxy as a chart repository.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(helm version --short)"

# `helm repo add` with the proxy mount replaces the upstream chart repository.
# The proxy rewrites the chart URLs in the index.yaml it serves, so the chart
# archive comes back through it (and is verified against the index digest) even
# when the upstream hosts its archives on another host.
helm repo add pullthrough "$MOUNT"
helm repo update

helm pull "pullthrough/$PKG_NAME" --version "$PKG_VERSION"
test -s "$PKG_NAME-$PKG_VERSION.tgz"
