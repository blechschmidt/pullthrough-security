#!/bin/sh
# helm — pull charts from the chart repository's own URL, intercepted by the
# proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(helm version --short)"

# The repository is added under its own URL. helm trusts the proxy's CA through
# SSL_CERT_FILE (or --ca-file); through a forward proxy it reads HTTPS_PROXY.
# The proxy moves the chart URLs in the index.yaml onto the repository's host,
# so the chart archive is intercepted (and verified against the index digest)
# too.
export SSL_CERT_FILE="$PT_CA_CERT"

helm repo add podinfo https://stefanprodan.github.io/podinfo
helm repo update

helm pull "podinfo/$PKG_NAME" --version "$PKG_VERSION"
test -s "$PKG_NAME-$PKG_VERSION.tgz"
