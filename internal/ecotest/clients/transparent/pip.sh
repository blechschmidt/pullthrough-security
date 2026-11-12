#!/bin/sh
# pip — install from pypi.org, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(pip --version | awk '{print $2}')"

# pip keeps its default index. It trusts the proxy's CA through PIP_CERT (or
# REQUESTS_CA_BUNDLE, or `pip config set global.cert`); through a forward proxy
# it reads HTTPS_PROXY from the environment. The proxy moves the file links in
# the Simple pages onto pypi.org, so wheels — files.pythonhosted.org's, as
# published — are intercepted too.
export PIP_CERT="$PT_CA_CERT"

pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore \
    "$PKG_NAME==$PKG_VERSION"
pip show "$PKG_NAME" >/dev/null
