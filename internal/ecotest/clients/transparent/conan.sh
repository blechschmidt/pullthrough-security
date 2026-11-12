#!/bin/sh
# conan — download recipes from ConanCenter, intercepted by the proxy.
set -eu

# Conan comes from pypi.org, intercepted as well; pip trusts the proxy's CA
# through PIP_CERT. (The proxy content-scans a package the first time it is
# pulled, which for a large wheel can exceed pip's 15 s default read timeout —
# hence --timeout.)
export PIP_CERT="$PT_CA_CERT"
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 conan
echo "ECOTEST_CLIENT_VERSION=$(conan --version | awk '{print $3}')"
export CONAN_HOME="$PWD/conan-home"

# Conan keeps its default remote, conancenter (center2.conan.io). It trusts the
# proxy's CA through core.net.http:cacert_path; through a forward proxy it reads
# HTTPS_PROXY.
mkdir -p "$CONAN_HOME"
echo "core.net.http:cacert_path=$PT_CA_CERT" > "$CONAN_HOME/global.conf"

conan download "$PKG_NAME/$PKG_VERSION" --remote conancenter --only-recipe
conan list "$PKG_NAME/$PKG_VERSION" | grep -q "$PKG_NAME/$PKG_VERSION"
