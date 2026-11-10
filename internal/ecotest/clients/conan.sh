#!/bin/sh
# conan — use the proxy as the only Conan remote.
set -eu

# Conan itself is a Python package; install it through the proxy's PyPI upstream.
# (The proxy content-scans a package the first time it is pulled, which for a
# large wheel can exceed pip's 15 s default read timeout — hence --timeout.)
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --index-url "$PROXY_URL/v1/pip/simple/" conan
echo "ECOTEST_CLIENT_VERSION=$(conan --version | awk '{print $3}')"
export CONAN_HOME="$PWD/conan-home"

# Remove ConanCenter and register the proxy mount as the only remote, so every
# recipe and binary lookup goes through the proxy.
conan remote remove conancenter
conan remote add pullthrough "$MOUNT"

# Download the recipe (conanfile, sources descriptor, export archives).
conan download "$PKG_NAME/$PKG_VERSION" --remote pullthrough --only-recipe
conan list "$PKG_NAME/$PKG_VERSION" | grep -q "$PKG_NAME/$PKG_VERSION"
