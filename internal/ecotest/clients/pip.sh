#!/bin/sh
# pip — point pip at the proxy's PyPI Simple index.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(pip --version | awk '{print $2}')"

# pip.conf (~/.config/pip/pip.conf, or PIP_INDEX_URL / --index-url) replaces
# pypi.org. The proxy rewrites the file links in the Simple pages it serves, so
# wheels and sdists (hosted on files.pythonhosted.org) come back through it too.
printf '[global]\nindex-url = %s/simple/\n' "$MOUNT" > pip.conf
export PIP_CONFIG_FILE="$PWD/pip.conf"

pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore \
    "$PKG_NAME==$PKG_VERSION"
pip show "$PKG_NAME" >/dev/null
