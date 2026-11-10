#!/bin/sh
# ansible — use the proxy as the only Ansible Galaxy server.
set -eu

# ansible-core is a Python package; install it through the proxy's PyPI upstream.
# (The proxy content-scans a package the first time it is pulled, which for a
# large wheel can exceed pip's 15 s default read timeout — hence --timeout.)
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --index-url "$PROXY_URL/v1/pip/simple/" ansible-core
echo "ECOTEST_CLIENT_VERSION=$(ansible-galaxy --version | awk 'NR==1 {print $3}' | tr -d ']')"

# A [galaxy_server.*] entry whose url is the proxy mount (trailing slash
# included) replaces galaxy.ansible.com. The proxy rewrites the links in the API
# documents it serves, so the collection tarball comes back through it and is
# verified against the SHA-256 Galaxy publishes.
cat > ansible.cfg <<ANSIBLECFG
[galaxy]
server_list = pullthrough

[galaxy_server.pullthrough]
url = $MOUNT/
ANSIBLECFG
export ANSIBLE_CONFIG="$PWD/ansible.cfg"

# PKG_NAME is "<namespace>.<collection>".
ansible-galaxy collection install "$PKG_NAME:$PKG_VERSION" --collections-path "$PWD/collections"
test -d "collections/ansible_collections/$(echo "$PKG_NAME" | tr . /)"
