#!/bin/sh
# ansible — install collections from galaxy.ansible.com, intercepted by the
# proxy.
set -eu

# ansible-core comes from pypi.org, intercepted as well; pip trusts the proxy's
# CA through PIP_CERT. (The proxy content-scans a package the first time it is
# pulled, which for a large wheel can exceed pip's 15 s default read timeout —
# hence --timeout.)
export PIP_CERT="$PT_CA_CERT"
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 ansible-core
echo "ECOTEST_CLIENT_VERSION=$(ansible-galaxy --version | awk 'NR==1 {print $3}' | tr -d ']')"

# ansible-galaxy keeps its default server, galaxy.ansible.com. It trusts the
# proxy's CA through SSL_CERT_FILE; through a forward proxy it reads
# HTTPS_PROXY. The proxy moves the download links in the API documents onto
# galaxy.ansible.com, so the collection tarball is intercepted too.
export SSL_CERT_FILE="$PT_CA_CERT"

# PKG_NAME is "<namespace>.<collection>".
ansible-galaxy collection install "$PKG_NAME:$PKG_VERSION" --collections-path "$PWD/collections"
test -d "collections/ansible_collections/$(echo "$PKG_NAME" | tr . /)"
