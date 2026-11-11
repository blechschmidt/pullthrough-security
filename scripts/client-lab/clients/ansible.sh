#!/bin/sh
# lab: client=ansible-galaxy
# lab: image=python:3.12-slim
set -eu
# The tool itself is installed with pip, through the proxy.
bootstrap_index=https://proxy.example.com/v1/pypi/simple/
if [ -n "${PROXY_TOKEN:-}" ]; then
    bootstrap_index=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/pypi/simple/
fi
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --cert /etc/ssl/corp-ca.pem --index-url "$bootstrap_index" ansible-core
echo "LAB_CLIENT_VERSION=$(ansible-galaxy --version | awk 'NR==1 {print $3}' | tr -d ']')"

if [ -n "${PROXY_TOKEN:-}" ]; then
cat > ansible.cfg <<EOF
[galaxy]
server_list = pullthrough

[galaxy_server.pullthrough]
url = https://proxy.example.com/v1/ansible/
token = ${PROXY_TOKEN}
EOF
else
cat > ansible.cfg <<EOF
[galaxy]
server_list = pullthrough

[galaxy_server.pullthrough]
url = https://proxy.example.com/v1/ansible/
EOF
fi
export ANSIBLE_CONFIG="$PWD/ansible.cfg"
# ansible-galaxy reads the CA bundle from SSL_CERT_FILE.
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem

ansible-galaxy collection install community.general:8.0.0 --collections-path "$PWD/collections"
test -d collections/ansible_collections/community/general
