#!/bin/sh
# lab: client=pip
# lab: image=python:3.12-slim
#
# pip with a user-level pip.conf. Where the proxy asks for a token, it is the
# password of the index URL (any user name).
set -eu
echo "LAB_CLIENT_VERSION=$(pip --version | awk '{print $2}')"

mkdir -p ~/.config/pip
if [ -n "${PROXY_TOKEN:-}" ]; then
cat > ~/.config/pip/pip.conf <<EOF
[global]
index-url = https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/pypi/simple/
cert = /etc/ssl/corp-ca.pem
EOF
else
cat > ~/.config/pip/pip.conf <<EOF
[global]
index-url = https://proxy.example.com/v1/pypi/simple/
cert = /etc/ssl/corp-ca.pem
EOF
fi

pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore six==1.16.0
pip show six >/dev/null
pip download --no-cache-dir --disable-pip-version-check --no-deps -d dl toml==0.10.2
test -s dl/toml-0.10.2-py2.py3-none-any.whl
