#!/bin/sh
# lab: client=puppet module
# lab: image=ruby:3.3-slim
set -eu
# The tool itself is a gem, installed through the proxy.
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
bootstrap_source=https://proxy.example.com/v1/rubygems/
if [ -n "${PROXY_TOKEN:-}" ]; then
    bootstrap_source=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/rubygems/
fi
gem install --clear-sources --source "$bootstrap_source" --no-document --silent puppet
echo "LAB_CLIENT_VERSION=$(puppet --version)"

if [ -n "${PROXY_TOKEN:-}" ]; then
    puppet module install puppetlabs-stdlib --version 9.4.1 --target-dir "$PWD/modules" \
        --module_repository https://proxy.example.com/v1/puppet \
        --forge_authorization "Bearer ${PROXY_TOKEN}"
else
    puppet module install puppetlabs-stdlib --version 9.4.1 --target-dir "$PWD/modules" \
        --module_repository https://proxy.example.com/v1/puppet
fi
test -d modules/stdlib
