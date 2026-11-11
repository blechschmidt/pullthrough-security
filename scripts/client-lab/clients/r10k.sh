#!/bin/sh
# lab: client=r10k
# lab: image=ruby:3.3-slim
set -eu
# The tool itself is a gem, installed through the proxy.
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
bootstrap_source=https://proxy.example.com/v1/rubygems/
if [ -n "${PROXY_TOKEN:-}" ]; then
    bootstrap_source=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/rubygems/
fi
gem install --clear-sources --source "$bootstrap_source" --no-document --silent r10k
echo "LAB_CLIENT_VERSION=$(r10k version | awk '{print $2}')"

if [ -n "${PROXY_TOKEN:-}" ]; then
cat > r10k.yaml <<EOF
forge:
  baseurl: 'https://proxy.example.com/v1/puppet'
  authorization_token: 'Bearer ${PROXY_TOKEN}'
EOF
else
cat > r10k.yaml <<EOF
forge:
  baseurl: 'https://proxy.example.com/v1/puppet'
EOF
fi
cat > Puppetfile <<EOF
mod 'puppetlabs-stdlib', '9.4.1'
EOF

r10k puppetfile install --config r10k.yaml --verbose info
test -d modules/stdlib
