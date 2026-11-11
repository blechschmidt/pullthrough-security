#!/bin/sh
# lab: client=RubyGems (gem) and a Gemfile source
# lab: image=ruby:3.3-slim
#
# `gem install` with the proxy as the only source, and a Gemfile that names the
# proxy as its source.
set -eu
echo "LAB_CLIENT_VERSION=$(gem --version)"
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem

if [ -n "${PROXY_TOKEN:-}" ]; then
    gem sources --add "https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/rubygems/" --remove https://rubygems.org/
else
    gem sources --add https://proxy.example.com/v1/rubygems/ --remove https://rubygems.org/
fi
gem install --no-document rake -v 13.1.0

# A Gemfile whose source is the proxy. Gemfile.lock then records the proxy URL
# (without credentials, which Bundler takes from its configuration).
mkdir app && cd app
if [ -n "${PROXY_TOKEN:-}" ]; then
    bundle config set --global proxy.example.com "pullthrough:${PROXY_TOKEN}"
fi
cat > Gemfile <<EOF
source "https://proxy.example.com/v1/rubygems"
gem "rainbow", "3.1.1"
EOF
bundle config set --local path vendor/bundle
bundle install
grep -q "remote: https://proxy.example.com/v1/rubygems/" Gemfile.lock
! grep -q "${PROXY_TOKEN:-no-token-in-the-lock-file}" Gemfile.lock
