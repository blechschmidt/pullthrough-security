#!/bin/sh
# lab: client=Bundler
# lab: image=ruby:3.3-slim
#
# Bundler with a mirror of rubygems.org: no Gemfile changes, and Gemfile.lock
# keeps naming rubygems.org.
set -eu
echo "LAB_CLIENT_VERSION=$(bundle --version | awk '{print $3}')"

# Ruby reads the CA bundle from SSL_CERT_FILE — for Bundler's index requests and
# for the gem downloads alike (Bundler's own ssl_ca_cert setting covers only the
# former).
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem

bundle config set --global mirror.https://rubygems.org https://proxy.example.com/v1/rubygems
if [ -n "${PROXY_TOKEN:-}" ]; then
    # Credentials for the proxy's host; the token is the password.
    bundle config set --global proxy.example.com "pullthrough:${PROXY_TOKEN}"
fi

cat > Gemfile <<EOF
source "https://rubygems.org"
gem "rake", "13.1.0"
EOF
bundle config set --local path vendor/bundle
bundle install
bundle exec rake --version

grep -q "remote: https://rubygems.org/" Gemfile.lock
if grep -q 'proxy.example.com' Gemfile.lock; then echo "Gemfile.lock names the proxy"; exit 1; fi
