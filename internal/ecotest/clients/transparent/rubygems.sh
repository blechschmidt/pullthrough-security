#!/bin/sh
# rubygems — install from rubygems.org with Bundler, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(bundle --version | awk '{print $3}')"

# No mirror: the Gemfile's source stays https://rubygems.org (whose index
# Bundler fetches from index.rubygems.org). Ruby trusts the proxy's CA through
# SSL_CERT_FILE; through a forward proxy Bundler reads HTTPS_PROXY.
export SSL_CERT_FILE="$PT_CA_CERT"

cat > Gemfile <<GEMFILE
source "https://rubygems.org"
gem "$PKG_NAME", "$PKG_VERSION"
GEMFILE
bundle config set --local path vendor/bundle
bundle install
bundle exec ruby -e 'puts Gem.loaded_specs.keys.sort.join(" ")'
