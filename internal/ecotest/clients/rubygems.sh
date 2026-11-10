#!/bin/sh
# rubygems — mirror rubygems.org through the proxy with Bundler.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(bundle --version | awk '{print $3}')"

# A Bundler mirror redirects the Gemfile's `source "https://rubygems.org"` to the
# proxy without editing the Gemfile. (Alternatively put the proxy URL in the
# Gemfile's `source` line, or use `gem install --clear-sources --source`.)
bundle config set --global mirror.https://rubygems.org "$MOUNT"

cat > Gemfile <<GEMFILE
source "https://rubygems.org"
gem "$PKG_NAME", "$PKG_VERSION"
GEMFILE
bundle config set --local path vendor/bundle
bundle install
bundle exec ruby -e 'puts Gem.loaded_specs.keys.sort.join(" ")'
