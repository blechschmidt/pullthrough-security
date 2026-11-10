#!/bin/sh
# puppet — point r10k at the proxy's Puppet Forge upstream.
set -eu

# r10k itself is a gem; install it through the proxy's RubyGems upstream.
gem install --clear-sources --source "$PROXY_URL/v1/rubygems/" --no-document --silent r10k
echo "ECOTEST_CLIENT_VERSION=$(r10k version | awk '{print $2}')"

# forge.baseurl in r10k.yaml replaces forgeapi.puppet.com. (The Puppet module
# tool takes the same URL as --module_repository.)
cat > r10k.yaml <<R10K
forge:
  baseurl: '$MOUNT'
R10K
cat > Puppetfile <<PUPPETFILE
mod '$PKG_NAME', '$PKG_VERSION'
PUPPETFILE

r10k puppetfile install --config r10k.yaml --verbose info
test -n "$(ls modules)"
