#!/bin/sh
# puppet — install Forge modules with r10k from forgeapi.puppet.com,
# intercepted by the proxy.
set -eu

# Ruby trusts the proxy's CA through SSL_CERT_FILE; through a forward proxy gem
# and r10k read HTTPS_PROXY. r10k itself comes from rubygems.org, intercepted as
# well.
export SSL_CERT_FILE="$PT_CA_CERT"
gem install --no-document --silent r10k
echo "ECOTEST_CLIENT_VERSION=$(r10k version | awk '{print $2}')"

# No forge.baseurl: r10k keeps forgeapi.puppet.com.
cat > Puppetfile <<PUPPETFILE
mod '$PKG_NAME', '$PKG_VERSION'
PUPPETFILE

r10k puppetfile install --verbose info
test -n "$(ls modules)"
