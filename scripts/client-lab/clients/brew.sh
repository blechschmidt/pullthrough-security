#!/bin/sh
# lab: client=Homebrew
# lab: image=homebrew/brew:4.6.20
#
# Homebrew with its formula API and its bottle downloads on the proxy.
set -eu
echo "LAB_CLIENT_VERSION=$(brew --version | awk 'NR==1 {print $2}')"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_NO_INSTALL_CLEANUP=1

# Both are required: the formula index is signed and cannot be rewritten, so it
# is brew itself that sends bottle downloads to the artifact domain.
export HOMEBREW_API_DOMAIN=https://proxy.example.com/v1/homebrew/api
export HOMEBREW_ARTIFACT_DOMAIN=https://proxy.example.com/v1/homebrew
# Fail rather than fall back to the default host for a download.
export HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1

# brew runs curl with a scrubbed environment and without ~/.curlrc, so neither
# SSL_CERT_FILE nor CURL_CA_BUNDLE reaches it. HOMEBREW_CURLRC makes it read
# ~/.curlrc, which names the CA.
export HOMEBREW_CURLRC=1
cat > ~/.curlrc <<EOF
cacert = "/etc/ssl/corp-ca.pem"
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
# The token for bottle downloads (brew sends it as a bearer token to the
# artifact domain) ...
export HOMEBREW_DOCKER_REGISTRY_TOKEN="${PROXY_TOKEN}"
# ... and, for the formula API, credentials for the proxy's host from ~/.netrc.
cat >> ~/.curlrc <<EOF
netrc
EOF
cat > ~/.netrc <<EOF
machine proxy.example.com
  login pullthrough
  password ${PROXY_TOKEN}
EOF
chmod 600 ~/.netrc
fi

brew install hello
hello | grep -q "Hello, world!"
