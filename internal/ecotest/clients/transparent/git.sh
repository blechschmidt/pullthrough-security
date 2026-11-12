#!/bin/sh
# git — clone from github.com, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(git --version | awk '{print $3}')"

# No insteadOf: the clone URL is GitHub's own. git trusts the proxy's CA
# through GIT_SSL_CAINFO (or http.sslCAInfo); through a forward proxy it reads
# https_proxy.
export GIT_SSL_CAINFO="$PT_CA_CERT"

# PKG_NAME is "<owner>/<repository>".
git clone "https://github.com/$PKG_NAME.git" repo
git -C repo log --oneline -1
