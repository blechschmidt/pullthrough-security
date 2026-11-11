#!/bin/sh
# lab: client=ovsx
# lab: image=node:22-slim
#
# The ovsx CLI downloading an extension. ovsx is fetched with npx, through the
# proxy's npm upstream.
set -eu
export NODE_EXTRA_CA_CERTS=/etc/ssl/corp-ca.pem
export NPM_CONFIG_REGISTRY=https://proxy.example.com/v1/npm/
if [ -n "${PROXY_TOKEN:-}" ]; then
    npm config set //proxy.example.com/v1/npm/:_authToken "${PROXY_TOKEN}"
fi
echo "LAB_CLIENT_VERSION=$(npx --yes ovsx --version | awk 'NR==1 {print $NF}')"

if [ -z "${PROXY_TOKEN:-}" ]; then
    npx --yes ovsx get dracula-theme.theme-dracula --versionRange 2.25.1 \
        --registryUrl https://proxy.example.com/v1/openvsx -o extension.vsix
    test -s extension.vsix
else
    # A LIMITATION, asserted: ovsx has a token only for publishing (-p /
    # OVSX_PAT) and sends none with a download.
    if OVSX_PAT="${PROXY_TOKEN}" npx --yes ovsx get dracula-theme.theme-dracula --versionRange 2.25.1 \
        --registryUrl https://proxy.example.com/v1/openvsx -p "${PROXY_TOKEN}" -o extension.vsix >get.log 2>&1; then
        echo "ovsx downloaded with a token: the limitation is gone — update docs/clients/openvsx.md"
        cat get.log; exit 1
    fi
    cat get.log
    grep -q "401" get.log
fi
