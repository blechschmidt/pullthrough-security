#!/bin/sh
# lab: client=Git
# lab: image=alpine/git:2.49.1
# lab: entrypoint=sh
set -eu
echo "LAB_CLIENT_VERSION=$(git --version | awk '{print $3}')"

# Rewrite the forge's base URL once: existing clone URLs, submodules and
# dependency manifests then go through the proxy unchanged.
git config --global url."https://proxy.example.com/v1/github/".insteadOf "https://github.com/"
git config --global http."https://proxy.example.com/".sslCAInfo /etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    # The token as a request header, for the proxy's host only.
    git config --global http."https://proxy.example.com/".extraHeader "Authorization: Bearer ${PROXY_TOKEN}"
fi

git clone https://github.com/octocat/Hello-World.git repo
git -C repo log --oneline -1
git -C repo fetch origin
# The checkout still records the forge's own URL; the rewrite happens on use.
test "$(git -C repo config --get remote.origin.url)" = "https://github.com/octocat/Hello-World.git"

# A checkout that also pushes: an identity pushInsteadOf rule keeps push URLs on
# the forge (the proxy is read-only), while fetches stay on the proxy.
git config --global url."https://github.com/".pushInsteadOf "https://github.com/"
test "$(git -C repo remote get-url origin)" = "https://proxy.example.com/v1/github/octocat/Hello-World.git"
test "$(git -C repo remote get-url --push origin)" = "https://github.com/octocat/Hello-World.git"

# The explicit address works as well.
git clone https://proxy.example.com/v1/github/octocat/Spoon-Knife.git explicit

if [ -n "${PROXY_TOKEN:-}" ]; then
    # A LIMITATION, asserted: Git presents a stored credential (or one in the
    # URL) only in answer to a Basic challenge, and the proxy challenges with
    # Bearer. Only the header form above works.
    export HOME="$PWD/other-home" GIT_TERMINAL_PROMPT=0
    mkdir -p "$HOME"
    git config --global http."https://proxy.example.com/".sslCAInfo /etc/ssl/corp-ca.pem
    git config --global credential.helper store
    printf 'https://pullthrough:%s@proxy.example.com\n' "${PROXY_TOKEN}" > "$HOME/.git-credentials"
    if git clone https://proxy.example.com/v1/github/octocat/Hello-World.git helper >helper.log 2>&1; then
        echo "git authenticated with a stored credential: the limitation is gone — update docs/clients/git.md"
        cat helper.log; exit 1
    fi
    cat helper.log
    grep -q "Authentication failed" helper.log
fi
