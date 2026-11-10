#!/bin/sh
# Minimal real Git build for the pull-through proxy test set.
# Clone a tiny upstream repository through the proxy's Git (HTTPS smart) backend,
# which scans the fetched commits before serving them.
set -eu
git clone "http://PROXY_HOST/v1/git/octocat/Hello-World.git"
cd Hello-World && git log --oneline -1
