#!/bin/sh
# Representative install exercised through the proxy's APT backend.
set -eu
apt-get update
apt-get install -y --no-install-recommends curl
