#!/bin/sh
# huggingface — download model files from the Hub through the proxy.
set -eu

# huggingface_hub is a Python package; install it through the proxy's PyPI
# upstream.
# (The proxy content-scans a package the first time it is pulled, which for a
# large wheel can exceed pip's 15 s default read timeout — hence --timeout.)
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --index-url "$PROXY_URL/v1/pip/simple/" huggingface_hub
echo "ECOTEST_CLIENT_VERSION=$(python -c 'import huggingface_hub; print(huggingface_hub.__version__)')"

# HF_ENDPOINT replaces huggingface.co for huggingface_hub, transformers,
# datasets and the hf / huggingface-cli tools. The proxy follows the Hub's CDN
# redirects itself, so the file content comes back through it.
export HF_ENDPOINT="$MOUNT"
export HF_HOME="$PWD/hf-home" HF_HUB_DISABLE_TELEMETRY=1

# PKG_NAME is "<owner>/<model>", PKG_VERSION a revision (a commit hash pins the
# download to immutable content), PKG_FILE the file to fetch.
python -c '
import os
from huggingface_hub import hf_hub_download
path = hf_hub_download(os.environ["PKG_NAME"], os.environ["PKG_FILE"], revision=os.environ["PKG_VERSION"])
print("downloaded", path, os.path.getsize(path), "bytes")
'
