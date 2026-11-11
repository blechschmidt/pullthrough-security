#!/bin/sh
# lab: client=huggingface_hub
# lab: image=python:3.12-slim
set -eu
# The tool itself is installed with pip, through the proxy.
bootstrap_index=https://proxy.example.com/v1/pypi/simple/
if [ -n "${PROXY_TOKEN:-}" ]; then
    bootstrap_index=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/pypi/simple/
fi
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --cert /etc/ssl/corp-ca.pem --index-url "$bootstrap_index" huggingface_hub
echo "LAB_CLIENT_VERSION=$(python -c 'import huggingface_hub; print(huggingface_hub.__version__)')"

export HF_ENDPOINT=https://proxy.example.com/v1/huggingface
# huggingface_hub reads the CA bundle from SSL_CERT_FILE (releases built on
# requests: REQUESTS_CA_BUNDLE).
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem REQUESTS_CA_BUNDLE=/etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    # The client's token variable carries the PROXY token; the proxy holds the
    # Hub token itself.
    export HF_TOKEN="${PROXY_TOKEN}"
fi
export HF_HOME="$PWD/hf-home"
# The `hf` command asks pypi.org whether a newer huggingface_hub exists; this
# switches the check off. (The library itself does not ask.)
export HF_HUB_DISABLE_UPDATE_CHECK=1

python -c '
from huggingface_hub import hf_hub_download
import os
path = hf_hub_download("hf-internal-testing/tiny-random-bert", "config.json",
                       revision="f171d7baecaf37b5da5a3616d8833b9969753535")
print("downloaded", path, os.path.getsize(path), "bytes")
'
hf download hf-internal-testing/tiny-random-bert vocab.txt --revision f171d7baecaf37b5da5a3616d8833b9969753535
