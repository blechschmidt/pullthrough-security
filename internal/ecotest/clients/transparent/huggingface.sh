#!/bin/sh
# huggingface — download model files from huggingface.co, intercepted by the
# proxy.
set -eu

# huggingface_hub comes from pypi.org, intercepted as well; pip trusts the
# proxy's CA through PIP_CERT. (The proxy content-scans a package the first time
# it is pulled, which for a large wheel can exceed pip's 15 s default read
# timeout — hence --timeout.)
export PIP_CERT="$PT_CA_CERT"
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 huggingface_hub
echo "ECOTEST_CLIENT_VERSION=$(python -c 'import huggingface_hub; print(huggingface_hub.__version__)')"

# HF_ENDPOINT keeps its default, huggingface.co. huggingface_hub trusts the
# proxy's CA through REQUESTS_CA_BUNDLE / SSL_CERT_FILE; through a forward
# proxy it reads HTTPS_PROXY. The proxy follows the Hub's CDN redirects itself,
# so the file content comes back from huggingface.co.
export REQUESTS_CA_BUNDLE="$PT_CA_CERT" SSL_CERT_FILE="$PT_CA_CERT"
export HF_HOME="$PWD/hf-home" HF_HUB_DISABLE_TELEMETRY=1

# PKG_NAME is "<owner>/<model>", PKG_VERSION a revision (a commit hash pins the
# download to immutable content), PKG_FILE the file to fetch.
python -c '
import os
from huggingface_hub import hf_hub_download
path = hf_hub_download(os.environ["PKG_NAME"], os.environ["PKG_FILE"], revision=os.environ["PKG_VERSION"])
print("downloaded", path, os.path.getsize(path), "bytes")
'
