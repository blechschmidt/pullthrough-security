"""Minimal real Hugging Face Hub pull for the pull-through proxy test set.

Downloads one small file of a real model repository at a pinned commit. With
HF_ENDPOINT pointing at the proxy's Hugging Face backend, huggingface_hub
resolves the file through the proxy; a commit-pinned revision is immutable, so
the proxy caches it.

    HF_ENDPOINT=https://proxy.example.com/v1/huggingface python download.py
"""
from huggingface_hub import hf_hub_download

path = hf_hub_download(
    "hf-internal-testing/tiny-random-bert",
    "config.json",
    revision="f171d7baecaf37b5da5a3616d8833b9969753535",
)
print("downloaded", path)
