# Hugging Face Hub

Download models and datasets through the proxy's Hub upstream. The examples use
the upstream name `huggingface`; replace it with the name your operator gave
the upstream ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `huggingface` |
| Package source | `https://proxy.example.com/v1/huggingface` |
| Clients | huggingface_hub (and what builds on it: transformers, datasets, the `hf` CLI) |
| Tested | huggingface_hub 2.4: [in CI on every push](../ecosystem-tests-reference.md#huggingface) and in the [client lab](../client-lab.md). |

## Configure

One environment variable replaces `huggingface.co` for every library built on
`huggingface_hub`:

<!-- verified: ci:huggingface lab:huggingface -->

```sh
export HF_ENDPOINT=https://proxy.example.com/v1/huggingface
```

<!-- verified: lab:huggingface -->

```sh
hf download hf-internal-testing/tiny-random-bert vocab.txt --revision f171d7baecaf37b5da5a3616d8833b9969753535
```

## Authenticate

Only when the proxy has access control switched on. The client's own token
variable carries your **proxy token** — not a Hub token. The proxy holds the Hub
token (for gated and private repositories) itself and never forwards yours.

<!-- verified: lab:huggingface -->

```sh
export HF_TOKEN="<token>"
```

## Trust a private CA

<!-- verified: lab:huggingface -->

```sh
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem REQUESTS_CA_BUNDLE=/etc/ssl/corp-ca.pem
```

Current releases read `SSL_CERT_FILE`; releases built on the `requests` library
read `REQUESTS_CA_BUNDLE`.

## Check that it works

The `hf download` command above prints the path of the downloaded file in the
local cache (`HF_HOME`).

## Good to know

- **Pin a commit.** A download at a 40-character commit hash (`--revision`,
  `revision=`) is immutable: the proxy caches it and serves it without asking
  the Hub again. A branch or tag (`main`) is looked up at the Hub every time.
- **Pickle weights are inspected.** `.bin`, `.pt`, `.pkl`, `.ckpt` files pass
  the proxy's weight scan before they are served, and a file that would execute
  code on load is a `403`. Prefer `safetensors`.
- **Large files** are streamed and verified against the SHA-256 the Hub
  declares; the proxy follows the Hub's CDN redirects itself.
- **The `hf` command checks pypi.org for a newer release of itself** — not a
  request the Hub upstream sees, and the one host besides the proxy the lab saw
  it look up. The library does not. To switch the check off:

  <!-- verified: lab:huggingface -->

  ```sh
  export HF_HUB_DISABLE_UPDATE_CHECK=1
  ```
- **Uploading does not go through the proxy** (`hf upload`, `push_to_hub`).

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  huggingface:
    type: huggingface
    url: https://huggingface.co
```

Commit-pinned files are cached immutably and verified against the Hub's
`X-Linked-Etag` SHA-256; the headers the client needs to identify a file are
stored with it and replayed on a cache hit. Details:
[backends: huggingface](../backends.md#huggingface).
