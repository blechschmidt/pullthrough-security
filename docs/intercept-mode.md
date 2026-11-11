# Access modes: explicit sources vs. TLS interception

The proxy can be consumed in two complementary ways. Both run from the same
binary and share the full caching + supply-chain-admission pipeline; they differ
only in how a client is pointed at the proxy.

| | **Explicit package sources** (default) | **TLS interception** (Task 100) |
|---|---|---|
| Client config | Per-tool: `.npmrc`, `pip.conf`, Docker mirror, … point at `https://proxy/v1/<name>/` | System proxy env (`HTTP_PROXY`/`HTTPS_PROXY`) + trust the proxy CA |
| What the client talks to | The proxy directly | The real upstream hostname (proxy transparently MITMs it) |
| URL rewriting | The proxy rewrites index links back through `/v1/...` | None needed; traffic stays on the real host |
| TLS | Proxy presents its own server cert | Proxy mints a per-host leaf from a locally trusted CA |
| Listener | `server.httpAddr` | `server.intercept.listenAddr` |

Explicit mode is always available and needs no extra configuration beyond
`upstreams:`. Interception is opt-in via `server.intercept`.

## Explicit package sources

This is the mode described throughout [clients.md](clients.md). Each upstream is
declared under `upstreams:` and served under `https://proxy/v1/<name>/...`.
Clients are reconfigured per tool to use that URL as their registry/index. The
proxy rewrites embedded artifact links so dependent downloads also flow through
the cache. Set `server.publicUrl` so those links are absolute and correct behind
a load balancer.

Use explicit mode when you want tight, auditable control over exactly which
tools use the proxy, or when you cannot distribute a trusted CA to clients.

## TLS interception (MITM forward proxy)

In interception mode the proxy runs as an ordinary HTTP *forwarding* proxy on a
separate listener. Clients need no per-tool registry reconfiguration — they keep
talking to `registry.npmjs.org`, `pypi.org`, etc. For HTTPS the client issues a
`CONNECT`; rather than blindly tunneling, the proxy terminates TLS with a
certificate minted on the fly by a locally trusted CA, maps the real upstream
host to a configured backend, and runs the request through the same cache and
admission gates. Clients only need to:

1. Trust the proxy's CA certificate (`server.intercept.caCertFile`).
2. Point their proxy environment at the interception listener.

```bash
export HTTPS_PROXY=http://proxy.example.com:3128
export HTTP_PROXY=http://proxy.example.com:3128
# Trust the CA (example for a Debian base image):
cp ca.crt /usr/local/share/ca-certificates/pullthrough.crt && update-ca-certificates
```

Many tools also honor their own CA settings (`NODE_EXTRA_CA_CERTS`,
`PIP_CERT`/`REQUESTS_CA_BUNDLE`, `CARGO_HTTP_CAINFO`, `GIT_SSL_CAINFO`, Docker's
`/etc/docker/certs.d/`), which avoids touching the system trust store. The
client guide lists the setting each package manager reads
([clients.md](clients.md#private-ca-settings-at-a-glance)); those were verified
with the real clients against a proxy with a private CA in explicit mode, and
the same settings name the CA here.

### Configuration

```yaml
server:
  httpAddr: ":8080"            # explicit /v1 mode (always on)
  intercept:
    enabled: true
    listenAddr: ":3128"        # forward-proxy listener (must differ from httpAddr)
    caCertFile: "/var/lib/pullthrough/ca/intercept-ca.crt"
    caKeyFile:  "/var/lib/pullthrough/ca/intercept-ca.key"
    generateCa: true           # create the CA on first start if absent
    # Extra upstream hosts to intercept, beyond each upstream's primary URL host.
    # Values are upstream names (keys under `upstreams:`). Supports "*.suffix".
    hosts:
      files.pythonhosted.org: pypi
    passthroughUnmatched: false # refuse (don't blind-tunnel) unconfigured hosts
    allowPlainHttp: false       # also intercept absolute-form http:// requests

upstreams:
  npm:  { type: npm,  url: "https://registry.npmjs.org" }
  pypi: { type: pip,  url: "https://pypi.org" }
```

The host→backend routing table is built automatically from the **primary host**
of every enabled upstream URL (e.g. `registry.npmjs.org` → `npm`,
`pypi.org` → `pypi`), then any `server.intercept.hosts` entries are layered on
top (and override). Because a backend serves its upstream's native path layout
and rewrites index links to stay on that same host, single-host ecosystems (npm,
Go module proxy, cargo index, NuGet, Maven, RubyGems, Composer) work out of the
box. Ecosystems that fetch artifacts from a separate CDN host (e.g. PyPI's
`files.pythonhosted.org`) need that host mapped explicitly, as shown above.

### Security notes

- **The CA is a trust anchor.** Any client that trusts it will accept the
  proxy's substituted certificates for *any* host it intercepts. Protect
  `caKeyFile` (written `0600`) like any signing key; scope the CA to the fleet
  that must trust it, and prefer per-tool CA settings over the system store so
  the trust is narrow.
- **`passthroughUnmatched: false` is the secure default.** With it, the proxy
  only carries traffic to hosts you configured; a `CONNECT` to anything else is
  refused with `403`. Enable passthrough only if you want the proxy to double as
  a general egress tunnel for unconfigured hosts (those connections are *not*
  decrypted, cached, or scanned).
- **Leaf certificates** are ECDSA P-256, minted on demand, cached in memory
  (`certCacheSize`), and regenerated on restart. `leafTtl` bounds their validity.
- Interception composes with the egress/SSRF guard, client authentication, rate
  limiting, and every admission gate exactly as explicit mode does — the
  decrypted request is dispatched back through the gateway's `/v1` pipeline.

### Verifying

```bash
# Fetch a package through the interception proxy, trusting the generated CA:
curl --cacert intercept-ca.crt -x http://proxy.example.com:3128 \
  https://registry.npmjs.org/lodash

# A host that is not configured is refused (passthroughUnmatched: false):
curl --cacert intercept-ca.crt -x http://proxy.example.com:3128 \
  https://example.com/           # => CONNECT tunnel failed, response 403
```
