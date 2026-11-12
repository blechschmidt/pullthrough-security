# Access modes: explicit sources, TLS interception and NAT

The proxy can be consumed in three ways. All three run from the same binary
and share the full caching and supply-chain-admission pipeline — the same
cache entries, the same gates, the same audit and download logs. They differ
only in how a client's request gets to the proxy.

| | **Explicit package sources** (default) | **TLS interception** (forward proxy) | **NAT** (transparent) |
|---|---|---|---|
| Client configuration | Per tool: `.npmrc`, `pip.conf`, a Docker mirror, … name `https://proxy/v1/<upstream>/` | `HTTPS_PROXY` / `HTTP_PROXY` + trust the proxy's CA | Trust the proxy's CA — nothing else |
| What the client talks to | The proxy, by its own name | `registry.npmjs.org`, `pypi.org`, … through a `CONNECT` to the proxy | `registry.npmjs.org`, `pypi.org`, … — the network sends the connection to the proxy |
| How the proxy routes | Path prefix `/v1/<upstream>/` | Host (and path) the client asked for | TLS server name (SNI) / `Host` header, and path |
| TLS presented | The proxy's own certificate | A certificate for the upstream host, minted by the proxy's CA | Same |
| Listener | `server.httpAddr` | `server.intercept.listenAddr` | `server.intercept.nat.httpsAddr` / `httpAddr` |

Explicit mode is always on. Interception — either way, or both — is enabled
with `server.intercept`. Every supported ecosystem's real client is run in all
three modes in CI; the exact client setup for each is published, generated
from those tests, in [ecosystem-tests-reference.md](ecosystem-tests-reference.md).

## Explicit package sources

This is the mode described throughout [clients.md](clients.md). Each upstream is
declared under `upstreams:` and served under `https://proxy/v1/<name>/...`.
Clients are reconfigured per tool to use that URL as their registry or index.
The proxy rewrites the artifact links in the index documents it serves so that
dependent downloads also flow through it. Set `server.publicUrl` so those links
are absolute and correct behind a load balancer.

Use explicit mode when you want tight, auditable control over exactly which
tools use the proxy, or when you cannot distribute a trusted CA to clients.

## Interception: what the two modes share

In both interception modes the client keeps its own registry configuration. It
connects to the upstream host — `registry.npmjs.org`, `pypi.org`,
`index.crates.io` — and the proxy, rather than passing the connection on,
terminates TLS itself with a certificate for that host minted on the fly by its
own CA. It then routes the decrypted request to a configured upstream and runs
it through exactly the pipeline an explicit request takes.

### Routing

A request is routed by the host the client asked for and the path it asked for
there. The routing table is built from the configuration:

1. **Every enabled upstream's URL** — its host and, when the URL has one, its
   path. An upstream configured as `https://repo1.maven.org/maven2` is served
   for `repo1.maven.org/maven2/…`, and the backend sees the path below
   `/maven2`, exactly as in explicit mode.
2. **The hosts a stock client uses for the same public registry**, where they
   differ from the URL an operator configures:

   | Ecosystem | Upstream URL | Also intercepted |
   |---|---|---|
   | maven | `repo1.maven.org/maven2` | `repo.maven.apache.org/maven2` (Maven's built-in central) — and the other way round |
   | npm | `registry.npmjs.org` | `registry.yarnpkg.com` (Yarn's default) — and the other way round |
   | rubygems | `rubygems.org` | `index.rubygems.org` (where Bundler fetches the index) — and the other way round |
   | dart | `pub.dev` | `pub.dartlang.org` — and the other way round |
   | homebrew | `formulae.brew.sh` | `ghcr.io` (bottles: their URLs are in the *signed* formula index, so brew downloads them from ghcr.io itself) |

   An upstream configured for one of these hosts explicitly keeps it.
3. **`server.intercept.hosts`**, which adds rules and overrides: a key is a
   host, a `*.suffix` wildcard, or either followed by a path prefix; the value
   is an upstream name.

Within a host the longest matching path prefix wins, on segment boundaries
(`/debian` does not cover `/debian-security`). A request to an intercepted
host for a path **no rule covers** is answered `404`: it names another
repository on the same host, which no configured upstream serves. A
connection to a host **no rule names at all** is refused — or, with
`passthroughUnmatched: true`, passed on undecrypted (see each mode below).

The table the proxy is running with is reported by the admin API:

```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" https://proxy.example.com/admin/api/intercept | jq .routes
```

### Links in intercepted responses

An index document names its packages' downloads, and the proxy's protocol
adapters write those as links to their mount: in explicit mode a PyPI page
links to `https://proxy.example.com/v1/pip/files/…/six-1.16.0-py2.py3-none-any.whl`.
An intercepted client must not be sent there — it was not configured for the
proxy, and in NAT mode it may not be able to reach the proxy's address at all.
So in an intercepted response those links are moved onto the host the client
is talking to, under a reserved path:

```
https://proxy.example.com/v1/pip/files/https/files.pythonhosted.org/packages/…/six.whl   (explicit)
https://pypi.org/_pullthrough/v1/pip/files/https/files.pythonhosted.org/packages/…/six.whl   (intercepted)
```

The client follows the link to `pypi.org` — a host it already reaches through
the proxy — and the interception listener dispatches the path after
`/_pullthrough` as it is. No registry protocol uses that path. The rules for
which documents are rewritten and where in them a link is recognised are those
of [personal cache links](user-links.md): only index documents a protocol
adapter wrote links into, only where a link starts a value, never a payload
and never anything that came out of the cache. Signed documents (an APT
`InRelease`, Hackage's TUF metadata, Homebrew's formula index) are served byte
for byte.

The result: an intercepted client only ever connects to the hosts it asked for,
and the downloads land in the same cache entries an explicit client's do.

### Identity and credentials

The proxy identifies an intercepted client by what it presented **to the
proxy**: the credentials of a forward-proxy URL
(`HTTPS_PROXY=http://user:token@proxy:3128`, sent as `Proxy-Authorization` on
the `CONNECT`) are handed to the access-control chain as the request's
credentials, exactly like an explicit request's `Authorization` header.

The client's own `Authorization` header is addressed to the registry, not to
the proxy. It is removed from an intercepted request and never sent anywhere —
the proxy fetches with its own upstream credentials, as always. A NAT client
presents nothing to the proxy; with client authentication enabled it is served
under the anonymous role ([access-control-and-audit.md](access-control-and-audit.md)),
so a NAT deployment identifies its clients by their network.

### Distributing the CA

Every intercepted client must trust the CA the proxy mints certificates with
(`server.intercept.caCertFile`). It is published by the admin API:

```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" -o pullthrough-intercept-ca.crt \
  https://proxy.example.com/admin/api/intercept/ca.crt
# or: ptctl intercept ca --out pullthrough-intercept-ca.crt
```

Install it in the system trust store (Debian/Ubuntu:
`cp pullthrough-intercept-ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates`),
or — narrower — hand it only to the tools that need it. The setting each
package manager reads, verified with the real clients, is in every
ecosystem's interception script in
[ecosystem-tests-reference.md](ecosystem-tests-reference.md):

| Client | CA setting |
|---|---|
| npm, Node.js tools | `NODE_EXTRA_CA_CERTS` |
| pip | `PIP_CERT` (or `REQUESTS_CA_BUNDLE`) |
| cargo | `CARGO_HTTP_CAINFO` |
| go, terraform, helm (Go programs), .NET, Ruby, Ansible | `SSL_CERT_FILE` |
| git | `GIT_SSL_CAINFO` |
| Maven, Bazel (JVM) | a trust store: `-Djavax.net.ssl.trustStore=…` (`MAVEN_OPTS`, Bazel `startup --host_jvm_args`) |
| Docker Engine | `/etc/docker/certs.d/<registry host>/ca.crt` |
| conda | `CONDA_SSL_VERIFY` / `ssl_verify` |
| Conan | `core.net.http:cacert_path` in `global.conf` |
| Composer | `composer config --global cafile …` |
| R | `CURL_CA_BUNDLE` |
| Julia | `JULIA_SSL_CA_ROOTS_PATH` |
| Nix | `NIX_SSL_CERT_FILE` |
| Deno | `DENO_CERT` |
| Homebrew | `cacert` in a curlrc named by `HOMEBREW_CURLRC` |
| huggingface_hub | `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` |
| Dart, cabal, mix/Hex | the system trust store (Hex also `HEX_CACERTS_PATH`) |
| APT, DNF, cpanm over `http://` | none — the archive's own signatures are verified |

## TLS interception (forward proxy)

The proxy runs an ordinary HTTP forward proxy on `server.intercept.listenAddr`.
For HTTPS the client issues a `CONNECT registry.npmjs.org:443`; for a host the
proxy routes, it answers `200`, terminates TLS itself and serves the decrypted
requests. A `CONNECT` to any other host is refused with `403` (or, with
`passthroughUnmatched: true`, tunnelled undecrypted). Absolute-form plain-HTTP
requests (`GET http://deb.debian.org/debian/…`, as APT and DNF send them through
a proxy) are intercepted when `allowPlainHttp: true`.

Clients need the CA and the proxy environment:

```bash
export HTTPS_PROXY=http://proxy.example.com:3128 HTTP_PROXY=http://proxy.example.com:3128
export https_proxy=$HTTPS_PROXY http_proxy=$HTTP_PROXY
```

Most package managers read these variables. The exceptions, verified in CI:

- **Maven** reads `<proxies>` in `settings.xml`, not the environment.
- **The Docker Engine** is the client, not the `docker` CLI: give the daemon
  the variables (a systemd drop-in: `[Service] Environment=HTTPS_PROXY=…`).
- **Node.js tools** other than npm (the `ovsx` CLI) need `NODE_USE_ENV_PROXY=1`
  to make Node's own HTTP client read them.

## NAT mode (transparent)

In NAT mode the client is not configured for the proxy at all. The network
sends its connections to the upstream hosts to the proxy's NAT listeners:

- `server.intercept.nat.httpsAddr` receives TLS connections (what clients send
  to port 443). Each is routed by the server name the client's TLS handshake
  asks for (SNI); a connection without one, or for a host no rule names, is
  refused with a TLS `unrecognized_name` alert — no certificate is minted for a
  host the proxy does not serve.
- `server.intercept.nat.httpAddr` receives plain-HTTP connections (port 80),
  routed by their `Host` header; an unknown host is answered `403`.

There are two ways to send the connections there.

### By DNS

Answer the intercepted hostnames with an address the NAT listeners listen on —
in a split-horizon zone, a `dnsmasq`/CoreDNS override, or a hosts file — with
the listeners on ports 443 and 80 of that address:

```yaml
server:
  intercept:
    enabled: true
    nat:
      httpsAddr: "10.0.0.5:443"
      httpAddr: "10.0.0.5:80"
```

The admin API lists the names to send, one per line, or as hosts-file lines:

```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://proxy.example.com/admin/api/intercept?format=hosts&address=10.0.0.5"
# 10.0.0.5	deb.debian.org
# 10.0.0.5	pypi.org
# …
# or: ptctl intercept hosts --address 10.0.0.5
```

Wildcard rules (`*.example.com`) cannot be listed; add them to the zone
yourself. **The proxy itself must resolve the upstream hosts to their real
addresses** — run it with a resolver that does not see the override, or its own
upstream fetches come back to it.

### By a NAT redirect

On a gateway the clients route through (or on the clients' host), redirect
their outbound ports 443 and 80 to the listeners:

```bash
# On the gateway: clients in 10.20.0.0/16, the proxy listening on :8443 and :8080.
iptables -t nat -A PREROUTING -s 10.20.0.0/16 -p tcp --dport 443 -j REDIRECT --to-ports 8443
iptables -t nat -A PREROUTING -s 10.20.0.0/16 -p tcp --dport 80  -j REDIRECT --to-ports 8080

# On the same host as the clients (containers, CI runners): exempt the proxy's own
# traffic, or its upstream fetches are redirected back to it.
iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner pullthrough -j REDIRECT --to-ports 8443
iptables -t nat -A OUTPUT -p tcp --dport 80  -m owner ! --uid-owner pullthrough -j REDIRECT --to-ports 8080
```

A redirect keeps the client's own address as the connection's source, so the
[download log](download-log.md) and the audit log attribute every download to
the real client.

A redirect sends *all* of a client's HTTPS through the proxy, not only package
traffic. By default the proxy refuses what it does not route. With
`passthroughUnmatched: true` it passes such a connection on, undecrypted and
unexamined, to its **original destination** — which the kernel records for a
redirected connection (Linux, `SO_ORIGINAL_DST`; iptables and nftables
`REDIRECT`/`DNAT`). A connection that reached the proxy by DNS has no other
destination; it is refused, as is one whose original destination is one of the
proxy's own listeners (it would loop).

## Configuration

```yaml
server:
  httpAddr: ":8080"                 # explicit /v1 mode (always on)
  intercept:
    enabled: true
    listenAddr: ":3128"             # forward proxy (HTTPS_PROXY); optional with NAT
    nat:                            # NAT mode; either or both
      httpsAddr: ":8443"            # redirected TLS (port 443), routed by SNI
      httpAddr: ":8081"             # redirected plain HTTP (port 80), routed by Host
    caCertFile: "/var/lib/pullthrough/ca/intercept-ca.crt"
    caKeyFile:  "/var/lib/pullthrough/ca/intercept-ca.key"
    generateCa: true                # create the CA on first start if absent
    hosts:                          # beyond what the upstreams give (see Routing)
      deb.debian.org/debian-security: apt-security
    passthroughUnmatched: false     # refuse (don't pass on) unconfigured hosts
    allowPlainHttp: true            # forward proxy: also absolute-form http:// requests

upstreams:
  npm:          { type: npm, url: "https://registry.npmjs.org" }
  pip:          { type: pip, url: "https://pypi.org" }
  apt:          { type: apt, url: "https://deb.debian.org/debian" }
  apt-security: { type: apt, url: "https://deb.debian.org/debian-security" }
```

At least one listener is required; every listener needs an address of its own,
distinct from `server.httpAddr` and `server.sshAddr`. The full reference is
in [configuration-reference.md](configuration-reference.md).

## Client notes

The interception script of every ecosystem in
[ecosystem-tests-reference.md](ecosystem-tests-reference.md) is the verified
setup. What is worth knowing beyond "trust the CA":

- **APT** — the stock sources (`http://deb.debian.org/debian` and
  `…/debian-security`) work unchanged when the proxy has an upstream for each
  archive. No CA is involved: APT verifies the archive signatures.
- **DNF/YUM** — distribution repo files use a *mirror list*, which names hosts
  the proxy cannot know in advance. Switch them to the distribution's own host
  (`baseurl=`), and enable the repositories the proxy has upstreams for.
- **cpanm** — use `--mirror-only`: module resolution otherwise asks
  cpanmetadb, a host the proxy does not serve.
- **Composer** — `--no-audit`: the security-advisory API lives on
  `packagist.org`, not on `repo.packagist.org`.
- **mix/Hex** — `mix local.hex` downloads Hex itself from `builds.hex.pm`; map
  that host to the Hex upstream (`hosts: {builds.hex.pm: hex}`).
- **Homebrew** — bottles come from `ghcr.io` (mapped automatically, see
  Routing); give brew's curl the CA with `HOMEBREW_CURLRC`.
- **Go** — `GOPROXY`/`GOSUMDB` stay at their defaults: the proxy tells the go
  command that it proxies the checksum database, so `sum.golang.org` is never
  contacted.
- **Julia, Docker registry mirrors** — fail-open clients in explicit mode
  (they fall back to another source when the proxy refuses) are fail-closed
  here: the intercepted host *is* the source.

## Observability

- The request log marks intercepted requests with `via` (`intercept` or `nat`)
  and the upstream `host` the client addressed.
- The [download log](download-log.md) records `via` for every intercepted
  download, and filters by it (`?via=intercept|nat|direct`).
- `GET /admin/api/intercept` — listeners, routing table, hostnames, counters;
  `GET /admin/api/intercept/ca.crt` — the CA certificate. `ptctl intercept
  status|ca|hosts` reads both ([client-cli.md](client-cli.md)).
- Metrics:

  | Metric | Labels |
  |---|---|
  | `pullthrough_intercept_connections_total` | `mode` |
  | `pullthrough_intercept_tls_intercepted_total` | `mode` |
  | `pullthrough_intercept_requests_total` | `mode` |
  | `pullthrough_intercept_passthrough_total` | `mode` |
  | `pullthrough_intercept_unrouted_total` | `mode` |
  | `pullthrough_intercept_refused_total` | `mode`, `reason` (`unmatched_host`, `no_server_name`, `not_tls`, `handshake`, `plain_http`) |
  | `pullthrough_intercept_rewritten_responses_total` | — |
  | `pullthrough_intercept_rewritten_links_total` | — |

## Security notes

- **The CA is a trust anchor.** A client that trusts it accepts the proxy's
  certificates for *any* host. Protect `caKeyFile` (written `0600`) like any
  signing key, scope the CA to the fleet that must trust it, and prefer the
  per-tool settings above to the system store so the trust stays narrow.
- **Refusal is the default.** Without `passthroughUnmatched`, the proxy carries
  only traffic to hosts it routes; nothing else is tunnelled, and in NAT mode no
  certificate is minted for an unknown name. Passed-through connections are
  not decrypted, cached or scanned.
- **Clients cannot claim to be intercepted.** Whether a request came through
  interception is attached by the interception listeners, not read from
  anything a client sends; a request to the proxy's own address is explicit.
- **No credential leaves.** A client's registry credentials are removed from
  intercepted requests; upstream fetches use the proxy's own credentials.
- **Leaf certificates** are ECDSA P-256, minted on demand for the routed host
  only, cached in memory (`certCacheSize`), and regenerated on restart.
  `leafTtl` bounds their validity.
- **FIPS mode** (`fips.enabled`) holds the TLS the proxy terminates for
  intercepted clients to the same approved floor as its own listener: TLS 1.2
  or later, AES-GCM cipher suites ([fips-compliance.md](fips-compliance.md)).
- Interception composes with the egress/SSRF guard, client authentication,
  rate limiting and every admission gate exactly as explicit mode does — the
  decrypted request is dispatched through the gateway's `/v1` pipeline.

## Verifying

```bash
# Through the forward proxy, trusting the CA:
curl --cacert intercept-ca.crt -x http://proxy.example.com:3128 https://registry.npmjs.org/lodash \
  | grep -o '"tarball":"[^"]*"' | head -1
# "tarball":"https://registry.npmjs.org/_pullthrough/v1/npm/lodash/-/lodash-0.1.0.tgz"

# As NAT mode sees it: the connection for registry.npmjs.org lands on the NAT listener.
curl --cacert intercept-ca.crt --connect-to registry.npmjs.org:443:proxy.example.com:8443 \
  https://registry.npmjs.org/lodash -o /dev/null -w '%{http_code}\n'

# A host that is not routed is refused:
curl --cacert intercept-ca.crt -x http://proxy.example.com:3128 https://example.com/
# curl: (56) CONNECT tunnel failed, response 403
curl --cacert intercept-ca.crt --connect-to example.com:443:proxy.example.com:8443 https://example.com/
# curl: (35) … tlsv1 unrecognized name
```

## Tests

- `internal/intercept` — routing (hosts, path prefixes, wildcards), the forward
  proxy, the NAT listeners (SNI and `Host` routing, refusals, passthrough to the
  original destination, the client's address), credentials.
- `internal/proxy` (`interceptedge_test.go`) — the link rewriting, and installs
  through the real npm, PyPI and cargo adapters via both listeners.
- The [ecosystem tests](ecosystem-tests.md) — every ecosystem's real client,
  in both modes, against the real registries, in CI.
