# Generic declarative backend

The proxy ships dedicated, protocol-aware backends for every common ecosystem
(pip, npm, cargo, Go, NuGet, Maven, Docker/OCI, Helm, APT/YUM, Terraform, Conan,
Conda, CRAN, Hex, Bazel, Julia, CPAN, Swift, Dart/pub, Hugging Face, OpenVSX,
Nix, Git, …). When you need to front a registry that none of those cover, the
**generic backend** (`type: generic`) lets you onboard it entirely in YAML — base
URL, path routing, cacheability, content-address verification, metadata URL
rewriting, and content-gate coverage — **with no code changes**.

A generic upstream routes through exactly the same gated pull pipeline as every
dedicated backend: cacheable artifacts flow through `serveCacheable` and are
therefore subject to every enabled admission/content gate (vulnerability scan,
license, content-analysis, antivirus, policy, risk, …). The only difference is
that classification is driven by declarative rules instead of compiled code.

> Security posture: the route set is an **allowlist**. A request whose path
> matches no route is refused (`501 Not Implemented`), and the fetched upstream
> URL is always your configured base joined with the request path — never a
> client-controlled host. A generic upstream can therefore never become an open
> relay. Unsafe or incoherent configurations are rejected at load time (see
> [Validation](#validation)).

## Quick start

```yaml
upstreams:
  mysource:
    type: generic
    url: https://repo.example.com          # upstream base URL
    # credentials: { token: "${MYSOURCE_TOKEN}" }   # optional
    generic:
      # Externally reachable mount, used to rewrite absolute upstream URLs in
      # metadata documents back through the proxy. Optional; defaults to the
      # proxy's derived public mount for this upstream.
      publicBaseURL: https://proxy.example.com/v1/mysource
      routes:
        # 1. Mutable metadata/index documents: served live, not cached, and their
        #    embedded upstream URLs rewritten so dependent downloads come back
        #    through the proxy (and its gates).
        - name: metadata
          match: '^/packages/[^/]+/index\.json$'
          rewrite: true

        # 2. Immutable artifacts: cached, routed through the content-gate
        #    pipeline, and verified against a sibling ".sha256" checksum file
        #    before any byte is cached or served.
        - name: artifact
          match: '^/packages/[^/]+/.+\.tar\.gz$'
          cacheable: true
          mediaType: application/gzip
          gates: [contentscan, avscan, vulnscan]
          verify:
            algorithm: sha256
            source: sidecar
            sidecarSuffix: .sha256
```

Clients then point at `https://proxy.example.com/v1/mysource/…` and the proxy
fronts `https://repo.example.com/…`.

Validate a candidate config before rollout:

```console
$ pullthrough verify-config -config config.yaml
# or
$ ptctl config validate config.yaml
```

## Routes

`generic.routes` is an **ordered** list; the **first** route whose `match`
matches the inbound request path (the path with the `/v1/<name>` mount prefix
already stripped, leading slash included) decides how the request is served.
Order your routes most-specific first.

| Field | Type | Meaning |
|-------|------|---------|
| `name` | string | Label for diagnostics, metrics, and resolved metadata. Optional. |
| `match` | string | **RE2 regular expression** matched against the request path. Required; must compile. Anchor it (`^…$`). |
| `cacheable` | bool | Cache responses and route them through the full content-gate pipeline. Use for immutable artifacts only; leave `false` for mutable listings. |
| `rewrite` | bool | Buffer the response body and rewrite absolute upstream-base URLs to the proxy's public base. For metadata documents; mutually exclusive with `cacheable`/`verify`. |
| `verify` | object | Enable [verify-on-fetch](#verification) content-address verification. Requires `cacheable`. |
| `gates` | []string | Operator-declared content-gate allowlist for audit/telemetry (see [Content gates](#content-gates)). |
| `mediaType` | string | Override the served `Content-Type` (e.g. `application/gzip`). Optional. |

## Verification

A `verify` block turns a cacheable route into a **content-addressable** route:
the fetched artifact is streamed through a hasher and the recomputed digest is
compared to the expected one. On a mismatch the stream fails with a
`ChecksumMismatchError` **at end-of-stream**, which aborts the cache write (the
partial blob is never committed) and fails the client download — so a tampered or
corrupt mirror/CDN can neither poison the cache nor reach a client. The artifact
body is never buffered; verification is streaming, exactly like the OpenVSX, Nix,
and Julia backends.

| Field | Type | Meaning |
|-------|------|---------|
| `algorithm` | string | `sha256`, `sha512`, or `sha1`. Required. Prefer `sha256`+. |
| `source` | string | Where the expected digest comes from: `sidecar` (default) or `path`. |
| `sidecarSuffix` | string | For `source: sidecar` — forms the sidecar URL from the artifact URL (e.g. `.sha256`). Required. |
| `sidecarReplacesExtension` | bool | Replace the artifact URL's final extension with `sidecarSuffix` (`foo.tar.gz` → `foo.tar.sha256`) instead of appending (`foo.tar.gz` → `foo.tar.gz.sha256`). |
| `digestGroup` | int | For `source: path` — 1-based index of the `match` capture group holding the hex digest. |
| `failOpen` | bool | Serve the artifact unverified if no digest can be recovered (e.g. a missing sidecar). Default `false` — **fail closed**, which refuses the fetch. |

### Sidecar digests

Many registries publish a checksum file next to each artifact. Point
`sidecarSuffix` at it; the proxy fetches the sidecar (from the same upstream
host, so no SSRF surface), parses a bare hex digest or the GNU coreutils
`<hex>  <filename>` form, and verifies the artifact against it.

```yaml
- name: artifact
  match: '^/dist/.+\.whl$'
  cacheable: true
  verify:
    algorithm: sha256
    source: sidecar
    sidecarSuffix: .sha256
```

### Path-embedded digests

Content-addressed layouts embed the digest in the URL. Capture it with a regex
group and reference it with `digestGroup`:

```yaml
- name: cas
  match: '^/cas/([0-9a-f]{64})/blob$'
  cacheable: true
  verify:
    algorithm: sha256
    source: path
    digestGroup: 1
```

The resolved metadata records `generic.checksumVerified` = the algorithm on a
verified artifact, or `none` when a `failOpen` route served an artifact with no
recoverable digest. A verified artifact also carries an `X-Checksum-Verified`
response header.

## Metadata URL rewriting

Registries typically return metadata/index documents containing absolute
download URLs that point at the upstream (or its CDN). A `rewrite: true` route
buffers the (bounded — see `maxRewriteBytes`) document and rewrites every
occurrence of the configured upstream base URL to `publicBaseURL`, so a client's
dependent downloads flow back through the proxy and its gates rather than going
directly to the upstream. Links to other hosts (a project homepage, source repo,
…) are left untouched. A document larger than the cap is streamed through
unmodified.

`rewrite` is mutually exclusive with `cacheable` and `verify` on the same route:
a mutable document is served live; an immutable artifact is verified, not
rewritten.

## Content gates

Marking a route `cacheable: true` is what subjects its artifacts to the proxy's
content-gate pipeline — the globally-enabled gates (vulnerability scan, license,
content-analysis, antivirus, policy, risk, …) run over every cacheable artifact
regardless of ecosystem. The per-route `gates` list is a **declared allowlist of
intent**: each name is validated at load time (so a typo is caught early) and
recorded in the artifact's metadata (`generic.contentGates`) for audit and
telemetry. Known gate identifiers:

`vulnscan`, `license`, `sbomdiff`, `installhooks`, `contentscan`, `mlguard`,
`avscan`, `llmpkgscan` (also accepted under its configuration key,
`llmPackageScan`), `sigverify`, `malfeed`, `maturity`, `nameguard`,
`depfirewall`, `reposcore`.

Note that some gates are inherently ecosystem-specific (for example `mlguard`
only acts on Hugging Face weight files, and coordinate-based OSV vulnerability
lookup has no ecosystem mapping for an arbitrary generic source). Those gates
simply no-op for a generic artifact they cannot interpret; the content-bytes
gates (`contentscan`, `avscan`) apply to any cached artifact.

### The LLM package scan on a generic route

One identifier in `gates` does more than record intent. A route that lists
`llmPackageScan` (or `llmpkgscan`) declares that what it serves is an
**installable payload** for the [LLM package-content scan](llm-package-scan.md):

```yaml
routes:
  - name: releases
    match: '^/releases/v[0-9.]+/tool-[a-z0-9_-]+\.tar\.gz$'
    cacheable: true
    gates: [llmPackageScan, contentscan]
  - name: installer            # a script on a moving path: not cacheable
    match: '^/install\.sh$'
    gates: [llmPackageScan]
```

- What such a route serves is **always examined**, as an archive or — an
  installer script, a single binary — as the one file it is.
- That holds **whether or not the route is cacheable**: a non-cacheable response
  is held until its verdict exists and only then served.
- The scope is the upstream's ecosystem key, `generic`; `llmPackageScan.exclude`
  or `excludeUpstreams` still take a generic upstream out of the scan.

A route that does not list it is not exempt. Its responses are unclassified,
and the scan still examines one whose bytes are an archive, an executable, a
script or a pickle; a `rewrite: true` route is treated as an index, which is
left alone unless it turns out to serve a package. See
[what is examined](llm-package-scan.md#what-is-examined).

## Top-level options

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `routes` | []route | — | Ordered classification rules. **At least one required.** |
| `publicBaseURL` | string | derived mount | Public base used for metadata URL rewriting. |
| `maxRewriteBytes` | int | 33554432 (32 MiB) | Cap on a metadata document buffered for rewriting; larger documents are streamed unmodified. |

## Validation

Both `pullthrough verify-config` / `ptctl config validate` (load-time preflight)
and backend construction run the **same** validation and reject:

- a `generic` upstream with no `generic` block, or a non-`generic` upstream that
  carries one;
- an empty route set, or a negative `maxRewriteBytes`;
- a missing or uncompilable `match` regexp;
- a duplicate route `name`;
- `rewrite` combined with `cacheable` or `verify` on the same route;
- a `verify` block with a missing/unsupported `algorithm`;
- `source: sidecar` without a `sidecarSuffix`, or `source: path` with a
  `digestGroup` that is `< 1` or exceeds the regexp's capture groups;
- an unknown content-gate name in `gates`.

## Metrics

The backend exports per-upstream counters (label `backend`), surfaced at
`/metrics` when observability is enabled:

| Metric | Meaning |
|--------|---------|
| `pullthrough_generic_artifacts_served_total` | Cacheable artifacts served. |
| `pullthrough_generic_artifacts_verified_total` | Artifacts whose content digest verified. |
| `pullthrough_generic_checksum_mismatches_total` | Artifacts that failed verification and were refused. |
| `pullthrough_generic_checksum_missing_total` | Verified-route artifacts served with no usable digest (fail-open). |
| `pullthrough_generic_sidecars_fetched_total` | Checksum sidecars fetched. |
| `pullthrough_generic_metadata_served_total` | Metadata/listing documents served. |
| `pullthrough_generic_metadata_rewritten_total` | Metadata documents whose URLs were rewritten. |
| `pullthrough_generic_unmatched_total` | Requests refused for matching no route. |

## When to prefer a dedicated backend

The generic backend is deliberately protocol-agnostic. If an ecosystem needs
protocol-specific behavior the declarative model can't express — bespoke
signature formats (Nix narinfo ed25519, APT/YUM GPG), non-trivial index
transforms, UUID/tree-hash coordinate schemes, OCI token handshakes, or
ecosystem-aware OSV coordinates — add a dedicated backend under
`internal/backends/` instead. The generic backend covers the common case: an
HTTP registry addressed by path, with optional sibling or in-path checksums.
