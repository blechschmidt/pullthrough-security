# Air-gapped mirror: pre-warm, export/import & sealed mode

This document describes the operational tooling for **disconnected** and
**enterprise** deployments (Task 17): pre-warming a cache from a declarative
manifest, exporting the cache and provenance metadata to a portable,
integrity-verified bundle, importing that bundle into an isolated instance, and
running the proxy in **sealed (offline)** mode where it serves only from cache
and never reaches upstreams.

All three CLI subcommands operate on the **same content-addressable cache store
and provenance link store** the running proxy uses, so the data they read and
write is exactly what the gateway serves.

```
pullthrough prewarm  -config c.yaml -manifest warm.yaml   # fill cache from a manifest
pullthrough export   -config c.yaml -out bundle.tar       # serialize cache → bundle
pullthrough import   -config c.yaml -in  bundle.tar       # load bundle → cache (verified)
```

## The typical workflow

```
┌─────────────── connected (staging) ───────────────┐      ┌──── air-gapped (prod) ────┐
│  1. prewarm  → pulls packages/images into cacheA   │      │                           │
│  2. export   → cacheA + provenance → bundle.tar    │ ───► │  3. import → cacheB        │
│               (+ bundle.tar.sha256 manifest digest)│ usb/ │     (verifies every blob   │
│                                                    │ wire │      against its digest)    │
└────────────────────────────────────────────────────┘      │  4. run sealed: serve-only │
                                                             └────────────────────────────┘
```

Transfer the bundle **and** its `.sha256` sidecar (the manifest digest) to the
target through your approved channel. The digest is what lets the importer prove
the bundle was not altered in transit.

## 1. Pre-warming the cache

Author a declarative manifest of the artifacts the sealed instance must serve.
Each entry names an upstream (by its configured route name) and the request path
under it — the same path a client would request through the proxy.

```yaml
# warm.yaml
packages:
  - upstream: npm
    path: /lodash/-/lodash-4.17.21.tgz
  - upstream: pip
    path: /packages/source/r/requests/requests-2.31.0.tar.gz
images:
  # For Docker/OCI, list the manifest and each layer/config blob you need.
  - upstream: dockerhub
    path: /v2/library/alpine/manifests/3.19
  - upstream: dockerhub
    path: /v2/library/alpine/blobs/sha256:c6a83f...
```

```
pullthrough prewarm -config c.yaml -manifest warm.yaml -concurrency 8
```

Pre-warming replays each request through the **live backend Resolve/Fetch
pipeline** — the exact code path the proxy uses on a cache miss — so warmed
entries land under precisely the keys the proxy will later read. Already-cached
entries are reported as `cached` and not re-fetched. Use `-continue-on-error` to
warm as much as possible and collect failures rather than stopping at the first.

> Non-cacheable resources (mutable index documents such as npm packuments or
> PyPI Simple pages) cannot be pinned and are reported as errors — pre-warm the
> concrete artifact paths instead.

## 2. Exporting a bundle

```
pullthrough export -config c.yaml -out bundle.tar
```

The bundle is an ordinary **tar archive** with a deterministic layout:

```
pullthrough-bundle.json          # manifest: format version, per-entry records + digests, provenance links, scan verdicts
blobs/<sha256-of-cache-key>      # one content blob per cache entry, in sorted order
```

* **Integrity root.** The manifest's canonical JSON is hashed to a
  `sha256:…` **manifest digest**, written to `bundle.tar.sha256`. Every cache
  entry additionally carries the `sha256` digest of its blob.
* **Deterministic.** Given the same store contents and creation timestamp the
  same bytes are produced (entries sorted by key, fixed tar mod-times), so an
  interrupted export is safely re-runnable.
* **Bounded memory.** Blobs are streamed, never buffered, so arbitrarily large
  caches export without large memory use.

Pass `-no-provenance` to omit provenance links (cache content only). The export
requires `cache.backend: filesystem`.

* **Scan verdicts travel with the content.** When the
  [LLM package-content scan](llm-package-scan.md) persists its verdicts
  (`llmPackageScan.storeDir`), the manifest also carries the verdicts on record
  for the artifacts in the bundle — and only for those. The gate needs an LLM
  provider, which a sealed instance cannot reach; carried verdicts are what let
  it refuse an artifact the connected instance judged malicious, and admit the
  ones it judged clean, without a scan. They are part of the manifest and so
  are covered by the manifest digest. Pass `-no-verdicts` to leave them out.

## 3. Importing a bundle

```
pullthrough import -config c.yaml -in bundle.tar -manifest-digest bundle.tar.sha256
```

Import verifies integrity at two levels:

1. **Per-blob.** Each blob is streamed into the cache store while its content is
   hashed and checked against the digest recorded in the manifest. A mismatch
   aborts the import and the partially-written entry is removed — a tampered or
   corrupt blob never lands in the cache.
2. **Whole-bundle (optional).** When `-manifest-digest` is supplied (either a
   literal `sha256:…` or the path to the `.sha256` sidecar), the importer
   recomputes the manifest digest and refuses the bundle on any mismatch,
   detecting tampering of the manifest itself.

**Resumable / idempotent.** Entries already present at the expected size are
skipped, so re-running an interrupted import only transfers what is missing.
Pass `-overwrite` to force re-importing every entry.

**Scan verdicts need the manifest digest.** Imported content is gated when it
is served, like anything else in the cache, so importing blobs from a bundle
nobody vouched for adds no trust. A verdict is different: the importing
instance *acts* on it — a "benign" verdict admits an artifact without a scan.
Verdicts are therefore imported **only when `-manifest-digest` was given and
matched**, i.e. when the bundle is known to be the one the exporting instance
wrote. Without it the blobs are imported, the verdicts are not, and the import
says how many were left out. In addition:

* each verdict must be about a blob the bundle itself carries, and must be
  filed under the key the gate derives from the artifact, model and prompt
  version it names — a record cannot be placed under another artifact's key;
* a verdict the importing instance already holds is never replaced;
* the importing instance needs `llmPackageScan.storeDir` (where the verdicts are
  filed) and the same `llmPackageScan.model` as the exporter (a verdict's key
  includes the model). An artifact that arrives without a verdict is handled by
  `llmPackageScan.failMode`, as on any instance that cannot reach its provider.

## 4. Sealed (offline) mode

Set `cache.sealed: true` to run a fully disconnected instance:

```yaml
cache:
  backend: filesystem
  dir: /var/lib/pullthrough/cache
  sealed: true
```

In sealed mode:

* **Cacheable artifacts** are served from the cache; a miss is **terminal** —
  the cache never invokes an upstream loader. This is enforced at the cache
  layer (`SealedCache`), the single seam through which a cacheable artifact would
  otherwise be fetched.
* **Live (non-cacheable) fetches** are refused at the backend layer
  (`backends.Seal`), so the gateway's direct-serving path also stays offline.
  The Git smart-HTTP backend is governed by its own mirror/refresh policy.

Sealing is **defence in depth**, not a substitute for network isolation: deploy
a sealed instance with no network route to upstreams as well. The admin overview
(`info.cacheSealed`) reports whether sealing is active.

> Pre-warming intentionally bypasses the seal (it must reach upstreams). Run
> `prewarm` on a connected instance — or against a connected config — before
> sealing the production instance.

## 5. Offline security-feed bundles

Several admission gates ingest curated external feeds that a sealed instance
cannot reach live. Each exports a **signed** bundle on a connected host for
transfer into the air-gapped environment:

* **Known-malicious packages** (`internal/malfeed`, Task 48) — build an
  Ed25519-signed bundle of the OSV/GHSA malware dataset and import it at startup:

  ```sh
  # connected host
  pullthrough malfeed keygen -private malfeed.key -public malfeed.pub
  pullthrough malfeed export -config c.yaml -key malfeed.key -out malfeed-bundle.json
  ```

  ```yaml
  # air-gapped proxy
  malfeed:
    enabled: true
    sources: []
    bundlePath: /etc/pullthrough/malfeed-bundle.json
    bundlePublicKeyFile: /etc/pullthrough/malfeed.pub   # pins the signer
  ```

  Import verifies the payload digest and signature against the pinned key. With
  `failClosed: true` the gate refuses all pulls once the bundle ages past
  `staleAfter`, so refresh the bundle on your transfer cadence. See
  [malfeed.md](malfeed.md).
* **Signature trust material** (`internal/sigverify`, Task 23) — see
  [sigverify.md](sigverify.md) and the `sigverify.offline` / `trustBundleFile`
  configuration.
