# Range requests & zero-buffer streaming

The proxy serves cached artifacts with **HTTP Range support (RFC 7233)** and
streams upstream fetches into the cache with **bounded memory**, so large
artifacts — Docker layers, multi-hundred-MB tarballs, OS package files — are
served and filled without ever being held whole in RAM, and clients can resume
or parallelize downloads.

This page documents the behavior and its memory/throughput characteristics.

## Serving partial content

Every artifact served from the content-addressable cache advertises
`Accept-Ranges: bytes`. Clients (Docker's layer puller, package managers,
download accelerators, `curl -C -`) may therefore request a byte range and
resume an interrupted transfer.

| Client sends | Proxy responds |
|--------------|----------------|
| no `Range` | `200 OK`, full body, `Content-Length: <size>` |
| `Range: bytes=5-9` | `206 Partial Content`, `Content-Range: bytes 5-9/<size>`, `Content-Length: 5` |
| `Range: bytes=-256` (suffix) | `206`, last 256 bytes |
| `Range: bytes=1000-` (open-ended) | `206`, from offset 1000 to end |
| `Range: bytes=<beyond size>` | `416 Range Not Satisfiable`, `Content-Range: bytes */<size>` |
| `Range` + `If-Range: <validator>` | `206` if the validator still matches, else `200` full body |

Range parsing, multi-range handling, `Content-Range`, and `If-Range` evaluation
are delegated to the Go standard library's `http.ServeContent`, which implements
RFC 7233 (including the rule that `If-Range` requires a **strong** validator).

### `If-Range` and validators

`If-Range` lets a client resume only if the representation has not changed. The
proxy serves the upstream's `ETag` when one was captured at fetch time; that is
normally a strong validator and works with `If-Range`. When the upstream
supplied no `ETag`, the proxy synthesizes a **weak** validator from the
content-addressable key and size (`W/"…"`). Per RFC 7233 a weak validator never
satisfies `If-Range`, so such a conditional resume safely falls back to a full
`200` re-download rather than risking a torn artifact. Artifacts addressed by
content digest are immutable, so this is conservative, not lossy.

## Memory characteristics

### Filesystem cache — the production path

The filesystem cache hands back the blob as an `*os.File`, which is seekable.
Range requests are satisfied by **seeking within the file** and streaming only
the requested window. Memory use per request is a fixed copy buffer (tens of
KiB), **independent of artifact size or range size**. No spill, no buffering.

### Forward-only bodies — spill to disk

Some cache backends (an object-storage stream, the in-memory cache in a
degraded path) may hand back a **forward-only** body with no random access. When
such a body receives a *range* request, the proxy **spools it to a temporary
file once** to obtain seek support, serves the range from that file, and removes
it when the response completes. This is the `pullthrough_range_spill_to_disk_total`
event. The spill copies to **disk, not RAM**, so memory stays bounded; the cost
is one extra disk pass. A *non-range* request over a forward-only body streams
straight through with no spill.

The filesystem cache never spills — it is already seekable — so a typical
deployment shows a spill counter of zero.

## Filling the cache without buffering

On a cache miss the upstream body is streamed **through** to the cache store,
which copies it to a staging file and atomically renames it into place only on
full completion. The body is never accumulated in memory.

Two integrity properties follow:

1. **Aborted/partial streams cannot poison the cache.** If the upstream
   connection drops mid-transfer, the copy fails, the staging file is discarded,
   and no cache entry is committed. The next request re-fetches.

2. **Digest is verified incrementally; commit only on a verified full stream.**
   When the resolution stage knows the expected content digest
   (`Resolved.Digest`, e.g. `sha256:…`), the body is streamed through a verifier
   that hashes bytes as they flow to disk. At end-of-stream the running hash is
   compared to the expected digest; a mismatch is substituted for the EOF, which
   fails the store write so the entry is **never committed**. A tampered or
   truncated upstream response is therefore refused before it can be served or
   cached, counted as `pullthrough_stream_digest_mismatch_total`. Verification is
   opt-in: an empty or unsupported digest scheme passes the body through
   unwrapped (digest checking still happens inside backends that compute their
   own checksums).

## Admission gates and the full artifact

Gates that need the whole artifact (vulnerability scan, signature/attestation
verification, secret detection, license, install-hook, SBOM-diff) run **after
the cache is filled and before the bytes are served**. Each gate opens its own
independent stream from the cache (the full blob), so range serving on the
client-facing side never starves a gate of content, and a gate never consumes
the stream destined for the client. Because the artifact is already committed to
the cache by the time gates run, they read it with the same bounded-memory,
seek-capable access described above.

## Throughput notes

- Range serving from the filesystem cache is a `sendfile`-friendly file copy;
  throughput is bounded by disk and network, not by the proxy.
- Parallel ranged GETs against the same cached artifact are independent file
  reads and scale with the underlying storage.
- The single-flight loader still collapses concurrent **misses** for the same
  artifact onto one upstream fetch; once filled, ranged reads fan out freely.

## Metrics

All counters are exported on the Prometheus endpoint:

| Metric | Meaning |
|--------|---------|
| `pullthrough_range_requests_total` | client requests carrying a `Range` header |
| `pullthrough_range_partial_served_total` | responses answered `206 Partial Content` |
| `pullthrough_range_unsatisfiable_total` | responses answered `416 Range Not Satisfiable` |
| `pullthrough_range_spill_to_disk_total` | forward-only bodies spooled to a temp file to satisfy a range |
| `pullthrough_streamed_bytes_total` | body bytes streamed to clients from the cache serve path |
| `pullthrough_stream_digest_mismatch_total` | upstream streams rejected mid-fill for a content-digest mismatch |

See [observability.md](observability.md) for the full metrics catalog.
