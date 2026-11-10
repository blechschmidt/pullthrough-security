# High availability: shared object-storage cache

By default each proxy replica keeps its own content-addressable cache on local
disk (the `filesystem` backend). That is simple and fast, but it does not scale
horizontally: every replica re-fetches and re-stores the same artifacts, the
cache hit ratio drops as you add replicas, and a per-pod `ReadWriteOnce` volume
ties a pod to a node.

The `s3` cache backend stores the cache in an **S3-compatible object store**
shared by all replicas. Pull an artifact through any replica once and every
replica serves it from the shared bucket thereafter. This is the recommended
backend for multi-replica, highly-available deployments.

Supported object stores: AWS S3, MinIO, Ceph RADOS Gateway, and Google Cloud
Storage via its S3-compatible XML API. The client speaks the S3 REST API with
AWS Signature V4 signing directly — no cloud SDK dependency.

## What is preserved

The `s3` backend implements the same `Store` contract as the filesystem backend
and sits under the same caching layer, so all of the existing semantics carry
over unchanged:

- **Content-addressing** — objects are keyed by the SHA-256 of the cache key,
  with the same two-level fan-out and `blobs/` + `meta/` layout as on disk.
- **Atomic writes** — each object PUT is atomic at the store level; the blob is
  written before its metadata, and reads key off metadata, so a reader never sees
  a torn or dangling entry. Deletes remove metadata first.
- **Single-flight de-duplication** — concurrent misses for the same key on a
  replica are coalesced into one upstream fetch.
- **Sealed (air-gapped) mode** — `cache.sealed: true` works the same way: serve
  what is in the bucket, never fetch upstream.
- **Metrics** — hits, misses, loads, coalesced loads, bytes, and errors are
  reported exactly as for the filesystem backend.

## Cache integrity across backends

Read-time content-integrity verification and self-healing (see
[security-model.md](security-model.md#cache-integrity-verification--self-healing))
work identically over **both** cache backends, because the fixity baseline lives
on the same `Store` contract they share:

- **Filesystem backend** — each replica owns its disk. The content digest is
  computed as the blob streams to disk on write, and verified as it streams to
  the client on serve. A replica detects rot or tampering of *its own* on-disk
  copy and re-fetches a clean copy from upstream, repopulating its local store.
- **S3 backend** — the shared bucket is the durable store. The digest recorded
  on write reuses the SHA-256 the signed `PUT` already computes, so there is no
  extra upload-time cost, and it is stored in the per-object metadata record in
  the bucket. On serve, each replica streams the object it downloaded from the
  bucket through that digest. A corruption introduced into the bucket (a
  truncated/garbled object, a lifecycle or replication mishap, out-of-band
  tampering) is caught by **whichever replica serves it next**.

**Self-heal is bucket-wide for S3.** When a replica quarantines a corrupted
object it deletes it from the shared bucket; the next pull — on *any* replica —
misses and re-fetches from upstream, and because keys are content addresses the
re-written object is byte-identical to what every other replica expects. One
replica's heal fixes the entry for the whole fleet.

**Sealed (air-gapped) mode caveat.** In `cache.sealed: true` a corrupted entry
is still quarantined and alerted on, but it **cannot** self-heal — there is no
upstream to re-fetch from. Restore the entry from a clean import bundle (see
[air-gapped import/export](configuration.md)) after investigating.

**The background integrity scan** (`POST /admin/api/integrity/scan`) re-reads and
re-hashes every cached entry. Trigger it against a **single replica**: with the
S3 backend that replica lists and downloads every object in the bucket to
re-hash it (a read-heavy, egress-incurring pass), so running it on every replica
at once would multiply that cost for no benefit — one replica's scan verifies and
heals the shared bucket for all. With the filesystem backend the scan is
inherently per-replica (each walks its own disk); schedule it on each.

Both backends expose the same integrity metrics
(`pullthrough_integrity_verifications_total`,
`pullthrough_integrity_failures_total`) on `/metrics`; a non-zero failure count
on a shared bucket warrants investigating the object store (lifecycle rules,
replication, client-side tampering) in addition to the proxy.

## How sharing works (and its consistency model)

Each replica keeps a small in-memory index for LRU ordering and TTL, warmed by
listing the bucket at startup. To make replicas genuinely share — including
artifacts a *peer* wrote after this replica started — the `s3` backend enables
**shared mode** (`cache.s3.sharedMode: true`, the default): a read that misses
the in-memory index falls back to the bucket before reporting a miss, and adopts
what it finds into the local index.

Because keys are content addresses, cross-replica writes are idempotent: if two
replicas fetch the same artifact before either has published it, single-flight
de-dupes within each replica and the two PUTs write identical bytes to the same
key. There is no destructive race.

**Retention.** Per-replica LRU eviction (`maxSizeBytes`) is uncoordinated across
replicas in shared mode — each replica only sees part of the bucket between
warm-ups. For a shared bucket, **leave `maxSizeBytes` at `0` and manage retention
with an object-store lifecycle policy** (e.g. expire objects under the cache
prefix after N days). TTL (`cache.ttl`) still applies per entry based on the
stored creation time and is safe to use.

**Scheduled jobs.** Once you run more than one replica, enable
[distributed coordination](coordination.md) (`coordination.enabled: true`) so the
shared-state scheduled jobs — CVE-drift re-scan, the backup scheduler, and audit
checkpoint signing — run on only one replica at a time instead of all of them.
The `s3` coordination backend reuses this same bucket and credentials.

## Minimal configuration

```yaml
cache:
  backend: s3
  ttl: 168h
  maxSizeBytes: 0            # retention via bucket lifecycle, not LRU
  s3:
    endpoint: https://s3.us-east-1.amazonaws.com
    region: us-east-1
    bucket: my-org-pullthrough-cache
    prefix: cache/
    usePathStyle: false      # true for MinIO / Ceph
    accessKeyId: ${PTS_CACHE_S3_ACCESS_KEY_ID}
    secretAccessKey: ${PTS_CACHE_S3_SECRET_ACCESS_KEY}
```

Credentials should never be committed: use `${VAR}` expansion (resolved from the
environment / a Kubernetes Secret), an `enc:v1:` encrypted value, or the
`PTS_CACHE_S3_*` environment overrides. See
[configuration.md](configuration.md#caches3-shared-object-storage-backend) for
every field.

### MinIO / Ceph

Non-AWS implementations require **path-style addressing**:

```yaml
    endpoint: http://minio.minio.svc:9000
    usePathStyle: true
```

### AWS S3

On EKS, prefer IRSA (IAM Roles for Service Accounts) or another mechanism that
injects temporary credentials; pass the session token via
`cache.s3.sessionToken` when present. The IAM policy needs `s3:GetObject`,
`s3:PutObject`, `s3:DeleteObject`, and `s3:ListBucket` on the bucket and prefix.

## Deploying for HA

1. **Create the bucket** and a lifecycle rule on the cache prefix.
2. **Switch the backend** to `s3` (see the snippets in `deploy/`):
   - Helm: set `config.cache.backend: s3` and the `config.cache.s3` block in
     `values.yaml`; add `PTS_CACHE_S3_*` to `secrets.data` or an existing Secret.
   - Raw manifests: patch the `cache:` block in `deploy/k8s/configmap.yaml` and
     apply `deploy/k8s/shared-cache.example.yaml` for the credentials Secret.
3. **Drop the per-pod cache volume** — the bucket is now the durable cache, so
   `persistence` / `pvc.yaml` is no longer required for the cache. (Keep a volume
   for the audit log and other `*.storeDir` state if you use them.)
4. **Scale out** — raise `replicaCount` / the HPA and add a PodDisruptionBudget;
   replicas are now stateless with respect to the cache.

A spool directory is used to stage large uploads so their length and digest can
be computed for a signed PUT. It defaults to the OS temp dir (the container's
`/tmp` emptyDir); set `cache.s3.spoolDir` to a sized volume if you cache very
large artifacts (e.g. multi-GB Docker layers) on a read-only root filesystem.

## Verifying

- `GET /readyz` and `GET /healthz` report process health as usual.
- The cache metrics on `/metrics` should show rising `hits` and a hit ratio that
  *improves* (not degrades) as you add replicas — the signal that sharing works.
- Inspect the bucket: you should see `…/<prefix>blobs/…` and `…/<prefix>meta/…`
  objects accumulating.

## Testing against MinIO

Integration tests run against a real MinIO and are gated behind the `integration`
build tag (the same convention as the Git and Docker backends):

```sh
docker compose --profile extras up -d minio
mc alias set local http://127.0.0.1:9000 pullthrough pullthrough123
mc mb local/pts-itest

PTS_TEST_S3_ENDPOINT=http://127.0.0.1:9000 \
PTS_TEST_S3_BUCKET=pts-itest \
PTS_TEST_S3_ACCESS_KEY=pullthrough \
PTS_TEST_S3_SECRET_KEY=pullthrough123 \
  go test -tags integration -run TestS3 ./internal/cache/
```

`make test-integration` runs the full tagged suite. Without `PTS_TEST_S3_ENDPOINT`
the S3 integration tests skip, so the default `make test` stays hermetic.
