# Disaster recovery: backup & restore

This runbook describes how to back up and restore the pull-through proxy's
**stateful data** so an enterprise deployment can meet its **RPO** (recovery
point objective — how much data you can afford to lose) and **RTO** (recovery
time objective — how quickly you must be serving again).

The proxy holds two classes of durable state, and the backup subsystem captures
both into a single, consistent, integrity-verified snapshot:

| Class | What | Where it lives |
|-------|------|----------------|
| **Cache** | the content-addressable artifact cache | `cache.dir` (filesystem) or the S3 bucket (`cache.backend: s3`) |
| **Metadata** | the tamper-evident audit/Merkle log, provenance link store, commit-scan verdicts, VEX statements, policy-as-code bundles | the per-subsystem `*.file` / `*.storeDir` / `*.dir` paths |

In-memory state — the provenance graph, the vulnerability-scan result cache, and
the quarantine set — is **not** captured: it is reconstructed from the durable
stores above and from live pull traffic after a restart, so it never needs to be
restored explicitly.

```
pullthrough backup   -config c.yaml -out snapshot.tar          # write a snapshot
pullthrough restore  -config c.yaml -in  snapshot.tar          # rehydrate from one
```

---

## 1. What a snapshot is

A snapshot is an ordinary **tar stream**, optionally wrapped in a streaming
encryption envelope. Its layout is deterministic:

```
pullthrough-backup.json          # manifest: schema version, per-member SHA-256 digests, record metadata
cache/<sha256-of-cache-key>      # one blob per cache entry, in sorted order
meta/<sha256-of-source+path>     # one member per captured metadata file
```

* **Schema/version header.** The manifest carries `formatVersion`; a restore
  refuses a snapshot whose version it does not understand, so you can never
  silently rehydrate an unrecognized format after an upgrade.
* **Integrity root.** The manifest's canonical JSON is hashed to a
  `sha256:…` **manifest digest**, written to `snapshot.tar.sha256`. Every cache
  blob and metadata file additionally records its own content digest. On restore
  each member is verified against its digest **as it streams**; a mismatch aborts
  the restore and the partially-written member is removed — a corrupt or tampered
  member never lands.
* **Deterministic & resumable.** Identical store contents and creation timestamp
  produce identical bytes (members sorted, fixed tar mod-times), so an interrupted
  backup is safe to re-run and a restore is idempotent (unchanged entries are
  skipped).
* **Bounded memory.** Blobs are streamed, never buffered, so an arbitrarily large
  cache backs up and restores without large memory use.

Transfer the snapshot **and** its `.sha256` sidecar to your recovery location
through your approved channel. Supplying the digest on restore proves the
snapshot was not altered in transit.

---

## 2. Taking a backup

### On demand (CLI)

```
pullthrough backup -config c.yaml -out /backups/snapshot-$(date -u +%Y%m%dT%H%M%SZ).tar
```

Useful flags:

| Flag | Effect |
|------|--------|
| `-out -` | stream the snapshot to **stdout** (pipe to tape, SSH, or `aws s3 cp - …`) |
| `-no-cache` | metadata-only snapshot (when the cache is cheap to re-pull) |
| `-no-metadata` | cache-only snapshot |
| `-encrypt -passphrase …` | encrypt with a scrypt-stretched passphrase |
| `-encrypt -key-file …` | encrypt with a 32-byte raw key (hex/base64) for KMS/HSM workflows |

Encryption flags override the `backup:` config section; without flags the CLI
falls back to it.

### Scheduled (config hook)

Set a `backup:` section to run a consistent snapshot on a fixed interval. The
proxy writes a timestamped snapshot (`pullthrough-backup-<RFC3339>.tar`, plus its
`.sha256`) into `backup.dir` and prunes old ones per `retain`.

```yaml
backup:
  dir: /var/lib/pullthrough/backups   # destination directory (required for scheduled/admin backups)
  interval: 6h                        # >0 enables the scheduled loop; omit/0 = on-demand only
  retain: 14                          # keep the newest 14 snapshots, prune older
  encrypt: true                       # wrap each snapshot in AES-256-GCM
  passphrase: "${PTS_BACKUP_PASSPHRASE}"   # or keyFile: /etc/pullthrough/backup.key
  includeCache: true                  # set false for metadata-only scheduled snapshots
  alertAfter: 26h                     # documented RPO window for the age alert
```

> Store the passphrase/key **out of band** — a snapshot encrypted with a key you
> have also lost is unrecoverable. Use a `${ENV_VAR}` reference or an `enc:v1:`
> sealed value rather than committing the secret.

### On demand (admin API)

`POST <adminPrefix>/api/backup/run` triggers a backup into `backup.dir` and
returns the resulting status. `GET <adminPrefix>/api/backup` reports the age and
outcome of the most recent backup. Both require the admin bearer token when one
is configured.

---

## 3. Restoring

Restore rehydrates a snapshot into the stores named by the **target** config —
usually a freshly-provisioned deployment.

```
pullthrough restore -config target.yaml -in snapshot.tar -manifest-digest snapshot.tar.sha256
```

The restore:

1. detects and removes the encryption envelope (supply `-passphrase`/`-key-file`,
   or the `backup:` config secret);
2. validates the manifest's format version and, when `-manifest-digest` is given,
   the whole-manifest digest;
3. streams each member into the cache store / onto disk, verifying its content
   digest; metadata files are written atomically (temp file + rename);
4. checks completeness — every member the manifest declares must have appeared.

Useful flags:

| Flag | Effect |
|------|--------|
| `-in -` | read the snapshot from **stdin** (air-gapped streaming restore) |
| `-overwrite` | re-write entries that already exist instead of skipping unchanged ones |
| `-cache-only` / `-metadata-only` | restore only one class of state |
| `-manifest-digest <sha256 \| path>` | verify the whole-snapshot digest before applying |

Metadata is restored to the paths in the **target** config: the audit log goes to
`audit.file`, VEX to `vulnerabilities.vex.dir`, and so on. To restore into a
different layout, point the target config at the new paths.

### Recommended recovery procedure (RTO)

1. Provision a new proxy instance with a config that points the cache and
   metadata paths at fresh (empty) storage.
2. Copy the latest `snapshot.tar` and `snapshot.tar.sha256` to the host.
3. `pullthrough restore -config target.yaml -in snapshot.tar -manifest-digest snapshot.tar.sha256`
   (add `-passphrase`/`-key-file` if encrypted).
4. Verify the audit log's tamper-evidence survived (next section).
5. Start the proxy. The in-memory provenance graph, scan cache, and quarantine
   set rebuild from the restored stores and resuming traffic.

---

## 4. Verifying the audit log survives a round-trip

The tamper-evident audit log is the most sensitive store: its Merkle
transparency guarantees (signed checkpoints, inclusion/consistency proofs) must
still hold after a restore. They do — the backup captures both the append-only
log file and its checkpoint file, and their digests are verified on restore — and
you can confirm it independently:

```
pullthrough verify-audit /restored/audit.log \
  --audit-key "$PTS_AUDIT_HMAC_KEY" \
  --audit-checkpoints /restored/audit.log.checkpoints
```

This recomputes the Merkle root over the restored records, cross-checks every
sealed checkpoint (the key-independent line of defense), and verifies checkpoint
signatures when a public key is supplied. A clean result proves the round-trip
preserved the log's integrity. (The round-trip is also covered by an automated
test: `TestMerkleConsistencyProofsSurviveRoundTrip`.)

---

## 5. Alerting

The proxy exposes backup-health metrics for Prometheus:

| Metric | Meaning |
|--------|---------|
| `pullthrough_backup_age_seconds` | seconds since the last successful backup (`-1` if none) — the **RPO signal** |
| `pullthrough_backup_last_success_timestamp` | Unix time of the last success (`0` if none) |
| `pullthrough_backup_last_duration_seconds` | duration of the most recent backup |
| `pullthrough_backup_last_bytes` | bytes written by the most recent successful backup |
| `pullthrough_backup_success_total` / `pullthrough_backup_failure_total` | cumulative outcomes |

Two alerts ship in `deploy/observability/prometheus/alerts.yaml`:

* **PullthroughBackupTooOld** — `backup_age_seconds` exceeds the RPO window (or is
  `-1`). Restoring would lose more data than allowed: investigate the scheduler
  and destination immediately.
* **PullthroughBackupFailing** — a backup attempt failed in the last hour. Even
  within RPO, an unaddressed failure streak will eventually breach it; check the
  destination's capacity/permissions and the proxy logs.

Tune the `PullthroughBackupTooOld` threshold to your `backup.interval` and RPO
(the default 26h suits a daily schedule with slack).

---

## 6. Operational notes

* **S3-backed caches.** Backup/restore work identically for `cache.backend: s3`:
  the cache is read and rehydrated through the storage-agnostic store interface.
  A backup of an S3 cache is a portable, point-in-time copy independent of the
  bucket's own versioning/replication.
* **Air-gapped transfer.** Use `-out -` / `-in -` to stream straight to and from
  removable media or `ssh`, never staging the whole snapshot on disk. This is the
  same streaming format the air-gapped mirror bundle uses (see
  [air-gapped.md](air-gapped.md)); the two are complementary — the mirror moves
  *content into* a sealed instance, backup/restore protects *all state* for DR.
* **Test your restores.** A backup you have never restored is a hypothesis. Run a
  periodic restore drill into a scratch instance and `verify-audit` the result.
* **Consistency.** A snapshot is taken from live stores; the cache and metadata
  are captured close together but not in a single atomic transaction. Because the
  cache is content-addressed and the audit log is append-only, a snapshot is
  always **self-consistent for recovery** — at worst it omits the most recent
  in-flight writes, which is exactly the RPO window the age alert guards.
```
