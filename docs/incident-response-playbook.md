# Operator runbook & incident-response playbook

This is the **consolidated, action-first** runbook for a security operator on
call. Where the [admin runbook](runbook.md) covers day-to-day operation (startup,
health, metrics, routine tasks), this document ties the proxy's many security
subsystems together into **step-by-step procedures** for the situations an
operator actually gets paged for:

1. [Responding to a quarantine / break-glass event](#1-quarantine--break-glass)
2. [Engaging and clearing the emergency lockdown kill-switch](#2-emergency-lockdown--kill-switch)
3. [Interpreting the risk-scoring verdict and the compliance scorecard](#3-reading-the-risk-verdict--compliance-scorecard)
4. [Disaster-recovery backup & restore](#4-disaster-recovery-backup--restore)
5. [Rotating signing keys and OIDC secrets](#5-rotating-signing-keys--oidc-secrets)
6. [Handling a newly-ingested malware-feed hit](#6-malware-feed-hit)

Each procedure names the **RBAC role** required for every action, the exact
**CLI subcommand / API endpoint** (validated against the current code), and a
decision tree for the common branches. Start with the conventions below, then
jump to the procedure you need.

---

## Conventions & prerequisites

### The two binaries

| Binary | Role | Used in this playbook for |
|--------|------|---------------------------|
| `pullthrough` | the server **and** its offline/maintenance subcommands | `backup`, `restore`, `malfeed …`, `-verify-audit` |
| `ptctl` | the client/operator CLI (HTTP-only, talks to the admin API) | `lockdown`, `inspect`, `dossier`, `timeline`, `snapshot` |

`ptctl` honours these global flags (and the matching `PULLTHROUGH_*` env vars) on
every subcommand:

```
--url           proxy base URL              (env PULLTHROUGH_URL)
--token         proxy / admin access token  (env PULLTHROUGH_TOKEN)
--tenant        tenant/team scope           (env PULLTHROUGH_TENANT)
--admin-prefix  admin API prefix (/admin)   (env PULLTHROUGH_ADMIN_PREFIX)
--insecure      skip TLS verification (dev only)
--timeout       per-request timeout (default 30s)
```

Admin-API calls shown as `curl` use the bearer token (legacy
`observability.adminToken`, or an SSO/static token under `adminAuth`):

```sh
curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
  "$BASE/admin/api/<endpoint>" | jq .
```

### RBAC: who can do what

When `adminAuth.enabled: true`, every admin endpoint is mapped to the **capability**
it requires, and a caller is denied (`403`) unless one of its roles grants that
capability. The role→capability table is fixed
([admin-sso-rbac.md](admin-sso-rbac.md)):

| Role | read | operate | approve | administer |
|------|:----:|:-------:|:-------:|:----------:|
| `viewer`   | ✓ | | | |
| `operator` | ✓ | ✓ | | |
| `approver` | ✓ | | ✓ | |
| `admin`    | ✓ | ✓ | ✓ | ✓ |

(`tenant-viewer` is a disjoint, tenant-scoped portal role and cannot reach any
admin incident action.)

Capability is derived from **method + path**: every `GET`/`HEAD` needs only
**read**; the mutations used in this playbook map as follows (from
`internal/admin/authz.go`):

| Action (endpoint) | Capability | Minimum role |
|-------------------|-----------|--------------|
| Grant/deny break-glass (`POST /api/approvals/{approve,deny}`) | approve | `approver` |
| Release a quarantine (`DELETE /api/quarantine/entry`) | operate | `operator` |
| Force a malfeed / compliance refresh, run a backup, trigger a re-scan (`POST …/refresh`, `…/backup/run`, `…/rescan`) | operate | `operator` |
| Engage / clear the lockdown kill-switch (`POST /api/lockdown/{engage,clear}`) | administer | `admin` |
| Mutate policy / config, org snapshot freeze/rollback, GitOps sync (`…/policyengine/reload`, `…/snapshots/{freeze,rollback}`, `…/gitops/sync`) | administer | `admin` |

Every authenticated mutation is attributed to the caller's identity in the
tamper-evident [audit log](access-control-and-audit.md). With `adminAuth` off,
these endpoints require only the legacy admin bearer token (or are open on a
trusted network).

### Observability anchors

Before and during any incident, the single-pane view is the admin UI
**Security Ops** tab, backed by `GET /admin/api/secops/summary`
([secops.md](secops.md)) — blocks/warns/admits in the rolling window, the
approval backlog, active anomalies, and the live risk-band distribution. The
Grafana dashboards and the 24 Prometheus alerts are in
[observability.md](observability.md).

---

## 1. Quarantine & break-glass

**Symptom:** a build is failing with a `403` from a gate, or the Security Ops
backlog / `pullthrough_approvals_open_requests` is climbing. An operator must
decide whether the block is correct, and if not, grant a **narrow, time-boxed**
exception rather than weakening policy for everyone.

Two distinct mechanisms are involved — know which one you are touching:

| Mechanism | What it is | Release action | Capability |
|-----------|-----------|----------------|-----------|
| **CVE-drift quarantine** | a previously-clean cached artifact that a *new* CVE re-scan flagged ([Task 18](observability.md)) | `DELETE /api/quarantine/entry?digest=` | operate |
| **Break-glass approval** | a time-boxed override of a *live gate block* (vulnscan, cve-drift, malfeed, sigverify, policy) ([approvals.md](approvals.md)) | `POST /api/approvals/approve` | approve |

### Decision tree

```
403 reported / approval backlog rising
        │
        ▼
Identify the artifact & the gate that blocked it
  ptctl inspect <name@version>            (verdict + findings, SARIF with -sarif)
  ptctl dossier <eco> <name@version>      (full 360 view: provenance, risk, history)
  GET /admin/api/approvals?status=pending (the pending review + which gate)
        │
        ▼
Is the block correct (real threat)?
        │
   ┌────┴─────────────────────────────┐
  YES                                  NO (false positive / accepted-risk hotfix)
   │                                    │
   ▼                                    ▼
POST /api/approvals/deny          Is it a stale CVE-drift quarantine of a
 → block confirmed, stays 403       cached artifact you trust again?
                                         │
                                 ┌───────┴────────┐
                                YES               NO (need the gate bypassed now)
                                 │                 │
                                 ▼                 ▼
                     DELETE /api/quarantine/  POST /api/approvals/approve
                       entry?digest=<sha256>    {id, approver, justification,
                       (operate)                 durationSeconds?}
                                                (approve; needs N distinct
                                                 approvers if requiredApprovers>1)
                                                      │
                                                      ▼
                                         grant is active until grantTtl,
                                         then auto-revokes & re-quarantines
```

### Steps

1. **Triage the artifact** (read; any role):
   ```sh
   ptctl inspect left-pad@1.0.0
   ptctl dossier npm left-pad@1.0.0
   curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
     "$BASE/admin/api/approvals?status=pending&limit=200" | jq .
   ```
   The pending-review record names the **gate** (`vulnscan`, `cve-drift`,
   `malfeed`, `sigverify`, or `policy`) and the request `id`.

2. **Confirm a real block — deny** (approve; `approver`/`admin`). The artifact
   stays refused and is not auto-reopened:
   ```sh
   curl -fsS -X POST -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"id":"<req-id>","approver":"you@example.com","justification":"confirmed credential stealer"}' \
     "$BASE/admin/api/approvals/deny"
   ```

3. **False positive / urgent hotfix — grant break-glass** (approve;
   `approver`/`admin`). The override is scoped to exactly
   `(tenant, ecosystem, coordinate, gate, reason)` and self-expires at
   `grantTtl`; `durationSeconds` overrides the TTL for this grant:
   ```sh
   curl -fsS -X POST -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"id":"<req-id>","approver":"you@example.com","justification":"INC-42 hotfix; CVE not reachable","durationSeconds":3600}' \
     "$BASE/admin/api/approvals/approve"
   ```
   With `approvals.requiredApprovers >= 2` (dual control) the request stays
   pending until **N distinct** identities approve. Served-under-grant pulls
   carry `X-Approval-Decision: break-glass` and `X-Approval-Request: <id>`.

4. **Stale CVE-drift quarantine you accept again — release the digest** (operate;
   `operator`/`admin`). This is not a gate override; it clears the quarantine
   flag on a specific cached blob:
   ```sh
   curl -fsS -X DELETE -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
     "$BASE/admin/api/quarantine/entry?digest=sha256:<artifact-digest>"
   ```

5. **Watch exposure.** `pullthrough_approvals_active_grants` is your live
   break-glass exposure; it should return to its baseline as grants expire and
   artifacts re-quarantine. Every request/grant/deny/expiry/serve is in the
   audit log and emitted as an `approval` notification.

> Everything here is runtime state — **no config edit, no redeploy**. Editing
> `policy`/`vulnerabilities` config to unblock is the wrong tool: it is slow,
> coarse (weakens the gate for every tenant), and easy to forget to revert.

---

## 2. Emergency lockdown / kill-switch

**Symptom:** a confirmed or suspected active incident (compromised upstream,
freshly-disclosed malware, credential enumeration) requires tightening the
proxy's posture **org-wide, instantly**, without redeploying. The lockdown
control ([lockdown.md](lockdown.md)) is the first check on the pull path.

**Prerequisite:** `lockdown.enabled: true` in config. Engage/clear require the
**administer** capability (`admin` role). Every transition needs a
`-reason` **and** an `-incident` ID, carries a TTL with auto-expiry, and is
written to the audit log + raised as an `EventLockdown` notification.

### Choose the mode

```
Active incident — what do you need?
        │
        ├─ Stop all NEW upstream fetches, keep serving known-good cache
        │        →  freeze     (pair with a snapshot freeze to pin digests)
        │
        ├─ Make every observe-mode gate enforce + harden thresholds, cluster-wide
        │        →  strict
        │
        └─ Deny one or more SPECIFIC coordinates everywhere, right now,
           ahead of the next malfeed refresh
                 →  block  <coord…>   ([ecosystem:]name[@version])
```

### Engage (ptctl — preferred)

```sh
ptctl lockdown status

ptctl lockdown freeze -incident INC-42 -reason "investigating compromised upstream" -ttl 2h
ptctl lockdown strict -incident INC-42 -reason "harden everything during triage"
ptctl lockdown block  -incident INC-42 -reason "freshly-disclosed malware" npm:evil-pkg@1.3.0 pip:badlib

ptctl lockdown clear  -reason "incident resolved"
```

Flags on `freeze`/`strict`/`block`: `-incident` (required), `-reason`
(required), `-ttl` (e.g. `30m`, `2h`; defaults to the server `defaultTtl`, capped
at `maxTtl`). `clear` needs only `-reason`. A block coordinate is
`[ecosystem:]name[@version]`; omit the version to block the whole package.

### Engage (admin API — equivalent)

| Method & path | Capability | Body |
|---------------|-----------|------|
| `GET /admin/api/lockdown` | read | — |
| `POST /admin/api/lockdown/engage` | administer | `{mode, reason, incidentId, ttl, targets?}` |
| `POST /admin/api/lockdown/clear` | administer | `{reason}` |

```sh
curl -fsS -X POST -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"freeze","incidentId":"INC-42","reason":"compromised upstream","ttl":"2h"}' \
  "$BASE/admin/api/lockdown/engage"
```

### Verify, hold, and clear

1. **Confirm it took:** `ptctl lockdown status` shows the mode, incident, operator,
   and time remaining. The admin UI shows a red **Incident** banner on every tab.
   A refused pull returns `403` with `X-Lockdown-Decision` / `X-Lockdown-Mode` /
   `X-Lockdown-Incident` headers (a frozen cache-miss returns
   `X-Lockdown-Decision: freeze-block`, `X-Cache: MISS-BLOCKED`).
2. **Metrics to watch:** `pullthrough_lockdown_active`,
   `pullthrough_lockdown_mode_active{mode}`,
   `pullthrough_lockdown_seconds_remaining`, and the
   `pullthrough_lockdown_*_total` counters.
3. **A forgotten lockdown self-heals** at TTL expiry (the lease leader persists
   the expiry sweep; followers compute the same state). Do **not** rely on this —
   clear explicitly once the incident is resolved.
4. **Break-glass still composes:** an individual
   [approval](#1-quarantine--break-glass) can be granted while the lockdown
   stands, so one team can be unblocked under dual control without lifting the
   org-wide posture.

### Clearing checklist

- [ ] Root cause understood; threat coordinates added to `malfeed`/`policy` as a
      durable control (so you can drop the `block` targets).
- [ ] `ptctl lockdown clear -reason "…"` run and `status` shows **no active
      lockdown**.
- [ ] Reconstruct the incident for the post-mortem:
      `ptctl timeline -incident INC-42 -markdown` ([timeline.md](timeline.md)).

---

## 3. Reading the risk verdict & compliance scorecard

Two different questions, two different subsystems. Know which one you are reading.

### Risk verdict — *"how risky is this one artifact?"*

The unified risk engine ([Task 37](secops.md)) produces an **explainable**
per-artifact assessment. Fetch the engine snapshot (read; any role) or inspect a
coordinate:

```sh
curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
  "$BASE/admin/api/riskscore?limit=50" | jq .
ptctl inspect   left-pad@1.0.0        # verdict + findings for one coordinate
ptctl dossier   npm left-pad@1.0.0    # the full 360 view incl. risk breakdown
```

Interpret the `Assessment`:

| Field | Meaning |
|-------|---------|
| `score` | composite normalized risk, **0–100** (higher = riskier) |
| `band` | `low` → `medium` → `high` → `critical` (cutoffs from `riskScore.bands`) |
| `action` | effective admission action: `off` (observe only), `warn`, or `block` |
| `exceeds` | whether `band` met/exceeded the configured `thresholdBand` (independent of `action`) |
| `contributions[]` | the explainable per-signal breakdown (weight × signal), in canonical order |
| `skipped[]` | signals not available for this artifact (excluded from the weighted average) |
| `summary` | one-line, human-readable "top drivers" sentence |

Contributing signals: `vulnerability`, `signature`, `license`, `nameguard`,
`secret`, `provenance`, `quarantine`, `installhooks`, `repohealth`,
`rebuildverify`, `continuity`. A verdict that blocks but looks wrong is almost
always one dominant contribution — read `contributions[]` (or `summary`) to find
it, then act via [break-glass](#1-quarantine--break-glass) (narrow) or retune
`riskScore.weights` / `riskScore.thresholdBand` (durable).

> `action` reflects the **effective** policy for the artifact's tenant.
> `riskScore.thresholdAction` defaults to `off` (score-and-record, never
> influences serving), so enabling the engine is non-disruptive; move it to
> `warn`/`block` deliberately, per-tenant if needed.

### Compliance scorecard — *"is the whole deployment's posture healthy?"*

The continuous-compliance scorecard (Task 35) is a **self-assessment of the
whole proxy**, not of one artifact. Fetch it (read; any role):

```sh
curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
  "$BASE/admin/api/compliance" | jq '{score,grade,status,slsa:.slsa.buildLevel,summary}'
curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
  "$BASE/admin/api/compliance?format=markdown"      # Markdown rendering
```

| Endpoint | Capability | Purpose |
|----------|-----------|---------|
| `GET /api/compliance` (`?format=markdown`, `?refresh=1`) | read | current scorecard JSON/Markdown |
| `POST /api/compliance/refresh` | operate | recompute now from live posture |
| `GET /api/compliance/report.html` | read | printable HTML (audit packet / PDF) |
| `GET /api/compliance/export` | read | signed, digest-stamped report artifact for auditors |

Interpret the card:

| Field | Meaning |
|-------|---------|
| `score` | overall **0.0–1.0** across scored controls |
| `grade` | letter from `score`: **A** ≥0.90, **B** ≥0.80, **C** ≥0.70, **D** ≥0.60, else **F** |
| `status` | worst-of rollup: `pass` / `warn` / `fail` (and `na` for inapplicable controls, excluded from scoring) |
| `controls[]` | per-control `status` + rationale — the drill-down for a `warn`/`fail` |
| `slsa.buildLevel` | estimated SLSA build level **0–3** (`estimated: true` — inferred from posture, not externally asserted) |

**When the grade drops or a control fails:** open `controls[]`, find the
`fail`/`warn` control and its rationale (a disabled required subsystem, coverage
below threshold, or detected tamper), and remediate the underlying subsystem. A
compliance `fail` on `audit-transparency` specifically points at a stale/broken
audit checkpoint — cross-check with `-verify-audit`
([§4](#4-disaster-recovery-backup--restore)). The exported report is signed with
`compliance.signingKey`/`signingKeyFile` so an auditor can verify it
independently.

---

## 4. Disaster-recovery backup & restore

Full detail, snapshot layout, and RPO/RTO guidance are in
[backup-restore.md](backup-restore.md); this is the operator quick-path. The
snapshot captures the **cache** and the durable **metadata** stores (audit/Merkle
log, provenance links, commit-scan verdicts, VEX, policy bundles); in-memory
state (provenance graph, scan cache, quarantine set) rebuilds automatically.

### Take a backup

On demand (no capability needed — it is a local CLI against the config's stores):

```sh
pullthrough backup -config c.yaml -out /backups/snapshot-$(date -u +%Y%m%dT%H%M%SZ).tar
```

Useful flags: `-out -` (stream to stdout), `-no-cache` / `-no-metadata`,
`-encrypt` with `-passphrase …` **or** `-key-file …` (32-byte raw AES key for
KMS/HSM). Transfer the `.tar` **and** its `.sha256` sidecar.

Via the admin API: `POST /admin/api/backup/run` (operate) writes into
`backup.dir`; `GET /admin/api/backup` (read) reports the age/outcome of the last
backup. Scheduled backups run from the `backup:` config section.

### Restore (recovery)

```
Provision a fresh instance (config → empty cache + metadata paths)
        │
        ▼
Copy snapshot.tar + snapshot.tar.sha256 to the host
        │
        ▼
pullthrough restore -config target.yaml -in snapshot.tar \
    -manifest-digest snapshot.tar.sha256 [-passphrase … | -key-file …]
        │   (each member verified against its digest as it streams;
        │    a mismatch aborts and removes the partial member)
        ▼
Verify the audit log survived the round-trip
        │
        ▼
Start the proxy — in-memory state rebuilds; resume traffic
```

Restore flags: `-in -` (stdin), `-overwrite` (re-write existing entries),
`-cache-only` / `-metadata-only`, `-manifest-digest <sha256|path>`. Metadata is
restored to the **target** config's paths.

### Verify tamper-evidence after a restore

```sh
pullthrough -verify-audit /restored/audit.log -audit-key "$PTS_AUDIT_HMAC_KEY"
# verify-audit: OK — N records form an intact tamper-evident chain
```

`-verify-audit` recomputes the Merkle root, cross-checks sealed checkpoints
(key-independent), and verifies checkpoint signatures when a public key is
supplied. It exits non-zero and names the first broken record on tampering. Also
reachable via the admin audit endpoints (`GET /api/audit`,
`/api/audit/checkpoint`, `/api/audit/proof`, `/api/audit/consistency`; read).

> If the snapshot was encrypted, the decryption passphrase/key is **out-of-band**
> — a snapshot whose key you also lost is unrecoverable.

---

## 5. Rotating signing keys & OIDC secrets

Routine credential hygiene and the response to a suspected key compromise. The
`secrets` master key lets you keep all of these as `${ENV_VAR}` or `enc:v1:`
sealed values rather than plaintext in config.

### Signing / integrity keys

| Key (config path) | What it protects | Rotation procedure | Blast radius |
|-------------------|------------------|--------------------|--------------|
| `audit.hmacKey` / `audit.hmacKeyEnv` | the tamper-evident audit hash chain | Rotating starts a **new** chain. Archive the old log **with its old key** for later `-verify-audit`. Do not rotate mid-stream if you need one continuous verifiable chain. | audit continuity |
| `audit.transparency.signingKey` / `signingKeyFile` | Merkle checkpoint signatures (PKCS#8/EC/RSA/Ed25519) | Update the key, restart; distribute the new **public** key to checkpoint verifiers. Old checkpoints stay verifiable under the old public key. | checkpoint verification |
| `attest.signingKey` / `signingKeyFile` | outbound SLSA/in-toto attestations for served artifacts | Update + restart. If unset, it **reuses the audit transparency key**, so rotating that rotates both. Publish the new public key to attestation consumers. | downstream attestation verification |
| `compliance.signingKey` / `signingKeyFile` | the signed compliance-export artifact | Update + restart; give auditors the new public key. | auditor report verification |
| `malfeed` bundle key (Ed25519, CLI-generated) | air-gapped malware-feed bundle signatures | `pullthrough malfeed keygen -private new.key -public new.pub`, re-export bundles with the new key, update `malfeed.bundlePublicKeyFile` on importers. | air-gapped feed trust |
| `secrets` master key (`secrets.keyFile` / `secrets.keyEnv` / `secrets.passphrase`) | every `enc:v1:` sealed value | **Re-encrypt all `enc:v1:` values with the new key before switching** `keyFile`/`keyEnv`, else sealed values become unreadable. | all sealed secrets |

No capability applies to these — they are config + restart operations, rolled out
like any config change (Helm `maxUnavailable: 0`, PDB; see
[../deploy/README.md](../deploy/README.md)). Cache/state persist across the
restart.

### OIDC / admin-auth secrets

See [admin-sso-rbac.md](admin-sso-rbac.md). IdP **signing keys (JWKS) rotate
automatically** — they are re-fetched after `oidc.jwksCacheTtl` (default 15m), so
there is nothing to do when your IdP rolls its keys. What you rotate manually:

| Secret (config path) | Rotation procedure | Effect |
|----------------------|--------------------|--------|
| `adminAuth.oidc.clientSecret` | rotate at the IdP, update the `${ENV}`/`enc:v1:` value, roll out | new server-side code exchanges only |
| `adminAuth.sessionKey` (≥16 bytes, cookie-signing HMAC) | `openssl rand -hex 32` → update + roll out | **invalidates all active admin sessions** — everyone re-logs-in (use this to force logout on compromise) |
| `adminAuth.staticTokens[].token` / `tokenHash` | add the new token (prefer `tokenHash: sha256:<hex>`), roll out, then remove the old | overlapping rollout, no downtime for the offline/air-gapped path |

**Suspected admin-session or token compromise — immediate response:**

1. Rotate `adminAuth.sessionKey` and roll out → every existing session is
   invalidated.
2. Revoke/rotate the affected `staticTokens` entry (or the legacy
   `observability.adminToken`); set `adminAuth.allowLegacyToken: false` if the
   legacy token is the exposure.
3. Review `pullthrough_adminauth_authz_denied_total{capability}` and the audit
   log (`EventAdmin` entries) for what the identity touched.
4. If the proxy's own posture is implicated, [engage a lockdown](#2-emergency-lockdown--kill-switch) while you investigate.

---

## 6. Malware-feed hit

**Symptom:** `pullthrough_malfeed_blocks_total` increments, a **critical**
`malicious_block` notification fires, or a client reports a `403` with
`X-Malfeed-Decision: block`. A pull matched the OpenSSF/OSV
`malicious-packages` feed ([malfeed.md](malfeed.md)) — the match is **never
advisory**: the coordinate is refused before any upstream fetch or cache fill, so
the malicious bytes were never transferred.

### Decision tree

```
malfeed block fires (notification / metric / client 403)
        │
        ▼
Read the block: code "malicious", advisory id, ecosystem/package/version
  GET /admin/api/malfeed?q=<name>        (what the loaded feed says)
  ptctl dossier <eco> <name@version>     (was anything pulled before the feed knew?)
        │
        ▼
Confirmed malicious?
        │
   ┌────┴─────────────────────────────────┐
  YES                                       NO (false positive in the feed)
   │                                         │
   ▼                                         ▼
1. Scope the blast radius                 Grant a narrow, time-boxed
   ptctl timeline -coordinate <name>        break-glass over the `malfeed`
   (did any pull succeed before the         gate (§1) — do NOT disable malfeed
    feed listed it? evict those blobs)       globally
2. Make the control durable & fast:
   ptctl lockdown block -incident … <eco:name[@version]>   (instant, cluster-wide)
3. Evict any pre-existing cached copy:
   DELETE /admin/api/cache/entry?key=…     (operate)
4. Notify affected tenants; record in the incident timeline
```

### Steps

1. **Read the match** (read; any role). The `403` body carries
   `code: "malicious"`, `reason`, `advisory`, `aliases`, `categories`, and
   `source`; the admin API lets you query the loaded feed:
   ```sh
   curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
     "$BASE/admin/api/malfeed?q=evil-stealer&limit=50" | jq .
   ```

2. **Scope the blast radius.** The block prevents *new* fetches, but confirm
   nothing was cached **before** the feed listed the coordinate:
   ```sh
   ptctl dossier npm evil-stealer@1.0.0
   ptctl timeline -coordinate evil-stealer -markdown
   ```
   If a copy was cached earlier, evict it (operate):
   ```sh
   curl -fsS -X DELETE -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
     "$BASE/admin/api/cache/entry?key=<cache-key>"
   ```
   Then find out **who has it**. The [download log](download-log.md) lists every
   client address (and authenticated identity) the package was served to, and
   every one that was refused it (read; any role):
   ```sh
   ptctl downloads --package evil-stealer                    # every pull and refused attempt
   ptctl downloads --package evil-stealer --outcome served   # the machines to clean up
   ptctl downloads --package evil-stealer --summary          # one line per client address
   ```
   or open the admin console at `#downloads?package=evil-stealer`. For each
   affected machine, `ptctl downloads --ip <address>` shows what else it pulled.

3. **Harden immediately** (administer) with a lockdown `block` so the coordinate
   is denied cluster-wide **ahead of the next feed refresh** on every replica —
   belt-and-braces while the feed propagates:
   ```sh
   ptctl lockdown block -incident INC-57 -reason "OSSF MAL-2024-0001 active" npm:evil-stealer@1.0.0
   ```

4. **Keep the feed fresh.** Force a conditional refresh if you suspect the feed
   lagged (operate), and alert on staleness:
   ```sh
   curl -fsS -X POST -H "Authorization: Bearer $PTS_ADMIN_TOKEN" \
     "$BASE/admin/api/malfeed/refresh" | jq '{entries,stale,refreshAgeSeconds}'
   ```
   Alert on rising `pullthrough_malfeed_refresh_age_seconds` (feed stopped
   updating) and any increase in `pullthrough_malfeed_blocks_total`. For
   safety-first sites, `malfeed.failClosed: true` refuses **all** covered pulls
   while the feed is stale.

5. **False positive?** Do **not** disable `malfeed` globally. Grant a narrow,
   time-boxed [break-glass](#1-quarantine--break-glass) over the `malfeed` gate
   for the specific coordinate/tenant, and report the false positive upstream.

6. **Air-gapped sites** refresh via signed offline bundles — rebuild on a
   connected host and re-import (also [§5](#5-rotating-signing-keys--oidc-secrets)
   for the bundle signing key):
   ```sh
   pullthrough malfeed export -config config.yaml -key malfeed.key -out malfeed-bundle.json
   pullthrough malfeed import -in malfeed-bundle.json -pubkey malfeed.pub   # verify before transfer
   ```

---

## Quick reference

```sh
# Posture at a glance
curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" "$BASE/admin/api/secops/summary" | jq .

# Quarantine / break-glass (approve = approver/admin; release = operator/admin)
curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" "$BASE/admin/api/approvals?status=pending" | jq .
curl -fsS -X POST   -H "Authorization: Bearer $PTS_ADMIN_TOKEN" -d '{"id":"…","approver":"…","justification":"…"}' "$BASE/admin/api/approvals/approve"
curl -fsS -X DELETE -H "Authorization: Bearer $PTS_ADMIN_TOKEN" "$BASE/admin/api/quarantine/entry?digest=sha256:…"

# Lockdown kill-switch (administer = admin)
ptctl lockdown status
ptctl lockdown freeze -incident INC-42 -reason "…" -ttl 2h
ptctl lockdown block  -incident INC-42 -reason "…" npm:evil@1.0.0
ptctl lockdown clear  -reason "resolved"

# Risk verdict & compliance (read = any role)
ptctl inspect <name@version>;  ptctl dossier <eco> <name@version>
curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" "$BASE/admin/api/riskscore?limit=50" | jq .
curl -fsS -H "Authorization: Bearer $PTS_ADMIN_TOKEN" "$BASE/admin/api/compliance" | jq '{score,grade,status}'

# Backup / restore / verify
pullthrough backup  -config c.yaml -out snap.tar
pullthrough restore -config c.yaml -in snap.tar -manifest-digest snap.tar.sha256
pullthrough -verify-audit "$AUDIT_LOG" -audit-key "$PTS_AUDIT_HMAC_KEY"

# Malware-feed hit (refresh = operator/admin)
curl -fsS -X POST -H "Authorization: Bearer $PTS_ADMIN_TOKEN" "$BASE/admin/api/malfeed/refresh" | jq .

# Post-mortem timeline
ptctl timeline -incident INC-42 -markdown
```

## See also

- [runbook.md](runbook.md) — day-to-day admin operations, health, metrics, scaling
- [lockdown.md](lockdown.md) · [approvals.md](approvals.md) · [malfeed.md](malfeed.md) — the owning subsystem docs
- [backup-restore.md](backup-restore.md) — full DR / RPO / RTO guide
- [admin-sso-rbac.md](admin-sso-rbac.md) — OIDC/RBAC model and secret rotation
- [secops.md](secops.md) — the real-time SOC dashboard · [observability.md](observability.md) — metrics, Grafana, alerts
- [timeline.md](timeline.md) — forensic incident reconstruction & export
