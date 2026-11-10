# Continuous Git commit scanning (webhook + polling)

The LLM commit-scanning pipeline ([security-model.md](security-model.md)) scans a
commit when one flows through the Git pull-through backend. The **continuous
commit scanner** runs that same pipeline *proactively* over a set of watched
repositories: it detects new commits — reactively from a push webhook, or by
polling — and scans only the commits it has not already scanned, so risky
commits are caught as they land rather than only when something pulls them.

It is built on three guarantees:

- **Incremental and idempotent.** A durable per-repository *cursor* records the
  ref tips already scanned. Each cycle scans only the range
  `cursor..<new head>`, so no commit is scanned twice and progress survives
  restarts. The underlying verdict cache is keyed by commit SHA, so even a
  redundant scan is free.
- **Rescan on new detector/model versions.** The cursor also records the
  *scanning signature* (the fold of model IDs, prompt version, and deterministic
  ruleset). When you change the model or rules, the signature changes, and the
  watcher re-enumerates and re-scans the affected history under the new
  configuration automatically.
- **Integrated.** Every scanned commit's verdict is persisted keyed by
  repo+commit, recorded in the unified findings store (SARIF/admin/portal,
  rule `commitscan/suspicious-commit`), written to the tamper-evident audit log,
  and — when flagged — alerted through the notification subsystem.

## How new commits are detected

| Trigger | When | Scope |
|---------|------|-------|
| **Push webhook** | A Git host POSTs a push event to the receiver endpoint. | The pushed ref range `before..after` (fast, near-real-time). |
| **Polling** | Every `pollInterval`. | The difference between each tracked ref's current upstream head and the cursor (a safety net that also catches missed/unconfigured webhooks). |
| **Backfill** | On first sighting (if enabled) or on demand. | Reachable history, in bounded `maxCommitsPerScan` chunks. |

All three converge on the same incremental cursor logic, so they compose safely:
a webhook and a poll can never double-scan or race a repository (per-repo
processing is serialized), and in an HA deployment only the coordination leader
runs the polling sweep (webhook scans are idempotent and are not gated).

Commit enumeration and diff extraction use the `git` binary against a local bare
mirror of each repository (kept under `mirrorDir`), so the scanner reads real
commit diffs, not just the truncated commit list a webhook payload carries.

## The push-webhook endpoint

The receiver is mounted at `webhookPath` (default `/webhooks/git`), **outside**
the `/v1` client access-control envelope — the external Git host posting to it
has no proxy client credentials. It authenticates deliveries itself.

- **`POST`** — a GitHub-style push payload. On success returns `202 Accepted`
  and schedules the scan asynchronously (so the sender gets a prompt
  acknowledgement even when the scan itself is slow).
- **`GET`** — returns the watcher status as JSON (repos watched, commits
  scanned/flagged, webhook counts, poll interval, current signature).
- A GitHub **`ping`** event returns `200`; non-`push` events are accepted and
  ignored; a branch **deletion** (`after` all-zero) is accepted and ignored.

### Signature verification (GitHub-style)

Set `webhookSecret` and the receiver verifies the
`X-Hub-Signature-256: sha256=<hex>` header: an HMAC-SHA256 of the raw request
body keyed by the secret, compared in constant time. A missing or invalid
signature is rejected with `401` and the payload is never parsed.

Configure the **same** secret on the Git host:

- **GitHub** → repository/organization *Settings → Webhooks → Add webhook*:
  - *Payload URL*: `https://<proxy-host><webhookPath>` (e.g.
    `https://proxy.example.com/webhooks/git`)
  - *Content type*: `application/json`
  - *Secret*: the value of `scanning.watch.webhookSecret`
  - *Events*: *Just the push event*
- **GitHub Enterprise / Gitea** use the same `X-Hub-Signature-256` scheme and
  work unchanged.

Leaving `webhookSecret` empty disables verification (the receiver then accepts
any well-formed payload). This is strongly discouraged outside a trusted network.

### Repository routing

An inbound push is matched to a watched repository by `fullName`
(`repository.full_name`, e.g. `acme/widgets`) or by clone URL (`clone_url`,
`ssh_url`, `git_url`, `html_url`, compared ignoring a trailing `.git`). A push
for a repository that is not watched is rejected with `404` — unless
`allowUnconfiguredWebhooks` is set, in which case it is scanned ad hoc with the
repository derived from the payload.

## Configuration

Under `scanning.watch` (continuous scanning reuses the `scanning` provider,
models, budget, and deterministic secret detector — see
[configuration-reference.md](configuration-reference.md)):

```yaml
scanning:
  enabled: true
  provider: claude            # or codex/openai; deterministic-only also works
  apiKey: ${ANTHROPIC_API_KEY}
  commit:
    storeDir: /var/lib/pts/verdicts   # durable verdict cache (recommended)
  watch:
    enabled: true
    mirrorDir: /var/lib/pts/commit-mirrors   # required: bare mirrors for enumeration
    stateDir: /var/lib/pts/commit-cursors    # durable per-repo cursors (recommended)
    pollInterval: 5m           # 0 disables polling (webhook-only)
    maxCommitsPerScan: 500     # per repo per cycle; remainder picked up next cycle
    backfill: false            # true = scan history on first sighting
    webhookPath: /webhooks/git
    webhookSecret: ${GIT_WEBHOOK_SECRET}     # HMAC secret; supports ${ENV} and enc:v1:
    allowUnconfiguredWebhooks: false
    repos:
      - name: widgets          # stable id (cursor key, findings key, webhook routing)
        url: https://github.com/acme/widgets.git
        fullName: acme/widgets # webhook routing (repository.full_name)
        branches: [main, release]   # empty = default branch only
        username: x-access-token    # optional HTTPS credentials
        token: ${ACME_GIT_TOKEN}    # supports ${ENV} and enc:v1:
```

Notes:

- `mirrorDir` is required when the watcher is enabled. `stateDir` is optional but
  recommended — without it cursors are in-memory and a restart re-baselines (or,
  with `backfill`, re-backfills) each repo.
- `backfill: false` (the default) records the current ref tips on first sighting
  **without** scanning history; only commits pushed afterward are scanned. Set
  `backfill: true` to scan history (bounded by `maxCommitsPerScan` per cycle).
- Credentials (`webhookSecret`, repo `token`/`username`) support `${ENV_VAR}`
  expansion and `enc:v1:` encryption at rest; they are never logged or sent to
  the model.
- On-demand backfill can be driven in code via `Service.Backfill(ctx, name)`; a
  polling sweep via `Service.PollOnce(ctx)`.

## What happens to a scanned commit

1. The commit is scanned by the configured pipeline (deterministic secret
   detection + LLM triage → deep analysis, per the normal pipeline).
2. The verdict is persisted keyed by commit SHA (shared verdict cache).
3. A flagged verdict (malicious, or any finding) is recorded in the findings
   store as a `commitscan/suspicious-commit` finding (secret findings map to
   `secretscan/exposed-credential`), keyed by coordinate `git/<repo>@<sha>`, and
   surfaced in the SARIF export, the admin findings view, and the tenant portal.
4. The scan is written to the tamper-evident audit log (`scan_verdict`, with the
   repository, commit, risk score, severity, and allow/deny decision).
5. A flagged verdict raises a notification (`commit_scan` event) through the
   configured sinks.
6. When a package is later associated with this commit (via build-provenance
   attestation or other provenance), the package-to-commit link surfaces this
   verdict on the artifact — so a risky commit blocks or flags the artifacts
   built from it.

## Observability

- `GET <webhookPath>` returns live status JSON.
- Prometheus metrics (when metrics are enabled):
  - `pullthrough_commitwatch_scans_total{repo,result}` — commits scanned
    (`result=fresh|cached`).
  - `pullthrough_commitwatch_flagged_total{repo}` — flagged commits.
  - `pullthrough_commitwatch_webhooks_total{outcome}` — webhook deliveries
    (`outcome=accepted|rejected`).
  - `pullthrough_commitwatch_repos_watched`, `pullthrough_commitwatch_commits_scanned`
    — live gauges.

## Operational notes

- The watcher requires the `git` binary and a commit-scanning pipeline (an LLM
  provider and/or the deterministic secret detector). With neither it disables
  itself with a warning.
- A failed mirror refresh degrades gracefully: the (possibly slightly stale)
  cached mirror is scanned and the failure is logged.
- A single commit that fails to scan stops that cycle's cursor advance at that
  point and is retried on the next cycle, so a transient provider error never
  skips commits.
- `maxCommitsPerScan` bounds how much a single large push or initial backfill can
  enqueue at once; the remainder is picked up on subsequent cycles (the cursor
  resumes exactly where it left off).
