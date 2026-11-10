# Policy & risk what-if simulation and replay

The proxy makes admission decisions with two operator-tunable engines: the
[policy-as-code engine](configuration.md#policyengine) (declarative allow/warn/
deny rules over the aggregated admission signals) and the
[unified risk-scoring engine](configuration.md#riskscore) (a weighted composite
score with a warn/block threshold). Changing either — a new policy bundle,
re-weighted risk signals, a lower block threshold — changes which artifacts your
developers can pull. Rolling such a change out blind risks a self-inflicted
outage: a bundle that looks reasonable can newly block a package half your fleet
depends on.

The **what-if simulation/replay harness** closes that loop. It records a
sampled, redacted buffer of the admission traffic the proxy actually saw, and
lets you replay it through a *candidate* configuration to produce a precise diff
**before** you deploy:

- which pulls would flip **admit → block** or **block → admit**,
- which artifacts would shift **risk band** (and by how many points),
- which **new policy violations** (deny rules) would fire,
- the **per-tenant blast radius** — the fraction of each tenant's pulls affected.

It reuses [`policyengine.Input`](../internal/policyengine/input.go) as the
canonical captured record, so the replay evaluates the exact same document the
live gates evaluated. Every stage is deterministic: capture sampling is
counter-based (not random), the engines evaluate purely, and the report orders
records by capture sequence and tenants lexicographically. The same capture
replayed through the same candidate always yields byte-identical output.

## How it works

```
   pull path                         capture                replay
 ┌───────────┐   admission doc   ┌──────────────┐      ┌──────────────┐
 │  gates    │ ────────────────► │  Recorder    │ ───► │  Simulator   │
 │ (policy,  │   + live verdict  │ (ring buffer,│ JSON │ candidate    │
 │  risk)    │                   │  sampled,    │ file │ policy+risk  │
 └───────────┘                   │  redacted)   │      │ engines      │
                                 └──────────────┘      └──────┬───────┘
                                                              │ diff
                                                       ┌──────▼───────┐
                                                       │  DiffReport  │
                                                       │ JSON / MD    │
                                                       └──────────────┘
```

1. **Capture.** After the admission gates run for a request, the gateway records
   the per-request admission document (sampled and redacted) together with the
   verdict the live configuration produced into a bounded ring buffer. This is
   passive and best-effort — it never affects serving.

2. **Persist.** The buffer is a self-describing, versioned JSON envelope. Export
   it from the admin endpoint (or write it from an air-gapped capture) so a
   buffer captured on one replica can be replayed anywhere — in CI, on a laptop,
   or in a disconnected environment.

3. **Replay.** Evaluate every captured record through a candidate evaluator (a
   policy engine + risk engine built from the candidate config) and diff the
   candidate verdict against the baseline.

By default the baseline is the verdict captured **live** (i.e. the diff is
candidate-vs-production). Supplying a separate baseline config recomputes the
reference, letting you diff two candidate configs against each other.

## Redaction

Captured records may be shipped off-box (to CI, a laptop, an air-gapped
reviewer), so the recorder redacts sensitive leaf fields by default: secret-
finding file paths, signer identity and issuer strings, and source-repository
URLs and commit SHAs are replaced with `[redacted]`.

Redaction is deliberately **fidelity-preserving**: it only clears fields the
admission engines do *not* key on. The scalar signals they actually score
(severities, counts, booleans, scores, license/nameguard outcomes) are retained
verbatim, so a redacted record replays to the same verdict as the original. This
is what lets a captured buffer be both shareable and a faithful replay corpus.

## Configuration

```yaml
simReplay:
  enabled: true      # default; capture live traffic and serve the admin endpoint
  capacity: 1024     # ring-buffer size (oldest-evicted)
  sampleRate: 1      # capture 1-in-N pulls (deterministic); 1 = every pull
  redact: true       # strip sensitive leaf fields (recommended)
```

See [configuration.md](configuration.md#simreplay) for the field reference.

## Candidate configuration schema

Both the CLI and the admin endpoint accept the same candidate-config schema
(YAML or JSON). Each section is optional; an absent section means that gate does
not run in the candidate. At least one gate must be enabled.

```yaml
policyEngine:
  enabled: true
  mode: enforce              # enforce | audit (default enforce)
  dir: /etc/pullthrough/policy   # optional: load bundles from a directory
  defaultAction: allow       # allow | warn | deny (decision when no rule matches)
  includeDefaultBundle: true # include the embedded default bundle (default true)
  inlineBundle: |            # optional: a policy bundle provided inline
    rules:
      - id: block-unsigned-critical
        when: 'has(input.vuln) && input.vuln.criticalCount > 0 && (!has(input.signature) || !input.signature.verified)'
        action: deny
        message: "unsigned artifact with a critical CVE"
riskScore:
  enabled: true
  thresholdBand: high        # low | medium | high | critical
  thresholdAction: block     # off | warn | block
  weights:                   # optional; omitted ⇒ engine defaults
    vulnerability: 1.0
    signature: 0.8
  bands:                     # optional; omitted ⇒ engine defaults
    medium: 40
    high: 70
    critical: 90
```

`inlineBundle` is the quickest way to test a brand-new policy bundle — through
the admin endpoint you can preview a bundle without first writing it to a
server-side directory.

## CLI: `pullthrough simulate`

The CLI needs no running proxy. Point it at an exported capture file and a
candidate config:

```console
$ pullthrough simulate \
    -capture traffic.json \
    -candidate candidate.yaml \
    -records -format markdown
```

| Flag | Description |
|------|-------------|
| `-capture` | Path to a captured-traffic file (JSON capture envelope or bare record array). **Required.** |
| `-candidate` | Path to the candidate configuration file (YAML/JSON). **Required.** |
| `-baseline` | Optional baseline config; when set, baselines are recomputed from it instead of using the verdicts captured live. |
| `-format` | `json` (default) or `markdown`. |
| `-output` | Write the report to a file (default stdout). |
| `-records` | Include per-record diffs (default: summary + per-tenant only). |
| `-all` | With `-records`, include unchanged records too (default: only changed). |
| `-limit` | With `-records`, cap the number of per-record diffs (0 = no cap). |

This makes `simulate` a natural **pre-rollout CI gate**: capture production
traffic, run the candidate bundle in CI, and fail the job if the diff would
newly block more than an acceptable number of pulls.

## Admin / API endpoints

All are served under the admin prefix (default `/admin`) and honor the admin
bearer token.

### `GET /admin/api/simreplay`

Returns the recorder's operational status: whether capture is on, ring-buffer
capacity and fill, sample rate, and the observed/captured counters.

### `GET /admin/api/simreplay/capture`

Exports the live capture buffer as a self-describing `Capture` envelope —
download it to replay offline with the `simulate` CLI.

### `POST /admin/api/simreplay/simulate`

Replays the live buffer through the candidate configuration in the request body
(YAML or JSON, the schema above) and returns the diff report.

Query parameters:

| Param | Description |
|-------|-------------|
| `format` | `json` (default) or `markdown`. |
| `records` | `1` to include per-record diffs (default: summary + tenants). |
| `all` | With `records=1`, include unchanged records too. |
| `limit` | With `records=1`, cap the number of per-record diffs. |

```console
$ curl -s -XPOST "$ADMIN/api/simreplay/simulate?records=1" \
    -H "Authorization: Bearer $TOKEN" \
    --data-binary @candidate.yaml | jq .summary
```

### `POST /admin/api/simreplay/reset`

Clears the capture buffer so you can start a fresh capture window (e.g. right
after deploying a config change).

## Report shape

```jsonc
{
  "generatedAt": "2026-06-20T05:33:43Z",
  "summary": {
    "total": 2, "changed": 1, "unchanged": 1,
    "flips": 1, "nowBlocked": 1, "nowAdmitted": 0,
    "bandShifts": 1, "bandUp": 1, "bandDown": 0,
    "newViolations": 1,
    "baselineBlocked": 0, "candidateBlocked": 1
  },
  "tenants": [
    { "tenant": "teamB", "total": 1, "changed": 1, "nowBlocked": 1,
      "bandShifts": 1, "newViolations": 1, "blastRadius": 1.0 }
  ],
  "records": [
    { "seq": 1, "tenant": "teamB", "coordinate": "evil@2.0.0",
      "flip": "now-blocked", "bandShift": "up", "scoreDelta": 92,
      "newDenyRules": ["deny-critical-cve-unsigned"], "changed": true,
      "baseline":  { "policyAction": "allow", "riskBand": "low" },
      "candidate": { "policyAction": "deny",  "riskBand": "critical" } }
  ]
}
```

**Blast radius** is `changed / total` per tenant — the headline number for
judging the rollout risk of a change to a specific team.

## Relationship to other subsystems

This harness is the simulation complement to the policy and risk features already
shipped:

- The **policy-as-code engine** ([Task 32](configuration.md#policyengine))
  already supports an `audit` (dry-run) mode that logs would-be denies on live
  traffic. The replay harness goes further: it lets you test a candidate bundle
  against *historical* traffic without exposing it to a single live request.
- The **risk-scoring engine** ([Task 37](configuration.md#riskscore)) records an
  explainable assessment per pull; the harness re-derives those assessments under
  candidate weights/thresholds so you can preview band movements.
- It reuses the same per-request admission accumulator the
  [findings/SARIF layer](findings.md) reads, so capture adds no scanning work.
