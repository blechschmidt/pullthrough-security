# Incident timeline reconstruction & forensic export

The **timeline** subsystem (`internal/timeline`) is a read-only forensic
correlation layer. Given a coordinate, tenant, identity, or incident ID, it
reconstructs a single, chronologically-ordered, deduplicated chain of *what
happened* — every pull, gate verdict, override, approval, anomaly, and lockdown
action — by joining facts the proxy already recorded across its subsystems.

It is the artifact an incident responder reads to answer three questions:

1. **What did the proxy do, to whom, and when?**
2. **Who acted** — which identity pulled, which gate decided, which approver
   granted a break-glass exception, which operator engaged a lockdown?
3. **Can I prove it?** Every entry drawn from the tamper-evident audit log
   carries a link to its Merkle inclusion proof.

The layer **captures nothing of its own**. It reconstructs the timeline live,
through narrow read-only provider interfaces, from the subsystems that own the
facts. Turning a source off simply removes its contribution.

## Sources correlated

| Source | Provides | Proof |
|--------|----------|-------|
| **audit** (Task 31) | the hash-chained, Merkle-anchored spine: pulls, cache, scan verdicts, policy decisions, auth, quota, admin mutations (lockdown / approvals / snapshot), attestations | ✅ Merkle inclusion proof |
| **secops** (Task 60) | the SOC notable-verdict feed (recent block/warn/admit decisions) | — |
| **anomaly** (Task 43) | behavioural anomaly triggers (fanout, new-namespace, off-hours, enumeration, egress) | — |
| **approvals** (Task 50) | quarantine-review and break-glass workflow state changes (requested → approved/denied → expired) | — |
| **lockdown** (Task 74) | the currently-active emergency-lockdown incident | — |
| **findings** (Task 42) | recorded admission-finding documents per coordinate | — |

The audit log is the spine because it already records most of the security
pipeline's decisions and is the only tamper-evident source. The other providers
**supplement** it with structured, subsystem-specific detail and ensure the live
state (an open break-glass grant, an active lockdown) appears even before its
audit record is read.

## Ordering, de-duplication, and proofs

- **Ordering.** Events from every source are folded onto one time axis and
  sorted ascending, with a deterministic tiebreaker (source priority, then
  category/coordinate/kind) so the timeline is stable across runs and
  independent of provider iteration order.
- **De-duplication.** The same underlying fact is often recorded by more than
  one source — a policy block appears both as an audit `policy_decision` record
  and as a SOC `block` verdict. Such gate-decision events collapse onto a single
  entry keyed by *coordinate + canonical decision + wall second*. The
  highest-priority source wins (the audit log, because it carries the proof),
  every contributing source is listed in the entry's `corroborated` set, and the
  merge is order-independent.
- **Proofs.** An entry reconstructed from the audit log carries a `proof`
  reference `{ auditSeq, path }`, where `path` is the admin inclusion-proof
  endpoint (`/admin/api/audit/proof?seq=N`). Following it returns the RFC 6962
  Merkle inclusion proof, anchored to a signed checkpoint, that makes the entry
  tamper-evident. When de-duplication merges an audit record with a non-provable
  one, the surviving entry keeps the proof.

## Tenant scoping

Scoping is enforced exactly like the self-service **portal** (Task 71): when a
query is scoped to a tenant, an event attributed to a *different* tenant is
**never** returned. Organisation-wide, un-attributed events (e.g. an emergency
lockdown engaged for everyone) remain visible — the correct behaviour for
incident response. Tenant isolation is proven by `TestTenantIsolation` in
`internal/timeline/timeline_test.go`.

## Querying

A query is AND-combined across its set selectors and requires **at least one**
of `coordinate`, `tenant`, `identity`, or `incidentId` (or `all=true`), so an
operator cannot accidentally dump the entire history.

- `coordinate` — pivot on a package. A **bare name** (`lodash`) matches every
  version; an exact `name@version` narrows to one.
- `tenant` — scope to a tenant (portal-consistent isolation, see above).
- `identity` — scope to an actor (the subject that pulled, the approver, the
  operator).
- `incidentId` — scope to a lockdown/approval incident; returns the engage /
  clear / correlated chain tagged with that incident.
- `since` / `until` — bound the window (RFC3339).
- `limit` — cap the returned events; the **most recent** are kept and presented
  oldest-first, with `truncated: true` when the cap elided older events.

### Admin API

`GET /admin/api/timeline` (capability: **read**). Parameters mirror the query
above. The response is JSON by default, or the Markdown forensic report when
`?format=md` (or `Accept: text/markdown`) is sent.

```bash
# JSON, scoped to a coordinate
curl -s -H "Authorization: Bearer $TOKEN" \
  "$PROXY/admin/api/timeline?coordinate=evil@2.0.0"

# Markdown forensic report for an incident
curl -s -H "Authorization: Bearer $TOKEN" \
  "$PROXY/admin/api/timeline?incident=INC-42&format=md"
```

An unscoped request (no selector, no `all=true`) returns `400` with the
machine-readable code `missing_selector`.

### Admin UI

The **Timeline** tab provides the same surface interactively: enter a
coordinate / tenant / identity / incident, click **Reconstruct**, and the
correlated chain renders as a chronological table. Audit-backed rows link to
their Merkle proof. **Export Markdown** downloads the forensic report for an
incident ticket or evidence bundle.

### `ptctl timeline`

```bash
# Everything that happened to a package, as a forensic report
ptctl timeline --coordinate evil@2.0.0 --markdown

# The full chain of an incident, as JSON for an evidence bundle
ptctl timeline --incident INC-42 --json

# An actor's activity within a tenant scope
ptctl timeline --tenant acme --identity alice@example.com
```

The default output is an aligned table; `--json` emits the raw result and
`--markdown` streams the server-rendered report.

### Federated query integration

The timeline also feeds the federated query API (Task 67) field registry, so a
coordinate's forensic activity is queryable alongside its risk, vulnerability,
and approval facts:

| Field | Meaning |
|-------|---------|
| `timelineEvents` | count of correlated timeline events for the coordinate |
| `timelineLastSource` | subsystem that produced the most recent event |
| `timelineLastAt` | timestamp of the most recent event |
| `timelineProvable` | at least one event carries a Merkle inclusion proof |

```bash
# Coordinates with recent, provable forensic activity and an active block
ptctl query \
  -where timelineProvable:eq:true -where timelineEvents:gt:3 \
  -where lastVerdict:eq:block \
  --select coordinate,timelineEvents,timelineLastSource,lastVerdict
```

## Incident-response workflow

A typical triage flow using the timeline:

1. **Detect.** An alert fires — a SOC block, an anomaly trigger, a malfeed hit —
   or an operator engages an emergency lockdown (`ptctl lockdown freeze
   --reason … --incident INC-42`).
2. **Scope.** Open the **Timeline** tab (or `ptctl timeline`) and pivot on the
   affected coordinate, the suspicious identity, or the incident ID.
3. **Reconstruct.** Read the unified chain: when the package was first pulled,
   which gates flagged it, whether a break-glass exception was granted and by
   whom, when the lockdown engaged. De-duplication keeps it readable; the
   `corroborated` set shows which subsystems independently observed each fact.
4. **Prove.** For any audit-backed entry, follow its `proof` link to the Merkle
   inclusion proof and verify it offline with `pullthrough verify-audit`. This
   makes the timeline admissible as tamper-evident evidence.
5. **Export.** Download the Markdown forensic report (`--markdown` or the UI
   **Export Markdown** button) and attach it to the incident ticket.
6. **Remediate & confirm.** After remediation (deny rule, version pin, lockdown
   target, snapshot rollback), re-run the timeline to confirm the offending
   coordinate is now blocked and no further serves occurred.

## Design notes

- **No new event capture.** The engine holds no state beyond its configuration;
  every query reads the sources live. This guarantees the timeline can never
  drift from the systems of record.
- **Bounded.** The audit scan is bounded to the most-recent *N* records
  (`Config.AuditScan`, default 20 000) and each result is bounded by `Limit`
  (default 200, max 2000), so a query stays cheap even against a large log.
- **Determinism.** Ordering, de-duplication, and the coordinate roll-up are all
  deterministic functions of the inputs, exercised by the tests in
  `internal/timeline/timeline_test.go` (ordering, dedup, order-independence,
  tenant isolation, coordinate/incident scoping, truncation, Markdown export).
