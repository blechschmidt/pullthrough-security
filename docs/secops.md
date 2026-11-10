# Security Operations dashboard (real-time SOC view)

The proxy enforces a stack of supply-chain admission gates — vulnerability/OSV
scanning, VEX adjudication, license compliance, secret detection,
signature/attestation verification, nameguard, known-malicious-package blocking,
behavioral anomaly detection, the unified risk score, the policy-as-code engine,
and the human-in-the-loop quarantine/approval workflow. Each gate has its own
admin tab, which is great for drilling in but leaves an operator without a single
at-a-glance answer to *"is anything on fire right now?"*

The **Security Operations** tab (admin UI) is that single pane of glass. It
aggregates, in near-real-time, a cross-subsystem view of recent admission
decisions and the current security posture, and streams notable verdicts live as
they happen — each with a drill-down link into the owning subsystem tab.

It introduces **no new source of truth**: the read-model taps the existing
in-process notification event bus for the live verdict feed and reads the
existing subsystem read-models (risk engine, anomaly engine, approvals service,
findings store) for the posture summary. Nothing is duplicated or persisted.

## What it shows

**Top-line posture (rolling window, default 1 hour):**

- **Notable verdicts** — total security-relevant decisions in the window.
- **Blocks vs warns vs admits** — the outcome split, as headline numbers and a
  colored split bar. *Admits* here means explicit allow overrides (granted
  break-glass exceptions); routine clean pulls are high-volume and are not
  streamed as individual events.
- **Breakdown by gate** — which subsystem is producing the verdicts (vulnscan,
  license, policyengine, riskscore, anomaly, malfeed, approvals, …).
- **Breakdown by tenant / subject** — which tenant or identity/scope the verdicts
  attribute to.
- **Breakdown by severity** — info → critical.

**Current posture (point-in-time, read live from each subsystem):**

- **Approval backlog** — pending quarantine reviews and active break-glass grants
  (with the oldest pending items).
- **Active anomalies** — tenant/identity scopes currently above the observe floor,
  and how many are soft-blocked.
- **Risk-band distribution** — low / medium / high / critical counts, plus the
  admission funnel (total scored, blocked, warned).
- **Findings** — aggregated findings artifacts retained, how many carry a blocking
  finding, and the by-gate / by-severity split.

**Live verdict feed:** a streaming table of notable verdicts (newest first). Each
row shows the time, derived outcome, owning gate (a link into that gate's tab
when one exists), severity, title, and the affected artifact/subject. The feed
updates instantly via server-sent events; the top-line aggregates short-poll
every 15 seconds so they stay current without a manual refresh.

## Operator workflow

1. Open the admin dashboard and select **Security Ops**. The stream pill shows
   `live` once the event stream connects.
2. Scan the KPI cards. A non-zero **Blocks** count, a growing **Approval backlog**,
   or any **Active anomalies** are the signals to act on; cards turn red/amber
   when they cross those thresholds.
3. Watch the **live verdict feed** for what is happening now. Click a gate chip in
   a row (or a gate bar) to jump straight to that subsystem's tab —
   e.g. a `malfeed` block, an `anomaly` soft-block, or an `approvals` request — to
   investigate or act (release a quarantine, grant/deny a break-glass exception,
   tune a policy).
4. Use the breakdowns to spot concentration: a single tenant dominating the
   *by-tenant* bar, or one gate dominating *by-gate*, usually points at the root
   cause (a compromised credential enumerating packages, a bad dependency wave, a
   misconfigured policy).
5. **Pause live feed** freezes the stream while you read a burst; **Resume** (or
   **Refresh**) reconnects and re-seeds. Pressing `r` refreshes the whole
   dashboard.

## API

Both endpoints sit under the admin API prefix (default `/admin`) and are guarded
by the admin SSO/RBAC capability map (Task 51): they require the **read**
capability (any authenticated role: viewer, operator, approver, admin). With the
legacy admin token they require the token; on a trusted network with neither, they
are open like the rest of the admin surface.

- `GET /admin/api/secops/summary` — the full read-model as JSON: the rolling-window
  tallies (`window`), the posture sections (`posture`, each omitted when its
  subsystem is disabled), the most recent notable events (`recent`), and a
  `subsystems` map flagging which contributors are enabled.
- `GET /admin/api/secops/stream` — a [server-sent events](https://developer.mozilla.org/docs/Web/API/Server-sent_events)
  stream. Each notable verdict is delivered as an `event: verdict` frame whose
  `data:` is a `NotableEvent` JSON object (the same shape as the `recent` entries),
  tagged with a monotonic `id:`. A comment heartbeat (`: ping`) keeps the
  connection warm. The stream is bounded and non-blocking end to end: a slow
  client never applies backpressure to the proxy's request path (events are
  dropped and counted instead), and the connection closes cleanly on disconnect.

  Because the admin API authenticates with a bearer token or SSO cookie (which the
  browser `EventSource` cannot attach for token auth), the dashboard consumes the
  stream via `fetch()` with the auth header and parses the SSE frames itself.

## Graceful degradation

The dashboard is always available when the admin surface is enabled, even with
every contributing subsystem disabled — it simply shows zeros and omits the
posture sections for disabled subsystems (the `subsystems` map and the toolbar
note make explicit what is off). The live feed reflects the in-process security
event bus: it works whether or not external notification delivery
(webhook/Slack) is configured — disabling `notifications` only turns off
off-box delivery, not the in-process feed that powers this dashboard.

## Metrics

The dashboard's own usage is observable via Prometheus counters (so you can alert
on, say, a stuck stream or query volume):

| Metric | Meaning |
| --- | --- |
| `pullthrough_secops_events_observed_total` | Notable events folded into the read-model. |
| `pullthrough_secops_summary_queries_total` | Posture-summary queries served. |
| `pullthrough_secops_stream_connections_total` | Live-event (SSE) streams opened. |
| `pullthrough_secops_stream_dropped_total` | Live events dropped because a subscriber fell behind. |
| `pullthrough_secops_active_streams` | Live streams currently connected (gauge). |

## Design notes

- **No duplicated source of truth.** The rolling-window tallies are a bounded,
  time-bucketed *projection* of events the Hub is told about via a notifier tap;
  the posture is read on demand from each owning subsystem. Restarting the proxy
  resets the window (it is an operational view, not an audit record — the
  tamper-evident audit log remains the ledger of record).
- **The Hub never re-decides anything.** It only *labels* what a gate already
  decided: an event's owning gate and coarse outcome (block/warn/admit) are
  derived from the event type and its `action`/`decision` field.
- **Bounded memory.** The feed ring and per-window key cardinality are capped, so a
  flood of unique subjects cannot grow memory without bound.
