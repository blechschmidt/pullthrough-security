# Federated query API

The federated query API (`internal/queryapi`) is a **read-only** endpoint that
lets operators and CI ask cross-cutting questions that span subsystems which
today require hitting many separate admin endpoints and joining the results by
hand. It joins the per-coordinate security facts spread across:

| Source        | Subsystem            | Contributes                                              |
| ------------- | -------------------- | ------------------------------------------------------- |
| `findings`    | admission findings   | gates, severities, blocking findings, signature status  |
| `riskscore`   | unified risk scoring | score, band, block/warn, block-adjacency                |
| `vulnscan`    | vuln/VEX gate        | CVE counts, max CVSS, identifiers, VEX, quarantine      |
| `provgraph`   | dependency graph     | downstream dependency paths (reverse-dep blast radius)  |
| `approvals`   | break-glass workflow | outstanding (active) exception grants                   |
| `secops`      | SOC read-model       | most recent serve verdict + timestamp                   |

into a single denormalized **row per `(tenant, ecosystem, coordinate)`**, then
filters, orders, projects, and paginates those rows through a small,
dependency-free JSON query/projection DSL — consistent with this project's
no-external-deps style (no GraphQL library).

The layer owns no source of truth: every fact is read live, through narrow
provider interfaces, from the subsystem that owns it. A disabled or unwired
subsystem simply contributes nothing, so the join degrades gracefully.

## Endpoints

All endpoints are under the admin prefix (default `/admin`) and are guarded by
the admin RBAC layer ([admin SSO & RBAC](admin-sso-rbac.md)). They require only
the **read** capability (`viewer` role and up). The query endpoint is a `POST`
because the query is a structured document, but it is strictly read-only and
mutates no state.

| Method & path             | Capability | Purpose                                        |
| ------------------------- | ---------- | ---------------------------------------------- |
| `POST /api/query`         | read       | Execute a federated query, return a result page |
| `GET  /api/query/schema`  | read       | The stable, self-describing query schema        |
| `GET  /api/query/metrics` | read       | Cumulative query-cost telemetry                 |

## Query document

```jsonc
{
  "tenant": "acme",                 // optional shorthand, ANDed as tenant eq <value>
  "select": ["coordinate", "riskBand", "downstreamPaths"], // omit ⇒ default set; ["*"] ⇒ all
  "where": { /* predicate tree, see below */ },
  "orderBy": [{ "field": "downstreamPaths", "desc": true }],
  "limit": 50,                      // clamped to schema.maxLimit
  "offset": 0
}
```

### Predicate tree

A `where` node is **either** a leaf predicate **or** exactly one boolean
combinator (`and`, `or`, `not`):

```jsonc
// leaf
{ "field": "riskBand", "op": "in", "value": ["high", "critical"] }

// composite
{ "and": [ <node>, <node> ] }
{ "or":  [ <node>, <node> ] }
{ "not": <node> }
```

### Operators

| Operator               | Applies to        | Meaning                                            |
| ---------------------- | ----------------- | -------------------------------------------------- |
| `eq` / `ne`            | string, number, bool | (in)equality; strings compare case-insensitively |
| `gt` / `gte` / `lt` / `lte` | number       | numeric comparison                                 |
| `in` / `nin`           | string, number, list | value is (not) one of a provided list / list intersection |
| `contains`             | string, list      | substring (string) or element membership (list)    |
| `prefix`               | string            | string starts with                                 |
| `exists`               | any filterable    | field present/non-empty when `value` is `true`     |

The authoritative field list, each field's kind, and its valid operators are
served by `GET /api/query/schema` and printed by `ptctl query --schema`.

## Result

```jsonc
{
  "rows":      [ { "coordinate": "evil@1.0.0", "riskBand": "critical", ... } ],
  "fields":    ["coordinate", "riskBand", ...],  // projection order
  "total":     1,        // records matching the filter (before pagination)
  "returned":  1,        // rows on this page
  "offset":    0,
  "limit":     50,
  "truncated": false,    // more matched than returned, or the scan bound was hit
  "scanned":   42,       // records considered
  "cost":      138,      // query cost units (see below)
  "generatedAt": "2026-06-20T12:00:00Z"
}
```

### Pagination & result bounds

`limit` is clamped to `schema.maxLimit` (default 500); omitting it uses
`schema.defaultLimit` (default 100). At most `schema.maxScan` (default 50000)
records are scanned per query; beyond that the result is flagged `truncated`.
Page through large result sets with `offset`.

### Query cost

`cost = scanned + scanned*predicates + returned*fields`. It is a deterministic
approximation of the engine effort a query costs, surfaced both in the response
and to Prometheus so operators can spot and budget expensive queries. Average
cost is derivable as `cost_units_total / queries_total`.

## The motivating query

> Every coordinate served to tenant `acme` in the last 24h whose risk band is
> block-adjacent **and** has an unverified signature **and** appears in more than
> 5 downstream dependency paths.

```json
{
  "tenant": "acme",
  "select": ["coordinate", "riskBand", "downstreamPaths", "signatureVerified"],
  "where": {
    "and": [
      { "field": "servedAgeSec",      "op": "lt", "value": 86400 },
      { "field": "blockAdjacent",     "op": "eq", "value": true },
      { "field": "signatureVerified", "op": "eq", "value": false },
      { "field": "downstreamPaths",   "op": "gt", "value": 5 }
    ]
  },
  "orderBy": [{ "field": "downstreamPaths", "desc": true }]
}
```

## `ptctl query`

The client CLI ([client-cli.md](client-cli.md)) wraps the endpoint. It accepts
either a raw query document or convenience flags that compose an AND-of-leaves
query.

```sh
# Builder mode (flags compose the query):
ptctl query --tenant acme \
  -where servedAgeSec:lt:86400 -where blockAdjacent:eq:true \
  -where signatureVerified:eq:false -where downstreamPaths:gt:5 \
  --select coordinate,riskBand,downstreamPaths --order -downstreamPaths

# Raw document mode (file, stdin, or positional JSON):
ptctl query --file query.json
echo '{"select":["*"],"limit":5}' | ptctl query --file -

# Inspect the schema / fields:
ptctl query --schema
ptctl query --fields          # offline; prints queryable field names

# Machine-readable output:
ptctl query --json --file query.json
```

A `-where` flag is `field:op:value`. With `in`/`nin` the value is comma-split
into a list (`riskBand:in:high,critical`); `true`/`false` become booleans and
numeric values become numbers. `--order` takes a comma list; prefix a field with
`-` for descending. Builder flags also layer over a raw `--file` document so
`--limit`/`--tenant` can override a saved query.

## Fields

The field registry (`internal/queryapi/schema.go`) is the stable schema. Notable
fields:

- **Identity:** `tenant`, `ecosystem`, `name`, `version`, `coordinate`, `digest`, `backend`
- **Risk:** `riskScore`, `riskBand`, `riskBlock`, `riskWarn`, `blockAdjacent` (band high/critical)
- **Signature:** `signatureVerified`, `signatureStatus` — `signatureVerified` is
  `true` unless a non-suppressed unverified-signature finding from the sigverify
  gate is present (a VEX-suppressed one still counts as unverified). Absent any
  sigverify finding the coordinate is treated as verified.
- **Findings:** `findings`, `blockingFindings`, `findingGates`, `findingRules`, `worstSeverity`
- **Vulnerabilities:** `hasVuln`, `vulnCritical`/`vulnHigh`/`vulnMedium`/`vulnLow`/`vulnTotal`, `maxCvss`, `maxSeverity`, `cves`, `quarantined`, `vexSuppressed`
- **Blast radius:** `downstreamPaths`, `directDependents`
- **Approvals:** `outstandingApprovals`, `approvalGates`
- **Serve recency:** `served`, `lastVerdict`, `lastVerdictGate`, `servedAgeSec`
  (very large when never served, so `servedAgeSec lt 86400` excludes it),
  `servedAt`
- **Timestamps (projectable, not filterable):** `servedAt`, `firstSeen`, `lastSeen`

### Coordinate joining

Sources are joined by a normalized `name@version` coordinate (tenant-less
sources — `vulnscan`, `secops` — attach by digest, then by ecosystem+coordinate).
The normalizer strips a leading `ecosystem/` qualifier so `npm/lodash@4.17.21`
and `lodash@4.17.21` join.

## Metrics

`bindQueryAPIMetrics` exports the engine's cumulative cost telemetry:

| Metric                                       | Type    | Meaning                              |
| -------------------------------------------- | ------- | ------------------------------------ |
| `pullthrough_queryapi_queries_total`         | counter | queries executed                     |
| `pullthrough_queryapi_rejected_total`        | counter | queries rejected at validation       |
| `pullthrough_queryapi_cost_units_total`      | counter | cumulative cost units                |
| `pullthrough_queryapi_rows_scanned_total`    | counter | records scanned                      |
| `pullthrough_queryapi_rows_returned_total`   | counter | rows returned                        |
| `pullthrough_queryapi_truncated_total`       | counter | queries truncated by a bound         |
| `pullthrough_queryapi_max_cost_units`        | gauge   | highest single-query cost            |
| `pullthrough_queryapi_last_cost_units`       | gauge   | cost of the most recent query        |

## Admin UI

The **Query** tab in the admin dashboard is a query console: a JSON editor
(Ctrl/Cmd+Enter runs), a schema browser, and a results table with the
cost/row/scan readout. It is the same endpoint the CLI uses.

## Validation errors

Validation failures return HTTP 400 with a stable machine-readable `code` so CI
can branch on them: `invalid_field`, `invalid_operator`, `not_filterable`,
`invalid_value`, `invalid_limit`, `invalid_offset`, `empty_filter`,
`ambiguous_filter`, `filter_too_deep`, `missing_operator`.
