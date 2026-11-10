# MCP server (security context for AI agents)

The MCP server (`internal/mcpserver`) is a **read-only** [Model Context
Protocol](https://modelcontextprotocol.io) endpoint that exposes the proxy's
supply-chain security knowledge to AI assistants — Claude, Codex, Cursor, and
other IDE/agentic developer tools. It turns the proxy into a first-class context
source: an AI coding agent can ask **"is this package safe to add?"** and get the
proxy's authoritative verdict, findings, provenance, incident timeline, and known
vulnerabilities for a coordinate, scoped to the agent's tenant.

It is deliberately a thin projection over the existing subsystems. Every tool is
backed by the [federated query engine](query-api.md) (Task 67), reusing its
**stable field registry** rather than reinventing per-tool projections, and so
inherits the engine's deterministic cost bounds. Tools additionally enrich the
summary with detail from the backing subsystems when they are wired:

| Tool                  | Backed by                                  | Answers                                                            |
| --------------------- | ------------------------------------------ | ----------------------------------------------------------------- |
| `get_risk_verdict`    | `riskscore` (+ query summary)              | Is this package safe to add? Score, band, recommended action.     |
| `get_findings`        | `findings`/SARIF (+ query summary)         | What admission findings does it have? (`summary` or `sarif`)      |
| `get_provenance`      | `provgraph` + `attestbundle` (+ summary)   | Where did it come from? Source commit, blast radius, attestation. |
| `get_timeline`        | `timeline`                                 | What happened to it / during an incident?                         |
| `get_vulnerabilities` | `vulnscan`/VEX (+ query summary)           | What CVEs affect it after VEX adjudication?                       |
| `run_query`           | `queryapi` (passthrough)                   | Ad-hoc questions over the whole security data model.              |

## Security model

The MCP endpoint is mounted **under the admin API** and reuses its authentication
and RBAC layer (see [admin SSO & RBAC](admin-sso-rbac.md)):

- It requires the **read** capability (`CapRead`). Every tool is strictly
  read-only — it mutates no state. (The endpoint is a `POST` only because a
  JSON-RPC message is a structured document.)
- It is **hard-scoped by tenant**. When the caller presents a tenant-bound
  identity (an OIDC bearer JWT with a tenant claim, or a static token bound to a
  tenant), every tool is locked to that identity's tenant — a query parameter or
  a `tenant` field in `run_query` arguments **cannot widen it**. A global identity
  (no tenant bound, e.g. an org-wide admin) or, on a trusted network with the
  admin surface left unauthenticated, a caller may target a tenant via the
  `?tenant=` query parameter; an empty result queries across tenants, matching
  the federated query API's semantics.
- The same **cost bounds** as the federated query API apply: each per-coordinate
  tool issues a single bounded lookup, detail payloads are capped at
  `observability.mcpMaxDetailItems` (default 100), and an accepted message body is
  capped at 1 MiB.

## Configuration

```yaml
observability:
  admin: true # the MCP endpoint is mounted under the admin API
  mcp: true # enable the MCP server (default: true when admin is on)
  mcpMaxDetailItems: 100 # per-tool detail cap (findings, vulns, events, dependents)
```

The endpoint is enabled by default whenever the admin surface is on. Set
`observability.mcp: false` to turn it off.

## Transports

The package speaks MCP (JSON-RPC 2.0) over two transports:

- **HTTP** — `POST <admin-prefix>/api/mcp` (default `/admin/api/mcp`). A single
  JSON-RPC message (or a batch array) per request; a notification yields `202
  Accepted` with no body. `GET /api/mcp` returns the tool catalog and server
  metadata for discovery without speaking JSON-RPC.
- **stdio** — newline-delimited JSON-RPC, via `(*mcpserver.Server).ServeStdio`.
  Because most IDE agents launch a local stdio MCP server, `ptctl mcp --stdio`
  provides a thin **stdio↔HTTP bridge**: it forwards each JSON-RPC line to the
  proxy's MCP HTTP endpoint, scoped to `--tenant`.

## MCP handshake

```jsonc
// → request
{ "jsonrpc": "2.0", "id": 1, "method": "initialize",
  "params": { "protocolVersion": "2025-06-18", "clientInfo": { "name": "claude" } } }

// ← response
{ "jsonrpc": "2.0", "id": 1, "result": {
    "protocolVersion": "2025-06-18",
    "capabilities": { "tools": { "listChanged": false } },
    "serverInfo": { "name": "pullthrough-security", "version": "1.4.0" },
    "instructions": "Read-only supply-chain security context for package coordinates. …" } }
```

`tools/list` returns each tool's `name`, `description`, and JSON-Schema
`inputSchema`. `tools/call` invokes a tool:

```jsonc
// → "is lodash@4.17.21 safe to add?"
{ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
  "params": { "name": "get_risk_verdict",
              "arguments": { "ecosystem": "npm", "name": "lodash", "version": "4.17.21" } } }

// ← the verdict (content[].text mirrors structuredContent as indented JSON)
{ "jsonrpc": "2.0", "id": 2, "result": {
    "isError": false,
    "structuredContent": {
      "coordinate": "lodash@4.17.21", "found": true,
      "score": 18, "band": "low", "verdict": "allow",
      "signatureVerified": true,
      "summary": "lodash@4.17.21 has risk band \"low\" (score 18). Recommended admission action: allow." },
    "content": [ { "type": "text", "text": "{ … }" } ] } }
```

Tool execution problems (an unknown tool, a missing required argument, a rejected
`run_query`) are reported as a normal result with `"isError": true` per the MCP
spec; JSON-RPC errors are reserved for protocol-level problems (unknown method,
malformed params).

### Tool arguments

The per-coordinate tools (`get_risk_verdict`, `get_findings`, `get_provenance`,
`get_timeline`, `get_vulnerabilities`) take `{ name, version?, ecosystem? }`;
`name` is required and the most-recently-seen version is used when `version` is
omitted. `get_findings` also takes `format` (`summary` (default) or `sarif`).
`get_timeline` also takes `incidentId` and `limit`. `run_query` takes a federated
query document (`select`, `where`, `orderBy`, `limit`, `offset`) — its `tenant`
field is always overridden with the caller's hard tenant scope.

## CLI: `ptctl mcp`

The [`ptctl`](client-cli.md) `mcp` subcommand both onboards an operator and
serves as a connectivity/auth/tool **smoke test**:

```console
$ ptctl mcp --url https://proxy.example.com --tenant acme
Connected to MCP server "pullthrough-security" (version 1.4.0, protocol 2025-06-18)

Exposed tools (6):
  - get_risk_verdict     Return the proxy's authoritative, explainable supply-chain risk verdict …
  - get_findings         Return the aggregated admission-gate findings for a coordinate …
  - get_provenance       Return the supply-chain provenance for a coordinate …
  - get_timeline         Reconstruct the forensic incident timeline for a coordinate …
  - get_vulnerabilities  Return the known vulnerabilities affecting a coordinate after VEX …
  - run_query            Run an ad-hoc read-only query over the proxy's federated security data model …

Smoke test OK. Pass --call <tool> --name <pkg> to invoke a tool.

$ ptctl mcp --url https://proxy.example.com --tenant acme \
    --call get_risk_verdict --name lodash --version 4.17.21 --json
```

### Wiring an IDE agent (stdio bridge)

Configure the agent to launch `ptctl` as its MCP server. For example, a Claude
Desktop `mcpServers` entry:

```jsonc
{
  "mcpServers": {
    "pullthrough-security": {
      "command": "ptctl",
      "args": ["mcp", "--stdio", "--url", "https://proxy.example.com", "--tenant", "acme"],
      "env": { "PULLTHROUGH_TOKEN": "<read-capable token>" }
    }
  }
}
```

The agent now has the six tools available and can consult the proxy's
authoritative verdict before recommending or adding a dependency.

## Metrics

The server exports cumulative telemetry via the Prometheus bridge:

| Metric                              | Type             | Meaning                                       |
| ----------------------------------- | ---------------- | --------------------------------------------- |
| `pullthrough_mcp_requests_total`    | counter          | JSON-RPC requests dispatched (no notifications)|
| `pullthrough_mcp_errors_total`      | counter          | Requests that errored (JSON-RPC or `isError`) |
| `pullthrough_mcp_tool_calls_total`  | counter `{tool}` | `tools/call` invocations per tool             |
| `pullthrough_mcp_tool_errors_total` | counter `{tool}` | `tools/call` errors per tool                  |

`GET /api/mcp` also returns the live snapshot under `metrics`.
