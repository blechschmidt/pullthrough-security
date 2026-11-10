# gRPC / Connect security API

The gRPC API (`internal/grpcapi`) is a **read-only**, [Connect](https://connectrpc.com)-compatible
surface over the proxy's supply-chain security data model. Because it is built
with Connect, a **single handler speaks three protocols** from one endpoint:

- **gRPC** (binary, HTTP/2) — for generated gRPC clients and service meshes.
- **gRPC-Web** — for browser clients.
- **Connect / HTTP-JSON** — plain `POST` with a JSON body, so `curl` and any
  HTTP client work without a protobuf toolchain.

It exposes exactly the same facts as the [federated GraphQL query API](query-api.md)
(Task 67) and the [MCP server](mcp-server.md) (Task 79) — coordinate dossier
lookup, findings/corpus queries, risk verdicts, provenance-graph edges, and the
compliance scorecard — and it **reuses the identical read-access layer** (the
federated query engine plus the per-subsystem detail providers) rather than
duplicating any query logic.

## Schema

The surface is defined in [`proto/pullthrough/security/v1/security.proto`](../proto/pullthrough/security/v1/security.proto)
as the `SecurityQueryService`:

| RPC                        | Kind            | Backed by                                   | Answers                                                            |
| -------------------------- | --------------- | ------------------------------------------- | ------------------------------------------------------------------ |
| `GetDossier`               | unary           | `dossier` builder (+ query model)           | The full per-coordinate "360 view" triage card.                    |
| `GetRiskVerdict`           | unary           | `riskscore` (+ query summary)               | Is this package safe to add? Score, band, recommended action.      |
| `GetFindings`              | unary           | `findings` (+ query summary)                | What admission findings does it have?                              |
| `GetProvenance`            | unary           | `provgraph` + `attestbundle` (+ summary)    | Source commit, reverse-dependency blast radius, attestation.       |
| `GetComplianceScorecard`   | unary           | `compliance`                                | SLSA/SOC2-style posture score, grade, and control checklist.       |
| `QueryCorpus`              | unary           | `queryapi` (passthrough)                     | Ad-hoc questions over the whole security data model.               |
| `StreamQueryCorpus`        | server-stream   | `queryapi` (passthrough)                     | The same query, streamed row-by-row then a terminal summary.       |

The Go stubs are **committed** under `internal/grpcapi/gen` so the build never
runs `protoc` or fetches a codegen plugin (no network codegen at build time).
Regenerate them after editing the proto with:

```sh
make proto-gen      # pins protoc-gen-go + protoc-gen-connect-go versions
```

## Enabling it

The service is **off by default**. Turn it on under the admin surface:

```yaml
observability:
  admin: true
  grpc: true              # mount the gRPC/Connect security API
  grpcMaxDetailItems: 100 # per-RPC bound on detail records (findings, deps, ...)
```

It mounts as a subtree under the admin API at `<adminPrefix>/api/grpc`, so
Connect's canonical `/<package>.<Service>/<Method>` procedure paths live beneath
the admin `/api/` subtree — e.g.
`/admin/api/grpc/pullthrough.security.v1.SecurityQueryService/GetRiskVerdict`.

## Security model

The endpoint is mounted **under the admin API** and reuses its authentication
and RBAC layer (see [admin SSO & RBAC](admin-sso-rbac.md)):

- Every RPC requires the **read** capability (`CapRead`). The whole `/api/grpc`
  subtree is read-only even though Connect dispatches every RPC as a `POST`.
- It is **hard-scoped by tenant**. When the caller presents a tenant-bound
  identity (an OIDC bearer JWT with a tenant claim, or a static token bound to a
  tenant), every RPC is locked to that identity's tenant — a `tenant` field in
  the request message **cannot widen it**. A global identity (no tenant bound,
  e.g. an org-wide admin) may target a tenant via the request's `tenant` field;
  an empty value queries across tenants, matching the GraphQL/MCP semantics.

Because true gRPC (binary over HTTP/2) needs an HTTP/2 transport, reach the
service over gRPC only when the admin listener terminates TLS (h2) or is fronted
by an h2c-capable proxy. The **Connect** and **gRPC-Web** protocols work over
plain HTTP/1.1, so the bundled `ptctl grpc` client and `curl` work against the
default admin listener with no extra setup.

## Using it

### `ptctl grpc` (reference client)

`ptctl grpc` is a worked example client built on the generated Connect stubs. It
attaches the bearer credential to every call (unary and streaming) and speaks the
Connect protocol over HTTP/1.1.

```sh
# Smoke test: a unary RPC (compliance scorecard) + a streamed corpus query.
ptctl grpc --url https://proxy.example.com --token "$TOKEN"

# Per-coordinate RPCs.
ptctl grpc --rpc risk       --name left-pad --ecosystem npm
ptctl grpc --rpc findings   --name log4j-core --ecosystem maven --version 2.14.1
ptctl grpc --rpc provenance --name express --ecosystem npm --version 4.18.2
ptctl grpc --rpc dossier    --coordinate left-pad --ecosystem npm

# Compliance scorecard (optionally recomputed from live posture).
ptctl grpc --rpc compliance --refresh

# Ad-hoc federated query (unary), and the same query streamed row-by-row.
ptctl grpc --rpc query  --select coordinate,riskScore --where '{"field":"riskBlock","op":"eq","value":true}'
ptctl grpc --rpc stream --select coordinate,riskScore --limit 25

# Add --json to any call for the raw structured result.
```

### curl (Connect / HTTP-JSON)

Every RPC is reachable as a JSON `POST`. The tenant is taken from your identity;
the `tenant` field below is honored only for a global identity.

```sh
curl -sS https://proxy.example.com/admin/api/grpc/pullthrough.security.v1.SecurityQueryService/GetRiskVerdict \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ecosystem":"npm","name":"left-pad"}'
```

For `StreamQueryCorpus` over Connect, each streamed message is length-prefixed in
the response body (the `connect-es`/`connect-go` clients and `ptctl grpc --rpc
stream` decode it for you).

### A generated gRPC/Connect client (Go)

```go
import (
    connect "connectrpc.com/connect"
    securityv1 "github.com/blechschmidt/pullthrough-security/internal/grpcapi/gen/securityv1"
    "github.com/blechschmidt/pullthrough-security/internal/grpcapi/gen/securityv1/securityv1connect"
)

client := securityv1connect.NewSecurityQueryServiceClient(
    httpClient, "https://proxy.example.com/admin/api/grpc")
resp, err := client.GetRiskVerdict(ctx, connect.NewRequest(&securityv1.CoordinateRequest{
    Ecosystem: "npm", Name: "left-pad",
}))
```

## Metrics

The service exports `pullthrough_grpc_*` Prometheus counters:

| Metric                                | Labels   | Meaning                                              |
| ------------------------------------- | -------- | ---------------------------------------------------- |
| `pullthrough_grpc_requests_total`     | —        | RPCs dispatched (unary and streaming).               |
| `pullthrough_grpc_errors_total`       | —        | RPCs that returned a Connect error.                  |
| `pullthrough_grpc_streams_total`      | —        | Server-streaming RPCs dispatched.                    |
| `pullthrough_grpc_stream_messages_total` | —     | Messages sent across all streaming RPCs.             |
| `pullthrough_grpc_rpc_calls_total`    | `method` | RPC invocations, partitioned by method name.         |
| `pullthrough_grpc_rpc_errors_total`   | `method` | RPC invocations that returned an error, by method.   |

## Relationship to the other read surfaces

This is the third projection of the same read-only data model, chosen to match
however a consumer prefers to integrate:

- [**GraphQL federated query API**](query-api.md) — ad-hoc cross-cutting
  questions from dashboards and scripts.
- [**MCP server**](mcp-server.md) — read-only security context for AI agents.
- **gRPC / Connect API** (this document) — typed, schema-first RPCs for services,
  meshes, and strongly-typed clients.

All three enforce the same OIDC/RBAC and per-tenant scoping and reuse the same
federated query engine and detail providers; none owns its own query logic.
