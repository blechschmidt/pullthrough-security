# Distributed tracing (OpenTelemetry)

The proxy can emit **OpenTelemetry distributed traces** so operators see the full
latency breakdown of every pull — and pivot from an audited security decision
straight to the trace that produced it. Tracing is **disabled by default** and
turns on only when you point it at an OTLP collector.

- **What you get:** one trace per pull, spanning ingress → auth/tenant
  resolution → rate limiting → cache lookup → upstream fetch → each admission
  gate (signature, vulnerability, license, policy-as-code, risk score, name
  guard) → response. Background workers (CVE-drift re-scan, LLM commit scanning)
  emit their own traces.
- **No new dependency:** the proxy ships a vendored-thin OTLP/HTTP exporter, so
  enabling tracing pulls in no third-party SDK.
- **Standards-based:** W3C `traceparent`/`tracestate` context is propagated in
  from clients and out via the resource model; trace ids are correlated into the
  tamper-evident audit log.

## Enable it

Add a `tracing` block (see [configuration.md](configuration.md)) pointing at your
collector. Tracing is active only when `enabled: true` **and** `endpoint` is set.

```yaml
tracing:
  enabled: true
  endpoint: http://otel-collector:4318   # base URL; /v1/traces is appended
  insecure: true                         # http:// for a scheme-less endpoint
  serviceName: pullthrough
  samplerRatio: 1.0                       # sample all new traces (0..1)
  resourceAttributes:
    cluster: prod-eu
  # headers: { authorization: ${OTLP_INGEST_TOKEN} }
```

Containerized deployments can instead set environment variables (handy for
sidecar/auto-instrumentation conventions); an endpoint **auto-enables** tracing:

| Variable | Effect |
|----------|--------|
| `PTS_TRACING_ENDPOINT` / `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector address (auto-enables) |
| `PTS_TRACING_ENABLED` | force on/off (`true`/`false`) |
| `PTS_TRACING_INSECURE` | `http://` for a scheme-less endpoint |
| `PTS_TRACING_SAMPLER_RATIO` | head-sampling probability |
| `OTEL_SERVICE_NAME` | `service.name` resource attribute |

## Try it locally (Collector + Jaeger)

The repo-root compose file ships a `tracing` profile with an OpenTelemetry
Collector and Jaeger:

```sh
cp deploy/docker/.env.example deploy/docker/.env
# uncomment PTS_TRACING_ENDPOINT / PTS_TRACING_INSECURE in the .env
docker compose --profile tracing up --build
```

Then pull something through the proxy and open the **Jaeger UI** at
<http://localhost:16686> — search for service `pullthrough`. The collector
config is [`deploy/observability/otel/collector.yaml`](../deploy/observability/otel/collector.yaml);
swap its `otlp/jaeger` exporter for `otlp/tempo` to send to Grafana Tempo
instead.

## Span model

| Span | Kind | Key attributes |
|------|------|----------------|
| `pull <backend>` | server | `http.request.method`, `url.path`, `pullthrough.backend`, `pullthrough.ecosystem`, `pullthrough.tenant`, `pullthrough.package.{name,version,digest}`, `pullthrough.cache.status`, `pullthrough.risk.{band,score}`, `http.response.status_code` |
| `auth.check` | internal | `pullthrough.auth.allowed`, `pullthrough.auth.stage`, `enduser.id`, `pullthrough.tenant` |
| `ratelimit.admit` | internal | `pullthrough.ratelimit.allowed`, `pullthrough.ratelimit.reason` |
| `backend.resolve` | internal | `pullthrough.backend`, `pullthrough.cacheable` |
| `cache.fetch` | internal | `pullthrough.cache.key`, `pullthrough.cache.status` |
| `upstream.fetch` | client | `pullthrough.upstream.url`, `pullthrough.upstream.bytes` |
| `gate.<name>` | internal | `pullthrough.gate`, `pullthrough.gate.allowed` (one per admission gate: nameguard, policy, sigverify, vulnscan, license, policyengine, riskscore) |
| `scan.commit` | internal | `vcs.commit.sha`, `pullthrough.scan.{risk_score,malicious,findings,cached}` |
| `vulnscan.rescan.sweep` | internal | `pullthrough.rescan.{candidates,rescanned,changed,newly_vulnerable,errors}` |

A gate that blocks sets its span status to error; the request-level span is set
to error on a 5xx response.

## Sampling

Sampling is **parent-based over a trace-id ratio**: a client that already made a
sampling decision (propagated via `traceparent`) is always honored, so a
distributed trace is captured whole or not at all; locally-rooted traces are
sampled at `samplerRatio`. Even an unsampled request still propagates context
downstream with the correct sampled flag.

## Audit correlation

Every audit record carries the `traceId`/`spanId` of the request that produced
it (when tracing is active), so you can pivot from a blocked pull or an
authorization denial in the [audit log](access-control-and-audit.md) to its full
latency trace. The ids are part of the hash-chained record, so correlation does
not weaken tamper-evidence.

## Operational signals

The exporter's health is on the `/metrics` endpoint (see
[observability.md](observability.md)):

| Metric | Meaning |
|--------|---------|
| `pullthrough_tracing_spans_started_total` | spans started (sampled + unsampled) |
| `pullthrough_tracing_spans_sampled_total` | spans recorded for export |
| `pullthrough_tracing_spans_exported_total` | spans delivered to the collector |
| `pullthrough_tracing_spans_dropped_total` | spans dropped (queue full — collector too slow/unreachable) |
| `pullthrough_tracing_export_errors_total` | failed OTLP export requests |
| `pullthrough_tracing_queue_depth` | spans waiting in the export queue |

Export is fully asynchronous and the span queue is bounded, so a slow or absent
collector **never** applies backpressure to the request path — it shows up as
dropped spans, not added latency. The admin API exposes the same status at
`<adminPathPrefix>/api/tracing`.

## What is and isn't traced

Implemented: W3C context propagation, parent-based ratio sampling, OTLP/HTTP
(protobuf-JSON) export, span emission across the pull/admission pipeline and
background workers, and audit-log correlation. Deliberately omitted (kept thin):
the OTLP **metrics/logs** signals, the **gRPC** OTLP transport, baggage, and span
links. Outbound spans to external registries are not injected (those are
third-party services, not part of this trace).
