# WASM extensibility: custom admission gates

The proxy's admission pipeline is rich but fixed — vulnerability/OSV scanning,
VEX adjudication, license compliance, secret detection, signature/attestation
verification, nameguard, the composite risk score, and the policy-as-code
engine. Enterprises frequently need **org-specific** gate logic on top of these
— custom naming rules, internal CMDB/inventory lookups, bespoke metadata checks
— that does not belong in the proxy core and must not require forking it.

The **extension** subsystem (`internal/extension`) loads operator-supplied
**WebAssembly** modules and runs them as an additional, late-stage admission
gate. A module receives a serialized, read-only view of the request's admission
context and returns a structured verdict (`allow` / `warn` / `block` + reason +
annotations). Modules run in a pure-Go WebAssembly interpreter
([wazero](https://wazero.io) — no cgo, no native codegen, air-gap friendly)
under strict CPU/memory/time/fuel limits with **no host filesystem or network
access** by default.

Like the policy and risk gates, an extension gate **composes** with the
hard-coded gates: it can turn an otherwise-allowed artifact into a `warn` or
`block`, but it is never consulted to re-admit something an earlier gate already
refused.

## Where it runs

The extension gate is the **final** admission stage, after the policy-as-code
and risk-scoring gates:

```
nameguard → malfeed → sigverify → vulnscan → license → policyengine → riskscore → EXTENSIONS → serve
```

By the time a module runs, every other gate's signals (and the composite risk
score) are already populated, so a module sees the full picture.

## Configuration

```yaml
extensions:
  enabled: true                    # on by default, but inert until modules exist
  defaults:                        # limit defaults for modules that omit a bound
    timeoutMs:      250            # per-invocation wall-clock CPU/time budget
    memoryBytes:    67108864       # linear-memory cap (64 MiB), rounded to 64KiB pages
    fuel:           0              # function-call budget; 0 disables fuel metering
    maxOutputBytes: 65536          # cap on the verdict bytes read back
  modules:
    - name: org-naming-policy      # stable id (metrics label, audit, admin, selection)
      path: /etc/pullthrough/gates/naming.wasm
      failClosed: false            # see "Failure policy" below
      tenants: [payments]          # restrict to these teams; omit ⇒ all tenants
      limits:                      # per-module overrides of `defaults`
        timeoutMs: 100
        fuel: 5000000
```

- **Per-tenant selection** — a module with a non-empty `tenants` list runs only
  for those teams; an empty list runs for every tenant. Modules run in the order
  listed.
- **Hot-reload** — `POST /admin/api/extensions/reload` recompiles every module
  from its `path` and swaps the working sandboxes in. A module whose rebuild
  fails is **kept online** (the previous compiled version keeps serving) and the
  error is reported in the admin snapshot, so a bad new build never takes a gate
  offline.

## Failure policy (fail-open vs fail-closed)

A module can fail to produce a verdict: it can time out, exhaust its fuel
budget, trap, or return a malformed verdict; or it can fail to compile at
startup. Each module's `failClosed` setting resolves these terminal outcomes:

- `failClosed: false` (default) — **fail open**: the module is skipped and the
  artifact proceeds. Availability over safety, matching the project's other
  gates whose failure modes default to open.
- `failClosed: true` — **fail closed**: the artifact is **blocked**. Safety over
  availability.

When several modules run, the **most severe** decision wins (`block` > `warn` >
`allow`), so any module can block and any can warn.

## Resource limits

Every invocation runs under three independent bounds:

| Bound | Config | Mechanism | Metric on breach |
|-------|--------|-----------|------------------|
| CPU / wall-clock time | `timeoutMs` | a context deadline that closes a runaway module mid-execution | `…_timeouts_total` |
| Linear memory | `memoryBytes` | a hard page cap on the module's memory | (contained; surfaces as timeout/error) |
| Fuel (instructions) | `fuel` | a function-call meter that aborts deep recursion / call-count explosions **deterministically**, independent of wall-clock time | `…_fuel_exhausted_total` |

Fuel metering is **off by default** (`fuel: 0`) because it adds per-call
overhead; enable it for an extra, time-independent bound against pathological
recursion. The memory page cap and the time budget are always in force.

> **Note on the wazero backend.** wazero is a pure-Go *interpreter* with no
> native instruction "fuel" register, so CPU is bounded by **time** and memory
> by a **page cap**. The `fuel` budget here meters **guest function calls** (via
> wazero's function-listener facility), which catches recursion/call-count
> explosions that a tight in-function loop would not — that case is caught by
> the wall-clock timeout instead. The two budgets are complementary.

## Metrics

Per module, labeled by `module` (and `decision` for verdicts):

- `pullthrough_extension_invocations_total{module}`
- `pullthrough_extension_verdicts_total{module,decision}` — `allow|warn|block`
- `pullthrough_extension_timeouts_total{module}`
- `pullthrough_extension_fuel_exhausted_total{module}`
- `pullthrough_extension_errors_total{module}` — traps, ABI violations, bad verdicts
- `pullthrough_extension_loaded{module}` — `1` loaded, `0` failed to load
- `pullthrough_extension_last_duration_microseconds{module}`

Every block/warn is also recorded in the tamper-evident **audit log**
(`policy_decision` event, reason `extension:<module>`) and emitted as a
**notification** (`extension` event type, severity high for block / medium for
warn). The admin UI **Extensions** tab shows per-module load state, limits, and
counters, with a reload button.

## Response headers

On the served (or blocked) response the gate sets:

- `X-Extension-Decision: allow|warn|block`
- `X-Extension-Module: <module that drove the decision>`
- `X-Extension-Reason: <reason>` (warn/block)

A block returns `403` with a JSON body (`code: "extension"`) carrying the
module, reason, annotations, and per-module breakdown.

---

## The host ABI (v1)

The wire contract between the host and a module is small, explicit, and
**versioned** (`ABIVersion = 1`). A module compiled against a future ABI is
refused at load rather than misbehaving per-call.

### Required exports

A module **must** export a linear memory named `memory` and:

```wat
(func (export "pt_abi_version") (result i32))        ;; returns the ABI version it implements
(func (export "pt_alloc") (param i32) (result i32))  ;; allocate N bytes, return offset (0 on failure)
(func (export "pt_eval")  (param i32 i32) (result i64));; evaluate input at [ptr,ptr+len), return packed result
```

It **may** export:

```wat
(func (export "pt_free") (param i32))                ;; release a pt_alloc'd buffer (best-effort)
```

### Call sequence (per invocation)

1. The host calls `pt_alloc(len)` to get an offset, writes the **host input
   JSON** there, and calls `pt_eval(ptr, len)`.
2. `pt_eval` returns a **packed `i64`**: the high 32 bits are the offset of the
   **verdict JSON** in linear memory, the low 32 bits are its length. Returning
   `0` signals an internal module error.
3. The host reads and parses the verdict, then best-effort calls `pt_free`.

The host instantiates a **fresh module instance per invocation**, so a module
carries **no state between requests** — every pull sees clean linear memory.

### Host input document

```json
{
  "abiVersion": 1,
  "module": "org-naming-policy",
  "signals": {
    "tenant": "payments",
    "artifact": { "ecosystem": "npm", "backend": "npm-public",
                  "name": "@acme/widgets", "version": "1.2.3", "digest": "sha256:…" },
    "vuln":      { "scanned": true, "criticalCount": 0, "maxSeverity": "high", "...": "..." },
    "license":   { "evaluated": true, "code": "ok", "...": "..." },
    "signature": { "checked": true, "verified": true, "...": "..." },
    "secret":    { "scanned": true, "findingCount": 0 },
    "nameguard": { "scanned": true, "typosquat": false },
    "provenance":{ "found": true, "confidence": "attested" }
  },
  "risk": { "score": 42, "band": "medium", "action": "off" }
}
```

`signals` is the proxy's canonical admission document (the same structure the
policy-as-code engine evaluates — see `internal/policyengine.Input`). Optional
sections are present only when the corresponding gate ran. `risk` is present
when the risk engine ran upstream.

### Verdict document

```json
{
  "decision": "block",
  "reason": "internal-namespace package served from a non-org backend",
  "annotations": { "rule": "dependency-confusion", "backend": "npm-public" }
}
```

`decision` must be `allow`, `warn`, or `block`. The host enforces bounds on the
verdict: `reason` ≤ 2 KiB, ≤ 32 annotations, annotation keys ≤ 128 bytes and
values ≤ 1 KiB, and the whole verdict ≤ `maxOutputBytes`. A verdict that
violates the ABI is treated as a module error (resolved by the fail policy).

## Writing a module

### Go (no extra toolchain — uses the standard Go ≥ 1.24 compiler)

The reference sample lives at
`internal/extension/testdata/src/sample_gate/` and demonstrates a
dependency-confusion guard, a risk-band escalation, and typosquat awareness. The
key shape:

```go
package main

import (
    "encoding/json"
    "unsafe"
)

var pinned = map[uint32][]byte{} // keep allocations alive across the host's writes/reads

//go:wasmexport pt_abi_version
func ptABIVersion() int32 { return 1 }

//go:wasmexport pt_alloc
func ptAlloc(n int32) int32 {
    b := make([]byte, n)
    p := uint32(uintptr(unsafe.Pointer(&b[0])))
    pinned[p] = b
    return int32(p)
}

//go:wasmexport pt_free
func ptFree(p int32) { delete(pinned, uint32(p)) }

//go:wasmexport pt_eval
func ptEval(ptr, n int32) int64 {
    var doc struct {
        Signals struct {
            Artifact struct{ Name, Backend string } `json:"artifact"`
        } `json:"signals"`
    }
    _ = json.Unmarshal(pinned[uint32(ptr)][:n], &doc)
    out := []byte(`{"decision":"allow"}`)
    // ... decide, then return the packed (offset<<32 | len) of the verdict bytes.
    p := ptAlloc(int32(len(out)))
    copy(pinned[uint32(p)], out)
    return (int64(uint32(p)) << 32) | int64(uint32(len(out)))
}

func main() {}
```

Build it (Go ≥ 1.24, which supports `//go:wasmexport` and the wasip1 reactor
build mode):

```sh
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o naming.wasm .
```

The repo's `make extension-fixtures` (or `internal/extension/testdata/build.sh`)
rebuilds the bundled Go fixtures.

### Rust / other languages

Any language that compiles to a WebAssembly module exporting the ABI works. A
zero-import (e.g. `wasm32-unknown-unknown`) module needs no WASI at all; the host
instantiates a **sealed** WASI surface (no preopens, no stdio, no sockets) only
so language runtimes that import it can initialize. Implement
`pt_abi_version`/`pt_alloc`/`pt_eval` (and optionally `pt_free`), export
`memory`, and follow the call sequence above.

---

## Threat model

Extension modules are **operator-supplied** but treated as **untrusted code**.
The design assumes a module may be buggy, malicious, or adversarially crafted
(including by an attacker who compromised the build pipeline that produced it),
and contains the blast radius accordingly.

**Isolation**
- Modules run in the wazero interpreter — a memory-safe, pure-Go WebAssembly VM
  with no cgo and no native code generation. A module cannot execute host code,
  read host memory, or escape the linear-memory sandbox.
- **No filesystem**: the WASI surface is instantiated with no preopened
  directories, so `open`/`read`/`readdir` see nothing on the host. (The
  conformance suite asserts a module probing `/` is denied or sees an empty
  root.)
- **No network**: WASI sockets are not wired; a module has no host networking.
- **No shared state**: a fresh instance is created per invocation, so one
  request's module run cannot observe or corrupt another's, and a module cannot
  accumulate state across pulls.

**Resource exhaustion**
- A CPU/time budget closes a runaway module; a memory page cap bounds its
  linear memory; an optional fuel meter bounds function-call explosions
  deterministically. A module cannot wedge the request path or exhaust host
  memory.
- The host bounds the bytes it reads back (`maxOutputBytes`) and the size of
  every verdict field, so a module cannot inject unbounded data into the audit
  log, response headers, or notifications. The verdict parse is strict (unknown
  fields rejected, decision validated).

**Failure containment**
- Every terminal outcome (timeout, fuel, trap, malformed verdict, failed load)
  is resolved by the module's `failClosed` policy, never by an unhandled panic.
  The host's evaluation path is **total**: it always yields a decision and never
  propagates an error into the request handler.
- A module that fails to compile at startup does not abort the proxy; it loads
  in a not-loaded state, is reported in the admin snapshot and the
  `…_loaded{module}=0` metric, and is resolved per its fail policy at request
  time.

**Input integrity**
- The host stamps the ABI version into every input document and refuses to load
  a module whose `pt_abi_version` it does not support, so an ABI mismatch fails
  fast at load rather than corrupting decisions per-call.
- The host-input serialization and the verdict parser are
  [fuzzed](testing.md) (`FuzzHostInputRoundTrip`, `FuzzParseVerdict`) to ensure
  neither panics on adversarial bytes and that the host's own document is always
  valid, bounded JSON.

**Residual risk / operator responsibilities**
- A module makes **admission decisions**; a malicious or buggy module within its
  resource envelope can still *wrongly allow or wrongly block* artifacts for the
  tenants it is selected for. Treat module binaries as security-sensitive
  configuration: review their source, build them reproducibly, and restrict who
  can change the `extensions.modules` config and the on-disk `.wasm` files.
- Wall-clock CPU bounding is best-effort to the interpreter's context-check
  granularity; pair it with the fuel budget for adversarial recursion.
- Hot-reload reads module files from disk; protect those paths with the same
  rigor as the proxy's other secrets/config.
