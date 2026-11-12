# FIPS 140-3 cryptographic mode & build variant

This document describes the FIPS 140-3 compliant cryptographic operating mode
added in **Task 120** for regulated and enterprise deployments: a FIPS-capable
build variant, an explicit `fips.enabled` runtime posture, the enforced
approved-algorithm set, the startup fail-fast behavior, and the compliance
limitations you must be aware of.

> **Scope.** This feature wires the proxy to Go's **FIPS 140-3 Cryptographic
> Module** and enforces a disciplined approved-only posture around it. It does
> **not**, by itself, make a deployment "FIPS certified" — see
> [Compliance posture & limitations](#compliance-posture--limitations).

It is **off by default**, so existing non-regulated deployments are unaffected.

## How it works

The proxy delegates the actual cryptographic enforcement to the **Go FIPS 140-3
Cryptographic Module** (`crypto/fips140`), shipped with the Go toolchain. When a
binary is built with `GOFIPS140` and run with `GODEBUG=fips140=on`, the standard
library's crypto packages restrict themselves to FIPS 140-3 approved algorithms,
key sizes, and parameters. The proxy does not reimplement that gating; instead it:

1. **Selects the module at build time** via the `fips` build variant
   (`make build-fips`, which sets `GOFIPS140`). The resulting binary
   self-reports its crypto build variant.
2. **Activates and asserts the mode at runtime** via `fips.enabled`, and
   **fails fast at startup** if FIPS is required but the validated module is not
   actually active — so a deployment can never silently run standard crypto
   while an operator believes it is compliant.
3. **Applies approved parameters defensively** where the application sets crypto
   parameters explicitly (TLS termination cipher suites / version floor).
4. **Rejects non-approved configuration** (e.g. a TLS floor below 1.2) during
   config validation.
5. **Surfaces the active mode** in startup logs and the admin API.

## The build variant

Build the FIPS variant with the dedicated Make target:

```sh
make build-fips            # -> bin/pullthrough-fips, bin/ptctl-fips
# equivalently, with an explicit module selector:
make build-fips GOFIPS140=v1.0.0
```

This compiles with `GOFIPS140=latest` (override via the `GOFIPS140` variable)
and the `fips` build tag. `GOFIPS140` links a frozen snapshot of the validated
module into the binary and makes `GODEBUG=fips140=on` the default at run time;
the `fips` build tag makes the binary report `buildVariant: "fips"`.

Run the suite under the module:

```sh
make test-fips             # GOFIPS140=... GODEBUG=fips140=on go test -tags fips ./...
```

CI builds and tests the FIPS variant on every change (the **FIPS 140-3 variant
build & test** job in `.github/workflows/ci.yml`), so the variant cannot
silently break.

### Runtime module controls (`GODEBUG=fips140=…`)

| Value | Effect |
|-------|--------|
| `on`   | Module active; approved algorithms used. Non-approved calls are permitted but not routed through the module. This is the default baked in by `GOFIPS140`. |
| `only` | Module active **and enforcing**: any attempt to use a non-approved algorithm fails/panics. Strongest posture. |
| `off`  | Module inactive even in a FIPS-built binary. |

`fips.enabled: true` with the default `requireModule: true` requires the module
to be **active** (`on` or `only`). Use `only` for the strictest guarantee.

## Runtime configuration

```yaml
fips:
  # Turn on FIPS 140-3 approved-crypto enforcement.
  enabled: true
  # Defaults to true when enabled. When true, startup fails fast unless the
  # validated Go FIPS 140-3 module is active in the process. Set to false to
  # apply the approved-algorithm enforcement (TLS hardening, config validation)
  # WITHOUT the validated module — e.g. for local testing on a non-FIPS build.
  requireModule: true
```

See [configuration-reference.md](configuration-reference.md) for the generated
field reference.

### Startup fail-fast

With `fips.enabled: true` and `requireModule: true` (the default), the process
**refuses to start** unless the module is active:

```
fips: fips.enabled is set with fips.requireModule=true, but the Go FIPS 140-3
cryptographic module is not active in this process; build the FIPS variant
(`make build-fips`, which sets GOFIPS140) and run it with GODEBUG=fips140=on,
or set fips.requireModule=false to run approved-algorithm enforcement without
the validated module
```

Config validation additionally rejects, at load time, any explicitly configured
TLS floor below 1.2 (`outbound.tls.minVersion`, each `upstreams.<n>.tls` and its
mirrors) while FIPS is enabled, because TLS 1.0/1.1 depend on non-approved
constructions.

### Startup log

The active crypto mode is logged once at startup:

```
level=INFO msg="crypto mode" mode=fips fips.enabled=true fips.requireModule=true \
  module.active=true module.enforced=false module.version=v1.0.0 build.variant=fips
```

## Supported / approved algorithms

The proxy's security primitives already use FIPS 140-3 approved algorithms; the
FIPS mode asserts and (for TLS) pins them.

| Surface | Algorithm(s) in use | FIPS 140-3 status |
|---------|---------------------|-------------------|
| **TLS termination** (inbound) | TLS 1.2+; cipher suites pinned to `ECDHE-{ECDSA,RSA}-AES{128,256}-GCM-SHA{256,384}`; TLS 1.3 suites gated by the module | Approved |
| **Signature verification** (sigverify / cosign) | ECDSA (P-256/384/521) over SHA-256, RSA PKCS#1 v1.5 over SHA-256, EdDSA (Ed25519, FIPS 186-5) | Approved |
| **Audit-log hashing** | HMAC-SHA-256 keyed hash chain; SHA-256 RFC 6962 Merkle tree; signed checkpoints | Approved |
| **Cache content addressing** | SHA-256 (default); SHA-512 for integrity verification | Approved |
| **Approved digest set** (policy) | SHA-224/256/384/512, SHA-512/224, SHA-512/256, SHA3-224/256/384/512 | Approved |
| **Rejected** | MD5, SHA-1, TLS 1.0/1.1, CBC-mode & RC4 cipher suites, ChaCha20-Poly1305 (not FIPS-approved) | Non-approved |

When the module is in enforcing mode (`GODEBUG=fips140=only`), any attempt to
use a non-approved primitive anywhere in the process fails loudly.

**Post-quantum signatures.** The optional post-quantum / hybrid verification
support in the signature gate (`sigverify.pqc`, see
[sigverify](sigverify.md#post-quantum--hybrid-signatures)) implements the FIPS
204 (ML-DSA) and FIPS 205 (SLH-DSA) *algorithms*, but via the `cloudflare/circl`
provider, which is **not a FIPS 140-3 validated module**. Enabling it while
`fips.enabled` is set therefore **fails startup preflight** rather than running a
non-validated provider under a FIPS posture — the two are mutually exclusive
until the provider is validated.

## Surfacing the active mode

The admin API reports the live crypto mode at `GET {adminPrefix}/api/policy`
under the `crypto` object:

```json
{
  "crypto": {
    "mode": "fips",
    "fipsEnabled": true,
    "moduleActive": true,
    "moduleEnforced": false,
    "module": "Go Cryptographic Module v1.0.0",
    "buildVariant": "fips"
  }
}
```

`mode` is `"fips"` when enforcement is enabled, else `"standard"`. `moduleActive`
reflects the live `crypto/fips140` state; `buildVariant` reflects the compile-time
build tag.

## Compliance posture & limitations

- **This is not a certification.** FIPS 140-3 validation applies to the
  **cryptographic module**, not to this application. The proxy uses the Go FIPS
  140-3 Cryptographic Module, which carries its own CMVP validation status and
  certificate (see the Go FIPS 140-3 documentation for the current status and
  module version). Running the FIPS variant correctly is **necessary but not
  sufficient** for an organizational FIPS compliance claim; consult your
  compliance authority.
- **Module activation is the real control.** `fips.enabled` without the module
  active (`requireModule: false`) only applies the proxy's own approved-algorithm
  discipline (TLS hardening + config validation). It does **not** route crypto
  through the validated module and must not be represented as FIPS-validated
  operation. The default (`requireModule: true`) prevents this footgun.
- **Non-crypto dependencies are out of scope.** Any crypto performed by external
  tools the proxy may invoke (e.g. a `git` binary over SSH/HTTPS, a container
  runtime) is governed by those tools, not this process's module.
- **TLS 1.3 cipher suites are not operator-configurable** in Go; the module
  restricts them when active. The pinned cipher-suite list affects TLS 1.2.
- **EdDSA/Ed25519** is approved under FIPS 186-5 and is accepted; deployments
  with a stricter internal policy should restrict upstream signing keys
  accordingly.
- **Toolchain requirement.** The FIPS module ships with the Go toolchain; build
  with a Go version that includes the validated module and set `GOFIPS140` to a
  module version your compliance scope accepts (pin an explicit `vX.Y.Z` rather
  than `latest` for auditability).

## References

- Go FIPS 140-3 documentation: <https://go.dev/doc/security/fips140>
- [access-control-and-audit.md](access-control-and-audit.md) — audit hashing &
  secret encryption that run under this mode.
- [sigverify.md](sigverify.md) — signature/attestation verification.
- [intercept-mode.md](intercept-mode.md) — TLS interception and NAT mode (a
  FIPS-relevant crypto path when enabled: the TLS terminated for intercepted
  clients gets the same approved floor as the gateway's listener).
- [self-release.md](self-release.md) — the FIPS build variant ships on the same
  reproducible, cosign-signed, SLSA-attested release path; verify it with
  `ptctl verify-self`.
