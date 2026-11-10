# Inbound build-provenance verification (Task 72)

The `internal/buildprov` admission gate **consumes** the build-provenance
attestations upstream registries publish and uses them to cryptographically bind
a pulled package version to the exact source repository, commit, and CI workflow
that built it — then cross-checks that proven commit against the
package-to-commit association the provenance subsystem (Task 8) reported, and
flags disagreements.

It is distinct from two neighbouring subsystems:

| Subsystem | Direction | Question it answers |
|-----------|-----------|---------------------|
| `internal/sigverify` (Task 23) | inbound | Is the artifact signed by a trusted identity? |
| `internal/attestbundle` (Task 46) | **outbound** | The proxy SIGNS an attestation for each artifact it serves. |
| **`internal/buildprov` (Task 72)** | **inbound** | Does the upstream build provenance prove the artifact was built from the source its metadata claims? |

## What it verifies

Two inbound provenance sources are understood, both Sigstore bundles carrying a
SLSA provenance in-toto statement in a DSSE envelope signed by a Fulcio
certificate:

- **npm provenance** — the bundle npm attaches to a package version published
  with `--provenance`, served at `/-/npm/v1/attestations/<name>@<version>`. The
  signing certificate's SAN identity is the GitHub Actions workflow that ran
  `npm publish`.
- **GitHub artifact attestations** — the in-toto SLSA provenance served at
  `/repos/{owner}/{repo}/attestations/{digest}` (opt-in; needs network access to
  the GitHub API and a repository hint).
- **GitLab CI/CD provenance** — SLSA provenance published by a GitLab pipeline,
  fetched from `/api/v4/projects/{url-encoded-path}/attestations/{digest}` (opt-in;
  `enableGitlabSource`). The project path preserves nested subgroups and is the
  full namespace path derived from the artifact's source-repository hint.
- **Bitbucket Pipelines attestations** — SLSA provenance published by a Bitbucket
  pipeline, fetched from
  `/2.0/repositories/{workspace}/{repo}/attestations/{digest}` (opt-in;
  `enableBitbucketSource`).

The cryptographic core (DSSE/PAE, Fulcio certificate-chain trust, identity
policy, SLSA source extraction) is **reused from `internal/sigverify`** via
`sigverify.Verifier`; this gate owns the inbound bundle parsing, the cross-check,
the policy, and the surfaces.

### Forge provider abstraction

Every forge is a `buildprov.Source` (attestation discovery) plus an optional
`ForgeTrust` entry (its Fulcio/CA roots and allowed OIDC issuers). A discovered
attestation is verified against the trust material of the forge that produced it
(`Material.Forge`), so a GitLab attestation is trusted under GitLab's root and
`https://gitlab.com` issuer independently of GitHub's — one forge's trust never
launders another forge's attestation. Adding a new forge means adding a `Source`
and a `forges:` config entry; the verification, cross-check, findings, and
admission logic are untouched.

## Signals

Each verification produces four headline signals, surfaced into
`policyengine.Input.buildProv`, the SARIF findings layer, and per-ecosystem
metrics:

- **present** — an inbound provenance attestation was discovered.
- **verified** — a SLSA-provenance attestation verified cryptographically (its
  DSSE signature validated against its certificate) and bound this artifact's
  digest.
- **sourceVerified** — the verifying attestation additionally chained to a
  configured Fulcio root with an allowed identity, so the proven source is
  authenticated.
- **mismatch** — the source commit/repository the attestation **proves**
  disagrees with the source **claimed** by package metadata. This is the decisive
  finding (`buildprov/source-mismatch`, critical).

A present-but-unverifiable attestation is flagged
`buildprov/unverified-provenance` (high).

## Modes

`observe` (default) records findings and feeds the policy/risk engines and the
findings layer but never blocks a pull. `enforce` additionally quarantines an
artifact whose worst finding meets `failSeverity` (default high; a mismatch is
critical), composing with the break-glass approval workflow. The mode and the
provenance requirement can be overridden per tenant.

## Configuration

```yaml
buildProv:
  enabled: true            # on by default
  mode: observe            # observe | enforce
  action: quarantine       # warn | block | quarantine (enforce only)
  failSeverity: high
  warnSeverity: medium
  requireProvenance: false # treat a missing attestation as a finding
  requireTrustedSource: false
  failOnError: false       # fail-open on fetch/parse errors
  npmRegistryUrl: https://registry.npmjs.org
  enableGithubSource: false
  githubApiUrl: https://api.github.com
  githubToken: ""
  # GitLab CI/CD and Bitbucket Pipelines provenance sources (opt-in):
  enableGitlabSource: false
  gitlabApiUrl: https://gitlab.com
  gitlabHost: gitlab.com         # set apiUrl+host for a self-hosted instance
  gitlabToken: ""
  enableBitbucketSource: false
  bitbucketApiUrl: https://api.bitbucket.org
  bitbucketHost: bitbucket.org
  bitbucketToken: ""
  timeout: 15s
  cacheTtl: 0
  cacheSize: 1024
  # Air-gapped trust material (shared format with sigverify):
  trustBundlePath: ""
  trustBundleDigest: ""
  offline: false
  # Allowed keyless-signer policy (establishes sourceVerified):
  identities:
    - issuer: https://token.actions.githubusercontent.com
      subjectPattern: '^https://github\.com/acme/.*'
  # Per-forge trust roots / OIDC issuers (GitLab/Bitbucket/self-hosted). An
  # attestation from a forge is verified against its forge's trust material; a
  # forge without an entry falls back to the shared roots/identities above.
  forges:
    - name: gitlab
      trustRootsFile: /etc/pullthrough/gitlab-fulcio-root.pem
      identities:
        - issuer: https://gitlab.com
          subjectPattern: '^https://gitlab\.com/acme-group/.*'
    - name: bitbucket
      trustRootsFile: /etc/pullthrough/bitbucket-fulcio-root.pem
      identities:
        - issuer: https://api.bitbucket.org/2.0/workspaces/acme/pipelines-config/identity/oidc
          subjectPattern: '^https://bitbucket\.org/acme/.*'
  tenants:
    team-a:
      mode: enforce
```

Each `forges[]` entry accepts the same trust material as the signature gate:
`trustRootsFile` / `useSystemTrustRoots`, a portable `trustBundlePath` (+
`trustBundleDigest`) for air-gapped deployments, `rekorKeyFiles`, and
`identities`.

Without trust roots/identities the gate still verifies the DSSE signature against
the embedded Fulcio certificate (establishing `present`/`verified` and the proven
source for the mismatch cross-check) but cannot establish `sourceVerified`.

## Pull-path placement

The gate runs right after the signature gate (Task 23) and before the
reproducible-build gate (Task 68), both of which establish source
authenticity/integrity. It folds its signals into the per-request admission
accumulator the policy-as-code (Task 32), risk-scoring (Task 37), and SARIF
findings (Task 42) layers consume.

## Admin & observability

- `GET {admin}/api/buildprov` — effective configuration, cumulative per-outcome
  and per-ecosystem tallies, and the recent verification reports. Rendered under
  the **Build Provenance** admin tab.
- Prometheus: `pullthrough_buildprov_*` counters/gauges, plus the
  `pullthrough_buildprov_outcomes_total{ecosystem,outcome}` labeled vector.
- Notifications: `notify.EventBuildProvenance` on a warn/block/quarantine
  decision.

## Testing

- Golden tests build real-shape, cryptographically-valid npm, GitLab, and
  Bitbucket provenance Sigstore bundles in-process (`internal/buildprov/*_test.go`)
  plus committed golden fixtures (`testdata/{npm,gitlab,bitbucket}-provenance.json`).
  Per-forge tests cover valid, expired, and forged attestations and the per-forge
  trust isolation (one forge's root/issuer never trusts another's attestation).
- `FuzzParseAttestations` (`-tags fuzz`) hardens the inbound bundle parser
  against malicious registry responses.
