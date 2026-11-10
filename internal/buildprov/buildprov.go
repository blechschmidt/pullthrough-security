// Package buildprov implements an inbound build-provenance admission gate (Task
// 72). Where the signature gate (internal/sigverify) asks "is this artifact
// signed by a trusted identity?" and the outbound attestation subsystem
// (internal/attestbundle) SIGNS the artifacts the proxy serves, this gate
// CONSUMES the build-provenance attestations upstream registries publish and uses
// them to cryptographically bind a pulled package version to the exact source
// repository + commit SHA + CI workflow that built it.
//
// Two inbound provenance sources are understood:
//
//   - npm provenance: the Sigstore bundle npm attaches to a package version
//     published with `--provenance` (served at
//     /-/npm/v1/attestations/<name>@<version>). It carries a SLSA provenance
//     in-toto statement inside a DSSE envelope, signed by a Fulcio certificate
//     whose SAN identity is the GitHub Actions workflow that ran `npm publish`.
//   - GitHub artifact attestations: the in-toto SLSA provenance fetched from the
//     GitHub attestations API (/repos/{owner}/{repo}/attestations/{digest}),
//     likewise a Sigstore bundle.
//
// Having proven the source commit, the gate cross-checks it against the
// package-to-commit association the provenance subsystem (Task 8) reported for
// the same artifact — the commit/repository *claimed* by package metadata. A
// disagreement (metadata claims commit/repo X, but the signed attestation proves
// commit/repo Y) is a strong supply-chain signal: the headline finding of this
// gate.
//
// The cryptographic core is deliberately NOT re-implemented: the DSSE/PAE,
// Fulcio certificate-chain, identity-policy, and SLSA source-extraction
// primitives live in internal/sigverify and are reused via sigverify.Verifier.
// This package owns the inbound bundle parsing (the npm and GitHub response
// shapes), the cross-check against the claimed association, the observe/enforce
// policy, and the gate/metrics/findings/notify surfaces. For air-gapped
// deployments the trust material is loaded from the same portable
// sigverify.TrustBundle the signature gate uses.
package buildprov

import (
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// Artifact is the subject the gate verifies: a concrete, content-addressed
// package release flowing through the proxy, together with the provenance
// association package metadata claims for it.
type Artifact struct {
	// Ecosystem is the normalized ecosystem (npm, github, ...).
	Ecosystem string `json:"ecosystem,omitempty"`
	// Backend is the upstream/backend name the request routed to.
	Backend string `json:"backend,omitempty"`
	// Name is the package coordinate (e.g. the npm package name).
	Name string `json:"name,omitempty"`
	// Version is the package version.
	Version string `json:"version,omitempty"`
	// Digest is the "<algo>:<hex>" content digest the attestation subject must
	// bind. npm provenance binds the tarball's sha512; an OCI/GitHub attestation
	// binds the sha256 content digest.
	Digest string `json:"digest,omitempty"`
	// RepositoryURL is an advisory source-repository hint (e.g. the packument
	// `repository` field) a GitHub source uses to locate attestations. Never
	// trusted output.
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	// Claim is the package-to-commit association the provenance subsystem reported
	// for this artifact (Task 8): the commit/repository claimed by metadata. The
	// gate cross-checks the source the signed attestation PROVES against it.
	Claim Claim `json:"claim"`
}

// Claim is the (untrusted) package-to-commit association the provenance
// subsystem reported, against which the proven source is cross-checked.
type Claim struct {
	// CommitSHA / RepositoryURL are the claimed source revision and repository.
	CommitSHA     string `json:"commitSha,omitempty"`
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	// Confidence is the provenance subsystem's confidence (attested|claimed|
	// heuristic); recorded for transparency.
	Confidence string `json:"confidence,omitempty"`
	// Source records which resolver produced the claim, for auditability.
	Source string `json:"source,omitempty"`
}

// HasSource reports whether the claim carries any usable commit or repository to
// cross-check against.
func (c Claim) HasSource() bool {
	return strings.TrimSpace(c.CommitSHA) != "" || strings.TrimSpace(c.RepositoryURL) != ""
}

// String renders a human-readable coordinate for messages and logs.
func (a Artifact) String() string {
	switch {
	case a.Name != "" && a.Version != "":
		return a.Ecosystem + " " + a.Name + "@" + a.Version
	case a.Name != "":
		return a.Ecosystem + " " + a.Name
	case a.Digest != "":
		return a.Ecosystem + " " + a.Digest
	default:
		return a.Ecosystem
	}
}

// Coordinate renders "name@version" (falling back to name, then digest), for the
// break-glass scope and notifications.
func (a Artifact) Coordinate() string {
	switch {
	case a.Name != "" && a.Version != "":
		return a.Name + "@" + a.Version
	case a.Name != "":
		return a.Name
	default:
		return a.Digest
	}
}

// Severity orders findings so the worst one drives the gate decision. It mirrors
// the signature/vulnerability gates' vocabulary so operators configure every gate
// with the same words.
type Severity string

const (
	SeverityNone     Severity = "none"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is at least as severe as other.
func (s Severity) AtLeast(other Severity) bool { return s.rank() >= other.rank() }

// NormalizeSeverity coerces a configured severity string to a known value,
// defaulting unknown/empty input to none.
func NormalizeSeverity(s string) Severity {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// ValidSeverity reports whether s is a recognized severity bucket (empty is valid
// and means the threshold is disabled). Used by config validation.
func ValidSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// Kind classifies a build-provenance finding.
type Kind string

const (
	// KindMissingProvenance: no inbound build-provenance attestation was found for
	// an artifact for which provenance is required.
	KindMissingProvenance Kind = "missing-provenance"
	// KindUnverifiedProvenance: an attestation was present but did not verify (its
	// DSSE signature did not validate, or it did not bind this artifact's digest).
	KindUnverifiedProvenance Kind = "unverified-provenance"
	// KindUntrustedSource: a digest-bound attestation verified cryptographically,
	// but its signer is not trusted (no chain to a configured Fulcio root, or its
	// identity is not in the allowed-identity policy) and trusted provenance is
	// required.
	KindUntrustedSource Kind = "untrusted-source"
	// KindSourceMismatch: the source commit/repository PROVEN by the signed
	// attestation disagrees with the commit/repository the package metadata claims.
	KindSourceMismatch Kind = "source-mismatch"
	// KindVerifyError: provenance material could not be fetched/parsed (infra error).
	KindVerifyError Kind = "verify-error"
)

// Finding is a single build-provenance problem detected for an artifact.
type Finding struct {
	Kind     Kind     `json:"kind"`
	Severity Severity `json:"severity"`
	Reason   string   `json:"reason"`
	// Identity is the signer identity (CI workflow) the finding relates to, when
	// applicable.
	Identity string `json:"identity,omitempty"`
}

// AttestationView records the outcome of verifying one discovered attestation,
// for the admin/inspection surface.
type AttestationView struct {
	PredicateType   string `json:"predicateType,omitempty"`
	Verified        bool   `json:"verified"` // signature valid AND signer trusted
	CryptoValid     bool   `json:"cryptoValid"`
	ChainTrusted    bool   `json:"chainTrusted,omitempty"`
	IdentityTrusted bool   `json:"identityTrusted,omitempty"`
	SLSAProvenance  bool   `json:"slsaProvenance,omitempty"`
	RepositoryURL   string `json:"repositoryUrl,omitempty"`
	CommitSHA       string `json:"commitSha,omitempty"`
	BuilderID       string `json:"builderId,omitempty"`
	// Identity is the keyless signer identity (the CI workflow SAN URI); Issuer is
	// the OIDC issuer.
	Identity string `json:"identity,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Report is the full build-provenance verification result for an artifact. It is
// cached by digest and surfaced through the admin API.
type Report struct {
	Artifact Artifact `json:"artifact"`
	// Source records where the provenance material came from ("npm-provenance",
	// "github-attestations", "gitlab-attestations", "bitbucket-attestations").
	Source string `json:"source,omitempty"`
	// Forge records the source-control/CI provider the attestations came from
	// (github|gitlab|bitbucket), for the admin/dossier surface and per-forge trust.
	Forge string `json:"forge,omitempty"`
	// Attestations records every discovered attestation's verification outcome.
	Attestations []AttestationView `json:"attestations,omitempty"`

	// The four headline signals (mirrored into policyengine.Input):
	//
	// Present  — at least one inbound provenance attestation was discovered.
	// Verified — at least one SLSA-provenance attestation cryptographically verified
	//            (DSSE signature valid against its certificate) AND bound this
	//            artifact's digest.
	// SourceVerified — a verified attestation additionally chained to a trusted root
	//                  with an allowed identity, so the bound source is authenticated.
	// Mismatch — the proven source commit/repository disagrees with the claimed one.
	Present        bool `json:"present"`
	Verified       bool `json:"verified"`
	SourceVerified bool `json:"sourceVerified"`
	Mismatch       bool `json:"mismatch"`

	// Proven source extracted from the strongest attestation (trusted preferred).
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	CommitSHA     string `json:"commitSha,omitempty"`
	BuilderID     string `json:"builderId,omitempty"`
	// WorkflowRef is the signer identity (CI workflow SAN URI) of the attestation
	// that produced the proven source.
	WorkflowRef string `json:"workflowRef,omitempty"`
	Issuer      string `json:"issuer,omitempty"`

	Findings []Finding `json:"findings,omitempty"`
	// Error is set when material could not be fetched/parsed (infra failure).
	Error      string    `json:"error,omitempty"`
	VerifiedAt time.Time `json:"verifiedAt"`
}

// Worst returns the highest-severity finding, or nil when the report is clean.
func (r *Report) Worst() *Finding {
	var worst *Finding
	for i := range r.Findings {
		f := &r.Findings[i]
		if worst == nil || f.Severity.rank() > worst.Severity.rank() {
			worst = f
		}
	}
	return worst
}

// MaxSeverity returns the label of the worst finding, or "" when clean.
func (r *Report) MaxSeverity() string {
	if w := r.Worst(); w != nil {
		return string(w.Severity)
	}
	return ""
}

// Material is the set of inbound attestations a Source discovered for an
// artifact, with a label for where they came from. It reuses the signature gate's
// DSSEAttestation so the shared verifier can be applied directly.
type Material struct {
	Source string
	// Forge identifies the source-control/CI provider the attestations came from
	// (ForgeGitHub/GitLab/Bitbucket, or "" for the shared/default trust material).
	// The gate verifies the attestations against the trust material of this forge.
	Forge        string
	Attestations []sigverify.DSSEAttestation
}

// IsEmpty reports whether no provenance material was discovered.
func (m *Material) IsEmpty() bool {
	return m == nil || len(m.Attestations) == 0
}
