// Package pypiattest implements an inbound PyPI PEP 740 digital-attestation
// verification gate (Task 146). It complements the npm/GitHub build-provenance
// gate (internal/buildprov, Task 72) and the Sigstore signature gate
// (internal/sigverify, Task 23) with the verification model PyPI publishes:
// PEP 740 "digital attestations".
//
// When a project is published to PyPI through a Trusted Publisher (a GitHub
// Actions / GitLab CI workflow authenticated by OIDC, no long-lived API token),
// PyPI records a PEP 740 provenance object for each distribution. The object is
// served from the Integrity API and referenced from the JSON Simple index's
// per-file "provenance" field. It carries one or more Sigstore attestations:
// a short-lived Fulcio signing certificate whose Subject Alternative Name is the
// publishing CI workflow, a DSSE-signed in-toto statement whose subject binds
// the distribution's sha256 digest, and (optionally) a Rekor transparency-log
// inclusion proof.
//
// This gate fetches that object for a served wheel/sdist, cryptographically
// verifies every enclosed attestation against the Fulcio/Rekor trust root
// (reusing internal/sigverify for the DSSE/PAE/Fulcio/identity core and
// internal/rekor for transparency-log verification), and — decisively — binds
// the attested sha256 digest to the artifact the proxy actually serves. An
// attestation that verifies but attests a *different* digest means the served
// file is not the one PyPI's publisher attested: a strong tampering signal.
//
// The cryptographic primitives are deliberately NOT re-implemented. The genuinely
// PyPI-specific work lives here: the Integrity-API/JSON-index source (source.go),
// the PEP 740 wire-format parser that reconstructs a DSSE envelope from the
// {statement, signature} form PyPI uses (bundle.go), the Trusted-Publisher
// identity policy, the sha256 digest binding, and the annotate|downgrade|block
// admission policy with its metrics/findings/dossier surfaces.
package pypiattest

import (
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// Artifact is the subject the gate verifies: a concrete, content-addressed PyPI
// distribution flowing through the proxy.
type Artifact struct {
	// Ecosystem is the normalized ecosystem (pip|pypi).
	Ecosystem string `json:"ecosystem,omitempty"`
	// Backend is the upstream/backend name the request routed to.
	Backend string `json:"backend,omitempty"`
	// Name is the PEP 503-normalized project name.
	Name string `json:"name,omitempty"`
	// Version is the release version.
	Version string `json:"version,omitempty"`
	// Digest is the "sha256:<hex>" content digest of the served distribution the
	// attestation subject must bind.
	Digest string `json:"digest,omitempty"`
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
// the signature/build-provenance gates' vocabulary so operators configure every
// gate with the same words.
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

// Kind classifies a PyPI attestation finding.
type Kind string

const (
	// KindMissingAttestation: no PEP 740 attestation was found for a distribution
	// for which an attestation is required.
	KindMissingAttestation Kind = "missing-attestation"
	// KindUnverifiedAttestation: an attestation was present but did not verify (its
	// DSSE signature did not validate, or no verifying attestation bound this
	// distribution's digest).
	KindUnverifiedAttestation Kind = "unverified-attestation"
	// KindDigestMismatch: a cryptographically-valid attestation was present, but it
	// attests a DIFFERENT distribution digest than the one served — the served file
	// is not the file the publisher attested.
	KindDigestMismatch Kind = "digest-mismatch"
	// KindUntrustedPublisher: a digest-bound attestation verified cryptographically
	// but its Trusted Publisher is not trusted (the certificate does not chain to a
	// configured Fulcio root, or its identity is not in the allowed-publisher
	// policy) and a trusted publisher is required.
	KindUntrustedPublisher Kind = "untrusted-publisher"
	// KindMissingTransparency: a verified attestation lacked a verifiable Rekor
	// transparency-log inclusion proof while one was required.
	KindMissingTransparency Kind = "missing-transparency"
	// KindVerifyError: attestation material could not be fetched/parsed (infra error).
	KindVerifyError Kind = "verify-error"
)

// Finding is a single PyPI-attestation problem detected for a distribution.
type Finding struct {
	Kind     Kind     `json:"kind"`
	Severity Severity `json:"severity"`
	Reason   string   `json:"reason"`
	// Publisher is the Trusted Publisher identity the finding relates to, when
	// applicable (the CI workflow SAN URI).
	Publisher string `json:"publisher,omitempty"`
}

// Publisher is the (PEP 740) Trusted Publisher an attestation bundle names. The
// repository/workflow fields come from the untrusted provenance wrapper and are
// advisory; the Identity/Issuer are read from the signing certificate and are the
// authenticated publisher identity.
type Publisher struct {
	// Kind is the publisher kind the provenance declares (e.g. "GitHub", "GitLab").
	Kind string `json:"kind,omitempty"`
	// Repository/Workflow/Environment are advisory wrapper fields.
	Repository  string `json:"repository,omitempty"`
	Workflow    string `json:"workflow,omitempty"`
	Environment string `json:"environment,omitempty"`
	// Identity is the authenticated signer identity (the certificate SAN URI);
	// Issuer is the OIDC issuer. These are trustworthy when the certificate chained
	// to a configured root.
	Identity string `json:"identity,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
}

// AttestationView records the outcome of verifying one discovered attestation,
// for the admin/inspection surface.
type AttestationView struct {
	PredicateType   string `json:"predicateType,omitempty"`
	CryptoValid     bool   `json:"cryptoValid"`
	DigestBound     bool   `json:"digestBound"`
	ChainTrusted    bool   `json:"chainTrusted,omitempty"`
	IdentityTrusted bool   `json:"identityTrusted,omitempty"`
	// Verified reports the attestation cryptographically verified AND bound this
	// artifact's digest AND its signer is trusted.
	Verified bool `json:"verified"`
	// SLSAProvenance reports the attestation additionally carried SLSA build
	// provenance (a source repository/commit); PEP 740 publish attestations do not.
	SLSAProvenance bool `json:"slsaProvenance,omitempty"`
	// TransparencyVerified reports a Rekor inclusion proof and/or SET verified.
	TransparencyVerified bool   `json:"transparencyVerified,omitempty"`
	RepositoryURL        string `json:"repositoryUrl,omitempty"`
	CommitSHA            string `json:"commitSha,omitempty"`
	Identity             string `json:"identity,omitempty"`
	Issuer               string `json:"issuer,omitempty"`
	Error                string `json:"error,omitempty"`
}

// Report is the full PyPI-attestation verification result for a distribution. It
// is cached by digest and surfaced through the admin/dossier surface.
type Report struct {
	Artifact Artifact `json:"artifact"`
	// Source records where the material came from ("pypi-attestations").
	Source string `json:"source,omitempty"`
	// Attestations records every discovered attestation's verification outcome.
	Attestations []AttestationView `json:"attestations,omitempty"`

	// The headline signals (mirrored into policyengine.PyPIAttestInput):
	//
	// Present          — at least one PEP 740 attestation was discovered.
	// Verified         — at least one attestation cryptographically verified AND
	//                    bound this artifact's digest.
	// PublisherTrusted — a verified attestation additionally chained to a trusted
	//                    Fulcio root with an allowed publisher identity.
	// DigestMismatch   — attestations were present and verified, but NONE bound this
	//                    artifact's digest and at least one bound a different one.
	Present          bool `json:"present"`
	Verified         bool `json:"verified"`
	PublisherTrusted bool `json:"publisherTrusted"`
	DigestMismatch   bool `json:"digestMismatch"`
	// TransparencyVerified reports at least one verified attestation carried a
	// verifiable Rekor inclusion proof / SET.
	TransparencyVerified bool `json:"transparencyVerified"`

	// Publisher summarizes the Trusted Publisher proven by the strongest
	// attestation (a trusted one preferred).
	Publisher Publisher `json:"publisher,omitempty"`
	// RepositoryURL/CommitSHA are the source extracted when an attestation carried
	// SLSA provenance (optional; publish attestations do not).
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	CommitSHA     string `json:"commitSha,omitempty"`

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

// WorkflowRef returns the authenticated publisher identity, for the dossier and
// notification surfaces.
func (r *Report) WorkflowRef() string { return r.Publisher.Identity }

// Material is the set of PEP 740 attestations a Source discovered for a
// distribution, parsed into the signature gate's DSSEAttestation plus the
// per-attestation publisher wrapper and transparency entries.
type Material struct {
	Source       string
	Attestations []ParsedAttestation
}

// ParsedAttestation is one PEP 740 attestation decoded into the shared verifier's
// DSSE input plus its advisory publisher wrapper and transparency-log entries.
type ParsedAttestation struct {
	DSSE      sigverify.DSSEAttestation
	Publisher Publisher
	// LogEntries are the Rekor transparency-log entries the attestation carried
	// (PEP 740 verification_material.transparency_entries), mapped onto the shared
	// rekor.LogEntry shape for verification by internal/rekor.
	LogEntries []*rekor.LogEntry
}

// IsEmpty reports whether no attestation material was discovered.
func (m *Material) IsEmpty() bool {
	return m == nil || len(m.Attestations) == 0
}
