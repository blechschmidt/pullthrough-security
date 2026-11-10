// Package sigverify implements a pull-path admission gate that cryptographically
// verifies artifact signatures and attestations before content is cached or
// served (Task 23). It is the supply-chain authenticity counterpart to the
// vulnerability gate (internal/vulnscan) and the name guard (internal/nameguard),
// and exposes the same gate shape: Verify produces a Report, and Gate maps that
// Report onto an admission Decision (allow/warn/block/quarantine) using the
// configured severity thresholds and enforcement action.
//
// What it verifies:
//
//   - Docker/OCI images: cosign signatures and SLSA provenance attestations,
//     discovered via the cosign tag scheme (sha256-<hex>.sig / .att) and the OCI
//     Referrers API. Both keyless (Fulcio certificate chain + OIDC identity
//     policy, optionally with a Rekor transparency-log inclusion proof) and keyed
//     (operator-configured public keys) trust models are supported.
//   - npm / pip packages: Sigstore-based publish attestations (DSSE bundles)
//     where the registry exposes them, verified through the same trust material.
//
// The gate is deliberately decoupled from how signature material is fetched: it
// consumes a Source (see source.go) the caller wires per ecosystem. This keeps
// the cryptographic core free of registry/HTTP concerns and exhaustively
// unit-testable with fixture signatures. For air-gapped deployments the trust
// material (Fulcio roots, Rekor keys, public keys, identity policy) is loaded
// from a portable trust bundle (see trustbundle.go) consistent with the mirror
// subsystem's export/import model.
package sigverify

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"
)

// Artifact is the subject the gate verifies: a concrete, content-addressed
// artifact flowing through the proxy.
type Artifact struct {
	// Ecosystem is the normalized ecosystem (docker, oci, npm, pip).
	Ecosystem string
	// Backend is the upstream/backend name the request was routed to. A Source may
	// use it to query the same upstream that served the artifact (cosign
	// signatures live in the same registry as the image).
	Backend string
	// Name is the package/repository coordinate (e.g. the OCI repository or the
	// npm package name).
	Name string
	// Version is the package version, when known (unused for OCI digest pulls).
	Version string
	// Digest is the "<algo>:<hex>" content digest the signatures must bind. For an
	// OCI image this is the manifest digest; for a package it is the artifact
	// (tarball/wheel) digest.
	Digest string
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

// Severity orders findings so the worst one drives the gate decision. It mirrors
// the vulnerability and name-guard subsystems' vocabulary so operators configure
// every gate with the same words.
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

// ValidSeverity reports whether s is a recognized severity bucket (empty is
// valid and means the threshold is disabled). Used by config validation.
func ValidSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// Kind classifies a verification finding.
type Kind string

const (
	// KindMissingSignature: no signature was found for an artifact that requires one.
	KindMissingSignature Kind = "missing-signature"
	// KindInvalidSignature: a signature was present but did not verify cryptographically.
	KindInvalidSignature Kind = "invalid-signature"
	// KindUntrustedIdentity: a keyless signature verified but its certificate did
	// not chain to a trusted root or its identity is not in the allowed policy.
	KindUntrustedIdentity Kind = "untrusted-identity"
	// KindUntrustedKey: a keyed signature did not verify against any configured key.
	KindUntrustedKey Kind = "untrusted-key"
	// KindMissingRekorProof: a keyless signature lacked a verified transparency-log
	// inclusion proof while one was required.
	KindMissingRekorProof Kind = "missing-rekor-proof"
	// KindMissingAttestation: no verified SLSA provenance attestation was found
	// while one was required.
	KindMissingAttestation Kind = "missing-attestation"
	// KindVerifyError: signature material could not be fetched/parsed (infra error).
	KindVerifyError Kind = "verify-error"
	// KindQuantumVulnerable: the only trusted signature uses a classical
	// (quantum-vulnerable) algorithm while the PQC policy requires post-quantum
	// protection (Task 151).
	KindQuantumVulnerable Kind = "quantum-vulnerable"
	// KindPQCRejected: a cryptographically-valid post-quantum/hybrid signature was
	// refused by the PQC policy (classical-only) or because PQC support is disabled.
	KindPQCRejected Kind = "pqc-rejected"
)

// Finding is a single verification problem detected for an artifact.
type Finding struct {
	Kind     Kind     `json:"kind"`
	Severity Severity `json:"severity"`
	Reason   string   `json:"reason"`
	// Identity is the signer identity the finding relates to, when applicable.
	Identity string `json:"identity,omitempty"`
}

// SignatureResult records the outcome of verifying one discovered signature, for
// the admin/inspection surface.
type SignatureResult struct {
	Verified bool `json:"verified"`
	// CryptoValid reports the signature verified against its key/certificate,
	// independent of whether the signer is trusted (chain/identity/key policy).
	CryptoValid     bool `json:"cryptoValid,omitempty"`
	Keyless         bool `json:"keyless"`
	ChainTrusted    bool `json:"chainTrusted,omitempty"`
	IdentityTrusted bool `json:"identityTrusted,omitempty"`
	// RekorVerified reports a verified Signed Entry Timestamp; RekorInclusionVerified
	// reports a verified Merkle inclusion proof (Task 142).
	RekorVerified          bool   `json:"rekorVerified,omitempty"`
	RekorInclusionVerified bool   `json:"rekorInclusionVerified,omitempty"`
	Identity               string `json:"identity,omitempty"`
	Issuer                 string `json:"issuer,omitempty"`
	// Algorithm is the signature algorithm (e.g. "ECDSA-P256", "ML-DSA-65"), and
	// AlgorithmClass its quantum-resistance category (classical|pqc|hybrid).
	Algorithm      string         `json:"algorithm,omitempty"`
	AlgorithmClass AlgorithmClass `json:"algorithmClass,omitempty"`
	// PostQuantum reports the signature provides post-quantum protection.
	PostQuantum bool   `json:"postQuantum,omitempty"`
	Error       string `json:"error,omitempty"`
}

// AttestationResult records the outcome of verifying one DSSE attestation.
type AttestationResult struct {
	SignatureResult
	PredicateType string `json:"predicateType,omitempty"`
	// SLSAProvenance reports the attestation carried SLSA build provenance.
	SLSAProvenance bool   `json:"slsaProvenance,omitempty"`
	RepositoryURL  string `json:"repositoryUrl,omitempty"`
	CommitSHA      string `json:"commitSha,omitempty"`
	BuilderID      string `json:"builderId,omitempty"`
}

// Report is the full verification result for an artifact. It is cached by digest
// and surfaced through the admin API.
type Report struct {
	Artifact Artifact `json:"artifact"`
	// Source records where the signature material came from (e.g. "oci-cosign-tag",
	// "oci-referrers", "npm").
	Source string `json:"source,omitempty"`
	// Signatures and Attestations record every discovered item's verification.
	Signatures   []SignatureResult   `json:"signatures,omitempty"`
	Attestations []AttestationResult `json:"attestations,omitempty"`
	// VerifiedSignature reports at least one signature verified to a trusted signer.
	VerifiedSignature bool `json:"verifiedSignature"`
	// VerifiedAttestation reports at least one SLSA provenance attestation verified
	// to a trusted signer.
	VerifiedAttestation bool `json:"verifiedAttestation"`
	// Algorithms lists the distinct signature algorithms of the trusted
	// signatures/attestations (e.g. ["ECDSA-P256", "ML-DSA-65"]), for reporting
	// and the per-verification audit record (Task 151).
	Algorithms []string `json:"algorithms,omitempty"`
	// PostQuantum reports at least one trusted signature used a post-quantum or
	// hybrid algorithm.
	PostQuantum bool      `json:"postQuantum,omitempty"`
	Findings    []Finding `json:"findings,omitempty"`
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

// SimpleSignature is one discovered cosign image signature plus the material
// needed to establish its trust (a keyless certificate chain and/or a Rekor
// bundle). Cert is nil for a keyed signature.
type SimpleSignature struct {
	// Payload is the signed cosign simple-signing JSON document.
	Payload []byte
	// Signature is the raw signature bytes (ECDSA ASN.1 DER, RSA PKCS1v15, or Ed25519).
	Signature []byte
	// Cert is the Fulcio leaf certificate for a keyless signature, when present.
	Cert *x509.Certificate
	// Chain holds any intermediate certificates accompanying the leaf.
	Chain []*x509.Certificate
	// RekorBundle is the cosign transparency-log bundle, when present.
	RekorBundle *rekorBundle
}

// DSSEAttestation is one discovered DSSE attestation envelope plus its trust
// material. Cert is nil for a keyed attestation.
type DSSEAttestation struct {
	Envelope    *Envelope
	Cert        *x509.Certificate
	Chain       []*x509.Certificate
	RekorBundle *rekorBundle
}

// Material is the set of signatures and attestations a Source discovered for an
// artifact, along with a label for where they came from.
type Material struct {
	Source       string
	Signatures   []SimpleSignature
	Attestations []DSSEAttestation
}

// IsEmpty reports whether no signature material was discovered.
func (m *Material) IsEmpty() bool {
	return m == nil || (len(m.Signatures) == 0 && len(m.Attestations) == 0)
}

// parsePEMCertificates parses zero or more PEM CERTIFICATE blocks.
func parsePEMCertificates(pemData []byte) []*x509.Certificate {
	var out []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, cert)
		}
	}
	return out
}
