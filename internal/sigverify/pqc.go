package sigverify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// This file implements post-quantum / hybrid signature-algorithm support for the
// inbound signature-verification gate (Task 151). Classical signatures (RSA,
// ECDSA, Ed25519) are verified by the Go standard library; post-quantum
// (ML-DSA / FIPS 204, SLH-DSA / FIPS 205) and hybrid classical+PQC composite
// signatures are verified through the cloudflare/circl provider.
//
// The feature is OFF by default (sigverify.pqc.enabled) because the PQC provider
// is not a FIPS 140-3 validated cryptographic module; see [PQCProviderFIPSValidated]
// and the FIPS-mode preflight interaction documented on [PQCPolicy].

// PQCProviderName identifies the library providing the post-quantum and hybrid
// signature primitives, for reporting and audit.
const PQCProviderName = "cloudflare/circl"

// PQCProviderFIPSValidated reports whether the post-quantum signature provider is
// a FIPS 140-3 validated cryptographic module. The cloudflare/circl
// implementations of ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) implement the
// standardized algorithms but the module itself has not completed FIPS 140-3
// validation. When FIPS mode is enabled this is consulted at startup
// (see the sigverify preflight) to fail fast rather than silently permit a
// non-validated provider, so an operator can never believe PQC verification is
// running under a validated module when it is not.
const PQCProviderFIPSValidated = false

// AlgorithmClass categorizes a signature algorithm by its resistance to a
// cryptographically-relevant quantum computer (CRQC).
type AlgorithmClass string

const (
	// ClassClassical covers RSA, ECDSA, and Ed25519 — algorithms a CRQC can break
	// (Shor's algorithm). They remain the status quo for today's signatures.
	ClassClassical AlgorithmClass = "classical"
	// ClassPQC covers the NIST post-quantum signature standards ML-DSA (FIPS 204)
	// and SLH-DSA (FIPS 205), and pre-standard lattice schemes.
	ClassPQC AlgorithmClass = "pqc"
	// ClassHybrid covers composite signatures that bind a classical and a
	// post-quantum signature so the artifact is protected as long as *either*
	// primitive is unbroken (defense-in-depth during the PQC migration).
	ClassHybrid AlgorithmClass = "hybrid"
)

// Algorithm describes a signature algorithm the gate can verify. It is produced
// by classifying a public key and threads through the verification outcome so
// the per-verification algorithm is reported in metrics and the audit log.
type Algorithm struct {
	// Name is the canonical algorithm name (e.g. "ECDSA-P256", "Ed25519",
	// "ML-DSA-65", "SLH-DSA-SHA2-128s", "Ed25519-Dilithium2").
	Name string
	// Class is the quantum-resistance category.
	Class AlgorithmClass
	// Standardized reports the algorithm is specified in a NIST FIPS publication
	// (FIPS 186-5 for the classical signatures, FIPS 204 for ML-DSA, FIPS 205 for
	// SLH-DSA). It is false for pre-standard lattice schemes (round-3 Dilithium)
	// and for hybrids whose PQC component is pre-standard.
	Standardized bool

	// scheme is the circl PQC/hybrid scheme used to verify, nil for classical
	// algorithms (which are verified by the Go standard library).
	scheme sign.Scheme
}

// PostQuantum reports whether the algorithm provides post-quantum protection
// (either a pure PQC signature or a hybrid that embeds one).
func (a Algorithm) PostQuantum() bool { return a.Class == ClassPQC || a.Class == ClassHybrid }

// IsZero reports whether the algorithm is the unclassified zero value.
func (a Algorithm) IsZero() bool { return a.Name == "" && a.Class == "" }

// classifyPublicKey maps a parsed public key onto its signature [Algorithm].
// Classical keys are the Go standard-library types; post-quantum and hybrid keys
// are the cloudflare/circl sign.PublicKey. ok is false for an unrecognized key
// type.
func classifyPublicKey(pub crypto.PublicKey) (alg Algorithm, ok bool) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return Algorithm{Name: "ECDSA-" + curveName(k.Curve), Class: ClassClassical, Standardized: true}, true
	case *rsa.PublicKey:
		return Algorithm{Name: "RSA", Class: ClassClassical, Standardized: true}, true
	case ed25519.PublicKey:
		return Algorithm{Name: "Ed25519", Class: ClassClassical, Standardized: true}, true
	case sign.PublicKey:
		return classifyScheme(k.Scheme()), true
	default:
		return Algorithm{}, false
	}
}

// curveName returns a short name for an ECDSA curve, for algorithm reporting.
func curveName(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return "P256"
	case elliptic.P384():
		return "P384"
	case elliptic.P521():
		return "P521"
	default:
		if c != nil && c.Params() != nil {
			return c.Params().Name
		}
		return "unknown"
	}
}

// classifyScheme maps a circl signature scheme onto an [Algorithm], deriving the
// quantum-resistance class from the scheme name. Hybrid composite schemes
// (EdXXX-DilithiumN) embed a classical and a PQC primitive.
func classifyScheme(s sign.Scheme) Algorithm {
	name := s.Name()
	up := strings.ToUpper(name)
	switch {
	case strings.Contains(up, "DILITHIUM") && (strings.HasPrefix(up, "ED25519") || strings.HasPrefix(up, "ED448")):
		// Composite classical (Ed25519/Ed448) + lattice (Dilithium) signature. The
		// embedded Dilithium is the pre-standard round-3 variant, so the composite
		// is not itself a FIPS-standardized construction.
		return Algorithm{Name: name, Class: ClassHybrid, Standardized: false, scheme: s}
	case strings.HasPrefix(up, "ML-DSA"):
		return Algorithm{Name: name, Class: ClassPQC, Standardized: true, scheme: s}
	case strings.HasPrefix(up, "SLH-DSA"):
		return Algorithm{Name: name, Class: ClassPQC, Standardized: true, scheme: s}
	default:
		// Any other circl signature scheme (e.g. round-3 Dilithium) is post-quantum
		// but not a final NIST standard.
		return Algorithm{Name: name, Class: ClassPQC, Standardized: false, scheme: s}
	}
}

// PQCPolicy selects how post-quantum and hybrid algorithms participate in the
// gate's trust decision. It is meaningful only when PQC support is enabled
// (sigverify.pqc.enabled); when PQC is disabled the gate behaves as
// classical-only and a presented PQC/hybrid signature is reported but never
// establishes trust.
type PQCPolicy string

const (
	// PQCPolicyClassicalOnly accepts only classical signatures: a presented
	// post-quantum or hybrid signature is cryptographically checked (for
	// reporting) but never establishes trust. Use it to stage PQC key
	// distribution before sanctioning PQC trust.
	PQCPolicyClassicalOnly PQCPolicy = "classical-only"
	// PQCPolicyAllowHybrid accepts classical, hybrid, and pure post-quantum
	// signatures. It is the default when PQC support is enabled: it lets artifacts
	// signed with any of the three classes be admitted during the migration.
	PQCPolicyAllowHybrid PQCPolicy = "allow-hybrid"
	// PQCPolicyRequirePQC demands post-quantum protection: a classical-only trusted
	// signature does not satisfy the gate, which flags the artifact as
	// quantum-vulnerable unless a trusted pure-PQC or hybrid signature is present.
	PQCPolicyRequirePQC PQCPolicy = "require-pqc"
)

// NormalizePQCPolicy coerces a configured policy string to a known value,
// defaulting empty/unknown input to allow-hybrid (the safe default once PQC is
// enabled). It is tolerant of underscores and surrounding whitespace.
func NormalizePQCPolicy(s string) PQCPolicy {
	switch PQCPolicy(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")) {
	case PQCPolicyClassicalOnly:
		return PQCPolicyClassicalOnly
	case PQCPolicyRequirePQC:
		return PQCPolicyRequirePQC
	default:
		return PQCPolicyAllowHybrid
	}
}

// ValidPQCPolicy reports whether s names a recognized PQC policy (empty is valid
// and selects the default). Used by config validation.
func ValidPQCPolicy(s string) bool {
	switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-") {
	case "", string(PQCPolicyClassicalOnly), string(PQCPolicyAllowHybrid), string(PQCPolicyRequirePQC):
		return true
	default:
		return false
	}
}

// pqcPEMType is the PEM block type for a post-quantum / hybrid public key. The
// scheme is carried in the block's "Scheme" header and the block bytes are the
// scheme's binary public-key encoding, e.g.:
//
//	-----BEGIN PQC PUBLIC KEY-----
//	Scheme: ML-DSA-65
//	<base64 raw public key>
//	-----END PQC PUBLIC KEY-----
const pqcPEMType = "PQC PUBLIC KEY"

// parsePQCPublicKey decodes a post-quantum / hybrid public key from a PEM block
// of type [pqcPEMType]. The scheme is read from the "Scheme" header and resolved
// against the circl scheme registry (ML-DSA, SLH-DSA, and hybrid Ed/Dilithium).
func parsePQCPublicKey(block *pem.Block) (crypto.PublicKey, error) {
	schemeName := strings.TrimSpace(block.Headers["Scheme"])
	if schemeName == "" {
		return nil, fmt.Errorf("PQC public-key PEM block is missing its \"Scheme\" header")
	}
	scheme := schemes.ByName(schemeName)
	if scheme == nil {
		return nil, fmt.Errorf("unknown post-quantum signature scheme %q (supported: %s)", schemeName, strings.Join(SupportedPQCSchemes(), ", "))
	}
	pub, err := scheme.UnmarshalBinaryPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing %s public key: %w", schemeName, err)
	}
	return pub, nil
}

// MarshalPQCPublicKeyPEM encodes a post-quantum / hybrid public key as a PEM
// block of type [pqcPEMType], carrying the scheme name in the "Scheme" header.
// It is the inverse of the parser used by the trust-material loader and is used
// by tooling and tests to produce configurable PQC key material.
func MarshalPQCPublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	spk, ok := pub.(sign.PublicKey)
	if !ok {
		return nil, fmt.Errorf("sigverify: %T is not a post-quantum/hybrid public key", pub)
	}
	raw, err := spk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("sigverify: marshaling PQC public key: %w", err)
	}
	block := &pem.Block{
		Type:    pqcPEMType,
		Headers: map[string]string{"Scheme": spk.Scheme().Name()},
		Bytes:   raw,
	}
	return pem.EncodeToMemory(block), nil
}

// SupportedPQCSchemes lists the post-quantum and hybrid scheme names the gate can
// verify, sorted, for diagnostics and documentation.
func SupportedPQCSchemes() []string {
	var out []string
	for _, s := range schemes.All() {
		alg := classifyScheme(s)
		if alg.PostQuantum() {
			out = append(out, s.Name())
		}
	}
	sort.Strings(out)
	return out
}
