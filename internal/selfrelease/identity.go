// Package selfrelease verifies the running pullthrough-security binary against
// its own signed release artifacts (Task 135).
//
// It closes the "trust the tool that enforces trust" gap: the proxy admits or
// blocks third-party supply-chain artifacts based on signatures, provenance, and
// SBOMs, so the proxy binary must itself be releasable with — and verifiable
// against — the same class of evidence. This package is the verification half of
// that loop. The production half (a reproducible build, an SLSA provenance
// attestation, a CycloneDX SBOM, a cosign keyless signature over the checksums
// file, and a published checksums manifest) is produced by `make release*` and
// the release CI workflow; see docs/self-release.md.
//
// The package is deliberately self-contained and dependency-free (standard
// library only). It performs its structural and cryptographic checks in-process
// so `ptctl verify-self` works in an air-gapped deployment with no network and
// no external tooling. When the `cosign` CLI is available it is additionally
// invoked for full Fulcio-root + Rekor transparency-log verification, which the
// offline path cannot perform.
//
// The expected signer identity is embedded at compile time (Identity, below) so
// a verifier does not depend on any external, mutable trust configuration: the
// anchor of trust travels inside the binary being verified.
package selfrelease

import "regexp"

// The expected release-signer identity. These values are the trust anchor for
// self-verification: they describe which keyless (Fulcio/OIDC) identity and
// which SLSA builder are permitted to have produced a legitimate release of this
// binary.
//
// They are compile-time defaults — hardcoded so an operator verifying a binary
// does not depend on any external, tamper-able configuration. A release build
// MAY override them via -ldflags "-X ..." to pin the exact tag ref at build
// time (see the `release` Makefile target), but the defaults already constrain
// verification to this repository's release workflow.
var (
	// CertificateIdentityPattern is an anchored regular expression the signing
	// certificate's SAN identity (the GitHub Actions workflow identity URI) must
	// match. The default pins it to this repository's release workflow on any
	// version tag.
	CertificateIdentityPattern = `^https://github\.com/blechschmidt/pullthrough-security/\.github/workflows/release\.yml@refs/tags/v.*$`

	// CertificateOIDCIssuer is the exact OIDC issuer embedded in the signing
	// certificate. For GitHub Actions keyless signing this is the Actions OIDC
	// provider.
	CertificateOIDCIssuer = "https://token.actions.githubusercontent.com"

	// BuilderIDPattern is an anchored regular expression the SLSA provenance
	// builder id must match. It accepts the two known-good builders a release of
	// this project uses: GitHub's own build-provenance attestation (which records
	// this repository's release workflow) and the canonical SLSA generic
	// generator reusable workflow. In SLSA terms the builder is the trusted build
	// platform, so pinning it to these two identities is the correct anchor.
	BuilderIDPattern = `^https://github\.com/(blechschmidt/pullthrough-security/\.github/workflows/release\.yml|slsa-framework/slsa-github-generator/\.github/workflows/generator_generic_slsa3\.yml)@refs/tags/v.*$`

	// SourceRepository is the expected source repository, recorded for reporting
	// and matched leniently against provenance source material.
	SourceRepository = "github.com/blechschmidt/pullthrough-security"
)

// Identity is the compiled, validated expected-signer identity used throughout
// verification.
type Identity struct {
	CertIdentity *regexp.Regexp
	OIDCIssuer   string
	BuilderID    *regexp.Regexp
	SourceRepo   string
	IdentityRaw  string
	BuilderIDRaw string
}

// EmbeddedIdentity compiles the compile-time identity constants into an
// Identity. It panics only on a programmer error (a malformed constant baked in
// at build time), which a unit test guards against.
func EmbeddedIdentity() Identity {
	return Identity{
		CertIdentity: regexp.MustCompile(CertificateIdentityPattern),
		OIDCIssuer:   CertificateOIDCIssuer,
		BuilderID:    regexp.MustCompile(BuilderIDPattern),
		SourceRepo:   SourceRepository,
		IdentityRaw:  CertificateIdentityPattern,
		BuilderIDRaw: BuilderIDPattern,
	}
}
