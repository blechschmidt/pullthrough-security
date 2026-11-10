// Package provenance defines the contract for associating package artifacts
// with the source revisions that produced them. Associations may be derived
// from SLSA / in-toto build provenance attestations, GitHub build provenance,
// signed manifests, or heuristic matching (see Task 8).
package provenance

import (
	"context"
	"errors"
	"time"
)

// ErrNoProvenance indicates that no provenance information could be located for
// the requested artifact.
var ErrNoProvenance = errors.New("provenance: no association found")

// Confidence expresses how strongly an artifact is believed to be associated
// with a source revision.
type Confidence string

const (
	// ConfidenceAttested means the link is backed by a verified, signed
	// attestation (e.g. SLSA provenance with a valid signature).
	ConfidenceAttested Confidence = "attested"
	// ConfidenceClaimed means the link is asserted but not cryptographically
	// verified (e.g. a repository URL in package metadata).
	ConfidenceClaimed Confidence = "claimed"
	// ConfidenceHeuristic means the link was inferred (e.g. by matching tags or
	// file hashes).
	ConfidenceHeuristic Confidence = "heuristic"
)

// Artifact identifies the package artifact whose provenance is sought.
type Artifact struct {
	// Ecosystem is the package manager, e.g. "npm", "pypi", "oci".
	Ecosystem string
	// Name and Version are the logical coordinate of the artifact.
	Name    string
	Version string
	// Digest is the content digest of the artifact (e.g. "sha256:..."). When set
	// it is the strongest identity and attestation resolvers MUST verify that the
	// attestation's subject binds this exact digest before trusting its claim.
	Digest string
	// RepositoryURL is an optional source-repository hint (e.g. discovered from
	// ecosystem metadata) that attestation resolvers may use to locate
	// attestations — for example which GitHub repository to query. It is advisory
	// input, never trusted output.
	RepositoryURL string
}

// Link is a resolved association between an artifact and a source revision.
type Link struct {
	Artifact Artifact
	// RepositoryURL is the canonical source repository.
	RepositoryURL string
	// CommitSHA is the revision that produced the artifact.
	CommitSHA string
	// BuilderID identifies the build system that produced the artifact, when
	// known (e.g. "https://github.com/actions/runner").
	BuilderID string
	// Confidence describes the strength of the association.
	Confidence Confidence
	// ResolverName records which Resolver produced the link (e.g.
	// "github-attestation", "oci-cosign", "npm-metadata"), for auditability.
	ResolverName string
	// PredicateType is the in-toto predicate type the link was derived from
	// (e.g. "https://slsa.dev/provenance/v1"), when attested.
	PredicateType string
	// SignerIdentity is the keyless signing identity (certificate SAN URI) that
	// signed the attestation, when attested (e.g. the GitHub Actions workflow
	// ref). Empty for unsigned/metadata-derived links.
	SignerIdentity string
	// SignatureVerified reports that the attestation's DSSE signature verified
	// against its signing certificate.
	SignatureVerified bool
	// ChainTrusted reports that the signing certificate chained to a configured
	// trust root. Attested confidence requires both SignatureVerified and
	// ChainTrusted.
	ChainTrusted bool
	// ResolvedAt is when the association was established.
	ResolvedAt time.Time
	// Attestation holds the raw attestation bytes (e.g. a Sigstore bundle / DSSE
	// envelope) when the link is attested. It is nil otherwise.
	Attestation []byte
}

// Resolver associates artifacts with their source revisions. Implementations
// must be safe for concurrent use and honor context cancellation.
type Resolver interface {
	// Name identifies the resolver (e.g. "github-attestation", "slsa").
	Name() string
	// Resolve returns the provenance Link for an artifact, or ErrNoProvenance
	// when none can be established.
	Resolve(ctx context.Context, artifact Artifact) (*Link, error)
}
