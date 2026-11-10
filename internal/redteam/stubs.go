package redteam

import (
	"context"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/buildprov"
	"github.com/blechschmidt/pullthrough-security/internal/maturity"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// stubVulnScanner returns a fixed set of vulnerabilities for any SBOM, so the
// vulnerability gate sees a deterministic critical-CVE finding regardless of the
// (synthetic) artifact's real contents.
type stubVulnScanner struct{ vulns []vulnscan.Vulnerability }

func (s stubVulnScanner) Name() string { return "redteam-stub" }

func (s stubVulnScanner) Scan(context.Context, *vulnscan.SBOM) ([]vulnscan.Vulnerability, error) {
	return s.vulns, nil
}

// noSignatureSource is a sigverify.Source that reports no signatures and no
// attestations for every artifact — the "unsigned upstream" attack. Under
// RequireSignature it drives the signature gate to block.
type noSignatureSource struct{}

func (noSignatureSource) Fetch(context.Context, sigverify.Artifact) (*sigverify.Material, error) {
	return &sigverify.Material{}, nil
}

// noProvenanceSource is a buildprov.Source that reports no published build
// provenance — the "missing/forged attestation" attack. Under RequireProvenance
// in enforce mode it drives the build-provenance gate to block.
type noProvenanceSource struct{}

func (noProvenanceSource) Fetch(context.Context, buildprov.Artifact) (*buildprov.Material, error) {
	return nil, nil
}

// fixedProvenanceResolver associates every artifact with a fixed source commit,
// so the reproducible-build gate has an attested source to rebuild from rather
// than short-circuiting to the "unattested" verdict.
type fixedProvenanceResolver struct {
	commit string
	repo   string
}

func (r fixedProvenanceResolver) Name() string { return "redteam-stub" }

func (r fixedProvenanceResolver) Resolve(_ context.Context, art provenance.Artifact) (*provenance.Link, error) {
	return &provenance.Link{
		Artifact:      art,
		RepositoryURL: r.repo,
		CommitSHA:     r.commit,
		Confidence:    provenance.ConfidenceAttested,
		ResolverName:  "redteam-stub",
		ResolvedAt:    time.Unix(0, 0).UTC(),
	}, nil
}

// mismatchBuilder is a rebuildverify.Builder that always "rebuilds" to a fixed
// digest and reports a different normalized upstream digest, producing a
// confirmed reproducible-build MISMATCH — the "tampered binary that does not
// derive from its attested source" attack. It self-reports the upstream digest
// (rather than relying on the coordinate's) so the comparison is over two
// parseable, deterministic digests independent of how the artifact was cached.
type mismatchBuilder struct {
	ecos           []string
	digest         string
	upstreamDigest string
}

func (b mismatchBuilder) Name() string { return "redteam-mismatch" }

func (b mismatchBuilder) Supports(ecosystem string) bool {
	for _, e := range b.ecos {
		if e == ecosystem {
			return true
		}
	}
	return false
}

func (b mismatchBuilder) Build(context.Context, rebuildverify.BuildContext) (rebuildverify.BuildOutput, error) {
	return rebuildverify.BuildOutput{Digest: b.digest, UpstreamDigest: b.upstreamDigest}, nil
}

// recentResolver dates every coordinate as published just now, so the
// release-maturity gate (with a long cooldown) always sees the version as
// freshly-published and quarantines it — the "publish-and-yank fast-moving
// attack" the cooldown blunts.
type recentResolver struct{ ago time.Duration }

func (r recentResolver) PublishedAt(context.Context, maturity.Coordinate) (time.Time, bool, error) {
	return time.Now().Add(-r.ago), true, nil
}
