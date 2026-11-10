package proxy

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// ingestProvGraph folds everything this request learned about the served
// artifact into the supply-chain provenance graph (Task 33): its source commit,
// SBOM dependencies, CVE findings, and signature status. It reads the per-request
// admission-signal accumulator the gates above populated, so it adds no extra
// scanning work. Ingestion is best-effort and must never affect the response —
// it runs only after the artifact has been admitted.
//
// Only concrete, versioned artifacts are ingested; mutable index documents carry
// no coordinate and are skipped (consistent with the admission gates).
func (g *Gateway) ingestProvGraph(r *http.Request, ecosystem string, resolved *backends.Resolved) {
	if g.deps.ProvGraph == nil {
		return
	}
	coord := resolved.Coordinate
	if coord.Name == "" || coord.Version == "" {
		return
	}

	ev := provgraph.Event{
		Artifact: provgraph.ArtifactRef{
			Ecosystem: ecosystem,
			Name:      coord.Name,
			Version:   coord.Version,
			Digest:    resolved.Digest,
		},
	}

	if s := signalsFrom(r.Context()); s != nil {
		s.mu.Lock()
		in := s.input
		sbom := s.sbom
		s.mu.Unlock()

		if p := in.Provenance; p != nil && p.Found && p.CommitSHA != "" {
			ev.Commit = &provgraph.CommitRef{
				SHA:             p.CommitSHA,
				RepositoryURL:   p.RepositoryURL,
				Confidence:      p.Confidence,
				RiskScore:       p.RiskScore,
				Malicious:       p.Malicious,
				HighestSeverity: p.HighestSeverity,
			}
			// Decorate the commit node with the source-repository health (Task 63)
			// when it was derived for this repository.
			if rh := in.RepoHealth; rh != nil && rh.Resolved {
				ev.Commit.RepoHealth = rh.Health
				ev.Commit.RepoHealthGrade = rh.Grade
			}
		}
		if v := in.Vuln; v != nil {
			for _, f := range v.Findings {
				ev.CVEs = append(ev.CVEs, provgraph.CVERef{
					ID:         f.ID,
					Severity:   f.Severity,
					CVSS:       f.CVSS,
					Package:    f.Package,
					Version:    f.Version,
					Suppressed: f.Suppressed,
				})
			}
		}
		if sig := in.Signature; sig != nil && sig.Identity != "" {
			ev.Signers = append(ev.Signers, provgraph.SignerRef{
				Identity: sig.Identity,
				Issuer:   sig.Issuer,
				Verified: sig.Verified,
				Keyless:  sig.Keyless,
			})
		}
		if sbom != nil {
			ev.Dependencies = sbomDependencies(sbom, ecosystem, coord.Name, coord.Version)
		}
	}

	// When no provenance signal was recorded (e.g. the hard policy gate is off but
	// a resolver is configured), resolve the source commit directly. The resolver
	// caches, so this is cheap after the first lookup for an artifact.
	if ev.Commit == nil && g.deps.Provenance != nil {
		art := provenance.Artifact{
			Ecosystem: ecosystem,
			Name:      coord.Name,
			Version:   coord.Version,
			Digest:    resolved.Digest,
		}
		if link, err := g.deps.Provenance.Resolve(r.Context(), art); err == nil && link != nil && link.CommitSHA != "" {
			ev.Commit = &provgraph.CommitRef{
				SHA:           link.CommitSHA,
				RepositoryURL: link.RepositoryURL,
				BuilderID:     link.BuilderID,
				Confidence:    string(link.Confidence),
			}
		}
	}

	g.deps.ProvGraph.Ingest(ev)
}

// sbomDependencies projects an SBOM's components into provenance-graph dependency
// refs, excluding the primary component (the artifact itself). The SBOM does not
// expose a per-component ecosystem outside its own package, so dependencies adopt
// the parent artifact's ecosystem — adequate for the common single-ecosystem
// package, and dependency edges remain correct by name/version regardless.
func sbomDependencies(sbom *vulnscan.SBOM, ecosystem, name, version string) []provgraph.ArtifactRef {
	if sbom == nil {
		return nil
	}
	deps := make([]provgraph.ArtifactRef, 0, len(sbom.Components))
	for _, c := range sbom.Components {
		if c.Name == "" {
			continue
		}
		if c.Name == name && c.Version == version {
			continue // the primary artifact restated as a component
		}
		deps = append(deps, provgraph.ArtifactRef{
			Ecosystem: ecosystem,
			Name:      c.Name,
			Version:   c.Version,
		})
	}
	return deps
}
