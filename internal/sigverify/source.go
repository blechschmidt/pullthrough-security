package sigverify

import (
	"context"
	"crypto/x509"
	"strings"
)

// Source discovers the signature/attestation material available for an artifact.
// Implementations are wired per ecosystem (OCI registry, npm registry, ...). A
// Source returns ErrNotApplicable when it does not handle the artifact's
// ecosystem, (nil, nil) when it handles the ecosystem but found no material, and
// an error for an infrastructure failure (network/parse) the gate treats with
// its fail-open/closed posture.
type Source interface {
	Fetch(ctx context.Context, art Artifact) (*Material, error)
}

// MultiSource routes an artifact to the first registered Source that handles its
// ecosystem. It lets a single Service verify several ecosystems.
type MultiSource struct {
	// byEcosystem maps a normalized ecosystem to its Source.
	byEcosystem map[string]Source
}

// NewMultiSource builds a MultiSource from an ecosystem→Source map. Ecosystem
// keys are normalized (lower-cased, trimmed).
func NewMultiSource(sources map[string]Source) *MultiSource {
	m := &MultiSource{byEcosystem: make(map[string]Source, len(sources))}
	for eco, src := range sources {
		if src == nil {
			continue
		}
		m.byEcosystem[normalizeEcosystem(eco)] = src
	}
	return m
}

// Len reports how many ecosystems are wired.
func (m *MultiSource) Len() int { return len(m.byEcosystem) }

// Fetch delegates to the Source registered for the artifact's ecosystem.
func (m *MultiSource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	src, ok := m.byEcosystem[normalizeEcosystem(art.Ecosystem)]
	if !ok {
		return nil, ErrNotApplicable
	}
	return src.Fetch(ctx, art)
}

// normalizeEcosystem maps ecosystem aliases to a canonical key. "oci" is treated
// as "docker" so a single OCI source serves both labels.
func normalizeEcosystem(eco string) string {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "oci":
		return "docker"
	case "pypi":
		return "pip"
	default:
		return strings.ToLower(strings.TrimSpace(eco))
	}
}

// certBundleFromAnnotations builds the keyless trust material (leaf cert, chain,
// Rekor bundle) from cosign OCI layer annotations. The leaf is nil when no
// certificate annotation is present (a keyed signature).
func certBundleFromAnnotations(annotations map[string]string) (leaf *x509.Certificate, chain []*x509.Certificate, bundle *rekorBundle) {
	certs := parsePEMCertificates([]byte(annotations[annoCertificate]))
	certs = append(certs, parsePEMCertificates([]byte(annotations[annoChain]))...)
	if len(certs) > 0 {
		leaf = certs[0]
		chain = certs[1:]
	}
	if b, ok := parseRekorBundle(annotations[annoBundle]); ok {
		bundle = b
	}
	return leaf, chain, bundle
}
