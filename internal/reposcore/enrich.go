package reposcore

import "context"

// Enrichment carries the optional online signals that genuinely cannot be derived
// from a local clone — chiefly the authoritative branch-protection setting, which
// lives in the forge's configuration rather than in the repository's history. An
// Enricher fills in whatever it knows and leaves the rest zero; absent fields fall
// back to the offline heuristics.
type Enrichment struct {
	// BranchProtectionKnown reports that BranchProtected reflects a real,
	// authoritatively-fetched setting (so the scorer trusts it instead of the
	// offline CODEOWNERS hint).
	BranchProtectionKnown bool
	BranchProtected       bool
}

// Enricher is the optional online enrichment hook. It is consulted after the
// offline facts are gathered and before scoring. Implementations must be safe for
// concurrent use and must respect the context deadline; a returned error is
// logged and ignored (the report degrades gracefully to the offline signals).
//
// Keeping this an interface means the air-gapped build links no forge client at
// all: with a nil Enricher the Service never imports or calls any online code.
type Enricher interface {
	// Enrich returns supplementary online signals for the repository at repoURL.
	Enrich(ctx context.Context, repoURL string) (Enrichment, error)
}
