package prewarm

import "context"

// Outcome is the terminal result of proactively fetching one predicted target
// through the gated pull pipeline.
type Outcome int

const (
	// OutcomeError means the fetch could not be completed (upstream error, egress
	// block, 404 for a predicted-but-nonexistent version, etc.). It is recorded but
	// is not a security event.
	OutcomeError Outcome = iota
	// OutcomeAdmitted means the artifact was fetched, passed every admission gate,
	// and is now cached and ready to serve a future client request.
	OutcomeAdmitted
	// OutcomeAlreadyCached means the artifact was already present in the cache, so
	// no upstream fetch was needed.
	OutcomeAlreadyCached
	// OutcomeGateBlocked means the artifact was fetched but an admission gate
	// refused it (block or quarantine). It is NOT served and, when quarantined by
	// the pull pipeline, is evicted from the cache. Pre-warming never admits an
	// artifact the gates reject; it only records (and the pipeline quarantines) it.
	OutcomeGateBlocked
)

// String renders an Outcome for logs and the status surface.
func (o Outcome) String() string {
	switch o {
	case OutcomeAdmitted:
		return "admitted"
	case OutcomeAlreadyCached:
		return "already-cached"
	case OutcomeGateBlocked:
		return "gate-blocked"
	default:
		return "error"
	}
}

// FetchResult reports the outcome of a single pre-warm fetch.
type FetchResult struct {
	Outcome Outcome
	// Bytes is the size of the fetched/cached artifact, when known.
	Bytes int64
	// Status is the HTTP status the gated pull pipeline produced, for diagnostics.
	Status int
}

// Fetcher proactively fetches and admission-gates a single predicted target by
// driving it through the proxy's full gated pull pipeline — the same code path a
// client pull takes, so the fetched artifact lands under exactly the cache key a
// later client read will hit, and every supply-chain gate (signature, vuln,
// license, lockdown, SSRF egress allowlist, …) runs unchanged.
//
// A Fetcher must never serve or expose a gate-blocked artifact; it returns
// OutcomeGateBlocked so the predictor can record it while the pipeline
// quarantines it. The concrete implementation lives in the server binary (it
// owns the *proxy.Gateway); the interface keeps this package testable with a
// fake fetcher.
type Fetcher interface {
	Fetch(ctx context.Context, t Target) (FetchResult, error)
}
