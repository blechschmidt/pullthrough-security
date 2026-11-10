package provenance

import (
	"context"
	"log/slog"
	"time"
)

// Service is the provenance orchestrator. It implements Resolver, so it can be
// dropped in wherever a single resolver is expected (the proxy, the admin API),
// while internally:
//
//   - serving previously established links from a durable LinkStore (so an
//     artifact's provenance is resolved and verified once, then reused);
//   - consulting an ordered set of Resolvers, preferring a cryptographically
//     attested link and threading any repository hint a metadata resolver
//     discovers into later (attestation) resolvers so a claimed repository can be
//     upgraded to an attested commit;
//   - joining the resulting source commit with the LLM scan verdict (Task 7) so a
//     consumed package's risk can be surfaced against the commit it was built
//     from.
type Service struct {
	resolvers []Resolver
	pins      *PinSet
	store     LinkStore
	verdicts  VerdictLookup
	logger    *slog.Logger
	now       func() time.Time
}

// VerdictLookup surfaces commit scan verdicts (Task 7) without coupling the
// provenance package to the scanning implementation. An adapter wraps the commit
// scanner to satisfy it.
type VerdictLookup interface {
	// VerdictFor returns the scan verdict for a commit SHA, and false when none is
	// stored (the commit has not been scanned).
	VerdictFor(ctx context.Context, sha string) (*CommitVerdict, bool)
}

// CommitVerdict is a decoupled, minimal view of a scan verdict, surfaced next to
// a provenance link.
type CommitVerdict struct {
	SHA             string `json:"sha"`
	RiskScore       int    `json:"riskScore"`
	Malicious       bool   `json:"malicious"`
	HighestSeverity string `json:"highestSeverity"`
	Findings        int    `json:"findings"`
}

// EnrichedLink is a provenance Link joined with the scan verdict for its source
// commit, when available.
type EnrichedLink struct {
	Link    *Link          `json:"link"`
	Verdict *CommitVerdict `json:"verdict,omitempty"`
}

// ServiceOptions configures a Service.
type ServiceOptions struct {
	// Resolvers are consulted in order. An attested link short-circuits the rest;
	// otherwise the highest-confidence link wins. Place attestation resolvers that
	// need a repository hint (e.g. GitHub) after the ecosystem-metadata resolvers
	// that discover it.
	Resolvers []Resolver
	// Pins are operator-asserted package -> commit associations. A pin is
	// authoritative for the coordinates it matches: it is consulted before the
	// link store and the resolver chain, so the operator's explicit assertion is
	// never shadowed by a previously persisted or metadata-derived link. Optional.
	Pins *PinSet
	// Store persists resolved links. Optional; without it every Resolve re-runs
	// the resolver chain.
	Store LinkStore
	// Verdicts joins source commits with scan verdicts. Optional.
	Verdicts VerdictLookup
	// Logger is used for diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
}

// NewService constructs a provenance Service.
func NewService(opts ServiceOptions) *Service {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		resolvers: opts.Resolvers,
		pins:      opts.Pins,
		store:     opts.Store,
		verdicts:  opts.Verdicts,
		logger:    logger,
		now:       time.Now,
	}
}

// Name implements Resolver.
func (s *Service) Name() string { return "provenance" }

// Resolve implements Resolver. An operator pin, when one matches, is
// authoritative. Otherwise it returns a cached link when present, or runs the
// resolver chain, persists the result, and returns it. ErrNoProvenance is
// returned when no resolver can establish an association.
func (s *Service) Resolve(ctx context.Context, art Artifact) (*Link, error) {
	if link, ok := s.pins.Link(art, s.now()); ok {
		s.rememberPin(ctx, link)
		return link, nil
	}
	if s.store != nil {
		// A stored link that originated from a pin is honored only while a pin
		// still matches (handled above). Once the operator removes or narrows the
		// pin, the stale assertion must not keep answering from the store: fall
		// through to the resolver chain, which overwrites it if it finds a link.
		if l, err := s.store.Get(ctx, art); err == nil && l.ResolverName != PinResolverName {
			return l, nil
		}
	}
	link, err := s.runChain(ctx, art)
	if err != nil {
		return nil, err
	}
	if s.store != nil {
		if perr := s.store.Put(ctx, link); perr != nil {
			s.logger.Warn("provenance: persisting link failed", "artifact", art.Name, "error", perr)
		}
	}
	s.logger.Info("provenance resolved",
		"ecosystem", art.Ecosystem, "name", art.Name, "version", art.Version,
		"resolver", link.ResolverName, "confidence", link.Confidence,
		"repository", link.RepositoryURL, "commit", link.CommitSHA)
	return link, nil
}

// rememberPin persists a pinned link so it appears in the admin "consumed
// packages" view alongside resolver-discovered links. The store is only written
// when the pinned association is new or has changed, so a hot coordinate does not
// cost a write per pull.
func (s *Service) rememberPin(ctx context.Context, link *Link) {
	if s.store == nil {
		return
	}
	if prev, err := s.store.Get(ctx, link.Artifact); err == nil &&
		prev.ResolverName == PinResolverName &&
		prev.CommitSHA == link.CommitSHA && prev.RepositoryURL == link.RepositoryURL {
		return
	}
	if err := s.store.Put(ctx, link); err != nil {
		s.logger.Warn("provenance: persisting pinned link failed", "artifact", link.Artifact.Name, "error", err)
		return
	}
	s.logger.Info("provenance pinned",
		"ecosystem", link.Artifact.Ecosystem, "name", link.Artifact.Name, "version", link.Artifact.Version,
		"repository", link.RepositoryURL, "commit", link.CommitSHA)
}

// runChain executes the resolver chain, threading discovered repository hints and
// preferring the strongest confidence.
func (s *Service) runChain(ctx context.Context, art Artifact) (*Link, error) {
	var best *Link
	for _, res := range s.resolvers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		probe := art
		// Thread a repository hint discovered by an earlier resolver into a later
		// one (e.g. so the GitHub attestation resolver knows which repo to query).
		if probe.RepositoryURL == "" && best != nil {
			probe.RepositoryURL = best.RepositoryURL
		}
		link, err := res.Resolve(ctx, probe)
		if err != nil || link == nil {
			continue
		}
		if best == nil || confidenceRank(link.Confidence) > confidenceRank(best.Confidence) {
			best = link
		}
		if link.Confidence == ConfidenceAttested {
			best = link
			break
		}
	}
	if best == nil {
		return nil, ErrNoProvenance
	}
	return best, nil
}

// ResolveEnriched resolves an artifact and joins its source commit with the scan
// verdict, so a caller can answer "what is this package, where did it come from,
// and is that commit risky?" in one call.
func (s *Service) ResolveEnriched(ctx context.Context, art Artifact) (*EnrichedLink, error) {
	link, err := s.Resolve(ctx, art)
	if err != nil {
		return nil, err
	}
	return &EnrichedLink{Link: link, Verdict: s.verdictFor(ctx, link.CommitSHA)}, nil
}

// Links returns every persisted link (empty when no store is configured), for
// administrative inspection. A link that was recorded from an operator pin is
// listed only while a pin still asserts it, so removing a pin also removes its
// association from the view rather than leaving a stale claim behind.
func (s *Service) Links(ctx context.Context) ([]*Link, error) {
	if s.store == nil {
		return nil, nil
	}
	links, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	out := links[:0]
	for _, l := range links {
		if l.ResolverName == PinResolverName {
			pin, ok := s.pins.Match(l.Artifact)
			if !ok || pin.Commit != l.CommitSHA {
				continue
			}
		}
		out = append(out, l)
	}
	return out, nil
}

// PinCount reports how many operator pins the service was configured with.
func (s *Service) PinCount() int { return s.pins.Len() }

// LinksWithVerdicts returns every persisted link joined with its source commit's
// scan verdict, for the admin/consumed-packages view.
func (s *Service) LinksWithVerdicts(ctx context.Context) ([]*EnrichedLink, error) {
	links, err := s.Links(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*EnrichedLink, 0, len(links))
	for _, l := range links {
		out = append(out, &EnrichedLink{Link: l, Verdict: s.verdictFor(ctx, l.CommitSHA)})
	}
	return out, nil
}

// verdictFor looks up the scan verdict for a commit SHA, tolerating an absent
// verdict source or unscanned commit.
func (s *Service) verdictFor(ctx context.Context, sha string) *CommitVerdict {
	if s.verdicts == nil || sha == "" {
		return nil
	}
	v, ok := s.verdicts.VerdictFor(ctx, sha)
	if !ok {
		return nil
	}
	return v
}

// ForEcosystems wraps a Resolver so it only applies to the given ecosystems,
// returning ErrNoProvenance for any other artifact. This prevents, e.g., the npm
// resolver from being consulted for a pip artifact. An empty ecosystem list
// matches every artifact (used for cross-ecosystem enrichers like GitHub).
func ForEcosystems(r Resolver, ecosystems ...string) Resolver {
	if len(ecosystems) == 0 {
		return r
	}
	set := make(map[string]bool, len(ecosystems))
	for _, e := range ecosystems {
		set[e] = true
	}
	return &ecosystemFilter{inner: r, ecosystems: set}
}

type ecosystemFilter struct {
	inner      Resolver
	ecosystems map[string]bool
}

func (f *ecosystemFilter) Name() string { return f.inner.Name() }

func (f *ecosystemFilter) Resolve(ctx context.Context, art Artifact) (*Link, error) {
	if !f.ecosystems[art.Ecosystem] {
		return nil, ErrNoProvenance
	}
	return f.inner.Resolve(ctx, art)
}

// confidenceRank orders confidence levels for "strongest wins" selection.
func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceAttested:
		return 3
	case ConfidenceClaimed:
		return 2
	case ConfidenceHeuristic:
		return 1
	default:
		return 0
	}
}
