package buildprov

import (
	"container/list"
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// Service orchestrates inbound build-provenance discovery, cryptographic
// verification (via the shared sigverify.Verifier), the cross-check against the
// claimed package-to-commit association, result caching, and admission gating. It
// is safe for concurrent use.
type Service struct {
	cfg      Config
	verifier *sigverify.Verifier
	// verifiers holds per-forge verifiers keyed by forge id; a forge absent here
	// falls back to verifier (the default/shared trust material).
	verifiers map[string]*sigverify.Verifier
	source    Source
	logger    *slog.Logger
	cache     *resultCache

	counters struct {
		verifications     atomic.Int64
		cacheHits         atomic.Int64
		errors            atomic.Int64
		present           atomic.Int64
		verified          atomic.Int64
		sourceVerified    atomic.Int64
		mismatch          atomic.Int64
		blocked           atomic.Int64
		warned            atomic.Int64
		quarantined       atomic.Int64
		attestationsCheck atomic.Int64
	}

	mu    sync.Mutex
	byEco map[string]*EcoCounts
}

// NewService constructs a Service. The source may be nil (then every artifact is
// reported not-applicable). Defaults are applied for mode/action/thresholds.
func NewService(cfg Config, source Source, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	verifier, err := sigverify.NewVerifier(cfg.Roots, cfg.Identities, cfg.Keys, cfg.RekorKeys)
	if err != nil {
		return nil, err
	}
	forgeVerifiers, err := buildForgeVerifiers(cfg.Forges)
	if err != nil {
		return nil, err
	}
	return &Service{
		cfg:       cfg,
		verifier:  verifier,
		verifiers: forgeVerifiers,
		source:    source,
		logger:    logger,
		cache:     newResultCache(cfg.CacheTTL, cfg.CacheMaxEntries),
		byEco:     make(map[string]*EcoCounts),
	}, nil
}

// verifierFor returns the verifier whose trust material applies to a forge,
// falling back to the default/shared verifier when the forge has no dedicated
// trust configured. This is how the gate verifies a GitLab attestation under
// GitLab's Fulcio root/issuer policy and a Bitbucket attestation under
// Bitbucket's, without the verification loop knowing anything forge-specific.
func (s *Service) verifierFor(forge string) *sigverify.Verifier {
	if forge != "" && s.verifiers != nil {
		if v, ok := s.verifiers[NormalizeForge(forge)]; ok {
			return v
		}
	}
	return s.verifier
}

// Enabled reports whether a provenance Source is wired (the gate can do work).
func (s *Service) Enabled() bool { return s != nil && s.source != nil }

// Mode returns the global enforcement mode.
func (s *Service) Mode() Mode {
	if s == nil {
		return ModeObserve
	}
	return s.cfg.Mode
}

// Verify discovers and verifies the inbound build provenance for an artifact and
// cross-checks the proven source against the claimed association. Results are
// cached by content digest. It returns ErrNotApplicable when no Source handles the
// artifact's ecosystem.
func (s *Service) Verify(ctx context.Context, art Artifact) (*Report, error) {
	if s == nil || s.source == nil {
		return nil, ErrNotApplicable
	}
	// The cache key folds the digest and the claimed commit so a changed claim
	// (e.g. provenance subsystem re-resolved) is re-evaluated.
	cacheKey := art.Digest
	if cacheKey != "" && art.Claim.CommitSHA != "" {
		cacheKey = art.Digest + "|" + art.Claim.CommitSHA
	}
	if cacheKey != "" {
		if report, ok := s.cache.get(cacheKey); ok {
			s.counters.cacheHits.Add(1)
			return report, nil
		}
	}

	material, err := s.source.Fetch(ctx, art)
	if err != nil {
		if errors.Is(err, ErrNotApplicable) {
			return nil, ErrNotApplicable
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		// A material-fetch failure is an infrastructure error, not a verification
		// failure; surface it as a report carrying Error so the gate applies its
		// fail-open/closed posture.
		s.counters.errors.Add(1)
		report := &Report{Artifact: art, VerifiedAt: time.Now()}
		report.Error = err.Error()
		s.evaluateInto(report)
		s.cachePut(cacheKey, report)
		return report, nil
	}

	report := s.verify(art, material)
	s.cachePut(cacheKey, report)
	return report, nil
}

// verify runs the cryptographic checks over discovered material, extracts the
// proven source, performs the cross-check, and composes the findings. It never
// returns nil.
func (s *Service) verify(art Artifact, material *Material) *Report {
	s.counters.verifications.Add(1)
	report := &Report{Artifact: art, VerifiedAt: time.Now()}
	var forge string
	if material != nil {
		report.Source = material.Source
		report.Forge = material.Forge
		forge = material.Forge
	}
	verifier := s.verifierFor(forge)

	// boundCommit/boundRepo hold the source from the BEST attestation observed: a
	// fully-trusted one is preferred, else a merely crypto-valid one (enough to
	// read the proven source for the mismatch cross-check).
	var (
		haveTrusted bool
		haveValid   bool
	)

	if material != nil {
		for i := range material.Attestations {
			s.counters.attestationsCheck.Add(1)
			// Verify the signature without delegating digest binding to the verifier:
			// npm provenance binds the tarball's sha512 while the proxy's content
			// digest may be a sha256, so binding must be algorithm-aware (a different
			// algorithm is "not checkable" here, not a binding failure). We assess
			// binding ourselves from the parsed statement's subject digests.
			res, statement := verifier.VerifyAttestation(material.Attestations[i], "")
			bindChecked, bindOK := digestBinds(statement, art.Digest)
			view := AttestationView{
				PredicateType:   res.PredicateType,
				CryptoValid:     res.CryptoValid,
				ChainTrusted:    res.ChainTrusted,
				IdentityTrusted: res.IdentityTrusted,
				SLSAProvenance:  res.SLSAProvenance,
				RepositoryURL:   res.RepositoryURL,
				CommitSHA:       res.CommitSHA,
				BuilderID:       res.BuilderID,
				Identity:        res.Identity,
				Issuer:          res.Issuer,
				Error:           res.Error,
			}

			report.Present = true
			// A binding violation (the artifact's digest algorithm appears in the
			// subject but with a different value) means the attestation is for a
			// different artifact: it must not count as verified.
			bindingViolation := bindChecked && !bindOK
			// A SLSA-provenance attestation whose signature verified and which did not
			// fail the binding check establishes "verified".
			cryptoSLSA := res.CryptoValid && res.SLSAProvenance && !bindingViolation
			if cryptoSLSA {
				report.Verified = true
			}
			view.Verified = res.Verified && res.SLSAProvenance && !bindingViolation
			trusted := res.Verified && res.SLSAProvenance && !bindingViolation
			if trusted {
				report.SourceVerified = true
			}

			// Record the proven source, preferring a trusted attestation. Only an
			// attestation whose signature verified contributes a proven source for the
			// cross-check (a bound source from an unverifiable attestation is not proof).
			if cryptoSLSA && (res.CommitSHA != "" || res.RepositoryURL != "") {
				if trusted && !haveTrusted {
					setProvenSource(report, res)
					haveTrusted = true
				} else if !haveTrusted && !haveValid {
					setProvenSource(report, res)
					haveValid = true
				}
			}
			report.Attestations = append(report.Attestations, view)
		}
	}

	// Cross-check the proven source against the claimed association.
	report.Mismatch = s.detectMismatch(art.Claim, report)

	s.evaluateInto(report)
	s.recordCounters(art.Ecosystem, report)
	return report
}

// setProvenSource records the proven repository/commit/builder/identity on the
// report from a verified attestation result.
func setProvenSource(report *Report, res sigverify.AttestationResult) {
	report.RepositoryURL = res.RepositoryURL
	report.CommitSHA = res.CommitSHA
	report.BuilderID = res.BuilderID
	report.WorkflowRef = res.Identity
	report.Issuer = res.Issuer
}

// detectMismatch reports whether the source PROVEN by the attestation disagrees
// with the source CLAIMED by package metadata. It compares the commit primarily
// (the strong identity) and falls back to the repository when no claimed commit
// is available. It only fires when both sides carry a comparable value (so a
// missing claim or missing proof is never a mismatch).
func (s *Service) detectMismatch(claim Claim, report *Report) bool {
	if !report.Present {
		return false
	}
	provenCommit := strings.TrimSpace(report.CommitSHA)
	provenRepo := strings.TrimSpace(report.RepositoryURL)
	if provenCommit == "" && provenRepo == "" {
		return false
	}
	claimCommit := strings.TrimSpace(claim.CommitSHA)
	claimRepo := strings.TrimSpace(claim.RepositoryURL)

	if claimCommit != "" && provenCommit != "" {
		if !sameCommit(claimCommit, provenCommit) {
			return true
		}
	}
	if claimRepo != "" && provenRepo != "" {
		if !sameRepo(claimRepo, provenRepo) {
			return true
		}
	}
	return false
}

// evaluateInto computes the findings for a report from its verification outcomes,
// the cross-check, and the configured requirements. It is pure (mutates only the
// report's Findings) so the result cache and the gate share one classification.
func (s *Service) evaluateInto(report *Report) {
	report.Findings = nil

	if report.Error != "" {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindVerifyError,
			Severity: SeverityMedium,
			Reason:   "build-provenance material could not be retrieved or parsed: " + report.Error,
		})
		return
	}

	// No provenance at all.
	if !report.Present {
		if s.cfg.RequireProvenance {
			report.Findings = append(report.Findings, Finding{
				Kind:     KindMissingProvenance,
				Severity: SeverityHigh,
				Reason:   "no inbound build-provenance attestation (npm provenance / GitHub artifact attestation) was found and provenance is required",
			})
		}
		return
	}

	// A confirmed mismatch is the headline finding regardless of mode/requirements.
	if report.Mismatch {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindSourceMismatch,
			Severity: SeverityCritical,
			Identity: report.WorkflowRef,
			Reason: "the source proven by the signed build-provenance attestation (" +
				describeSource(report.RepositoryURL, report.CommitSHA) +
				") does not match the source claimed by package metadata (" +
				describeSource(report.Artifact.Claim.RepositoryURL, report.Artifact.Claim.CommitSHA) +
				")",
		})
	}

	// Present but the attestation did not even verify cryptographically / bind the
	// digest: a tampered or irrelevant attestation.
	if !report.Verified {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindUnverifiedProvenance,
			Severity: SeverityHigh,
			Reason:   "a build-provenance attestation was present but did not verify (its signature did not validate against the signing certificate, or it did not bind this artifact's digest)",
		})
		return
	}

	// Verified but the signer is not trusted, and the operator requires a trusted
	// source.
	if s.cfg.RequireTrustedSource && !report.SourceVerified {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindUntrustedSource,
			Severity: SeverityHigh,
			Identity: report.WorkflowRef,
			Reason:   "the build-provenance attestation is cryptographically valid but its signer is not trusted (the certificate does not chain to a configured Fulcio root, or its identity is not in the allowed-identity policy)",
		})
	}
}

// describeSource renders a "repo @ commit" description, tolerating empties.
func describeSource(repo, commit string) string {
	repo = strings.TrimSpace(repo)
	commit = strings.TrimSpace(commit)
	switch {
	case repo != "" && commit != "":
		return repo + "@" + shortSHA(commit)
	case repo != "":
		return repo
	case commit != "":
		return "commit " + shortSHA(commit)
	default:
		return "unknown"
	}
}

// Decision is the gating outcome for an artifact's verification Report.
type Decision struct {
	Action policy.Action
	Code   string
	Reason string
	Mode   Mode
	// Highest is the finding that drove the decision, when any.
	Highest *Finding
}

// Gate maps a Report onto an admission decision for a tenant, honoring the
// per-tenant observe/enforce mode, and records the cumulative gate counters. In
// observe mode the decision never exceeds a warning. A clean (or nil) report
// allows.
func (s *Service) Gate(report *Report, tenant string) Decision {
	d := s.evaluate(report, tenant)
	s.countDecision(d)
	return d
}

// evaluate is the pure gating logic; it never mutates counters.
func (s *Service) evaluate(report *Report, tenant string) Decision {
	mode := s.cfg.resolveMode(tenant)
	if report == nil {
		return Decision{Action: policy.ActionAllow, Code: "ok", Mode: mode}
	}

	worst := report.Worst()
	if worst == nil {
		return Decision{Action: policy.ActionAllow, Code: "ok", Mode: mode, Reason: s.allowReason(report)}
	}

	// An infrastructure error applies the fail-open/closed posture.
	if worst.Kind == KindVerifyError {
		if mode.Enforces() && s.cfg.FailOnError {
			return Decision{Action: s.cfg.Action, Code: string(worst.Kind), Mode: mode,
				Reason:  "build-provenance verification could not be performed and the gate is fail-closed: " + report.Error,
				Highest: worst}
		}
		return Decision{Action: policy.ActionWarn, Code: string(worst.Kind), Mode: mode,
			Reason:  "build-provenance verification could not be performed; served with a warning: " + report.Error,
			Highest: worst}
	}

	meetsFail := s.cfg.FailSeverity != SeverityNone && worst.Severity.AtLeast(s.cfg.FailSeverity)
	meetsWarn := s.cfg.WarnSeverity != SeverityNone && worst.Severity.AtLeast(s.cfg.WarnSeverity)

	// Observe mode never blocks: the worst it does is warn (so the signal is still
	// visible to clients and the policy/risk engines see the recorded signals).
	if !mode.Enforces() {
		if meetsWarn {
			return Decision{Action: policy.ActionWarn, Code: string(worst.Kind), Mode: mode, Reason: worst.Reason, Highest: worst}
		}
		return Decision{Action: policy.ActionAllow, Code: "ok", Mode: mode, Reason: worst.Reason, Highest: worst}
	}

	if meetsFail {
		return Decision{Action: s.cfg.Action, Code: string(worst.Kind), Mode: mode, Reason: worst.Reason, Highest: worst}
	}
	if meetsWarn {
		return Decision{Action: policy.ActionWarn, Code: string(worst.Kind), Mode: mode, Reason: worst.Reason, Highest: worst}
	}
	return Decision{Action: policy.ActionAllow, Code: "ok", Mode: mode, Reason: worst.Reason, Highest: worst}
}

func (s *Service) allowReason(report *Report) string {
	switch {
	case report.SourceVerified && report.CommitSHA != "":
		return "artifact has a verified build-provenance attestation binding it to source commit " + shortSHA(report.CommitSHA)
	case report.Verified:
		return "artifact has a cryptographically-valid build-provenance attestation"
	case report.Present:
		return "build-provenance attestation present"
	default:
		return "no build-provenance requirement violated"
	}
}

// countDecision records the cumulative gate counters for a decision (a fail-open
// verify-error warning is intentionally not counted as a warning).
func (s *Service) countDecision(d Decision) {
	if d.Code == string(KindVerifyError) && d.Action == policy.ActionWarn {
		return
	}
	switch d.Action {
	case policy.ActionQuarantine:
		s.counters.quarantined.Add(1)
	case policy.ActionBlock:
		s.counters.blocked.Add(1)
	case policy.ActionWarn:
		s.counters.warned.Add(1)
	}
}

// recordCounters folds a report's outcome into the global and per-ecosystem
// tallies.
func (s *Service) recordCounters(ecosystem string, report *Report) {
	if report.Present {
		s.counters.present.Add(1)
	}
	if report.Verified {
		s.counters.verified.Add(1)
	}
	if report.SourceVerified {
		s.counters.sourceVerified.Add(1)
	}
	if report.Mismatch {
		s.counters.mismatch.Add(1)
	}

	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	if eco == "" {
		eco = "unknown"
	}
	s.mu.Lock()
	c := s.byEco[eco]
	if c == nil {
		c = &EcoCounts{}
		s.byEco[eco] = c
	}
	c.Checked++
	if report.Present {
		c.Present++
	}
	if report.Verified {
		c.Verified++
	}
	if report.SourceVerified {
		c.SourceVerified++
	}
	if report.Mismatch {
		c.Mismatch++
	}
	s.mu.Unlock()
}

func (s *Service) cachePut(key string, report *Report) {
	if key != "" {
		s.cache.put(key, report)
	}
}

// Report returns the cached verification Report for a content digest, if present.
func (s *Service) Report(digest string) (*Report, bool) {
	if s == nil {
		return nil, false
	}
	return s.cache.get(digest)
}

// Reports lists the cached verification Reports (most-recent first).
func (s *Service) Reports() []*Report {
	if s == nil {
		return nil
	}
	return s.cache.snapshot()
}

// --- result cache -----------------------------------------------------------

// resultCache is a bounded, optionally TTL-expiring cache of verification reports
// keyed by content digest. It mirrors the signature gate's result cache.
type resultCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]*list.Element
	order   *list.List // front = most-recently-used
}

type cacheItem struct {
	key    string
	report *Report
	stored time.Time
}

func newResultCache(ttl time.Duration, max int) *resultCache {
	if max <= 0 {
		max = defaultCacheMaxEntries
	}
	return &resultCache{
		ttl:     ttl,
		max:     max,
		entries: make(map[string]*list.Element),
		order:   list.New(),
	}
}

func (c *resultCache) get(key string) (*Report, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	it := el.Value.(*cacheItem)
	if c.ttl > 0 && time.Since(it.stored) > c.ttl {
		c.order.Remove(el)
		delete(c.entries, key)
		return nil, false
	}
	c.order.MoveToFront(el)
	return it.report, true
}

func (c *resultCache) put(key string, report *Report) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		it := el.Value.(*cacheItem)
		it.report = report
		it.stored = time.Now()
		c.order.MoveToFront(el)
		return
	}
	el := c.order.PushFront(&cacheItem{key: key, report: report, stored: time.Now()})
	c.entries[key] = el
	for c.order.Len() > c.max {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*cacheItem).key)
	}
}

func (c *resultCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// snapshot returns the cached reports, most-recently-verified first.
func (c *resultCache) snapshot() []*Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*Report, 0, len(c.entries))
	for el := c.order.Front(); el != nil; el = el.Next() {
		out = append(out, el.Value.(*cacheItem).report)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].VerifiedAt.After(out[j].VerifiedAt) })
	return out
}
