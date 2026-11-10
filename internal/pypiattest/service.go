package pypiattest

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

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// Service orchestrates inbound PyPI PEP 740 attestation discovery, cryptographic
// verification (via the shared sigverify.Verifier and internal/rekor), the
// sha256 digest binding, result caching, and admission gating. It is safe for
// concurrent use.
type Service struct {
	cfg      Config
	verifier *sigverify.Verifier
	rekor    *rekor.Verifier
	source   Source
	logger   *slog.Logger
	cache    *resultCache

	counters struct {
		verifications     atomic.Int64
		cacheHits         atomic.Int64
		errors            atomic.Int64
		present           atomic.Int64
		verified          atomic.Int64
		publisherTrusted  atomic.Int64
		digestMismatch    atomic.Int64
		transparency      atomic.Int64
		blocked           atomic.Int64
		downgraded        atomic.Int64
		attestationsCheck atomic.Int64
	}

	mu    sync.Mutex
	byEco map[string]*EcoCounts
}

// NewService constructs a Service. The source may be nil (then every artifact is
// reported not-applicable). Defaults are applied for action/thresholds.
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
	return &Service{
		cfg:      cfg,
		verifier: verifier,
		rekor:    rekor.NewVerifier(cfg.RekorKeys),
		source:   source,
		logger:   logger,
		cache:    newResultCache(cfg.CacheTTL, cfg.CacheMaxEntries),
		byEco:    make(map[string]*EcoCounts),
	}, nil
}

// Enabled reports whether a Source is wired (the gate can do work).
func (s *Service) Enabled() bool { return s != nil && s.source != nil }

// Action returns the global action.
func (s *Service) Action() Action {
	if s == nil {
		return ActionAnnotate
	}
	return s.cfg.Action
}

// Verify discovers and verifies the inbound PEP 740 attestations for a
// distribution and binds the attested digest to the served artifact. Results are
// cached by content digest. It returns ErrNotApplicable when the source cannot
// locate the distribution.
func (s *Service) Verify(ctx context.Context, art Artifact) (*Report, error) {
	if s == nil || s.source == nil {
		return nil, ErrNotApplicable
	}
	cacheKey := art.Digest
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

// verify runs the cryptographic checks over discovered material, binds the
// attested digest to the served artifact, and composes the findings. It never
// returns nil.
func (s *Service) verify(art Artifact, material *Material) *Report {
	s.counters.verifications.Add(1)
	report := &Report{Artifact: art, VerifiedAt: time.Now()}
	if material != nil {
		report.Source = material.Source
	}

	var (
		haveTrusted  bool
		haveVerified bool
		haveValid    bool
		sawMismatch  bool
	)

	if material != nil {
		for i := range material.Attestations {
			pa := &material.Attestations[i]
			s.counters.attestationsCheck.Add(1)

			// Verify the DSSE signature without delegating digest binding to the
			// verifier: we assess the sha256 binding against the served artifact
			// ourselves (algorithm-aware), so a different digest algorithm is "not
			// checkable" rather than a binding failure.
			res, statement := s.verifier.VerifyAttestation(pa.DSSE, "")
			bindChecked, bindOK := digestBinds(statement, art.Digest)
			boundToThis := bindChecked && bindOK
			transparency := s.verifyTransparency(pa.LogEntries)

			view := AttestationView{
				PredicateType:        res.PredicateType,
				CryptoValid:          res.CryptoValid,
				DigestBound:          boundToThis,
				ChainTrusted:         res.ChainTrusted,
				IdentityTrusted:      res.IdentityTrusted,
				SLSAProvenance:       res.SLSAProvenance,
				TransparencyVerified: transparency,
				RepositoryURL:        res.RepositoryURL,
				CommitSHA:            res.CommitSHA,
				Identity:             res.Identity,
				Issuer:               res.Issuer,
				Error:                res.Error,
			}

			report.Present = true

			verifiedThis := res.CryptoValid && boundToThis
			trustedThis := res.Verified && boundToThis // res.Verified == crypto-valid && signer trusted
			view.Verified = trustedThis

			if verifiedThis {
				report.Verified = true
			}
			if trustedThis {
				report.PublisherTrusted = true
			}
			if verifiedThis && transparency {
				report.TransparencyVerified = true
			}
			// A crypto-valid attestation that binds a DIFFERENT digest is evidence the
			// served file is not the attested one.
			if res.CryptoValid && bindChecked && !bindOK {
				sawMismatch = true
			}

			// Record the publisher/source, preferring a trusted attestation, then a
			// verified one, then any crypto-valid one.
			if res.CryptoValid {
				switch {
				case trustedThis && !haveTrusted:
					setPublisher(report, pa, res)
					haveTrusted, haveVerified, haveValid = true, true, true
				case verifiedThis && !haveTrusted && !haveVerified:
					setPublisher(report, pa, res)
					haveVerified, haveValid = true, true
				case !haveTrusted && !haveVerified && !haveValid:
					setPublisher(report, pa, res)
					haveValid = true
				}
			}

			report.Attestations = append(report.Attestations, view)
		}
	}

	// A digest mismatch is only decisive when NO attestation bound the served
	// digest: a single binding attestation (Verified) means the file is attested.
	report.DigestMismatch = report.Present && !report.Verified && sawMismatch

	s.evaluateInto(report)
	s.recordCounters(art.Ecosystem, report)
	return report
}

// setPublisher records the publisher/source from an attestation onto the report.
func setPublisher(report *Report, pa *ParsedAttestation, res sigverify.AttestationResult) {
	pub := pa.Publisher
	pub.Identity = res.Identity
	pub.Issuer = res.Issuer
	report.Publisher = pub
	report.RepositoryURL = res.RepositoryURL
	report.CommitSHA = res.CommitSHA
}

// verifyTransparency reports whether any of the attestation's Rekor log entries
// verifies (its Signed Entry Timestamp validates against a configured trusted log
// key; and the Merkle inclusion proof too when RequireInclusionProof is set).
func (s *Service) verifyTransparency(entries []*rekor.LogEntry) bool {
	if s.rekor == nil || !s.rekor.HasKeys() || len(entries) == 0 {
		return false
	}
	opts := rekor.Options{RequireSET: true, RequireInclusionProof: s.cfg.RequireInclusionProof}
	for _, e := range entries {
		if s.rekor.VerifyEntry(e).OK(opts) {
			return true
		}
	}
	return false
}

// evaluateInto computes the findings for a report from its verification outcomes
// and the configured requirements. It is pure (mutates only the report's
// Findings) so the result cache and the gate share one classification.
func (s *Service) evaluateInto(report *Report) {
	report.Findings = nil

	if report.Error != "" {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindVerifyError,
			Severity: SeverityMedium,
			Reason:   "PyPI attestation material could not be retrieved or parsed: " + report.Error,
		})
		return
	}

	if !report.Present {
		if s.cfg.RequireAttestation {
			report.Findings = append(report.Findings, Finding{
				Kind:     KindMissingAttestation,
				Severity: SeverityHigh,
				Reason:   "no PyPI PEP 740 digital attestation was found for this distribution and an attestation is required",
			})
		}
		return
	}

	// A digest mismatch is the headline finding: a valid attestation exists but the
	// served file is not the one it attests.
	if report.DigestMismatch {
		report.Findings = append(report.Findings, Finding{
			Kind:      KindDigestMismatch,
			Severity:  SeverityCritical,
			Publisher: report.Publisher.Identity,
			Reason:    "a cryptographically-valid PyPI attestation was found but it attests a different distribution digest than the one served (the served file is not the file the publisher attested)",
		})
		return
	}

	if !report.Verified {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindUnverifiedAttestation,
			Severity: SeverityHigh,
			Reason:   "a PyPI attestation was present but did not verify (its DSSE signature did not validate against the signing certificate, or none bound this distribution's digest)",
		})
		return
	}

	if s.cfg.RequireTrustedPublisher && !report.PublisherTrusted {
		report.Findings = append(report.Findings, Finding{
			Kind:      KindUntrustedPublisher,
			Severity:  SeverityHigh,
			Publisher: report.Publisher.Identity,
			Reason:    "the PyPI attestation is cryptographically valid but its Trusted Publisher is not trusted (the certificate does not chain to a configured Fulcio root, or its identity is not in the allowed-publisher policy)",
		})
	}

	if s.cfg.RequireInclusionProof && !report.TransparencyVerified {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindMissingTransparency,
			Severity: SeverityHigh,
			Reason:   "the PyPI attestation verified but lacked a verifiable Rekor transparency-log inclusion proof, which is required",
		})
	}
}

// Decision is the gating outcome for a distribution's verification Report.
type Decision struct {
	Action  Action   `json:"action"`
	Code    string   `json:"code"`
	Reason  string   `json:"reason"`
	Highest *Finding `json:"highest,omitempty"`
}

// Gate maps a Report onto an admission decision for a tenant and records the
// cumulative gate counters. A clean (or nil) report annotates (allows).
func (s *Service) Gate(report *Report, tenant string) Decision {
	d := s.evaluate(report, tenant)
	s.countDecision(d)
	return d
}

// evaluate is the pure gating logic; it never mutates counters.
func (s *Service) evaluate(report *Report, tenant string) Decision {
	action := s.cfg.resolveAction(tenant)
	if report == nil {
		return Decision{Action: ActionAnnotate, Code: "ok"}
	}

	worst := report.Worst()
	if worst == nil {
		return Decision{Action: ActionAnnotate, Code: "ok", Reason: s.allowReason(report)}
	}

	// An infrastructure error applies the fail-open/closed posture.
	if worst.Kind == KindVerifyError {
		if s.cfg.FailOnError {
			return Decision{Action: action, Code: string(worst.Kind),
				Reason:  "PyPI attestation verification could not be performed and the gate is fail-closed: " + report.Error,
				Highest: worst}
		}
		return Decision{Action: ActionAnnotate, Code: string(worst.Kind),
			Reason:  "PyPI attestation verification could not be performed; served without gate: " + report.Error,
			Highest: worst}
	}

	meetsFail := s.cfg.FailSeverity != SeverityNone && worst.Severity.AtLeast(s.cfg.FailSeverity)
	meetsWarn := s.cfg.WarnSeverity != SeverityNone && worst.Severity.AtLeast(s.cfg.WarnSeverity)

	if meetsFail {
		return Decision{Action: action, Code: string(worst.Kind), Reason: worst.Reason, Highest: worst}
	}
	if meetsWarn {
		// A sub-fail finding is still surfaced, but never escalated past a downgrade.
		return Decision{Action: action.capAt(ActionDowngrade), Code: string(worst.Kind), Reason: worst.Reason, Highest: worst}
	}
	return Decision{Action: ActionAnnotate, Code: string(worst.Kind), Reason: worst.Reason, Highest: worst}
}

func (s *Service) allowReason(report *Report) string {
	switch {
	case report.PublisherTrusted && report.Publisher.Identity != "":
		return "distribution has a verified PyPI attestation from trusted publisher " + report.Publisher.Identity
	case report.Verified:
		return "distribution has a cryptographically-valid, digest-bound PyPI attestation"
	case report.Present:
		return "PyPI attestation present"
	default:
		return "no PyPI attestation requirement violated"
	}
}

// countDecision records the cumulative gate counters for a decision.
func (s *Service) countDecision(d Decision) {
	switch d.Action {
	case ActionBlock:
		s.counters.blocked.Add(1)
	case ActionDowngrade:
		s.counters.downgraded.Add(1)
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
	if report.PublisherTrusted {
		s.counters.publisherTrusted.Add(1)
	}
	if report.DigestMismatch {
		s.counters.digestMismatch.Add(1)
	}
	if report.TransparencyVerified {
		s.counters.transparency.Add(1)
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
	if report.PublisherTrusted {
		c.PublisherTrusted++
	}
	if report.DigestMismatch {
		c.DigestMismatch++
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
// keyed by content digest. It mirrors the signature/build-provenance gates'
// result cache.
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
