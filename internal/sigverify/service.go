package sigverify

import (
	"container/list"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

// ErrNotApplicable signals that the gate does not apply to an artifact (no
// configured Source handles its ecosystem, or the resource is not a signable
// subject). The caller treats it as "skip" rather than a verification failure.
var ErrNotApplicable = errors.New("sigverify: gate not applicable to artifact")

// Config configures the signature/attestation verification Service.
type Config struct {
	// Action is applied when a finding meets FailSeverity: warn, block, or
	// quarantine. Empty defaults to block. Operators select the enforcement mode
	// here: "block"/"quarantine" is required (enforcing), "warn" is advisory.
	Action policy.Action
	// FailSeverity is the minimum finding severity that triggers Action (default
	// high). Empty/none disables severity-based gating.
	FailSeverity Severity
	// WarnSeverity is the minimum severity that triggers a warning below the fail
	// threshold (default medium). Empty/none disables warnings.
	WarnSeverity Severity

	// RequireSignature blocks (per the thresholds) an artifact for which no valid,
	// trusted signature could be established. When false, a missing signature is
	// informational and the artifact is allowed.
	RequireSignature bool
	// RequireAttestation additionally requires a verified SLSA provenance
	// attestation, not merely a signature.
	RequireAttestation bool
	// RequireRekorProof requires keyless signatures to carry a verified Rekor
	// Signed Entry Timestamp (SET): proof a trusted log key witnessed the entry.
	RequireRekorProof bool
	// RequireInclusionProof additionally requires a verified RFC 6962 Merkle
	// inclusion proof to a trusted log root (Task 142) — the stronger claim that
	// the entry is actually present in the public append-only log, not merely
	// timestamped. Implies the SET requirement.
	RequireInclusionProof bool

	// RekorMetrics, when set, receives inbound inclusion-proof/SET verification
	// counters (shared with the outbound submit path).
	RekorMetrics *rekor.Metrics

	// FailOnError controls behavior when verification material cannot be fetched
	// or parsed (an infrastructure error, distinct from a verification failure):
	// true blocks (fail-closed), false serves with a warning (fail-open, default).
	FailOnError bool

	// Trust material.
	Roots      *x509.CertPool     // Fulcio root(s) for keyless certificate-chain trust
	Identities []Identity         // allowed keyless signer identities (issuer + subject)
	Keys       []TrustedKey       // operator-configured public keys for keyed verification
	RekorKeys  []crypto.PublicKey // Rekor log public keys for SET verification

	// CacheTTL bounds how long a verification result is reused before re-checking.
	// 0 means results never expire.
	CacheTTL time.Duration
	// CacheMaxEntries bounds the result cache (0 = default 1024).
	CacheMaxEntries int

	// Offline records that the deployment is air-gapped: it is informational for
	// reporting (the Source decides whether it can fetch material).
	Offline bool

	// PQCEnabled turns on post-quantum / hybrid signature verification (Task 151).
	// Default off. When enabled, ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and hybrid
	// classical+PQC signatures can be verified.
	PQCEnabled bool
	// PQCPolicy selects how PQC/hybrid algorithms participate in trust once
	// enabled: classical-only, allow-hybrid (default), or require-pqc.
	PQCPolicy PQCPolicy
}

// Snapshot is a point-in-time view of the subsystem's cumulative counters,
// surfaced through the metrics layer.
type Snapshot struct {
	Verifications      int64
	CacheHits          int64
	Errors             int64
	Verified           int64 // artifacts with a trusted signature
	Unsigned           int64 // artifacts with no signature material
	Blocked            int64
	Warned             int64
	Quarantined        int64
	SignaturesChecked  int64
	AttestationsParsed int64
	RekorVerified      int64
	RekorInclusion     int64
	CacheEntries       int
	// Post-quantum / hybrid counters (Task 151).
	PQCSignatures int64
	PQCVerified   int64
	PQCRejected   int64
	// AlgorithmUsage is the per-algorithm tally of cryptographically-valid
	// signatures, for the labeled pullthrough_sigverify_pqc_signatures_total
	// metric.
	AlgorithmUsage []AlgorithmUsage
}

// AlgorithmUsage is a per-algorithm count of cryptographically-valid signatures.
type AlgorithmUsage struct {
	Algorithm string
	Class     AlgorithmClass
	Count     int64
}

// Service orchestrates signature/attestation discovery, cryptographic
// verification, result caching, and admission gating. It is safe for concurrent
// use.
type Service struct {
	cfg      Config
	verifier *Verifier
	source   Source
	logger   *slog.Logger
	cache    *resultCache

	counters struct {
		verifications      atomic.Int64
		cacheHits          atomic.Int64
		errors             atomic.Int64
		verified           atomic.Int64
		unsigned           atomic.Int64
		blocked            atomic.Int64
		warned             atomic.Int64
		quarantined        atomic.Int64
		signaturesChecked  atomic.Int64
		attestationsParsed atomic.Int64
		rekorVerified      atomic.Int64
		rekorInclusion     atomic.Int64
		// Post-quantum / hybrid counters (Task 151).
		pqcSignatures atomic.Int64 // crypto-valid PQC/hybrid signatures seen
		pqcVerified   atomic.Int64 // artifacts whose trust rested on a PQC/hybrid signature
		pqcRejected   atomic.Int64 // PQC/hybrid signatures refused by policy / disabled flag
	}

	// algMu guards algCounts, the per-algorithm usage tally exposed as a labeled
	// metric. It is written only on cache-miss verifications, so contention is low.
	algMu     sync.Mutex
	algCounts map[string]int64 // key: "algorithm\x00class"
}

// NewService constructs a Service. The source may be nil (then every artifact is
// reported not-applicable). Defaults are applied for the action and thresholds.
func NewService(cfg Config, source Source, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Action == "" {
		cfg.Action = policy.ActionBlock
	}
	if cfg.FailSeverity == "" {
		cfg.FailSeverity = SeverityHigh
	}
	if cfg.WarnSeverity == "" {
		cfg.WarnSeverity = SeverityMedium
	}
	if cfg.CacheMaxEntries <= 0 {
		cfg.CacheMaxEntries = 1024
	}
	if cfg.PQCEnabled && cfg.PQCPolicy == "" {
		cfg.PQCPolicy = PQCPolicyAllowHybrid
	}
	verifier, err := NewVerifierWithPQC(cfg.Roots, cfg.Identities, cfg.Keys, cfg.RekorKeys,
		PQCOptions{Enabled: cfg.PQCEnabled, Policy: cfg.PQCPolicy})
	if err != nil {
		return nil, err
	}
	return &Service{
		cfg:       cfg,
		verifier:  verifier,
		source:    source,
		logger:    logger,
		cache:     newResultCache(cfg.CacheTTL, cfg.CacheMaxEntries),
		algCounts: make(map[string]int64),
	}, nil
}

// Verify discovers and verifies the signature material for an artifact and
// returns the verification Report. Results are cached by content digest. It
// returns ErrNotApplicable when no Source handles the artifact's ecosystem.
func (s *Service) Verify(ctx context.Context, art Artifact) (*Report, error) {
	if s.source == nil {
		return nil, ErrNotApplicable
	}
	if art.Digest != "" {
		if report, ok := s.cache.get(art.Digest); ok {
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
		report := &Report{Artifact: art, Error: err.Error(), VerifiedAt: time.Now()}
		s.evaluateInto(report)
		s.cachePut(art.Digest, report)
		return report, nil
	}

	report := s.verify(art, material)
	s.cachePut(art.Digest, report)
	return report, nil
}

// verify runs the cryptographic checks over discovered material and composes the
// findings. It never returns nil.
func (s *Service) verify(art Artifact, material *Material) *Report {
	s.counters.verifications.Add(1)
	report := &Report{Artifact: art, VerifiedAt: time.Now()}
	if material != nil {
		report.Source = material.Source
	}

	trustedAlgs := make(map[string]struct{})
	if material != nil {
		for _, sig := range material.Signatures {
			s.counters.signaturesChecked.Add(1)
			check := s.verifier.verifySignature(sig, art.Digest)
			s.recordRekor(check)
			s.recordAlgorithm(check)
			res := toSignatureResult(check)
			report.Signatures = append(report.Signatures, res)
			if check.Trusted() {
				report.VerifiedSignature = true
				s.noteTrustedAlgorithm(report, check, trustedAlgs)
			}
		}
		for _, att := range material.Attestations {
			s.counters.attestationsParsed.Add(1)
			check, statement := s.verifier.verifyAttestation(att, art.Digest)
			s.recordRekor(check)
			s.recordAlgorithm(check)
			res := AttestationResult{SignatureResult: toSignatureResult(check)}
			if statement != nil {
				res.PredicateType = statement.PredicateType
				if src, ok := statement.SourceRef(); ok {
					res.SLSAProvenance = statement.IsSLSAProvenance()
					res.RepositoryURL = src.RepositoryURL
					res.CommitSHA = src.CommitSHA
					res.BuilderID = src.BuilderID
				}
			}
			report.Attestations = append(report.Attestations, res)
			if check.Trusted() {
				report.VerifiedSignature = true
				s.noteTrustedAlgorithm(report, check, trustedAlgs)
				if res.SLSAProvenance {
					report.VerifiedAttestation = true
				}
			}
		}
	}
	if report.PostQuantum {
		s.counters.pqcVerified.Add(1)
	}

	s.evaluateInto(report)
	if report.VerifiedSignature {
		s.counters.verified.Add(1)
	} else if material.IsEmpty() && report.Error == "" {
		s.counters.unsigned.Add(1)
	}
	return report
}

// evaluateInto computes the findings for a report from its verification outcomes
// and the configured requirements. It is pure (mutates only the report's
// Findings) so the result cache and the gate share one classification.
func (s *Service) evaluateInto(report *Report) {
	// Infrastructure error: the gate's fail-open/closed posture is applied in Gate
	// via the verify-error finding.
	if report.Error != "" {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindVerifyError,
			Severity: SeverityMedium,
			Reason:   "signature material could not be retrieved or parsed: " + report.Error,
		})
		return
	}

	hasSignatureMaterial := len(report.Signatures) > 0 || len(report.Attestations) > 0

	// No signature at all.
	if !hasSignatureMaterial {
		if s.cfg.RequireSignature {
			report.Findings = append(report.Findings, Finding{
				Kind:     KindMissingSignature,
				Severity: SeverityHigh,
				Reason:   "no cosign signature or attestation was found and signatures are required",
			})
		}
		return
	}

	if !report.VerifiedSignature {
		// Material exists but nothing established trust: classify the strongest
		// reason so the operator sees an actionable cause.
		f := s.classifyUntrusted(report)
		report.Findings = append(report.Findings, f)
		return
	}

	// A trusted signature exists. Apply the remaining requirements.
	// Require-PQC: a classical-only trusted signature does not satisfy a policy
	// that demands post-quantum protection (Task 151).
	if s.cfg.PQCEnabled && s.cfg.PQCPolicy == PQCPolicyRequirePQC && !report.PostQuantum {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindQuantumVulnerable,
			Severity: SeverityHigh,
			Reason:   "the artifact's trusted signature uses a classical (quantum-vulnerable) algorithm, but the PQC policy requires a post-quantum or hybrid signature",
		})
	}
	if s.cfg.RequireInclusionProof && !s.anyRekorInclusionVerified(report) {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindMissingRekorProof,
			Severity: SeverityHigh,
			Reason:   "no verified Rekor Merkle inclusion proof accompanied the signature and an inclusion proof is required",
		})
	} else if s.cfg.RequireRekorProof && !s.anyRekorVerified(report) {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindMissingRekorProof,
			Severity: SeverityHigh,
			Reason:   "no verified Rekor transparency-log Signed Entry Timestamp accompanied the signature and a proof is required",
		})
	}
	if s.cfg.RequireAttestation && !report.VerifiedAttestation {
		report.Findings = append(report.Findings, Finding{
			Kind:     KindMissingAttestation,
			Severity: SeverityMedium,
			Reason:   "no verified SLSA provenance attestation was found and an attestation is required",
		})
	}
}

// classifyUntrusted picks the most actionable finding for an artifact that has
// signature material none of which established trust.
func (s *Service) classifyUntrusted(report *Report) Finding {
	var (
		sawKeylessValid   bool // keyless, crypto-valid, but chain/identity not trusted
		sawKeylessInvalid bool // keyless, signature did not verify (possible tamper)
		sawKeyed          bool // keyed, did not verify against any configured key
		identity          string
	)
	all := make([]SignatureResult, 0, len(report.Signatures)+len(report.Attestations))
	all = append(all, report.Signatures...)
	for _, a := range report.Attestations {
		all = append(all, a.SignatureResult)
	}
	// A cryptographically-valid post-quantum/hybrid signature that did not
	// establish trust was refused by the PQC policy (classical-only) or because
	// PQC support is disabled; report that precisely rather than as an untrusted
	// key/identity (Task 151).
	for _, r := range all {
		if r.CryptoValid && r.PostQuantum && !r.Verified {
			reason := r.Error
			if reason == "" {
				reason = "a valid post-quantum/hybrid signature was refused by the PQC policy"
			}
			return Finding{
				Kind:     KindPQCRejected,
				Severity: SeverityHigh,
				Identity: r.Identity,
				Reason:   reason,
			}
		}
	}
	for _, r := range all {
		switch {
		case r.Keyless && r.CryptoValid:
			sawKeylessValid = true
			if identity == "" {
				identity = r.Identity
			}
		case r.Keyless:
			sawKeylessInvalid = true
		default:
			sawKeyed = true
		}
	}

	switch {
	case sawKeylessValid:
		// The signature verified against its certificate, but the certificate did
		// not chain to a trusted root or the identity is disallowed.
		return Finding{
			Kind:     KindUntrustedIdentity,
			Severity: SeverityHigh,
			Identity: identity,
			Reason:   "signature is cryptographically valid but its signer is not trusted (certificate does not chain to a configured root, or its identity is not in the allowed-identity policy)",
		}
	case sawKeylessInvalid:
		return Finding{
			Kind:     KindInvalidSignature,
			Severity: SeverityCritical,
			Reason:   "a signature was present but did not verify — the artifact may have been tampered with",
		}
	case sawKeyed:
		// Keyed signature(s) that matched no configured key.
		return Finding{
			Kind:     KindUntrustedKey,
			Severity: SeverityHigh,
			Reason:   "signature did not verify against any configured trusted key",
		}
	default:
		// Material existed but every item failed digest binding (irrelevant to this
		// artifact); treat as no usable signature.
		return Finding{
			Kind:     KindInvalidSignature,
			Severity: SeverityHigh,
			Reason:   "no signature bound this artifact's digest",
		}
	}
}

func (s *Service) anyRekorVerified(report *Report) bool {
	for _, r := range report.Signatures {
		if r.Verified && r.Keyless && r.RekorVerified {
			return true
		}
	}
	for _, r := range report.Attestations {
		if r.Verified && r.Keyless && r.RekorVerified {
			return true
		}
	}
	return false
}

// anyRekorInclusionVerified reports whether any trusted keyless signature or
// attestation carried a verified Merkle inclusion proof.
func (s *Service) anyRekorInclusionVerified(report *Report) bool {
	for _, r := range report.Signatures {
		if r.Verified && r.Keyless && r.RekorInclusionVerified {
			return true
		}
	}
	for _, r := range report.Attestations {
		if r.Verified && r.Keyless && r.RekorInclusionVerified {
			return true
		}
	}
	return false
}

// Decision is the gating outcome for an artifact's verification Report.
type Decision struct {
	Action policy.Action
	Code   string
	Reason string
	// Highest is the finding that drove the decision, when any.
	Highest *Finding
}

// Gate maps a Report onto an admission decision using the configured thresholds,
// recording the cumulative gate counters. A clean (or nil) report allows.
func (s *Service) Gate(report *Report) Decision {
	d := s.evaluate(report)
	s.countDecision(d)
	return d
}

// evaluate is the pure gating logic; it never mutates counters.
func (s *Service) evaluate(report *Report) Decision {
	if report == nil {
		return Decision{Action: policy.ActionAllow, Code: "ok"}
	}

	worst := report.Worst()
	if worst == nil {
		return Decision{Action: policy.ActionAllow, Code: "ok",
			Reason: s.allowReason(report)}
	}

	// An infrastructure error applies the fail-open/closed posture.
	if worst.Kind == KindVerifyError {
		if s.cfg.FailOnError {
			return Decision{Action: policy.ActionBlock, Code: string(worst.Kind),
				Reason:  "signature verification could not be performed and the gate is fail-closed: " + report.Error,
				Highest: worst}
		}
		return Decision{Action: policy.ActionWarn, Code: string(worst.Kind),
			Reason:  "signature verification could not be performed; served with a warning: " + report.Error,
			Highest: worst}
	}

	if s.cfg.FailSeverity != SeverityNone && worst.Severity.AtLeast(s.cfg.FailSeverity) {
		return Decision{Action: s.cfg.Action, Code: string(worst.Kind), Reason: worst.Reason, Highest: worst}
	}
	if s.cfg.WarnSeverity != SeverityNone && worst.Severity.AtLeast(s.cfg.WarnSeverity) {
		return Decision{Action: policy.ActionWarn, Code: string(worst.Kind), Reason: worst.Reason, Highest: worst}
	}
	return Decision{Action: policy.ActionAllow, Code: "ok", Reason: worst.Reason, Highest: worst}
}

func (s *Service) allowReason(report *Report) string {
	switch {
	case report.VerifiedAttestation:
		return "artifact has a verified signature and SLSA provenance attestation"
	case report.VerifiedSignature:
		return "artifact has a verified, trusted signature"
	default:
		return "no signature requirement violated"
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

// recordRekor folds one signature/attestation's transparency-log outcome into
// the gate counters and the shared rekor.Metrics, so the pullthrough_rekor_*
// series reflects inbound verification as well as outbound submission.
func (s *Service) recordRekor(c sigCheck) {
	if c.RekorVerified {
		s.counters.rekorVerified.Add(1)
	}
	if c.RekorInclusionVerified {
		s.counters.rekorInclusion.Add(1)
	}
	if s.cfg.RekorMetrics != nil {
		s.cfg.RekorMetrics.RecordVerification(
			rekor.Verification{SETVerified: c.RekorVerified, InclusionVerified: c.RekorInclusionVerified},
			rekor.Options{RequireInclusionProof: s.cfg.RequireInclusionProof, RequireSET: s.cfg.RequireRekorProof},
		)
	}
}

// recordAlgorithm tallies a cryptographically-valid signature by algorithm for
// the labeled PQC metric, and increments the PQC/hybrid counters.
func (s *Service) recordAlgorithm(c sigCheck) {
	if !c.CryptoValid || c.Algorithm == "" {
		return
	}
	s.algMu.Lock()
	s.algCounts[c.Algorithm+"\x00"+string(c.AlgorithmClass)]++
	s.algMu.Unlock()
	if c.PostQuantum {
		s.counters.pqcSignatures.Add(1)
		if c.PQCRejected {
			s.counters.pqcRejected.Add(1)
		}
	}
}

// noteTrustedAlgorithm folds a trusted signature's algorithm into the report's
// distinct-algorithm list and post-quantum flag.
func (s *Service) noteTrustedAlgorithm(report *Report, c sigCheck, seen map[string]struct{}) {
	if c.Algorithm != "" {
		if _, dup := seen[c.Algorithm]; !dup {
			seen[c.Algorithm] = struct{}{}
			report.Algorithms = append(report.Algorithms, c.Algorithm)
		}
	}
	if c.PostQuantum {
		report.PostQuantum = true
	}
}

// toSignatureResult projects a sigCheck onto the JSON-facing result type.
func toSignatureResult(c sigCheck) SignatureResult {
	return SignatureResult{
		Verified:               c.Trusted(),
		CryptoValid:            c.CryptoValid,
		Keyless:                c.Keyless,
		ChainTrusted:           c.ChainTrusted,
		IdentityTrusted:        c.IdentityTrusted,
		RekorVerified:          c.RekorVerified,
		RekorInclusionVerified: c.RekorInclusionVerified,
		Identity:               c.Identity,
		Issuer:                 c.Issuer,
		Algorithm:              c.Algorithm,
		AlgorithmClass:         c.AlgorithmClass,
		PostQuantum:            c.PostQuantum,
		Error:                  c.Err,
	}
}

func (s *Service) cachePut(digest string, report *Report) {
	if digest != "" {
		s.cache.put(digest, report)
	}
}

// GateAction returns the action applied when the fail threshold is met.
func (s *Service) GateAction() policy.Action { return s.cfg.Action }

// Enabled reports whether a signature Source is wired (the gate can do work).
func (s *Service) Enabled() bool { return s != nil && s.source != nil }

// Report returns the cached verification Report for a content digest, if present.
func (s *Service) Report(digest string) (*Report, bool) { return s.cache.get(digest) }

// Reports lists the cached verification Reports (most-recent first), for the
// admin and observability surfaces.
func (s *Service) Reports() []*Report { return s.cache.snapshot() }

// Metrics returns a snapshot of the cumulative counters.
func (s *Service) Metrics() Snapshot {
	return Snapshot{
		Verifications:      s.counters.verifications.Load(),
		CacheHits:          s.counters.cacheHits.Load(),
		Errors:             s.counters.errors.Load(),
		Verified:           s.counters.verified.Load(),
		Unsigned:           s.counters.unsigned.Load(),
		Blocked:            s.counters.blocked.Load(),
		Warned:             s.counters.warned.Load(),
		Quarantined:        s.counters.quarantined.Load(),
		SignaturesChecked:  s.counters.signaturesChecked.Load(),
		AttestationsParsed: s.counters.attestationsParsed.Load(),
		RekorVerified:      s.counters.rekorVerified.Load(),
		RekorInclusion:     s.counters.rekorInclusion.Load(),
		CacheEntries:       s.cache.size(),
		PQCSignatures:      s.counters.pqcSignatures.Load(),
		PQCVerified:        s.counters.pqcVerified.Load(),
		PQCRejected:        s.counters.pqcRejected.Load(),
		AlgorithmUsage:     s.algorithmUsage(),
	}
}

// algorithmUsage returns a stable snapshot of the per-algorithm signature tally.
func (s *Service) algorithmUsage() []AlgorithmUsage {
	s.algMu.Lock()
	out := make([]AlgorithmUsage, 0, len(s.algCounts))
	for k, n := range s.algCounts {
		alg, class, _ := strings.Cut(k, "\x00")
		out = append(out, AlgorithmUsage{Algorithm: alg, Class: AlgorithmClass(class), Count: n})
	}
	s.algMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Algorithm < out[j].Algorithm })
	return out
}

// PQCEnabled reports whether post-quantum / hybrid verification is active.
func (s *Service) PQCEnabled() bool { return s != nil && s.cfg.PQCEnabled }

// PQCPolicy returns the configured post-quantum policy (empty when disabled).
func (s *Service) PQCPolicy() PQCPolicy {
	if s == nil || !s.cfg.PQCEnabled {
		return ""
	}
	return s.cfg.PQCPolicy
}

// --- result cache -----------------------------------------------------------

// resultCache is a bounded, optionally TTL-expiring cache of verification
// reports keyed by content digest. It mirrors the vulnscan result cache's shape.
type resultCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]*list.Element
	order   *list.List // front = most-recently-used
}

type cacheItem struct {
	digest string
	report *Report
	stored time.Time
}

func newResultCache(ttl time.Duration, max int) *resultCache {
	if max <= 0 {
		max = 1024
	}
	return &resultCache{
		ttl:     ttl,
		max:     max,
		entries: make(map[string]*list.Element),
		order:   list.New(),
	}
}

func (c *resultCache) get(digest string) (*Report, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[digest]
	if !ok {
		return nil, false
	}
	it := el.Value.(*cacheItem)
	if c.ttl > 0 && time.Since(it.stored) > c.ttl {
		c.order.Remove(el)
		delete(c.entries, digest)
		return nil, false
	}
	c.order.MoveToFront(el)
	return it.report, true
}

func (c *resultCache) put(digest string, report *Report) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[digest]; ok {
		it := el.Value.(*cacheItem)
		it.report = report
		it.stored = time.Now()
		c.order.MoveToFront(el)
		return
	}
	el := c.order.PushFront(&cacheItem{digest: digest, report: report, stored: time.Now()})
	c.entries[digest] = el
	for c.order.Len() > c.max {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*cacheItem).digest)
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
