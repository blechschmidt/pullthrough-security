package attestbundle

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

// Service is the outbound attestation engine: it builds, signs, retains, and
// serves the proxy's supply-chain attestation for every artifact the proxy
// admits and serves. A nil *Service is a valid no-op so the gateway needs no nil
// checks at call sites — Attest on a nil service returns (nil, nil).
type Service struct {
	signer   *Signer
	attester Attester
	store    *Store
	now      func() time.Time

	// Transparency-log submission (Task 142). When rekorClient is non-nil, every
	// signed bundle is asynchronously submitted to a Sigstore Rekor log and the
	// returned log pointer is attached to a republished copy of the bundle.
	rekorClient   rekor.Client
	rekorVerifier *rekor.Verifier
	rekorBaseURL  string
	rekorMetrics  *rekor.Metrics
	pubPEM        []byte
	rekorTimeout  time.Duration
	logger        *slog.Logger
	inflight      atomic.Int64 // outstanding async submissions (for graceful shutdown/tests)

	// Counters exposed to metrics (read at scrape time). Atomic so the lock-free
	// pull path can bump them.
	produced atomic.Uint64
	signErrs atomic.Uint64
	warned   atomic.Uint64
	withSrc  atomic.Uint64
}

// Config configures a Service.
type Config struct {
	// Signer signs the DSSE envelopes. Required.
	Signer *Signer
	// Attester identifies the proxy in every predicate. ID is required; Name,
	// Version, Instance are recommended. KeyID is filled from the signer.
	Attester Attester
	// Store retains produced bundles. When nil a default-bounded store is created.
	Store *Store
	// Now overrides the clock (tests). Nil uses time.Now.
	Now func() time.Time

	// Rekor, when set, submits every signed bundle to a Sigstore transparency log
	// and records the returned log index + inclusion proof on a republished copy.
	Rekor *RekorConfig
	// Logger receives best-effort submission diagnostics. Nil uses slog.Default.
	Logger *slog.Logger
}

// RekorConfig wires transparency-log submission into the attestation engine
// (Task 142). Submission is best-effort and asynchronous: it never blocks or
// fails serving.
type RekorConfig struct {
	// Client is the transparency-log transport (an HTTP client in production, a
	// fake in tests). Required to enable submission.
	Client rekor.Client
	// Verifier verifies the inclusion proof + SET on the returned entry, so the
	// recorded pointer reflects whether the log actually witnessed the entry.
	// Optional; when nil the pointer records the log index without a verified flag.
	Verifier *rekor.Verifier
	// PublicKeyPEM is the attestation signer's public key, submitted so the Rekor
	// entry is self-describing and verifiable. Required by the public log.
	PublicKeyPEM []byte
	// BaseURL is the log base URL, used to synthesize entry deep links.
	BaseURL string
	// Timeout bounds a single submission (default 15s).
	Timeout time.Duration
	// Metrics receives submit-path counters (shared with the inbound verify path).
	Metrics *rekor.Metrics
}

// NewService constructs an attestation Service. It returns an error when no
// signer is supplied, since an unsigned attestation would be worthless (the whole
// point is a verifiable, non-repudiable proxy signature).
func NewService(cfg Config) (*Service, error) {
	if cfg.Signer == nil {
		return nil, fmt.Errorf("attestbundle: a signer is required")
	}
	att := cfg.Attester
	if att.ID == "" {
		att.ID = "pullthrough-proxy"
	}
	att.KeyID = cfg.Signer.KeyID()
	store := cfg.Store
	if store == nil {
		store = NewStore(StoreOptions{Now: cfg.Now})
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	svc := &Service{signer: cfg.Signer, attester: att, store: store, now: now, logger: logger}
	if rc := cfg.Rekor; rc != nil && rc.Client != nil {
		svc.rekorClient = rc.Client
		svc.rekorVerifier = rc.Verifier
		svc.rekorBaseURL = rc.BaseURL
		svc.rekorMetrics = rc.Metrics
		svc.pubPEM = rc.PublicKeyPEM
		svc.rekorTimeout = rc.Timeout
		if svc.rekorTimeout <= 0 {
			svc.rekorTimeout = 15 * time.Second
		}
	}
	return svc, nil
}

// RekorEnabled reports whether transparency-log submission is wired.
func (s *Service) RekorEnabled() bool { return s != nil && s.rekorClient != nil }

// KeyID returns the signing key identifier, for diagnostics and the admin status
// view. A nil Service returns "".
func (s *Service) KeyID() string {
	if s == nil {
		return ""
	}
	return s.attester.KeyID
}

// Attester returns the configured attester identity. A nil Service returns a
// zero Attester.
func (s *Service) AttesterID() Attester {
	if s == nil {
		return Attester{}
	}
	return s.attester
}

// Store returns the underlying retention store (for the admin/CLI surfaces and
// the referrers endpoint). A nil Service returns nil.
func (s *Service) Store() *Store {
	if s == nil {
		return nil
	}
	return s.store
}

// Attest builds the in-toto statement for the admitted artifact, signs it into a
// DSSE bundle, retains it, and returns it. It is best-effort from the gateway's
// perspective: a signing failure returns an error the caller logs but never lets
// block serving. A nil Service returns (nil, nil) so callers need no guard.
//
// in is the same aggregated admission document the policy/risk/findings layers
// consume; opts carries the policy and risk verdicts (mirroring findings.Options).
func (s *Service) Attest(in policyengine.Input, opts Options) (*Bundle, error) {
	if s == nil {
		return nil, nil
	}
	if opts.ServedAt.IsZero() {
		opts.ServedAt = s.now()
	}
	stmt := BuildStatement(s.attester, in, opts)

	env, err := s.signer.SignStatement(stmt)
	if err != nil {
		s.signErrs.Add(1)
		return nil, err
	}
	b, err := newBundle(env, stmt, s.now())
	if err != nil {
		s.signErrs.Add(1)
		return nil, err
	}
	s.store.Record(b)

	s.produced.Add(1)
	if stmt.Predicate.Admission.Warned {
		s.warned.Add(1)
	}
	if stmt.Predicate.Source != nil {
		s.withSrc.Add(1)
	}

	// Submit to the transparency log out of band so the (potentially network-
	// bound) submission never blocks serving. The returned bundle carries no
	// pointer yet; the submit path republishes an enriched copy into the store.
	if s.rekorClient != nil {
		s.inflight.Add(1)
		go s.submitToRekor(b)
	}
	return b, nil
}

// submitToRekor submits a signed bundle's DSSE envelope to the transparency log,
// verifies the returned entry, and republishes a copy of the bundle carrying the
// log pointer. It is best-effort: any failure is logged and counted, never
// surfaced to the pull path.
func (s *Service) submitToRekor(b *Bundle) {
	defer s.inflight.Add(-1)

	envJSON, err := b.EnvelopeJSON()
	if err != nil {
		s.logger.Warn("rekor: could not marshal attestation envelope for submission",
			"coordinate", b.Coordinate, "error", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.rekorTimeout)
	defer cancel()

	entry, err := s.rekorClient.Submit(ctx, rekor.SubmitRequest{Envelope: envJSON, PublicKeyPEM: s.pubPEM})
	if err != nil {
		s.rekorMetrics.RecordSubmission(false, false)
		s.logger.Warn("rekor: attestation submission failed",
			"coordinate", b.Coordinate, "subjectDigest", b.SubjectDigest, "error", err)
		return
	}

	var ver rekor.Verification
	if s.rekorVerifier != nil {
		ver = s.rekorVerifier.VerifyEntry(entry)
		s.rekorMetrics.RecordVerification(ver, rekor.Options{})
	}
	s.rekorMetrics.RecordSubmission(true, ver.InclusionVerified)
	ptr := entry.Pointer(s.rekorBaseURL, ver)
	s.store.AttachRekor(b, &ptr)
	s.logger.Info("rekor: attestation recorded in transparency log",
		"coordinate", b.Coordinate, "logIndex", ptr.LogIndex,
		"inclusionProofVerified", ptr.InclusionProofVerified, "setVerified", ptr.SETVerified)
}

// WaitForRekor blocks until all outstanding async transparency-log submissions
// have completed or ctx is done. It is used by tests and graceful shutdown; a
// nil Service returns immediately.
func (s *Service) WaitForRekor(ctx context.Context) error {
	if s == nil {
		return nil
	}
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.inflight.Load() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// AttestFromSignals is the gateway's convenience entry point: it assembles
// Options from the neutral risk/policy signals (the same the findings layer
// receives) and delegates to Attest.
func (s *Service) AttestFromSignals(in policyengine.Input, risk *findings.RiskSignal, policy *findings.PolicySignal) (*Bundle, error) {
	return s.Attest(in, Options{Risk: risk, Policy: policy})
}

// Get returns the retained bundle for an artifact (see Store.Get semantics).
func (s *Service) Get(tenant, pkg string) (*Bundle, bool) {
	if s == nil {
		return nil, false
	}
	return s.store.Get(tenant, pkg)
}

// Referrers returns the OCI referrers index for a subject content digest: an OCI
// image index whose manifests are the attestations the proxy produced for that
// digest. The bool is false when the digest is empty.
func (s *Service) Referrers(subjectDigest string) (ReferrersIndex, bool) {
	if s == nil || subjectDigest == "" {
		return ReferrersIndex{}, false
	}
	bundles := s.store.ByDigest(subjectDigest)
	return referrersIndex(bundles), true
}

// Snapshot is a point-in-time view of the service's counters for metrics and the
// admin status endpoint.
type Snapshot struct {
	Enabled       bool   `json:"enabled"`
	KeyID         string `json:"keyId,omitempty"`
	AttesterID    string `json:"attesterId,omitempty"`
	PredicateType string `json:"predicateType"`
	Produced      uint64 `json:"produced"`
	WithSource    uint64 `json:"withSource"`
	Warned        uint64 `json:"warned"`
	SignErrors    uint64 `json:"signErrors"`
	Retained      int    `json:"retained"`
	// RekorEnabled reports whether transparency-log submission is wired; the
	// counters below mirror the shared rekor.Metrics submit path.
	RekorEnabled   bool   `json:"rekorEnabled"`
	RekorSubmitted uint64 `json:"rekorSubmitted,omitempty"`
	RekorSubmitErr uint64 `json:"rekorSubmitErrors,omitempty"`
	RekorWithProof uint64 `json:"rekorWithProof,omitempty"`
}

// Snapshot returns the current counters. A nil Service reports Enabled=false.
func (s *Service) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{Enabled: false, PredicateType: PredicateType}
	}
	snap := Snapshot{
		Enabled:       true,
		KeyID:         s.attester.KeyID,
		AttesterID:    s.attester.ID,
		PredicateType: PredicateType,
		Produced:      s.produced.Load(),
		WithSource:    s.withSrc.Load(),
		Warned:        s.warned.Load(),
		SignErrors:    s.signErrs.Load(),
		Retained:      s.store.Len(),
		RekorEnabled:  s.rekorClient != nil,
	}
	if s.rekorMetrics != nil {
		rm := s.rekorMetrics.Snapshot()
		snap.RekorSubmitted = rm.Submissions
		snap.RekorSubmitErr = rm.SubmissionErrors
		snap.RekorWithProof = rm.SubmissionProofs
	}
	return snap
}
