package rekor

import "sync/atomic"

// Metrics holds the transparency-log subsystem's cumulative counters, shared by
// the submit path (outbound attester) and the verify path (inbound gate). It is
// safe for concurrent use; a nil *Metrics is a valid no-op so call sites need no
// guards. The gateway constructs one instance and the observability layer binds
// scrape-time callbacks over its Snapshot, keeping these atomics the single
// source of truth for the pullthrough_rekor_* series.
type Metrics struct {
	submissions       atomic.Uint64 // outbound entries submitted to the log
	submissionErrors  atomic.Uint64 // submissions that failed (network / non-2xx / parse)
	submissionProofs  atomic.Uint64 // submissions whose returned entry carried a verified inclusion proof
	verifications     atomic.Uint64 // inbound entries checked
	inclusionVerified atomic.Uint64 // inbound entries with a valid inclusion proof
	setVerified       atomic.Uint64 // inbound entries with a valid Signed Entry Timestamp
	verifyFailures    atomic.Uint64 // inbound entries that failed a required check
}

// NewMetrics returns a fresh counter set.
func NewMetrics() *Metrics { return &Metrics{} }

// RecordSubmission folds one outbound submission outcome into the counters. It
// is called by the orchestrator (the attestation engine / self-release signer)
// rather than the transport, so every Client implementation — the HTTP client
// and the in-memory fake alike — is counted uniformly. proofVerified reports the
// returned entry carried a verified inclusion proof.
func (m *Metrics) RecordSubmission(ok, proofVerified bool) {
	if m == nil {
		return
	}
	if ok {
		m.submissions.Add(1)
		if proofVerified {
			m.submissionProofs.Add(1)
		}
	} else {
		m.submissionErrors.Add(1)
	}
}

// RecordVerification folds one inbound verification outcome into the counters.
// required reports whether the caller required a check to pass (so a benign
// "no proof present, none required" is not counted as a failure).
func (m *Metrics) RecordVerification(v Verification, opts Options) {
	if m == nil {
		return
	}
	m.verifications.Add(1)
	if v.InclusionVerified {
		m.inclusionVerified.Add(1)
	}
	if v.SETVerified {
		m.setVerified.Add(1)
	}
	if !v.OK(opts) && (opts.RequireInclusionProof || opts.RequireSET) {
		m.verifyFailures.Add(1)
	}
}

// Snapshot is a point-in-time copy of the counters for the metrics layer.
type Snapshot struct {
	Submissions       uint64
	SubmissionErrors  uint64
	SubmissionProofs  uint64
	Verifications     uint64
	InclusionVerified uint64
	SETVerified       uint64
	VerifyFailures    uint64
}

// Snapshot reads the current counter values. A nil *Metrics reports zeros.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	return Snapshot{
		Submissions:       m.submissions.Load(),
		SubmissionErrors:  m.submissionErrors.Load(),
		SubmissionProofs:  m.submissionProofs.Load(),
		Verifications:     m.verifications.Load(),
		InclusionVerified: m.inclusionVerified.Load(),
		SETVerified:       m.setVerified.Load(),
		VerifyFailures:    m.verifyFailures.Load(),
	}
}
