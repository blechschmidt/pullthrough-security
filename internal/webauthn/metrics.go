package webauthn

import "sync/atomic"

// Metrics holds the WebAuthn subsystem's cumulative counters plus live gauges.
// A nil *Metrics is a valid no-op so the service can hold one unconditionally.
// The proxy's observability layer bridges a Snapshot into pullthrough_webauthn_*
// scrape-time callbacks (Pattern A, like keyrotation).
type Metrics struct {
	registrations    atomic.Uint64 // completed credential enrolments
	registrationFail atomic.Uint64 // failed registration ceremonies
	assertions       atomic.Uint64 // successful assertion (step-up) ceremonies
	assertionFail    atomic.Uint64 // failed assertion ceremonies
	counterRollbacks atomic.Uint64 // signature-counter regressions detected
	challengesIssued atomic.Uint64 // registration + assertion challenges minted
	challengeExpired atomic.Uint64 // ceremonies rejected for an expired/unknown challenge
	stepUpRequired   atomic.Uint64 // protected requests that demanded a step-up token
	stepUpVerified   atomic.Uint64 // protected requests admitted by a fresh assertion
	stepUpDenied     atomic.Uint64 // protected requests blocked for a missing/invalid token

	// Live gauges maintained by the service under its own lock.
	activeCredentials atomic.Int64
	enrolledSubjects  atomic.Int64
	pendingChallenges atomic.Int64
}

// NewMetrics constructs a zeroed Metrics.
func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) recordRegistration(ok bool) {
	if m == nil {
		return
	}
	if ok {
		m.registrations.Add(1)
	} else {
		m.registrationFail.Add(1)
	}
}

func (m *Metrics) recordAssertion(ok bool) {
	if m == nil {
		return
	}
	if ok {
		m.assertions.Add(1)
	} else {
		m.assertionFail.Add(1)
	}
}

func (m *Metrics) recordCounterRollback() {
	if m == nil {
		return
	}
	m.counterRollbacks.Add(1)
}

func (m *Metrics) recordChallengeIssued() {
	if m == nil {
		return
	}
	m.challengesIssued.Add(1)
}

func (m *Metrics) recordChallengeExpired() {
	if m == nil {
		return
	}
	m.challengeExpired.Add(1)
}

func (m *Metrics) recordStepUpRequired() {
	if m == nil {
		return
	}
	m.stepUpRequired.Add(1)
}

func (m *Metrics) recordStepUpVerified() {
	if m == nil {
		return
	}
	m.stepUpVerified.Add(1)
}

func (m *Metrics) recordStepUpDenied() {
	if m == nil {
		return
	}
	m.stepUpDenied.Add(1)
}

func (m *Metrics) setGauges(credentials, subjects, pending int) {
	if m == nil {
		return
	}
	m.activeCredentials.Store(int64(credentials))
	m.enrolledSubjects.Store(int64(subjects))
	m.pendingChallenges.Store(int64(pending))
}

// Snapshot is an immutable view of the counters/gauges for the metrics layer.
type Snapshot struct {
	Registrations        uint64 `json:"registrations"`
	RegistrationFailures uint64 `json:"registrationFailures"`
	Assertions           uint64 `json:"assertions"`
	AssertionFailures    uint64 `json:"assertionFailures"`
	CounterRollbacks     uint64 `json:"counterRollbacks"`
	ChallengesIssued     uint64 `json:"challengesIssued"`
	ChallengesExpired    uint64 `json:"challengesExpired"`
	StepUpRequired       uint64 `json:"stepUpRequired"`
	StepUpVerified       uint64 `json:"stepUpVerified"`
	StepUpDenied         uint64 `json:"stepUpDenied"`
	ActiveCredentials    int64  `json:"activeCredentials"`
	EnrolledSubjects     int64  `json:"enrolledSubjects"`
	PendingChallenges    int64  `json:"pendingChallenges"`
}

// Snapshot returns a consistent copy of the current counters.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	return Snapshot{
		Registrations:        m.registrations.Load(),
		RegistrationFailures: m.registrationFail.Load(),
		Assertions:           m.assertions.Load(),
		AssertionFailures:    m.assertionFail.Load(),
		CounterRollbacks:     m.counterRollbacks.Load(),
		ChallengesIssued:     m.challengesIssued.Load(),
		ChallengesExpired:    m.challengeExpired.Load(),
		StepUpRequired:       m.stepUpRequired.Load(),
		StepUpVerified:       m.stepUpVerified.Load(),
		StepUpDenied:         m.stepUpDenied.Load(),
		ActiveCredentials:    m.activeCredentials.Load(),
		EnrolledSubjects:     m.enrolledSubjects.Load(),
		PendingChallenges:    m.pendingChallenges.Load(),
	}
}
