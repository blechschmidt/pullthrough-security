package keyrotation

import "time"

// Status grades a material's remaining lifetime.
type Status string

const (
	// StatusOK: the material is not near expiry (or a staged overlap window
	// intentionally suppresses a warning).
	StatusOK Status = "ok"
	// StatusWarning: within the warn threshold of its effective expiry.
	StatusWarning Status = "warning"
	// StatusCritical: within the critical threshold of its effective expiry.
	StatusCritical Status = "critical"
	// StatusExpired: already past its effective expiry.
	StatusExpired Status = "expired"
	// StatusUnknown: the material has no cryptographic expiry and no rotation
	// policy, so its lifetime cannot be assessed; rotation is operator-driven.
	StatusUnknown Status = "unknown"
)

// Thresholds grade remaining lifetime into the warning and critical bands. A
// material with less than Warn remaining is a warning; less than Critical is
// critical. A non-positive threshold disables that band.
type Thresholds struct {
	Warn     time.Duration
	Critical time.Duration
}

// Expiry source labels, reported on MaterialStatus so an operator can tell a
// hard cryptographic expiry from a policy-driven soft one.
const (
	expirySourceNotAfter = "notAfter"
	expirySourcePolicy   = "policy"
)

// MaterialStatus is the evaluated expiry/rotation status of one Material at a
// given instant. It embeds the Material so the admin/SOC surfaces have the full
// descriptor plus the derived verdict in one object.
type MaterialStatus struct {
	Material
	// HasExpiry is true when an effective expiry could be computed (from a hard
	// NotAfter or a rotation policy).
	HasExpiry bool `json:"hasExpiry"`
	// EffectiveExpiry is the earliest of the hard NotAfter and the policy-driven
	// soft expiry. Zero when HasExpiry is false.
	EffectiveExpiry time.Time `json:"effectiveExpiry,omitempty"`
	// ExpirySource is "notAfter" or "policy" — which bound set EffectiveExpiry.
	ExpirySource string `json:"expirySource,omitempty"`
	// SecondsRemaining is EffectiveExpiry minus the evaluation instant. It may be
	// negative (expired); it is 0 when HasExpiry is false.
	SecondsRemaining float64 `json:"secondsRemaining"`
	// Status is the graded verdict.
	Status Status `json:"status"`
	// Note explains a non-obvious verdict (e.g. an overlap suppression).
	Note string `json:"note,omitempty"`
}

// effectiveExpiry returns the earliest meaningful expiry for a material and which
// bound produced it: the hard NotAfter, the policy-driven LastRotated+RotateEvery
// soft expiry, or the zero time when neither is available.
func effectiveExpiry(m Material) (time.Time, string) {
	var policy time.Time
	if m.RotateEvery > 0 && !m.LastRotated.IsZero() {
		policy = m.LastRotated.Add(m.RotateEvery)
	}
	hard := m.NotAfter

	switch {
	case hard.IsZero() && policy.IsZero():
		return time.Time{}, ""
	case hard.IsZero():
		return policy, expirySourcePolicy
	case policy.IsZero():
		return hard, expirySourceNotAfter
	case policy.Before(hard):
		return policy, expirySourcePolicy
	default:
		return hard, expirySourceNotAfter
	}
}

// Evaluate grades a single material at time now against the thresholds. It is a
// pure function: given the same inputs it always yields the same verdict, which
// is what the state-machine and scanner tests exercise.
//
// When a staged dual-key overlap window is active (Material.Overlap), any
// warning/critical/expired verdict is downgraded to OK with an explanatory note:
// the near/past expiry being observed is the retiring previous key, which is
// intentional during a rotation, so it must not raise a false alarm. This is the
// "no drift false-positives" guarantee.
func Evaluate(now time.Time, m Material, th Thresholds) MaterialStatus {
	exp, src := effectiveExpiry(m)
	out := MaterialStatus{Material: m}
	if exp.IsZero() {
		out.Status = StatusUnknown
		out.Note = "no cryptographic expiry or rotation policy configured; rotation is operator-driven"
		return out
	}

	remaining := exp.Sub(now)
	out.HasExpiry = true
	out.EffectiveExpiry = exp
	out.ExpirySource = src
	out.SecondsRemaining = remaining.Seconds()

	switch {
	case remaining <= 0:
		out.Status = StatusExpired
	case th.Critical > 0 && remaining <= th.Critical:
		out.Status = StatusCritical
	case th.Warn > 0 && remaining <= th.Warn:
		out.Status = StatusWarning
	default:
		out.Status = StatusOK
	}

	if m.Overlap && out.Status != StatusOK {
		out.Status = StatusOK
		out.Note = "staged dual-key overlap window active; the near/past expiry is the retiring previous key (rotation in progress)"
	}
	return out
}

// worseThan reports whether status a is strictly more severe than b, using the
// ordering ok < unknown < warning < critical < expired. It drives notification
// de-duplication (emit only when a material's band worsens).
func (a Status) worseThan(b Status) bool {
	return statusRank(a) > statusRank(b)
}

func statusRank(s Status) int {
	switch s {
	case StatusExpired:
		return 4
	case StatusCritical:
		return 3
	case StatusWarning:
		return 2
	case StatusUnknown:
		return 1
	default:
		return 0
	}
}

// alerting reports whether a status warrants an operator notification.
func (s Status) alerting() bool {
	switch s {
	case StatusWarning, StatusCritical, StatusExpired:
		return true
	default:
		return false
	}
}
