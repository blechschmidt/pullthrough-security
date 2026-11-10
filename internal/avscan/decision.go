package avscan

import "fmt"

// Outcome is the effective admission decision for a scanned artifact.
type Outcome string

const (
	// OutcomeAllow serves the artifact (clean, not-scanned, or annotate mode).
	OutcomeAllow Outcome = "allow"
	// OutcomeRefuse refuses to serve the artifact (quarantine/block, or a
	// fail-closed engine-unavailable).
	OutcomeRefuse Outcome = "refuse"
)

// Decision is the admission verdict for an assessed artifact.
type Decision struct {
	Outcome Outcome `json:"outcome"`
	// Action is the configured detection action this decision reflects, or a
	// degradation label for an engine-unavailable decision.
	Action string `json:"action"`
	// Evict reports whether the cached artifact should be removed (quarantine).
	Evict bool `json:"evict"`
	// Code is a short machine-readable reason code.
	Code string `json:"code"`
	// Reason is a human-readable explanation.
	Reason string `json:"reason"`
	// Signature is the matched malware signature, when infected.
	Signature string `json:"signature,omitempty"`
}

// Served reports whether the decision permits serving the artifact.
func (d Decision) Served() bool { return d.Outcome == OutcomeAllow }

// Gate applies the configured action and fail-open/fail-closed policy to a
// report and returns the admission decision, folding the result into the
// metrics. A clean or unscannable (not-applicable) report always allows.
func (s *Service) Gate(report *Report) Decision {
	if report == nil {
		return Decision{Outcome: OutcomeAllow, Code: "clean"}
	}

	// Engine unavailable: degrade per policy, never evict (nothing was confirmed).
	if report.Unavailable {
		if s.cfg.FailOpen {
			s.degraded.Add(1)
			return Decision{
				Outcome: OutcomeAllow,
				Action:  "fail-open",
				Code:    "engine-unavailable",
				Reason:  "antivirus engine unavailable; served under fail-open policy",
			}
		}
		return Decision{
			Outcome: OutcomeRefuse,
			Action:  "fail-closed",
			Code:    "engine-unavailable",
			Reason:  "antivirus engine unavailable; refused under fail-closed policy",
		}
	}

	if !report.Infected {
		return Decision{Outcome: OutcomeAllow, Code: "clean"}
	}

	reason := fmt.Sprintf("antivirus engine detected malware signature %q in the artifact payload", report.Signature)
	switch s.cfg.Action {
	case ActionAnnotate:
		s.annotated.Add(1)
		return Decision{
			Outcome:   OutcomeAllow,
			Action:    string(ActionAnnotate),
			Code:      "infected",
			Reason:    reason,
			Signature: report.Signature,
		}
	case ActionBlock:
		s.blocked.Add(1)
		return Decision{
			Outcome:   OutcomeRefuse,
			Action:    string(ActionBlock),
			Code:      "infected",
			Reason:    reason,
			Signature: report.Signature,
		}
	default: // ActionQuarantine
		s.quarantined.Add(1)
		return Decision{
			Outcome:   OutcomeRefuse,
			Action:    string(ActionQuarantine),
			Evict:     true,
			Code:      "infected",
			Reason:    reason,
			Signature: report.Signature,
		}
	}
}
