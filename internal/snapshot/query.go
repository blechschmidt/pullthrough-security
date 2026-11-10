package snapshot

import "time"

// QueryFact is the neutral per-coordinate projection of the snapshot live state
// that the federated query API (Task 67) joins into its model. It carries the
// most-recently-served resolved state plus whether the coordinate is part of the
// currently-active frozen set.
type QueryFact struct {
	Tenant            string
	Ecosystem         string
	Name              string
	Version           string
	Coordinate        string
	Digest            string
	Verdict           string
	RiskBand          string
	RiskScore         int
	SourceCommit      string
	AttestationDigest string
	// Frozen is true when a freeze is active and this exact coordinate is part of
	// the frozen set (i.e. it would be served under the freeze).
	Frozen   bool
	ServedAt time.Time
}

// QueryFacts returns the live-state coordinates as query facts. Safe on nil.
func (s *Service) QueryFacts() []QueryFact {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]QueryFact, 0, len(s.live))
	for k, e := range s.live {
		f := QueryFact{
			Tenant:            e.Tenant,
			Ecosystem:         e.Ecosystem,
			Name:              e.Name,
			Version:           e.Version,
			Coordinate:        e.Coordinate,
			Digest:            e.Digest,
			Verdict:           e.Verdict,
			RiskBand:          e.RiskBand,
			RiskScore:         e.RiskScore,
			SourceCommit:      e.SourceCommit,
			AttestationDigest: e.AttestationDigest,
			ServedAt:          e.ServedAt,
		}
		if s.freeze.Active && s.frozenSet != nil {
			_, f.Frozen = s.frozenSet[k]
		}
		out = append(out, f)
	}
	return out
}
