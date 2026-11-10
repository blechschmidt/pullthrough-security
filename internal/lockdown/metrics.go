package lockdown

// Snapshot is an immutable copy of the subsystem's cumulative counters and the
// current lockdown posture, read by the Prometheus bridge at scrape time.
type Snapshot struct {
	// Active / Mode describe the current effective posture.
	Active bool
	Mode   string
	// IncidentID is the active incident identifier (empty when not engaged).
	IncidentID string
	// SecondsRemaining is the time until the active lockdown auto-expires; -1 when
	// there is no active lockdown (or it has no expiry).
	SecondsRemaining float64
	// TargetCount is the number of coordinates a targeted block denies.
	TargetCount int
	// Checks is the total number of pull-path consults.
	Checks uint64
	// Blocks is the total number of targeted-block coordinate denials.
	Blocks uint64
	// FreezeFetchBlocks is the total number of upstream fetches refused under a freeze.
	FreezeFetchBlocks uint64
	// Engagements / Clears / Expirations count lifecycle transitions.
	Engagements uint64
	Clears      uint64
	Expirations uint64
}

// ModeActive reports whether the given mode is the current effective mode; the
// metrics bridge uses it to render a per-mode {mode="freeze|strict|block"} gauge.
func (snap Snapshot) ModeActive(m string) float64 {
	if snap.Active && snap.Mode == m {
		return 1
	}
	return 0
}

// Metrics returns the current counter/gauge snapshot. Safe on a nil Service.
func (s *Service) Metrics() Snapshot {
	if s == nil || !s.cfg.Enabled {
		return Snapshot{SecondsRemaining: -1}
	}
	st := s.Status()
	return Snapshot{
		Active:            st.Active,
		Mode:              string(st.Mode),
		IncidentID:        st.IncidentID,
		SecondsRemaining:  st.SecondsRemaining,
		TargetCount:       len(st.Targets),
		Checks:            s.checks.Load(),
		Blocks:            s.blocks.Load(),
		FreezeFetchBlocks: s.freezeBlocks.Load(),
		Engagements:       s.engagements.Load(),
		Clears:            s.clears.Load(),
		Expirations:       s.expirations.Load(),
	}
}

// Modes is the canonical list of lockdown modes for per-mode metric rendering.
func Modes() []string { return []string{string(ModeFreeze), string(ModeStrict), string(ModeBlock)} }
