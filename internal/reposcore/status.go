package reposcore

// Status is the cumulative Service state for the admin API.
type Status struct {
	Enabled    bool              `json:"enabled"`
	Window     int               `json:"window"`
	Weights    Weights           `json:"weights"`
	Evaluated  uint64            `json:"evaluated"`
	Resolved   uint64            `json:"resolved"`
	Unresolved uint64            `json:"unresolved"`
	CacheHits  uint64            `json:"cacheHits"`
	Online     uint64            `json:"online"`
	Errors     uint64            `json:"errors"`
	CacheSize  int               `json:"cacheSize"`
	AvgHealth  int               `json:"avgHealth"`
	ByGrade    map[string]uint64 `json:"byGrade"`
	Recent     []Report          `json:"recent,omitempty"`
}

// Status returns a snapshot of the cumulative engine state for the admin surface.
// limit bounds the recent-report list (<=0 returns the full retained history).
func (s *Service) Status(limit int) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	byGrade := make(map[string]uint64, len(s.byGrade))
	for _, g := range []string{"A", "B", "C", "D", "F"} {
		byGrade[g] = s.byGrade[g]
	}
	avg := 0
	if s.resolved > 0 {
		avg = int(s.healthSum / s.resolved)
	}
	return Status{
		Enabled:    s.cfg.Enabled,
		Window:     s.cfg.Window,
		Weights:    s.cfg.Weights,
		Evaluated:  s.evaluated,
		Resolved:   s.resolved,
		Unresolved: s.unresolved,
		CacheHits:  s.cacheHits,
		Online:     s.online,
		Errors:     s.errors,
		CacheSize:  len(s.cache),
		AvgHealth:  avg,
		ByGrade:    byGrade,
		Recent:     s.recentLocked(limit),
	}
}

// Metrics is the compact counter snapshot for the Prometheus bridge.
type Metrics struct {
	Evaluated  uint64
	Resolved   uint64
	Unresolved uint64
	CacheHits  uint64
	Online     uint64
	Errors     uint64
	CacheSize  uint64
	AvgHealth  float64
	ByGrade    map[string]uint64
}

// Metrics returns the cumulative counters for the metrics bridge.
func (s *Service) Metrics() Metrics {
	s.mu.Lock()
	defer s.mu.Unlock()
	byGrade := make(map[string]uint64, 5)
	for _, g := range []string{"A", "B", "C", "D", "F"} {
		byGrade[g] = s.byGrade[g]
	}
	var avg float64
	if s.resolved > 0 {
		avg = float64(s.healthSum) / float64(s.resolved)
	}
	return Metrics{
		Evaluated:  s.evaluated,
		Resolved:   s.resolved,
		Unresolved: s.unresolved,
		CacheHits:  s.cacheHits,
		Online:     s.online,
		Errors:     s.errors,
		CacheSize:  uint64(len(s.cache)),
		AvgHealth:  avg,
		ByGrade:    byGrade,
	}
}
