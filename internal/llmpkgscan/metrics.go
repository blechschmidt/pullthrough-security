package llmpkgscan

// Snapshot is the cumulative, scrape-time view of the gate's activity used by
// the Prometheus metrics bridge. Counters are monotonic.
type Snapshot struct {
	// Assessed counts requests the gate produced a report for. NotPackage counts
	// requests it left alone because the resource is not an archive (a metadata
	// document served under a package's coordinate).
	Assessed   uint64
	NotPackage uint64
	// CacheHits counts requests answered from a stored verdict; CacheMisses those
	// that needed a scan; NegativeHits those answered from a remembered failure.
	CacheHits    uint64
	CacheMisses  uint64
	NegativeHits uint64
	// Coalesced counts requests that joined a scan already in flight.
	Coalesced uint64
	// Scans counts scans that produced a verdict; ScanErrors those that did not.
	Scans      uint64
	ScanErrors uint64
	// Fresh verdicts by what the model said.
	VerdictMalicious  uint64
	VerdictSuspicious uint64
	VerdictBenign     uint64
	// InjectionDetected counts scanned artifacts whose content addressed the
	// scanner; Truncated those whose verdict rests on an incomplete view.
	InjectionDetected uint64
	Truncated         uint64
	// Decisions.
	Blocked      uint64
	Quarantined  uint64
	Annotated    uint64
	FailedOpen   uint64
	FailedClosed uint64
	// Provider activity.
	ProviderCalls   uint64
	ProviderErrors  uint64
	InputTokens     uint64
	OutputTokens    uint64
	CacheReadTokens uint64
	Turns           uint64
	CostUSD         float64
	ScanSeconds     float64
	// InFlight is the number of scans currently running and Queued the number
	// waiting for a slot (gauges).
	InFlight int64
	Queued   int64
	// BreakerOpen reports whether the provider circuit breaker is open (a gauge).
	BreakerOpen bool
	// MetadataOnly counts verdicts on an artifact larger than the scan limit,
	// reached from its metadata alone (a subset of Scans).
	MetadataOnly uint64
	// Breakdowns.
	UnscannedByCode       map[string]uint64
	ToolCallsByTool       map[string]uint64
	ScansByEcosystem      map[string]uint64
	BudgetExhaustedByKind map[string]uint64
	// ScansByKind breaks Scans down by how the artifact was read: "archive",
	// "file" or "oci-image".
	ScansByKind map[string]uint64
	// EnforcedByPath counts the times a stored verdict was enforced on a serve
	// path that does not scan: "blob" (a blob of a refused image), "peer" (an
	// artifact a sibling proxy asked for), "import" (an air-gap bundle).
	EnforcedByPath map[string]uint64
}

// Metrics returns a consistent snapshot of the counters. Safe on a nil Service.
func (s *Service) Metrics() Snapshot {
	snap := Snapshot{
		UnscannedByCode:       map[string]uint64{},
		ToolCallsByTool:       map[string]uint64{},
		ScansByEcosystem:      map[string]uint64{},
		BudgetExhaustedByKind: map[string]uint64{},
		ScansByKind:           map[string]uint64{},
		EnforcedByPath:        map[string]uint64{},
	}
	if s == nil {
		return snap
	}
	snap.MetadataOnly = s.metadataOnly.Load()
	snap.Assessed = s.assessed.Load()
	snap.NotPackage = s.notPackage.Load()
	snap.CacheHits = s.cacheHits.Load()
	snap.CacheMisses = s.cacheMisses.Load()
	snap.NegativeHits = s.negHits.Load()
	snap.Coalesced = s.joined.Load()
	snap.Scans = s.scans.Load()
	snap.ScanErrors = s.scanErrors.Load()
	snap.VerdictMalicious = s.verdictMal.Load()
	snap.VerdictSuspicious = s.verdictSus.Load()
	snap.VerdictBenign = s.verdictBenign.Load()
	snap.InjectionDetected = s.injected.Load()
	snap.Truncated = s.truncatedScans.Load()
	snap.Blocked = s.blocked.Load()
	snap.Quarantined = s.quarantined.Load()
	snap.Annotated = s.annotated.Load()
	snap.FailedOpen = s.failedOpen.Load()
	snap.FailedClosed = s.failedClosed.Load()
	snap.ProviderCalls = s.providerCalls.Load()
	snap.ProviderErrors = s.providerErrs.Load()
	snap.InputTokens = s.inputTokens.Load()
	snap.OutputTokens = s.outputTokens.Load()
	snap.CacheReadTokens = s.cacheReadTok.Load()
	snap.Turns = s.turns.Load()
	snap.InFlight = s.running.Load()
	snap.Queued = s.waiting.Load()

	s.mu.Lock()
	snap.CostUSD = s.costUSD
	snap.ScanSeconds = s.scanSecs
	snap.BreakerOpen = s.now().Before(s.breaker.openUntil)
	for k, v := range s.byCode {
		snap.UnscannedByCode[k] = v
	}
	for k, v := range s.byTool {
		snap.ToolCallsByTool[k] = v
	}
	for k, v := range s.byEco {
		snap.ScansByEcosystem[k] = v
	}
	for k, v := range s.byScope {
		snap.BudgetExhaustedByKind[k] = v
	}
	for k, v := range s.byKind {
		snap.ScansByKind[k] = v
	}
	for k, v := range s.byPath {
		snap.EnforcedByPath[k] = v
	}
	s.mu.Unlock()
	return snap
}

// NoteEnforced counts one enforcement of a stored verdict on a serve path that
// does not scan (see Snapshot.EnforcedByPath). Safe on a nil receiver.
func (s *Service) NoteEnforced(path string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.byPath[path]++
	s.mu.Unlock()
}

// Status is the admin status DTO: the effective configuration (no secrets) plus
// cumulative tallies and the budget state.
type Status struct {
	Enabled             bool     `json:"enabled"`
	Provider            string   `json:"provider"`
	Model               string   `json:"model"`
	Mode                string   `json:"mode"`
	ToolUse             bool     `json:"toolUse"`
	Thinking            bool     `json:"thinking"`
	PromptVersion       int      `json:"promptVersion"`
	Action              Action   `json:"action"`
	FailMode            FailMode `json:"failMode"`
	Oversize            Oversize `json:"oversize"`
	MaliciousThreshold  float64  `json:"maliciousThreshold"`
	SuspiciousThreshold float64  `json:"suspiciousThreshold"`
	TimeoutSeconds      float64  `json:"timeoutSeconds"`
	Ecosystems          []string `json:"ecosystems"`
	Excluded            []string `json:"excluded,omitempty"`
	ExcludedUpstreams   []string `json:"excludedUpstreams,omitempty"`
	Limits              Limits   `json:"limits"`

	Assessed          uint64            `json:"assessed"`
	NotPackage        uint64            `json:"notPackage"`
	CacheHits         uint64            `json:"cacheHits"`
	CacheMisses       uint64            `json:"cacheMisses"`
	Coalesced         uint64            `json:"coalesced"`
	Scans             uint64            `json:"scans"`
	ScanErrors        uint64            `json:"scanErrors"`
	VerdictMalicious  uint64            `json:"verdictMalicious"`
	VerdictSuspicious uint64            `json:"verdictSuspicious"`
	VerdictBenign     uint64            `json:"verdictBenign"`
	InjectionDetected uint64            `json:"injectionDetected"`
	Truncated         uint64            `json:"truncated"`
	MetadataOnly      uint64            `json:"metadataOnly"`
	Blocked           uint64            `json:"blocked"`
	Quarantined       uint64            `json:"quarantined"`
	Annotated         uint64            `json:"annotated"`
	FailedOpen        uint64            `json:"failedOpen"`
	FailedClosed      uint64            `json:"failedClosed"`
	ProviderCalls     uint64            `json:"providerCalls"`
	ProviderErrors    uint64            `json:"providerErrors"`
	InputTokens       uint64            `json:"inputTokens"`
	OutputTokens      uint64            `json:"outputTokens"`
	CostUSD           float64           `json:"costUsd"`
	InFlight          int64             `json:"inFlight"`
	Queued            int64             `json:"queued"`
	MaxConcurrent     int               `json:"maxConcurrent"`
	MaxQueued         int               `json:"maxQueued"`
	BreakerOpen       bool              `json:"breakerOpen"`
	UnscannedByCode   map[string]uint64 `json:"unscannedByCode,omitempty"`
	ScansByKind       map[string]uint64 `json:"scansByKind,omitempty"`
	EnforcedByPath    map[string]uint64 `json:"enforcedByPath,omitempty"`
	Budget            BudgetStatus      `json:"budget"`
}

// Status returns the effective configuration plus cumulative tallies for the
// admin surface. Safe on a nil Service.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	snap := s.Metrics()
	return Status{
		Enabled:             s.cfg.Enabled,
		Provider:            s.provider.Name(),
		Model:               s.cfg.Model,
		Mode:                string(s.cfg.Mode),
		ToolUse:             s.toolsUsable(),
		Thinking:            s.cfg.Thinking,
		PromptVersion:       PromptVersion,
		Action:              s.cfg.Action,
		FailMode:            s.cfg.FailMode,
		Oversize:            s.cfg.Oversize,
		MaliciousThreshold:  s.cfg.MaliciousThreshold,
		SuspiciousThreshold: s.cfg.SuspiciousThreshold,
		TimeoutSeconds:      s.cfg.Timeout.Seconds(),
		Ecosystems:          append([]string(nil), s.cfg.Include...),
		Excluded:            append([]string(nil), s.cfg.Exclude...),
		ExcludedUpstreams:   append([]string(nil), s.cfg.ExcludeUpstreams...),
		Limits:              s.cfg.Limits,
		Assessed:            snap.Assessed,
		NotPackage:          snap.NotPackage,
		CacheHits:           snap.CacheHits,
		CacheMisses:         snap.CacheMisses,
		Coalesced:           snap.Coalesced,
		Scans:               snap.Scans,
		ScanErrors:          snap.ScanErrors,
		VerdictMalicious:    snap.VerdictMalicious,
		VerdictSuspicious:   snap.VerdictSuspicious,
		VerdictBenign:       snap.VerdictBenign,
		InjectionDetected:   snap.InjectionDetected,
		Truncated:           snap.Truncated,
		MetadataOnly:        snap.MetadataOnly,
		Blocked:             snap.Blocked,
		Quarantined:         snap.Quarantined,
		Annotated:           snap.Annotated,
		FailedOpen:          snap.FailedOpen,
		FailedClosed:        snap.FailedClosed,
		ProviderCalls:       snap.ProviderCalls,
		ProviderErrors:      snap.ProviderErrors,
		InputTokens:         snap.InputTokens,
		OutputTokens:        snap.OutputTokens,
		CostUSD:             snap.CostUSD,
		InFlight:            snap.InFlight,
		Queued:              snap.Queued,
		MaxConcurrent:       cap(s.sem),
		MaxQueued:           s.queueLimit(),
		BreakerOpen:         snap.BreakerOpen,
		UnscannedByCode:     snap.UnscannedByCode,
		ScansByKind:         snap.ScansByKind,
		EnforcedByPath:      snap.EnforcedByPath,
		Budget:              s.budget.status(),
	}
}

// BudgetStatus returns the budget's current state. Safe on a nil Service.
func (s *Service) BudgetStatus() BudgetStatus {
	if s == nil {
		return BudgetStatus{}
	}
	return s.budget.status()
}
