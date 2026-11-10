package depfirewall

// Snapshot is the cumulative, scrape-time view of the gate's activity used by the
// Prometheus metrics bridge. All counters are monotonic.
type Snapshot struct {
	Checks       uint64
	Blocks       uint64
	Allowed      uint64
	ChecksByEco  map[string]uint64
	BlocksByEco  map[string]uint64
	BlocksByCode map[string]uint64
}

// Metrics returns a consistent snapshot of the cumulative counters partitioned by
// ecosystem and violation code. Safe on a nil Service.
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	snap := Snapshot{
		Checks:       s.checks.Load(),
		Blocks:       s.blocks.Load(),
		Allowed:      s.allowed.Load(),
		ChecksByEco:  make(map[string]uint64),
		BlocksByEco:  make(map[string]uint64),
		BlocksByCode: make(map[string]uint64),
	}
	s.mu.RLock()
	for eco, c := range s.byEco {
		snap.ChecksByEco[eco] = c.checks
		snap.BlocksByEco[eco] = c.blocked
	}
	for code, n := range s.byCode {
		snap.BlocksByCode[code] = n
	}
	s.mu.RUnlock()
	return snap
}

// Status is the admin status DTO for the dependency-firewall gate.
type Status struct {
	Enabled        bool              `json:"enabled"`
	DefaultAction  string            `json:"defaultAction"`
	GlobalRules    int               `json:"globalRules"`
	TenantPolicies int               `json:"tenantPolicies"`
	TenantRules    int               `json:"tenantRules"`
	Checks         uint64            `json:"checks"`
	Blocks         uint64            `json:"blocks"`
	Allowed        uint64            `json:"allowed"`
	BlocksByCode   map[string]uint64 `json:"blocksByCode,omitempty"`
	TenantDefaults map[string]string `json:"tenantDefaults,omitempty"`
}

// Status returns the effective configuration plus cumulative tallies for the
// admin surface. Safe on a nil Service.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	st := Status{
		Enabled:      true,
		Checks:       s.checks.Load(),
		Blocks:       s.blocks.Load(),
		Allowed:      s.allowed.Load(),
		BlocksByCode: make(map[string]uint64),
	}
	s.mu.RLock()
	st.DefaultAction = string(s.defaultAction)
	st.GlobalRules = len(s.global)
	st.TenantPolicies = len(s.tenants)
	for _, tp := range s.tenants {
		st.TenantRules += len(tp.rules)
	}
	if len(s.tenants) > 0 {
		st.TenantDefaults = make(map[string]string)
		for id, tp := range s.tenants {
			if tp.DefaultAction != "" {
				st.TenantDefaults[id] = string(tp.DefaultAction)
			}
		}
		if len(st.TenantDefaults) == 0 {
			st.TenantDefaults = nil
		}
	}
	for code, n := range s.byCode {
		st.BlocksByCode[code] = n
	}
	s.mu.RUnlock()
	if len(st.BlocksByCode) == 0 {
		st.BlocksByCode = nil
	}
	return st
}

// RuleView is one rule rendered for the admin list, tagged with its scope.
type RuleView struct {
	Rule
	Tenant string `json:"tenant,omitempty"`
}

// Rules returns the configured rules (global plus, optionally, those of a single
// tenant) ordered by (ecosystem, name). An empty tenant returns only the global
// rules; tenant="*" returns global plus every tenant rule. Safe on a nil Service.
func (s *Service) Rules(tenant string) []RuleView {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RuleView, 0)
	globals := make([]Rule, 0, len(s.global))
	for _, r := range s.global {
		globals = append(globals, copyRule(r))
	}
	sortRules(globals)
	for _, r := range globals {
		out = append(out, RuleView{Rule: r})
	}
	emit := func(id string, tp *TenantPolicy) {
		trules := make([]Rule, 0, len(tp.rules))
		for _, r := range tp.rules {
			trules = append(trules, copyRule(r))
		}
		sortRules(trules)
		for _, r := range trules {
			out = append(out, RuleView{Rule: r, Tenant: id})
		}
	}
	if tenant == "*" {
		ids := make([]string, 0, len(s.tenants))
		for id := range s.tenants {
			ids = append(ids, id)
		}
		// Stable order.
		for i := 0; i < len(ids); i++ {
			for j := i + 1; j < len(ids); j++ {
				if ids[j] < ids[i] {
					ids[i], ids[j] = ids[j], ids[i]
				}
			}
		}
		for _, id := range ids {
			emit(id, s.tenants[id])
		}
	} else if tenant != "" {
		if tp := s.tenants[tenant]; tp != nil {
			emit(tenant, tp)
		}
	}
	return out
}

// copyRule returns a shallow value copy of a rule without the compiled ranges,
// safe to hand to JSON/admin callers.
func copyRule(r *Rule) Rule {
	c := *r
	c.parsedRanges = nil
	return c
}
