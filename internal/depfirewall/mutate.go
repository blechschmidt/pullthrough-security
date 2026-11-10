package depfirewall

import (
	"fmt"
	"strings"
)

// SetRule installs or replaces a rule. An empty tenant targets the global rule
// set; a non-empty tenant targets that tenant's policy (creating it if needed).
// The rule's ranges are validated; a malformed range is rejected without
// mutating state. Safe for concurrent use.
func (s *Service) SetRule(tenant string, r Rule) error {
	if s == nil {
		return fmt.Errorf("dependency firewall is not enabled")
	}
	rule := r // copy; compile populates parsedRanges
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(tenant) == "" {
		return s.putRuleLocked(s.global, &rule)
	}
	tp := s.tenants[tenant]
	if tp == nil {
		tp = &TenantPolicy{rules: make(map[string]*Rule)}
		s.tenants[tenant] = tp
	}
	return s.putRuleLocked(tp.rules, &rule)
}

// DeleteRule removes a rule for (ecosystem, name) from the global set (empty
// tenant) or a tenant's set. It reports whether a rule was present.
func (s *Service) DeleteRule(tenant, ecosystem, name string) bool {
	if s == nil {
		return false
	}
	key := ruleKey(normalizeEco(ecosystem), name)
	s.mu.Lock()
	defer s.mu.Unlock()
	var m map[string]*Rule
	if strings.TrimSpace(tenant) == "" {
		m = s.global
	} else if tp := s.tenants[tenant]; tp != nil {
		m = tp.rules
	} else {
		return false
	}
	if _, ok := m[key]; !ok {
		return false
	}
	delete(m, key)
	return true
}

// SetDefaultAction sets the deny/allow disposition for ungoverned coordinates.
// An empty tenant sets the global default; a non-empty tenant sets that tenant's
// override.
func (s *Service) SetDefaultAction(tenant string, action Action) error {
	if s == nil {
		return fmt.Errorf("dependency firewall is not enabled")
	}
	a := normalizeAction(action, "")
	if a == "" {
		return fmt.Errorf("invalid default action %q (want allow|block)", action)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(tenant) == "" {
		s.defaultAction = a
		return nil
	}
	tp := s.tenants[tenant]
	if tp == nil {
		tp = &TenantPolicy{rules: make(map[string]*Rule)}
		s.tenants[tenant] = tp
	}
	tp.DefaultAction = a
	return nil
}

// ImportResult summarizes a lockfile import.
type ImportResult struct {
	Format        string `json:"format"`
	Source        string `json:"source"`
	Tenant        string `json:"tenant,omitempty"`
	RulesImported int    `json:"rulesImported"`
	Versions      int    `json:"versions"`
	Replaced      bool   `json:"replaced"`
}

// ImportLockfile parses lockfile content and installs pinned rules so the tenant
// can only fetch the exact versions the lockfile resolved. Each distinct
// (ecosystem, name) becomes a pinned rule whose allowlist is the set of versions
// the lockfile names for it (transitive duplicates accumulate). When replace is
// true the target rule set is cleared first, so the lockfile becomes the
// complete allowlist (pair with DefaultAction=block for a hard lockfile lock).
// An empty tenant imports into the global rule set.
func (s *Service) ImportLockfile(tenant, format string, content []byte, replace bool) (ImportResult, error) {
	if s == nil {
		return ImportResult{}, fmt.Errorf("dependency firewall is not enabled")
	}
	rules, detected, err := ParseLockfile(format, content)
	if err != nil {
		return ImportResult{}, err
	}
	if len(rules) == 0 {
		return ImportResult{}, fmt.Errorf("lockfile (%s) contained no pinnable dependencies", detected)
	}

	// Compile up front so a bad entry rejects the whole import atomically.
	for i := range rules {
		if err := rules[i].compile(); err != nil {
			return ImportResult{}, err
		}
	}

	versions := 0
	for i := range rules {
		versions += len(rules[i].Pinned)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var m map[string]*Rule
	if strings.TrimSpace(tenant) == "" {
		if replace {
			s.global = make(map[string]*Rule)
		}
		m = s.global
	} else {
		tp := s.tenants[tenant]
		if tp == nil {
			tp = &TenantPolicy{rules: make(map[string]*Rule)}
			s.tenants[tenant] = tp
		}
		if replace {
			tp.rules = make(map[string]*Rule)
		}
		m = tp.rules
	}
	for i := range rules {
		r := rules[i]
		m[ruleKey(r.Ecosystem, r.Name)] = &r
	}

	return ImportResult{
		Format:        detected,
		Source:        rules[0].Source,
		Tenant:        tenant,
		RulesImported: len(rules),
		Versions:      versions,
		Replaced:      replace,
	}, nil
}
