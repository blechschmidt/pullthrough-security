package spiffe

import (
	"fmt"
	"regexp"
	"strings"
)

// Rule maps SPIFFE IDs matching a pattern to a tenant and a set of roles
// (capabilities). Patterns are matched against the canonical SPIFFE ID string
// (e.g. "spiffe://example.org/ns/prod/sa/web").
//
// Pattern is a glob by default: '*' matches any run of non-'/' characters and
// '**' matches across '/' separators, so "spiffe://example.org/ns/prod/sa/*"
// matches every service account in the prod namespace while
// "spiffe://example.org/ns/**" matches the whole domain subtree. A pattern
// prefixed with "re:" is compiled as a Go regular expression instead, anchored
// at both ends, for operators who need finer control.
type Rule struct {
	Pattern string
	Tenant  string
	Roles   []string
}

// RuleSet declares the identity-mapping policy: an ordered list of global rules
// (first match wins), an optional default tenant for matched IDs whose rule
// names none, and per-tenant override rules consulted after a global rule has
// selected a tenant.
type RuleSet struct {
	Rules         []Rule
	DefaultTenant string
	// TenantOverrides maps a tenant name to override rules. After a global rule
	// resolves an ID to tenant T, the override rules for T (if any) are evaluated
	// against the same ID; the first that matches replaces the role set. This
	// lets an operator grant elevated capabilities to a specific workload within
	// a tenant without duplicating the global rule.
	TenantOverrides map[string][]Rule
}

// Mapping is the result of resolving a SPIFFE ID against a Policy.
type Mapping struct {
	Tenant string
	Roles  []string
}

// Policy is a compiled, immutable identity-mapping policy.
type Policy struct {
	rules         []compiledRule
	defaultTenant string
	overrides     map[string][]compiledRule
}

type compiledRule struct {
	raw    string
	tenant string
	roles  []string
	re     *regexp.Regexp // the matcher (glob patterns are translated to a regexp)
}

// NewPolicy compiles a RuleSet into a Policy, validating every pattern.
func NewPolicy(rs RuleSet) (*Policy, error) {
	p := &Policy{defaultTenant: strings.TrimSpace(rs.DefaultTenant)}
	for i, r := range rs.Rules {
		cr, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("spiffe: rule %d: %w", i, err)
		}
		p.rules = append(p.rules, cr)
	}
	if len(rs.TenantOverrides) > 0 {
		p.overrides = make(map[string][]compiledRule, len(rs.TenantOverrides))
		for tenant, rules := range rs.TenantOverrides {
			tenant = strings.TrimSpace(tenant)
			for i, r := range rules {
				cr, err := compileRule(r)
				if err != nil {
					return nil, fmt.Errorf("spiffe: tenant %q override rule %d: %w", tenant, i, err)
				}
				p.overrides[tenant] = append(p.overrides[tenant], cr)
			}
		}
	}
	return p, nil
}

func compileRule(r Rule) (compiledRule, error) {
	pat := strings.TrimSpace(r.Pattern)
	if pat == "" {
		return compiledRule{}, fmt.Errorf("empty pattern")
	}
	cr := compiledRule{raw: pat, tenant: strings.TrimSpace(r.Tenant), roles: dedupeRoles(r.Roles)}
	var src string
	if rest, ok := strings.CutPrefix(pat, "re:"); ok {
		src = "^(?:" + rest + ")$"
	} else {
		src = globToRegexp(pat)
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return compiledRule{}, fmt.Errorf("invalid pattern %q: %w", pat, err)
	}
	cr.re = re
	return cr, nil
}

func (c compiledRule) match(id string) bool {
	return c.re != nil && c.re.MatchString(id)
}

// Resolve maps a SPIFFE ID to a tenant and roles. It returns ok=false when no
// global rule matches (the identity is authenticated but unmapped, which the
// authenticator treats as forbidden).
func (p *Policy) Resolve(id ID) (Mapping, bool) {
	if p == nil {
		return Mapping{}, false
	}
	s := id.String()
	for _, r := range p.rules {
		if !r.match(s) {
			continue
		}
		tenant := r.tenant
		if tenant == "" {
			tenant = p.defaultTenant
		}
		roles := r.roles
		if ov, ok := p.overrides[tenant]; ok {
			for _, o := range ov {
				if o.match(s) {
					roles = o.roles
					break
				}
			}
		}
		return Mapping{Tenant: tenant, Roles: append([]string(nil), roles...)}, true
	}
	return Mapping{}, false
}

// globToRegexp converts a glob into an anchored regular-expression source.
// '**' matches any characters (including '/'); a single '*' matches any run of
// characters except '/'; '?' matches a single non-'/' character. All other
// regexp metacharacters are escaped so the pattern is literal otherwise.
func globToRegexp(glob string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return b.String()
}

func dedupeRoles(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
