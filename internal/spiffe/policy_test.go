package spiffe

import (
	"reflect"
	"testing"
)

func TestPolicyResolveGlob(t *testing.T) {
	p, err := NewPolicy(RuleSet{
		Rules: []Rule{
			{Pattern: "spiffe://example.org/ns/payments/sa/*", Tenant: "payments", Roles: []string{"reader"}},
			{Pattern: "spiffe://example.org/ns/**", Tenant: "corp", Roles: []string{"reader"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	m, ok := p.Resolve(mustParse(t, "spiffe://example.org/ns/payments/sa/web"))
	if !ok || m.Tenant != "payments" || !reflect.DeepEqual(m.Roles, []string{"reader"}) {
		t.Fatalf("payments resolve = %+v ok=%v", m, ok)
	}

	// '*' does not cross '/', so a deeper path falls through to the '**' rule.
	m, ok = p.Resolve(mustParse(t, "spiffe://example.org/ns/payments/sa/web/extra"))
	if !ok || m.Tenant != "corp" {
		t.Fatalf("deep path resolve = %+v ok=%v, want corp", m, ok)
	}

	if _, ok := p.Resolve(mustParse(t, "spiffe://other.org/ns/x")); ok {
		t.Fatal("unmatched domain should not resolve")
	}
}

func TestPolicyResolveRegex(t *testing.T) {
	p, err := NewPolicy(RuleSet{
		Rules: []Rule{
			{Pattern: `re:^spiffe://example\.org/ns/.+/sa/ci$`, Tenant: "ci", Roles: []string{"reader", "writer"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := p.Resolve(mustParse(t, "spiffe://example.org/ns/build/sa/ci"))
	if !ok || m.Tenant != "ci" {
		t.Fatalf("ci resolve = %+v ok=%v", m, ok)
	}
	if _, ok := p.Resolve(mustParse(t, "spiffe://example.org/ns/build/sa/web")); ok {
		t.Fatal("non-ci should not match")
	}
}

func TestPolicyDefaultTenant(t *testing.T) {
	p, _ := NewPolicy(RuleSet{
		DefaultTenant: "fallback",
		Rules:         []Rule{{Pattern: "spiffe://example.org/**", Roles: []string{"reader"}}},
	})
	m, ok := p.Resolve(mustParse(t, "spiffe://example.org/ns/x/sa/y"))
	if !ok || m.Tenant != "fallback" {
		t.Fatalf("default tenant resolve = %+v ok=%v", m, ok)
	}
}

func TestPolicyTenantOverride(t *testing.T) {
	p, err := NewPolicy(RuleSet{
		Rules: []Rule{
			{Pattern: "spiffe://example.org/ns/payments/sa/*", Tenant: "payments", Roles: []string{"reader"}},
		},
		TenantOverrides: map[string][]Rule{
			"payments": {
				{Pattern: "spiffe://example.org/ns/payments/sa/admin", Roles: []string{"admin"}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Normal workload gets the base role.
	m, _ := p.Resolve(mustParse(t, "spiffe://example.org/ns/payments/sa/web"))
	if !reflect.DeepEqual(m.Roles, []string{"reader"}) {
		t.Fatalf("web roles = %v, want [reader]", m.Roles)
	}
	// The admin SA's roles are replaced by the override.
	m, _ = p.Resolve(mustParse(t, "spiffe://example.org/ns/payments/sa/admin"))
	if m.Tenant != "payments" || !reflect.DeepEqual(m.Roles, []string{"admin"}) {
		t.Fatalf("admin resolve = %+v, want payments/[admin]", m)
	}
}

func TestPolicyInvalidPattern(t *testing.T) {
	if _, err := NewPolicy(RuleSet{Rules: []Rule{{Pattern: "re:([", Tenant: "x"}}}); err == nil {
		t.Fatal("expected error for invalid regexp")
	}
	if _, err := NewPolicy(RuleSet{Rules: []Rule{{Pattern: "  ", Tenant: "x"}}}); err == nil {
		t.Fatal("expected error for empty pattern")
	}
}

func TestGlobToRegexp(t *testing.T) {
	cases := map[string]struct {
		pattern string
		in      string
		want    bool
	}{
		"star within segment":  {"spiffe://d/sa/*", "spiffe://d/sa/web", true},
		"star stops at slash":  {"spiffe://d/sa/*", "spiffe://d/sa/web/x", false},
		"doublestar crosses":   {"spiffe://d/**", "spiffe://d/a/b/c", true},
		"literal dot escaped":  {"spiffe://ex.org/x", "spiffe://exXorg/x", false},
		"question single char": {"spiffe://d/sa/?", "spiffe://d/sa/a", true},
		"question not slash":   {"spiffe://d/sa/?", "spiffe://d/sa/", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cr, err := compileRule(Rule{Pattern: tc.pattern})
			if err != nil {
				t.Fatal(err)
			}
			if got := cr.match(tc.in); got != tc.want {
				t.Fatalf("match(%q, %q) = %v, want %v", tc.pattern, tc.in, got, tc.want)
			}
		})
	}
}
