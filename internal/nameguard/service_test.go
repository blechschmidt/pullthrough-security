package nameguard

import (
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// newTestService builds a Service with the built-in lists, default thresholds,
// homoglyph detection on, and the supplied internal namespaces.
func newTestService(internal map[string][]string) *Service {
	return NewService(Config{
		InternalNamespaces: internal,
		DetectHomoglyphs:   true,
	}, nil)
}

// findingKinds collects the kinds present in a report for assertions.
func findingKinds(r *Report) map[Kind]Finding {
	m := make(map[Kind]Finding, len(r.Findings))
	for _, f := range r.Findings {
		m[f.Kind] = f
	}
	return m
}

func TestTyposquatTruePositives(t *testing.T) {
	svc := newTestService(nil)
	tests := []struct {
		ecosystem, name, wantSimilar string
		wantSeverity                 Severity
	}{
		{"pip", "reqeusts", "requests", SeverityHigh}, // transposition, distance 1
		{"pip", "numpu", "numpy", SeverityHigh},       // substitution, distance 1
		{"npm", "expres", "express", SeverityHigh},    // deletion, distance 1
		{"npm", "lodahs", "lodash", SeverityHigh},     // transposition, distance 1
		{"npm", "1odash", "lodash", SeverityHigh},     // confusable digit substitution
		{"npm", "rnoment", "moment", SeverityHigh},    // rn->m ligature squat
		{"cargo", "tokoi", "tokio", SeverityHigh},     // transposition
		{"pip", "djangoo", "django", SeverityHigh},    // duplicated char, distance 1
	}
	for _, tt := range tests {
		r := svc.Inspect(Artifact{Ecosystem: tt.ecosystem, Name: tt.name})
		kinds := findingKinds(r)
		f, ok := kinds[KindTyposquat]
		if !ok {
			t.Errorf("%s/%s: expected a typosquat finding, got %+v", tt.ecosystem, tt.name, r.Findings)
			continue
		}
		if f.Similar != tt.wantSimilar {
			t.Errorf("%s/%s: similar = %q, want %q", tt.ecosystem, tt.name, f.Similar, tt.wantSimilar)
		}
		if f.Severity != tt.wantSeverity {
			t.Errorf("%s/%s: severity = %q, want %q", tt.ecosystem, tt.name, f.Severity, tt.wantSeverity)
		}
		// A high-severity typosquat must block under the default policy.
		if d := svc.Gate(r); d.Action != policy.ActionBlock {
			t.Errorf("%s/%s: gate action = %q, want block", tt.ecosystem, tt.name, d.Action)
		}
	}
}

func TestFalsePositiveAvoidance(t *testing.T) {
	svc := newTestService(map[string][]string{
		"npm": {"acme-internal"},
	})
	clean := []struct{ ecosystem, name string }{
		{"pip", "requests"},                     // exact popular
		{"pip", "urllib3"},                      // exact popular
		{"pip", "numpy"},                        // exact popular
		{"npm", "react"},                        // exact popular
		{"npm", "react-dom"},                    // popular + allow
		{"npm", "preact"},                       // legitimate near-neighbor of react (allowlisted)
		{"npm", "vuex"},                         // legitimate near-neighbor of vue (allowlisted)
		{"npm", "lodash"},                       // exact popular
		{"npm", "express"},                      // exact popular
		{"npm", "fs"},                           // below min length, no distance check
		{"npm", "ms"},                           // below min length
		{"cargo", "serde-json"},                 // exact popular
		{"cargo", "serde_json"},                 // underscore variant folds to popular
		{"pip", "my-unique-internal-tool-2026"}, // unrelated, far from everything
		{"npm", "@scope/totally-unique-thing"},  // unrelated scoped name
	}
	for _, c := range clean {
		r := svc.Inspect(Artifact{Ecosystem: c.ecosystem, Name: c.name})
		if r.Flagged() {
			t.Errorf("%s/%s: expected no findings, got %+v", c.ecosystem, c.name, r.Findings)
		}
		if d := svc.Gate(r); d.Action != policy.ActionAllow {
			t.Errorf("%s/%s: expected allow, got %q", c.ecosystem, c.name, d.Action)
		}
	}
}

func TestDependencyConfusion(t *testing.T) {
	svc := newTestService(map[string][]string{
		"npm":   {"acme-internal-utils", "@acme"},
		"pip":   {"acme_secrets"},
		"go":    {"github.com/acme/*"},
		"nuget": {"Acme.Internal.Core"},
	})
	tests := []struct {
		ecosystem, name string
		wantSimilar     string
	}{
		{"npm", "acme-internal-utils", "acme-internal-utils"},    // exact internal name
		{"npm", "@acme/config", "@acme"},                         // internal scope prefix
		{"pip", "acme-secrets", "acme-secrets"},                  // underscore folds to internal
		{"pip", "Acme_Secrets", "acme-secrets"},                  // case + separator fold
		{"go", "github.com/acme/secret-lib", "github.com/acme/"}, // internal go namespace
		{"nuget", "acme.internal.core", "acme.internal.core"},    // case-insensitive nuget
	}
	for _, tt := range tests {
		r := svc.Inspect(Artifact{Ecosystem: tt.ecosystem, Name: tt.name})
		kinds := findingKinds(r)
		f, ok := kinds[KindDependencyConfusion]
		if !ok {
			t.Errorf("%s/%s: expected dependency-confusion finding, got %+v", tt.ecosystem, tt.name, r.Findings)
			continue
		}
		if f.Severity != SeverityCritical {
			t.Errorf("%s/%s: severity = %q, want critical", tt.ecosystem, tt.name, f.Severity)
		}
		if f.Similar != tt.wantSimilar {
			t.Errorf("%s/%s: similar = %q, want %q", tt.ecosystem, tt.name, f.Similar, tt.wantSimilar)
		}
		if d := svc.Gate(r); d.Action != policy.ActionBlock {
			t.Errorf("%s/%s: gate action = %q, want block", tt.ecosystem, tt.name, d.Action)
		}
	}
}

func TestDependencyConfusionBoundary(t *testing.T) {
	// An unrelated owner that merely shares a prefix string must NOT be flagged.
	svc := newTestService(map[string][]string{
		"go":  {"github.com/acme/*"},
		"npm": {"@acme"},
	})
	clean := []struct{ ecosystem, name string }{
		{"go", "github.com/acme-other/lib"}, // different owner, prefix boundary
		{"npm", "@acmecorp/widget"},         // different scope sharing leading chars
	}
	for _, c := range clean {
		r := svc.Inspect(Artifact{Ecosystem: c.ecosystem, Name: c.name})
		if k := findingKinds(r); func() bool { _, ok := k[KindDependencyConfusion]; return ok }() {
			t.Errorf("%s/%s: unexpected dependency-confusion finding: %+v", c.ecosystem, c.name, r.Findings)
		}
	}
}

func TestHomoglyphDetection(t *testing.T) {
	svc := newTestService(nil)

	// Cyrillic 'а' impersonating "react" -> critical (skeleton matches popular).
	r := svc.Inspect(Artifact{Ecosystem: "npm", Name: "reаct"})
	f, ok := findingKinds(r)[KindHomoglyph]
	if !ok {
		t.Fatalf("expected homoglyph finding, got %+v", r.Findings)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("homoglyph severity = %q, want critical", f.Severity)
	}
	if f.Similar != "react" {
		t.Errorf("homoglyph similar = %q, want react", f.Similar)
	}
	if d := svc.Gate(r); d.Action != policy.ActionBlock {
		t.Errorf("gate action = %q, want block", d.Action)
	}

	// A known confusable that does not match any popular name -> high.
	r2 := svc.Inspect(Artifact{Ecosystem: "npm", Name: "wіdget-thing"}) // Cyrillic 'і'
	if f := findingKinds(r2)[KindHomoglyph]; f.Severity != SeverityHigh {
		t.Errorf("unmatched confusable severity = %q, want high", f.Severity)
	}

	// Homoglyph detection can be disabled. Use a name whose only signal is the
	// non-ASCII character and which is not within typo distance of a popular name,
	// so disabling homoglyph detection leaves it clean.
	off := NewService(Config{DetectHomoglyphs: false}, nil)
	if off.Inspect(Artifact{Ecosystem: "npm", Name: "wіdget-thing"}).Flagged() {
		t.Errorf("expected no findings when homoglyph detection is disabled")
	}
}

func TestNamespaceMismatch(t *testing.T) {
	svc := NewService(Config{
		PopularNames:     map[string][]string{"npm": {"@angular/core"}},
		DetectHomoglyphs: true,
	}, nil)

	// A near-miss scope on an otherwise-distant package name fires namespace
	// mismatch (medium) without a typosquat.
	r := svc.Inspect(Artifact{Ecosystem: "npm", Name: "@anggular/some-unrelated-pkg"})
	f, ok := findingKinds(r)[KindNamespaceMismatch]
	if !ok {
		t.Fatalf("expected namespace-mismatch finding, got %+v", r.Findings)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	// Medium severity warns (not blocks) under the default thresholds.
	if d := svc.Gate(r); d.Action != policy.ActionWarn {
		t.Errorf("gate action = %q, want warn", d.Action)
	}

	// The exact known scope is clean.
	if svc.Inspect(Artifact{Ecosystem: "npm", Name: "@angular/forms"}).Flagged() {
		t.Errorf("exact known scope should not be flagged")
	}
}

func TestNewPackageOracle(t *testing.T) {
	oracle := oracleFunc(func(_, name string) (bool, bool) {
		return name == "fresh-package", true
	})
	svc := NewService(Config{AgeOracle: oracle, DetectHomoglyphs: true}, nil)

	r := svc.Inspect(Artifact{Ecosystem: "npm", Name: "fresh-package"})
	if f, ok := findingKinds(r)[KindNewPackage]; !ok || f.Severity != SeverityLow {
		t.Errorf("expected low-severity new-package finding, got %+v", r.Findings)
	}
	// Low severity is below the warn threshold by default -> allow.
	if d := svc.Gate(r); d.Action != policy.ActionAllow {
		t.Errorf("gate action = %q, want allow", d.Action)
	}

	// An established package yields nothing.
	if svc.Inspect(Artifact{Ecosystem: "npm", Name: "established-pkg"}).Flagged() {
		t.Errorf("established package should not be flagged")
	}
}

type oracleFunc func(ecosystem, name string) (bool, bool)

func (f oracleFunc) IsNew(ecosystem, name string) (bool, bool) { return f(ecosystem, name) }

func TestGateActionOverride(t *testing.T) {
	// With Action=warn, even a high-severity typosquat only warns.
	svc := NewService(Config{Action: policy.ActionWarn, DetectHomoglyphs: true}, nil)
	r := svc.Inspect(Artifact{Ecosystem: "pip", Name: "reqeusts"})
	if d := svc.Gate(r); d.Action != policy.ActionWarn {
		t.Errorf("gate action = %q, want warn", d.Action)
	}

	// With FailSeverity=critical, a high typosquat drops to a warning and a
	// critical dependency-confusion still blocks.
	strict := NewService(Config{
		FailSeverity:       SeverityCritical,
		WarnSeverity:       SeverityMedium,
		InternalNamespaces: map[string][]string{"npm": {"acme-internal"}},
		DetectHomoglyphs:   true,
	}, nil)
	if d := strict.Gate(strict.Inspect(Artifact{Ecosystem: "pip", Name: "reqeusts"})); d.Action != policy.ActionWarn {
		t.Errorf("high typosquat under critical-fail: action = %q, want warn", d.Action)
	}
	if d := strict.Gate(strict.Inspect(Artifact{Ecosystem: "npm", Name: "acme-internal"})); d.Action != policy.ActionBlock {
		t.Errorf("critical confusion under critical-fail: action = %q, want block", d.Action)
	}
}

func TestMetrics(t *testing.T) {
	svc := newTestService(map[string][]string{"npm": {"acme-internal"}})
	svc.Gate(svc.Inspect(Artifact{Ecosystem: "pip", Name: "reqeusts"}))      // typosquat -> block
	svc.Gate(svc.Inspect(Artifact{Ecosystem: "npm", Name: "acme-internal"})) // confusion -> block
	svc.Gate(svc.Inspect(Artifact{Ecosystem: "npm", Name: "reаct"}))         // homoglyph -> block
	svc.Gate(svc.Inspect(Artifact{Ecosystem: "pip", Name: "requests"}))      // clean -> allow

	m := svc.Metrics()
	if m.Inspected != 4 {
		t.Errorf("Inspected = %d, want 4", m.Inspected)
	}
	if m.Flagged != 3 {
		t.Errorf("Flagged = %d, want 3", m.Flagged)
	}
	if m.Blocked != 3 {
		t.Errorf("Blocked = %d, want 3", m.Blocked)
	}
	if m.Typosquat != 1 {
		t.Errorf("Typosquat = %d, want 1", m.Typosquat)
	}
	if m.DependencyConfusion != 1 {
		t.Errorf("DependencyConfusion = %d, want 1", m.DependencyConfusion)
	}
	if m.Homoglyph != 1 {
		t.Errorf("Homoglyph = %d, want 1", m.Homoglyph)
	}
}

func TestWorstFindingPrecedence(t *testing.T) {
	// When multiple findings tie on severity, dependency-confusion outranks.
	r := &Report{Findings: []Finding{
		{Kind: KindHomoglyph, Severity: SeverityCritical},
		{Kind: KindDependencyConfusion, Severity: SeverityCritical},
	}}
	if w := r.Worst(); w.Kind != KindDependencyConfusion {
		t.Errorf("worst kind = %q, want dependency-confusion", w.Kind)
	}
}

func TestEmptyAndUnknownInputs(t *testing.T) {
	svc := newTestService(nil)
	// Empty name -> no findings, no panic.
	if svc.Inspect(Artifact{Ecosystem: "pip", Name: ""}).Flagged() {
		t.Errorf("empty name should not be flagged")
	}
	// Unknown ecosystem with no reference set -> no findings (nothing to compare).
	if svc.Inspect(Artifact{Ecosystem: "rubygems", Name: "reqeusts"}).Flagged() {
		t.Errorf("unknown ecosystem should not be flagged without reference data")
	}
}
