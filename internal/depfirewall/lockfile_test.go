package depfirewall

import (
	"testing"
)

func ruleFor(rules []Rule, eco, name string) (Rule, bool) {
	for _, r := range rules {
		if r.Ecosystem == eco && r.Name == name {
			return r, true
		}
	}
	return Rule{}, false
}

func hasVersion(r Rule, v string) bool {
	for _, p := range r.Pinned {
		if p == v {
			return true
		}
	}
	return false
}

func TestParsePackageLockV3(t *testing.T) {
	content := []byte(`{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/@scope/util": {"version": "2.1.0"},
    "node_modules/a/node_modules/left-pad": {"version": "1.2.0"}
  }
}`)
	rules, format, err := ParseLockfile("package-lock.json", content)
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	if format != "package-lock.json" {
		t.Fatalf("format = %q", format)
	}
	lp, ok := ruleFor(rules, "npm", "left-pad")
	if !ok {
		t.Fatalf("left-pad rule missing: %+v", rules)
	}
	if !hasVersion(lp, "1.3.0") || !hasVersion(lp, "1.2.0") {
		t.Fatalf("left-pad should pin both transitive versions, got %v", lp.Pinned)
	}
	if _, ok := ruleFor(rules, "npm", "@scope/util"); !ok {
		t.Fatalf("scoped package missing: %+v", rules)
	}
}

func TestParsePackageLockV1(t *testing.T) {
	content := []byte(`{
  "name": "app",
  "lockfileVersion": 1,
  "dependencies": {
    "left-pad": {"version": "1.3.0"},
    "minimist": {"version": "1.2.6", "dependencies": {"left-pad": {"version": "1.1.0"}}}
  }
}`)
	rules, _, err := ParseLockfile("auto", content)
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	lp, ok := ruleFor(rules, "npm", "left-pad")
	if !ok || !hasVersion(lp, "1.3.0") || !hasVersion(lp, "1.1.0") {
		t.Fatalf("nested v1 deps not collected: %+v", rules)
	}
}

func TestParseRequirements(t *testing.T) {
	content := []byte(`
# comment
requests==2.31.0
Flask==2.0.1  # inline comment
urllib3==1.26.5 ; python_version < "3.10"
ignored>=1.0
numpy==1.24.*
django[argon2]==4.2.0
`)
	rules, format, err := ParseLockfile("requirements.txt", content)
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	if format != "requirements.txt" {
		t.Fatalf("format = %q", format)
	}
	if r, ok := ruleFor(rules, "pip", "requests"); !ok || !hasVersion(r, "2.31.0") {
		t.Fatalf("requests pin missing: %+v", rules)
	}
	if r, ok := ruleFor(rules, "pip", "flask"); !ok || !hasVersion(r, "2.0.1") {
		t.Fatalf("flask (normalized) pin missing: %+v", rules)
	}
	if _, ok := ruleFor(rules, "pip", "ignored"); ok {
		t.Fatalf("non-== specifier should be skipped")
	}
	if _, ok := ruleFor(rules, "pip", "numpy"); ok {
		t.Fatalf("wildcard pin should be skipped")
	}
	if r, ok := ruleFor(rules, "pip", "django"); !ok || !hasVersion(r, "4.2.0") {
		t.Fatalf("extras name should normalize and pin: %+v", rules)
	}
}

func TestParseGoSum(t *testing.T) {
	content := []byte(`golang.org/x/crypto v0.17.0 h1:abc=
golang.org/x/crypto v0.17.0/go.mod h1:def=
github.com/pkg/errors v0.9.1 h1:ghi=
github.com/pkg/errors v0.9.1/go.mod h1:jkl=
`)
	rules, format, err := ParseLockfile("go.sum", content)
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	if format != "go.sum" {
		t.Fatalf("format = %q", format)
	}
	r, ok := ruleFor(rules, "go", "golang.org/x/crypto")
	if !ok {
		t.Fatalf("crypto rule missing: %+v", rules)
	}
	if len(r.Pinned) != 1 || r.Pinned[0] != "v0.17.0" {
		t.Fatalf("go.sum should dedup the /go.mod line: %v", r.Pinned)
	}
}

func TestParseCargoLock(t *testing.T) {
	content := []byte(`# auto-generated
version = 3

[[package]]
name = "serde"
version = "1.0.197"

[[package]]
name = "tokio"
version = "1.36.0"
dependencies = ["mio"]

[metadata]
foo = "bar"
`)
	rules, format, err := ParseLockfile("Cargo.lock", content)
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	if format != "Cargo.lock" {
		t.Fatalf("format = %q", format)
	}
	if r, ok := ruleFor(rules, "cargo", "serde"); !ok || !hasVersion(r, "1.0.197") {
		t.Fatalf("serde pin missing: %+v", rules)
	}
	if r, ok := ruleFor(rules, "cargo", "tokio"); !ok || !hasVersion(r, "1.36.0") {
		t.Fatalf("tokio pin missing: %+v", rules)
	}
}

func TestImportLockfileEnforces(t *testing.T) {
	s := mustService(t, Config{DefaultAction: ActionBlock})
	lock := []byte(`{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}`)
	res, err := s.ImportLockfile("team", "package-lock.json", lock, true)
	if err != nil {
		t.Fatalf("ImportLockfile: %v", err)
	}
	if res.RulesImported != 1 || res.Versions != 1 {
		t.Fatalf("unexpected import result: %+v", res)
	}
	// The lockfile-resolved version passes; a different version is blocked.
	if d := s.Check("team", Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}); d.Blocked {
		t.Fatalf("lockfile-approved version should pass, got %+v", d)
	}
	if d := s.Check("team", Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.1"}); !d.Blocked {
		t.Fatalf("non-lockfile version should be blocked, got %+v", d)
	}
	// A package not in the lockfile is denied by default for this strict tenant.
	if d := s.Check("team", Coordinate{Ecosystem: "npm", Name: "other", Version: "1.0.0"}); !d.Blocked {
		t.Fatalf("non-lockfile package should be denied-by-default, got %+v", d)
	}
}

func TestDetectFormat(t *testing.T) {
	cases := map[string]string{
		`{"lockfileVersion":3}`:         "package-lock.json",
		"[[package]]\nname=\"x\"":       "cargo.lock",
		"example.com/m v1.0.0 h1:x=":    "go.sum",
		"requests==2.0.0\nflask==1.0.0": "requirements.txt",
	}
	for content, want := range cases {
		if got := detectFormat([]byte(content)); got != want {
			t.Errorf("detectFormat(%q) = %q, want %q", content, got, want)
		}
	}
}
