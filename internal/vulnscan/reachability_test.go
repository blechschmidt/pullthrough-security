package vulnscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// --- fixture builders -------------------------------------------------------

// buildGoModuleZip builds an in-memory Go module zip whose entries are prefixed
// with "<modpath>@<version>/", matching the layout the proxy pulls. files maps a
// module-relative path to its contents.
func buildGoModuleZip(t *testing.T, modpath, version string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	prefix := modpath + "@" + version + "/"
	for name, body := range files {
		w, err := zw.Create(prefix + name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// buildNPMTarball builds an in-memory npm tarball (gzip+tar) whose entries are
// prefixed with "package/". files maps a package-relative path to its contents.
func buildNPMTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		full := "package/" + name
		if err := tw.WriteHeader(&tar.Header{
			Name:     full,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(body)),
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

const goModFixture = `module example.com/consumer

go 1.21

require (
	example.com/reached v1.2.0
	example.com/unreached v0.9.0 // indirect
	example.com/directmissing v2.0.0
)
`

const goMainFixture = `package main

import (
	"fmt"

	"example.com/reached/sub"
)

func main() { fmt.Println(sub.Hello()) }
`

// --- Go analyzer tests ------------------------------------------------------

func TestGoReachabilityClassification(t *testing.T) {
	data := buildGoModuleZip(t, "example.com/consumer", "v1.0.0", map[string]string{
		"go.mod":  goModFixture,
		"main.go": goMainFixture,
	})
	idx := analyzeReachability(Artifact{Ecosystem: "go"}, data)
	if !idx.analyzed {
		t.Fatalf("expected analyzed index, reason=%q", idx.reason)
	}

	cases := []struct {
		name string
		key  string
		want Reachability
	}{
		// Imported via a sub-package ("example.com/reached/sub") → reachable by prefix.
		{"direct-imported", "example.com/reached", ReachabilityReachable},
		// Indirect require not imported by any source → unreachable.
		{"indirect-unimported", "example.com/unreached", ReachabilityUnreachable},
		// Declared direct but no import observed → conservative unknown.
		{"direct-unobserved", "example.com/directmissing", ReachabilityUnknown},
		// Not a declared dependency at all → unknown.
		{"undeclared", "example.com/stranger", ReachabilityUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := idx.classify(tc.key, false)
			if got != tc.want {
				t.Fatalf("classify(%q) = %q (%s), want %q", tc.key, got, reason, tc.want)
			}
		})
	}
}

func TestGoReachabilityGoModOnly(t *testing.T) {
	// No source files: the direct/indirect classification is authoritative on its
	// own. Indirect → unreachable; direct → unknown (no import could be observed).
	data := buildGoModuleZip(t, "example.com/consumer", "v1.0.0", map[string]string{
		"go.mod": goModFixture,
	})
	idx := analyzeReachability(Artifact{Ecosystem: "go"}, data)
	if !idx.analyzed {
		t.Fatalf("expected analyzed index from go.mod alone, reason=%q", idx.reason)
	}
	if got, _ := idx.classify("example.com/unreached", false); got != ReachabilityUnreachable {
		t.Fatalf("indirect dep = %q, want unreachable", got)
	}
	if got, _ := idx.classify("example.com/directmissing", false); got != ReachabilityUnknown {
		t.Fatalf("direct dep with no source = %q, want unknown", got)
	}
}

func TestGoReachabilityPrimaryAlwaysReachable(t *testing.T) {
	idx := analyzeReachability(Artifact{Ecosystem: "go"}, []byte("not a zip"))
	if idx.analyzed {
		t.Fatalf("expected unparseable zip to be not analyzed")
	}
	// Even with no usable analysis, the primary component is trivially reachable.
	if got, _ := idx.classify("example.com/consumer", true); got != ReachabilityReachable {
		t.Fatalf("primary = %q, want reachable", got)
	}
	// A dependency, by contrast, is unknown when nothing could be analyzed.
	if got, _ := idx.classify("example.com/dep", false); got != ReachabilityUnknown {
		t.Fatalf("dep with no analysis = %q, want unknown", got)
	}
}

// --- npm analyzer tests -----------------------------------------------------

func TestNPMReachabilityClassification(t *testing.T) {
	pkgJSON := `{
		"name": "consumer",
		"version": "1.0.0",
		"dependencies": { "used-dep": "^1.0.0", "@scope/used": "^2.0.0", "unused-dep": "^3.0.0" }
	}`
	index := `const a = require('used-dep');
import x from '@scope/used/lib';
import './local';
const n = require('node:fs');
`
	data := buildNPMTarball(t, map[string]string{
		"package.json": pkgJSON,
		"index.js":     index,
	})
	idx := analyzeReachability(Artifact{Ecosystem: "npm"}, data)
	if !idx.analyzed {
		t.Fatalf("expected analyzed npm index, reason=%q", idx.reason)
	}
	if idx.dynamic {
		t.Fatalf("did not expect dynamic import flag")
	}
	cases := []struct {
		key  string
		want Reachability
	}{
		{"used-dep", ReachabilityReachable},
		{"@scope/used", ReachabilityReachable},
		{"unused-dep", ReachabilityUnreachable},
		{"USED-DEP", ReachabilityReachable}, // case-insensitive
		{"never-declared", ReachabilityUnknown},
	}
	for _, tc := range cases {
		if got, reason := idx.classify(tc.key, false); got != tc.want {
			t.Fatalf("classify(%q) = %q (%s), want %q", tc.key, got, reason, tc.want)
		}
	}
}

func TestNPMReachabilityDynamicImportYieldsUnknown(t *testing.T) {
	pkgJSON := `{"name":"c","version":"1.0.0","dependencies":{"maybe-dep":"^1.0.0"}}`
	// A dynamic require with a non-literal argument means we cannot prove any
	// declared-but-unimported dependency unreachable.
	src := `const name = process.env.MOD; const m = require(name);`
	data := buildNPMTarball(t, map[string]string{
		"package.json": pkgJSON,
		"index.js":     src,
	})
	idx := analyzeReachability(Artifact{Ecosystem: "npm"}, data)
	if !idx.dynamic {
		t.Fatalf("expected dynamic import flag to be set")
	}
	if got, _ := idx.classify("maybe-dep", false); got != ReachabilityUnknown {
		t.Fatalf("declared dep with dynamic import = %q, want unknown", got)
	}
}

func TestReachabilityUnsupportedEcosystem(t *testing.T) {
	idx := analyzeReachability(Artifact{Ecosystem: "cargo"}, []byte("whatever"))
	if idx.analyzed {
		t.Fatalf("cargo should not be analyzed")
	}
	if got, _ := idx.classify("some-crate", false); got != ReachabilityUnknown {
		t.Fatalf("unsupported ecosystem = %q, want unknown", got)
	}
}

func TestNilIndexClassify(t *testing.T) {
	var idx *reachabilityIndex
	if got, _ := idx.classify("anything", false); got != ReachabilityUnknown {
		t.Fatalf("nil index dep = %q, want unknown", got)
	}
	if got, _ := idx.classify("anything", true); got != ReachabilityReachable {
		t.Fatalf("nil index primary = %q, want reachable", got)
	}
}

func TestNPMPackageName(t *testing.T) {
	cases := []struct {
		spec string
		want string
		ok   bool
	}{
		{"lodash", "lodash", true},
		{"lodash/fp", "lodash", true},
		{"@babel/core", "@babel/core", true},
		{"@babel/core/lib/x", "@babel/core", true},
		{"./local", "", false},
		{"../up", "", false},
		{"/abs", "", false},
		{"node:fs", "", false},
		{"", "", false},
		{"@bad", "", false},
	}
	for _, tc := range cases {
		got, ok := npmPackageName(tc.spec)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("npmPackageName(%q) = (%q,%v), want (%q,%v)", tc.spec, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDowngradeSeverity(t *testing.T) {
	cases := map[Severity]Severity{
		SeverityCritical: SeverityHigh,
		SeverityHigh:     SeverityMedium,
		SeverityMedium:   SeverityLow,
		SeverityLow:      SeverityNone,
		SeverityUnknown:  SeverityNone,
		SeverityNone:     SeverityNone,
	}
	for in, want := range cases {
		if got := downgradeSeverity(in); got != want {
			t.Fatalf("downgradeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- service-level integration ----------------------------------------------

// reachFixtureScanner returns one vuln per component path regardless of the SBOM,
// so the service's reachability application can be exercised end to end.
type reachFixtureScanner struct{ vulns []Vulnerability }

func (r *reachFixtureScanner) Name() string { return "reach-fixture" }
func (r *reachFixtureScanner) Scan(ctx context.Context, sbom *SBOM) ([]Vulnerability, error) {
	return r.vulns, nil
}

func reachOpener(data []byte) ContentOpener {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
}

func goTwoVulnScanner() *reachFixtureScanner {
	return &reachFixtureScanner{vulns: []Vulnerability{
		{ID: "CVE-REACH", Severity: SeverityCritical, CVSS: 9.8, Package: "example.com/reached", Version: "1.2.0"},
		{ID: "CVE-UNREACH", Severity: SeverityCritical, CVSS: 9.1, Package: "example.com/unreached", Version: "0.9.0"},
	}}
}

func TestServiceReachabilitySuppress(t *testing.T) {
	data := buildGoModuleZip(t, "example.com/consumer", "v1.0.0", map[string]string{
		"go.mod":  goModFixture,
		"main.go": goMainFixture,
	})
	svc, err := NewService(Config{
		FailSeverity: SeverityHigh,
		Action:       policy.ActionBlock,
		Reachability: ReachabilityConfig{Enabled: true, UnreachableAction: ReachActionSuppress},
	}, goTwoVulnScanner(), nil)
	if err != nil {
		t.Fatal(err)
	}
	art := Artifact{Ecosystem: "go", Name: "example.com/consumer", Version: "1.0.0", Digest: "sha256:r1"}
	report, _ := svc.Assess(context.Background(), art, reachOpener(data))

	byID := map[string]Vulnerability{}
	for _, v := range report.Vulnerabilities {
		byID[v.ID] = v
	}
	if got := byID["CVE-REACH"].Reachability; got != ReachabilityReachable {
		t.Fatalf("reached finding reachability = %q, want reachable", got)
	}
	unreach := byID["CVE-UNREACH"]
	if unreach.Reachability != ReachabilityUnreachable {
		t.Fatalf("unreached finding reachability = %q, want unreachable", unreach.Reachability)
	}
	if !unreach.ReachSuppressed {
		t.Fatalf("expected unreachable finding to be reach-suppressed")
	}
	// The suppressed finding must be excluded from counts: only the reachable
	// critical remains.
	if report.Counts.Critical != 1 {
		t.Fatalf("critical count = %d, want 1 (suppressed one excluded)", report.Counts.Critical)
	}
	// Both findings are still present in the report for transparency.
	if len(report.Vulnerabilities) != 2 {
		t.Fatalf("report has %d findings, want 2", len(report.Vulnerabilities))
	}
	// The gate still blocks (the reachable critical remains).
	if d := svc.Gate(report); !d.Action.Blocked() {
		t.Fatalf("expected block on reachable critical, got %s", d.Action)
	}
	m := svc.Metrics()
	if m.ReachUnreachable != 1 || m.ReachSuppressed != 1 {
		t.Fatalf("metrics unreachable=%d suppressed=%d, want 1/1", m.ReachUnreachable, m.ReachSuppressed)
	}
}

func TestServiceReachabilityDowngrade(t *testing.T) {
	data := buildGoModuleZip(t, "example.com/consumer", "v1.0.0", map[string]string{
		"go.mod":  goModFixture,
		"main.go": goMainFixture,
	})
	// Only the unreachable finding, so a downgrade is observable in the headline.
	sc := &reachFixtureScanner{vulns: []Vulnerability{
		{ID: "CVE-UNREACH", Severity: SeverityCritical, CVSS: 9.1, Package: "example.com/unreached", Version: "0.9.0"},
	}}
	svc, err := NewService(Config{
		FailSeverity: SeverityCritical,
		Action:       policy.ActionBlock,
		Reachability: ReachabilityConfig{Enabled: true, UnreachableAction: ReachActionDowngrade},
	}, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	art := Artifact{Ecosystem: "go", Name: "example.com/consumer", Version: "1.0.0", Digest: "sha256:r2"}
	report, _ := svc.Assess(context.Background(), art, reachOpener(data))

	v := report.Vulnerabilities[0]
	if v.Severity != SeverityHigh || v.ReachOriginalSeverity != SeverityCritical {
		t.Fatalf("downgrade: severity=%q original=%q, want high/critical", v.Severity, v.ReachOriginalSeverity)
	}
	if report.MaxSeverity != SeverityHigh {
		t.Fatalf("headline severity = %q, want high after downgrade", report.MaxSeverity)
	}
	// FailSeverity is critical; the downgraded high no longer trips it.
	if d := svc.Gate(report); d.Action.Blocked() {
		t.Fatalf("expected allow after downgrade below critical, got %s / %s", d.Action, d.Reason)
	}
}

func TestServiceReachabilityAnnotateDoesNotGate(t *testing.T) {
	data := buildGoModuleZip(t, "example.com/consumer", "v1.0.0", map[string]string{
		"go.mod":  goModFixture,
		"main.go": goMainFixture,
	})
	sc := &reachFixtureScanner{vulns: []Vulnerability{
		{ID: "CVE-UNREACH", Severity: SeverityCritical, CVSS: 9.1, Package: "example.com/unreached", Version: "0.9.0"},
	}}
	svc, _ := NewService(Config{
		FailSeverity: SeverityHigh,
		Action:       policy.ActionBlock,
		Reachability: ReachabilityConfig{Enabled: true, UnreachableAction: ReachActionAnnotate},
	}, sc, nil)
	art := Artifact{Ecosystem: "go", Name: "example.com/consumer", Version: "1.0.0", Digest: "sha256:r3"}
	report, _ := svc.Assess(context.Background(), art, reachOpener(data))

	v := report.Vulnerabilities[0]
	if v.Reachability != ReachabilityUnreachable {
		t.Fatalf("annotate: reachability = %q, want unreachable", v.Reachability)
	}
	if v.ReachSuppressed || v.ReachOriginalSeverity != "" {
		t.Fatalf("annotate must not suppress or downgrade: %+v", v)
	}
	// Annotate leaves gating intact: the critical still blocks.
	if d := svc.Gate(report); !d.Action.Blocked() {
		t.Fatalf("annotate mode must still gate the critical, got %s", d.Action)
	}
}

func TestServiceReachabilityDisabledNoAnnotation(t *testing.T) {
	data := buildGoModuleZip(t, "example.com/consumer", "v1.0.0", map[string]string{
		"go.mod":  goModFixture,
		"main.go": goMainFixture,
	})
	svc, _ := NewService(Config{FailSeverity: SeverityHigh, Action: policy.ActionBlock}, goTwoVulnScanner(), nil)
	art := Artifact{Ecosystem: "go", Name: "example.com/consumer", Version: "1.0.0", Digest: "sha256:r4"}
	report, _ := svc.Assess(context.Background(), art, reachOpener(data))
	for _, v := range report.Vulnerabilities {
		if v.Reachability != "" {
			t.Fatalf("reachability disabled, but %s carries %q", v.ID, v.Reachability)
		}
	}
}

func TestServiceReachabilityDeterministic(t *testing.T) {
	data := buildGoModuleZip(t, "example.com/consumer", "v1.0.0", map[string]string{
		"go.mod":  goModFixture,
		"main.go": goMainFixture,
	})
	run := func() []Reachability {
		svc, _ := NewService(Config{
			FailSeverity: SeverityHigh, Action: policy.ActionBlock,
			Reachability: ReachabilityConfig{Enabled: true, UnreachableAction: ReachActionSuppress},
		}, goTwoVulnScanner(), nil)
		art := Artifact{Ecosystem: "go", Name: "example.com/consumer", Version: "1.0.0", Digest: "sha256:det"}
		report, _ := svc.Assess(context.Background(), art, reachOpener(data))
		out := make([]Reachability, 0, len(report.Vulnerabilities))
		for _, v := range report.Vulnerabilities {
			out = append(out, v.Reachability)
		}
		return out
	}
	first := run()
	for i := 0; i < 5; i++ {
		got := run()
		if len(got) != len(first) {
			t.Fatalf("non-deterministic length: %d vs %d", len(got), len(first))
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("non-deterministic verdict at %d: %q vs %q", j, got[j], first[j])
			}
		}
	}
}
