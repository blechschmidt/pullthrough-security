package vulnscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// vexCritical is a critical finding carrying a concrete component purl so VEX
// product correlation has something to match against.
func vexCritical() Vulnerability {
	return Vulnerability{
		ID:        "CVE-2026-1111",
		Severity:  SeverityCritical,
		CVSS:      9.8,
		Component: "pkg:npm/lodash@4.17.20",
		Package:   "lodash",
		Version:   "4.17.20",
	}
}

func vexArtifact() Artifact {
	return Artifact{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Digest: "sha256:lod"}
}

func newVEXStoreFrom(t *testing.T, docs ...string) *VEXStore {
	t.Helper()
	store := NewVEXStore(nil)
	for i, d := range docs {
		parsed, err := ParseVEX([]byte(d), "doc-"+string(rune('a'+i)))
		if err != nil {
			t.Fatalf("ParseVEX: %v", err)
		}
		store.AddDocument(parsed)
	}
	return store
}

func TestService_VEXSuppressesFinding(t *testing.T) {
	store := newVEXStoreFrom(t, openVEXNotAffected)
	fs := &fakeScanner{vulns: []Vulnerability{vexCritical()}}
	svc, err := NewService(Config{FailSeverity: SeverityHigh, Action: policy.ActionBlock, VEX: store}, fs, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, err := svc.Assess(context.Background(), vexArtifact(), openNil)
	if err != nil {
		t.Fatal(err)
	}
	if report.VEXSuppressed != 1 {
		t.Errorf("VEXSuppressed = %d, want 1", report.VEXSuppressed)
	}
	if report.Counts.Critical != 0 {
		t.Errorf("suppressed finding should not count: %+v", report.Counts)
	}
	if !report.Vulnerabilities[0].Suppressed {
		t.Error("finding should be marked suppressed")
	}
	if report.Vulnerabilities[0].VEXSource == "" {
		t.Error("suppressed finding should record its VEX source for audit")
	}
	// The gate now allows the artifact despite the critical finding.
	if dec := svc.Gate(report); dec.Action != policy.ActionAllow {
		t.Errorf("gate action = %s, want allow (finding suppressed by VEX)", dec.Action)
	}
	if m := svc.Metrics(); m.VEXSuppressed != 1 {
		t.Errorf("metrics VEXSuppressed = %d, want 1", m.VEXSuppressed)
	}
}

const openVEXAffected = `{
	"@context": "https://openvex.dev/ns/v0.2.0",
	"timestamp": "2026-03-01T00:00:00Z",
	"statements": [{
		"vulnerability": {"name": "CVE-2026-2222"},
		"products": [{"@id": "pkg:npm/lodash@4.17.20"}],
		"status": "affected"
	}]
}`

func TestService_VEXEscalatesFinding(t *testing.T) {
	store := newVEXStoreFrom(t, openVEXAffected)
	// A medium finding that would normally pass a high-severity gate.
	med := Vulnerability{ID: "CVE-2026-2222", Severity: SeverityMedium, CVSS: 5.0,
		Component: "pkg:npm/lodash@4.17.20", Package: "lodash", Version: "4.17.20"}
	fs := &fakeScanner{vulns: []Vulnerability{med}}
	svc, err := NewService(Config{FailSeverity: SeverityHigh, Action: policy.ActionBlock, VEX: store}, fs, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, err := svc.Assess(context.Background(), vexArtifact(), openNil)
	if err != nil {
		t.Fatal(err)
	}
	if report.VEXEscalated != 1 {
		t.Errorf("VEXEscalated = %d, want 1", report.VEXEscalated)
	}
	v := report.Vulnerabilities[0]
	if v.Severity != SeverityHigh {
		t.Errorf("escalated severity = %q, want high", v.Severity)
	}
	if v.OriginalSeverity != SeverityMedium {
		t.Errorf("original severity = %q, want medium", v.OriginalSeverity)
	}
	if dec := svc.Gate(report); dec.Action != policy.ActionBlock {
		t.Errorf("gate action = %s, want block (escalated to high)", dec.Action)
	}
}

// TestService_VEXRevocationReQuarantines verifies the CVE-drift integration: a
// finding suppressed by a not_affected VEX statement becomes active again — and is
// re-quarantined by the re-scan loop — once that statement is revoked (the file is
// removed and the directory reloaded).
func TestService_VEXRevocationReQuarantines(t *testing.T) {
	dir := t.TempDir()
	vexPath := filepath.Join(dir, "v.json")
	if err := os.WriteFile(vexPath, []byte(openVEXNotAffected), 0o644); err != nil {
		t.Fatal(err)
	}
	store := NewVEXStore(nil)
	if err := store.LoadDir(dir); err != nil {
		t.Fatal(err)
	}

	fs := &fakeScanner{vulns: []Vulnerability{vexCritical()}}
	svc, err := NewService(Config{FailSeverity: SeverityHigh, Action: policy.ActionBlock, VEX: store}, fs, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Prime the cache: the critical finding is suppressed, so the artifact is clean.
	report, err := svc.Assess(context.Background(), vexArtifact(), openNil)
	if err != nil {
		t.Fatal(err)
	}
	if dec := svc.Gate(report); dec.Action != policy.ActionAllow {
		t.Fatalf("expected initial allow, got %s", dec.Action)
	}
	if svc.IsQuarantined(vexArtifact().Digest) {
		t.Fatal("artifact should not be quarantined while suppressed")
	}

	// Revoke the VEX statement and reload the store.
	if err := os.Remove(vexPath); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadDir(dir); err != nil {
		t.Fatal(err)
	}

	// The re-scan loop re-evaluates the cached artifact; with the suppression gone
	// the critical finding is active again and the artifact is quarantined.
	rescanner := NewRescanner(svc, RescanConfig{}, nil, nil, nil)
	summary := rescanner.RunOnce(context.Background())
	if summary.NewlyVulnerable != 1 {
		t.Errorf("NewlyVulnerable = %d, want 1 (VEX revoked)", summary.NewlyVulnerable)
	}
	if !svc.IsQuarantined(vexArtifact().Digest) {
		t.Error("artifact should be quarantined after VEX revocation")
	}
}

// TestService_VEXSupersedeReQuarantines verifies revocation via a newer affected
// statement superseding an older not_affected one.
func TestService_VEXSupersedeReQuarantines(t *testing.T) {
	store := newVEXStoreFrom(t, openVEXNotAffected)
	fs := &fakeScanner{vulns: []Vulnerability{vexCritical()}}
	svc, err := NewService(Config{FailSeverity: SeverityHigh, Action: policy.ActionBlock, VEX: store}, fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	report, _ := svc.Assess(context.Background(), vexArtifact(), openNil)
	if dec := svc.Gate(report); dec.Action != policy.ActionAllow {
		t.Fatalf("expected initial allow, got %s", dec.Action)
	}

	// A newer "affected" statement for the same product/vuln supersedes the older
	// not_affected one (newest-wins).
	const supersede = `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"timestamp": "2026-12-31T00:00:00Z",
		"statements": [{
			"vulnerability": {"name": "CVE-2026-1111"},
			"products": [{"@id": "pkg:npm/lodash@4.17.20"}],
			"status": "affected"
		}]
	}`
	parsed, err := ParseVEX([]byte(supersede), "supersede.json")
	if err != nil {
		t.Fatal(err)
	}
	store.AddDocument(parsed)

	rescanner := NewRescanner(svc, RescanConfig{}, nil, nil, nil)
	summary := rescanner.RunOnce(context.Background())
	if summary.NewlyVulnerable != 1 {
		t.Errorf("NewlyVulnerable = %d, want 1 (superseded by affected)", summary.NewlyVulnerable)
	}
}
