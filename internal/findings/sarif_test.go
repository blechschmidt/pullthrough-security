package findings

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// update regenerates the golden SARIF files when set (-update).
var update = flag.Bool("update", false, "update golden SARIF files")

// fixedTime is a deterministic timestamp so golden output is stable.
var fixedTime = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

// richInput exercises every gate so the golden file covers the full taxonomy.
func richInput() (policyengine.Input, Options) {
	in := policyengine.Input{
		Tenant: "acme",
		Artifact: policyengine.ArtifactInput{
			Ecosystem: "npm",
			Backend:   "npmjs",
			Name:      "left-pad",
			Version:   "1.3.0",
			Digest:    "sha256:abc123",
		},
		Vuln: &policyengine.VulnInput{
			Scanned:       true,
			Scanner:       "osv",
			MaxSeverity:   "critical",
			MaxCVSS:       9.8,
			Total:         2,
			CriticalCount: 1,
			HighCount:     1,
			Findings: []policyengine.VulnFinding{
				{ID: "CVE-2024-0001", Severity: "critical", CVSS: 9.8, Package: "left-pad", Version: "1.3.0", Fixed: []string{"1.3.1"}},
				{ID: "CVE-2023-9999", Severity: "high", CVSS: 7.5, Package: "transitive-dep", Version: "0.1.0", Suppressed: true, VEXStatus: "not_affected", VEXJustification: "vulnerable_code_not_in_execute_path"},
			},
		},
		License: &policyengine.LicenseInput{
			Evaluated: true,
			Action:    "block",
			Code:      "denied",
			Findings: []policyengine.LicenseFinding{
				{Component: "left-pad", Outcome: "denied", License: "GPL-3.0-only", Category: "copyleft"},
				{Component: "left-pad", License: "MIT", Drift: true},
			},
		},
		Secret: &policyengine.SecretInput{
			Scanned:      true,
			FindingCount: 1,
			MaxSeverity:  "high",
			Risk:         80,
			Findings: []policyengine.SecretFinding{
				{RuleID: "aws-access-key", Severity: "high", File: "dist/config.js"},
			},
		},
		Signature: &policyengine.SignatureInput{
			Checked:      true,
			Source:       "npm",
			HasSignature: false,
			Verified:     false,
			Error:        "no publish attestation found",
		},
		Nameguard: &policyengine.NameguardInput{
			Scanned:      true,
			FindingCount: 1,
			MaxSeverity:  "high",
			Typosquat:    true,
			Findings: []policyengine.NameguardFinding{
				{Kind: "typosquat", Severity: "high", Name: "left-pad", Similar: "leftpad", Distance: 1},
			},
		},
		Provenance: &policyengine.ProvenanceInput{
			Found:         true,
			Confidence:    "claimed",
			ChainTrusted:  false,
			CommitSHA:     "0123456789abcdef0123456789abcdef01234567",
			RepositoryURL: "https://github.com/example/left-pad",
		},
	}
	opts := Options{
		GeneratedAt: fixedTime,
		Risk: &RiskSignal{
			Score:   82,
			Band:    "high",
			Exceeds: true,
			Action:  "block",
			Summary: "risk 82/100 (high) — top drivers: vulnerability +40.0, secret +20.0",
		},
		Policy: &PolicySignal{
			Action: "deny",
			Reason: "critical CVE on unsigned artifact",
			Matches: []PolicyMatch{
				{RuleID: "deny-critical-unsigned", Action: "deny", Reason: "critical CVE on unsigned artifact"},
			},
		},
	}
	return in, opts
}

func TestSARIFGoldenRich(t *testing.T) {
	in, opts := richInput()
	doc := FromInput(in, opts)
	log := doc.SARIF(SARIFOptions{ToolVersion: "test"})
	assertGolden(t, "rich.sarif.json", log)
}

func TestSARIFGoldenClean(t *testing.T) {
	// An artifact that passes every gate produces an empty-results SARIF log.
	in := policyengine.Input{
		Tenant:   "acme",
		Artifact: policyengine.ArtifactInput{Ecosystem: "go", Name: "golang.org/x/text", Version: "v0.14.0"},
		Vuln:     &policyengine.VulnInput{Scanned: true, Scanner: "osv"},
		Signature: &policyengine.SignatureInput{
			Checked: true, Source: "cosign", Verified: true, CryptoValid: true, ChainTrusted: true, IdentityTrusted: true,
		},
		License:    &policyengine.LicenseInput{Evaluated: true, Action: "allow", Code: "ok", Allowed: true},
		Provenance: &policyengine.ProvenanceInput{Found: true, Confidence: "attested", ChainTrusted: true, CommitSHA: "deadbeef"},
	}
	doc := FromInput(in, Options{GeneratedAt: fixedTime})
	if len(doc.Findings) != 0 {
		t.Fatalf("expected no findings for a clean artifact, got %d: %+v", len(doc.Findings), doc.Findings)
	}
	log := doc.SARIF(SARIFOptions{ToolVersion: "test"})
	assertGolden(t, "clean.sarif.json", log)
}

func TestSARIFBatchGolden(t *testing.T) {
	in, opts := richInput()
	doc1 := FromInput(in, opts)

	in2 := policyengine.Input{
		Tenant:   "acme",
		Artifact: policyengine.ArtifactInput{Ecosystem: "pip", Name: "requests", Version: "2.31.0"},
		Nameguard: &policyengine.NameguardInput{
			Scanned: true, FindingCount: 1, DependencyConfusion: true,
			Findings: []policyengine.NameguardFinding{{Kind: "dependency-confusion", Severity: "critical", Name: "requests", Similar: "internal-requests"}},
		},
	}
	doc2 := FromInput(in2, Options{GeneratedAt: fixedTime})

	log := SARIFFromDocuments([]Document{doc1, doc2}, SARIFOptions{ToolVersion: "test"})
	assertGolden(t, "batch.sarif.json", log)
}

// assertGolden compares the rendered SARIF against the golden file, regenerating
// it under -update. It also validates SARIF 2.1.0 structural conformance.
func assertGolden(t *testing.T, name string, log Log) {
	t.Helper()
	validateSARIF(t, log)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(log); err != nil {
		t.Fatalf("encoding SARIF: %v", err)
	}
	got := buf.Bytes()

	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("writing golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden %s (run with -update to create): %v", path, err)
	}
	if !bytes.Equal(bytes.TrimRight(got, "\n"), bytes.TrimRight(want, "\n")) {
		t.Errorf("SARIF mismatch for %s.\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}
