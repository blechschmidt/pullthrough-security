package presets

import (
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

func TestRegistryHasThreePresets(t *testing.T) {
	names := Names()
	want := map[string]bool{"slsa-l3": false, "nist-ssdf": false, "baseline-hardened": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("missing preset %q (have %v)", n, names)
		}
	}
}

func TestGetUnknownPreset(t *testing.T) {
	if _, err := Get("does-not-exist"); err == nil {
		t.Fatal("expected error for unknown preset")
	}
}

func TestEveryPresetProjectsToValidConfig(t *testing.T) {
	base := config.Default()
	for _, p := range All() {
		t.Run(p.Name, func(t *testing.T) {
			d, err := p.Diff(&base)
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}
			if d.Validation == nil {
				t.Fatal("expected a validation report")
			}
			if !d.Validation.OK {
				t.Fatalf("projected config invalid: %d errors: %+v", d.Validation.Errors, d.Validation.Issues)
			}
			if d.Changed == 0 {
				t.Fatal("expected the preset to change at least one setting vs defaults")
			}
			if len(d.Settings) != len(p.Settings) {
				t.Fatalf("setting count mismatch: diff %d, preset %d", len(d.Settings), len(p.Settings))
			}
			if d.RunningFingerprint == d.ProposedFingerprint {
				t.Fatal("expected fingerprints to differ after projection")
			}
			if len(d.Controls) == 0 {
				t.Fatal("expected the preset to declare satisfied controls")
			}
		})
	}
}

func TestDiffIsIdempotentOnProjectedConfig(t *testing.T) {
	base := config.Default()
	p, err := Get("slsa-l3")
	if err != nil {
		t.Fatal(err)
	}
	projected, err := p.Project(&base)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	// Re-diffing against the already-projected config should report no changes.
	d, err := p.Diff(projected)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if d.Changed != 0 {
		var changed []string
		for _, s := range d.Settings {
			if s.Changed {
				changed = append(changed, s.Path+": "+s.Current+"->"+s.Proposed)
			}
		}
		t.Fatalf("expected idempotent diff, got %d changes: %v", d.Changed, changed)
	}
}

func TestPatchOnDiskPreservesUnrelatedKeysAndComments(t *testing.T) {
	raw := []byte("# my config\nserver:\n  httpAddr: \":9999\"\nsigverify:\n  enabled: false\n")
	p, err := Get("slsa-l3")
	if err != nil {
		t.Fatal(err)
	}
	patched, err := p.PatchOnDisk(raw)
	if err != nil {
		t.Fatalf("PatchOnDisk: %v", err)
	}
	out := string(patched)
	if !strings.Contains(out, "# my config") {
		t.Errorf("comment was dropped:\n%s", out)
	}
	if !strings.Contains(out, "httpAddr") {
		t.Errorf("unrelated key was dropped:\n%s", out)
	}
	// The patched doc must load over the defaults and validate.
	if rep := config.CheckBytes(patched); !rep.OK {
		t.Fatalf("patched config invalid: %+v", rep.Issues)
	}
	// And sigverify.enabled must now be true.
	cfg, err := decodeConfig(patched)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sigverify.Enabled {
		t.Error("expected sigverify.enabled=true after patch")
	}
}

func TestPatchOnDiskFromEmpty(t *testing.T) {
	p, err := Get("nist-ssdf")
	if err != nil {
		t.Fatal(err)
	}
	patched, err := p.PatchOnDisk(nil)
	if err != nil {
		t.Fatalf("PatchOnDisk: %v", err)
	}
	if rep := config.CheckBytes(patched); !rep.OK {
		t.Fatalf("patched config invalid: %+v", rep.Issues)
	}
	if !strings.Contains(string(patched), "deny:") {
		t.Errorf("expected license deny sequence in output:\n%s", patched)
	}
}

func TestSimulateReusesSimreplay(t *testing.T) {
	p, err := Get("slsa-l3")
	if err != nil {
		t.Fatal(err)
	}
	// A record for an unsigned artifact with an unresolved critical CVE — the
	// default policy bundle denies this, so under the preset's enforced policy it
	// must be blocked.
	rec := simreplay.Record{
		Seq:        1,
		Tenant:     "team-a",
		Coordinate: "npm:evil@1.0.0",
		Input: policyengine.Input{
			Tenant: "team-a",
			// An unsigned artifact with an unresolved critical CVE: the default
			// bundle's deny-critical-cve-unsigned rule denies this.
			Vuln: &policyengine.VulnInput{Scanned: true, CriticalCount: 1},
		},
	}
	report, err := p.Simulate([]simreplay.Record{rec}, simreplay.Options{})
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if report.Summary.Total != 1 {
		t.Fatalf("expected 1 record, got %d", report.Summary.Total)
	}
	if report.Summary.CandidateBlocked != 1 {
		t.Errorf("expected the candidate to block the malicious record, summary=%+v", report.Summary)
	}
}
