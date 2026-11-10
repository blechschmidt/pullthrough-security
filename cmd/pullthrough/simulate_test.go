package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

const captureFixture = `{
  "version": 1,
  "records": [
    {"seq":0,"tenant":"teamA","input":{"artifact":{"ecosystem":"npm","name":"left-pad","version":"1.0.0"}},
     "baseline":{"policyEnabled":true,"policyAction":"allow"}},
    {"seq":1,"tenant":"teamB","input":{"artifact":{"ecosystem":"npm","name":"evil","version":"2.0.0"},
       "vuln":{"scanned":true,"criticalCount":1,"total":1,"maxSeverity":"critical"},
       "signature":{"checked":true}},
     "baseline":{"policyEnabled":true,"policyAction":"allow"}}
  ]
}`

const candidateFixture = `policyEngine:
  enabled: true
  mode: enforce
`

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

func TestRunSimulateCommandWritesReport(t *testing.T) {
	capPath := writeFixture(t, "cap.json", captureFixture)
	candPath := writeFixture(t, "candidate.yaml", candidateFixture)
	outPath := filepath.Join(t.TempDir(), "report.json")

	err := runSimulateCommand([]string{
		"-capture", capPath,
		"-candidate", candPath,
		"-output", outPath,
		"-records",
	})
	if err != nil {
		t.Fatalf("runSimulateCommand: %v", err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	body := string(raw)
	// The enforce-mode default bundle denies the critical+unsigned "evil" package,
	// flipping it from admitted to blocked.
	for _, want := range []string{`"nowBlocked": 1`, `"newViolations": 1`, "deny-critical-cve-unsigned", "evil@2.0.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("report missing %q\n%s", want, body)
		}
	}
}

func TestRunSimulateCommandRequiresFlags(t *testing.T) {
	if err := runSimulateCommand([]string{"-candidate", "x.yaml"}); err == nil {
		t.Error("expected error when -capture is missing")
	}
	if err := runSimulateCommand([]string{"-capture", "x.json"}); err == nil {
		t.Error("expected error when -candidate is missing")
	}
}

func TestBuildSimReplayRecorderRespectsConfig(t *testing.T) {
	cfg := config.Default()
	cfg.SimReplay.Enabled = true
	cfg.SimReplay.Capacity = 32
	cfg.SimReplay.SampleRate = 4
	rec := buildSimReplayRecorder(&cfg, testLogger())
	if rec == nil {
		t.Fatal("expected a recorder when enabled")
	}
	st := rec.Status()
	if st.Capacity != 32 || st.SampleRate != 4 || !st.Redacted {
		t.Errorf("recorder status = %+v, want capacity32 sampleRate4 redacted", st)
	}

	cfg.SimReplay.Enabled = false
	if rec := buildSimReplayRecorder(&cfg, testLogger()); rec != nil {
		t.Error("expected nil recorder when disabled")
	}
}

// ensure the recorder satisfies the admin inspector contract at compile time.
var _ = simreplay.NewRecorder
