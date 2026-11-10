package contentscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"io"
	"strings"
	"testing"
)

// --- archive builders --------------------------------------------------------

func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func rawTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	return buf.Bytes()
}

func zipBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// gemBytes builds a .gem: an uncompressed outer tar carrying data.tar.gz (the
// gem's real files) plus a trivial metadata entry.
func gemBytes(t *testing.T, dataFiles map[string][]byte) []byte {
	t.Helper()
	inner := tarGz(t, dataFiles)
	return rawTar(t, map[string][]byte{
		"metadata.gz": gzipBytes(t, []byte("--- !ruby/object:Gem::Specification\nname: x\n")),
		"data.tar.gz": inner,
	})
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(data)
	gw.Close()
	return buf.Bytes()
}

// highEntropyBytes returns n deterministic near-random bytes (chained SHA-256),
// including NUL bytes so the content reads as binary.
func highEntropyBytes(n int) []byte {
	out := make([]byte, 0, n)
	seed := sha256.Sum256([]byte("contentscan-seed"))
	for len(out) < n {
		seed = sha256.Sum256(seed[:])
		out = append(out, seed[:]...)
	}
	return out[:n]
}

func opener(b []byte) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
}

func mustService(t *testing.T, cfg Config) *Service {
	t.Helper()
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func assess(t *testing.T, svc *Service, art Artifact, archive []byte) *Report {
	t.Helper()
	rep, err := svc.Assess(context.Background(), art, opener(archive))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	return rep
}

func hasCategory(rep *Report, cat string) bool {
	for _, f := range rep.Findings {
		if f.Category == cat {
			return true
		}
	}
	return false
}

// --- tests -------------------------------------------------------------------

func TestConfigValidate(t *testing.T) {
	if _, err := NewService(Config{Action: "nope"}); err == nil {
		t.Fatal("expected invalid action error")
	}
	if _, err := NewService(Config{FailSeverity: "extreme"}); err == nil {
		t.Fatal("expected invalid severity error")
	}
	if _, err := NewService(Config{EntropyThreshold: 9}); err == nil {
		t.Fatal("expected entropy-range error")
	}
	if _, err := NewService(DefaultConfig()); err != nil {
		t.Fatalf("default config must validate: %v", err)
	}
}

func TestEmbeddedBinaryInSourcePackage(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x01}, 2048)...)
	arc := tarGz(t, map[string][]byte{"package/index.js": []byte("module.exports = 1\n"), "package/prebuilt.node": elf})
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1", Filename: "x-1.tgz"}, arc)
	if !rep.Inspected || !hasCategory(rep, "embedded-binary") {
		t.Fatalf("expected embedded-binary finding, got %+v", rep.Findings)
	}
	if rep.MaxSeverity != SeverityHigh {
		t.Fatalf("expected high severity, got %q", rep.MaxSeverity)
	}
}

func TestBinaryExpectedInWheelSuppressed(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x02}, 2048)...)
	// A wheel is a zip; a compiled .so inside it is expected (manylinux wheels ship
	// native code), so no embedded-binary finding should be raised.
	arc := zipBytes(t, map[string][]byte{"pkg/_speedups.so": elf, "pkg/__init__.py": []byte("x = 1\n")})
	rep := assess(t, svc, Artifact{Ecosystem: "pip", Name: "x", Version: "1", Filename: "x-1-cp311-manylinux.whl"}, arc)
	if hasCategory(rep, "embedded-binary") {
		t.Fatalf("binary in a wheel must not be flagged, got %+v", rep.Findings)
	}
}

func TestHighEntropyBlob(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	arc := tarGz(t, map[string][]byte{"package/payload.dat": highEntropyBytes(4096), "package/index.js": []byte("ok\n")})
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, arc)
	if !hasCategory(rep, "high-entropy-blob") {
		t.Fatalf("expected high-entropy-blob finding, got %+v", rep.Findings)
	}
}

func TestHighEntropyExpectedExtensionNotFlagged(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	// A .png with high-entropy content is unremarkable and must not be flagged.
	arc := tarGz(t, map[string][]byte{"package/logo.png": highEntropyBytes(4096)})
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, arc)
	if hasCategory(rep, "high-entropy-blob") {
		t.Fatalf("high-entropy .png must not be flagged, got %+v", rep.Findings)
	}
}

func TestObfuscatedJS(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	minified := "var a=1;" + strings.Repeat("b=b+1;", 300) + "eval(atob('Zm9v'));"
	arc := tarGz(t, map[string][]byte{"package/bundle.min.js": []byte(minified)})
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, arc)
	if !hasCategory(rep, "obfuscated-code") {
		t.Fatalf("expected obfuscated-code finding, got %+v", rep.Findings)
	}
}

func TestDynamicExecSinks(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	js := "const x = eval(atob('cm0gLXJm'));\n"
	py := "import os\nos.system('rm -rf /')\n"
	arc := tarGz(t, map[string][]byte{"package/a.js": []byte(js), "package/b.py": []byte(py)})
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, arc)
	if !hasCategory(rep, "dynamic-exec") {
		t.Fatalf("expected dynamic-exec finding, got %+v", rep.Findings)
	}
	// The base64-decode-then-eval combo must be high severity.
	var sawHigh bool
	for _, f := range rep.Findings {
		if f.Category == "dynamic-exec" && f.Severity == SeverityHigh {
			sawHigh = true
		}
	}
	if !sawHigh {
		t.Fatalf("expected a high-severity decode-then-exec finding, got %+v", rep.Findings)
	}
}

func TestInSourceSecret(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	src := "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"
	arc := tarGz(t, map[string][]byte{"package/config.js": []byte(src)})
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, arc)
	if !hasCategory(rep, "embedded-secret") {
		t.Fatalf("expected embedded-secret finding, got %+v", rep.Findings)
	}
	// The raw secret must never appear verbatim in a finding.
	for _, f := range rep.Findings {
		if strings.Contains(f.Excerpt, "AKIAIOSFODNN7EXAMPLE") {
			t.Fatalf("finding leaked the raw secret: %q", f.Excerpt)
		}
	}
}

func TestGemNestedTarScanned(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x03}, 2048)...)
	arc := gemBytes(t, map[string][]byte{"ext/evil.so": elf, "lib/x.rb": []byte("puts 1\n")})
	rep := assess(t, svc, Artifact{Ecosystem: "rubygems", Name: "x", Version: "1", Filename: "x-1.gem"}, arc)
	if !rep.Inspected {
		t.Fatalf("gem should have been inspected")
	}
	if !hasCategory(rep, "embedded-binary") {
		t.Fatalf("expected embedded-binary from the gem's data.tar.gz, got %+v", rep.Findings)
	}
}

func TestActionBlockRefuses(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Action = ActionBlock
	cfg.FailSeverity = SeverityHigh
	svc := mustService(t, cfg)
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x04}, 2048)...)
	arc := tarGz(t, map[string][]byte{"package/x.node": elf})
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, arc)
	dec := svc.Gate(rep)
	if dec.Outcome != OutcomeRefuse || !dec.Evict {
		t.Fatalf("expected refuse+evict, got %+v", dec)
	}
}

func TestActionAnnotateServes(t *testing.T) {
	svc := mustService(t, DefaultConfig()) // annotate
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x05}, 2048)...)
	arc := tarGz(t, map[string][]byte{"package/x.node": elf})
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, arc)
	if dec := svc.Gate(rep); dec.Outcome != OutcomeAllow {
		t.Fatalf("annotate must allow, got %+v", dec)
	}
}

func TestActionDowngradeLowersSeverity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Action = ActionDowngrade
	svc := mustService(t, cfg)
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x06}, 2048)...)
	arc := tarGz(t, map[string][]byte{"package/x.node": elf})
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, arc)
	// The embedded-binary finding is high; downgrade lowers it to medium.
	if rep.MaxSeverity != SeverityMedium {
		t.Fatalf("downgrade should lower high->medium, got %q", rep.MaxSeverity)
	}
	if dec := svc.Gate(rep); dec.Outcome != OutcomeAllow {
		t.Fatalf("downgrade must allow, got %+v", dec)
	}
}

func TestEcosystemGating(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x07}, 2048)...)
	arc := tarGz(t, map[string][]byte{"blob.node": elf})
	// docker is not in the default source-package set; the gate must not apply.
	rep := assess(t, svc, Artifact{Ecosystem: "docker", Name: "x", Version: "1"}, arc)
	if rep.Inspected || len(rep.Findings) != 0 {
		t.Fatalf("docker should be skipped, got %+v", rep)
	}
	if svc.Applies("docker") {
		t.Fatal("Applies(docker) should be false")
	}
	if !svc.Applies("npm") {
		t.Fatal("Applies(npm) should be true")
	}
}

func TestUnrecognizedArchiveFailsOpen(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, []byte("not an archive at all"))
	if rep.Inspected {
		t.Fatalf("unrecognized archive must not be marked inspected")
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("no findings expected, got %+v", rep.Findings)
	}
}

func TestFindingBudget(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxFindings = 3
	svc := mustService(t, cfg)
	files := map[string][]byte{}
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x08}, 2048)...)
	for i := 0; i < 50; i++ {
		files["package/lib"+string(rune('a'+i%26))+itoa(i)+".node"] = elf
	}
	arc := tarGz(t, files)
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, arc)
	if len(rep.Findings) > 3 {
		t.Fatalf("finding budget not enforced: %d findings", len(rep.Findings))
	}
	if !rep.Truncated {
		t.Fatalf("expected truncated=true when finding budget is hit")
	}
}

func TestCleanPackageNoFindings(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	arc := tarGz(t, map[string][]byte{
		"package/package.json": []byte(`{"name":"x","version":"1.0.0"}`),
		"package/index.js":     []byte("export const n = 42;\n"),
		"package/README.md":    []byte("# hello\n"),
	})
	rep := assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, arc)
	if !rep.Inspected {
		t.Fatal("clean package should be inspected")
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("clean package produced findings: %+v", rep.Findings)
	}
	if dec := svc.Gate(rep); dec.Outcome != OutcomeAllow || dec.Code != "clean" {
		t.Fatalf("clean gate: %+v", dec)
	}
}

func TestDeterministicOrdering(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	arc := tarGz(t, map[string][]byte{
		"package/b.py":   []byte("import os\nos.system('x')\n"),
		"package/a.node": append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x09}, 2048)...),
		"package/c.js":   []byte("eval(x)\n"),
	})
	art := Artifact{Ecosystem: "npm", Name: "x", Version: "1"}
	r1 := assess(t, svc, art, arc)
	r2 := assess(t, svc, art, arc)
	if len(r1.Findings) != len(r2.Findings) {
		t.Fatalf("non-deterministic finding count: %d vs %d", len(r1.Findings), len(r2.Findings))
	}
	for i := range r1.Findings {
		if r1.Findings[i].File != r2.Findings[i].File || r1.Findings[i].RuleID != r2.Findings[i].RuleID {
			t.Fatalf("non-deterministic ordering at %d", i)
		}
	}
}

func TestMetricsSnapshot(t *testing.T) {
	svc := mustService(t, DefaultConfig())
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x0a}, 2048)...)
	arc := tarGz(t, map[string][]byte{"package/x.node": elf})
	_ = assess(t, svc, Artifact{Ecosystem: "npm", Name: "x", Version: "1"}, arc)
	snap := svc.Metrics()
	if snap.Scanned != 1 || snap.FlaggedArts != 1 || snap.FindingsTotal == 0 {
		t.Fatalf("unexpected metrics: %+v", snap)
	}
	if snap.ByCategory["embedded-binary"] == 0 {
		t.Fatalf("category metric not recorded: %+v", snap.ByCategory)
	}
	if snap.ByEcosystem["npm"] != 1 {
		t.Fatalf("ecosystem metric not recorded: %+v", snap.ByEcosystem)
	}
}

func TestNilServiceSafe(t *testing.T) {
	var svc *Service
	if svc.Enabled() {
		t.Fatal("nil service must not be enabled")
	}
	if svc.Applies("npm") {
		t.Fatal("nil service must not apply")
	}
	_ = svc.Metrics()
	_ = svc.Status()
}
