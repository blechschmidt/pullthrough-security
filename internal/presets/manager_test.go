package presets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
)

func TestManagerApplyPatchesOnDiskConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	orig := "# operator config\nserver:\n  httpAddr: \":8443\"\nsigverify:\n  enabled: false\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}

	live, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	mgr := NewManager(path, live)

	result, err := mgr.Apply("nist-ssdf")
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Changed == 0 {
		t.Fatal("expected changes")
	}
	if result.BackupPath == "" {
		t.Fatal("expected a backup path")
	}
	if _, err := os.Stat(result.BackupPath); err != nil {
		t.Fatalf("backup not written: %v", err)
	}

	// The patched file must preserve the operator's comment and unrelated key, and
	// must load + validate.
	patched, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(patched), "# operator config") {
		t.Errorf("comment dropped:\n%s", patched)
	}
	if !strings.Contains(string(patched), ":8443") {
		t.Errorf("unrelated setting dropped:\n%s", patched)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload after apply: %v", err)
	}
	if !reloaded.Sigverify.Enabled {
		t.Error("expected sigverify.enabled=true after apply")
	}
	if reloaded.Vulnerabilities.FailSeverity != "high" {
		t.Errorf("expected vulnerabilities.failSeverity=high, got %q", reloaded.Vulnerabilities.FailSeverity)
	}
	if len(reloaded.License.Policy.Deny) == 0 {
		t.Error("expected license deny set to be applied")
	}
}

func TestManagerApplyRequiresConfigFile(t *testing.T) {
	def := config.Default()
	mgr := NewManager("", &def)
	if _, err := mgr.Apply("slsa-l3"); err == nil {
		t.Fatal("expected apply to fail without a backing config file")
	}
}

func TestManagerListAndDiff(t *testing.T) {
	def := config.Default()
	mgr := NewManager("", &def)
	if len(mgr.List()) < 3 {
		t.Fatal("expected at least 3 presets")
	}
	d, err := mgr.Diff("baseline-hardened")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if d.Preset != "baseline-hardened" {
		t.Fatalf("unexpected preset %q", d.Preset)
	}
}
