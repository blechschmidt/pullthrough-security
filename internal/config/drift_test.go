package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFingerprintStableAndSensitive(t *testing.T) {
	a := Default()
	b := Default()
	if Fingerprint(&a) != Fingerprint(&b) {
		t.Fatalf("identical configs must share a fingerprint")
	}
	b.Server.HTTPAddr = ":9999"
	if Fingerprint(&a) == Fingerprint(&b) {
		t.Fatalf("a changed field must change the fingerprint")
	}
}

func TestDetectorReportsDriftOnFileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  httpAddr: \":8080\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	boot, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d := NewDetector(path, boot)

	st := d.Status()
	if st.Drifted {
		t.Fatalf("expected no drift immediately after boot, got %+v", st)
	}
	if st.RunningConfigHash != st.CurrentConfigHash {
		t.Fatalf("hashes should match with no change: %+v", st)
	}

	// A comment-only change alters the file hash but not the effective config.
	if err := os.WriteFile(path, []byte("# tweak\nserver:\n  httpAddr: \":8080\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st = d.Status()
	if st.Drifted {
		t.Fatalf("a comment-only change must not be effective drift, got %+v", st)
	}
	if st.CurrentFileHash == st.RunningFileHash {
		t.Fatalf("the raw file hash should have changed: %+v", st)
	}

	// A semantic change is drift.
	if err := os.WriteFile(path, []byte("server:\n  httpAddr: \":9090\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st = d.Status()
	if !st.Drifted {
		t.Fatalf("expected drift after a semantic change, got %+v", st)
	}
}

func TestDetectorReportsDriftWhenFileBreaks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  httpAddr: \":8080\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	boot, _ := Load(path)
	d := NewDetector(path, boot)

	// Rewrite the file with an unknown key so loadEffective (strict) fails.
	if err := os.WriteFile(path, []byte("server:\n  nope: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := d.Status()
	if !st.Drifted || st.Error == "" {
		t.Fatalf("a broken on-disk file must report drift with an error, got %+v", st)
	}
}
