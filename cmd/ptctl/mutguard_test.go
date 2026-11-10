package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSplitList(t *testing.T) {
	if got := splitList(" a , b ,, c "); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("splitList = %+v", got)
	}
	if got := splitList("  "); got != nil {
		t.Errorf("empty splitList = %+v, want nil", got)
	}
}

func TestLoadIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "equiv.txt")
	content := "# a comment\n\nabc123\n  def456  # equivalent: boundary unreachable\nghi789\t# note\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadIgnoreFile(path)
	if err != nil {
		t.Fatalf("loadIgnoreFile: %v", err)
	}
	want := map[string]bool{"abc123": true, "def456": true, "ghi789": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ignore set = %+v, want %+v", got, want)
	}

	// A missing file is an empty set, not an error (the gate works before any
	// equivalents are triaged).
	if m, err := loadIgnoreFile(filepath.Join(dir, "nope.txt")); err != nil || m != nil {
		t.Errorf("missing ignore file = (%v, %v), want (nil, nil)", m, err)
	}
}

func TestNormalizeFloorKeys(t *testing.T) {
	const mod = "github.com/blechschmidt/pullthrough-security"

	// Module-relative keys are rewritten to full import paths; already-absolute
	// keys are left untouched. The result must key floors exactly like the
	// baseline's Packages map so Compare can match them.
	got := normalizeFloorKeys(map[string]float64{
		"internal/sigverify":       80,
		mod + "/internal/vulnscan": 75, // already absolute
	}, mod)
	want := map[string]float64{
		mod + "/internal/sigverify": 80,
		mod + "/internal/vulnscan":  75,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalizeFloorKeys = %+v, want %+v", got, want)
	}

	// An empty or nil map is returned unchanged (no floors configured).
	if got := normalizeFloorKeys(nil, mod); got != nil {
		t.Errorf("normalizeFloorKeys(nil) = %+v, want nil", got)
	}
}

func TestReadModulePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("module example.com/foo/bar\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readModulePath(path)
	if err != nil {
		t.Fatalf("readModulePath: %v", err)
	}
	if got != "example.com/foo/bar" {
		t.Errorf("module path = %q, want example.com/foo/bar", got)
	}

	if _, err := readModulePath(filepath.Join(dir, "missing")); err == nil {
		t.Error("expected error for missing go.mod")
	}
}
