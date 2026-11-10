package muttest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setupTempModule writes a minimal, dependency-free Go module containing one
// package `p` (a file under p/) plus a test, and returns the module dir and
// import path. It is used to exercise the full compile+run mutation loop
// offline.
func setupTempModule(t *testing.T, pkgSrc, testSrc string) (moduleDir, modulePath string) {
	t.Helper()
	moduleDir = t.TempDir()
	modulePath = "example.com/mut"
	if err := os.WriteFile(filepath.Join(moduleDir, "go.mod"), []byte("module "+modulePath+"\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(moduleDir, "p")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "p.go"), []byte(pkgSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "p_test.go"), []byte(testSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	return moduleDir, modulePath
}

func TestEngineKillsAndSurvives(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping nested-build mutation engine test in -short mode")
	}

	// Positive(n) returns n > 0. The test only asserts the positive case, so a
	// `>` -> `>=` mutant (Positive(0) becomes true) is NOT detected and SURVIVES,
	// while flipping the returned boolean or negating the condition IS detected
	// and is KILLED.
	pkgSrc := `package p

func Positive(n int) bool {
	if n > 0 {
		return true
	}
	return false
}
`
	testSrc := `package p

import "testing"

func TestPositive(t *testing.T) {
	if !Positive(5) {
		t.Fatal("5 should be positive")
	}
}
`
	moduleDir, modulePath := setupTempModule(t, pkgSrc, testSrc)

	eng := New(Options{
		ModuleDir:         moduleDir,
		ModulePath:        modulePath,
		Operators:         DefaultOperators(),
		Seed:              1,
		TestTimeout:       60 * time.Second,
		BuildTimeout:      90 * time.Second,
		KeepMutantResults: true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	run, err := eng.Run(ctx, []string{"p"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(run.Packages) != 1 {
		t.Fatalf("expected 1 package run, got %d", len(run.Packages))
	}
	pr := run.Packages[0]
	if pr.Killed == 0 {
		t.Errorf("expected at least one killed mutant, got %+v", pr)
	}
	if pr.Survived == 0 {
		t.Errorf("expected at least one surviving mutant (the `>`->`>=` boundary), got %+v", pr)
	}
	// Sanity: the score reflects killed/(killed+survived).
	if want := score(pr.Killed, pr.Killed+pr.Survived); pr.ScorePct != want {
		t.Errorf("score pct = %v, want %v", pr.ScorePct, want)
	}

	// The source file must be byte-for-byte restored after the run.
	after, err := os.ReadFile(filepath.Join(moduleDir, "p", "p.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != pkgSrc {
		t.Fatalf("source not restored after run:\n%s", string(after))
	}
}

func TestEngineRejectsRedBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping nested-build mutation engine test in -short mode")
	}
	// A failing baseline test must be rejected: mutation testing a red suite is
	// meaningless.
	pkgSrc := `package p

func Add(a, b int) int { return a + b }
`
	testSrc := `package p

import "testing"

func TestAddWrong(t *testing.T) {
	if Add(1, 1) != 3 { // deliberately wrong
		t.Fatal("baseline is red on purpose")
	}
}
`
	moduleDir, modulePath := setupTempModule(t, pkgSrc, testSrc)
	eng := New(Options{
		ModuleDir:    moduleDir,
		ModulePath:   modulePath,
		Seed:         1,
		TestTimeout:  60 * time.Second,
		BuildTimeout: 90 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if _, err := eng.Run(ctx, []string{"p"}); err == nil {
		t.Fatal("expected Run to reject a red baseline suite")
	}
}

func TestEngineIgnoreExcludesMutant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping nested-build mutation engine test in -short mode")
	}
	pkgSrc := `package p

func Positive(n int) bool { return n > 0 }
`
	testSrc := `package p

import "testing"

func TestPositive(t *testing.T) {
	if !Positive(5) || Positive(-1) {
		t.Fatal("bad")
	}
}
`
	moduleDir, modulePath := setupTempModule(t, pkgSrc, testSrc)

	// First enumerate to learn the mutant IDs for this package.
	ms, err := EnumerateFile(filepath.Join(moduleDir, "p", "p.go"), modulePath+"/p", "p/p.go", enabledAll())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 {
		t.Fatal("no mutants enumerated")
	}
	ignore := map[string]bool{ms[0].ID: true}

	eng := New(Options{
		ModuleDir:    moduleDir,
		ModulePath:   modulePath,
		Seed:         1,
		Ignore:       ignore,
		TestTimeout:  60 * time.Second,
		BuildTimeout: 90 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	run, err := eng.Run(ctx, []string{"p"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	pr := run.Packages[0]
	if pr.Ignored != 1 {
		t.Fatalf("expected 1 ignored mutant, got %d", pr.Ignored)
	}
	if pr.Total != len(ms)-1 {
		t.Fatalf("ignored mutant should be excluded from Total: total=%d enumerated=%d", pr.Total, len(ms))
	}
}
