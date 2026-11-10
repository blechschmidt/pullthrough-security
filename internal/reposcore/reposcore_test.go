package reposcore

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// fixedNow is the deterministic analysis clock used across the tests. The fixture
// commit dates are expressed relative to it so age-based signals are stable.
var fixedNow = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

// commitSpec describes one fixture commit.
type commitSpec struct {
	files     map[string]string
	authorEml string
	whenDays  int // days before fixedNow
}

// buildRepo creates a non-bare git repository under t.TempDir() with the given
// commits applied in order, each at a deterministic date. It returns the repo
// directory. The test is skipped when git is unavailable.
func buildRepo(t *testing.T, commits []commitSpec) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(env []string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run(nil, "init", "-q", "-b", "main")
	run(nil, "config", "commit.gpgsign", "false")

	for i, c := range commits {
		for path, content := range c.files {
			full := filepath.Join(dir, filepath.FromSlash(path))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		run(nil, "add", "-A")
		when := fixedNow.Add(-time.Duration(c.whenDays) * 24 * time.Hour).Format(time.RFC3339)
		email := c.authorEml
		if email == "" {
			email = "dev@example.com"
		}
		env := []string{
			"GIT_AUTHOR_NAME=Dev", "GIT_AUTHOR_EMAIL=" + email,
			"GIT_COMMITTER_NAME=Dev", "GIT_COMMITTER_EMAIL=" + email,
			"GIT_AUTHOR_DATE=" + when, "GIT_COMMITTER_DATE=" + when,
		}
		run(env, "commit", "-q", "-m", "commit "+itoa(i))
	}
	return dir
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// staticLocator maps any URL to a fixed directory, for end-to-end Service tests
// without cloning.
type staticLocator struct {
	dir      string
	resolved bool
}

func (l staticLocator) Locate(ctx context.Context, repoURL string) (string, bool, bool, error) {
	return l.dir, l.resolved, false, nil
}

func TestGatherFacts_HealthyRepo(t *testing.T) {
	dir := buildRepo(t, []commitSpec{
		{files: map[string]string{
			"README.md":                "# project",
			".github/workflows/ci.yml": "name: ci",
			"SECURITY.md":              "report to security@example.com",
			".github/CODEOWNERS":       "* @owner",
			".github/dependabot.yml":   "version: 2",
		}, authorEml: "alice@example.com", whenDays: 40},
		{files: map[string]string{"a.txt": "1"}, authorEml: "bob@example.com", whenDays: 20},
		{files: map[string]string{"b.txt": "2"}, authorEml: "carol@example.com", whenDays: 10},
		{files: map[string]string{"c.txt": "3"}, authorEml: "dave@example.com", whenDays: 5},
	})

	g, err := newGitRunner("git", dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := gatherFacts(context.Background(), g, fixedNow, defaultWindow)
	if err != nil {
		t.Fatalf("gatherFacts: %v", err)
	}

	if !f.HasCI || len(f.CISystems) == 0 || f.CISystems[0] != "github-actions" {
		t.Errorf("expected github-actions CI, got HasCI=%v systems=%v", f.HasCI, f.CISystems)
	}
	if !f.HasSecurityPolicy {
		t.Error("expected SECURITY.md to be detected")
	}
	if !f.HasCodeowners {
		t.Error("expected CODEOWNERS to be detected")
	}
	if !f.HasDepAutomation || len(f.DepTools) == 0 || f.DepTools[0] != "dependabot" {
		t.Errorf("expected dependabot, got %v %v", f.HasDepAutomation, f.DepTools)
	}
	if f.CommitsAnalyzed != 4 {
		t.Errorf("expected 4 commits analyzed, got %d", f.CommitsAnalyzed)
	}
	if f.DistinctAuthors != 4 {
		t.Errorf("expected 4 distinct authors, got %d", f.DistinctAuthors)
	}
	// Four authors with one commit each: bus factor is 3 (>50% of 4 needs 3 of them).
	if f.BusFactor != 3 {
		t.Errorf("expected bus factor 3, got %d", f.BusFactor)
	}
	// Newest commit is 5 days before fixedNow.
	if f.LastCommitAgeDays != 5 {
		t.Errorf("expected last commit age 5d, got %d", f.LastCommitAgeDays)
	}
	// Commits are unsigned in the fixture (gpgsign disabled).
	if f.SignedCommits != 0 {
		t.Errorf("expected 0 signed commits, got %d", f.SignedCommits)
	}
}

func TestGatherFacts_MinimalRepo(t *testing.T) {
	dir := buildRepo(t, []commitSpec{
		{files: map[string]string{"main.go": "package main"}, authorEml: "solo@example.com", whenDays: 900},
	})
	g, err := newGitRunner("git", dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := gatherFacts(context.Background(), g, fixedNow, defaultWindow)
	if err != nil {
		t.Fatalf("gatherFacts: %v", err)
	}
	if f.HasCI || f.HasSecurityPolicy || f.HasCodeowners || f.HasDepAutomation {
		t.Errorf("expected a bare repo with no governance files, got %+v", f)
	}
	if f.DistinctAuthors != 1 || f.BusFactor != 1 {
		t.Errorf("expected single maintainer, got authors=%d bus=%d", f.DistinctAuthors, f.BusFactor)
	}
	if f.LastCommitAgeDays != 900 {
		t.Errorf("expected last commit age 900d, got %d", f.LastCommitAgeDays)
	}
}

func TestService_Score_ResolvedVsUnresolved(t *testing.T) {
	dir := buildRepo(t, []commitSpec{
		{files: map[string]string{
			".github/workflows/ci.yml": "name: ci",
			"SECURITY.md":              "x",
			".github/CODEOWNERS":       "* @o",
			".github/dependabot.yml":   "version: 2",
		}, authorEml: "alice@example.com", whenDays: 10},
		{files: map[string]string{"a": "1"}, authorEml: "bob@example.com", whenDays: 8},
		{files: map[string]string{"b": "2"}, authorEml: "carol@example.com", whenDays: 6},
		{files: map[string]string{"c": "3"}, authorEml: "dave@example.com", whenDays: 4},
	})

	svc, err := New(Config{
		Enabled: true,
		Locator: staticLocator{dir: dir, resolved: true},
		Now:     func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}

	r := svc.Score(context.Background(), RepoRef{RepositoryURL: "https://github.com/acme/widget"})
	if !r.Evaluated || !r.Resolved {
		t.Fatalf("expected resolved report, got %+v", r)
	}
	// A repo with CI, SECURITY.md, dependabot, CODEOWNERS hint, 4 maintainers, and
	// recent activity should be reasonably healthy (only signed commits missing).
	if r.Health < 60 {
		t.Errorf("expected health >= 60 for a well-governed repo, got %d (%s)", r.Health, r.Summary)
	}
	if r.Risk != 100-r.Health {
		t.Errorf("risk should be inverse of health: risk=%d health=%d", r.Risk, r.Health)
	}
	if len(r.Signals) != len(allSignals) {
		t.Errorf("expected %d sub-signals, got %d", len(allSignals), len(r.Signals))
	}

	// The unresolved path: a locator with no clone contributes no health.
	svc2, _ := New(Config{
		Enabled: true,
		Locator: staticLocator{resolved: false},
		Now:     func() time.Time { return fixedNow },
	})
	u := svc2.Score(context.Background(), RepoRef{RepositoryURL: "https://github.com/acme/missing"})
	if !u.Evaluated || u.Resolved {
		t.Errorf("expected an unresolved-but-evaluated report, got %+v", u)
	}
	if u.Health != 0 || len(u.Signals) != 0 {
		t.Errorf("unresolved report should carry no health, got %+v", u)
	}
}

func TestService_Score_CachesFactsAndHonorsTenantWeights(t *testing.T) {
	dir := buildRepo(t, []commitSpec{
		{files: map[string]string{".github/workflows/ci.yml": "x"}, authorEml: "solo@example.com", whenDays: 5},
	})
	// A tenant that weighs ONLY signed commits will score this (unsigned) repo at
	// health 0, while the default model gives partial credit for CI.
	svc, err := New(Config{
		Enabled: true,
		Locator: staticLocator{dir: dir, resolved: true},
		Now:     func() time.Time { return fixedNow },
		TenantOverrides: map[string]TenantOverride{
			"strict": {Weights: &Weights{SignedCommits: 1}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	def := svc.Score(context.Background(), RepoRef{RepositoryURL: "https://x/y", Tenant: "default"})
	strict := svc.Score(context.Background(), RepoRef{RepositoryURL: "https://x/y", Tenant: "strict"})

	if strict.Health != 0 {
		t.Errorf("strict tenant (signed-commits only, repo unsigned) should be health 0, got %d", strict.Health)
	}
	if def.Health <= strict.Health {
		t.Errorf("default model should score higher than signed-only strict model: def=%d strict=%d", def.Health, strict.Health)
	}
	// The second call should have reused the cached facts.
	if got := svc.Metrics().CacheHits; got == 0 {
		t.Error("expected a facts cache hit on the second Score call")
	}
}
