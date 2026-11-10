//go:build integration
// +build integration

// Per-ecosystem LLM commit-scan admission integration tests (Task 168).
//
// For every real package ecosystem the proxy fronts, this suite stands up the
// full in-process pull-through proxy — configured instead of the official
// registry (e.g. a cargo/npm/pip/... backend pointed at a recorded upstream) —
// with the production provenance → policy admission bridge wired to a MOCK LLM
// commit scanner. Each ecosystem's package is associated with a source commit;
// a "good" package's commit is scanned benign and must be admitted (200), while
// a "bad" package's commit carries a malicious marker the mock LLM flags, so the
// policy gate must block the pull (403) before the artifact is served.
//
// This exercises the real pipeline end-to-end: the commit-scan pipeline parses
// and scores the mock verdict, the provenance service joins package→commit→
// verdict, and the policy engine turns a malicious source commit into a package
// admission block — with no network and no real LLM API calls.
//
// It emits a per-ecosystem efficacy matrix as a task artifact and fails CI if any
// supported package ecosystem lacks both a good-admit and a bad-block result.
//
// Run with: go test -tags integration ./internal/e2e/ -run LLM
package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/testset"
)

// llmResult records one ecosystem's outcome for the matrix artifact.
type llmResult struct {
	Ecosystem   string `json:"ecosystem"`
	Backend     string `json:"backend"`
	Coordinate  string `json:"coordinate"`
	GoodAdmit   bool   `json:"goodAdmitted"`
	BadBlock    bool   `json:"badBlocked"`
	Scanned     bool   `json:"scanned"`
	BlockReason string `json:"blockReason,omitempty"`
}

func (r llmResult) ok() bool { return r.GoodAdmit && r.BadBlock && r.Scanned }

func TestLLMScanBlocksBadPackagesPerEcosystem(t *testing.T) {
	if err := testset.Validate(); err != nil {
		t.Fatalf("testset corpus invalid: %v", err)
	}

	ctx := context.Background()
	var results []llmResult

	for _, f := range testset.Corpus() {
		f := f
		// Git's clone is a non-cacheable pack negotiation with no package
		// coordinate to associate with a commit, so the package-admission bridge
		// does not apply; its commits are gated by the commit watcher / git backend,
		// not this package-pull path.
		ap, ok := artifactPull(f)
		if !ok {
			continue
		}

		res := llmResult{Ecosystem: f.Ecosystem, Backend: f.Backend, Coordinate: f.Dep.Coordinate()}
		t.Run(f.ID, func(t *testing.T) {
			driveGoodAndBad(t, ctx, f, ap.Path, &res)
		})
		results = append(results, res)
	}

	writeLLMMatrix(t, results)

	// CI gate: every package ecosystem must demonstrate both a good-admit and a
	// bad-block, and must have actually invoked the (mock) LLM scanner.
	var gaps []string
	for _, r := range results {
		if !r.ok() {
			gaps = append(gaps, r.Backend)
		}
	}
	sort.Strings(gaps)
	if len(gaps) > 0 {
		t.Errorf("LLM-scan admission coverage gap for %d ecosystem(s): %s",
			len(gaps), strings.Join(gaps, ", "))
	}
}

// driveGoodAndBad runs the benign and malicious variants for one fixture and
// records the outcomes.
func driveGoodAndBad(t *testing.T, ctx context.Context, f testset.Fixture, artifactPath string, res *llmResult) {
	// Good package: its source commit is scanned benign, so the pull is admitted.
	good, err := buildLLMScenario(f, false)
	if err != nil {
		t.Fatalf("build good scenario: %v", err)
	}
	defer good.cleanup()

	if calls := good.provider.calls.Load(); calls < 1 {
		t.Errorf("good: mock LLM was never invoked (%d calls); the source commit was not scanned", calls)
	}
	recGood := good.get(ctx, artifactPath)
	res.Scanned = good.provider.calls.Load() >= 1
	res.GoodAdmit = recGood.Code == 200 && recGood.Header().Get("X-Policy-Decision") != "block"
	if !res.GoodAdmit {
		t.Errorf("good: benign package pull returned %d (policy=%q); want 200 admit",
			recGood.Code, recGood.Header().Get("X-Policy-Decision"))
	}

	// Bad package: its source commit carries the malicious marker, so the mock LLM
	// flags it and the policy gate must block the pull before serving.
	bad, err := buildLLMScenario(f, true)
	if err != nil {
		t.Fatalf("build bad scenario: %v", err)
	}
	defer bad.cleanup()

	recBad := bad.get(ctx, artifactPath)
	blocked := recBad.Code == 403 &&
		recBad.Header().Get("X-Policy-Decision") == "block" &&
		recBad.Header().Get("X-Policy-Code") == "malicious"
	res.BadBlock = blocked
	res.BlockReason = recBad.Header().Get("X-Policy-Code")
	if !blocked {
		t.Errorf("bad: malicious-commit package pull returned %d (decision=%q code=%q); want 403 block/malicious",
			recBad.Code, recBad.Header().Get("X-Policy-Decision"), recBad.Header().Get("X-Policy-Code"))
	}

	// A hard block must not serve the artifact bytes.
	if blocked && recBad.Body.Len() > 0 && !strings.Contains(recBad.Body.String(), "malicious") {
		t.Errorf("bad: blocked response body did not explain the malicious verdict: %q", recBad.Body.String())
	}
	// A hard block must not fetch the artifact from the upstream.
	if rest := restOf(f.Backend, artifactPath); bad.up.count(rest) != 0 {
		t.Errorf("bad: a policy-blocked pull still hit the upstream (%d fetches)", bad.up.count(rest))
	}

	// The block must be explained in the SARIF findings for the coordinate: a
	// malicious-source-commit finding from the provenance gate, so CI can retrieve
	// why the package was refused.
	if doc, found := bad.store.Get("", f.Dep.Coordinate()); found {
		if !hasGate(doc, findings.GateProvenance) {
			t.Errorf("bad: findings document for %s records no provenance-gate finding explaining the block",
				f.Dep.Coordinate())
		}
	} else {
		t.Errorf("bad: no findings document recorded for blocked coordinate %s", f.Dep.Coordinate())
	}

	// The benign variant's verdict must genuinely be non-malicious and the
	// malicious variant's verdict genuinely malicious — i.e. the mock LLM drove the
	// distinction, not some other gate.
	assertVerdict(t, ctx, good, f, false)
	assertVerdict(t, ctx, bad, f, true)
}

// assertVerdict confirms the pipeline persisted the expected scan verdict for the
// fixture's associated source commit.
func assertVerdict(t *testing.T, ctx context.Context, sc *llmScenario, f testset.Fixture, malicious bool) {
	sha := commitSHAFor(f, malicious)
	v, err := sc.pipeline.Get(ctx, sha)
	if err != nil {
		t.Fatalf("reading persisted verdict for %s: %v", sha, err)
	}
	if v.Malicious != malicious {
		t.Errorf("verdict for %s: Malicious=%v, want %v (riskScore=%d)", sha, v.Malicious, malicious, v.RiskScore)
	}
	if malicious && v.RiskScore < 90 {
		t.Errorf("malicious verdict for %s has risk score %d, want >= 90", sha, v.RiskScore)
	}
}

// writeLLMMatrix emits the per-ecosystem efficacy matrix (JSON + Markdown) to the
// task attachments directory when available, falling back to the package dir.
func writeLLMMatrix(t *testing.T, results []llmResult) {
	sort.Slice(results, func(i, j int) bool { return results[i].Backend < results[j].Backend })

	dir := artifactDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("could not ensure artifact dir %q: %v", dir, err)
		return
	}

	jsonBytes, _ := json.MarshalIndent(results, "", "  ")
	jsonPath := filepath.Join(dir, "llm-scan-matrix.json")
	if err := os.WriteFile(jsonPath, jsonBytes, 0o644); err != nil {
		t.Logf("write %s: %v", jsonPath, err)
	} else {
		t.Logf("wrote LLM-scan matrix artifact: %s", jsonPath)
	}

	var md strings.Builder
	md.WriteString("# LLM commit-scan admission efficacy (Task 168)\n\n")
	md.WriteString("Each package ecosystem is pulled through the proxy with a mock LLM scanning the\n")
	md.WriteString("package's associated source commit. A benign commit admits the package; a\n")
	md.WriteString("malicious commit blocks it.\n\n")
	md.WriteString("| Ecosystem | Backend | Coordinate | Scanned | Good→admit | Bad→block | Block code |\n")
	md.WriteString("|---|---|---|:-:|:-:|:-:|---|\n")
	tick := func(b bool) string {
		if b {
			return "✅"
		}
		return "❌"
	}
	for _, r := range results {
		md.WriteString("| " + r.Ecosystem + " | " + r.Backend + " | `" + r.Coordinate + "` | " +
			tick(r.Scanned) + " | " + tick(r.GoodAdmit) + " | " + tick(r.BadBlock) + " | " + r.BlockReason + " |\n")
	}
	md.WriteString("\n")
	md.WriteString(summaryLine(results))
	md.WriteString("\n")

	mdPath := filepath.Join(dir, "llm-scan-matrix.md")
	if err := os.WriteFile(mdPath, []byte(md.String()), 0o644); err != nil {
		t.Logf("write %s: %v", mdPath, err)
	} else {
		t.Logf("wrote LLM-scan matrix artifact: %s", mdPath)
	}
	t.Logf("LLM-scan admission matrix:\n%s", md.String())
}

func summaryLine(results []llmResult) string {
	full := 0
	for _, r := range results {
		if r.ok() {
			full++
		}
	}
	return "**" + itoa(full) + "/" + itoa(len(results)) +
		" package ecosystems fully covered** (good admitted, bad blocked, scanned).\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
