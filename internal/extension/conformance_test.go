package extension

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// conformancePath is the prebuilt Go→wasm fixture exercised below. Rebuild it
// with internal/extension/testdata/build.sh after changing its source.
func conformancePath() string { return filepath.Join("testdata", "conformance_gate.wasm") }

// loadConformance builds a single-module manager wrapping the conformance fixture
// under the given limits and fail policy.
func loadConformance(t *testing.T, limits Limits, failClosed bool) *Manager {
	t.Helper()
	mgr, err := NewManager(context.Background(), Config{
		Enabled: true,
		Modules: []ModuleConfig{{
			Name:       "conformance",
			Path:       conformancePath(),
			FailClosed: failClosed,
			Limits:     limits,
		}},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if !mgr.Snapshot().Modules[0].Loaded {
		t.Fatalf("conformance module failed to load: %s", mgr.Snapshot().Modules[0].LoadError)
	}
	t.Cleanup(func() { mgr.Close(context.Background()) })
	return mgr
}

// inputFor builds a host input naming the artifact and (optionally) carrying a
// composite risk score.
func inputFor(name string, riskScore int) HostInput {
	in := HostInput{Signals: policyengine.Input{Artifact: policyengine.ArtifactInput{
		Ecosystem: "npm", Backend: "npm-public", Name: name, Version: "1.0.0",
	}}}
	if riskScore >= 0 {
		band := "low"
		if riskScore >= 75 {
			band = "critical"
		}
		in.Risk = &RiskView{Score: riskScore, Band: band}
	}
	return in
}

// TestConformanceVerdicts is the behavioral conformance suite: each case drives
// the fixture to a documented outcome and asserts the host's combined Result. The
// verdict-producing cases share one manager (one compiled module) for speed.
func TestConformanceVerdicts(t *testing.T) {
	mgr := loadConformance(t, Limits{Timeout: 2 * time.Second}, false)

	cases := []struct {
		name      string
		artifact  string
		risk      int
		decision  Decision
		outcome   Outcome
		reasonSub string
	}{
		{"allow", "ordinary-pkg", -1, DecisionAllow, OutcomeAllow, ""},
		{"block", "ext-block-evil", -1, DecisionBlock, OutcomeBlock, "blocked by conformance"},
		{"warn", "ext-warn-pkg", -1, DecisionWarn, OutcomeWarn, "warned by conformance"},
		{"risk high blocks", "ext-risk-pkg", 90, DecisionBlock, OutcomeBlock, "risk score above"},
		{"risk low allows", "ext-risk-pkg", 10, DecisionAllow, OutcomeAllow, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mgr.Evaluate(context.Background(), inputFor(tc.artifact, tc.risk))
			if res.Decision != tc.decision {
				t.Fatalf("decision = %s, want %s (reason %q)", res.Decision, tc.decision, res.Reason)
			}
			if len(res.Modules) != 1 {
				t.Fatalf("expected 1 module result, got %d", len(res.Modules))
			}
			if got := res.Modules[0].Outcome; got != tc.outcome {
				t.Fatalf("outcome = %s, want %s", got, tc.outcome)
			}
			if tc.reasonSub != "" && !strings.Contains(res.Reason, tc.reasonSub) {
				t.Errorf("reason %q does not contain %q", res.Reason, tc.reasonSub)
			}
		})
	}
}

// TestConformanceTimeout asserts a runaway (infinite-loop) module is terminated
// by the wall-clock CPU budget and classified OutcomeTimeout, and that the fail
// policy governs the resulting decision.
func TestConformanceTimeout(t *testing.T) {
	for _, failClosed := range []bool{false, true} {
		mgr := loadConformance(t, Limits{Timeout: 150 * time.Millisecond}, failClosed)
		res := mgr.Evaluate(context.Background(), inputFor("ext-timeout-pkg", -1))
		if got := res.Modules[0].Outcome; got != OutcomeTimeout {
			t.Fatalf("failClosed=%v outcome = %s, want timeout", failClosed, got)
		}
		want := DecisionAllow
		if failClosed {
			want = DecisionBlock
		}
		if res.Decision != want {
			t.Errorf("failClosed=%v decision = %s, want %s", failClosed, res.Decision, want)
		}
	}
}

// TestConformanceFuel asserts the function-call fuel meter aborts deep recursion
// deterministically (independent of wall-clock time) and is classified distinctly
// from a timeout.
func TestConformanceFuel(t *testing.T) {
	// A generous time budget so only the fuel meter can fire, and a fuel budget the
	// deep-recursion path is guaranteed to exceed.
	mgr := loadConformance(t, Limits{Timeout: 10 * time.Second, Fuel: 20_000}, true)
	res := mgr.Evaluate(context.Background(), inputFor("ext-recurse-pkg", -1))
	if got := res.Modules[0].Outcome; got != OutcomeFuel {
		t.Fatalf("outcome = %s, want fuel", got)
	}
	if res.Decision != DecisionBlock {
		t.Errorf("fail-closed fuel exhaustion should block, got %s", res.Decision)
	}
}

// TestConformanceMalformedVerdict asserts a module returning non-JSON is rejected
// as an error rather than crashing the host or silently admitting.
func TestConformanceMalformedVerdict(t *testing.T) {
	mgr := loadConformance(t, Limits{Timeout: 2 * time.Second}, false)
	res := mgr.Evaluate(context.Background(), inputFor("ext-badjson-pkg", -1))
	if got := res.Modules[0].Outcome; got != OutcomeError {
		t.Fatalf("outcome = %s, want error", got)
	}
	// Fail-open: a malformed verdict admits.
	if res.Decision != DecisionAllow {
		t.Errorf("fail-open malformed verdict should allow, got %s", res.Decision)
	}
}

// TestConformanceMemoryContainment asserts an unbounded-allocation module is
// contained (terminated, never admitted as allow on its own merits) rather than
// exhausting the host.
func TestConformanceMemoryContainment(t *testing.T) {
	mgr := loadConformance(t, Limits{Timeout: 500 * time.Millisecond}, true)
	res := mgr.Evaluate(context.Background(), inputFor("ext-grow-pkg", -1))
	if !res.Modules[0].Outcome.terminal() {
		t.Fatalf("outcome = %s, want a terminal (contained) outcome", res.Modules[0].Outcome)
	}
	if res.Decision != DecisionBlock {
		t.Errorf("fail-closed containment should block, got %s", res.Decision)
	}
}

// TestConformanceSandboxDeniesFilesystem asserts the module cannot reach the host
// filesystem: its probe of "/" is denied or empty.
func TestConformanceSandboxDeniesFilesystem(t *testing.T) {
	mgr := loadConformance(t, Limits{Timeout: 2 * time.Second}, false)
	res := mgr.Evaluate(context.Background(), inputFor("ext-probe-fs-pkg", -1))
	if res.Decision != DecisionAllow || res.Modules[0].Verdict == nil {
		t.Fatalf("expected allow with verdict, got %s", res.Decision)
	}
	probe := res.Modules[0].Verdict.Annotations["fsProbe"]
	if probe == "" {
		t.Fatalf("missing fsProbe annotation")
	}
	// The sandbox grants no preopened directories, so the module must NOT have read
	// any real host entries: it should be denied, or see an empty root.
	if !strings.HasPrefix(probe, "denied") && probe != "read:0" {
		t.Errorf("module appears to have read the host filesystem: fsProbe=%q", probe)
	}
}
