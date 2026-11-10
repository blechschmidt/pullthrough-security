// Package redteam is an internal supply-chain attack red-team simulation and
// gate-efficacy harness (Task 76). It injects a curated catalog of synthetic
// supply-chain attack scenarios end-to-end through the full admission pipeline
// of an in-process proxy.Gateway — each wired with deterministic stub backends
// and the specific admission gate(s) under test — and asserts that the expected
// gate blocks (or, for the VEX-suppression case, deliberately admits) each one.
//
// The dozens of admission gates built across the project are each individually
// unit-tested, but their END-TO-END efficacy as a defense-in-depth pipeline is
// only meaningfully measured by driving real attacks through the real gateway
// and observing the verdict. This harness turns that into a measurable,
// regression-tested property: every scenario records which gate fired, the
// verdict, and a pass/fail, and the suite emits a coverage matrix (scenario ×
// expected-gate × actual outcome) as JSON or Markdown.
//
// It is a security-validation/test harness, not a new admission gate: nothing
// here runs on the production pull path. It is invoked on demand via
// `ptctl redteam` and gated in CI by TestSuite_NoRegressions, which fails if any
// expect-block scenario regresses from "blocked" to "admitted".
package redteam

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"time"
)

// Outcome is the observed end-to-end verdict for a scenario's pull.
type Outcome string

const (
	// OutcomeBlocked: the pull was refused by an admission gate (HTTP 4xx with a
	// recognized gate decision header, or any non-2xx refusal).
	OutcomeBlocked Outcome = "blocked"
	// OutcomeAdmitted: the artifact was served (HTTP 2xx) — the pull passed every
	// wired gate.
	OutcomeAdmitted Outcome = "admitted"
	// OutcomeError: the scenario could not be evaluated (setup failure or an
	// unexpected transport error). Counted as a failure, never as an admit/block.
	OutcomeError Outcome = "error"
)

// Result is the evaluated outcome of a single scenario run.
type Result struct {
	// Scenario is the stable scenario ID.
	Scenario string `json:"scenario"`
	// Name is the human-readable scenario title.
	Name string `json:"name"`
	// Category is the attack family (e.g. "typosquat", "known-malicious").
	Category string `json:"category"`
	// ExpectedGate is the security control under test (the gate expected to fire).
	ExpectedGate string `json:"expectedGate"`
	// Attack is a short description of the synthetic attack injected.
	Attack string `json:"attack"`
	// ExpectBlock is the asserted disposition: true = the pull must be blocked;
	// false = the pull must be admitted (e.g. a critical CVE suppressed by VEX).
	ExpectBlock bool `json:"expectBlock"`
	// Status is the HTTP status the gateway returned.
	Status int `json:"status"`
	// Outcome is the observed verdict.
	Outcome Outcome `json:"outcome"`
	// FiredGate is the gate that produced the block, detected from the response's
	// decision headers; empty when the pull was admitted or no gate header was set.
	FiredGate string `json:"firedGate,omitempty"`
	// Pass reports whether the observed outcome matched the assertion.
	Pass bool `json:"pass"`
	// Regression is true when an expect-block scenario was admitted — the specific
	// failure the CI job guards against (a defense silently going from block→admit).
	Regression bool `json:"regression"`
	// Detail explains a failure, or carries the block reason on success.
	Detail string `json:"detail,omitempty"`
}

// Report is the full coverage matrix produced by Run.
type Report struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Total       int       `json:"total"`
	Passed      int       `json:"passed"`
	Failed      int       `json:"failed"`
	// Regressions counts expect-block scenarios that admitted — the CI-fail signal.
	Regressions int      `json:"regressions"`
	Results     []Result `json:"results"`
}

// OK reports whether every scenario passed (no failures, no regressions).
func (r *Report) OK() bool { return r != nil && r.Failed == 0 }

// Run executes the full scenario catalog against fresh in-process gateways and
// returns the coverage matrix. It is deterministic and self-contained: every
// scenario builds its own gateway with stub backends, so no external network,
// registry, or running proxy is required. ctx bounds each scenario's request.
func Run(ctx context.Context) (*Report, error) {
	return run(ctx, Scenarios(), time.Now())
}

// run evaluates the supplied scenarios with an injectable clock for the report
// timestamp, so tests stay deterministic.
func run(ctx context.Context, scenarios []Scenario, now time.Time) (*Report, error) {
	rep := &Report{GeneratedAt: now, Results: make([]Result, 0, len(scenarios))}
	for _, sc := range scenarios {
		rep.Results = append(rep.Results, evaluate(ctx, sc))
	}
	// Stable ordering by ID makes the JSON/Markdown matrix reproducible regardless
	// of catalog declaration order.
	sort.SliceStable(rep.Results, func(i, j int) bool {
		return rep.Results[i].Scenario < rep.Results[j].Scenario
	})
	for i := range rep.Results {
		rep.Total++
		if rep.Results[i].Pass {
			rep.Passed++
		} else {
			rep.Failed++
		}
		if rep.Results[i].Regression {
			rep.Regressions++
		}
	}
	return rep, nil
}

// evaluate runs one scenario and classifies the result.
func evaluate(ctx context.Context, sc Scenario) Result {
	res := Result{
		Scenario:     sc.ID,
		Name:         sc.Name,
		Category:     sc.Category,
		ExpectedGate: sc.ExpectedGate,
		Attack:       sc.Attack,
		ExpectBlock:  sc.ExpectBlock,
	}

	setup, err := sc.setup()
	if err != nil {
		res.Outcome = OutcomeError
		res.Detail = fmt.Sprintf("scenario setup failed: %v", err)
		return res
	}
	defer setup.cleanup()

	req := setup.request
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	rr := httptest.NewRecorder()
	setup.gateway.Handler().ServeHTTP(rr, req)

	res.Status = rr.Code
	if rr.Code >= 200 && rr.Code < 300 {
		res.Outcome = OutcomeAdmitted
	} else {
		res.Outcome = OutcomeBlocked
		res.FiredGate = detectFiredGate(rr.Header())
	}

	accept := sc.AcceptGates
	if len(accept) == 0 {
		accept = []string{sc.ExpectedGate}
	}

	switch {
	case sc.ExpectBlock && res.Outcome == OutcomeAdmitted:
		// The defining regression: a synthetic attack that should have been refused
		// was served. This is what fails CI.
		res.Pass = false
		res.Regression = true
		res.Detail = fmt.Sprintf("REGRESSION: attack admitted (HTTP %d); expected %s to block", res.Status, sc.ExpectedGate)
	case sc.ExpectBlock && res.Outcome == OutcomeBlocked:
		if res.FiredGate == "" {
			res.Pass = false
			res.Detail = fmt.Sprintf("blocked (HTTP %d) but no recognized gate decision header was set", res.Status)
			break
		}
		if !contains(accept, res.FiredGate) {
			res.Pass = false
			res.Detail = fmt.Sprintf("blocked by %q gate; expected one of %v", res.FiredGate, accept)
			break
		}
		res.Pass = true
		res.Detail = fmt.Sprintf("blocked by %q gate as expected (HTTP %d)", res.FiredGate, res.Status)
	case !sc.ExpectBlock && res.Outcome == OutcomeAdmitted:
		res.Pass = true
		res.Detail = fmt.Sprintf("admitted as expected (HTTP %d)", res.Status)
	default: // !ExpectBlock && blocked
		res.Pass = false
		res.Detail = fmt.Sprintf("expected admit but blocked by %q gate (HTTP %d)", res.FiredGate, res.Status)
	}
	return res
}

// gateHeader pairs a response header with the values that signal a hard refusal,
// used to attribute a block to the specific gate that produced it. A gate may
// refuse with several dispositions (e.g. "block" or "quarantine"), and the
// reproducible-build gate signals its refusal with verdict "mismatch".
type gateHeader struct {
	gate     string
	header   string
	blockVal []string
}

// blockHeaders enumerates the decision headers each admission gate sets on a
// refusal, in pipeline order. detectFiredGate scans them so a refused pull is
// attributed to the exact control that fired.
var blockHeaders = []gateHeader{
	{"lockdown", "X-Lockdown-Decision", []string{"block"}},
	{"nameguard", "X-Nameguard-Decision", []string{"block", "quarantine"}},
	{"depfirewall", "X-Depfirewall-Decision", []string{"block"}},
	{"malfeed", "X-Malfeed-Decision", []string{"block"}},
	{"maturity", "X-Maturity-Decision", []string{"block"}},
	{"policy", "X-Policy-Decision", []string{"block"}},
	{"sigverify", "X-Sigverify-Decision", []string{"block", "quarantine"}},
	{"buildprov", "X-BuildProv-Decision", []string{"block", "quarantine"}},
	{"rebuildverify", "X-Rebuild-Verify", []string{"mismatch"}},
	{"vulnscan", "X-Vuln-Decision", []string{"block", "quarantine"}},
	{"license", "X-License-Decision", []string{"block", "quarantine"}},
	{"installhooks", "X-InstallHooks-Decision", []string{"block"}},
}

// detectFiredGate returns the name of the gate that produced a block by matching
// the response's decision headers. Empty when none matched.
func detectFiredGate(h http.Header) string {
	for _, gh := range blockHeaders {
		if v := h.Get(gh.header); v != "" && contains(gh.blockVal, v) {
			return gh.gate
		}
	}
	return ""
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
