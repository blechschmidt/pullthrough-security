//go:build integration || livellm

package livescan

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// Response headers the gate and the gateway set.
const (
	hdrPolicyDecision = "X-Policy-Decision"
	hdrPolicyCode     = "X-Policy-Code"
	hdrScanDecision   = "X-Llmpkgscan-Decision"
	hdrScanVerdict    = "X-Llmpkgscan-Verdict"
	hdrModelVerdict   = "X-Llmpkgscan-Model-Verdict"
	hdrScanCode       = "X-Llmpkgscan-Code"
	// policyMalicious is the refusal code of a malicious verdict; policyUnscanned
	// the one of an artifact the gate could not judge (failMode closed).
	policyMalicious = "llm-package-malicious"
	policyUnscanned = "llm-package-unscanned"
)

// Evidence is one citation of a verdict.
type Evidence struct {
	Path     string `json:"path"`
	Line     int    `json:"line,omitempty"`
	Excerpt  string `json:"excerpt,omitempty"`
	Verified bool   `json:"verified"`
}

// PackageResult is what a run observed for one variant of a package sample.
type PackageResult struct {
	Sample    string  `json:"sample"`
	Title     string  `json:"title"`
	Campaign  string  `json:"campaign"`
	Kind      string  `json:"kind"`
	Ecosystem string  `json:"ecosystem"`
	Name      string  `json:"name"`
	Version   string  `json:"version"`
	Variant   Variant `json:"variant"`
	Digest    string  `json:"digest"`
	// Expected is "refused" for the malicious variant, "served" for the benign.
	Expected string `json:"expected"`

	// The pull, as the client saw it.
	Status     int    `json:"status"`
	PolicyCode string `json:"policyCode,omitempty"`
	// ScanCode is the gate's reason code when it had no verdict
	// (X-LLMPkgScan-Code: provider-refusal, timeout, ...).
	ScanCode string `json:"scanCode,omitempty"`
	// Repull is what a second pull of a refused artifact got: the block must
	// hold (the verdict is cached) and must not cost another model call.
	Repull   *Repull `json:"repull,omitempty"`
	Decision string  `json:"decision,omitempty"`
	Served   bool    `json:"served"`
	// Outcome classifies the pull of a malicious release: "detected" (refused
	// on the model's malicious verdict), "blocked-no-verdict" (refused because
	// the gate had no verdict and failMode is closed), "served" or "other".
	Outcome string `json:"outcome,omitempty"`
	// Notes are findings that do not fail the check (an expected refusal).
	Notes []string `json:"notes,omitempty"`
	// SameBytes reports that a served artifact is byte for byte the registry's.
	SameBytes bool   `json:"sameBytes,omitempty"`
	PullError string `json:"pullError,omitempty"`
	PullTime  string `json:"pullTime"`

	// The verdict, as the admin API lists it.
	Verdict    string  `json:"verdict,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	// ConfidenceUnstated: see verdictRow.
	ConfidenceUnstated bool       `json:"confidenceUnstated,omitempty"`
	Reasons            []string   `json:"reasons,omitempty"`
	Evidence           []Evidence `json:"evidence,omitempty"`
	Mode               string     `json:"mode,omitempty"`
	Model              string     `json:"model,omitempty"`
	Truncated          bool       `json:"truncated,omitempty"`
	Coverage           []string   `json:"coverage,omitempty"`
	InputTokens        int        `json:"inputTokens,omitempty"`
	OutputTokens       int        `json:"outputTokens,omitempty"`

	Pass     bool     `json:"pass"`
	Problems []string `json:"problems,omitempty"`
}

// Repull is the second pull of a refused artifact.
type Repull struct {
	Status     int    `json:"status"`
	PolicyCode string `json:"policyCode,omitempty"`
	// ModelCalls is how many completions the second pull made the bridge
	// serve; -1 when the gates talk to the API directly and nothing counts them.
	ModelCalls int `json:"modelCalls"`
}

// CommitResult is what a run observed for one commit of a git-commit sample.
type CommitResult struct {
	Sample     string  `json:"sample"`
	Title      string  `json:"title"`
	Campaign   string  `json:"campaign"`
	Repository string  `json:"repository"`
	Variant    Variant `json:"variant"`
	SHA        string  `json:"sha"`
	// Expected is "malicious" or "benign".
	Expected  string          `json:"expected"`
	RiskScore int             `json:"riskScore"`
	Malicious bool            `json:"malicious"`
	Rationale string          `json:"rationale,omitempty"`
	Findings  []CommitFinding `json:"findings,omitempty"`
	Models    []string        `json:"models,omitempty"`
	Escalated bool            `json:"escalated,omitempty"`
	Error     string          `json:"error,omitempty"`
	// DeepStage says what became of the deep analysis the triage score asked
	// for: "ok", "refused" (the provider's safety system declined it), "failed",
	// or "not needed" (the triage score stayed under the escalation threshold).
	DeepStage string   `json:"deepStage,omitempty"`
	Pass      bool     `json:"pass"`
	Notes     []string `json:"notes,omitempty"`
	Problems  []string `json:"problems,omitempty"`
}

// CommitFinding is one finding of a commit verdict.
type CommitFinding struct {
	Category   string  `json:"category"`
	Severity   string  `json:"severity"`
	Title      string  `json:"title"`
	File       string  `json:"file,omitempty"`
	Line       int     `json:"line,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// Report is a run's outcome.
type Report struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Model    string    `json:"model"`
	// Partial reports that the run was restricted to some samples.
	Partial  bool            `json:"partial,omitempty"`
	Packages []PackageResult `json:"packages"`
	Commits  []CommitResult  `json:"commits"`
	// Calls are the completions the Claude Code bridge served (empty when the
	// gates called the API directly).
	Calls []BridgeCall `json:"calls,omitempty"`
}

// Failures lists every result that did not meet its expectation.
func (r *Report) Failures() []string {
	var out []string
	for _, p := range r.Packages {
		if !p.Pass {
			out = append(out, fmt.Sprintf("%s (%s %s@%s): %s", p.Sample, p.Variant, p.Name, p.Version, strings.Join(p.Problems, "; ")))
		}
	}
	for _, c := range r.Commits {
		if !c.Pass {
			out = append(out, fmt.Sprintf("%s (%s commit %.12s): %s", c.Sample, c.Variant, c.SHA, strings.Join(c.Problems, "; ")))
		}
	}
	return out
}

// suiteOptions configure one run.
type suiteOptions struct {
	Samples  []*Sample
	Partial  bool
	Model    Model
	ProxyBin string
	WorkDir  string
	Parallel int
}

// selectSamples returns the corpus, restricted by envSamples.
func selectSamples(t *testing.T) (samples []*Sample, partial bool) {
	t.Helper()
	all, err := Corpus()
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}
	want := strings.FieldsFunc(os.Getenv(envSamples), func(r rune) bool { return r == ',' || r == ' ' })
	if len(want) == 0 {
		return all, false
	}
	byID := map[string]*Sample{}
	for _, s := range all {
		byID[s.ID] = s
	}
	for _, id := range want {
		s, ok := byID[id]
		if !ok {
			t.Fatalf("%s names %q, which is not a sample (have %d)", envSamples, id, len(all))
		}
		samples = append(samples, s)
	}
	return samples, true
}

// proxyBinary returns the proxy binary under test, building it when
// envProxyBin does not name one.
func proxyBinary(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv(envProxyBin); bin != "" {
		abs, err := filepath.Abs(bin)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("%s: %v", envProxyBin, err)
		}
		return abs
	}
	out := filepath.Join(t.TempDir(), "pullthrough")
	build := exec.Command("go", "build", "-o", out, "../../../cmd/pullthrough")
	build.Env = withoutCredentials(os.Environ())
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the proxy (set %s to a prebuilt binary to skip this): %v\n%s", envProxyBin, err, b)
	}
	return out
}

// parallelism is envParallel, or the default.
func parallelism() int {
	if n, err := strconv.Atoi(os.Getenv(envParallel)); err == nil && n > 0 {
		return n
	}
	return 3
}

// runSuite pulls every package sample's two variants through a proxy whose
// only content gate is the LLM package scan, has the LLM commit scan judge
// every commit sample's commits, and reports what happened to each.
func runSuite(t *testing.T, opt suiteOptions) *Report {
	t.Helper()
	rep := &Report{Started: time.Now().UTC(), Model: opt.Model.Label, Partial: opt.Partial}
	var pkgSamples, commitSamples []*Sample
	for _, s := range opt.Samples {
		if s.Kind == KindGitCommit {
			commitSamples = append(commitSamples, s)
		} else {
			pkgSamples = append(pkgSamples, s)
		}
	}

	stubs, pulls, err := registries(pkgSamples)
	if err != nil {
		t.Fatalf("building the registries: %v", err)
	}
	defer func() {
		for _, s := range stubs {
			s.Close()
		}
	}()
	var repos []*commitRepo
	if len(commitSamples) > 0 {
		gitDir := filepath.Join(opt.WorkDir, "git")
		if err := os.MkdirAll(gitDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, s := range commitSamples {
			r, err := buildCommitRepo(gitDir, s)
			if err != nil {
				t.Fatalf("building the repository of %s: %v", s.ID, err)
			}
			repos = append(repos, r)
		}
	}

	urls := map[string]string{}
	for name, s := range stubs {
		urls[name] = s.URL()
	}
	if len(urls) == 0 {
		// A proxy without a single upstream is not ready (/readyz): a run of
		// commit samples alone gets an idle registry that nothing pulls from.
		idle := newStubServer()
		defer idle.Close()
		urls["npm"] = idle.URL()
	}
	proc, err := startProxy(opt.ProxyBin, opt.WorkDir, runConfig{
		StateDir: filepath.Join(opt.WorkDir, "state"), Model: opt.Model, Upstreams: urls, Repos: repos,
	})
	if err != nil {
		t.Fatalf("starting the proxy: %v", err)
	}
	defer proc.stop()
	t.Logf("proxy %s (config %s, log %s)", proc.base, proc.cfgPath, proc.logPath)

	// The pulls. Each waits for its verdict, so they run side by side.
	results := make([]PackageResult, len(pulls))
	work := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < opt.Parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				results[i] = pullOne(proc, pulls[i])
				t.Logf("pulled %s %s %s@%s: %d %s (%s)", pulls[i].Sample.ID, pulls[i].Variant, pulls[i].Name, pulls[i].Version,
					results[i].Status, results[i].PolicyCode, results[i].PullTime)
			}
		}()
	}
	for i := range pulls {
		work <- i
	}
	close(work)
	wg.Wait()

	// A block must hold: pull each refused artifact again. The verdict is
	// cached, so the answer is the same and no model is asked.
	for i := range results {
		if results[i].Status == 403 && pulls[i].Variant == Malicious {
			results[i].Repull = repull(proc, pulls[i], opt.Model.Bridge)
		}
	}

	// The verdicts behind them.
	verdicts, err := listVerdicts(proc)
	if err != nil {
		t.Errorf("listing the package-scan verdicts: %v", err)
	}
	model := packageModel(opt.Model)
	for i := range results {
		judgePackage(&results[i], pulls[i], verdicts, model)
	}
	rep.Packages = results

	// The commit verdicts: the watcher scans the history on its own.
	if len(repos) > 0 {
		rep.Commits = awaitCommitVerdicts(t, proc, repos, 3*opt.Model.Timeout)
	}
	if opt.Model.Bridge != nil {
		rep.Calls = opt.Model.Bridge.Calls()
	}
	rep.Finished = time.Now().UTC()
	return rep
}

// repull requests a refused artifact again.
func repull(proc *proxyProc, p *pull, bridge *Bridge) *Repull {
	// Only package-scan completions count: the commit watcher keeps working in
	// the background and its calls are not the second pull's.
	calls := func() int {
		if bridge == nil {
			return -1
		}
		n := 0
		for _, c := range bridge.Calls() {
			if c.Kind == "package" {
				n++
			}
		}
		return n
	}
	before := calls()
	out := &Repull{}
	if r, err := proc.get(p.Upstream, p.Payload); err == nil {
		out.Status, out.PolicyCode = r.Status, r.Header.Get(hdrPolicyCode)
	}
	if before >= 0 {
		out.ModelCalls = calls() - before
	} else {
		out.ModelCalls = -1
	}
	return out
}

// pullOne makes the requests a client makes for one variant.
func pullOne(proc *proxyProc, p *pull) (res PackageResult) {
	s := p.Sample
	res = PackageResult{
		Sample: s.ID, Title: s.Title, Campaign: s.Campaign, Kind: s.Kind, Ecosystem: s.Ecosystem,
		Name: p.Name, Version: p.Version, Variant: p.Variant, Digest: p.Digest, Expected: "served",
	}
	if p.Variant == Malicious {
		res.Expected = "refused"
	}
	started := time.Now()
	defer func() { res.PullTime = time.Since(started).Round(time.Millisecond).String() }()
	mount := proc.base + "/v1/" + p.Upstream
	for _, st := range p.Preamble {
		r, err := proc.get(p.Upstream, st)
		if err != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("metadata request %s: %v", st.Path, err))
			continue
		}
		if r.Status != 200 {
			res.Problems = append(res.Problems, fmt.Sprintf("metadata request %s returned %d: %s", st.Path, r.Status, firstLine(r.Body)))
			continue
		}
		for _, want := range st.Contains {
			want = strings.ReplaceAll(want, mountPlaceholder, mount)
			if !bytes.Contains(r.Body, []byte(want)) {
				res.Problems = append(res.Problems, fmt.Sprintf("the document at %s does not send the client to %s", st.Path, want))
			}
		}
	}
	r, err := proc.get(p.Upstream, p.Payload)
	if err != nil {
		res.PullError = err.Error()
		return res
	}
	res.Status = r.Status
	res.PolicyCode = r.Header.Get(hdrPolicyCode)
	res.ScanCode = r.Header.Get(hdrScanCode)
	res.Decision = r.Header.Get(hdrScanDecision)
	res.Served = r.Status == 200
	res.SameBytes = res.Served && bytes.Equal(r.Body, p.Body)
	if res.Served {
		for _, f := range p.Followers {
			fr, err := proc.get(p.Upstream, f)
			if err != nil || fr.Status != 200 {
				status := 0
				if fr != nil {
					status = fr.Status
				}
				res.Problems = append(res.Problems, fmt.Sprintf("%s (follows a served image) was not served: %d %v", f.Path, status, err))
			}
		}
	}
	return res
}

// verdictRow is the part of a verdict listing row the suite reads.
type verdictRow struct {
	Digest     string  `json:"digest"`
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	// ConfidenceUnstated: the model gave a malicious verdict without a
	// confidence and the gate read it as 1.
	ConfidenceUnstated bool       `json:"confidenceUnstated"`
	Reasons            []string   `json:"reasons"`
	Evidence           []Evidence `json:"evidence"`
	Mode               string     `json:"mode"`
	Model              string     `json:"model"`
	Truncated          bool       `json:"truncated"`
	Coverage           []string   `json:"coverage"`
	InputTokens        int        `json:"inputTokens"`
	OutputTokens       int        `json:"outputTokens"`
	RootFS             bool       `json:"rootfs"`
	Scope              string     `json:"scope"`
}

// listVerdicts reads every stored verdict, by digest (a whole-artifact
// reading wins over a layer's or a metadata-only one).
func listVerdicts(proc *proxyProc) (map[string]verdictRow, error) {
	var doc struct {
		Verdicts []verdictRow `json:"verdicts"`
	}
	if _, err := proc.adminJSON("llmpkgscan/verdicts?limit=500", &doc); err != nil {
		return nil, err
	}
	out := map[string]verdictRow{}
	for _, v := range doc.Verdicts {
		if prev, ok := out[v.Digest]; ok && !prev.RootFS && prev.Scope == "" {
			continue
		}
		out[v.Digest] = v
	}
	return out, nil
}

// Outcomes of the pull of a malicious release.
const (
	OutcomeDetected  = "detected"           // refused on the model's malicious verdict
	OutcomeNoVerdict = "blocked-no-verdict" // refused because there was no verdict and failMode is closed
	OutcomeServed    = "served"
	OutcomeOther     = "other"
)

// packageModel is the model the package scan runs with: the one the run names,
// or the proxy's default.
func packageModel(m Model) string {
	if m.PackageModel != "" {
		return m.PackageModel
	}
	return string(commit.DefaultDeepModel)
}

// mayRefuse reports whether the sample lists model as one whose safeguards
// decline to judge it.
func mayRefuse(s *Sample, model string) bool {
	for _, m := range s.ModelsMayRefuse {
		if m == model {
			return true
		}
	}
	return false
}

// judgePackage fills in the verdict and decides whether the result meets its
// expectation.
//
// A malicious release must be blocked, and what blocks it matters. Refused on
// the model's malicious verdict is a detection. Refused because the provider's
// safeguards declined to judge it (provider-refusal: the gate has no verdict
// and only failMode closed stopped it) is not: it passes, with a note, only for
// a model the sample lists in modelsMayRefuse, and fails for any other, because
// there a new refusal is a regression. Any other unscanned reason (a timeout, a
// provider error) says nothing about the sample and fails. A malicious release
// that is served always fails.
func judgePackage(res *PackageResult, p *pull, verdicts map[string]verdictRow, model string) {
	if v, ok := verdicts[p.Digest]; ok {
		res.Verdict, res.Confidence, res.Reasons, res.Evidence = v.Verdict, v.Confidence, v.Reasons, v.Evidence
		res.ConfidenceUnstated = v.ConfidenceUnstated
		res.Mode, res.Model, res.Truncated, res.Coverage = v.Mode, v.Model, v.Truncated, v.Coverage
		res.InputTokens, res.OutputTokens = v.InputTokens, v.OutputTokens
	}
	if res.PullError != "" {
		res.Problems = append(res.Problems, "the pull failed: "+res.PullError)
	}
	switch p.Variant {
	case Malicious:
		switch {
		case res.Status == 403 && res.PolicyCode == policyMalicious:
			res.Outcome = OutcomeDetected
			if res.Verdict != "malicious" {
				res.Problems = append(res.Problems, fmt.Sprintf("the model's verdict is %q, want malicious", res.Verdict))
			}
			if mayRefuse(p.Sample, model) {
				res.Notes = append(res.Notes, model+" is listed in modelsMayRefuse for this sample but judged it: it may no longer decline (the list may be stale)")
			}
		case res.Status == 403 && res.PolicyCode == policyUnscanned:
			res.Outcome = OutcomeNoVerdict
			switch {
			case res.ScanCode == "provider-refusal" && mayRefuse(p.Sample, model):
				res.Notes = append(res.Notes, fmt.Sprintf("blocked without a verdict: %s declined to judge it (provider-refusal), as the sample records; only failMode closed stopped it", model))
			case res.ScanCode == "provider-refusal":
				res.Problems = append(res.Problems, fmt.Sprintf("blocked without a verdict: %s declined to judge it (provider-refusal). That is a detection gap (under failMode open the package is served); if it is expected, list the model in the sample's modelsMayRefuse", model))
			default:
				res.Problems = append(res.Problems, fmt.Sprintf("blocked without a verdict (the gate reports %q): the model did not judge the package", res.ScanCode))
			}
		case res.Status == 200:
			res.Outcome = OutcomeServed
			res.Problems = append(res.Problems, fmt.Sprintf("served: the malicious release was not refused (verdict %q)", res.Verdict))
		default:
			res.Outcome = OutcomeOther
			res.Problems = append(res.Problems, fmt.Sprintf("not refused as malicious: status %d, policy code %q, verdict %q", res.Status, res.PolicyCode, res.Verdict))
		}
		// A block must hold: the second pull is refused again, from the cached
		// verdict, without asking the model.
		if rp := res.Repull; rp != nil && res.Status == 403 {
			if rp.Status != 403 || rp.PolicyCode != res.PolicyCode {
				res.Problems = append(res.Problems, fmt.Sprintf("the block did not hold: a second pull got %d %q", rp.Status, rp.PolicyCode))
			}
			if rp.ModelCalls > 0 {
				res.Problems = append(res.Problems, fmt.Sprintf("a second pull of a refused artifact cost %d model call(s); the verdict should have been cached", rp.ModelCalls))
			}
		}
	default:
		if !res.Served {
			res.Problems = append(res.Problems, fmt.Sprintf("the clean release was not served: status %d, policy code %q, verdict %q", res.Status, res.PolicyCode, res.Verdict))
		} else if !res.SameBytes {
			res.Problems = append(res.Problems, "the clean release was served, but not byte for byte")
		}
		if res.Verdict == "malicious" {
			res.Problems = append(res.Problems, "false positive: the clean release was judged malicious")
		}
		if res.Verdict == "suspicious" {
			// Served (a suspicious verdict only annotates under action block), so
			// no failure, but a control the model doubts is worth a look.
			res.Notes = append(res.Notes, fmt.Sprintf("the clean release was served, but the model judged it suspicious (confidence %.2f): a near false positive", res.Confidence))
		}
		if res.Verdict == "" {
			res.Problems = append(res.Problems, "no verdict was recorded for the clean release")
		}
	}
	res.Pass = len(res.Problems) == 0
}

// commitVerdict is the part of a commit verdict the suite reads.
type commitVerdict struct {
	// Provider and InputTokens say whether a model judged the commit at all: a
	// deterministic-only verdict (no provider, or a degraded scan) is a clean
	// "benign" verdict that no model gave.
	Provider    string          `json:"provider"`
	Truncated   bool            `json:"truncated"`
	InputTokens int             `json:"inputTokens"`
	SHA         string          `json:"sha"`
	RiskScore   int             `json:"riskScore"`
	Malicious   bool            `json:"malicious"`
	Rationale   string          `json:"rationale"`
	Findings    []CommitFinding `json:"findings"`
	Models      []string        `json:"models"`
	Escalated   bool            `json:"escalated"`
	Error       string          `json:"error"`
}

// deepStage classifies the deep analysis of a commit verdict.
func deepStage(v *commitVerdict) string {
	switch {
	case v.Escalated:
		return "ok"
	case strings.HasPrefix(v.Error, "deep analysis failed") && strings.Contains(v.Error, "refused by safety system"):
		return "refused"
	case strings.HasPrefix(v.Error, "deep analysis failed"):
		return "failed"
	default:
		return "not needed"
	}
}

// judgeCommit fills in a commit's verdict and decides whether it meets its
// expectation (res.Variant says which it is).
//
// A malicious commit must be judged malicious, a control must not. A scan that
// did not complete is a problem, with one exception: when the triage model
// flagged the commit and only the deep analysis it asked for failed — the
// provider's safeguards may decline to read an attack — the pipeline keeps the
// triage verdict and records the degradation. The commit is still judged
// malicious, so it passes, with a note; the report's deep-stage column says what
// was lost.
func judgeCommit(res *CommitResult, v *commitVerdict) {
	res.RiskScore, res.Malicious, res.Rationale, res.Findings = v.RiskScore, v.Malicious, v.Rationale, v.Findings
	res.Models, res.Escalated, res.Error = v.Models, v.Escalated, v.Error
	res.DeepStage = deepStage(v)
	switch {
	case v.Error == "":
	case res.Variant == Malicious && v.Malicious && res.DeepStage == "refused":
		// Only a refusal is tolerated, not any failure of the deep stage: a
		// mistyped deep model, a rate-limit storm or a bridge error would
		// otherwise leave the deep stage silently dead while every attacker
		// commit still passed on the triage verdict.
		res.Notes = append(res.Notes, "judged malicious by the triage model alone: the provider's safeguards refused the deep analysis")
	default:
		res.Problems = append(res.Problems, "the scan did not complete: "+v.Error)
	}
	if v.Provider == "" || v.Provider == "none" || len(v.Models) == 0 || v.InputTokens == 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("no model judged this commit (provider %q, models %v, %d input tokens): the verdict is the deterministic fallback", v.Provider, v.Models, v.InputTokens))
	}
	if v.Truncated {
		res.Problems = append(res.Problems, "the diff was truncated: the model did not see all of the commit")
	}
	if res.Variant == Malicious && !v.Malicious {
		res.Problems = append(res.Problems, fmt.Sprintf("not judged malicious (risk %d)", v.RiskScore))
	}
	if res.Variant == Benign && v.Malicious {
		res.Problems = append(res.Problems, fmt.Sprintf("false positive: the control commit was judged malicious (risk %d): %s", v.RiskScore, capText(v.Rationale, 200)))
	}
}

// awaitCommitVerdicts waits for the commit scanner's verdicts on each
// repository's control and malicious commits.
func awaitCommitVerdicts(t *testing.T, proc *proxyProc, repos []*commitRepo, wait time.Duration) []CommitResult {
	t.Helper()
	type want struct {
		repo    *commitRepo
		variant Variant
		sha     string
	}
	var wants []want
	for _, r := range repos {
		wants = append(wants, want{r, Benign, r.Benign}, want{r, Malicious, r.Malicious})
	}
	found := map[string]*commitVerdict{}
	deadline := time.Now().Add(wait)
	for {
		for _, w := range wants {
			if _, ok := found[w.sha]; ok {
				continue
			}
			var v commitVerdict
			if status, err := proc.adminJSON("scans/entry?sha="+w.sha, &v); err == nil {
				found[w.sha] = &v
			} else if status != 404 {
				t.Logf("reading the verdict of %s: %v", w.sha, err)
			}
		}
		if len(found) == len(wants) || time.Now().After(deadline) {
			break
		}
		time.Sleep(3 * time.Second)
	}
	var out []CommitResult
	for _, w := range wants {
		s := w.repo.Sample
		res := CommitResult{
			Sample: s.ID, Title: s.Title, Campaign: s.Campaign, Repository: s.Commit.Repository,
			Variant: w.variant, SHA: w.sha, Expected: "benign",
		}
		if w.variant == Malicious {
			res.Expected = "malicious"
		}
		if v, ok := found[w.sha]; ok {
			judgeCommit(&res, v)
		} else {
			res.Problems = append(res.Problems, fmt.Sprintf("no commit-scan verdict within %s", wait))
		}
		res.Pass = len(res.Problems) == 0
		out = append(out, res)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Sample < out[j].Sample })
	return out
}
