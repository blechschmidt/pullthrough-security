//go:build integration

package livescan

import (
	"testing"
	"time"
)

// TestKnownMalwareHermetic runs the live suite's machinery end to end without
// a model or a credential: the real proxy binary, the stub registries, the
// commit repositories, the Claude Code bridge — with the fake CLI behind it,
// which judges by the corpus's indicators instead of reading the code.
//
// It proves the plumbing the gated live job relies on, so that job cannot rot
// unnoticed while it is switched off: the corpus builds into artifacts every
// backend accepts, a malicious verdict refuses the pull, a clean one serves
// it, the commit scanner's verdicts are collected, and every CLI session the
// bridge ran had no tools. It says nothing about what a real model concludes
// — that is TestKnownMalwareLive's question.
func TestKnownMalwareHermetic(t *testing.T) {
	samples, partial := selectSamples(t)
	bridge := startFakeBridge(t, fakeVerdict)
	model := Model{
		Label:   "fake CLI behind the Claude Code bridge (hermetic)",
		BaseURL: bridge.BaseURL(), APIKey: bridge.APIKey(), Mode: "bundle",
		PackageModel: "fake-package-model", TriageModel: "fake-triage-model", DeepModel: "fake-deep-model",
		Timeout: time.Minute, Bridge: bridge,
	}
	rep := runSuite(t, suiteOptions{
		Samples: samples, Partial: partial, Model: model,
		ProxyBin: proxyBinary(t), WorkDir: t.TempDir(), Parallel: 4,
	})
	for _, f := range rep.Failures() {
		t.Error(f)
	}
	if len(rep.Calls) == 0 {
		t.Fatal("the bridge served no completion: the gates never reached it")
	}
	for _, p := range rep.Packages {
		if p.Variant != Malicious {
			continue
		}
		// A block holds: the refused artifact is refused again, from the
		// cached verdict, without asking the model.
		if p.Repull == nil || p.Repull.Status != 403 || p.Repull.ModelCalls != 0 {
			t.Errorf("%s: second pull of the refused artifact: %+v, want 403 and no model call", p.Sample, p.Repull)
		}
	}
	kinds := map[string]int{}
	for _, c := range rep.Calls {
		kinds[c.Kind]++
		if len(c.Tools) > 0 || len(c.MCPServers) > 0 || c.Status != 200 {
			t.Errorf("bridge call %d: status %d (%s), tools %v, MCP servers %v", c.Seq, c.Status, c.Outcome, c.Tools, c.MCPServers)
		}
	}
	if len(rep.Commits) > 0 && kinds["commit"] == 0 {
		t.Errorf("no commit-scan completion went through the bridge (calls by kind: %v)", kinds)
	}
	if len(rep.Packages) > 0 && kinds["package"] == 0 {
		t.Errorf("no package-scan completion went through the bridge (calls by kind: %v)", kinds)
	}
	t.Logf("%d package checks, %d commit checks, bridge calls by kind %v", len(rep.Packages), len(rep.Commits), kinds)
}
