//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Policy codes and reason codes the gate answers with. They are spelled out
// here rather than imported from internal/llmpkgscan on purpose: they are part
// of the proxy's contract with its clients and its operators' automation, and
// this suite holds the binary to the documented spelling.
const (
	policyMalicious  = "llm-package-malicious"
	policySuspicious = "llm-package-suspicious"
	policyUnscanned  = "llm-package-unscanned"

	codeProviderError = "provider-error"
	codeTimeout       = "timeout"

	ruleMaliciousPackage = "llmpkgscan/malicious-package"
)

// Response headers the gate sets (canonical MIME form).
const (
	hdrDecision     = "X-Llmpkgscan-Decision"
	hdrVerdict      = "X-Llmpkgscan-Verdict"
	hdrModelVerdict = "X-Llmpkgscan-Model-Verdict"
	hdrCached       = "X-Llmpkgscan-Cached"
	hdrCode         = "X-Llmpkgscan-Code"
	hdrReason       = "X-Llmpkgscan-Reason"
	hdrPolicyCode   = "X-Policy-Code"
	hdrPolicyDec    = "X-Policy-Decision"
	hdrCache        = "X-Cache"
)

// blockBody is the JSON body of a refusal by the gate.
type blockBody struct {
	Error        string  `json:"error"`
	Code         string  `json:"code"`
	PolicyCode   string  `json:"policyCode"`
	Action       string  `json:"action"`
	Reason       string  `json:"reason"`
	Ecosystem    string  `json:"ecosystem"`
	Package      string  `json:"package"`
	Version      string  `json:"version"`
	Digest       string  `json:"digest"`
	Verdict      string  `json:"verdict"`
	ModelVerdict string  `json:"modelVerdict"`
	Confidence   float64 `json:"confidence"`
	Locations    []struct {
		Path string `json:"path"`
		Line int    `json:"line"`
	} `json:"locations"`
	RetryAfterSeconds int `json:"retryAfterSeconds"`
}

// runner drives one ecosystem's row.
type runner struct {
	t    *testing.T
	bin  string
	e    eco
	row  *row
	dir  string // the row's workspace
	stub *stub
	keep bool

	procs []*proxyProc
	llms  []*mockLLM
}

// newRunner prepares a row's workspace and stub registry.
func newRunner(t *testing.T, bin, workDir string, e eco, rw *row) *runner {
	t.Helper()
	r := &runner{t: t, bin: bin, e: e, row: rw, dir: filepath.Join(workDir, e.ID), keep: os.Getenv(envKeep) != ""}
	if err := os.RemoveAll(r.dir); err != nil {
		t.Fatalf("clearing the workspace: %v", err)
	}
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		t.Fatalf("creating the workspace: %v", err)
	}
	t.Cleanup(r.cleanup)
	if e.Registry != nil {
		s, err := startStub(e)
		if err != nil {
			t.Fatalf("%v", err)
		}
		r.stub = s
	}
	return r
}

// cleanup stops whatever the row started and, when the row failed, says where
// its evidence is and what the stub registry was asked for.
func (r *runner) cleanup() {
	for _, p := range r.procs {
		p.stop()
	}
	for _, m := range r.llms {
		m.Close()
	}
	if r.stub != nil {
		r.stub.Close()
	}
	if r.t.Failed() {
		r.t.Logf("[%s] workspace kept for diagnosis: %s", r.e.ID, r.dir)
		if r.stub != nil {
			reqs := r.stub.reg.mux.Requests()
			if len(reqs) > 60 {
				reqs = append([]string{fmt.Sprintf("… (%d earlier requests)", len(reqs)-60)}, reqs[len(reqs)-60:]...)
			}
			r.t.Logf("[%s] requests the stub registry received:\n  %s", r.e.ID, strings.Join(reqs, "\n  "))
		}
		for _, p := range r.procs {
			r.t.Logf("[%s] %s proxy log tail (%s):\n%s", r.e.ID, p.pc.Role, p.logPath, tailFile(p.logPath, 12))
		}
		return
	}
	if !r.keep {
		_ = os.RemoveAll(r.dir)
	}
}

// failf records a failed assertion under a scenario and reports it.
func (r *runner) failf(sc scenario, format string, args ...any) {
	r.t.Helper()
	msg := fmt.Sprintf(format, args...)
	r.row.fail(sc, msg)
	r.t.Errorf("[%s] %s: %s", r.e.ID, sc.ID, msg)
}

// llm starts a mock LLM endpoint for the row.
func (r *runner) llm() *mockLLM {
	m := startMockLLM()
	r.llms = append(r.llms, m)
	return m
}

// start starts a proxy process for the row. A proxy that does not come up
// leaves nothing to assert on: the row stops there.
func (r *runner) start(role, stateDir string, gate *gateConfig, llm *mockLLM) *proxyProc {
	r.t.Helper()
	stubURL := ""
	if r.stub != nil {
		stubURL = r.stub.URL()
	}
	p, err := startProxy(r.bin, r.dir, procConfig{Role: role, Eco: r.e, StubURL: stubURL, StateDir: stateDir, Gate: gate, LLM: llm})
	if err != nil {
		r.t.Fatalf("[%s] starting the %s proxy: %v", r.e.ID, role, err)
	}
	r.procs = append(r.procs, p)
	return p
}

// pull makes the requests a client makes for one package: its metadata
// requests, then the payload. It returns the payload's response. A metadata
// request that is not served, or does not say what the fixture expects, is a
// failure of sc — and so is a transport error on the payload, for which nil is
// returned.
func (r *runner) pull(p *proxyProc, v variant, sc scenario) *response {
	r.t.Helper()
	pk := r.stub.reg.pulls[v]
	for _, st := range pk.Preamble {
		res, err := p.get(st)
		if err != nil {
			r.failf(sc, "%s proxy: metadata request %s (%s package): %v", p.pc.Role, st.Path, v, err)
			continue
		}
		if res.Status != http.StatusOK {
			r.failf(sc, "%s proxy: metadata request %s (%s package) returned %d, want 200: %s",
				p.pc.Role, st.Path, v, res.Status, firstLine(res.Body))
			continue
		}
		// A document is not a package: the gate must leave it alone, whatever the
		// fail mode — or a fail-closed proxy would break every client for nothing.
		if d := res.Header.Get(hdrPolicyCode); strings.HasPrefix(d, "llm-package-") {
			r.failf(sc, "%s proxy: metadata request %s was put before the package gate (%s)", p.pc.Role, st.Path, d)
		}
		for _, want := range st.Contains {
			want = strings.ReplaceAll(want, mountPlaceholder, p.mount())
			if !bytes.Contains(res.Body, []byte(want)) {
				r.failf(sc, "%s proxy: the document at %s does not contain %q — a client reading it would not be sent to the payload through the proxy.\nDocument: %s",
					p.pc.Role, st.Path, want, clip(res.Body, 1500))
			}
		}
	}
	res, err := p.get(pk.Payload)
	if err != nil {
		r.failf(sc, "%s proxy: payload request %s (%s package): %v", p.pc.Role, pk.Payload.Path, v, err)
		return nil
	}
	return res
}

// clip bounds a body for a failure message.
func clip(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}

// expectServed asserts that a payload response is the artifact, served.
func (r *runner) expectServed(sc scenario, p *proxyProc, v variant, res *response) bool {
	r.t.Helper()
	if res == nil {
		return false
	}
	pk := r.stub.reg.pulls[v]
	if res.Status != http.StatusOK {
		r.failf(sc, "%s proxy: the %s package (%s) returned %d, want 200. Headers: %s. Body: %s",
			p.pc.Role, v, pk.Payload.Path, res.Status, gateHeaders(res.Header), clip(res.Body, 600))
		return false
	}
	if !bytes.Equal(res.Body, pk.Body) {
		r.failf(sc, "%s proxy: the %s package was served, but not byte for byte: got %d bytes (%s), the registry holds %d (%s)",
			p.pc.Role, v, len(res.Body), digestOf(res.Body), len(pk.Body), digestOf(pk.Body))
		return false
	}
	return true
}

// gateHeaders renders the response headers that say what the gates decided.
func gateHeaders(h http.Header) string {
	var parts []string
	for _, k := range []string{hdrDecision, hdrVerdict, hdrModelVerdict, hdrCached, hdrCode, hdrPolicyDec, hdrPolicyCode, "X-Policy-Reason", hdrCache} {
		if v := h.Get(k); v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	if len(parts) == 0 {
		return "(none of the gate's)"
	}
	return strings.Join(parts, " ")
}

// expectRefused asserts that a payload response is a refusal by the gate with
// the given policy code, carrying no artifact bytes, and returns its body.
func (r *runner) expectRefused(sc scenario, p *proxyProc, v variant, res *response, policyCode string) *blockBody {
	r.t.Helper()
	if res == nil {
		return nil
	}
	pk := r.stub.reg.pulls[v]
	if res.Status != http.StatusForbidden {
		r.failf(sc, "%s proxy: the %s package (%s) returned %d, want 403. Headers: %s",
			p.pc.Role, v, pk.Payload.Path, res.Status, gateHeaders(res.Header))
		return nil
	}
	ok := true
	for header, want := range map[string]string{hdrPolicyDec: "block", hdrPolicyCode: policyCode, hdrCache: "BLOCKED", hdrDecision: "block"} {
		if got := res.Header.Get(header); got != want {
			r.failf(sc, "%s proxy: refusal of the %s package has %s = %q, want %q (headers: %s)",
				p.pc.Role, v, header, got, want, gateHeaders(res.Header))
			ok = false
		}
	}
	// Not one byte of the artifact: neither the file itself nor its text.
	if bytes.Contains(res.Body, pk.Body) || bytes.Contains(res.Body, []byte(r.spec(v).Token)) {
		r.failf(sc, "%s proxy: the refusal of the %s package carries artifact content", p.pc.Role, v)
		ok = false
	}
	var body blockBody
	if err := json.Unmarshal(res.Body, &body); err != nil {
		r.failf(sc, "%s proxy: the refusal of the %s package is not the documented JSON body: %v: %s", p.pc.Role, v, err, clip(res.Body, 300))
		return nil
	}
	if body.PolicyCode != policyCode {
		r.failf(sc, "%s proxy: refusal body policyCode = %q, want %q", p.pc.Role, body.PolicyCode, policyCode)
		ok = false
	}
	if !ok {
		return nil
	}
	return &body
}

// spec returns the spec of a variant for this row.
func (r *runner) spec(v variant) pkgSpec { return newSpec(r.e.ID, v) }

// scans counts the package-scan completions a mock served for a variant.
func (r *runner) scans(m *mockLLM, v variant) int { return len(m.PackageScans(r.spec(v).Token)) }

// follow requests a package's followers and asserts each is served (want 200)
// or refused (want 403).
func (r *runner) follow(sc scenario, p *proxyProc, v variant, want int) {
	r.t.Helper()
	for _, st := range r.stub.reg.pulls[v].Followers {
		res, err := p.get(st)
		if err != nil {
			r.failf(sc, "%s proxy: %s (follows the %s package): %v", p.pc.Role, st.Path, v, err)
			continue
		}
		if res.Status != want {
			r.failf(sc, "%s proxy: %s follows the verdict on the %s package and returned %d, want %d (headers: %s)",
				p.pc.Role, st.Path, v, res.Status, want, gateHeaders(res.Header))
		}
	}
}

// expectCached asserts whether the content cache holds a variant's artifact.
// It is skipped for a payload the backend never caches.
func (r *runner) expectCached(sc scenario, p *proxyProc, v variant, want bool, why string) {
	r.t.Helper()
	pk := r.stub.reg.pulls[v]
	if pk.Uncached {
		return
	}
	got, err := p.cached(digestOf(pk.Body))
	if err != nil {
		r.failf(sc, "%s proxy: %v", p.pc.Role, err)
		return
	}
	if got != want {
		state := map[bool]string{true: "holds", false: "does not hold"}
		r.failf(sc, "%s proxy: the content cache %s the %s package (%s): %s", p.pc.Role, state[got], v, digestOf(pk.Body), why)
	}
}

// standard runs the scenarios of a package-scan row.
//
// Four proxy processes are started in turn, over two state directories:
//
//	strict    action quarantine, failMode closed, Anthropic wire format — the
//	          strictest posture: every scenario but fail-open.
//	strict'   the same deployment restarted: verdicts and refusals survive.
//	control   the gate off, on a fresh state directory: the very same packages
//	          are served, so every refusal elsewhere is the gate's doing — and
//	          the content cache now holds them.
//	default   the gate on with its shipped defaults (action block, failMode
//	          open; neither is written to the file), OpenAI wire format, on the
//	          control's state: packages cached before the gate existed.
func (r *runner) standard() {
	began := time.Now()
	defer func() { r.row.Seconds = time.Since(began).Seconds() }()

	strictState := filepath.Join(r.dir, "state-strict")
	defaultState := filepath.Join(r.dir, "state-default")
	strictGate := &gateConfig{Provider: "claude", Action: "quarantine", FailMode: "closed"}

	llmA := r.llm()
	p := r.start("strict", strictState, strictGate, llmA)
	r.checkPosture(p, "claude", "quarantine", "closed")
	r.strictBenign(p, llmA)
	r.strictMalicious(p, llmA)
	r.strictInjection(p, llmA)
	r.strictFailClosed(p, llmA)
	p.stop()
	if err := verifyAudit(r.bin, strictState); err != nil {
		r.failf(scAudit, "%v", err)
	}

	p = r.start("strict-restarted", strictState, strictGate, llmA)
	r.afterRestart(p, llmA)
	p.stop()

	p = r.start("control", defaultState, nil, nil)
	r.control(p)
	p.stop()

	llmB := r.llm()
	p = r.start("default", defaultState, &gateConfig{Provider: "openai"}, llmB)
	r.checkPosture(p, "openai", "block", "open")
	r.defaults(p, llmB)
	p.stop()

	r.row.LLMCalls = len(llmA.Calls()) + len(llmB.Calls())
	for _, sc := range packageScenarios() {
		r.row.pass(sc)
	}
}

// checkPosture confirms that the process runs the gate the scenario is about:
// the provider, action and fail mode the configuration asked for — or, where it
// asked for none, the shipped defaults.
func (r *runner) checkPosture(p *proxyProc, provider, action, failMode string) {
	r.t.Helper()
	st, err := p.status()
	if err != nil {
		r.t.Fatalf("[%s] %s proxy: reading the gate status: %v", r.e.ID, p.pc.Role, err)
	}
	if !st.Enabled || st.Provider != provider || st.Action != action || st.FailMode != failMode {
		r.t.Fatalf("[%s] %s proxy runs the gate as enabled=%v provider=%s action=%s failMode=%s; the scenario needs %s/%s/%s",
			r.e.ID, p.pc.Role, st.Enabled, st.Provider, st.Action, st.FailMode, provider, action, failMode)
	}
}

// strictBenign: (a) a benign artifact is served and the model was shown its
// contents; (c) a second pull costs no LLM call.
func (r *runner) strictBenign(p *proxyProc, llm *mockLLM) {
	pk := r.stub.reg.pulls[benign]
	spec := r.spec(benign)

	res := r.pull(p, benign, scBenignServed)
	if r.expectServed(scBenignServed, p, benign, res) {
		if got := res.Header.Get(hdrDecision); got != "clean" {
			r.failf(scBenignServed, "the benign package was served with %s = %q, want \"clean\" (headers: %s)", hdrDecision, got, gateHeaders(res.Header))
		}
		if got := res.Header.Get(hdrVerdict); got != "benign" {
			r.failf(scBenignServed, "the benign package was served with %s = %q, want \"benign\"", hdrVerdict, got)
		}
		if got := res.Header.Get(hdrPolicyCode); got != "" {
			r.failf(scBenignServed, "the benign package was served with a policy code (%q)", got)
		}
	}
	r.follow(scBenignServed, p, benign, http.StatusOK)

	r.expectShown(scContentScanned, llm, benign, "anthropic", "benign")
	if v, err := p.verdictFor(digestOf(pk.Body)); err != nil {
		r.failf(scContentScanned, "%v", err)
	} else {
		if v.Verdict != "benign" || v.Provider != "claude" || v.Model != "mock-model" {
			r.failf(scContentScanned, "the stored verdict is %s by %s/%s, want benign by claude/mock-model", v.Verdict, v.Provider, v.Model)
		}
		if v.Files < 1 || v.Truncated {
			r.failf(scContentScanned, "the stored verdict rests on %d file(s), truncated=%v: the artifact (%s, %s) was not read whole",
				v.Files, v.Truncated, v.Format, v.Kind)
		}
		r.row.ScannedAs = fmt.Sprintf("%s, read as %s: %d file(s)", v.Format, v.Kind, v.Files)
		r.row.Marker = pk.Marker
	}

	before := r.scans(llm, benign)
	res = r.pull(p, benign, scVerdictCached)
	if r.expectServed(scVerdictCached, p, benign, res) {
		if got := res.Header.Get(hdrCached); got != "true" {
			r.failf(scVerdictCached, "the second pull has %s = %q, want \"true\" (headers: %s)", hdrCached, got, gateHeaders(res.Header))
		}
		if !pk.Uncached {
			if got := res.Header.Get(hdrCache); got != "HIT" {
				r.failf(scVerdictCached, "the second pull has %s = %q, want HIT", hdrCache, got)
			}
		}
	}
	if after := r.scans(llm, benign); after != before {
		r.failf(scVerdictCached, "the second pull of the benign package cost %d more LLM call(s) (token %s)", after-before, spec.Token)
	}
}

// expectShown asserts that the mock was asked about a variant's artifact over
// the given wire format, was shown its marker file — path and content token —
// and answered as expected.
func (r *runner) expectShown(sc scenario, llm *mockLLM, v variant, wire, outcome string) {
	r.t.Helper()
	pk := r.stub.reg.pulls[v]
	spec := r.spec(v)
	calls := llm.PackageScans(spec.Token)
	if len(calls) == 0 {
		r.failf(sc, "the mock LLM was never shown the %s package's content token %s: the artifact's contents did not reach the model (%d completions served in all)",
			v, spec.Token, len(llm.Calls()))
		return
	}
	c := calls[len(calls)-1]
	if c.Wire != wire {
		r.failf(sc, "the %s package was scanned over the %s wire format, want %s", v, c.Wire, wire)
	}
	if !c.Authorized {
		r.failf(sc, "the scan request for the %s package did not carry the configured API key", v)
	}
	if c.Model != "mock-model" {
		r.failf(sc, "the scan request for the %s package named model %q, want the configured one", v, c.Model)
	}
	if !strings.Contains(c.Material, pk.Marker) {
		r.failf(sc, "the material shown to the model for the %s package does not name the marker file %q.\nMaterial:\n%s", v, pk.Marker, clip([]byte(c.Material), 3000))
	}
	if c.Outcome != outcome {
		r.failf(sc, "the mock LLM's answer for the %s package was %q, want %q", v, c.Outcome, outcome)
	}
}

// strictMalicious: (b) a flagged artifact is refused, quarantined, never
// served on a retry, and leaves a finding and audit records.
func (r *runner) strictMalicious(p *proxyProc, llm *mockLLM) {
	pk := r.stub.reg.pulls[malicious]
	spec := r.spec(malicious)
	digest := digestOf(pk.Body)

	res := r.pull(p, malicious, scMaliciousBlocked)
	if body := r.expectRefused(scMaliciousBlocked, p, malicious, res, policyMalicious); body != nil {
		if body.Code != "malicious" || body.Verdict != "malicious" || body.ModelVerdict != "malicious" || body.Action != "quarantine" {
			r.failf(scMaliciousBlocked, "refusal body: code=%q verdict=%q modelVerdict=%q action=%q, want malicious/malicious/malicious/quarantine",
				body.Code, body.Verdict, body.ModelVerdict, body.Action)
		}
		if body.Package != pk.Name || body.Version != pk.Version {
			r.failf(scMaliciousBlocked, "the refusal names %q version %q, want %q version %q", body.Package, body.Version, pk.Name, pk.Version)
		}
		if body.Digest != digest {
			r.failf(scMaliciousBlocked, "the refusal names digest %s, want the digest of the artifact, %s", body.Digest, digest)
		}
		wantLine := spec.MarkerLine(pk.MarkerOffset)
		switch {
		case len(body.Locations) == 0 || body.Locations[0].Path != pk.Marker:
			r.failf(scMaliciousBlocked, "the refusal cites %+v, want the confirmed location in %s", body.Locations, pk.Marker)
		case pk.MarkerAnyLine && body.Locations[0].Line < 1:
			r.failf(scMaliciousBlocked, "the refusal cites %s without a line", pk.Marker)
		case !pk.MarkerAnyLine && body.Locations[0].Line != wantLine:
			r.failf(scMaliciousBlocked, "the refusal cites %s:%d, want line %d", pk.Marker, body.Locations[0].Line, wantLine)
		}
		if got := res.Header.Get(hdrVerdict); got != "malicious" {
			r.failf(scMaliciousBlocked, "refusal header %s = %q, want malicious", hdrVerdict, got)
		}
		if res.Header.Get("Retry-After") != "" {
			r.failf(scMaliciousBlocked, "a verdict is not a passing fault, but the refusal carries Retry-After")
		}
	}
	r.expectShown(scMaliciousBlocked, llm, malicious, "anthropic", "malicious")

	// Quarantined: not retained, a review open for exactly these bytes, and
	// refused again — from the stored verdict — when asked for again.
	r.expectCached(scQuarantined, p, malicious, false, "a refused artifact must be evicted")
	r.follow(scQuarantined, p, malicious, http.StatusForbidden)
	if reviews, err := p.reviews(); err != nil {
		r.failf(scQuarantined, "listing reviews: %v", err)
	} else {
		open := false
		for _, rv := range reviews {
			if rv.Gate == "llmpkgscan" && rv.Status == "pending" && strings.Contains(rv.Reason, digest) {
				open = true
			}
		}
		if !open {
			r.failf(scQuarantined, "no pending llmpkgscan review is open for %s (reviews: %+v)", digest, reviews)
		}
	}
	before := r.scans(llm, malicious)
	res = r.pull(p, malicious, scQuarantined)
	if body := r.expectRefused(scQuarantined, p, malicious, res, policyMalicious); body != nil {
		if got := res.Header.Get(hdrCached); got != "true" {
			r.failf(scQuarantined, "the retry was refused with %s = %q, want \"true\": the refusal should come from the stored verdict", hdrCached, got)
		}
	}
	if after := r.scans(llm, malicious); after != before {
		r.failf(scQuarantined, "the retry of the refused package cost %d more LLM call(s)", after-before)
	}
	r.expectCached(scQuarantined, p, malicious, false, "the re-fetched artifact must not be left in the cache")

	// Finding.
	findingsName := pk.Name
	if pk.FindingsName != "" {
		findingsName = pk.FindingsName
	}
	if docs, err := p.findings(); err != nil {
		r.failf(scFinding, "listing findings: %v", err)
	} else {
		var found *finding
		for i := range docs {
			if docs[i].Artifact.Name != findingsName || docs[i].Artifact.Version != pk.Version {
				continue
			}
			for j := range docs[i].Findings {
				if docs[i].Findings[j].RuleID == ruleMaliciousPackage {
					found = &docs[i].Findings[j]
				}
			}
		}
		switch {
		case found == nil:
			r.failf(scFinding, "no %s finding is recorded for %s@%s (%d findings documents)", ruleMaliciousPackage, findingsName, pk.Version, len(docs))
		case found.Gate != "llmpkgscan" || found.Location.File != pk.Marker:
			r.failf(scFinding, "the finding is by gate %q at %q, want llmpkgscan at %q", found.Gate, found.Location.File, pk.Marker)
		}
	}

	// Audit records, for these bytes.
	r.expectAudit(p.pc.StateDir, digest, "malicious")
}

// expectAudit asserts that the audit log of a state directory holds the
// verdict on, and a refusal of, the bytes with the given digest.
func (r *runner) expectAudit(stateDir, digest, verdict string) {
	r.t.Helper()
	// The log is appended as each request completes; give the writer a moment.
	var verdictSeen, refusalSeen bool
	deadline := time.Now().Add(3 * time.Second)
	for {
		events, err := auditEvents(stateDir)
		if err != nil {
			r.failf(scAudit, "reading the audit log: %v", err)
			return
		}
		for _, ev := range events {
			if ev.Detail["digest"] != digest || ev.Reason != "llmpkgscan:"+verdict {
				continue
			}
			switch {
			case ev.Type == "scan_verdict" && ev.Decision == "deny":
				verdictSeen = true
			case ev.Type == "policy_decision" && ev.Decision == "deny" && ev.Status == http.StatusForbidden:
				refusalSeen = true
			}
		}
		if (verdictSeen && refusalSeen) || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !verdictSeen {
		r.failf(scAudit, "the audit log has no scan_verdict record (llmpkgscan:%s, deny) for %s", verdict, digest)
	}
	if !refusalSeen {
		r.failf(scAudit, "the audit log has no policy_decision record (llmpkgscan:%s, deny, 403) for %s", verdict, digest)
	}
}

// strictInjection: (e) text in the package that tells the reviewer what to
// answer does not turn a malicious verdict around — and where the model does
// follow it, the gate still does not call the package clean.
func (r *runner) strictInjection(p *proxyProc, llm *mockLLM) {
	pk := r.stub.reg.pulls[injection]

	res := r.pull(p, injection, scInjectionResisted)
	if body := r.expectRefused(scInjectionResisted, p, injection, res, policyMalicious); body != nil {
		if body.Verdict != "malicious" || body.ModelVerdict != "malicious" {
			r.failf(scInjectionResisted, "refusal body: verdict=%q modelVerdict=%q, want malicious/malicious", body.Verdict, body.ModelVerdict)
		}
	}
	r.expectShown(scInjectionResisted, llm, injection, "anthropic", "malicious")
	if calls := llm.PackageScans(r.spec(injection).Token); len(calls) > 0 && !strings.Contains(calls[len(calls)-1].Material, injectionText) {
		r.failf(scInjectionResisted, "the injection text did not reach the model: the scenario tested nothing")
	}
	if v, err := p.verdictFor(digestOf(pk.Body)); err != nil {
		r.failf(scInjectionResisted, "%v", err)
	} else {
		recorded := false
		for _, hit := range v.Injection {
			if hit.Strong && hit.Rule == "ignore-instructions" && hit.Path == pk.Marker {
				recorded = true
			}
		}
		if !recorded {
			r.failf(scInjectionResisted, "the stored verdict does not record the injection attempt (rule ignore-instructions in %s): %+v", pk.Marker, v.Injection)
		}
	}
	r.expectCached(scInjectionResisted, p, injection, false, "a refused artifact must be evicted")

	// The same package, and a model that obeys it.
	res = r.pull(p, obeyed, scInjectionFloor)
	if body := r.expectRefused(scInjectionFloor, p, obeyed, res, policySuspicious); body != nil {
		if body.Verdict != "suspicious" || body.ModelVerdict != "benign" || body.Code != "suspicious" {
			r.failf(scInjectionFloor, "refusal body: verdict=%q modelVerdict=%q code=%q; want the gate's reading (suspicious) apart from the model's answer (benign)",
				body.Verdict, body.ModelVerdict, body.Code)
		}
		if got := res.Header.Get(hdrModelVerdict); got != "benign" {
			r.failf(scInjectionFloor, "%s = %q, want benign: the model was meant to be taken in", hdrModelVerdict, got)
		}
	}
	r.expectShown(scInjectionFloor, llm, obeyed, "anthropic", "obeyed")
	r.expectCached(scInjectionFloor, p, obeyed, false, "a held artifact must be evicted")
}

// strictFailClosed: (d) with failMode closed, a provider error and a scan
// timeout each refuse the pull.
func (r *runner) strictFailClosed(p *proxyProc, llm *mockLLM) {
	res := r.pull(p, llmerror, scFailClosedError)
	if body := r.expectRefused(scFailClosedError, p, llmerror, res, policyUnscanned); body != nil {
		if body.Code != codeProviderError || body.Verdict != "unscanned" || body.Action != "fail-closed" || body.ModelVerdict != "" {
			r.failf(scFailClosedError, "refusal body: code=%q verdict=%q action=%q modelVerdict=%q, want %s/unscanned/fail-closed/(none)",
				body.Code, body.Verdict, body.Action, body.ModelVerdict, codeProviderError)
		}
		if res.Header.Get(hdrCode) != codeProviderError {
			r.failf(scFailClosedError, "%s = %q, want %s", hdrCode, res.Header.Get(hdrCode), codeProviderError)
		}
		if res.Header.Get("Retry-After") == "" || body.RetryAfterSeconds == 0 {
			r.failf(scFailClosedError, "a provider failure is a passing fault: the refusal should invite a retry (Retry-After)")
		}
	}
	r.expectShown(scFailClosedError, llm, llmerror, "anthropic", "error")
	r.expectOneAttempt(scFailClosedError, llm)
	// Nothing was established about the artifact, so nothing is evicted.
	r.expectCached(scFailClosedError, p, llmerror, true, "an unscanned artifact must not be evicted")

	began := time.Now()
	res = r.pull(p, llmhang, scFailClosedTimeout)
	elapsed := time.Since(began)
	if body := r.expectRefused(scFailClosedTimeout, p, llmhang, res, policyUnscanned); body != nil {
		if body.Code != codeTimeout || body.Verdict != "unscanned" || body.Action != "fail-closed" {
			r.failf(scFailClosedTimeout, "refusal body: code=%q verdict=%q action=%q, want %s/unscanned/fail-closed", body.Code, body.Verdict, body.Action, codeTimeout)
		}
		if res.Header.Get(hdrCode) != codeTimeout {
			r.failf(scFailClosedTimeout, "%s = %q, want %s", hdrCode, res.Header.Get(hdrCode), codeTimeout)
		}
	}
	if elapsed < scanTimeout-500*time.Millisecond {
		r.failf(scFailClosedTimeout, "the pull was answered after %s, before llmPackageScan.timeout (%s) could have elapsed: this was not a timeout", elapsed.Round(time.Millisecond), scanTimeout)
	}
	r.expectShown(scFailClosedTimeout, llm, llmhang, "anthropic", "hang")
}

// expectOneAttempt asserts that the provider was asked exactly once about the
// package whose scan fails: every proxy of the suite is configured with
// llmPackageScan.maxRetries: -1, which the configuration documents as "no
// retries" — for either provider client.
func (r *runner) expectOneAttempt(sc scenario, llm *mockLLM) {
	r.t.Helper()
	if n := r.scans(llm, llmerror); n != 1 {
		r.failf(sc, "the provider was asked %d times about the package whose scan fails; with llmPackageScan.maxRetries: -1 it must be asked once", n)
	}
}

// afterRestart: the same deployment, restarted. (c) The verdict on the benign
// artifact is still there; (b) so is the refusal of the malicious one.
func (r *runner) afterRestart(p *proxyProc, llm *mockLLM) {
	beforeBenign, beforeMalicious := r.scans(llm, benign), r.scans(llm, malicious)

	res := r.pull(p, benign, scVerdictCached)
	if r.expectServed(scVerdictCached, p, benign, res) {
		if got := res.Header.Get(hdrCached); got != "true" {
			r.failf(scVerdictCached, "after a restart the benign package was served with %s = %q, want \"true\": the verdict store did not survive", hdrCached, got)
		}
	}
	if after := r.scans(llm, benign); after != beforeBenign {
		r.failf(scVerdictCached, "after a restart the benign package cost %d more LLM call(s)", after-beforeBenign)
	}

	res = r.pull(p, malicious, scQuarantined)
	if body := r.expectRefused(scQuarantined, p, malicious, res, policyMalicious); body != nil {
		if got := res.Header.Get(hdrCached); got != "true" {
			r.failf(scQuarantined, "after a restart the malicious package was refused with %s = %q, want \"true\"", hdrCached, got)
		}
	}
	if after := r.scans(llm, malicious); after != beforeMalicious {
		r.failf(scQuarantined, "after a restart the refused package cost %d more LLM call(s)", after-beforeMalicious)
	}
	r.expectCached(scQuarantined, p, malicious, false, "the refused artifact must not be retained across a restart")
	r.follow(scQuarantined, p, malicious, http.StatusForbidden)
}

// control: the gate is off. The packages the other processes refuse are plain
// artifacts to this one — which is what makes each of those refusals the
// gate's, not a fixture's or another gate's.
func (r *runner) control(p *proxyProc) {
	for _, v := range []variant{malicious, benign, llmerror, llmhang} {
		res := r.pull(p, v, scMaliciousBlocked)
		if !r.expectServed(scMaliciousBlocked, p, v, res) {
			r.failf(scMaliciousBlocked, "with the gate off the %s package is not served: the refusals in this row cannot be attributed to the gate", v)
			continue
		}
		for name := range res.Header {
			if strings.HasPrefix(name, "X-Llmpkgscan-") {
				r.failf(scMaliciousBlocked, "with the gate off the response still carries %s", name)
			}
		}
		r.follow(scMaliciousBlocked, p, v, http.StatusOK)
		r.expectCached(scQuarantined, p, v, true, "the control process should have cached it for the next one")
	}
}

// defaults: the gate with its shipped defaults — action block, failMode open —
// over a cache that already holds the packages. (b) The cached malicious
// artifact is not served from the cache; (d) a failed scan is served, marked.
func (r *runner) defaults(p *proxyProc, llm *mockLLM) {
	// A package cached before the gate was on: found in the cache, examined
	// there, refused and evicted.
	res := r.pull(p, malicious, scQuarantined)
	if body := r.expectRefused(scQuarantined, p, malicious, res, policyMalicious); body != nil {
		if body.Action != "block" {
			r.failf(scMaliciousBlocked, "under the default action the refusal says action=%q, want block", body.Action)
		}
	} else {
		r.failf(scMaliciousBlocked, "under the default action (block) the malicious package was not refused")
	}
	r.expectShown(scMaliciousBlocked, llm, malicious, "openai", "malicious")
	r.expectCached(scQuarantined, p, malicious, false, "an artifact cached before the gate was enabled must be evicted once it is refused")
	r.follow(scQuarantined, p, malicious, http.StatusForbidden)

	res = r.pull(p, benign, scBenignServed)
	if r.expectServed(scBenignServed, p, benign, res) {
		if got := res.Header.Get(hdrDecision); got != "clean" {
			r.failf(scBenignServed, "under the default posture the benign package was served with %s = %q, want clean", hdrDecision, got)
		}
		if !r.stub.reg.pulls[benign].Uncached {
			if got := res.Header.Get(hdrCache); got != "HIT" {
				r.failf(scBenignServed, "the benign package was in the cache, but was served with %s = %q", hdrCache, got)
			}
		}
	}
	r.follow(scBenignServed, p, benign, http.StatusOK)
	r.expectShown(scContentScanned, llm, benign, "openai", "benign")

	r.expectDegraded(scFailOpenError, p, llm, llmerror, codeProviderError, "error")
	r.expectOneAttempt(scFailOpenError, llm)

	began := time.Now()
	r.expectDegraded(scFailOpenTimeout, p, llm, llmhang, codeTimeout, "hang")
	if elapsed := time.Since(began); elapsed < scanTimeout-500*time.Millisecond {
		r.failf(scFailOpenTimeout, "the pull was answered after %s, before llmPackageScan.timeout (%s) could have elapsed: this was not a timeout", elapsed.Round(time.Millisecond), scanTimeout)
	}
}

// expectDegraded asserts that, under failMode open, a package whose scan
// failed is served — and says so.
func (r *runner) expectDegraded(sc scenario, p *proxyProc, llm *mockLLM, v variant, code, outcome string) {
	r.t.Helper()
	res := r.pull(p, v, sc)
	if !r.expectServed(sc, p, v, res) {
		return
	}
	for header, want := range map[string]string{hdrDecision: "degraded", hdrVerdict: "unscanned", hdrCode: code} {
		if got := res.Header.Get(header); got != want {
			r.failf(sc, "the unscanned package was served with %s = %q, want %q (headers: %s)", header, got, want, gateHeaders(res.Header))
		}
	}
	if res.Header.Get(hdrReason) == "" {
		r.failf(sc, "the unscanned package was served without %s: a client cannot tell why it went unexamined", hdrReason)
	}
	if res.Header.Get(hdrModelVerdict) != "" {
		r.failf(sc, "an unscanned package carries a model verdict (%q)", res.Header.Get(hdrModelVerdict))
	}
	r.expectShown(sc, llm, v, "openai", outcome)
}
