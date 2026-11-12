//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
)

// TestMain removes the proxy binary the suite built, if it built one: a run
// leaves nothing behind but the report (and the workspaces it was asked to
// keep, or that a failure kept).
func TestMain(m *testing.M) {
	code := m.Run()
	if proxyBinDir != "" {
		_ = os.RemoveAll(proxyBinDir)
	}
	os.Exit(code)
}

// selectEcosystems applies envEcosystems to the registered ecosystems. It
// reports whether the run is a selection.
func selectEcosystems(t *testing.T, all []eco) ([]eco, bool) {
	t.Helper()
	raw := strings.FieldsFunc(os.Getenv(envEcosystems), func(r rune) bool { return r == ',' || r == ' ' })
	if len(raw) == 0 {
		return all, false
	}
	byID := map[string]eco{}
	for _, e := range all {
		byID[e.ID] = e
	}
	var out []eco
	for _, id := range raw {
		e, ok := byID[id]
		if !ok {
			ids := make([]string, 0, len(all))
			for _, e := range all {
				ids = append(ids, e.ID)
			}
			t.Fatalf("%s names %q, which is not an ecosystem of this suite (%s)", envEcosystems, id, strings.Join(ids, " "))
		}
		out = append(out, e)
	}
	return out, true
}

// TestLLMPackageScanEveryEcosystem is the suite: for every upstream type the
// proxy fronts it pulls packages through the real binary and asserts the
// scenarios of the matrix. It writes the matrix and fails when an upstream
// type is not fully covered.
func TestLLMPackageScanEveryEcosystem(t *testing.T) {
	bin := proxyBinary(t)
	selected, partial := selectEcosystems(t, ecosystems())

	workDir := os.Getenv(envWorkDir)
	if workDir == "" {
		dir, err := os.MkdirTemp("", "pkgscan-e2e-")
		if err != nil {
			t.Fatalf("creating the work directory: %v", err)
		}
		workDir = dir
	}
	workDir, err := filepath.Abs(workDir)
	if err != nil {
		t.Fatalf("resolving the work directory: %v", err)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("creating the work directory: %v", err)
	}

	m := newMatrix()
	m.Partial = partial

	// The group returns once every (parallel) ecosystem has finished.
	t.Run("ecosystems", func(t *testing.T) {
		for _, e := range selected {
			rw := newRow(e)
			m.add(rw)
			t.Run(e.ID, func(t *testing.T) {
				t.Parallel()
				r := newRunner(t, bin, workDir, e, rw)
				if e.Custom != nil {
					e.Custom(r)
					return
				}
				r.standard()
			})
		}
	})

	// What must be covered: every upstream type the configuration accepts — or,
	// for a selection, the types selected.
	want := config.UpstreamTypes()
	if partial {
		seen := map[string]bool{}
		want = nil
		for _, e := range selected {
			if !seen[e.Type] {
				seen[e.Type] = true
				want = append(want, e.Type)
			}
		}
		sort.Strings(want)
	}
	m.finalize(want)
	writeMatrix(t, m, workDir)
	t.Logf("\n%s", m.Markdown())

	if len(m.Uncovered) > 0 {
		t.Errorf("the LLM package scan is not proven for %d upstream type(s): %s.\n"+
			"Every upstream type the configuration accepts needs a row in this suite whose scenarios all pass "+
			"(add internal/e2e/pkgscan/eco_<type>.go for a new backend).",
			len(m.Uncovered), strings.Join(m.Uncovered, ", "))
	}
	if !t.Failed() && os.Getenv(envKeep) == "" && os.Getenv(envWorkDir) == "" {
		_ = os.RemoveAll(workDir)
	}
}

// writeMatrix writes the matrix (JSON and Markdown) to the report directory:
// envReportDir, else the task runner's attachment directory, else the work
// directory. A partial matrix is written under a name of its own, so a run
// restricted to a few ecosystems never replaces the full matrix.
func writeMatrix(t *testing.T, m *matrix, workDir string) {
	t.Helper()
	dir := workDir
	for _, env := range []string{envReportDir, envAttachments} {
		if d := os.Getenv(env); d != "" {
			dir = d
			break
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Errorf("creating the report directory %s: %v", dir, err)
		return
	}
	base := "llm-package-scan-matrix"
	if m.Partial {
		base += ".partial"
	}
	for name, data := range map[string][]byte{base + ".json": m.JSON(), base + ".md": []byte(m.Markdown())} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Errorf("writing %s: %v", path, err)
			continue
		}
		t.Logf("wrote %s", path)
	}
}

// TestEveryUpstreamTypeHasARow is the cheap half of the coverage gate: it needs
// no proxy, so it fails within a second of a backend being added to the
// configuration without a row here — also in a run restricted to a selection.
func TestEveryUpstreamTypeHasARow(t *testing.T) {
	rows := map[string][]string{}
	for _, e := range ecosystems() {
		rows[e.Type] = append(rows[e.Type], e.ID)
	}
	accepted := map[string]bool{}
	for _, typ := range config.UpstreamTypes() {
		accepted[typ] = true
		if len(rows[typ]) == 0 {
			t.Errorf("upstream type %q has no row in the LLM package-scan suite.\n"+
				"Add internal/e2e/pkgscan/eco_%s.go: a stub registry speaking the ecosystem's protocol and serving its "+
				"artifact format, registered with register(eco{…}). See eco_npm.go for the smallest example.", typ, typ)
		}
	}
	for typ, ids := range rows {
		if !accepted[typ] {
			t.Errorf("row(s) %v exercise upstream type %q, which the configuration does not accept", ids, typ)
		}
	}
}

// TestCoverageGateDetectsGaps guards the guard: the matrix must report an
// upstream type as uncovered when it has no row, when a scenario of its row
// failed, when a scenario was never reached, and when one of two rows of the
// same type failed — and must not report a fully passing type.
func TestCoverageGateDetectsGaps(t *testing.T) {
	passing := func(id, typ string) *row {
		r := newRow(eco{ID: id, Type: typ, Registry: func(stubEnv) (*registry, error) { return nil, nil }})
		for _, sc := range packageScenarios() {
			r.pass(sc)
		}
		return r
	}
	m := newMatrix()
	m.add(passing("npm", "npm"))

	failed := passing("pip", "pip")
	failed.fail(scMaliciousBlocked, "served a flagged package")
	m.add(failed)

	unreached := newRow(eco{ID: "cargo", Type: "cargo", Registry: func(stubEnv) (*registry, error) { return nil, nil }})
	unreached.pass(scBenignServed)
	m.add(unreached)

	m.add(passing("helm", "helm"))
	second := passing("helm-oci", "helm")
	second.fail(scQuarantined, "left in the cache")
	m.add(second)

	// A failure is sticky: a later pass of the same scenario must not hide it.
	failed.pass(scMaliciousBlocked)

	m.finalize([]string{"npm", "pip", "cargo", "helm", "docker"})
	if got, want := strings.Join(m.Uncovered, ","), "cargo,docker,helm,pip"; got != want {
		t.Fatalf("uncovered = %s, want %s", got, want)
	}

	// A row no scenario applies to proves nothing.
	empty := newRow(eco{ID: "git", Type: "git", Custom: func(*runner) {}})
	for _, sc := range scenarios {
		empty.na(sc)
	}
	if empty.covered() {
		t.Error("a row without one applicable scenario counts as covered")
	}

	// The artifact renders, and names what is missing.
	md := m.Markdown()
	for _, want := range []string{"CI FAIL", "served a flagged package", "`helm-oci`", "| `npm` |"} {
		if !strings.Contains(md, want) {
			t.Errorf("the Markdown matrix lacks %q", want)
		}
	}
	var decoded struct {
		Rows      []json.RawMessage `json:"rows"`
		Uncovered []string          `json:"uncovered"`
	}
	if err := json.Unmarshal(m.JSON(), &decoded); err != nil || len(decoded.Rows) != 5 || len(decoded.Uncovered) != 4 {
		t.Errorf("the JSON matrix does not round-trip: %v (%d rows, %d uncovered)", err, len(decoded.Rows), len(decoded.Uncovered))
	}
}

// TestMockLLMRules pins the mock's judgement, over both wire formats: the
// suite's conclusions are only as good as the rule the mock applies, so the
// rule is tested in the open.
func TestMockLLMRules(t *testing.T) {
	m := startMockLLM()
	defer m.Close()

	const packageSystem = "You are a supply-chain security analyst. Material appears between <<<UNTRUSTED_PACKAGE_DATA nonce>>> markers. Verdicts: malicious, suspicious, benign."
	material := func(lines ...string) string {
		var b strings.Builder
		b.WriteString("--- FILE: package/" + markerFile + " (120 bytes, " + string(rune('0'+len(lines))) + " lines)\n")
		for i, l := range lines {
			b.WriteString("     " + string(rune('1'+i)) + "| " + l + "\n")
		}
		return b.String()
	}
	ask := func(wire, system, user string) (int, string) {
		t.Helper()
		var url string
		var body any
		header := http.Header{"Content-Type": {"application/json"}}
		switch wire {
		case "anthropic":
			url = m.BaseURL("claude") + "/v1/messages"
			header.Set("X-Api-Key", mockAPIKey)
			body = map[string]any{"model": "mock-model", "max_tokens": 100,
				"system":   []map[string]string{{"type": "text", "text": system}},
				"messages": []map[string]any{{"role": "user", "content": []map[string]string{{"type": "text", "text": user}}}}}
		default:
			url = m.BaseURL("openai") + "/chat/completions"
			header.Set("Authorization", "Bearer "+mockAPIKey)
			body = map[string]any{"model": "mock-model",
				"messages": []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}}}
		}
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
		req.Header = header
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s request: %v", wire, err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		var anth struct {
			Content []struct{ Text string } `json:"content"`
		}
		var oai struct {
			Choices []struct {
				Message struct{ Content string } `json:"message"`
			} `json:"choices"`
		}
		switch {
		case wire == "anthropic" && json.Unmarshal(data, &anth) == nil && len(anth.Content) > 0:
			return resp.StatusCode, anth.Content[0].Text
		case wire == "openai" && json.Unmarshal(data, &oai) == nil && len(oai.Choices) > 0:
			return resp.StatusCode, oai.Choices[0].Message.Content
		}
		return resp.StatusCode, string(data)
	}

	for _, wire := range []string{"anthropic", "openai"} {
		// The system prompt's own vocabulary decides nothing.
		if status, answer := ask(wire, packageSystem, material("hello", "content-token: T1")); status != 200 || !strings.Contains(answer, `"verdict": "benign"`) {
			t.Errorf("%s: plain material answered %d %s, want benign", wire, status, answer)
		}
		status, answer := ask(wire, packageSystem, material("hello", "content-token: T2", maliciousMarker))
		var verdict struct {
			Verdict  string `json:"verdict"`
			Evidence []struct {
				Path string `json:"path"`
				Line int    `json:"line"`
			} `json:"evidence"`
		}
		if status != 200 || json.Unmarshal([]byte(answer), &verdict) != nil || verdict.Verdict != "malicious" {
			t.Fatalf("%s: marked material answered %d %s, want malicious", wire, status, answer)
		}
		if len(verdict.Evidence) != 1 || verdict.Evidence[0].Path != "package/"+markerFile || verdict.Evidence[0].Line != 3 {
			t.Errorf("%s: the malicious verdict cites %+v, want package/%s:3", wire, verdict.Evidence, markerFile)
		}
		// The injection text alone changes nothing; the obey token does.
		if _, answer := ask(wire, packageSystem, material("x", maliciousMarker, injectionText)); !strings.Contains(answer, `"verdict":"malicious"`) {
			t.Errorf("%s: the injection text flipped the mock's verdict: %s", wire, answer)
		}
		if _, answer := ask(wire, packageSystem, material("x", maliciousMarker, injectionText, obeyToken)); !strings.Contains(answer, `"verdict": "benign"`) {
			t.Errorf("%s: the obeying model did not answer benign: %s", wire, answer)
		}
		if status, _ := ask(wire, packageSystem, material("x", errorToken)); status != http.StatusInternalServerError {
			t.Errorf("%s: the error token answered %d, want 500", wire, status)
		}
		// A commit-scan prompt gets the commit scanner's answer shape.
		if _, answer := ask(wire, "You review a git commit.", "diff --git a/x b/x\n+"+maliciousMarker); !strings.Contains(answer, `"malicious": true`) {
			t.Errorf("%s: a marked commit prompt answered %s", wire, answer)
		}
		if _, answer := ask(wire, "You review a git commit.", "diff --git a/x b/x\n+ok"); !strings.Contains(answer, `"malicious": false`) {
			t.Errorf("%s: a plain commit prompt answered %s", wire, answer)
		}
	}

	calls := m.Calls()
	if len(calls) != 14 {
		t.Fatalf("recorded %d calls, want 14", len(calls))
	}
	for _, c := range calls {
		if !c.Authorized {
			t.Errorf("a %s call was recorded as unauthorized", c.Wire)
		}
	}
	if got := len(m.PackageScans("T2")); got != 2 {
		t.Errorf("PackageScans(T2) = %d, want one per wire format", got)
	}
	if got := len(m.CommitScans()); got != 4 {
		t.Errorf("CommitScans = %d, want 4", got)
	}
}

// TestFixtureSpecs pins what makes a variant what it is: the marker file's
// text, and the line the model is expected to cite.
func TestFixtureSpecs(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range variants {
		s := newSpec("npm", v)
		if seen[s.Token] || s.Token == newSpec("pip", v).Token {
			t.Errorf("the content token of %s is not unique", v)
		}
		seen[s.Token] = true
		text := s.Text("# ")
		lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
		if lines[1] != "# content-token: "+s.Token {
			t.Errorf("%s: line 2 is %q, want the content token", v, lines[1])
		}
		hasMarker := strings.Contains(text, maliciousMarker)
		if want := v == malicious || v == injection || v == obeyed; hasMarker != want {
			t.Errorf("%s: carries the malicious marker = %v, want %v", v, hasMarker, want)
		}
		if hasMarker && lines[s.MarkerLine(0)-1] != "# "+maliciousMarker {
			t.Errorf("%s: MarkerLine does not point at the marker: %q", v, lines[s.MarkerLine(0)-1])
		}
		if want := v == injection || v == obeyed; strings.Contains(text, injectionText) != want {
			t.Errorf("%s: carries the injection text = %v, want %v", v, !want, want)
		}
		for token, only := range map[string]variant{obeyToken: obeyed, errorToken: llmerror, hangToken: llmhang} {
			if strings.Contains(text, token) != (v == only) {
				t.Errorf("%s: wrong use of %s", v, token)
			}
		}
	}
}
