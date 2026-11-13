package llmpkgscan

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// A long run of hidden code points is shown as one marker, not as the raw
// characters: text-hiding loaders (GlassWorm's extension JavaScript carried
// thousands of variation selectors that a short decoder turned into code) are
// built from exactly such runs.
func TestVisibleSummarisesLongHiddenRuns(t *testing.T) {
	vs := func(n int) string { return strings.Repeat("\U000E0101", n) } // variation selector 18
	for name, tc := range map[string]struct{ in, want string }{
		"a long run of supplementary variation selectors": {
			"const s = \"" + vs(1163) + "\"", `const s = "<hidden run of 1163 code points, U+E0101..U+E0101>"`},
		"a mixed run reports its range": {
			"x︀\U000E0110️\U000E01EF︁︂︃\U000E0100y", "x<hidden run of 8 code points, U+FE00..U+E01EF>y"},
		"exactly the minimum":    {"a" + vs(8) + "b", "a<hidden run of 8 code points, U+E0101..U+E0101>b"},
		"private-use characters": {"a" + strings.Repeat("", 9) + "b", "a<hidden run of 9 code points, U+E000..U+E000>b"},
		"tag characters":         {"a" + strings.Repeat("\U000E0041", 12) + "b", "a<hidden run of 12 code points, U+E0041..U+E0041>b"},
		"zero-width characters":  {"a" + strings.Repeat("​", 10) + "b", "a<hidden run of 10 code points, U+200B..U+200B>b"},
		"two runs":               {vs(8) + "mid" + vs(9), "<hidden run of 8 code points, U+E0101..U+E0101>mid<hidden run of 9 code points, U+E0101..U+E0101>"},
		// Short runs and ordinary text keep their old rendering.
		"one variation selector after an emoji is text":  {"ok ❤️", "ok ❤️"},
		"a short run of invisible characters is spelled": {"a​‌b", "a<U+200B><U+200C>b"},
		"seven is not a run":                             {"a" + vs(7) + "b", "a" + vs(7) + "b"},
		"plain text":                                     {"plain text", "plain text"},
	} {
		if got := visible([]byte(tc.in), maxLineChars); got != tc.want {
			t.Errorf("%s: visible(%q) = %q, want %q", name, tc.in, got, tc.want)
		}
	}
}

// The marker counts as one character of the line's budget, so a loader whose
// hidden literal is longer than the line limit is still shown to its end.
func TestVisibleCountsAHiddenRunAsOneCharacter(t *testing.T) {
	line := "const s = \"" + strings.Repeat("\U000E0101", 3000) + "\"; eval(decode(s));"
	got := visible([]byte(line), maxLineChars)
	if strings.Contains(got, "line cut") {
		t.Errorf("a %d-code-point hidden run made the line look over the limit: %q", 3000, got)
	}
	if !strings.HasSuffix(got, `"; eval(decode(s));`) || !strings.Contains(got, "<hidden run of 3000 code points") {
		t.Errorf("the loader around the hidden run is not shown: %q", got)
	}
	// A line that really is long is still cut, runs or not.
	long := strings.Repeat("a", 2000) + strings.Repeat("\U000E0101", 50)
	if got := visible([]byte(long), 100); !strings.Contains(got, "line cut") || strings.Count(got, "a") != 100 {
		t.Errorf("a long line was not cut at 100 characters: %.160q", got)
	}
}

// Whatever the bytes, the rendering is valid UTF-8 and holds none of the raw
// hidden characters of a run (so none reaches the provider as a run).
func TestVisibleNeverLeaksARawHiddenRun(t *testing.T) {
	inputs := []string{
		strings.Repeat("︀", 100), strings.Repeat("\U000E0100", 100) + "\xff\xfe",
		"\xf3\xa0\x84", // a truncated variation selector
		strings.Repeat("\U000E0100\xff", 20), strings.Repeat("​️", 50),
	}
	for _, in := range inputs {
		got := visible([]byte(in), maxLineChars)
		if !utf8.ValidString(got) {
			t.Errorf("visible(%q) is not valid UTF-8: %q", in, got)
		}
		run := 0
		for _, r := range got {
			if isHiddenRune(r) && !isInvisibleRune(r) {
				run++
				if run >= hiddenRunMin {
					t.Errorf("visible(%q) still holds a raw run: %q", in, got)
					break
				}
			} else {
				run = 0
			}
		}
	}
}

// Through the whole pipeline: the package's file is rendered into the prompt
// with the marker, the model is told what the marker means, and the verdict is
// stored under the new prompt version.
func TestHiddenRunReachesTheModelAsAMarker(t *testing.T) {
	loader := "const payload = \"" + strings.Repeat("\U000E0101", 600) + "\";\neval(Buffer.from(decode(payload)).toString());\n"
	var seen string
	p := &pkgscantest.Provider{Judge: func(material string) string {
		seen = material
		return `{"verdict": "malicious", "confidence": 0.9, "reasons": ["hidden data is decoded and evaluated"], "evidence": []}`
	}}
	svc := newService(t, p, func(c *Config) { c.Mode = ModeBundle })
	rep := assess(t, svc, request(pkgscantest.TarGz(map[string]string{"pkg/extension.js": loader}), "ext", "1.0.0", nil))
	if rep.Disposition != DispositionMalicious {
		t.Fatalf("disposition = %q, want malicious", rep.Disposition)
	}
	if !strings.Contains(seen, "<hidden run of 600 code points, U+E0101..U+E0101>") {
		t.Errorf("the model was not shown the marker:\n%s", seen)
	}
	if strings.ContainsRune(seen, '\U000E0101') {
		t.Errorf("the raw hidden characters reached the model")
	}
	if !strings.Contains(systemPrompt(false), "hidden run of N code points") {
		t.Errorf("the system prompt does not explain the marker")
	}
	if PromptVersion < 3 {
		t.Errorf("PromptVersion = %d: rendering changed, verdicts of version 2 must be recomputed", PromptVersion)
	}
	if rep.Verdict == nil || rep.Verdict.PromptVersion != PromptVersion {
		t.Errorf("verdict = %+v, want it stored under prompt version %d", rep.Verdict, PromptVersion)
	}
}
