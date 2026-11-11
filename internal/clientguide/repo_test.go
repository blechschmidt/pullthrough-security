package clientguide

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/ecotest"
	"github.com/blechschmidt/pullthrough-security/internal/onboard"
)

// The tests in this file read the repository: the guide (docs/clients.md,
// docs/clients/*.md), the pages around it, the client-lab scripts and the
// ecosystem test scripts.

const (
	repoRoot   = "../.."
	hubPath    = "docs/clients.md"
	pagesDir   = "docs/clients"
	labDoc     = "docs/client-lab.md"
	backendDoc = "docs/backends.md"
	labDir     = "scripts/client-lab"
)

func readRepo(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return data
}

func parseRepo(t *testing.T, rel string) *Page {
	t.Helper()
	page, err := Parse(readRepo(t, rel))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return page
}

// pageSlugs returns the slugs of the ecosystem pages, sorted.
func pageSlugs(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(repoRoot, filepath.FromSlash(pagesDir)))
	if err != nil {
		t.Fatalf("reading %s: %v", pagesDir, err)
	}
	var slugs []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			t.Errorf("%s/%s: only ecosystem pages (*.md) belong here", pagesDir, e.Name())
			continue
		}
		slugs = append(slugs, strings.TrimSuffix(e.Name(), ".md"))
	}
	sort.Strings(slugs)
	return slugs
}

// guideFiles returns every file of the guide: the hub, the ecosystem pages, and
// the two pages that belong to it.
func guideFiles(t *testing.T) []string {
	t.Helper()
	files := []string{hubPath, labDoc, backendDoc}
	for _, slug := range pageSlugs(t) {
		files = append(files, pagesDir+"/"+slug+".md")
	}
	return files
}

// labScripts returns the client-lab scripts by name (without ".sh").
func labScripts(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join(repoRoot, filepath.FromSlash(labDir), "clients")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s/clients: %v", labDir, err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sh") {
			t.Errorf("%s/clients/%s: only client scripts (*.sh) belong here", labDir, e.Name())
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[strings.TrimSuffix(e.Name(), ".sh")] = string(data)
	}
	if len(out) == 0 {
		t.Fatalf("%s/clients holds no script", labDir)
	}
	return out
}

// unclosed returns a bracket of which a block of a configuration language has
// more openings than closings (or the other way round), "" when it is balanced.
// A block may show part of a file, but a part that stops in the middle of a
// structure — an init script without its last braces — is a file the client
// rejects. Shell is exempt: a `case` pattern closes a parenthesis it never
// opened.
func unclosed(b Block) string {
	if b.Lang == "" || b.Lang == "sh" {
		return ""
	}
	text := strings.Join(b.Lines, "\n")
	for _, pair := range []string{"{}", "[]", "()"} {
		if strings.Count(text, pair[:1]) != strings.Count(text, pair[1:]) {
			return pair[:1]
		}
	}
	return ""
}

// labClientName returns the "# lab: client=" name of a client-lab script.
func labClientName(script string) string {
	for _, m := range labMetaRE.FindAllStringSubmatch(script, -1) {
		if m[1] == "client" {
			return strings.TrimSpace(m[2])
		}
	}
	return ""
}

// scriptOf returns the text of the script a source names.
func scriptOf(t *testing.T, lab map[string]string, src Source) (string, bool) {
	t.Helper()
	switch src.Kind {
	case SourceLab:
		s, ok := lab[src.Name]
		return s, ok
	case SourceCI:
		eco, ok := ecotest.Lookup(src.Name)
		if !ok {
			return "", false
		}
		data, err := eco.Script()
		if err != nil {
			return "", false
		}
		return string(data), true
	}
	return "", false
}

// labUpstreams returns the upstream names of the lab proxy and their types.
func labUpstreams(t *testing.T) map[string]string {
	t.Helper()
	var doc struct {
		Upstreams map[string]struct {
			Type string `yaml:"type"`
		} `yaml:"upstreams"`
	}
	if err := yaml.Unmarshal(readRepo(t, labDir+"/proxy.yaml"), &doc); err != nil {
		t.Fatalf("%s/proxy.yaml: %v", labDir, err)
	}
	out := map[string]string{}
	for name, u := range doc.Upstreams {
		out[name] = u.Type
	}
	return out
}

// A backend that is added to the proxy needs a page in the guide; a page needs a
// backend.
func TestEveryUpstreamTypeHasAPage(t *testing.T) {
	have := map[string]bool{}
	for _, slug := range pageSlugs(t) {
		have[slug] = true
	}
	want := map[string]bool{}
	for _, typ := range config.UpstreamTypes() {
		slug := PageFor(typ)
		want[slug] = true
		if !have[slug] {
			t.Errorf("upstream type %q has no page %s/%s.md", typ, pagesDir, slug)
		}
	}
	for slug := range have {
		if !want[slug] {
			t.Errorf("%s/%s.md is not the page of any upstream type", pagesDir, slug)
		}
	}
}

// The hub links to every page, and to nothing in the pages directory that does
// not exist.
func TestHubLinksToEveryPage(t *testing.T) {
	hub := parseRepo(t, hubPath)
	linked := map[string]bool{}
	for _, l := range hub.Links {
		target, _, _ := strings.Cut(l.Target, "#")
		if slug, ok := strings.CutPrefix(target, "clients/"); ok {
			linked[strings.TrimSuffix(slug, ".md")] = true
		}
	}
	for _, slug := range pageSlugs(t) {
		if !linked[slug] {
			t.Errorf("%s does not link to clients/%s.md", hubPath, slug)
		}
	}
}

// Every ecosystem page has the same sections in the same order.
func TestPagesFollowTheTemplate(t *testing.T) {
	for _, slug := range pageSlugs(t) {
		rel := pagesDir + "/" + slug + ".md"
		page := parseRepo(t, rel)
		if page.Title() == "" {
			t.Errorf("%s: no title (a level-1 heading)", rel)
		}
		if got := page.Sections(); strings.Join(got, "|") != strings.Join(Template, "|") {
			t.Errorf("%s: sections are\n    %s\nwant\n    %s", rel, strings.Join(got, " | "), strings.Join(Template, " | "))
		}
		// The summary box above the first section names the upstream type, so a
		// reader (and an operator) can tell which backend the page is about.
		if !strings.Contains(string(readRepo(t, rel)), "| Upstream type |") {
			t.Errorf("%s: no summary table with an \"Upstream type\" row", rel)
		}
	}
}

// Every fenced block in the guide says what stands behind it, and a block that
// says "verified" is, line for line, what the scripts it names execute.
func TestSnippetsAreVerified(t *testing.T) {
	lab := labScripts(t)
	usedLab := map[string]bool{}
	checker := Checker{Scripts: map[Source]string{}, MountTypes: labUpstreams(t), CITypes: map[string]string{}}
	for _, rel := range guideFiles(t) {
		page := parseRepo(t, rel)
		verified := 0
		for _, b := range page.Blocks {
			at := fmt.Sprintf("%s:%d", rel, b.Line)
			if b.Marker == nil {
				t.Errorf("%s: the block has no marker. Put one on the line above it: "+
					"<!-- verified: lab:<script> --> (or ci:<ecosystem>), <!-- untested: why -->, "+
					"<!-- proxy-config -->, <!-- output: lab:<script> --> or <!-- illustration -->", at)
				continue
			}
			for _, src := range b.Marker.Sources {
				text, ok := scriptOf(t, lab, src)
				if !ok {
					t.Errorf("%s: the marker names %s, which does not exist", at, src)
					continue
				}
				checker.Scripts[src] = text
				switch src.Kind {
				case SourceLab:
					usedLab[src.Name] = true
				case SourceCI:
					if eco, ok := ecotest.Lookup(src.Name); ok {
						checker.CITypes[src.Name] = eco.Upstream.Type
					}
				}
			}
			switch b.Marker.Kind {
			case KindOutput:
				// What a client printed is shown as text. A block in a shell's
				// colours reads as something to type.
				if b.Lang != "" {
					t.Errorf("%s: an output block has no language (it has %q)", at, b.Lang)
				}
			case KindVerified:
				verified++
				// A script named "… (with a token: refused)" asserts that a
				// client cannot authenticate: it holds the configuration that
				// does NOT work. Its error message may be quoted (an output
				// block); its lines are not a configuration to copy.
				for _, src := range b.Marker.Sources {
					if src.Kind == SourceLab && strings.Contains(labClientName(lab[src.Name]), "with a token: refused") {
						t.Errorf("%s: %s asserts that its configuration is refused; a verified block cannot be taken from it", at, src)
					}
				}
				if open := unclosed(b); open != "" {
					t.Errorf("%s: the block does not close every %q it opens: a file cut short?", at, open)
				}
				res := checker.Check(b)
				for _, line := range res.Missing {
					t.Errorf("%s: marked verified by %v, but none of them executes the line\n    %s", at, b.Marker.Sources, line)
				}
				for _, line := range res.Misordered {
					t.Errorf("%s: the script executes this line before the one above it; the block has the script's lines in another order\n    %s", at, line)
				}
				for _, line := range res.Misindented {
					t.Errorf("%s: the script indents this line of the file differently, relative to the line above it\n    %s", at, line)
				}
				if res.Scattered {
					t.Errorf("%s: the block's lines of a file are written by several of %v and by none of them all: no client was given this file", at, b.Marker.Sources)
				}
				for _, src := range res.Unused {
					if _, ok := checker.Scripts[src]; ok {
						t.Errorf("%s: the marker names %s, but that script executes no line of the block (braces and the like do not count)", at, src)
					}
				}
			case KindProxyConfig:
				checkProxyConfig(t, at, strings.Join(b.Lines, "\n"))
			}
		}
		if strings.HasPrefix(rel, pagesDir+"/") && verified == 0 {
			// A page with nothing verified is a page of claims. The two backends
			// without a public registry say so instead.
			if !strings.Contains(string(readRepo(t, rel)), "**Not tested with a real client.**") {
				t.Errorf("%s: no verified block, and the page does not say \"**Not tested with a real client.**\"", rel)
			}
		}
	}
	// A lab script exists to stand behind the guide.
	for name := range lab {
		if !usedLab[name] {
			t.Errorf("%s/clients/%s.sh is referenced by no block of the guide", labDir, name)
		}
	}
}

// keyedMaps are the configuration maps whose keys are names chosen by the
// operator rather than settings: the level below such a path is skipped when a
// fragment is held to the schema ("upstreams.npm.type" is the setting
// "upstreams.type"). freeFormMaps hold data only.
var (
	keyedMaps    = map[string]bool{"upstreams": true, "auth.teams": true}
	freeFormMaps = map[string]bool{"upstreams.settings": true, "server.intercept.hosts": true}
)

// checkProxyConfig holds a fragment of the proxy's configuration to the schema:
// it is YAML, every key path in it names a real setting, and it decodes as
// configuration — values have the types of their settings, an upstream is a name
// with settings below it, and its type is one the proxy has.
func checkProxyConfig(t *testing.T, at, text string) {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		t.Errorf("%s: the proxy-config block is not YAML: %v", at, err)
		return
	}
	if len(doc) == 0 {
		t.Errorf("%s: the proxy-config block is empty", at)
	}
	var cfg config.Config
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		t.Errorf("%s: the proxy-config block does not decode as the proxy's configuration: %v", at, err)
	}
	types := map[string]bool{}
	for _, typ := range config.UpstreamTypes() {
		types[typ] = true
	}
	for name, up := range cfg.Upstreams {
		if !types[up.Type] {
			t.Errorf("%s: upstream %q has type %q, which is not an upstream type", at, name, up.Type)
		}
	}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch node := v.(type) {
		case []any:
			for _, item := range node {
				walk(path, item)
			}
		case map[string]any:
			if freeFormMaps[path] {
				return
			}
			for key, val := range node {
				if keyedMaps[path] {
					walk(path, val) // key is a name; its value has the settings
					continue
				}
				child := key
				if path != "" {
					child = path + "." + key
				}
				if !config.YAMLPathExists(child) {
					t.Errorf("%s: %q is not a configuration setting", at, child)
					continue
				}
				walk(child, val)
			}
		}
	}
	walk("", doc)
}

// untestedUpstreams are the example names of the two upstream types the lab
// cannot front — there is no public registry to put behind them. Their pages say
// "Not tested with a real client".
var untestedUpstreams = map[string]bool{
	"swiftpm":  true, // swift: no public Swift package registry exists
	"mysource": true, // generic: routes are deployment-specific
}

var guideMountRE = regexp.MustCompile(`proxy\.example\.com/v1/([A-Za-z0-9._-]+)`)

// The upstream names the guide uses in its addresses are the lab proxy's: an
// address in the guide is one a lab client can reach.
func TestGuideUsesTheLabsUpstreamNames(t *testing.T) {
	names := labUpstreams(t)
	for _, rel := range guideFiles(t) {
		for i, line := range strings.Split(string(readRepo(t, rel)), "\n") {
			for _, m := range guideMountRE.FindAllStringSubmatch(line, -1) {
				name := m[1]
				if strings.HasPrefix(name, "<") || untestedUpstreams[name] {
					continue
				}
				if _, ok := names[name]; !ok {
					t.Errorf("%s:%d: /v1/%s is not an upstream of the lab proxy (%s/proxy.yaml)", rel, i+1, name, labDir)
				}
			}
		}
	}
}

// Relative links of the guide resolve: the file exists and, where the link
// names an anchor in another page of the documentation, so does the anchor.
func TestGuideLinksResolve(t *testing.T) {
	anchorsOf := map[string]map[string]bool{}
	anchors := func(rel string) (map[string]bool, bool) {
		if a, ok := anchorsOf[rel]; ok {
			return a, a != nil
		}
		data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			anchorsOf[rel] = nil
			return nil, false
		}
		page, _ := Parse(data)
		anchorsOf[rel] = page.Anchors()
		return anchorsOf[rel], true
	}
	for _, rel := range guideFiles(t) {
		page := parseRepo(t, rel)
		for _, l := range page.Links {
			if strings.Contains(l.Target, "://") || strings.HasPrefix(l.Target, "mailto:") {
				continue
			}
			file, anchor, _ := strings.Cut(l.Target, "#")
			target := rel
			if file != "" {
				target = filepath.ToSlash(filepath.Join(filepath.Dir(rel), file))
			}
			info, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(target)))
			if err != nil {
				t.Errorf("%s:%d: link %q: %s does not exist", rel, l.Line, l.Target, target)
				continue
			}
			if anchor == "" || info.IsDir() || !strings.HasSuffix(target, ".md") {
				continue
			}
			if a, ok := anchors(target); ok && !a[anchor] {
				t.Errorf("%s:%d: link %q: %s has no heading with the anchor #%s", rel, l.Line, l.Target, target, anchor)
			}
		}
	}
}

var (
	labMetaRE  = regexp.MustCompile(`(?m)^# lab: ([a-z-]+)=(.*)$`)
	labImageRE = regexp.MustCompile(`^[a-z0-9./_-]+:[A-Za-z0-9._-]+$`)
	// negatedRE matches a command line that starts with "!", also after "&&",
	// "||", ";" or "then".
	negatedRE = regexp.MustCompile(`(^|&&|\|\||;|\bthen|\bdo)\s*!\s`)
)

// Client-lab scripts follow the contract lab.sh relies on, and use only
// addresses the lab proxy serves.
func TestLabScriptsFollowTheContract(t *testing.T) {
	names := labUpstreams(t)
	for name, text := range labScripts(t) {
		at := labDir + "/clients/" + name + ".sh"
		meta := map[string]string{}
		for _, m := range labMetaRE.FindAllStringSubmatch(text, -1) {
			meta[m[1]] = strings.TrimSpace(m[2])
		}
		if !strings.HasPrefix(text, "#!/bin/sh\n") {
			t.Errorf("%s: must start with #!/bin/sh", at)
		}
		if meta["client"] == "" {
			t.Errorf("%s: no \"# lab: client=\" line (the name in the result table)", at)
		}
		switch image := meta["image"]; {
		case image == "":
			t.Errorf("%s: no \"# lab: image=\" line", at)
		case !labImageRE.MatchString(image) || strings.HasSuffix(image, ":latest"):
			// A floating tag makes a result irreproducible: the client that
			// failed yesterday is not the client that runs today.
			t.Errorf("%s: image %q must be pinned to an explicit, non-latest tag", at, image)
		}
		for _, mode := range strings.Fields(meta["modes"]) {
			if mode != "open" && mode != "auth" && mode != "anon" {
				t.Errorf("%s: unknown mode %q", at, mode)
			}
		}
		if d := meta["daemon"]; d != "" && d != "docker" {
			t.Errorf("%s: unknown daemon %q", at, d)
		}
		for key := range meta {
			switch key {
			case "client", "image", "modes", "daemon", "entrypoint", "lookups", "user":
			default:
				t.Errorf("%s: unknown \"# lab: %s=\" line", at, key)
			}
		}
		if !strings.Contains(text, "\nset -eu\n") {
			t.Errorf("%s: must run under `set -eu`, so that a failing step fails the script", at)
		}
		// … which `set -e` does not do for a negated command: "! grep -q x f"
		// never ends a script, whatever grep finds. An assertion that something
		// is absent is written "if grep -q x f; then echo …; exit 1; fi".
		for i, line := range strings.Split(text, "\n") {
			if negatedRE.MatchString(line) {
				t.Errorf("%s:%d: a negated command cannot fail the script (`set -e` ignores it): use `if …; then …; exit 1; fi`\n    %s", at, i+1, line)
			}
		}
		if strings.Count(text, "LAB_CLIENT_VERSION=") < 1 {
			t.Errorf("%s: must print LAB_CLIENT_VERSION=<version>", at)
		}
		for _, m := range guideMountRE.FindAllStringSubmatch(text, -1) {
			if _, ok := names[m[1]]; !ok {
				t.Errorf("%s: /v1/%s is not an upstream of the lab proxy", at, m[1])
			}
		}
		// The token never appears literally: a script takes it from PROXY_TOKEN.
		if strings.Contains(text, "ptk_") {
			t.Errorf("%s: contains a literal token", at)
		}
	}
}

// The lab proxy fronts every upstream type, under the names the example
// configuration uses where it has an entry for the type.
func TestLabProxyCoversEveryUpstreamType(t *testing.T) {
	have := map[string]bool{}
	for _, typ := range labUpstreams(t) {
		have[PageFor(typ)] = true
	}
	for _, typ := range config.UpstreamTypes() {
		slug := PageFor(typ)
		if slug == "swift" || slug == "generic" {
			continue // no public registry to front
		}
		if !have[slug] {
			t.Errorf("the lab proxy (%s/proxy.yaml) has no upstream of type %q", labDir, slug)
		}
	}
}

var (
	resultRowRE   = regexp.MustCompile("\\[`([a-z0-9-]+)\\.sh`\\]")
	fingerprintRE = regexp.MustCompile(`(?s)<!-- fingerprints:[^\n]*\n(.*?)-->`)
)

// labResults reads the result table of docs/client-lab.md: for every script the
// cells of its row, and the fingerprint recorded for it next to the table.
func labResults(t *testing.T) (rows map[string][]string, fingerprints map[string]string) {
	t.Helper()
	doc := string(readRepo(t, labDoc))
	_, rest, ok := strings.Cut(doc, "<!-- results:begin -->")
	section, _, ok2 := strings.Cut(rest, "<!-- results:end -->")
	if !ok || !ok2 {
		t.Fatalf("%s: no results:begin … results:end section", labDoc)
	}
	rows = map[string][]string{}
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		m := resultRowRE.FindStringSubmatch(line)
		if m == nil {
			continue // the header and its rule
		}
		var cells []string
		for _, cell := range strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|") {
			cells = append(cells, strings.TrimSpace(cell))
		}
		if _, dup := rows[m[1]]; dup {
			t.Errorf("%s: two result rows for %s.sh", labDoc, m[1])
		}
		rows[m[1]] = cells
	}
	fingerprints = map[string]string{}
	if m := fingerprintRE.FindStringSubmatch(section); m != nil {
		for _, line := range strings.Split(m[1], "\n") {
			if name, value, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
				fingerprints[name] = value
			}
		}
	}
	return rows, fingerprints
}

// The result table in docs/client-lab.md is the record of a complete, passing
// run of the scripts as they are: every script has a row, the row says "passed"
// for every mode the script is for and for no other, and the script has not
// changed since (its fingerprint is the one lab.sh recorded when it wrote the
// table). A script that was edited has to be run again.
func TestLabResultsAreCurrent(t *testing.T) {
	rows, fingerprints := labResults(t)
	scripts := labScripts(t)
	// stale collects the scripts whose result is missing or of another version
	// of the script; they are reported together.
	var stale []string
	for name, text := range scripts {
		cells, ok := rows[name]
		if !ok {
			stale = append(stale, name)
			continue
		}
		// | Client | Version | open | auth | anon | Other hosts looked up | Script |
		if len(cells) != 7 {
			t.Errorf("%s: the row of %s.sh has %d cells, want 7", labDoc, name, len(cells))
			continue
		}
		if cells[1] == "" || cells[1] == "?" {
			t.Errorf("%s: the row of %s.sh has no client version", labDoc, name)
		}
		modes := "open auth"
		if m := regexp.MustCompile(`(?m)^# lab: modes=(.*)$`).FindStringSubmatch(text); m != nil {
			modes = m[1]
		}
		for i, mode := range []string{"open", "auth", "anon"} {
			want := "—"
			if strings.Contains(" "+modes+" ", " "+mode+" ") {
				want = "✔"
			}
			if got := cells[2+i]; got != want {
				t.Errorf("%s: the row of %s.sh says %q for mode %s, want %q", labDoc, name, got, mode, want)
			}
		}
		if fingerprints[name] != Fingerprint(text) {
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("%s holds no result of the current version of %d script(s): %s\n"+
			"a script that is new or was edited has to be run again:\n"+
			"    scripts/client-lab/lab.sh up && scripts/client-lab/lab.sh run <script> && scripts/client-lab/lab.sh document",
			labDoc, len(stale), strings.Join(stale, " "))
	}
	for name := range rows {
		if _, ok := scripts[name]; !ok {
			t.Errorf("%s has a result row for %s.sh, which does not exist", labDoc, name)
		}
	}
	for name := range fingerprints {
		if _, ok := scripts[name]; !ok {
			t.Errorf("%s records a fingerprint for %s.sh, which does not exist", labDoc, name)
		}
	}
}

// `ptctl config` prints client configurations too (internal/onboard). For the
// upstreams of the lab proxy listed here, every line it prints — without a
// token and with one — is a line a lab script executes: the generator cannot
// print a configuration no client has run.
var heldGenerators = []string{
	"ansible", "bazel", "conda-forge", "cpan", "crates", "hackage", "hex", "homebrew",
	"huggingface", "julia", "maven", "nix", "nuget", "opentofu", "terraform",
}

// looseGenerators are the upstreams whose snippet is not held to the lab yet,
// with what is in the way. An entry leaves this list by making the generator
// print the guide's lines.
var looseGenerators = map[string]string{
	"conancenter":    "the remote is added without the options the lab passes",
	"cran":           "prints an R session, where the lab writes an Rprofile",
	"debian":         "a one-line sources.list entry with placeholders, where the guide has a .sources file",
	"dockerhub":      "prints docker login, which fails against the proxy's challenge",
	"ghcr":           "prints docker login, which fails against the proxy's challenge",
	"github":         "placeholders in the clone URL; the header is spelled without the quotes the lab uses",
	"goproxy":        "a one-line ~/.netrc entry, where the lab's has three lines",
	"gradle-plugins": "the Maven mirror is tested with the maven upstream",
	"helm-oci":       "adds the repository under the name pullthrough, and for an OCI upstream",
	"podinfo":        "adds the repository under the name pullthrough",
	"jsr":            "a trailing comment on the deno command",
	"npm":            "the token placeholder is spelled ${PULLTHROUGH_TOKEN}",
	"npm-jsr":        "the lab uses this upstream for the @jsr scope only",
	"openvsx":        "placeholders for the extension",
	"packagist":      "a repositories array in composer.json, where the lab uses composer config",
	"pub":            "a trailing comment on the dart command",
	"puppet":         "puppet module install with a module the lab does not install",
	"pypi":           "the token as a user name alone (it works: tried by hand), where the lab uses pullthrough:<token>",
	"rocky":          "a repository section of its own naming",
	"rubygems":       "bundle config without set --global; the token as a user name alone (it works: tried by hand)",
}

// unverifiedGeneratorLines returns the lines `ptctl config` prints for an
// upstream of the lab proxy that no lab script executes.
func unverifiedGeneratorLines(name, typ string, executedLines map[string]bool) []string {
	// What a generator needs to know about the upstream behind the mount.
	upstreamURL := map[string]string{"nix": "https://cache.nixos.org", "github": "https://github.com"}
	var out []string
	for _, token := range []string{"", "LABTOKEN"} {
		ctx := onboard.Context{ProxyBase: "https://proxy.example.com", Host: "proxy.example.com", Token: token}
		for _, snip := range onboard.For(ctx, onboard.Backend{Name: name, Type: typ, URL: upstreamURL[name]}) {
			body := strings.ReplaceAll(snip.Body, "LABTOKEN", labToken)
			for _, raw := range strings.Split(body, "\n") {
				line := squash(raw)
				// The generator's own comments: every snippet format has "#" ones.
				if line == "" || line == "#" || strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "<!--") {
					continue
				}
				if !executedLines[line] {
					out = append(out, raw)
				}
			}
		}
	}
	return out
}

func TestPtctlConfigPrintsWhatTheLabRuns(t *testing.T) {
	executedLines := map[string]bool{}
	for _, text := range labScripts(t) {
		for _, line := range executed(text, SourceLab) {
			for _, form := range line.forms {
				executedLines[form] = true
			}
		}
	}
	upstreams := labUpstreams(t)
	held := map[string]bool{}
	for _, name := range heldGenerators {
		held[name] = true
		typ, ok := upstreams[name]
		if !ok {
			t.Errorf("heldGenerators names %q, which is not an upstream of the lab proxy", name)
			continue
		}
		if _, both := looseGenerators[name]; both {
			t.Errorf("%q is in heldGenerators and in looseGenerators", name)
		}
		for _, line := range unverifiedGeneratorLines(name, typ, executedLines) {
			t.Errorf("`ptctl config` prints, for the %s upstream %q, a line no lab script executes:\n    %s\n"+
				"print the line the guide documents (docs/clients/%s.md), or run this one in a lab script first",
				typ, name, line, PageFor(typ))
		}
	}
	for name, why := range looseGenerators {
		typ, ok := upstreams[name]
		if !ok {
			t.Errorf("looseGenerators names %q, which is not an upstream of the lab proxy", name)
			continue
		}
		if why == "" {
			t.Errorf("looseGenerators[%q] does not say what is in the way", name)
		}
		if len(unverifiedGeneratorLines(name, typ, executedLines)) == 0 {
			t.Errorf("every line `ptctl config` prints for %q is executed by the lab now: move it to heldGenerators", name)
		}
	}
	// A new upstream of the lab proxy is in one list or the other.
	for name := range upstreams {
		if _, loose := looseGenerators[name]; !held[name] && !loose {
			t.Errorf("the lab upstream %q is in neither heldGenerators nor looseGenerators", name)
		}
	}
}

// keepsOnTheProxy lists, per page, the lines without which a client that is
// otherwise configured for the proxy still goes to the public registry — what
// the lab's name server found, or what the client's own documentation says. A
// block may show part of a file, so the check of a verified block cannot notice
// that such a line was left out; this list can. Each line has to be in a
// verified block of its page.
var keepsOnTheProxy = map[string][]string{
	"composer": {
		// Redefining "packagist" is not enough: Composer keeps asking packagist.org.
		"composer config --global repositories.packagist.org false",
		`{ "packagist.org": false }`,
	},
	// An empty default_channels: the "defaults" channel is repo.anaconda.com.
	"conda": {"default_channels: []"},
	// Without --mirror-only cpanm asks cpanmetadb and other mirrors.
	"cpan": {`export PERL_CPANM_OPT="--mirror https://proxy.example.com/v1/cpan --mirror-only"`},
	// Without the artifact domain brew downloads every bottle from ghcr.io.
	"homebrew": {"export HOMEBREW_ARTIFACT_DOMAIN=https://proxy.example.com/v1/homebrew"},
	// A mirror of every repository, not of Maven Central alone.
	"maven": {"<mirrorOf>*</mirrorOf>"},
	// <clear /> removes nuget.org, which is a source by default.
	"nuget": {"<clear />"},
	// Source replacement, not an additional registry.
	"cargo": {`replace-with = "proxy"`},
}

func TestPagesShowTheLinesThatKeepAClientOnTheProxy(t *testing.T) {
	for slug, lines := range keepsOnTheProxy {
		rel := pagesDir + "/" + slug + ".md"
		shown := map[string]bool{}
		for _, b := range parseRepo(t, rel).Blocks {
			if b.Marker == nil || b.Marker.Kind != KindVerified {
				continue
			}
			for _, line := range b.Lines {
				shown[squash(line)] = true
			}
		}
		for _, line := range lines {
			if !shown[line] {
				t.Errorf("%s: no verified block has the line\n    %s\nwithout it the client still goes to the public registry", rel, line)
			}
		}
	}
}
