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
// says "verified" is, line for line, in the scripts it names.
func TestSnippetsAreVerified(t *testing.T) {
	lab := labScripts(t)
	usedLab := map[string]bool{}
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
			scripts := map[Source]string{}
			for _, src := range b.Marker.Sources {
				text, ok := scriptOf(t, lab, src)
				if !ok {
					t.Errorf("%s: the marker names %s, which does not exist", at, src)
					continue
				}
				scripts[src] = text
				if src.Kind == SourceLab {
					usedLab[src.Name] = true
				}
			}
			switch b.Marker.Kind {
			case KindVerified:
				verified++
				missing, unused := b.Unverified(scripts)
				for _, line := range missing {
					t.Errorf("%s: marked verified by %v, but no such script has the line\n    %s", at, b.Marker.Sources, line)
				}
				for _, src := range unused {
					if _, ok := scripts[src]; ok {
						t.Errorf("%s: the marker names %s, but no line of the block is in that script", at, src)
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
// it is YAML, and every key path in it names a real setting.
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

// The result table in docs/client-lab.md has a row for every lab script: a
// script that was added has been run.
func TestLabResultsListEveryScript(t *testing.T) {
	doc := string(readRepo(t, labDoc))
	for name := range labScripts(t) {
		if !strings.Contains(doc, "[`"+name+".sh`]") {
			t.Errorf("%s has no result row for %s.sh (run it and regenerate the table: scripts/client-lab/lab.sh report)", labDoc, name)
		}
	}
}
