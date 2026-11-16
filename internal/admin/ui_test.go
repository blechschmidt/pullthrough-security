package admin

import (
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The dashboard's script is one function scope (an IIFE) without a build
// step, so nothing but these tests notices two declarations of one name: the
// later silently replaces the earlier everywhere in the file. That happened
// once (Task 181 declared a second verdictPill taking a verdict string, and
// the commit-scan views, which pass a boolean, rendered "true" and "—").

// topLevelFunction matches a function declared directly in the IIFE's body
// (two spaces of indentation).
var topLevelFunction = regexp.MustCompile(`(?m)^  (?:async )?function\*? ?([A-Za-z_$][\w$]*)\s*\(`)

func readUIAsset(t *testing.T, name string) string {
	t.Helper()
	data, err := fs.ReadFile(uiFS, "ui/"+name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(data)
}

func TestAdminUIDeclaresEachFunctionOnce(t *testing.T) {
	for _, asset := range []string{"app.js", "graph.js"} {
		src := readUIAsset(t, asset)
		seen := map[string]int{}
		for _, m := range topLevelFunction.FindAllStringSubmatchIndex(src, -1) {
			name := src[m[2]:m[3]]
			line := strings.Count(src[:m[0]], "\n") + 1
			if first, dup := seen[name]; dup {
				t.Errorf("%s:%d declares function %s again (first at line %d): the later declaration replaces the earlier one everywhere", asset, line, name, first)
				continue
			}
			seen[name] = line
		}
		if len(seen) < 10 {
			t.Fatalf("%s: found only %d top-level functions; the pattern no longer matches the file", asset, len(seen))
		}
	}
}

// idLookup matches $("#id") and document.getElementById("id").
var idLookup = regexp.MustCompile(`\$\("#([A-Za-z][\w-]*)"\)|getElementById\("([A-Za-z][\w-]*)"\)`)

// TestAdminUILooksUpExistingElements holds every element the script looks up
// by ID to the markup: a renamed or forgotten element otherwise fails only
// when a user opens the view (a TypeError on null).
func TestAdminUILooksUpExistingElements(t *testing.T) {
	js := readUIAsset(t, "app.js")
	html := readUIAsset(t, "index.html")
	// IDs the script creates itself: el("tag#id", …).
	created := map[string]bool{}
	for _, m := range regexp.MustCompile(`el\("[a-z0-9]*#([A-Za-z][\w-]*)`).FindAllStringSubmatch(js, -1) {
		created[m[1]] = true
	}
	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`\sid="([^"]+)"`).FindAllStringSubmatch(html, -1) {
		defined[m[1]] = true
	}
	missing := map[string]bool{}
	for _, m := range idLookup.FindAllStringSubmatch(js, -1) {
		id := m[1] + m[2]
		if !defined[id] && !created[id] {
			missing[id] = true
		}
	}
	var list []string
	for id := range missing {
		list = append(list, id)
	}
	sort.Strings(list)
	if len(list) > 0 {
		t.Errorf("app.js looks up elements index.html does not have: %s", strings.Join(list, ", "))
	}
}

// mirroringSection returns the Mirroring tab's part of app.js (Task 193):
// from its banner to the next section's.
func mirroringSection(t *testing.T) string {
	t.Helper()
	js := readUIAsset(t, "app.js")
	start := strings.Index(js, "// --- Full mirroring and full scan (Tasks 189-193)")
	end := strings.Index(js, "// --- Security Operations (SOC)")
	if start < 0 || end < start {
		t.Fatal("app.js has no Mirroring section before the SOC section")
	}
	return js[start:end]
}

// htmlSinks are the ways script turns a string into markup.
var htmlSinks = regexp.MustCompile(`innerHTML|outerHTML|insertAdjacentHTML|document\.write|\bhtml:|createContextualFragment|DOMParser`)

// TestMirroringViewRendersRegistryTextAsText: upstream, package and file
// names, cursors and error messages come from registries and the repositories
// behind them. The Mirroring tab (and the SOC tile it renders) puts them in
// text nodes and attribute values only — never through an HTML sink.
func TestMirroringViewRendersRegistryTextAsText(t *testing.T) {
	sec := mirroringSection(t)
	if m := htmlSinks.FindString(sec); m != "" {
		t.Fatalf("the Mirroring section uses an HTML sink: %s", m)
	}
	// Links are built from URLSearchParams, never by pasting a name in.
	if !strings.Contains(sec, `"#dossier?" + p.toString()`) || strings.Contains(sec, `"#dossier?coordinate=" +`) {
		t.Error("the dossier link is not built with URLSearchParams")
	}
	// Focus is restored by comparing keys, never by building a selector out
	// of a name (a name is no CSS).
	if regexp.MustCompile(`\$\([^)]*\+`).MatchString(sec) {
		t.Error("the Mirroring section builds a selector out of data")
	}
}

// TestMirroringControlsGoThroughTheAPIClient: every control posts with
// api.post — api.request runs the passkey step-up when the server asks for
// one — to the endpoints the admin API serves; the only other request the
// section makes is the identity lookup.
func TestMirroringControlsGoThroughTheAPIClient(t *testing.T) {
	sec := mirroringSection(t)
	for _, want := range []string{
		`await api.post(path, body)`,
		`mirroringControl(kind + "/pause"`, `mirroringControl(kind + "/resume"`,
		`mirroringControl("fullmirror/resync"`, `mirroringControl("fullscan/rescan"`,
		`api.get("fullmirror/status")`, `api.get("fullscan/status")`,
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("the Mirroring section lacks %s", want)
		}
	}
	for _, m := range regexp.MustCompile(`fetch\(([^,)]*)`).FindAllStringSubmatch(sec, -1) {
		if m[1] != `"auth/userinfo"` {
			t.Errorf("the Mirroring section fetches %s around api.request", m[1])
		}
	}
	// The kinds the pause and resume controls are called with name the
	// endpoints' prefixes.
	for _, call := range regexp.MustCompile(`mirroring(?:Pause|Resume)\("([a-z]+)"`).FindAllStringSubmatch(sec, -1) {
		if call[1] != "fullmirror" && call[1] != "fullscan" {
			t.Errorf("a control for %q", call[1])
		}
	}
	for _, path := range []string{"/api/fullmirror/pause", "/api/fullmirror/resume", "/api/fullmirror/resync",
		"/api/fullscan/pause", "/api/fullscan/resume", "/api/fullscan/rescan"} {
		if !regexp.MustCompile(`"` + regexp.QuoteMeta(path) + `"`).MatchString(readWebAuthnSource(t)) {
			t.Errorf("%s is not a step-up protected action: the console's automatic step-up would never run", path)
		}
	}
}

// readWebAuthnSource reads the step-up service's list of protected actions.
func readWebAuthnSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../webauthn/webauthn.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestMirroringControlsAreOfferedOnlyToTheirRoles: a control is offered only
// to an identity the server lets use it. Pausing and resuming need operate,
// a resync or a re-scan administer (authz.go), and none of them is a
// tenant-bound identity's; every function that renders a control asks first.
func TestMirroringControlsAreOfferedOnlyToTheirRoles(t *testing.T) {
	sec := mirroringSection(t)
	for _, want := range []string{
		`function mirroringMayOperate() { return adminCan("operate") && !adminIdentity.tenant; }`,
		`function mirroringMayAdminister() { return adminCan("administer") && !adminIdentity.tenant; }`,
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("the Mirroring section lacks %s", want)
		}
	}
	for path, guard := range map[string]string{
		"/api/fullmirror/pause": "operate", "/api/fullmirror/resume": "operate", "/api/fullscan/pause": "operate", "/api/fullscan/resume": "operate",
		"/api/fullmirror/resync": "administer", "/api/fullscan/rescan": "administer",
	} {
		if got := requiredCapability(http.MethodPost, path).String(); got != guard {
			t.Errorf("POST %s needs %s on the server, but the console offers it on %s", path, got, guard)
		}
	}
	// Split the section into its functions; each that renders a control
	// (calls one of the control functions) checks the guard for it.
	controls := map[string]string{"mirroringPause(": "mirroringMayOperate()", "mirroringResume(": "mirroringMayOperate()",
		"mirroringResync(": "mirroringMayAdminister()", "mirroringRescan(": "mirroringMayAdminister()"}
	funcs := regexp.MustCompile(`(?m)^  (?:async )?function ([A-Za-z]+)\(`).FindAllStringSubmatchIndex(sec, -1)
	rendering := 0
	for i, f := range funcs {
		name := sec[f[2]:f[3]]
		end := len(sec)
		if i+1 < len(funcs) {
			end = funcs[i+1][0]
		}
		body := sec[f[1]:end]
		for call, guard := range controls {
			if strings.HasPrefix(call, name+"(") || !strings.Contains(body, call) {
				continue
			}
			rendering++
			if !strings.Contains(body, guard) {
				t.Errorf("%s renders a %s control without asking %s", name, strings.TrimSuffix(call, "("), guard)
			}
		}
	}
	if rendering < 4 {
		t.Fatalf("found %d control renderings; the split no longer matches the code", rendering)
	}
	// What the identity lookup decides on: the capabilities and the tenant
	// auth/userinfo reports.
	for _, want := range []string{`info.capabilities`, `info.tenant`, `fetch("auth/userinfo"`} {
		if !strings.Contains(sec, want) {
			t.Errorf("the identity lookup lacks %s", want)
		}
	}
}

// TestMirroringViewIsWired: the tab opens the view, the address bar names the
// open panel, leaving the tab stops its refresh, the SOC dashboard shows the
// tile, and the dossier can be linked to.
func TestMirroringViewIsWired(t *testing.T) {
	js := readUIAsset(t, "app.js")
	html := readUIAsset(t, "index.html")
	for _, want := range []string{
		`views.mirroring = async function`,
		`if (currentView === "mirroring" && name !== "mirroring") mirroringStopAuto();`,
		`else if (currentView === "mirroring") filter = mirroringHashParams().toString();`,
		`if (target.name === "mirroring") setMirroringFromParams(target.params);`,
		`else if (currentView === "dossier") filter = dossierParams().toString();`,
		`if (target.name === "dossier") setDossierFromParams(target.params);`,
		`secopsMirroringTile();`,
		`(await loadAdminIdentity(true)).info`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	for _, id := range []string{"mirroring-body", "mirroring-foot", "mirroring-cards", "mirroring-notice", "mirroring-status",
		"mirroring-updated", "mirroring-refresh", "mirroring-auto", "mirroring-controls", "mirroring-detail",
		"mirroring-detail-title", "mirroring-detail-body", "mirroring-detail-close", "secops-cards"} {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("index.html has no #%s", id)
		}
	}
	// The detail panel's region is named by its heading, which the focus
	// moves to when the panel opens.
	if !strings.Contains(js, `$("#mirroring-detail-title").focus()`) {
		t.Error("opening a panel does not move the focus to its heading")
	}
}
