package admin

import (
	"regexp"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/uiaudit"
)

// TestAdminUIAccessibility enforces the WCAG 2.1 AA baseline documented in
// docs/accessibility.md against the embedded admin dashboard assets (the SPA
// shell, the SOC/dossier/timeline views and the supply-chain graph page). It is
// the lightweight, always-runnable "axe-core equivalent" check the task calls
// for: no browser or Node toolchain required.
func TestAdminUIAccessibility(t *testing.T) {
	findings, err := uiaudit.Audit(dashboardFS)
	if err != nil {
		t.Fatalf("auditing embedded admin UI: %v", err)
	}
	for _, f := range findings {
		t.Logf("[%s] %s: %s (%s)", f.Severity, f.File, f.Detail, f.Rule)
	}
	if errs := uiaudit.Errors(findings); len(errs) != 0 {
		for _, f := range errs {
			t.Errorf("accessibility: %s: %s (%s)", f.File, f.Detail, f.Rule)
		}
	}
}

// TestMirroringViewAccessibility holds the Mirroring tab (Task 193) to the
// patterns docs/accessibility.md describes, beyond what the generic audit
// checks: a polite live region announces refreshes, the auto-refresh toggle
// states whether it is on, the table is captioned with its column groups
// headed, and the detail panel is a region named by a heading the focus can
// be moved to.
func TestMirroringViewAccessibility(t *testing.T) {
	html := readUIAsset(t, "index.html")
	start := strings.Index(html, `<section id="view-mirroring"`)
	if start < 0 {
		t.Fatal("index.html has no Mirroring view")
	}
	end := strings.Index(html[start:], "</section>")
	view := html[start : start+end]
	tag := func(id string) string {
		t.Helper()
		m := regexp.MustCompile(`<[a-z0-9]+[^>]*\sid="` + regexp.QuoteMeta(id) + `"[^>]*>`).FindString(view)
		if m == "" {
			t.Fatalf("the Mirroring view has no #%s", id)
		}
		return m
	}
	for id, attrs := range map[string][]string{
		"mirroring-status":       {`role="status"`, `aria-live="polite"`, `aria-atomic="true"`},
		"mirroring-auto":         {`aria-pressed="true"`, `type="button"`},
		"mirroring-detail":       {`role="region"`, `aria-labelledby="mirroring-detail-title"`, "hidden"},
		"mirroring-detail-title": {`tabindex="-1"`},
		"mirroring-detail-close": {`aria-controls="mirroring-detail"`, `type="button"`},
		"mirroring-controls":     {`role="group"`, `aria-label=`},
		"mirroring-table":        {},
		"mirroring-body":         {},
		"mirroring-foot":         {},
		"mirroring-refresh":      {`type="button"`},
		"mirroring-notice":       {},
		"mirroring-cards":        {},
		"mirroring-detail-body":  {},
		"mirroring-updated":      {},
	} {
		el := tag(id)
		for _, a := range attrs {
			if !strings.Contains(el, a) {
				t.Errorf("#%s lacks %s: %s", id, a, el)
			}
		}
	}
	if !regexp.MustCompile(`<section id="view-mirroring"[^>]*aria-label="[^"]+"`).MatchString(view) {
		t.Error("the Mirroring view has no aria-label")
	}
	if !strings.Contains(view, "<caption") {
		t.Error("the Mirroring table has no caption")
	}
	// The two groups of columns are headed as groups, over col groups.
	if strings.Count(view, `scope="colgroup"`) != 2 || strings.Count(view, "<colgroup") != 3 {
		t.Error("the Mirroring table's column groups are not headed as groups")
	}
	for _, th := range regexp.MustCompile(`<th\b[^>]*>`).FindAllString(view, -1) {
		if !strings.Contains(th, "scope=") {
			t.Errorf("a header without a scope: %s", th)
		}
	}
	// The tab itself.
	if !regexp.MustCompile(`<button class="tab" role="tab" aria-selected="false" data-view="mirroring">Mirroring</button>`).MatchString(html) {
		t.Error("the tab list has no Mirroring tab")
	}
}
