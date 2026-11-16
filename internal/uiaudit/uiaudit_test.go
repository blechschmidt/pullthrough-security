package uiaudit

import (
	"testing"
	"testing/fstest"
)

func findingsByRule(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Rule] = f
	}
	return m
}

// A fully-conformant single-page app should produce no findings.
func TestAudit_CleanDocument(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": {Data: []byte(`<!DOCTYPE html>
<html lang="en">
<head><meta name="color-scheme" content="light dark"><link rel="stylesheet" href="styles.css"></head>
<body>
  <a class="skip-link" href="#main">Skip to content</a>
  <nav class="tabs" role="tablist" aria-label="Sections">
    <button role="tab" aria-selected="true" aria-controls="view-a">A</button>
  </nav>
  <main id="main" tabindex="-1">
    <section id="view-a" role="tabpanel"><h1>A</h1>
      <label class="visually-hidden" for="q">Query</label>
      <input id="q" type="search">
      <label>Wrapped <input type="text"></label>
      <select aria-label="Mode"><option>x</option></select>
      <button aria-label="Close">x</button>
    </section>
  </main>
  <div role="dialog" aria-modal="true" aria-labelledby="dt"><h2 id="dt">Details</h2></div>
</body></html>`)},
		"styles.css": {Data: []byte(`:focus-visible{outline:2px solid blue}
@media (prefers-reduced-motion: reduce){*{animation:none}}`)},
	}
	findings, err := Audit(fsys)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if errs := Errors(findings); len(errs) != 0 {
		t.Fatalf("expected no error findings, got %d: %+v", len(errs), errs)
	}
}

// A document that violates each rule should be flagged for each.
func TestAudit_DetectsViolations(t *testing.T) {
	fsys := fstest.MapFS{
		"bad.html": {Data: []byte(`<html>
<body>
  <nav class="tabs"><button role="tab">A</button></nav>
  <input id="noname" type="text" placeholder="only a placeholder">
  <select id="s2"></select>
  <button></button>
  <div role="dialog"></div>
  <a href="#nowhere">broken</a>
</body></html>`)},
		"styles.css": {Data: []byte(`body{color:red}`)},
	}
	findings, err := Audit(fsys)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	byRule := findingsByRule(findings)
	want := []string{
		"html-has-lang",     // <html> missing lang
		"has-main-landmark", // no <main>
		"landmark-labeled",  // <nav> unlabeled
		"tablist-present",   // role=tab without role=tablist
		"control-has-name",  // unlabeled input/select
		"button-has-name",   // empty button
		"dialog-name",       // dialog without name
		"skip-link",         // navigable page, no skip link
		"focus-visible",     // CSS lacks focus style
		"reduced-motion",    // CSS lacks reduced-motion
		"anchor-target",     // #nowhere has no target
	}
	for _, r := range want {
		if _, ok := byRule[r]; !ok {
			t.Errorf("expected a %q finding, got none; all findings: %+v", r, findings)
		}
	}
}

// The wrapping-label and for= association heuristics must not produce false
// positives for correctly-labelled controls.
func TestAudit_LabelAssociations(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": {Data: []byte(`<html lang="en"><body>
  <a class="skip-link" href="#main">Skip</a>
  <nav aria-label="x"><button role="tab" aria-selected="true">T</button></nav>
  <main id="main">
    <label>Outer <input type="text"></label>
    <label class="muted">Tenant <input id="t2" type="text"></label>
    <label for="t3">Three</label><input id="t3" type="text">
    <textarea aria-label="body"></textarea>
  </main>
</body></html>`)},
		"s.css": {Data: []byte(`:focus-visible{outline:1px}@media (prefers-reduced-motion:reduce){*{}}`)},
	}
	findings, err := Audit(fsys)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, f := range Errors(findings) {
		if f.Rule == "control-has-name" {
			t.Errorf("false positive control-has-name: %+v", f)
		}
	}
}

// The reference and value rules (Task 193): every ID a static attribute names
// exists, enumerated ARIA values are valid, table headers have a scope, a
// region is named, and a live region's politeness agrees with its role.
func TestAudit_ReferencesAndValues(t *testing.T) {
	page := func(body string) fstest.MapFS {
		return fstest.MapFS{
			"index.html": {Data: []byte(`<html lang="en"><body><a class="skip-link" href="#main">Skip</a>
  <nav aria-label="x" role="tablist"><button role="tab" aria-selected="true" aria-controls="main">T</button></nav>
  <main id="main">` + body + `</main></body></html>`)},
			"s.css": {Data: []byte(`:focus-visible{outline:1px}@media (prefers-reduced-motion:reduce){*{}}`)},
		}
	}
	clean := page(`
    <p id="st" class="visually-hidden" role="status" aria-live="polite" aria-atomic="true"></p>
    <button type="button" aria-pressed="true" aria-controls="panel">Auto-refresh</button>
    <div id="panel" role="region" aria-labelledby="ttl" hidden><h3 id="ttl" tabindex="-1">npm</h3></div>
    <label for="f">Filter</label><select id="f"><option>x</option></select>
    <table><caption>c</caption><thead><tr><th scope="col" rowspan="2">A</th><th scope="colgroup" colspan="2">B</th></tr>
      <tr><th scope="col">B1</th><th scope="col">B2</th></tr></thead>
      <tbody><tr><th scope="row">r</th><td>1</td><td>2</td></tr></tbody></table>
    <a href="#main" aria-current="page">here</a>`)
	findings, err := Audit(clean)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("a conformant page: %+v", findings)
	}

	bad := page(`
    <p role="status" aria-live="assertive"></p>
    <button type="button" aria-pressed="yes" aria-controls="gone">Toggle</button>
    <button type="button" aria-expanded="1">More</button>
    <div role="region"><h3>untitled</h3></div>
    <input id="i" aria-describedby="hint missing-hint"><span id="hint">h</span>
    <label for="nothing">Lost</label>
    <table><thead><tr><th>A</th></tr></thead></table>`)
	findings, err = Audit(bad)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, f := range findings {
		count[f.Rule]++
	}
	want := map[string]int{"aria-idref": 3, "aria-valid-value": 2, "th-has-scope": 1, "region-has-name": 1, "live-region-politeness": 1}

	for rule, n := range want {
		if count[rule] != n {
			t.Errorf("%s: %d findings, want %d (all: %+v)", rule, count[rule], n, findings)
		}
	}
	for _, f := range findings {
		if f.Rule == "live-region-politeness" && f.Severity != SeverityWarn {
			t.Errorf("%s should be advisory", f.Rule)
		}
	}
}

// Unquoted attribute values are values, and ARIA tokens are ASCII
// case-insensitive: valid markup written either way raises nothing.
func TestAudit_UnquotedAndMixedCaseValues(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": {Data: []byte(`<html lang=en><body><a class="skip-link" href="#main">Skip</a>
  <nav aria-label=x role=tablist><button role=tab aria-selected=TRUE aria-controls=main>T</button></nav>
  <main id=main><button type=button aria-expanded=false aria-pressed="True" aria-controls=main>More</button>
    <table><thead><tr><th scope=col>A</th></tr></thead></table></main></body></html>`)},
		"s.css": {Data: []byte(`:focus-visible{outline:1px}@media (prefers-reduced-motion:reduce){*{}}`)},
	}
	findings, err := Audit(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("valid unquoted and mixed-case markup: %+v", findings)
	}
}
