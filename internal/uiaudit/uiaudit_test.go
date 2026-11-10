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
