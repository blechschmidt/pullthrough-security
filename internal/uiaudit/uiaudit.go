// Package uiaudit is a lightweight, dependency-free accessibility linter for
// the proxy's embedded admin/portal web assets. It is an "axe-core equivalent"
// that runs in-process against an fs.FS of HTML/CSS (typically an embed.FS), so
// the WCAG 2.1 AA baseline documented in docs/accessibility.md is enforced in
// CI by a plain `go test` with no browser, Node, or network dependency.
//
// The checker deliberately covers the structural, name, landmark, keyboard and
// motion rules that are verifiable from static markup — the same class of
// issues axe-core flags as "serious"/"critical" without needing a rendered DOM
// (missing form labels, unlabeled landmarks, incomplete tab/dialog ARIA, a
// missing skip link, no visible focus style, no reduced-motion handling). Pixel
// colour-contrast is audited and documented separately (it depends on composited
// CSS custom properties that a static scan cannot resolve reliably).
package uiaudit

import (
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Severity classifies a finding. Error findings fail the build; Warn findings
// are advisory.
type Severity string

const (
	SeverityError Severity = "error"
	SeverityWarn  Severity = "warn"
)

// Finding is a single accessibility issue located in one asset.
type Finding struct {
	File     string   // asset path within the FS
	Rule     string   // stable rule id, e.g. "control-has-name"
	Detail   string   // human-readable description
	Severity Severity // error (fails CI) or warn (advisory)
}

// element is a parsed open tag with its attributes and whether it is nested
// inside a <label> (used to resolve implicit form labelling).
type element struct {
	name      string
	attrs     map[string]string
	inLabel   bool
	innerText string // for buttons/anchors: text content with tags stripped
	hasInner  bool
}

var (
	// Matches opening/closing tags, tolerating quoted attribute values that
	// themselves contain angle brackets.
	tokenRe    = regexp.MustCompile(`(?is)<(/?)([a-zA-Z][a-zA-Z0-9]*)((?:[^<>"']|"[^"]*"|'[^']*')*?)\s*(/?)>`)
	attrRe     = regexp.MustCompile(`([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*"([^"]*)"|\s*=\s*'([^']*)')?`)
	tagStripRe = regexp.MustCompile(`(?is)<[^>]*>`)
)

func parseAttrs(s string) map[string]string {
	m := map[string]string{}
	for _, mm := range attrRe.FindAllStringSubmatch(s, -1) {
		key := strings.ToLower(mm[1])
		val := mm[2]
		if val == "" {
			val = mm[3]
		}
		if _, dup := m[key]; !dup {
			m[key] = val
		}
	}
	return m
}

// parseHTML returns the ordered open elements and the full set of `for`
// attribute values declared by <label> elements in the document.
func parseHTML(src string) (els []element, labelFor map[string]bool) {
	labelFor = map[string]bool{}
	labelDepth := 0
	locs := tokenRe.FindAllStringSubmatchIndex(src, -1)
	for _, l := range locs {
		closing := src[l[2]:l[3]] == "/"
		name := strings.ToLower(src[l[4]:l[5]])
		attrStr := src[l[6]:l[7]]
		selfClose := src[l[8]:l[9]] == "/"

		if closing {
			if name == "label" && labelDepth > 0 {
				labelDepth--
			}
			continue
		}
		attrs := parseAttrs(attrStr)
		el := element{name: name, attrs: attrs, inLabel: labelDepth > 0}

		if name == "label" {
			if f := attrs["for"]; f != "" {
				labelFor[f] = true
			}
		}
		// Capture inner text for elements where an accessible name may come
		// from content (button, a). Find the matching close tag naively.
		if name == "button" || name == "a" {
			if end := matchCloseTag(src, l[1], name); end >= 0 {
				inner := tagStripRe.ReplaceAllString(src[l[1]:end], "")
				el.innerText = strings.TrimSpace(inner)
				el.hasInner = true
			}
		}
		els = append(els, el)

		if name == "label" && !selfClose {
			labelDepth++
		}
	}
	return els, labelFor
}

// matchCloseTag finds the index of the matching </name> after start, honoring
// simple nesting of the same tag name.
func matchCloseTag(src string, start int, name string) int {
	depth := 1
	re := regexp.MustCompile(`(?is)<(/?)` + regexp.QuoteMeta(name) + `(\s[^<>]*)?/?>`)
	for _, m := range re.FindAllStringSubmatchIndex(src[start:], -1) {
		if src[start+m[2]:start+m[3]] == "/" {
			depth--
			if depth == 0 {
				return start + m[0]
			}
		} else {
			depth++
		}
	}
	return -1
}

func attrPresent(a map[string]string, keys ...string) bool {
	for _, k := range keys {
		if strings.TrimSpace(a[k]) != "" {
			return true
		}
	}
	return false
}

// labelledControlTypes: input types that do not require an accessible name
// because they carry their own semantics or label.
var selfNamedInputTypes = map[string]bool{
	"hidden": true, "submit": true, "reset": true, "button": true, "image": true,
}

// Audit scans every *.html and *.css asset in fsys and returns all findings,
// ordered by file then rule. CSS-level rules (visible focus, reduced motion)
// are evaluated against the union of all stylesheets plus inline <style> blocks,
// since a single-page app's pages share one stylesheet.
func Audit(fsys fs.FS) ([]Finding, error) {
	var htmlFiles, cssFiles []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(path.Ext(p)) {
		case ".html", ".htm":
			htmlFiles = append(htmlFiles, p)
		case ".css":
			cssFiles = append(cssFiles, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var findings []Finding
	var allCSS strings.Builder

	for _, f := range cssFiles {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		allCSS.Write(b)
		allCSS.WriteByte('\n')
	}

	styleBlock := regexp.MustCompile(`(?is)<style[^>]*>(.*?)</style>`)

	for _, f := range htmlFiles {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		src := string(b)
		for _, m := range styleBlock.FindAllStringSubmatch(src, -1) {
			allCSS.WriteString(m[1])
			allCSS.WriteByte('\n')
		}
		findings = append(findings, auditHTML(f, src)...)
	}

	findings = append(findings, auditCSS(allCSS.String())...)

	// Collapse exact-duplicate findings (e.g. a runtime-wired attribute absent
	// from every one of many repeated tabs) so the report stays readable;
	// findings that differ by control id remain distinct.
	seen := map[Finding]bool{}
	deduped := findings[:0]
	for _, f := range findings {
		if seen[f] {
			continue
		}
		seen[f] = true
		deduped = append(deduped, f)
	}
	findings = deduped

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Rule < findings[j].Rule
	})
	return findings, nil
}

func auditHTML(file, src string) []Finding {
	var out []Finding
	add := func(rule, detail string, sev Severity) {
		out = append(out, Finding{File: file, Rule: rule, Detail: detail, Severity: sev})
	}

	els, labelFor := parseHTML(src)

	var hasNavOrTablist, hasHTML, hasMain, hasSkipLink bool
	var mainIDs = map[string]bool{}
	var anchorTargets []string
	var tabCount, tablistCount int
	allIDs := map[string]bool{}

	for _, e := range els {
		if id := e.attrs["id"]; id != "" {
			allIDs[id] = true
		}
	}

	for _, e := range els {
		switch e.name {
		case "html":
			hasHTML = true
			if strings.TrimSpace(e.attrs["lang"]) == "" {
				add("html-has-lang", "<html> is missing a non-empty lang attribute", SeverityError)
			}
		case "main":
			hasMain = true
			if id := e.attrs["id"]; id != "" {
				mainIDs[id] = true
			}
		case "nav":
			hasNavOrTablist = true
			if !attrPresent(e.attrs, "aria-label", "aria-labelledby") {
				add("landmark-labeled", "<nav> landmark lacks aria-label/aria-labelledby", SeverityError)
			}
		case "a":
			if h := e.attrs["href"]; strings.HasPrefix(h, "#") && len(h) > 1 {
				anchorTargets = append(anchorTargets, strings.TrimPrefix(h, "#"))
			}
			if e.hasInner && e.innerText == "" && !attrPresent(e.attrs, "aria-label", "aria-labelledby", "title") && e.attrs["aria-hidden"] != "true" {
				add("link-has-name", "<a> link has no text content or accessible name", SeverityWarn)
			}
		case "button":
			if e.hasInner && e.innerText == "" && !attrPresent(e.attrs, "aria-label", "aria-labelledby", "title") {
				add("button-has-name", "icon-only <button> has no text or accessible name (id="+e.attrs["id"]+")", SeverityError)
			}
		case "input", "select", "textarea":
			if e.name == "input" && selfNamedInputTypes[strings.ToLower(e.attrs["type"])] {
				break
			}
			named := attrPresent(e.attrs, "aria-label", "aria-labelledby", "title") ||
				e.inLabel ||
				(e.attrs["id"] != "" && labelFor[e.attrs["id"]])
			if !named {
				add("control-has-name", "form control <"+e.name+" id="+e.attrs["id"]+"> has no associated label or accessible name", SeverityError)
			}
		case "canvas":
			if !attrPresent(e.attrs, "aria-label", "aria-labelledby", "role") && e.attrs["aria-hidden"] != "true" {
				add("canvas-has-alt", "<canvas> has no text alternative (role/aria-label)", SeverityWarn)
			}
		case "img":
			if _, ok := e.attrs["alt"]; !ok && e.attrs["aria-hidden"] != "true" && !attrPresent(e.attrs, "aria-label", "aria-labelledby") {
				add("image-alt", "<img> has no alt text", SeverityError)
			}
		}

		if e.attrs["role"] == "tablist" {
			tablistCount++
			hasNavOrTablist = true
		}
		if e.attrs["role"] == "tab" {
			tabCount++
			if !attrPresent(e.attrs, "aria-selected") {
				add("tab-aria-selected", "element role=tab lacks aria-selected", SeverityError)
			}
			if !attrPresent(e.attrs, "aria-controls") {
				add("tab-aria-controls", "element role=tab lacks aria-controls (may be wired at runtime)", SeverityWarn)
			}
		}
		if e.attrs["role"] == "dialog" || e.attrs["role"] == "alertdialog" {
			if e.attrs["aria-modal"] != "true" {
				add("dialog-modal", "role=dialog should set aria-modal=true", SeverityWarn)
			}
			if !attrPresent(e.attrs, "aria-label", "aria-labelledby") {
				add("dialog-name", "role=dialog has no accessible name (aria-label/aria-labelledby)", SeverityError)
			}
		}
	}

	if hasHTML && !hasMain {
		add("has-main-landmark", "document has no <main> landmark", SeverityError)
	}
	if tabCount > 0 && tablistCount == 0 {
		add("tablist-present", "role=tab elements exist but no role=tablist container", SeverityError)
	}

	// Skip link: required on pages that expose section navigation. The anchor
	// must point at the main landmark's id.
	for _, t := range anchorTargets {
		if mainIDs[t] {
			hasSkipLink = true
		}
	}
	if hasHTML && hasNavOrTablist && !hasSkipLink {
		add("skip-link", "navigable page has no skip link targeting the <main> landmark", SeverityError)
	}

	// Dangling same-page anchors (fragment targets that do not exist) are a
	// common keyboard-navigation bug.
	for _, t := range anchorTargets {
		if !allIDs[t] && t != "" {
			add("anchor-target", "same-page link points at #"+t+" which has no matching element", SeverityWarn)
		}
	}

	return out
}

func auditCSS(css string) []Finding {
	var out []Finding
	low := strings.ToLower(css)
	if !strings.Contains(low, ":focus-visible") && !strings.Contains(low, ":focus") {
		out = append(out, Finding{File: "(stylesheets)", Rule: "focus-visible", Detail: "no visible focus indicator (:focus-visible / :focus) defined", Severity: SeverityError})
	}
	if !strings.Contains(low, "prefers-reduced-motion") {
		out = append(out, Finding{File: "(stylesheets)", Rule: "reduced-motion", Detail: "no prefers-reduced-motion handling defined", Severity: SeverityError})
	}
	return out
}

// Errors returns only the error-severity findings.
func Errors(fs []Finding) []Finding {
	var e []Finding
	for _, f := range fs {
		if f.Severity == SeverityError {
			e = append(e, f)
		}
	}
	return e
}
