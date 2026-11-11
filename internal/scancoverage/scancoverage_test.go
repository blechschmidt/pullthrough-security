package scancoverage

import (
	"strings"
	"testing"
)

func TestCatalogIsConsistent(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	cat := Catalog()
	if len(cat) == 0 {
		t.Fatal("the catalog is empty")
	}
	for i := 1; i < len(cat); i++ {
		if cat[i-1].Type >= cat[i].Type {
			t.Errorf("Catalog() is not sorted by type: %q before %q", cat[i-1].Type, cat[i].Type)
		}
	}
	// Catalog returns a copy: a caller cannot alter the data.
	cat[0].Type = "tampered"
	if Catalog()[0].Type == "tampered" {
		t.Error("Catalog() hands out the catalog itself")
	}
}

func TestLookupByTypeAndAlias(t *testing.T) {
	for _, e := range Catalog() {
		for _, name := range append([]string{e.Type}, e.Aliases...) {
			got, ok := Lookup(name)
			if !ok || got.Type != e.Type {
				t.Errorf("Lookup(%q) = %q, %v; want %q", name, got.Type, ok, e.Type)
			}
			if got, ok := Lookup("  " + strings.ToUpper(name) + " "); !ok || got.Type != e.Type {
				t.Errorf("Lookup is not case- and space-insensitive for %q", name)
			}
		}
	}
	if _, ok := Lookup("cobol"); ok {
		t.Error("Lookup found an entry for a type that does not exist")
	}
	if _, ok := Lookup(""); ok {
		t.Error("Lookup found an entry for the empty type")
	}
}

// Git is the one type the package scan does not examine, and the catalog must
// say what does: the commit scan reads commits, and the package scan — under
// its own scope key — the LFS objects a commit only points at.
//
// It must also say what does not happen. No gate refuses a clone or fetch: the
// commit scan's verdicts gate the packages built from a commit, not the Git
// traffic. An earlier draft of this entry claimed otherwise; the record is only
// worth having if it does not flatter the code. (That Git traffic passes no
// gate is checked against the code in cmd/pullthrough.)
func TestGitIsRecordedAsCommitScanWithLFSUnderThePackageScan(t *testing.T) {
	git, ok := Lookup("git")
	if !ok {
		t.Fatal("no entry for git")
	}
	if git.Gate != GateCommitScan || git.Ecosystem != "" {
		t.Errorf("git: gate %q, ecosystem %q; want the commit scan and no package-scan scope key", git.Gate, git.Ecosystem)
	}
	notes := strings.Join(git.Notes, " ")
	for _, want := range []string{"commit scan", "git-lfs", "llmPackageScan.include", "scanning.watch", "is not refused by a verdict", "runs no admission gate"} {
		if !strings.Contains(notes, want) {
			t.Errorf("the git entry's notes do not mention %q", want)
		}
	}
	for _, sp := range ServePaths() {
		if strings.HasPrefix(sp.Path, "Git clone") && !strings.Contains(sp.How, "do not refuse a clone or fetch") {
			t.Errorf("the serve-path row for a Git clone does not say that nothing refuses it: %q", sp.How)
		}
	}
	lfs := false
	for _, p := range git.Paths {
		lfs = lfs || p.Serve == ServeLFS
	}
	if !lfs {
		t.Error("the git entry does not list the LFS object path")
	}
	// Every other entry is examined by the package scan.
	for _, e := range Catalog() {
		if e.Type != "git" && e.Gate != GatePackageScan {
			t.Errorf("%s is examined by %q, want the package scan", e.Type, e.Gate)
		}
	}
}

func TestValidateCatchesInconsistentEntries(t *testing.T) {
	saved := catalog
	defer func() { catalog = saved }()
	base := Entry{Type: "x", Title: "X", Gate: GatePackageScan, Ecosystem: "x",
		Paths: []Path{{What: "artifact", Example: "/a.tgz", Class: ClassPayload, Format: "tar.gz", Serve: ServeCache}}}

	cases := map[string]func(e *Entry){
		"no title":                     func(e *Entry) { e.Title = "" },
		"unknown gate":                 func(e *Entry) { e.Gate = "vibes" },
		"package scan without a key":   func(e *Entry) { e.Ecosystem = "" },
		"package scan without payload": func(e *Entry) { e.Paths[0].Class = ClassMetadata },
		"payload without a format":     func(e *Entry) { e.Paths[0].Format = "" },
		"unknown class":                func(e *Entry) { e.Paths[0].Class = "maybe" },
		"unknown kind":                 func(e *Entry) { e.Paths[0].Kind = "blob-ish" },
		"unknown serve path":           func(e *Entry) { e.Paths[0].Serve = "carrier pigeon" },
		"path without an example":      func(e *Entry) { e.Paths[0].Example = "" },
		"index archive that is a payload": func(e *Entry) {
			e.Paths[0].Kind = KindIndexArchive
		},
	}
	for name, mutate := range cases {
		e := base
		e.Paths = append([]Path(nil), base.Paths...)
		mutate(&e)
		catalog = []Entry{e}
		if err := Validate(); err == nil {
			t.Errorf("%s: Validate accepted the entry", name)
		}
	}

	catalog = []Entry{base, base}
	if err := Validate(); err == nil || !strings.Contains(err.Error(), "claimed by both") {
		t.Errorf("a duplicate type: err = %v", err)
	}
	alias := base
	alias.Type, alias.Aliases = "y", []string{"x"}
	catalog = []Entry{base, alias}
	if err := Validate(); err == nil {
		t.Error("an alias that collides with another type was accepted")
	}
	catalog = []Entry{base}
	if err := Validate(); err != nil {
		t.Errorf("the base entry is valid: %v", err)
	}
}

func TestGenerateReference(t *testing.T) {
	doc := GenerateReference()
	if doc != GenerateReference() {
		t.Fatal("GenerateReference is not deterministic")
	}
	if !strings.HasPrefix(doc, "# LLM scan coverage (generated)\n") || !strings.Contains(doc, "GENERATED FILE — DO NOT EDIT") {
		t.Error("the document lacks its title or its generated-file notice")
	}
	for _, e := range Catalog() {
		if !strings.Contains(doc, "### "+e.Title+"\n") {
			t.Errorf("the document has no section for %s", e.Type)
		}
		for _, p := range e.Paths {
			if !strings.Contains(doc, "`"+p.Example+"`") {
				t.Errorf("%s: example path %q is not in the document", e.Type, p.Example)
			}
		}
		for _, n := range e.Notes {
			if !strings.Contains(doc, n) {
				t.Errorf("%s: a note is missing from the document", e.Type)
			}
		}
	}
	for _, sp := range ServePaths() {
		if !strings.Contains(doc, sp.Path) {
			t.Errorf("serve path %q is not in the document", sp.Path)
		}
	}
	for _, f := range Formats() {
		if !strings.Contains(doc, f.Format) {
			t.Errorf("format %q is not in the document", f.Format)
		}
	}
	// Every serve path a client can reach is accounted for.
	paths := strings.ToLower(strings.Join(func() []string {
		var out []string
		for _, sp := range ServePaths() {
			out = append(out, sp.Path)
		}
		return out
	}(), "\n"))
	for _, want := range []string{"cache miss", "cache hit", "non-cacheable", "range", "head", "manifest", "blob", "lfs", "clone", "peer endpoint", "sibling", "pre-warm", "air-gap"} {
		if !strings.Contains(paths, want) {
			t.Errorf("no serve-path row mentions %q", want)
		}
	}
	// Table rows are well-formed: no row is broken by a stray newline.
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "|") && !strings.HasSuffix(line, "|") {
			t.Errorf("a table row does not end with a cell separator: %q", line)
		}
	}
}
