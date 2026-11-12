package lockfiles_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/scancoverage"
)

// TestEveryUpstreamTypeIsCovered holds the lock-file coverage table to the
// backend catalog: every upstream type the configuration accepts
// (config.UpstreamTypes, aliases included) must have a parser or an explicit
// entry saying why it has none. A backend added without either fails here.
func TestEveryUpstreamTypeIsCovered(t *testing.T) {
	types := config.UpstreamTypes()
	if len(types) < 30 {
		t.Fatalf("config.UpstreamTypes() returned only %d types", len(types))
	}
	reg := lockfiles.DefaultRegistry()
	for _, typ := range types {
		c, ok := lockfiles.CoverageFor(typ)
		if !ok {
			t.Errorf("upstream type %q has neither a lock-file parser nor a no-parser entry with a reason (internal/lockfiles/coverage.go)", typ)
			continue
		}
		hasParsers := len(reg.Parsers(typ)) > 0
		switch {
		case hasParsers && len(c.Formats) == 0:
			t.Errorf("%s: parsers registered but no formats reported", typ)
		case !hasParsers && strings.TrimSpace(c.Reason) == "":
			t.Errorf("%s: no parser and an empty reason", typ)
		case !hasParsers && len(strings.Fields(c.Reason)) < 6:
			t.Errorf("%s: the reason %q explains nothing", typ, c.Reason)
		}
	}
}

// TestNoParserEntriesAreCurrent fails on a no-parser entry for a type that has
// a parser after all, or that the configuration does not know.
func TestNoParserEntriesAreCurrent(t *testing.T) {
	known := map[string]bool{}
	for _, typ := range config.UpstreamTypes() {
		known[lockfiles.CanonicalType(typ)] = true
	}
	reg := lockfiles.DefaultRegistry()
	for _, c := range lockfiles.CoverageTable() {
		if !known[c.Type] {
			t.Errorf("coverage entry %q is not an upstream type the configuration accepts", c.Type)
		}
		if c.Reason != "" && len(reg.Parsers(c.Type)) > 0 {
			t.Errorf("%s has parsers and still a no-parser reason; remove the entry", c.Type)
		}
	}
	for _, typ := range reg.Types() {
		if !known[typ] {
			t.Errorf("parsers are registered for %q, which is not an upstream type", typ)
		}
	}
}

// TestAliasesMatchTheBackendCatalog keeps lockfiles' alias table in step with
// the scan-coverage catalog, which records each type's other names.
func TestAliasesMatchTheBackendCatalog(t *testing.T) {
	for _, e := range scancoverage.Catalog() {
		for _, alias := range e.Aliases {
			if got := lockfiles.CanonicalType(alias); got != e.Type {
				t.Errorf("CanonicalType(%q) = %q, want %q", alias, got, e.Type)
			}
		}
		if got := lockfiles.CanonicalType(e.Type); got != e.Type {
			t.Errorf("CanonicalType(%q) = %q", e.Type, got)
		}
	}
}

// TestTheTaskEcosystemsHaveParsers pins the formats this package must read.
func TestTheTaskEcosystemsHaveParsers(t *testing.T) {
	want := map[string][]string{
		"npm":      {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"},
		"pip":      {"requirements.txt", "Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock"},
		"cargo":    {"Cargo.lock"},
		"go":       {"go.mod", "go.sum"},
		"nuget":    {"packages.lock.json"},
		"maven":    {"gradle.lockfile", "pom.xml"},
		"rubygems": {"Gemfile.lock"},
		"composer": {"composer.lock"},
		"docker":   {"Dockerfile", "compose"},
	}
	for typ, formats := range want {
		c, _ := lockfiles.CoverageFor(typ)
		got := append([]string(nil), c.Formats...)
		sort.Strings(got)
		sort.Strings(formats)
		if strings.Join(got, ",") != strings.Join(formats, ",") {
			t.Errorf("%s formats = %v, want %v", typ, got, formats)
		}
	}
}

// TestDocsListEveryType keeps docs/lockfiles.md in step with the coverage
// table: every type with a parser or a no-parser entry has a row.
func TestDocsListEveryType(t *testing.T) {
	doc, err := os.ReadFile("../../docs/lockfiles.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range lockfiles.CoverageTable() {
		if !strings.Contains(string(doc), "| `"+c.Type+"` |") {
			t.Errorf("docs/lockfiles.md has no row for %q", c.Type)
		}
	}
}
