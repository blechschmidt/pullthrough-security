package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/generic"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/git"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/scancoverage"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The LLM-scan coverage catalog (internal/scancoverage) is what the published
// coverage table is generated from. These tests hold it to the code:
//
//   - every upstream type the configuration accepts has an entry — a backend
//     added without one fails here, so it cannot silently opt out of the scan;
//   - every example path is resolved against the real backend, built by the
//     same function the server uses, and must come out classified, refined and
//     cached exactly as the catalog (and so the documentation) says.

func TestEveryUpstreamTypeHasAnLLMScanCoverageEntry(t *testing.T) {
	if err := scancoverage.Validate(); err != nil {
		t.Fatalf("the coverage catalog is inconsistent: %v", err)
	}
	accepted := map[string]bool{}
	for _, typ := range config.UpstreamTypes() {
		accepted[typ] = true
		if _, ok := scancoverage.Lookup(typ); !ok {
			t.Errorf("upstream type %q has no LLM-scan coverage entry.\n"+
				"Add one to internal/scancoverage/catalog_data.go: the request paths that carry installable content, their format and serve path, and the documents next to them. "+
				"Classify those paths in the backend's Resolve (backends.Resolved.Artifact), then run `make llmscan-coverage-gen`.", typ)
		}
	}
	// And the other way round: the catalog describes nothing that does not exist.
	for _, e := range scancoverage.Catalog() {
		for _, name := range append([]string{e.Type}, e.Aliases...) {
			if !accepted[name] {
				t.Errorf("the coverage catalog has an entry for %q, which is not an upstream type the configuration accepts", name)
			}
		}
	}
}

// The scope key the catalog (and the documentation) gives a type is the one the
// gate actually scopes it by, under every name the type can be configured as —
// and with an empty include list, every one of them is scanned.
func TestLLMScanCoverageScopeKeysMatchTheGate(t *testing.T) {
	svc, err := llmpkgscan.NewService(llmpkgscan.Config{Enabled: true, Provider: &pkgscantest.Provider{}, Model: "m", Logger: llmTestLogger()})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer svc.Close()

	for _, e := range scancoverage.Catalog() {
		names := append([]string{e.Type}, e.Aliases...)
		switch e.Gate {
		case scancoverage.GatePackageScan:
			for _, name := range names {
				// The gateway reports an upstream's ecosystem as its configured type.
				if got := llmpkgscan.CanonEcosystem(name); got != e.Ecosystem {
					t.Errorf("%s: the gate scopes upstream type %q under %q, the catalog says %q", e.Type, name, got, e.Ecosystem)
				}
				if !svc.Applies(name) {
					t.Errorf("%s: upstream type %q is not scanned by default, but the catalog says the package scan examines it", e.Type, name)
				}
			}
		case scancoverage.GateCommitScan:
			for _, name := range names {
				if svc.Applies(name) {
					t.Errorf("%s: upstream type %q is in the package scan's default scope, but the catalog says the commit scan examines it", e.Type, name)
				}
			}
		}
	}
	// Git LFS objects are examined under a key of their own.
	if !svc.Applies(llmpkgscan.EcosystemGitLFS) {
		t.Errorf("%s is not in the package scan's default scope", llmpkgscan.EcosystemGitLFS)
	}
	// Every key in the gate's default scope is accounted for by the catalog.
	documented := map[string]bool{llmpkgscan.EcosystemGitLFS: true}
	for _, e := range scancoverage.Catalog() {
		if e.Ecosystem != "" {
			documented[e.Ecosystem] = true
		}
	}
	for _, eco := range llmpkgscan.DefaultEcosystems {
		if !documented[eco] {
			t.Errorf("ecosystem %q is scanned by default but no coverage entry describes it", eco)
		}
	}
}

// coverageUpstream is a stand-in upstream for backends whose Resolve consults
// one: it answers every request with an empty 404.
func coverageUpstream(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	return srv.URL
}

// coverageBackend builds the backend for a catalog entry exactly as the server
// does (buildBackend), from the settings and routes the entry states.
func coverageBackend(t *testing.T, e scancoverage.Entry, typ string) backends.Backend {
	t.Helper()
	cfg := config.Default()
	cfg.Server.PublicURL = "https://proxy.example"
	up := config.UpstreamConfig{Type: typ, URL: coverageUpstream(t), Settings: e.Settings}
	if len(e.Routes) > 0 {
		gc := &generic.BackendConfig{}
		for _, r := range e.Routes {
			gc.Routes = append(gc.Routes, generic.RouteConfig{Name: r.Name, Match: r.Match, Cacheable: r.Cacheable, Rewrite: r.Rewrite, Gates: r.Gates})
		}
		up.Generic = gc
	}
	b, err := buildBackend(&cfg, "up", up, upstream.NewWithHTTPClient(http.DefaultClient, "coverage-test/1"), upstream.Credentials{})
	if err != nil {
		t.Fatalf("buildBackend(%s): %v", typ, err)
	}
	return b
}

func TestLLMScanCoverageMatchesTheBackends(t *testing.T) {
	classOf := func(c backends.ArtifactClass) string { return c.String() }

	for _, e := range scancoverage.Catalog() {
		if e.Gate != scancoverage.GatePackageScan {
			// Git: served by its own handler, gated by the commit scan. That its
			// LFS objects reach the package scan is covered by the gateway's and
			// the Git backend's own tests.
			continue
		}
		for _, typ := range append([]string{e.Type}, e.Aliases...) {
			t.Run(typ, func(t *testing.T) {
				backend := coverageBackend(t, e, typ)
				for _, p := range e.Paths {
					rawPath, rawQuery, _ := strings.Cut(p.Example, "?")
					query, err := url.ParseQuery(rawQuery)
					if err != nil {
						t.Errorf("%s: example %q has an unparsable query", p.What, p.Example)
						continue
					}
					res, err := backend.Resolve(context.Background(), &backends.Request{
						Method: http.MethodGet, Path: rawPath, Query: query, Header: http.Header{},
					})
					if err != nil {
						if errors.Is(err, backends.ErrNotSupported) {
							t.Errorf("%s: the backend does not serve the example path %q", p.What, p.Example)
						} else {
							t.Errorf("%s: Resolve(%q): %v", p.What, p.Example, err)
						}
						continue
					}
					if got := classOf(res.Artifact.Class); got != p.Class {
						t.Errorf("%s: %q is classified %s by the backend, %s in the catalog", p.What, p.Example, got, p.Class)
					}
					if got := string(res.Artifact.Kind); got != p.Kind {
						t.Errorf("%s: %q has kind %q in the backend, %q in the catalog", p.What, p.Example, got, p.Kind)
					}
					wantCacheable := p.Serve == scancoverage.ServeCache
					if res.Cacheable != wantCacheable {
						t.Errorf("%s: %q cacheable = %v in the backend, but the catalog says it is served by %q", p.What, p.Example, res.Cacheable, p.Serve)
					}
					if p.Serve != scancoverage.ServeCache && p.Serve != scancoverage.ServeDirect {
						t.Errorf("%s: serve path %q is not one a package backend has", p.What, p.Serve)
					}
				}
			})
		}
	}
}

// The catalog must list at least one payload for every backend the package scan
// examines, and must say what happens to the documents served next to it:
// "metadata" is the one classification that lets bytes through on the strength
// of a path, so every entry either names the paths it gives that class, or —
// for a backend that deliberately gives it to none (Open VSX forwards whole
// trees that serve the extension under other names too) — lists what it leaves
// unclassified and says in a note that nothing is metadata.
func TestLLMScanCoverageListsAPayloadForEveryBackend(t *testing.T) {
	for _, e := range scancoverage.Catalog() {
		if e.Gate != scancoverage.GatePackageScan {
			continue
		}
		if len(e.Payloads()) == 0 {
			t.Errorf("%s lists no payload path", e.Type)
		}
		metadata, unclassified := 0, 0
		for _, p := range e.Paths {
			switch p.Class {
			case scancoverage.ClassMetadata:
				metadata++
			case scancoverage.ClassUnclassified:
				unclassified++
			}
		}
		if metadata > 0 {
			continue
		}
		if unclassified == 0 {
			t.Errorf("%s lists only payload paths: say which of its documents the scan leaves alone, or judges from their bytes", e.Type)
			continue
		}
		explained := false
		for _, note := range e.Notes {
			if strings.Contains(strings.ToLower(note), "nothing as metadata") {
				explained = true
			}
		}
		if !explained {
			t.Errorf("%s lists no metadata path. If the backend really classifies nothing as metadata, say so in a note (\"classifies nothing as metadata\") and why; otherwise list the documents it does classify", e.Type)
		}
	}
}

// The coverage record states that a Git clone or fetch passes no admission
// gate. That is a statement about the code, and this is where it is held to it:
// the Git backend owns its HTTP traffic (backends.HTTPHandler), and the gateway
// hands such a backend the request before any gate runs. If a fetch-time gate
// is ever added, this test and the record's Git entry change together.
func TestGitCoverageRecordMatchesHowGitIsServed(t *testing.T) {
	var gitBackend backends.Backend = (*git.Backend)(nil)
	if _, owns := gitBackend.(backends.HTTPHandler); !owns {
		t.Fatal("the Git backend no longer owns its HTTP traffic: it now passes through the gateway's gates, and the coverage record's Git entry (internal/scancoverage) must say which")
	}
	entry, ok := scancoverage.Lookup("git")
	if !ok {
		t.Fatal("no coverage entry for git")
	}
	if entry.Gate != scancoverage.GateCommitScan {
		t.Errorf("git is recorded as examined by %q", entry.Gate)
	}
	if !strings.Contains(strings.Join(entry.Notes, " "), "runs no admission gate") {
		t.Error("the Git entry does not say that Git traffic runs no admission gate")
	}
}
