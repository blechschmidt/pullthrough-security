package generic

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// classRoutes is a route set with one route of every kind the classification
// distinguishes. Routes are matched in order, so each path below names its route
// by its first segment.
var classRoutes = []RouteConfig{
	{Name: "alias", Match: `^/alias/.+$`, Cacheable: true, Gates: []string{"llmPackageScan"}},
	{Name: "canonical", Match: `^/canonical/.+$`, Cacheable: true, Gates: []string{"llmpkgscan"}},
	{Name: "both", Match: `^/both/.+$`, Cacheable: true, Gates: []string{"llmPackageScan", "llmpkgscan", "llmPackageScan"}},
	{Name: "mixed", Match: `^/mixed/.+$`, Cacheable: true, Gates: []string{"contentscan", "llmPackageScan", "avscan"}},
	{Name: "live-payload", Match: `^/live/.+$`, Gates: []string{"llmPackageScan"}},
	{Name: "rewrite-payload", Match: `^/recipes/.+$`, Rewrite: true, Gates: []string{"llmpkgscan"}},
	{Name: "index", Match: `^/index/.*$`, Rewrite: true},
	{Name: "index-gated", Match: `^/listing/.*$`, Rewrite: true, Gates: []string{"contentscan"}},
	{Name: "plain", Match: `^/pkg/.+$`, Cacheable: true},
	{Name: "plain-gated", Match: `^/scanned/.+$`, Cacheable: true, Gates: []string{"contentscan", "avscan"}},
	{Name: "live", Match: `^/misc/.+$`},
}

// TestResolveArtifactClass pins what Resolve tells the content gates about a
// declared route. A route that lists the LLM package-content scan gate, under
// either spelling, serves payloads; otherwise a rewrite route serves metadata;
// any other route makes no statement. The gate list is recorded in canonical
// form whatever the route's spelling.
func TestResolveArtifactClass(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	b := newTestBackend(t, m, BackendConfig{Routes: classRoutes}, &Metrics{})

	cases := []struct {
		name      string
		path      string
		route     string
		class     backends.ArtifactClass
		gates     string // the persisted MetaContentGates value; "" when absent
		cacheable bool
	}{
		{"gate listed by its configuration key", "/alias/foo-1.0.tar.gz", "alias", backends.ArtifactPayload, "llmpkgscan", true},
		{"gate listed by its identifier", "/canonical/foo-1.0.tar.gz", "canonical", backends.ArtifactPayload, "llmpkgscan", true},
		{"both spellings, repeated", "/both/foo-1.0.tar.gz", "both", backends.ArtifactPayload, "llmpkgscan", true},
		{"alias among other gates keeps its position", "/mixed/foo-1.0.tar.gz", "mixed", backends.ArtifactPayload, "contentscan,llmpkgscan,avscan", true},
		{"payload that is not an archive", "/alias/install.sh", "alias", backends.ArtifactPayload, "llmpkgscan", true},
		{"payload on a route that is not cacheable", "/live/build.gradle", "live-payload", backends.ArtifactPayload, "llmpkgscan", false},
		{"payload on a rewrite route", "/recipes/foo.rb", "rewrite-payload", backends.ArtifactPayload, "llmpkgscan", false},

		{"rewrite route", "/index/foo.json", "index", backends.ArtifactMetadata, "", false},
		{"rewrite route with another gate", "/listing/foo.json", "index-gated", backends.ArtifactMetadata, "contentscan", false},

		{"cacheable route", "/pkg/foo-1.0.tar.gz", "plain", backends.ArtifactUnclassified, "", true},
		{"cacheable route with other gates", "/scanned/foo-1.0.tar.gz", "plain-gated", backends.ArtifactUnclassified, "contentscan,avscan", true},
		{"route that declares nothing", "/misc/whatever", "live", backends.ArtifactUnclassified, "", false},

		// An upstream resolves a dot segment before it serves the request, so the
		// response to these is not the document the rewrite route was declared for.
		{"rewrite route, parent segment", "/index/../pkg/foo-1.0.tar.gz", "index", backends.ArtifactUnclassified, "", false},
		{"rewrite route, current segment", "/index/./foo.json", "index", backends.ArtifactUnclassified, "", false},
		{"rewrite route, parent segment with a path parameter", "/index/..;x=y/pkg/foo-1.0.tar.gz", "index", backends.ArtifactUnclassified, "", false},
		{"rewrite route, trailing parent segment", "/index/foo/..", "index", backends.ArtifactUnclassified, "", false},
		// A dot segment never makes a declared payload anything less.
		{"payload route, parent segment", "/alias/../index/foo.json", "alias", backends.ArtifactPayload, "llmpkgscan", true},
		// Dots inside a name are not dot segments.
		{"rewrite route, dotted file names", "/index/..foo/.hidden/a..b.json", "index", backends.ArtifactMetadata, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolved, err := b.Resolve(context.Background(), &backends.Request{
				Method: http.MethodGet, Path: tc.path, Query: url.Values{},
			})
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.path, err)
			}
			if got := resolved.Metadata[MetaRoute]; got != tc.route {
				t.Fatalf("Resolve(%q) matched route %q, want %q", tc.path, got, tc.route)
			}
			got := resolved.Artifact
			if got.Class != tc.class {
				t.Errorf("Resolve(%q) class = %s, want %s", tc.path, got.Class, tc.class)
			}
			// A route the operator put under the gate may serve an archive or a
			// single file; nothing else is refined.
			wantKind := backends.ArtifactKind("")
			if got.Class == backends.ArtifactPayload {
				wantKind = backends.KindFile
			}
			if got.Kind != wantKind || got.Filename != "" {
				t.Errorf("Resolve(%q) artifact = %+v, want no kind and no filename", tc.path, got)
			}
			gates, present := resolved.Metadata[MetaContentGates]
			if gates != tc.gates || present != (tc.gates != "") {
				t.Errorf("Resolve(%q) %s = %q (present=%v), want %q", tc.path, MetaContentGates, gates, present, tc.gates)
			}
			if resolved.Cacheable != tc.cacheable {
				t.Errorf("Resolve(%q) cacheable = %v, want %v", tc.path, resolved.Cacheable, tc.cacheable)
			}
		})
	}
}

// TestGateAliasValidation covers the configuration side of the alias: Validate
// accepts both spellings of the LLM package-content scan gate, still rejects
// anything that is not a gate, and KnownGates keeps listing canonical
// identifiers only.
func TestGateAliasValidation(t *testing.T) {
	route := func(gates ...string) *BackendConfig {
		return &BackendConfig{Routes: []RouteConfig{{Match: "^/x$", Gates: gates}}}
	}

	for _, gates := range [][]string{
		{"llmPackageScan"},
		{"llmpkgscan"},
		{"llmPackageScan", "llmpkgscan"},
		{"contentscan", "llmPackageScan", "avscan"},
	} {
		if err := route(gates...).Validate("mysource"); err != nil {
			t.Errorf("Validate rejected gates %q: %v", gates, err)
		}
	}

	// The alias is one exact spelling, not a loosening of the check.
	for _, gate := range []string{
		"bogus", "", "llmpackagescan", "LLMPackageScan", "llmPackageScan ", "llm-package-scan", "llmpkgscan,avscan",
	} {
		err := route("contentscan", gate).Validate("mysource")
		if err == nil {
			t.Errorf("Validate accepted unknown gate %q", gate)
			continue
		}
		if !strings.Contains(err.Error(), "unknown content gate") {
			t.Errorf("Validate(%q) error = %q, want an unknown-content-gate error", gate, err)
		}
		// The message lists the gates by their canonical identifiers.
		_, knownList, found := strings.Cut(err.Error(), "(known: ")
		if !found || !strings.Contains(knownList, "llmpkgscan") || strings.Contains(knownList, "llmPackageScan") {
			t.Errorf("Validate(%q) error = %q, want it to list the canonical identifiers", gate, err)
		}
	}

	known := KnownGates()
	if !slices.IsSorted(known) {
		t.Errorf("KnownGates() = %q, want it sorted", known)
	}
	if !slices.Contains(known, "llmpkgscan") {
		t.Errorf("KnownGates() = %q, want it to list llmpkgscan", known)
	}
	if len(known) != len(knownGates) {
		t.Errorf("KnownGates() has %d entries, want the %d canonical identifiers", len(known), len(knownGates))
	}
	for alias, canonical := range gateAliases {
		if slices.Contains(known, alias) {
			t.Errorf("KnownGates() lists the alias %q; it must list canonical identifiers only", alias)
		}
		if !knownGates[canonical] {
			t.Errorf("alias %q names %q, which is not a known gate", alias, canonical)
		}
		if knownGates[alias] {
			t.Errorf("%q is both an alias and a canonical identifier", alias)
		}
	}
	if !knownGates[gateLLMPackageScan] {
		t.Errorf("%q is not a known gate", gateLLMPackageScan)
	}
	if got, ok := canonicalGate("llmPackageScan"); !ok || got != gateLLMPackageScan {
		t.Errorf("canonicalGate(llmPackageScan) = %q, %v; want %q", got, ok, gateLLMPackageScan)
	}
}

func TestCanonicalGates(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{nil, nil},
		{[]string{}, nil},
		{[]string{"contentscan"}, []string{"contentscan"}},
		{[]string{"llmPackageScan"}, []string{"llmpkgscan"}},
		{[]string{"llmpkgscan", "llmPackageScan"}, []string{"llmpkgscan"}},
		{[]string{"llmPackageScan", "avscan", "llmpkgscan"}, []string{"llmpkgscan", "avscan"}},
		{[]string{"avscan", "contentscan", "avscan"}, []string{"avscan", "contentscan"}},
		// Validate refuses an unknown name before a route is compiled; if one gets
		// here anyway it is not recorded as a gate.
		{[]string{"avscan", "bogus"}, []string{"avscan"}},
	}
	for _, tc := range cases {
		if got := canonicalGates(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("canonicalGates(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// The route's own list is left as the operator wrote it.
	in := []string{"llmPackageScan", "llmpkgscan"}
	_ = canonicalGates(in)
	if !slices.Equal(in, []string{"llmPackageScan", "llmpkgscan"}) {
		t.Errorf("canonicalGates modified its argument: %q", in)
	}
}
