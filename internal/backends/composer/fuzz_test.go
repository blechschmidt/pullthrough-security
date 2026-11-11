//go:build fuzz
// +build fuzz

// Fuzz targets for the Composer pull-through parsers (Task 30, Task 45).
//
// A malicious or compromised Packagist mirror controls packages.json and the v2
// metadata documents (the source of the dist download URL and the verification
// shasum) and, via the client, the request path. All are parsed on the pull path
// before any content is cached or served, so the parsers must never panic, must
// not allocate without bound, and must fail closed on malformed input. The
// minified-delta expansion is a particular focus: a hostile document must not be
// able to drive unbounded growth or a panic through the "__unset" sentinel.
//
// The same documents are also rewritten before they are served, so that the URLs
// a client follows lead back to the proxy. The rewrite targets assert the
// property that makes that safe: whatever dist URL the rewrite emits must parse
// back into a dist request that resolves, against the untouched upstream
// document, to the entry the URL was written for — the rewrite and the lookup
// may never disagree about which archive a URL names.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzParseMetadata ./internal/backends/composer/
package composer

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/packages.json",
		"/p2/symfony/console.json",
		"/p2/symfony/console~dev.json",
		"/p/monolog/monolog.json",
		"/lists/all/summary.json",
		"/dist/symfony/console/3.0.0/abc123.zip",
		"/dist/symfony/console/dev-feature/x/abc123.zip",
		"/dist/symfony/console/dev-master/_.zip",
		"/dist/symfony/console/1.0.0/.zip",
		"/dist/symfony/console/1.0.0/_0123456789abcdef0123456789abcdef.tar",
		"/dist/symfony/console/abc123.zip",
		"/dist/../../etc/passwd.zip",
		"/dist/symfony/console/../1.0.0/abc.zip",
		"",
		"/",
		"////",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		res, ok := classify(path)
		if !ok {
			return
		}
		_ = res.cacheable()
		_ = res.kindLabel()
		_ = res.coordinateName()
		// The dist archive, and nothing else, is what the content gates examine as
		// a payload; no accepted path is left without a classification.
		a := res.artifact()
		if (a.Class == backends.ArtifactPayload) != res.verifiableArtifact() ||
			(a.Class != backends.ArtifactPayload && a != backends.Metadata()) {
			t.Fatalf("artifact of %q (%s) = %+v", path, res.kindLabel(), a)
		}
		if !res.verifiableArtifact() {
			if res.cacheable() {
				t.Fatalf("a non-dist resource is cacheable: %q", path)
			}
			return
		}
		// A dist is resolved to its package's metadata document, so it names its
		// archive itself — the same name for every spelling of the locator.
		if a != backends.PayloadNamed(res.reference+"."+res.ext) || strings.ContainsAny(a.Filename, `/\`) {
			t.Fatalf("dist %q is named %+v", path, a)
		}
		// A dist must carry the complete coordinate the admission gates need, and
		// every element must be inert enough to build URLs and cache keys from.
		if res.vendor == "" || res.pkg == "" || res.version == "" || res.reference == "" || res.ext == "" {
			t.Fatalf("dist with an incomplete locator: %q -> %+v", path, res)
		}
		if !validVersion(res.version) || !validReferenceToken(res.reference) || !validDistType(res.ext) {
			t.Fatalf("dist with an invalid locator element: %q -> %+v", path, res)
		}
		// The canonical key must itself be a dist path naming the same resource,
		// so every spelling of a dist shares one cache entry.
		again, ok := classify("/" + res.distKey())
		if !ok || again != res {
			t.Fatalf("dist key %q of %q does not classify back to itself: %+v vs %+v", res.distKey(), path, again, res)
		}
	})
}

func FuzzParseMetadata(f *testing.F) {
	seeds := []string{
		metadataFixture,
		minifiedFixture,
		inheritedDistFixture,
		`{"packages":{}}`,
		`{"packages":[]}`,
		`{"minified":"composer/2.0","packages":{"a/b":[{"version":"1.0.0"},{"version":"__unset"}]}}`,
		`{"minified":"composer/2.0","packages":{"a/b":[]}}`,
		`{"packages":{"a/b":{"1.0.0":{"version":"1.0.0","dist":{"type":"zip","url":"https://x.test/a.zip"}}}}}`,
		`{}`,
		`not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		md, err := ParseMetadata(data)
		if err != nil {
			return
		}
		for name, versions := range md.Packages {
			for _, v := range versions {
				// A version that carries a dist must be findable by its own version,
				// reference token and type (FindDist is how the backend recovers the
				// download URL and shasum for a dist request).
				if v.Dist.URL != "" && v.Version != "" {
					if _, found := md.FindDist(name, v.Version, referenceToken(v.Dist.Reference), v.Dist.Type); !found {
						t.Fatalf("version %q with reference %q not findable", v.Version, v.Dist.Reference)
					}
				}
				// A reported checksum must be a well-formed SHA-1 hex digest.
				if cs, ok := v.Checksum(); ok && len(cs.hex) != distShasumHexLen {
					t.Fatalf("checksum of wrong length: %q", cs.hex)
				}
			}
		}
	})
}

func FuzzParseRoot(f *testing.F) {
	seeds := []string{
		`{"metadata-url":"/p2/%package%.json"}`,
		`{"packages":{},"providers-url":"/p/%package%$%hash%.json"}`,
		`{}`,
		`not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseRoot(data)
	})
}

// fuzzBackend builds a backend that never touches the network. absolute selects
// between an absolute public base and the root-relative fallback.
func fuzzBackend(t *testing.T, absolute bool) *Backend {
	t.Helper()
	publicBase := ""
	if absolute {
		publicBase = "https://proxy.example.com/v1/packagist"
	}
	b, err := New(Options{
		Name:          "packagist",
		UpstreamURL:   "https://repo.example.test/acme",
		PublicBaseURL: publicBase,
		Client:        upstream.NewWithHTTPClient(http.DefaultClient, "fuzz/1"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func FuzzRewriteMetadata(f *testing.F) {
	seeds := []string{
		metadataFixture,
		minifiedFixture,
		inheritedDistFixture,
		`{"packages":{}}`,
		`{"packages":[]}`,
		`{"minified":"composer/2.0","packages":{"a/b":[{"version":"1.0.0","dist":{"type":"zip","url":"https://x.test/a.zip","reference":"r"}},{"version":"0.9.0"},{"dist":"__unset"},{"version":"__unset"}]}}`,
		`{"minified":"composer/2.0","packages":{"a/b":[{"version":"dev-a/../b","dist":{"type":"zip","url":"https://x.test/a.zip","reference":"r/x"}},{"version":"dev-ok"}]}}`,
		`{"packages":{"a/b":{"1.0.0":{"version":"1.0.0","dist":{"type":"zip","url":"https://x.test/a.zip"}},"1.0.0":{"version":"1.0.0","dist":{"type":"tar","url":"https://x.test/b.tar","reference":"q"}}}}}`,
		`{"packages":{"a/b":[{"version":"1.0.0","notification-url":"https://x.test/n","dist":{"type":"zip","url":"HTTPS://x.test/a.zip","reference":"r","mirrors":[{"url":"https://m.test/%package%","preferred":true}]}}]}}`,
		`{"packages":{"a/b":[{"version":"1.0.0","dist":{"type":"zip","url":"file:///etc/passwd","reference":"r"}}]}}`,
		`{"packages":{"A/B":[{"version":"1.0.0","dist":{"type":"zip","url":"https://x.test/a.zip"}}]}}`,
		`{}`,
		`not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s), true)
		f.Add([]byte(s), false)
	}
	f.Fuzz(func(t *testing.T, data []byte, absolute bool) {
		b := fuzzBackend(t, absolute)
		out, err := b.rewriteMetadata(data)
		if err != nil {
			return
		}
		// The output must itself be a metadata document, and parse to the same
		// packages and versions as the input: a rewrite adds and removes nothing.
		before, err := ParseMetadata(data)
		if err != nil {
			t.Fatalf("rewrote a document ParseMetadata rejects: %v", err)
		}
		after, err := ParseMetadata(out)
		if err != nil {
			t.Fatalf("rewrite produced an unparsable document: %v\n%s", err, out)
		}
		if len(before.Packages) != len(after.Packages) {
			t.Fatalf("package count changed: %d -> %d", len(before.Packages), len(after.Packages))
		}
		mount, err := url.Parse(b.publicBase)
		if err != nil {
			t.Fatalf("public base: %v", err)
		}
		for name, versions := range after.Packages {
			orig := before.Packages[name]
			if len(orig) != len(versions) {
				t.Fatalf("%s: version count changed: %d -> %d", name, len(orig), len(versions))
			}
			for i, v := range versions {
				if v.Version != orig[i].Version {
					t.Fatalf("%s[%d]: version changed: %q -> %q", name, i, orig[i].Version, v.Version)
				}
				if v.Dist.Reference != orig[i].Dist.Reference || v.Dist.Type != orig[i].Dist.Type || v.Dist.Shasum != orig[i].Dist.Shasum {
					t.Fatalf("%s[%d]: dist changed beyond its URL: %+v -> %+v", name, i, orig[i].Dist, v.Dist)
				}
				if v.Dist.URL == orig[i].Dist.URL {
					// Left as listed. That is only acceptable for a dist the proxy
					// cannot route: any routable http(s) dist must have been rewritten.
					vendor, pkg, nameOK := splitPackageName(name)
					if !nameOK || v.Dist.URL == "" {
						continue
					}
					if want, routable := b.distURL(vendor, pkg, v.Version, v.Dist); routable && want != v.Dist.URL {
						t.Fatalf("%s[%d]: routable dist %q was not rewritten (want %q)", name, i, v.Dist.URL, want)
					}
					continue
				}
				// Rewritten: the URL must sit under the public base and name a dist
				// request for exactly this package and version...
				if !strings.HasPrefix(v.Dist.URL, b.publicBase+"/dist/") {
					t.Fatalf("%s[%d]: dist URL changed to something off the mount: %q", name, i, v.Dist.URL)
				}
				u, err := url.Parse(v.Dist.URL)
				if err != nil {
					t.Fatalf("%s[%d]: rewritten URL %q does not parse: %v", name, i, v.Dist.URL, err)
				}
				if u.RawQuery != "" || u.Fragment != "" {
					t.Fatalf("%s[%d]: rewritten URL %q leaks into query/fragment", name, i, v.Dist.URL)
				}
				res, ok := classify(strings.TrimPrefix(u.Path, mount.Path))
				if !ok || res.kind != kindDist {
					t.Fatalf("%s[%d]: rewritten URL %q is not a routable dist request", name, i, v.Dist.URL)
				}
				if res.coordinateName() != name || res.version != v.Version {
					t.Fatalf("%s[%d]: URL %q names %s@%s, the client sees %s@%s",
						name, i, v.Dist.URL, res.coordinateName(), res.version, name, v.Version)
				}
				// ...and resolve, against the upstream document, to an entry that
				// lists the very URL this version had.
				entry, found := before.FindDist(name, res.version, res.reference, res.ext)
				if !found {
					t.Fatalf("%s[%d]: rewritten URL %q does not resolve upstream", name, i, v.Dist.URL)
				}
				if entry.Dist.Reference != orig[i].Dist.Reference || entry.Dist.Type != orig[i].Dist.Type {
					t.Fatalf("%s[%d]: URL %q resolves to another dist: %+v, want %+v", name, i, v.Dist.URL, entry.Dist, orig[i].Dist)
				}
			}
		}
	})
}

func FuzzRewriteRoot(f *testing.F) {
	seeds := []string{
		packagistRootFixture,
		`{"metadata-url":"/p2/%package%.json"}`,
		`{"packages":{},"providers-url":"/p/%package%$%hash%.json","providers-lazy-url":"/p/%package%.json"}`,
		`{"metadata-url":42,"notify":"/downloads/%package%","mirrors":[{"dist-url":"https://m.test/%package%/%reference%.%type%","preferred":true}]}`,
		`{"metadata-url":"/acme/p2/%package%.json","available-packages":["a/b"],"security-advisories":{"metadata":true,"api-url":"/acme/api"}}`,
		`{"security-advisories":[],"filter":"x"}`,
		`{"filter":{"metadata":true,"summary-url":"https://repo.example.test/acme/lists/all/summary.json","api-url":"https://repo.example.test/acme/filter"}}`,
		`{"filter":{"summary-url":"//evil.test/acme/lists/../x.json"}}`,
		`{}`,
		`not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s), true)
		f.Add([]byte(s), false)
	}
	f.Fuzz(func(t *testing.T, data []byte, absolute bool) {
		b := fuzzBackend(t, absolute)
		out, err := b.rewriteRoot(data)
		if err != nil {
			return
		}
		var root map[string]json.RawMessage
		if err := json.Unmarshal(out, &root); err != nil || root == nil {
			t.Fatalf("rewrite produced a non-object root: %v\n%s", err, out)
		}
		// Endpoints the backend does not front are never advertised.
		for _, key := range []string{"notify-batch", "notify", "search", "list", "providers-api", "metadata-changes-url"} {
			if _, present := root[key]; present {
				t.Fatalf("%s survived the rewrite:\n%s", key, out)
			}
		}
		// A package lookup, when advertised, points at this backend's mount.
		for key, template := range map[string]string{
			"metadata-url":       metadataURLTemplate,
			"providers-url":      providersURLTemplate,
			"providers-lazy-url": providersLazyURLTemplate,
		} {
			raw, present := root[key]
			if !present {
				continue
			}
			if s, ok := exactString(raw); !ok || s != b.publicBase+template {
				t.Fatalf("%s = %s, want %q", key, raw, b.publicBase+template)
			}
		}
		// Dist mirrors: only this backend's own endpoint, and only in the fallback.
		if raw, present := root["mirrors"]; present {
			var mirrors []map[string]any
			if absolute || json.Unmarshal(raw, &mirrors) != nil || len(mirrors) != 1 ||
				mirrors[0]["dist-url"] != b.publicBase+distMirrorTemplate || mirrors[0]["preferred"] != true {
				t.Fatalf("unexpected mirrors: %s", raw)
			}
		} else if !absolute {
			t.Fatalf("the fallback root must advertise the dist mirror:\n%s", out)
		}
		// Advisory and filter configuration never keep an API endpoint, and a
		// surviving summary URL is one the backend routes.
		for _, key := range []string{"security-advisories", "filter"} {
			raw, present := root[key]
			if !present {
				continue
			}
			var config map[string]json.RawMessage
			if err := json.Unmarshal(raw, &config); err != nil || config == nil {
				t.Fatalf("%s is not an object after the rewrite: %s", key, raw)
			}
			if _, present := config["api-url"]; present {
				t.Fatalf("%s.api-url survived the rewrite: %s", key, raw)
			}
			if key == "security-advisories" && !isJSONTrue(config["metadata"]) {
				t.Fatalf("security-advisories kept without in-metadata advisories: %s", raw)
			}
			if summary, present := config["summary-url"]; present {
				s, ok := exactString(summary)
				if !ok || !strings.HasPrefix(s, b.publicBase+"/") {
					t.Fatalf("filter.summary-url is off the mount: %s", summary)
				}
				u, err := url.Parse(s)
				if err != nil {
					t.Fatalf("filter.summary-url %q does not parse: %v", s, err)
				}
				mount, _ := url.Parse(b.publicBase)
				if res, ok := classify(strings.TrimPrefix(u.Path, mount.Path)); !ok || res.kind != kindFilterList {
					t.Fatalf("filter.summary-url %q is not routable", s)
				}
			}
		}
	})
}
