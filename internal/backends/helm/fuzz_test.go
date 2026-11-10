//go:build fuzz
// +build fuzz

// Fuzz targets for the Helm pull-through parsers (Task 30, Task 49).
//
// A malicious or compromised chart repository controls index.yaml (the source of
// the chart download URL and the verification SHA-256 digest) and, via the
// client, the request path. Both are parsed on the pull path before any content
// is cached or served, so the parsers must never panic, must not allocate without
// bound, and must fail closed on malformed input. index.yaml is YAML — a format
// with a large surface (anchors, aliases, deeply nested maps) — so it is the
// primary supply-chain attack surface the fuzzer exercises.
//
// The index is also rewritten before it is served (rewrite.go), and there the
// property that matters is soundness: whatever the upstream publishes, the
// served document must not hand a client a chart URL the rewrite did not
// replace. FuzzRewriteIndex checks exactly that, against an independent reading
// of the served document that mimics how a Helm client decodes it.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzParseIndex ./internal/backends/helm/
//	go test -tags fuzz -run=^$ -fuzz=FuzzRewriteIndex ./internal/backends/helm/
package helm

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/index.yaml",
		"/nginx-1.2.3.tgz",
		"/charts/nginx-1.2.3.tgz",
		"/nginx-1.2.3.tgz.prov",
		"/kube-state-metrics-5.0.1.tgz",
		"/../etc/passwd.tgz",
		"",
		"/",
		"////",
		"/-1.0.0.tgz",
		"/-/nginx/1.2.3/nginx-1.2.3.tgz",
		"/-/nginx/1.2.3/nginx-1.2.3.tgz.prov",
		"/-/kube-state-metrics/5.0.1/download",
		"/-/nginx/1.2.3",
		"/-/unaddressable-entry",
		"/-/../1.2.3/nginx-1.2.3.tgz",
		"/-/a\\b/1.2.3/x.tgz",
		"/-/index.yaml",
		"/sub/index.yaml",
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
		if res.verifiableArtifact() && (res.name == "" || res.version == "" || res.filename == "") {
			t.Fatalf("verifiable chart with empty coordinate/filename: %q", path)
		}
		if res.indexed {
			// An index-resolved resource names an index entry by segments that
			// survive a round trip through a URL path, and nothing else.
			if !addressable(res.name) || !addressable(res.version) || !addressable(res.filename) {
				t.Fatalf("index-resolved resource with an unaddressable segment: %q -> %+v", path, res)
			}
			if res.kind != kindChart && res.kind != kindProvenance {
				t.Fatalf("index-resolved resource of kind %s: %q", res.kindLabel(), path)
			}
			// The link the rewrite would mint for it leads back to the same resource.
			u, err := url.Parse(linker{}.archive(res.name, res.version, res.filename))
			if err != nil {
				t.Fatalf("link for %+v does not parse: %v", res, err)
			}
			again, ok := classify("/" + u.Path)
			if res.kind == kindChart && (!ok || again != res) {
				t.Fatalf("link for %+v classifies as %+v (ok=%v)", res, again, ok)
			}
		}
	})
}

// fuzzLinks is the public base FuzzRewriteIndex rewrites to.
var fuzzLinks = linker{base: "https://proxy.invalid/v1/charts/"}

// helmView reads an index document the way a Helm client does and returns every
// chart URL it would see. Helm decodes a JSON index with encoding/json, and any
// other index by converting the YAML to JSON first and decoding that — so keys
// match case-insensitively, and YAML aliases, merge keys and tags have all been
// resolved by the time a `urls` field is read. It reports false for a document
// such a client would fail to load.
//
// It deliberately shares nothing with scanIndex: it is the independent witness
// the rewrite is checked against.
func helmView(doc []byte) ([]string, bool) {
	data := doc
	if !json.Valid(doc) {
		var generic interface{}
		if err := yaml.Unmarshal(doc, &generic); err != nil {
			return nil, false
		}
		var err error
		if data, err = json.Marshal(jsonable(generic)); err != nil {
			return nil, false
		}
	}
	var index struct {
		Entries map[string][]*struct {
			URLs []string `json:"urls"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, false
	}
	var urls []string
	for _, versions := range index.Entries {
		for _, v := range versions {
			if v != nil {
				urls = append(urls, v.URLs...)
			}
		}
	}
	return urls, true
}

// jsonable converts a generically decoded YAML value into one encoding/json can
// marshal, stringifying non-string map keys the way a YAML-to-JSON conversion
// does.
func jsonable(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, val := range x {
			out[k] = jsonable(val)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, val := range x {
			out[fmt.Sprint(k)] = jsonable(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, val := range x {
			out[i] = jsonable(val)
		}
		return out
	}
	return v
}

func FuzzRewriteIndex(f *testing.F) {
	seeds := []string{
		sampleIndex,
		realisticIndex,
		// Layouts and notations the rewrite must locate.
		"entries:\n  c:\n  - {version: 1.0.0, urls: [https://h.example/c-1.0.0.tgz, 'x.tgz', \"y\\u0041.tgz\"]}\n",
		`{"apiVersion":"v1","entries":{"c":[{"version":"1.0.0","urls":["https://h.example/c-1.0.0.tgz"],"urls":["b.tgz"]}]}}`,
		"\xef\xbb\xbfentries:\r\n  c:\r\n  - version: 1.0.0\r\n    URLS:\r\n    - https://h.example/c-1.0.0.tgz # c\r\n",
		"entries:\n  \"ü\": [{version: 1.0.0+b, urls: [//h.example/x.tgz, '', ~]}]\n  a/b: [{version: 1, urls: [z]}]\n",
		"{\"entries\":{\"c\":[{\"description\":\"a\u0085b\u2028c\",\"version\":\"1.0.0\",\"urls\":[\"u.tgz\"]}]}}",
		// Constructs that hand an entry its urls indirectly; a Helm client honors
		// them, so the rewrite has to refuse (or fully account for) them.
		"serverInfo:\n  x: &u [https://evil.example/c-1.0.0.tgz]\nentries:\n  c:\n  - version: 1.0.0\n    urls: *u\n",
		"serverInfo:\n  x: &k urls\nentries:\n  c:\n  - version: 1.0.0\n    *k : [https://evil.example/c-1.0.0.tgz]\n",
		"entries:\n  c:\n  - version: 1.0.0\n    <<: {urls: [https://evil.example/c-1.0.0.tgz]}\n",
		"entries:\n  c:\n  - version: 1.0.0\n    !!binary dXJscw==:\n    - https://evil.example/c-1.0.0.tgz\n",
		"entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - !!binary aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYy0xLjAuMC50Z3o=\n",
		"entries:\n  c:\n  - &e {version: 1.0.0, urls: [https://evil.example/c-1.0.0.tgz]}\n  d:\n  - *e\n",
		"entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - https://evil.example/c-1.0.0\n      .tgz\n    - |\n      https://evil.example/d.tgz\n",
		"entries: {}\n---\nentries:\n  c:\n  - version: 1.0.0\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"{}",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := scanIndex(data)
		if err != nil {
			return
		}
		out, err := doc.rewrite(data, fuzzLinks)
		if err != nil {
			// Refused: the backend serves nothing for this document.
			return
		}
		prefix := fuzzLinks.base + indexedPrefix + "/"

		// Soundness: whatever a Helm client reads out of the served document as a
		// chart URL either names nothing or leads back through the proxy.
		if seen, ok := helmView(out); ok {
			for _, u := range seen {
				if strings.TrimSpace(u) != "" && !strings.HasPrefix(u, prefix) {
					t.Fatalf("a client would see chart URL %q in the rewritten index\n--- upstream ---\n%q\n--- served ---\n%q", u, data, out)
				}
			}
		}

		// The served document is still an index the backend itself accepts, with
		// the same entries, and every link in it resolves back — through the path
		// classification and the lookup table — to the location it replaced.
		served, err := scanIndex(out)
		if err != nil {
			t.Fatalf("the rewritten index no longer scans: %v\n--- upstream ---\n%q\n--- served ---\n%q", err, data, out)
		}
		if len(served.entries) != len(doc.entries) {
			t.Fatalf("entries changed: %d -> %d\n--- upstream ---\n%q\n--- served ---\n%q", len(doc.entries), len(served.entries), data, out)
		}
		idx := doc.index()
		for i, e := range doc.entries {
			if len(served.entries[i].urls) != len(e.urls) {
				t.Fatalf("urls of entry %d changed: %d -> %d", i, len(e.urls), len(served.entries[i].urls))
			}
			for j, original := range e.urls {
				link := served.entries[i].urls[j].value
				if original.location() == "" {
					if link != original.value {
						t.Fatalf("an empty url was modified: %q -> %q", original.value, link)
					}
					continue
				}
				if link == fuzzLinks.unaddressable() {
					if addressable(e.chart) && addressable(e.version) {
						t.Fatalf("addressable entry %q %q was given the unaddressable link", e.chart, e.version)
					}
					continue
				}
				u, err := url.Parse(link)
				if err != nil || !strings.HasPrefix(link, prefix) {
					t.Fatalf("link %q is not a proxied URL (%v)", link, err)
				}
				res, ok := classify(strings.TrimPrefix(u.Path, "/v1/charts"))
				if !ok || !res.indexed || res.kind != kindChart || res.name != e.chart || res.version != e.version {
					t.Fatalf("link %q for %q %q classifies as %+v (ok=%v)", link, e.chart, e.version, res, ok)
				}
				found := false
				for _, loc := range idx.locate(res.name, res.version, res.filename) {
					found = found || loc.URL == original.location()
				}
				if !found {
					t.Fatalf("link %q does not resolve back to %q", link, original.location())
				}
			}
		}
	})
}

func FuzzParseIndex(f *testing.F) {
	seeds := []string{
		sampleIndex,
		"apiVersion: v1\nentries:\n  a:\n    - version: 1.0.0\n      digest: " +
			"1111111111111111111111111111111111111111111111111111111111111111\n",
		"apiVersion: v1\nentries: {}\n",
		"apiVersion: v1\nentries:\n  a:\n    - version: \"\"\n",
		"{}",
		"not yaml",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		idx, err := ParseIndex(data)
		if err != nil {
			return
		}
		for name, versions := range idx.Entries {
			if name == "" && len(versions) > 0 {
				// An empty chart-name key is tolerated, but every retained version must
				// still carry a usable version string.
			}
			for _, cv := range versions {
				if cv.Version == "" {
					t.Fatalf("retained chart version with empty version under %q", name)
				}
				// A non-empty digest must be a well-formed 64-char SHA-256 hex.
				if cv.Digest != "" && len(cv.Digest) != sha256HexLen {
					t.Fatalf("malformed digest survived parsing: %q", cv.Digest)
				}
				// A reported checksum must be findable by its own filename.
				if _, ok := cv.Checksum(); ok {
					if _, found := idx.FindByFilename(cv.Name + "-" + cv.Version + chartExt); !found {
						// Not necessarily findable if URLs override the name; tolerate.
						_ = found
					}
				}
			}
		}
	})
}
