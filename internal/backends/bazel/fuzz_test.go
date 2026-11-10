//go:build fuzz
// +build fuzz

// Fuzz targets for the Bazel registry pull-through parsers (Task 30, Task 124).
//
// A malicious or compromised upstream registry controls the source.json body
// and (via the client) the request path. Both are parsed on the pull path before
// any content is cached or served, so the parsers must never panic, must not
// allocate without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/bazel/
package bazel

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/bazel_registry.json",
		"/modules/platforms/metadata.json",
		"/modules/rules_cc/0.0.9/MODULE.bazel",
		"/modules/rules_cc/0.0.9/source.json",
		"/modules/rules_cc/0.0.9/archive",
		"/modules/abseil-cpp/20230802.0/patches/fix.patch",
		"/modules/platforms/../../etc/passwd",
		"", "/", "////", "/modules", "/modules/Foo/metadata.json",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		res, ok := classify(path)
		if !ok {
			return
		}
		// Invariants for an accepted path: the predicates must be callable without
		// panicking, and a module-scoped resource must carry a valid name.
		_ = res.cacheable()
		_ = res.kindLabel()
		_ = res.coordinateName()
		if res.verifiableArchive() {
			if res.name == "" || res.version == "" {
				t.Fatalf("verifiable archive with incomplete coordinate: %q -> %+v", path, res)
			}
		}
		if res.kind != kindRegistry && res.name == "" {
			t.Fatalf("module-scoped resource with empty name: %q -> %+v", path, res)
		}
		if !isModuleName(res.name) && res.name != "" {
			t.Fatalf("accepted invalid module name %q from %q", res.name, path)
		}
	})
}

func FuzzParseSource(f *testing.F) {
	seeds := []string{
		`{"url":"https://example.com/a.tar.gz","integrity":"sha256-abc"}`,
		`{"urls":["https://a/x","ftp://b/x"],"integrity":"sha512-xyz"}`,
		`{"integrity":"sha256-abc"}`,
		`{`,
		`not json`,
		``,
		`{"url":123}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		info, err := parseSource(body)
		if err != nil {
			return
		}
		// primaryURL must only ever return an http(s) URL.
		if u, ok := info.primaryURL(); ok {
			if len(u) < 7 || (u[:7] != "http://" && (len(u) < 8 || u[:8] != "https://")) {
				t.Fatalf("primaryURL returned non-http url %q", u)
			}
		}
		// Rewriting must either fail cleanly or produce parseable JSON with the
		// archive URL substituted.
		if out, rerr := rewriteSourceJSON(body, "https://proxy/archive"); rerr == nil {
			var m map[string]any
			if jerr := json.Unmarshal(out, &m); jerr != nil {
				t.Fatalf("rewritten source.json is not valid JSON: %v", jerr)
			}
			if m["url"] != "https://proxy/archive" {
				t.Fatalf("rewritten url = %v", m["url"])
			}
		}
	})
}

func FuzzParseIntegrity(f *testing.F) {
	seeds := []string{
		"sha256-" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64)),
		"sha256-notbase64",
		"md5-abc",
		"garbage",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, ok := parseIntegrity(s)
		if !ok {
			return
		}
		switch e.algo {
		case "sha256", "sha384", "sha512":
		default:
			t.Fatalf("accepted unknown algo %q", e.algo)
		}
		if n := sriAlgoLen[e.algo]; len(e.raw) != n {
			t.Fatalf("algo %q raw len = %d, want %d", e.algo, len(e.raw), n)
		}
		// newHash must not panic and must match the declared size.
		if h := e.newHash(); h.Size() != len(e.raw) {
			t.Fatalf("hash size %d != raw len %d", h.Size(), len(e.raw))
		}
	})
}
