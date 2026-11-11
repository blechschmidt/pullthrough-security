//go:build fuzz
// +build fuzz

// Fuzz targets for the package-manager pull-through parsers (Task 30, Task 4).
//
// These exercise the untrusted-input handling on the package-manager pull path:
// index-document URL rewriting (every ecosystem), Cargo config.json rewriting,
// NuGet gzip decoding (a decompression-bomb surface), PyPI filename →
// coordinate parsing, and the classification of a request path for the content
// gates. A malicious upstream registry controls the documents and a client the
// request path, so the parsers must never panic and must not allocate without
// bound.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzMaybeGunzip ./internal/backends/pkgmgr/
package pkgmgr

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// FuzzClassify fuzzes the per-ecosystem classifiers that tell the content gates
// what a request path addresses. The path is the client's to choose and a
// resource classified as metadata is served unexamined, so beyond never
// panicking, no classifier may call metadata a path that its ecosystem's payload
// grammar matches, or one written with anything but plain name characters.
func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/lodash", "/@babel/core", "/lodash/4.17.21", "/lodash/-/lodash-4.17.21.tgz", "/-/v1/search",
		"/download/@scope/pkg/1.0.0/abcdef",
		"/simple/", "/simple/requests/", "/pypi/requests/json", "/simple/requests/requests-2.31.0.tar.gz",
		"/integrity/requests/2.31.0/requests-2.31.0-py3-none-any.whl/provenance",
		"/files/https/files.pythonhosted.org/packages/ab/cd/requests-2.31.0-py3-none-any.whl",
		"/files/https/files.pythonhosted.org/packages/ab/cd/requests-2.31.0-py3-none-any.whl.metadata",
		"/files/https/files.pythonhosted.org/packages/evil-1.0.tar.gz;x=.metadata",
		"/config.json", "/1/a", "/2/ab", "/3/a/abc", "/se/rd/serde", "/api/v1/crates/serde",
		"/api/v1/crates/serde/1.0.193/download", "/api/v1/crates/serde/1.0.193/download/",
		"/golang.org/x/mod/@v/list", "/golang.org/x/mod/@latest", "/golang.org/x/mod/@v/v0.1.0.info",
		"/golang.org/x/mod/@v/v0.1.0.mod", "/golang.org/x/mod/@v/v0.1.0.zip",
		"/sumdb/sum.golang.org/supported", "/sumdb/sum.golang.org/lookup/rsc.io/quote@v1.5.2",
		"/sumdb/sum.golang.org/tile/8/1/x001/085.p/119", "/sumdb/sum.golang.org/../../m/@v/v1.0.0.zip",
		"/v3/index.json", "/v3-flatcontainer/newtonsoft.json/index.json",
		"/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec",
		"/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
		"/v3/registration5-semver1/newtonsoft.json/page/1.0.0/13.0.3.json",
		"/api/v2/package/Newtonsoft.Json", "/registration-semver2/Download/evil/1.0.0-rc.json",
		"/simple/../packages/x.tar.gz", "/a//b", `/a\b`, "/a;b/index.json", "/a%2f..", "", "/", "////",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	allowed := map[string]bool{"files.pythonhosted.org": true}
	f.Fuzz(func(t *testing.T, path string) {
		req := &backends.Request{Method: "GET", Path: path}
		lower := strings.ToLower(path)
		file := lower[strings.LastIndex(lower, "/")+1:]

		// What each ecosystem's own payload grammar says about the path.
		payloadShaped := map[string]bool{
			"npm":   strings.Contains(path, "/-/"),
			"pip":   hasAnySuffix(file, pipPayloadSuffixes),
			"cargo": strings.HasSuffix(strings.TrimRight(lower, "/"), "/download"),
			"go":    strings.HasSuffix(path, ".zip"),
			"nuget": strings.HasSuffix(lower, ".nupkg"),
		}
		for eco, a := range map[string]backends.Artifact{
			"npm":   npmClassify(req),
			"pip":   pipClassify(path, allowed),
			"cargo": cargoClassify(req),
			"go":    goClassify(req),
			"nuget": nugetClassify(req),
		} {
			switch a.Class {
			case backends.ArtifactPayload:
				if a.Kind != "" || strings.ContainsAny(a.Filename, `/\`) {
					t.Fatalf("%s: payload %q carries %+v", eco, path, a)
				}
				continue
			case backends.ArtifactUnclassified:
				if a != (backends.Artifact{}) {
					t.Fatalf("%s: unclassified %q carries %+v", eco, path, a)
				}
				continue
			}
			if a != backends.Metadata() {
				t.Fatalf("%s: metadata %q carries %+v", eco, path, a)
			}
			if payloadShaped[eco] {
				t.Fatalf("%s: payload-shaped path %q is classified as metadata", eco, path)
			}
			if strings.Contains(path, "//") || strings.Contains(path+"/", "/./") || strings.Contains(path+"/", "/../") {
				t.Fatalf("%s: path %q with an empty or dot segment is classified as metadata", eco, path)
			}
			for i := 0; i < len(path); i++ {
				if c := path[i]; c <= ' ' || c >= 0x7f || strings.IndexByte(`\;%?#:,=&$*'"()[]{}|<>^`+"`", c) >= 0 {
					t.Fatalf("%s: path %q with byte %q is classified as metadata", eco, path, c)
				}
			}
		}
	})
}

// FuzzApplyRules fuzzes the index-document prefix rewriter with both the body and
// the rule endpoints under fuzzer control.
func FuzzApplyRules(f *testing.F) {
	seeds := [][3]string{
		{`{"dl":"https://upstream.example/api"}`, "https://upstream.example", "https://proxy.local"},
		{`<a href="https://files.pythonhosted.org/x.whl">x</a>`, "https://files.pythonhosted.org", "https://proxy.local/pip"},
		{`{"urls":["https://registry.npmjs.org/-/x"]}`, "https://registry.npmjs.org", "https://proxy.local/npm"},
		{"", "", ""},
		{"abc", "a", "aaaa"}, // growth on each replace
		{"aaaa", "a", ""},    // shrink to empty
		{"https://x/https://x", "https://x", "p"},
	}
	for _, s := range seeds {
		f.Add([]byte(s[0]), s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, body []byte, from, to string) {
		// Bound the blow-up factor the fuzzer can request: a tiny "from" mapped to
		// a huge "to" is a legitimate concern in real code, but here we only assert
		// the function itself stays panic-free and terminates.
		if len(to) > 1024 {
			to = to[:1024]
		}
		rules := []rewriteRule{{from: from, to: to}}
		out := applyRules(append([]byte(nil), body...), rules)
		if from == "" || from == to {
			if !bytes.Equal(out, body) {
				t.Fatalf("no-op rule changed body")
			}
		}
	})
}

// FuzzRewriteCargoConfig fuzzes the Cargo registry config.json rewriter.
func FuzzRewriteCargoConfig(f *testing.F) {
	seeds := []string{
		`{"dl":"https://crates.io/api/v1/crates","api":"https://crates.io"}`,
		`{}`,
		`{"dl":42}`,
		`{"dl":{"nested":true}}`,
		`[]`,
		`null`,
		`not json`,
		`{"dl":"` + string(make([]byte, 1000)) + `"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s), "https://proxy.local/cargo/api/v1/crates")
	}
	f.Fuzz(func(t *testing.T, body []byte, proxyDL string) {
		out := rewriteCargoConfig(append([]byte(nil), body...), proxyDL)
		// If the input was a JSON object, the output must remain valid JSON whose
		// "dl" was set to proxyDL. Otherwise the original bytes pass through.
		var obj map[string]any
		if json.Unmarshal(body, &obj) == nil && obj != nil {
			var got map[string]any
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("rewrote a valid object into invalid JSON: %v", err)
			}
			// proxyDL is a proxy-controlled URL (always valid UTF-8) in production;
			// only then does it survive the JSON marshal/unmarshal round-trip
			// byte-for-byte (Go replaces invalid UTF-8 with U+FFFD on marshal).
			if utf8.ValidString(proxyDL) && got["dl"] != proxyDL {
				t.Fatalf("dl not rewritten: got %v want %q", got["dl"], proxyDL)
			}
		} else if !bytes.Equal(out, body) {
			t.Fatalf("non-object input was modified")
		}
	})
}

// FuzzMaybeGunzip fuzzes the NuGet gzip decoder. This is the decompression-bomb
// surface: maybeGunzip must reject (not buffer without bound) an over-large
// expansion and must never panic on a truncated/garbage gzip stream.
func FuzzMaybeGunzip(f *testing.F) {
	// A small legitimate gzip body.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(`{"versions":["1.0.0","1.0.1"]}`))
	zw.Close()
	f.Add(buf.Bytes())

	// Non-gzip payloads (must pass through unchanged).
	f.Add([]byte(`{"plain":"json"}`))
	f.Add([]byte(""))
	f.Add([]byte{0x1f}) // single magic byte
	// Gzip magic followed by garbage (header parses, stream is invalid).
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00})

	// A decompression bomb: ~1 MiB of zeros compresses to a few KiB and, with the
	// old unbounded ReadAll, would have expanded freely. The cap must reject it.
	var bomb bytes.Buffer
	bw := gzip.NewWriter(&bomb)
	bw.Write(make([]byte, 1<<20))
	bw.Close()
	f.Add(bomb.Bytes())

	f.Fuzz(func(t *testing.T, body []byte) {
		out, err := maybeGunzip(body)
		if err != nil {
			return // graceful failure is acceptable
		}
		if len(out) > maxGunzipBytes {
			t.Fatalf("decompressed output %d exceeds cap %d", len(out), maxGunzipBytes)
		}
		// Non-gzip input must be returned verbatim.
		if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
			if !bytes.Equal(out, body) {
				t.Fatalf("non-gzip body was altered")
			}
		}
	})
}

// FuzzPipNameVersion fuzzes the PyPI distribution-filename parser, which derives
// a package coordinate from an attacker-influenced filename.
func FuzzPipNameVersion(f *testing.F) {
	seeds := []string{
		"requests-2.31.0-py3-none-any.whl",
		"numpy-1.26.4-cp312-cp312-manylinux_2_17_x86_64.whl",
		"Flask-3.0.0.tar.gz",
		"some_pkg-1.0.zip",
		"pkg-1.0.tar.bz2",
		"a-b-c-1.0.0-py3-none-any.whl",
		"noextension",
		".whl",
		"-.whl",
		"-1.0.tar.gz",
		"pkg-.tar.gz",
		"....whl",
		"x" + string(make([]byte, 4096)) + "-1.0.whl",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, file string) {
		coord, ok := pipNameVersion(file)
		if ok {
			// A claimed-valid coordinate must carry a non-empty name and version.
			if coord.Name == "" {
				t.Fatalf("ok coordinate has empty name for %q", file)
			}
			if coord.Version == "" {
				t.Fatalf("ok coordinate has empty version for %q", file)
			}
		}
	})
}
