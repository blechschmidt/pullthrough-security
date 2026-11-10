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
	"net/url"
	"strings"
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
		// The archive endpoint with the upstream file name appended.
		"/modules/platforms/0.0.10/archive/platforms-0.0.10.tar.gz",
		"/modules/abc/0.0.0-20250408-yosyshq/archive/e55d316cc9a7f72a84a76eda555aa6ec083c9d0d.zip",
		"/modules/eigen/3.4.1/archive/download.tar.gz",
		"/modules/foo/1.0/archive/..",
		"/modules/foo/1.0/archive/a/b.tar.gz",
		"/modules/foo/1.0/archive/a%2fb.tar.gz",
		"/modules/foo/1.0/archive/../source.json",
		// Overlay files.
		"/modules/abc/0.0.0-20250408-yosyshq/overlay/BUILD.bazel",
		"/modules/foo/1.0/overlay/src/lib/BUILD.bazel",
		"/modules/foo/1.0/overlay/packages/@scope/pkg/defs.bzl",
		"/modules/foo/1.0/overlay/../source.json",
		"/modules/foo/1.0/overlay/a/../../../x",
		"/modules/foo/1.0/overlay",
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
		// Whatever is cached carries the full coordinate the admission gates need.
		if res.cacheable() && (res.name == "" || res.version == "" || !isModuleVersion(res.version)) {
			t.Fatalf("cacheable resource without a full coordinate: %q -> %+v", path, res)
		}
		switch res.kind {
		case kindArchive:
			// The trailing label is "archive" (bare endpoint) or a plain file name.
			if res.filename != archiveEndpoint && !isArchiveFileName(res.filename) {
				t.Fatalf("archive endpoint accepted file name %q from %q", res.filename, path)
			}
			if strings.ContainsAny(res.filename, "/\\%?#") {
				t.Fatalf("archive file name %q carries a path or URL metacharacter (from %q)", res.filename, path)
			}
		case kindOverlay:
			// A relative path that cannot leave the overlay directory.
			segs := strings.Split(res.filename, "/")
			if len(segs) == 0 || len(segs) > maxOverlayDepth || !isOverlayPath(segs) {
				t.Fatalf("overlay accepted path %q from %q", res.filename, path)
			}
			for _, s := range segs {
				if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "\\%?# ") {
					t.Fatalf("overlay path %q has an unsafe segment %q (from %q)", res.filename, s, path)
				}
			}
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
		// The shapes the real BCR uses.
		`{"url":"https://github.com/YosysHQ/abc/archive/e55d316cc9a7f72a84a76eda555aa6ec083c9d0d.zip","strip_prefix":"abc-e55d","integrity":"sha256-ZWxk","overlay":{"BUILD.bazel":"sha256-HQ58","MODULE.bazel":"sha256-XBSS"}}`,
		`{"url":"https://mirror.bazel.build/ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz","mirror_urls":["https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz","https://mirrors.kernel.org/gnu/bison/bison-3.8.2.tar.xz"],"integrity":"sha256-m7oC","patch_strip":1,"patches":{"a.patch":"sha256-AMd+"}}`,
		`{"url":"https://gitlab.com/libeigen/eigen/-/package_files/233618439/download","archive_type":"tar.gz","integrity":"sha256-uTxm"}`,
		`{"type":"git_repository","remote":"https://github.com/raspberrypi/pico-sdk.git","commit":"4b6e6475","patch_strip":1,"patches":{"p.patch":"sha256-F9pU"}}`,
		`{"type":"local_path","path":"../m"}`,
		`{"type":"archive","url":"HTTPS://Example.com/x.TAR.GZ?token=1#frag"}`,
		`{"type":7,"url":"https://example.com/x.zip"}`,
		`{"url":"https://example.com/a/../../x%2F..%2Fy.tar.gz","archive_type":"../zip"}`,
		`{"url":"file:///etc/passwd","mirror_urls":["//h/x.zip",5,null]}`,
		`null`,
		`[]`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	const (
		proxyRoot = "https://proxy/v1/bazel"
		endpoint  = proxyRoot + "/modules/m/1.0/archive"
	)
	f.Fuzz(func(t *testing.T, body []byte) {
		info, err := parseSource(body)
		if err != nil {
			// What cannot be parsed cannot be rewritten either.
			if _, rerr := rewriteSourceJSON(body, endpoint); rerr == nil {
				t.Fatalf("rewrote a descriptor that does not parse: %q", body)
			}
			return
		}
		// Archive candidates are bounded, unique, and only ever http(s) URLs.
		candidates := info.archiveURLs()
		if len(candidates) > maxArchiveCandidates {
			t.Fatalf("%d archive candidates exceed the cap", len(candidates))
		}
		seen := map[string]bool{}
		for _, c := range candidates {
			u, perr := url.Parse(c)
			if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				t.Fatalf("archive candidate %q is not an http(s) url", c)
			}
			if seen[c] {
				t.Fatalf("archive candidate %q listed twice", c)
			}
			seen[c] = true
		}
		if u, ok := info.primaryURL(); ok != (len(candidates) > 0) || (ok && u != candidates[0]) {
			t.Fatalf("primaryURL = %q, %v disagrees with candidates %q", u, ok, candidates)
		}
		if !info.isArchive() && len(candidates) != 0 {
			t.Fatalf("non-archive descriptor yielded archive candidates %q", candidates)
		}

		out, rerr := rewriteSourceJSON(body, endpoint)
		if rerr != nil {
			return
		}
		// Only an archive descriptor is ever rewritten.
		if !info.isArchive() {
			t.Fatalf("rewrote a non-archive descriptor (type %q): %q", info.Type, body)
		}
		var m map[string]any
		if jerr := json.Unmarshal(out, &m); jerr != nil {
			t.Fatalf("rewritten source.json is not valid JSON: %v", jerr)
		}
		// The client is left with exactly one archive location: the proxy's
		// endpoint, optionally followed by a plain file name.
		got, _ := m["url"].(string)
		rest, ok := strings.CutPrefix(got, endpoint)
		if !ok || (rest != "" && (rest[0] != '/' || !isArchiveFileName(rest[1:]))) {
			t.Fatalf("rewritten url = %q, want %q[/<file>]", got, endpoint)
		}
		for _, k := range []string{"mirror_urls", "urls"} {
			if _, present := m[k]; present {
				t.Fatalf("rewritten source.json still carries %q: %s", k, out)
			}
		}
		// That URL must lead back to this module version's archive endpoint.
		res, cok := classify(strings.TrimPrefix(got, proxyRoot))
		if !cok || res.kind != kindArchive || res.name != "m" || res.version != "1.0" {
			t.Fatalf("rewritten url %q does not classify as the module's archive (%+v, %v)", got, res, cok)
		}
		// The rewrite is deterministic and idempotent in shape: the lockfile hash
		// Bazel records for the served descriptor must be stable.
		again, aerr := rewriteSourceJSON(body, endpoint)
		if aerr != nil || string(again) != string(out) {
			t.Fatalf("rewrite is not deterministic: %s vs %s (%v)", out, again, aerr)
		}
	})
}

func FuzzArchiveFileName(f *testing.F) {
	seeds := [][2]string{
		{"https://github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz", ""},
		{"https://gitlab.com/libeigen/eigen/-/package_files/233618439/download", "tar.gz"},
		{"https://example.com/My%20Pkg%20(1).tar.gz?x=y.zip#frag", ""},
		{"https://example.com/a%2F..%2F..%2Fb.zip", ".tar.zst"},
		{"https://example.com/", "zip"},
		{"https://example.com/a/..", "../../etc"},
		{"not a url %zz", "tar.gz"},
		{"", ""},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, rawURL, archiveType string) {
		name := archiveFileName(rawURL, archiveType)
		if name == "" {
			return
		}
		// A derived name is always one the classifier accepts after the endpoint,
		// so the URL the proxy writes is a URL the proxy serves.
		if !isArchiveFileName(name) {
			t.Fatalf("archiveFileName(%q, %q) = %q, which the classifier rejects", rawURL, archiveType, name)
		}
		res, ok := classify("/modules/m/1.0/archive/" + name)
		if !ok || res.kind != kindArchive {
			t.Fatalf("derived name %q does not classify as the archive endpoint", name)
		}
		// A plausible declared type always ends up as the name's suffix, exactly
		// as Bazel would append it.
		if typ := sanitizeArchiveType(archiveType); typ != "" && !strings.HasSuffix(name, "."+typ) {
			t.Fatalf("archiveFileName(%q, %q) = %q lacks the declared type suffix", rawURL, archiveType, name)
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
