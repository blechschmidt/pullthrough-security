//go:build fuzz
// +build fuzz

// Fuzz targets for the Conan pull-through parsers (Task 30, Task 95).
//
// A malicious or compromised upstream remote controls the conanmanifest.txt
// body and (via the client) the request path. Both are parsed on the pull path
// before any content is cached or served, so the parsers must never panic, must
// not allocate without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/conan/
package conan

import (
	"net/http"
	"strings"
	"testing"
)

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/v1/ping",
		"/v1/ping/extra",
		"/v1/users/authenticate",
		"/v1/conans/zlib/1.2.13/_/_/latest",
		"/v2/ping",
		"/v2/users/authenticate",
		"/v2/conans/search",
		"/v2/conans/zlib/1.2.13/_/_/latest",
		"/v2/conans/zlib/1.2.13/_/_/revisions/abc/files/conanfile.py",
		"/v2/conans/z/1/u/c/revisions/r/packages/p/revisions/pr/files/conan_package.tgz",
		"/v2/conans/a/b/c/../../../etc/passwd",
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
		// Invariants for an accepted path: the predicates must be callable without
		// panicking, and a verifiable file must carry a non-empty filename.
		_ = res.cacheable()
		_ = res.kindLabel()
		_ = res.coordinateName()
		_ = res.reference()
		if res.verifiableFile() && res.filename == "" {
			t.Fatalf("verifiable file with empty filename: %q", path)
		}
		// The legacy v1 prefix serves the capability probe and nothing else.
		if strings.Split(strings.Trim(path, "/"), "/")[0] == "v1" && res.kind != kindPing {
			t.Fatalf("v1 route accepted for a non-ping resource: %q -> %s", path, res.kindLabel())
		}
		// Only a resource pinned beneath a revision is cacheable, and the gates
		// need its full coordinate.
		if res.cacheable() && (res.name == "" || res.version == "" || res.rrev == "") {
			t.Fatalf("cacheable resource without a full coordinate: %q -> %+v", path, res)
		}
	})
}

func FuzzHeaderMD5(f *testing.F) {
	for _, s := range []string{
		"373b2b3b570caa67d7fcce21b9d484c1",
		"373B2B3B570CAA67D7FCCE21B9D484C1",
		" 373b2b3b570caa67d7fcce21b9d484c1 ",
		"373b2b3b570caa67d7fcce21b9d484c",
		"096169aa6b128bab6763ed9127c7dd34f47b1ffd",
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		h := http.Header{}
		h.Set(checksumMD5Header, value)
		got, ok := headerMD5(h)
		if !ok {
			return
		}
		// An accepted header value is always a canonical 32-char lowercase hex MD5.
		if len(got) != md5HexLen || !isHex(got) || got != strings.ToLower(got) {
			t.Fatalf("headerMD5(%q) accepted non-canonical digest %q", value, got)
		}
	})
}

func FuzzParseManifest(f *testing.F) {
	seeds := []string{
		"1700000000\nconanfile.py: 5d41402abc4b2a76b9719d911017c592\n",
		"conan_package.tgz: 7d793037a0760186574b0282f2f435e7",
		"garbage\nwithout: digests\n",
		"",
		"   \n\t  ",
		":::::",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		m := ParseManifest(body)
		// Every recorded digest must be a valid 32-char hex MD5, and lookups must
		// be safe for arbitrary keys.
		for name, d := range m.Digests {
			if len(d) != md5HexLen || !isHex(d) {
				t.Fatalf("manifest accepted invalid digest %q for %q", d, name)
			}
		}
		_, _ = m.digestFor("conanfile.py")
		_, _ = m.digestFor("")
	})
}
