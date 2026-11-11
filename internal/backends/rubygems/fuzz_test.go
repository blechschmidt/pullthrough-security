//go:build fuzz
// +build fuzz

// Fuzz targets for the RubyGems pull-through parsers (Task 30, Task 45).
//
// A malicious or compromised gem server controls the compact-index /info
// document (the source of the verification checksum) and, via the client, the
// request path. Both are parsed on the pull path before any content is cached or
// served, so the parsers must never panic, must not allocate without bound, and
// must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzParseInfo ./internal/backends/rubygems/
package rubygems

import (
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/gems/rails-7.0.4.gem",
		"/gems/nokogiri-1.13.0-x86_64-linux.gem",
		"/info/rails",
		"/versions",
		"/names",
		"/specs.4.8.gz",
		"/quick/Marshal.4.8/rails-7.0.4.gemspec.rz",
		"/api/v1/dependencies?gems=rails",
		"/a/b/../../etc/passwd",
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
		// Invariants for an accepted path: the predicate methods must be callable
		// without panicking, and a verifiable .gem must carry a non-empty version
		// token (needed to look up its checksum).
		_ = res.cacheable()
		_ = res.kindLabel()
		_ = res.coordinateName()
		if res.verifiableArtifact() && (res.name == "" || res.version == "") {
			t.Fatalf("verifiable gem with empty name/version: %q", path)
		}
		// The .gem, and nothing else, is what the content gates examine as a
		// payload; no accepted path is left without a classification.
		a := res.artifact()
		if (a == backends.Payload()) != res.verifiableArtifact() || (a != backends.Payload() && a != backends.Metadata()) {
			t.Fatalf("artifact of %q (%s) = %+v", path, res.kindLabel(), a)
		}
	})
}

func FuzzParseInfo(f *testing.F) {
	seeds := []string{
		infoFixture,
		"---\n1.0.0 |checksum:" + zeroSHA256 + "\n",
		"---\n1.0.0-java rake:>= 0|checksum:" + zeroSHA256 + ",ruby:>= 2.0\n",
		"---\n",
		"not an info file",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		info, err := ParseInfo(data)
		if err != nil {
			return
		}
		for _, v := range info.Versions {
			if v.Version == "" {
				t.Fatalf("parsed info version with empty version token")
			}
			if v.Checksum != "" && len(v.Checksum) != gemChecksumHexLen {
				t.Fatalf("parsed checksum of wrong length: %q", v.Checksum)
			}
			// Lookup must be safe on any parsed document.
			_, _ = info.ChecksumFor(v.Version)
		}
	})
}
