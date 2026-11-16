//go:build fuzz
// +build fuzz

package fullmirror

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fuzz targets for the RubyGems feed adapter's parsers (Task 190): the
// compact index /versions (whole, and the tail appended to it), /info
// documents, and the headers a Range answer is checked with are registry
// input. None may panic, and what they return must be what the adapter can
// hand on.

// rubygemsFuzzSeeds adds the recorded fixtures of the RubyGems tests.
func rubygemsFuzzSeeds(f *testing.F, pattern string) {
	matches, _ := filepath.Glob(filepath.Join("testdata", "feeds", "rubygems", pattern))
	for _, m := range matches {
		if data, err := os.ReadFile(m); err == nil {
			f.Add(data)
		}
	}
}

func FuzzRubyGemsVersions(f *testing.F) {
	rubygemsFuzzSeeds(f, "versions*.txt")
	f.Add([]byte("created_at: 2026-11-01T00:00:04Z\n---\na 1.0,-1.0,1.0-java x\n- 1 y\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// The whole file: its header, its gems, the versions it holds.
		created, first, ok := rubygemsHeader(data)
		if ok && (!bytes.HasPrefix(data, first) || !cleanName(created+"x")) {
			t.Fatalf("header %q %q", created, first)
		}
		live := rubygemsSet{}
		_ = rubygemsScan(bytes.NewReader(data), func(name string, versions []string) {
			if !rubygemsValidName(name) {
				t.Fatalf("gem %q", name)
			}
			live.replay(name, versions)
		})
		// As a tail: the versions it adds.
		for _, c := range rubygemsAppended(data) {
			if v, p, ok := rubygemsSplit(c.Version); !rubygemsValidName(c.Name) || !ok || v != c.Version || p != "" {
				t.Fatalf("coordinate %+v", c)
			}
			if err := validateBatch(Batch{Items: []Coordinate{c}, Next: "x"}); err != nil {
				t.Fatalf("coordinate %+v: %v", c, err)
			}
		}
	})
}

func FuzzRubyGemsInfo(f *testing.F) {
	rubygemsFuzzSeeds(f, "info-*.txt")
	f.Add([]byte("---\n1.0 a:>= 1|checksum:00,created_at:2026-01-01T00:00:00Z|x\n1.0-java |created_at:nope\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for token, created := range rubygemsInfoTimes(data) {
			if created.IsZero() || strings.ContainsAny(token, " \n") {
				t.Fatalf("%q: %v", token, created)
			}
		}
		for _, line := range strings.Split(string(data), "\n") {
			token, _, _ := strings.Cut(strings.TrimSpace(line), " ")
			if v, p, ok := rubygemsSplit(token); ok && (v == "" || (p != "" && v+"-"+p != token) || (p == "" && v != token)) {
				t.Fatalf("%q split as %q %q", token, v, p)
			}
		}
	})
}

func FuzzRubyGemsRangeHeaders(f *testing.F) {
	f.Add("bytes 24376921-24377420/24377421", `sha-256="anIVmJblahrFCf6N0pzNuLGuzQaWBNNkzDLHYbJPnes="`, `"1ad61d7c19b54fff7d5a0847c7ac4816"`)
	f.Add("bytes 0-0/1", "sha-512=:AAAA:, sha-256=:anIVmJblahrFCf6N0pzNuLGuzQaWBNNkzDLHYbJPnes=:", "W/\"x\"")
	f.Add("bytes */20", "SHA-256=", "")
	f.Fuzz(func(t *testing.T, contentRange, digest, etag string) {
		if first, last, length, ok := rubygemsParseContentRange(contentRange); ok && (first < 0 || last < first || length <= last) {
			t.Fatalf("%q: %d-%d/%d", contentRange, first, last, length)
		}
		h := http.Header{}
		h.Set("Repr-Digest", digest)
		h.Set("ETag", etag)
		if sum, ok := rubygemsDigest(h); ok && len(sum) != 32 {
			t.Fatalf("%q: %x", digest, sum)
		}
		if e := rubygemsETag(h); e != "" && (len(e) > 256 || !cleanName(e)) {
			t.Fatalf("etag %q", e)
		}
	})
}
