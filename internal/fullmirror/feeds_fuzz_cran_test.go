//go:build fuzz
// +build fuzz

// Fuzz targets for the cran feed's parsers (Task 191): the streaming reader
// of a repository's PACKAGES (DCF) index — which a mirror controls — with the
// records it makes, and the version order. Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzCRANPackages$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func FuzzCRANPackages(f *testing.F) {
	data, err := os.ReadFile(filepath.Join("testdata", "feeds", "cran", "PACKAGES"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte("Package: x\nVersion: 1.0\nPath: a/b\nFile: x_1.0.tar.gz\n\n\tcont\nPackage: y\nVersion:\t2-3\nPublished: 2026-01-02 03:04:05 UTC\n"))
	f.Add([]byte("Package: dup\nPackage: dup\nVersion: 1\n\r\nPackage: z\r\nVersion: 1.0\r\n"))
	src := &cranSource{k: kit{env: Env{Upstream: "cran-test", Type: "cran", URL: "https://cran.example"}}}
	src.k.upstream, _ = parseBaseURL("upstream", "https://cran.example")
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, err := cranParsePackages(bytes.NewReader(data), func(st cranStanza) {
			rec, ok := src.record(context.Background(), st)
			if !ok {
				return
			}
			if !rec.valid() || rec.Name != st.Package || rec.Version != st.Version || !cranValidName(rec.Name) || !cranValidVersion(rec.Version) || rec.Time < 0 {
				t.Fatalf("%+v made the record %+v", st, rec)
			}
		})
		if err != nil {
			t.Fatalf("reading from memory failed: %v", err)
		}
	})
}

func FuzzCRANVersionOrder(f *testing.F) {
	f.Add("1.0-1", "1.0.1", "0.10")
	f.Add("2.0.0", "1.10-0", "1.0a")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		ab, ba := cranCompareVersions(a, b), cranCompareVersions(b, a)
		if ab != -ba || (ab == 0) != (a == b) || cranCompareVersions(a, a) != 0 {
			t.Fatalf("compare(%q, %q) = %d, compare(%q, %q) = %d", a, b, ab, b, a, ba)
		}
		if ab <= 0 && cranCompareVersions(b, c) <= 0 && cranCompareVersions(a, c) > 0 {
			t.Fatalf("%q <= %q <= %q but %q > %q", a, b, c, a, c)
		}
	})
}
