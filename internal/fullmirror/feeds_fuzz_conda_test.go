//go:build fuzz
// +build fuzz

// Fuzz targets for the conda feed's parsers (Task 191): the streaming reader
// of a subdir's repodata — which a channel controls — and the version order.
// Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzCondaRepodata$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func condaFuzzSeed(f *testing.F, name string) []byte {
	f.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "feeds", "conda", name))
	if err != nil {
		f.Fatal(err)
	}
	return data
}

func FuzzCondaRepodata(f *testing.F) {
	for _, fx := range []string{"noarch-repodata.json", "win-arm64-repodata.json", "win-arm64-current_repodata.json"} {
		f.Add(condaFuzzSeed(f, fx))
	}
	f.Add([]byte(`{"info":{"subdir":"noarch","base_url":"./"},"packages":{"a-1.0-0.tar.bz2":{"name":"a","version":"1.0","size":"7","timestamp":1.5e12}},"packages.conda":null,"repodata_version":2}`))
	f.Add([]byte(`{"packages":{"x-1-0.conda":"s","y-1-0.tar.bz2":null},"removed":[["a"],{"b":1}]}`))
	f.Add([]byte(`{"signatures":{"a-1.0-0.conda":{"k":{"signature":"s"}}},"removed":` + strings.Repeat("[", 70) + strings.Repeat("]", 70) + `,"packages":{"a-1.0-0.tar.bz2":{"name":"a","version":"1.0","depends":[["x"]]}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = condaParseRepodata(bytes.NewReader(data), func(section, filename string, rec *condaRecord) {
			if rec.Name == "" || rec.Version == "" {
				t.Fatalf("a record without a name or version was emitted: %+v", rec)
			}
			r, ok := condaRecordOf("noarch", section, filename, rec)
			if !ok {
				return
			}
			if !r.valid() || !validArtifactPath(r.Path) || r.Name != rec.Name || r.Version != rec.Version || r.Index != "noarch" || r.Size < 0 || r.Time < 0 {
				t.Fatalf("%q in %s made the record %+v", filename, section, r)
			}
		})
	})
}

func FuzzCondaVersionOrder(f *testing.F) {
	f.Add("1.1.0post1", "1.1post1", "1!0.4.1")
	f.Add("1.0.1_", "1.0.1a", "1.0-1")
	f.Add("2023.10.11", "0.960923", "1.*")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		ab, ba := condaCompareVersions(a, b), condaCompareVersions(b, a)
		if ab != -ba || (ab == 0) != (a == b) || condaCompareVersions(a, a) != 0 {
			t.Fatalf("compare(%q, %q) = %d, compare(%q, %q) = %d", a, b, ab, b, a, ba)
		}
		if ab <= 0 && condaCompareVersions(b, c) <= 0 && condaCompareVersions(a, c) > 0 {
			t.Fatalf("%q <= %q <= %q but %q > %q", a, b, c, a, c)
		}
	})
}
