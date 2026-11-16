//go:build fuzz
// +build fuzz

// Fuzz targets for the cpan feed's parsers (Task 190): the RECENT files, the
// package index, the CHECKSUMS lister (in the cpan backend) and the paths and
// epochs the feed reads from them — all of which a mirror controls. Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzCPANRecent$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/cpan"
)

func cpanFuzzSeed(f *testing.F, name string) []byte {
	f.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "feeds", "cpan", name))
	if err != nil {
		f.Fatal(err)
	}
	return data
}

func FuzzCPANRecent(f *testing.F) {
	f.Add(cpanFuzzSeed(f, "recent-1h.json"))
	f.Add(cpanFuzzSeed(f, "recent-6h.json"))
	f.Add([]byte(`{"meta":{"dirtymark":"1.5","minmax":{"min":"1","max":2}},"recent":[{"epoch":"1e3","path":"x","type":"new"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := cpanParseRecent(data)
		if err != nil {
			return
		}
		for _, e := range r.events {
			if !cpanDecimal(e.epoch) || (e.typ != "new" && e.typ != "delete") {
				t.Fatalf("event %+v kept", e)
			}
		}
		events := cpanMerge([]cpanRecent{r}, "0")
		for i := 1; i < len(events); i++ {
			if cpanCompareEpochs(events[i-1].epoch, events[i].epoch) > 0 {
				t.Fatalf("events out of order: %v %v", events[i-1], events[i])
			}
		}
		for _, e := range events {
			if c, dir, ok := cpanEventCoordinate(e); ok {
				d, dist, ok := cpanParseName(c.Name)
				if !ok || d != dir || !strings.HasSuffix(c.Name, "/"+dist) || !cpanIsVersion(c.Version) {
					t.Fatalf("%q mapped to %v in %q, which reads back as %q %q %v", e.path, c, dir, d, dist, ok)
				}
			}
		}
		_ = r.intervals()
		_ = r.covers(r.newest())
	})
}

func FuzzCPANPackages(f *testing.F) {
	f.Add(cpanFuzzSeed(f, "02packages.details.txt.gz"))
	f.Add([]byte("File: x\n\nA::B 1.0 A/AA/AAA/A-B-1.0.tar.gz\nC 1 C/CC/CCC/sub/C-1.zip\n"))
	f.Add([]byte("\x1f\x8b"))
	f.Fuzz(func(t *testing.T, data []byte) {
		names, err := cpanParsePackages(data)
		if err != nil {
			return
		}
		for i, n := range names {
			if _, _, ok := cpanParseName(n); !ok || (i > 0 && names[i-1] >= n) {
				t.Fatalf("name %q not valid or not in order", n)
			}
		}
	})
}

func FuzzCPANChecksums(f *testing.F) {
	f.Add(cpanFuzzSeed(f, "checksums-cpanic.txt"))
	f.Add(cpanFuzzSeed(f, "checksums-ether.txt"))
	f.Add([]byte("'a' => {\n'size' => 99999999999999999999,\n'isdir' => 1\n'mtime' => '2026-13-45'\n}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := cpan.ListChecksums(data)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, e := range entries {
			if e.Size < 0 || seen[e.File] || (e.SHA256 != "" && len(e.SHA256) != 64) {
				t.Fatalf("entry %+v", e)
			}
			seen[e.File] = true
		}
	})
}

func FuzzCPANPaths(f *testing.F) {
	for _, s := range []string{"C/CP/CPANIC/Ekorn-Pipeline-v0.3.3.tar.gz", "C/CJ/CJCOLLIER/Google-Cloud/Protobuf-0.09.tar.gz", "N/NI/NI-S/Tk-800.024.tar.gz",
		"a/aa/aaa/x-1.tar.gz", "A/AA/AAA/../x-1.zip", "A/AA/AAA/x%2f-1.tgz"} {
		f.Add(s, "1794795306.63291", "1794795306.6329")
	}
	f.Fuzz(func(t *testing.T, rel, a, b string) {
		if name, version, dir, ok := cpanDistPath(rel); ok {
			d, dist, ok := cpanParseName(name)
			if !ok || d != dir || !cpanIsVersion(version) || !cpanIsDist(dist) {
				t.Fatalf("%q read as %q %q in %q; the name reads back as %q %q %v", rel, name, version, dir, d, dist, ok)
			}
			if !validArtifactPath("/authors/id/" + dir + "/" + dist) {
				t.Fatalf("%q makes an invalid path", rel)
			}
		}
		if cpanDecimal(a) && cpanDecimal(b) {
			if cpanCompareEpochs(a, b) != -cpanCompareEpochs(b, a) {
				t.Fatalf("compare(%q, %q) is not antisymmetric", a, b)
			}
			if m := cpanEpochMinus(a, time.Hour); !cpanDecimal(m) || cpanCompareEpochs(m, a) > 0 {
				t.Fatalf("%q minus an hour is %q", a, m)
			}
			_ = cpanEpochTime(a)
			_ = cpanAge(a, b)
		}
	})
}
