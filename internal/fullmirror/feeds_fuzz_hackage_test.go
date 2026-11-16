//go:build fuzz
// +build fuzz

// Fuzz targets for the hackage feed's parsers (Task 190): the index tarball's
// headers and entry chain, which a registry or a man in the middle controls
// byte for byte, and the JSON documents the feed reads. Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzHackageIndex$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzHackageIndex(f *testing.F) {
	tail, err := os.ReadFile(filepath.Join("testdata", "feeds", "hackage", "index-tail.bin"))
	if err != nil {
		f.Fatal(err)
	}
	// Small seeds: the engine minimizes every new input it finds, at a
	// cost that grows with the square of its length. (The unit tests run
	// the whole recorded tail.)
	f.Add(tail[11776:])       // time-manager's upload: package.json, .cabal, end blocks
	f.Add(tail[12800:])       // time-manager's .cabal and the end blocks
	f.Add(tail[11776:15360])  // no end-of-archive blocks
	f.Add(make([]byte, 1024)) // an empty index
	f.Add([]byte("not a tar archive"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		entries, stop, atEnd, err := hackageWalk(data, 0, 0, 1000)
		prev := int64(-1)
		for _, e := range entries {
			if e.off <= prev || e.off%512 != 0 || e.end <= e.off || e.end > int64(len(data)) {
				t.Fatalf("entry %+v out of order or outside the data", e)
			}
			prev = e.off
		}
		if err == nil && (stop < 0 || stop > int64(len(data)) || (atEnd && stop+512 > int64(len(data)))) {
			t.Fatalf("stop %d (at end %v) outside %d bytes", stop, atEnd, len(data))
		}
		for _, c := range hackageUploads(entries) {
			if !hackageIsName(c.Name) || !hackageIsVersion(c.Version) {
				t.Fatalf("upload %v is not a valid coordinate", c)
			}
		}
		aligned := data[:len(data)-len(data)%512]
		if c, ok := hackageTailCursor(aligned, 0, int64(len(aligned))); ok {
			if c.Header >= 0 && (c.Header+512 > c.End || c.End > int64(len(aligned))-1024 || c.Header%512 != 0) {
				t.Fatalf("tail cursor %+v outside %d bytes", c, len(aligned))
			}
		}
		if len(data) >= 512 {
			if _, size, _, _, ok := hackageHeader(data[:512]); ok && size < 0 {
				t.Fatalf("negative size %d", size)
			}
		}
	})
}

func FuzzHackageContentRange(f *testing.F) {
	for _, s := range []string{"bytes 1054601728-1054618111/1054618112", "bytes 0-0/1", "bytes */1024", "bytes 5-4/10", "bytes -1-2/3", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		first, last, total, ok := hackageContentRange(s)
		if ok && (first < 0 || last < first || total <= last) {
			t.Fatalf("%q read as %d-%d/%d", s, first, last, total)
		}
	})
}

func FuzzHackagePackages(f *testing.F) {
	body, err := os.ReadFile(filepath.Join("testdata", "feeds", "hackage", "packages.json"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(body)
	f.Add([]byte(`[{"packageName":"../x"},{"packageName":"a--b"},{"packageName":1}]`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		names, err := hackageParsePackages(data)
		if err != nil {
			return
		}
		for i, n := range names {
			if !hackageIsName(n) || (i > 0 && names[i-1] >= n) {
				t.Fatalf("name %q not valid or not in order", n)
			}
		}
	})
}

func FuzzHackagePreferred(f *testing.F) {
	for _, name := range []string{"preferred-base64.json", "preferred-time-manager.json"} {
		body, err := os.ReadFile(filepath.Join("testdata", "feeds", "hackage", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(body)
	}
	f.Add([]byte(`{"normal-version":["1.0","1.0"],"deprecated-version":["1.0"],"x-version":"y"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		vs, err := hackageParsePreferred(data)
		if err != nil {
			return
		}
		for i, v := range vs {
			if !hackageIsVersion(v.version) || (i > 0 && hackageCompareVersions(vs[i-1].version, v.version) >= 0) {
				t.Fatalf("version %q not valid or not in order", v.version)
			}
		}
	})
}
