//go:build fuzz
// +build fuzz

// Fuzz targets for the maven feed's parsers (Task 191): an index data file
// (Maven Indexer's format, compressed or not), the index's properties file,
// and the records one index document becomes. None of them may panic; what
// they accept must stay bounded and well formed.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzMavenIndex$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"
)

// mavenFuzzRaw is an index's uncompressed content: the fuzzer mutates it far
// better than gzip's.
func mavenFuzzRaw(t testing.TB, gz []byte) []byte {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func FuzzMavenIndex(f *testing.F) {
	for _, name := range []string{"clojars-index.gz", "jenkins-index.gz", "clojars-index.1.gz"} {
		data := fixture(f, "maven", name)
		f.Add(data)
		f.Add(mavenFuzzRaw(f, data))
	}
	one, two := mavenChainChunks()
	f.Add(mavenFuzzRaw(f, one))
	f.Add(mavenFuzzRaw(f, two))
	f.Add(mavenFuzzRaw(f, mavenChainFull()))
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 0, 1, 'u', 0, 0, 0, 0})
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff})
	f.Add([]byte("<html>"))
	all := &mavenSource{all: true}
	f.Fuzz(func(t *testing.T, data []byte) {
		docs := 0
		_, err := mavenParse(context.Background(), bytes.NewReader(data), "fuzz", 16<<20, func(d mavenDoc) bool {
			docs++
			for _, v := range []string{d.uinfo, d.info, d.sha1, d.deleted} {
				if len(v) > mavenMaxKept || !mavenASCII([]byte(v)) {
					t.Fatalf("kept value %q", v)
				}
			}
			for _, r := range all.records(d) {
				if !r.valid() || r.Index != d.uinfo || !strings.Contains(r.Name, ":") || r.Version == "" || !validArtifactPath(r.Path) || mavenSnapshot(r.Version) {
					t.Fatalf("record %+v of %+v", r, d)
				}
			}
			return docs < 100_000
		})
		_ = err
	})
}

func FuzzMavenProperties(f *testing.F) {
	for _, name := range []string{"clojars-index.properties", "jenkins-index.properties", "apache-index.properties"} {
		f.Add(fixture(f, "maven", name))
	}
	f.Add(mavenTestProps("100", 2, 2, 1))
	f.Add([]byte("nexus.index.chain-id=a\\\nb\nnexus.index.last-incremental: 3\r\nnexus.index.incremental-0 = 3\n"))
	f.Add([]byte("\\\n\\\n\\"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := mavenParseProps(data)
		if err != nil {
			return
		}
		if (p.chain != "" && !mavenPropValue(p.chain)) || p.last < 0 || p.last > 1_000_000_000 || len(p.chunks) > 4096 {
			t.Fatalf("%+v", p)
		}
		for n := range p.chunks {
			if n < 0 || n > 1_000_000_000 {
				t.Fatalf("chunk %d", n)
			}
		}
	})
}

func FuzzMavenRecords(f *testing.F) {
	for _, s := range [][3]string{
		{"g.x|a|1.0|NA|pom", "jar|1700000000000|-1|0|0|0|pom", ""},
		{"g|a|1.0|NA|jar", "jar|1700000000000|31975|0|0|0|jar", "3b8989e49e98a2b58cf77038692a500ead0f446a"},
		{"g|a|1.0|sources|jar", "jar|0|300|2|2|0|jar", ""},
		{"g|a|1.0|NA", "war|0|10|0|0|0", ""},
		{"g|a|1.0-SNAPSHOT|NA|jar", "jar|0|10|0|0|0|jar", ""},
		{"g|a|1.0|NA|jar.sig", "jar|0|294|0|0|0|jar.sig", ""},
		{"g|a|1|NA|pom", "${x}|-1|-1|0|0|0|pom", ""},
		{"0|0|0||\xf2", "0", "0"}, // an extension that is not UTF-8 once gave a record with an invalid Index
	} {
		f.Add(s[0], s[1], s[2])
	}
	src := &mavenSource{classifiers: map[string]bool{"sources": true}}
	f.Fuzz(func(t *testing.T, uinfo, info, sha1 string) {
		recs := src.records(mavenDoc{uinfo: uinfo, info: info, sha1: sha1})
		if len(recs) > 3 {
			t.Fatalf("%d records", len(recs))
		}
		for _, r := range recs {
			if !r.valid() || r.Index != uinfo || r.Size < 0 || r.Time < 0 || (r.Digest != "" && !mavenIsSHA1(r.Digest)) {
				t.Fatalf("record %+v", r)
			}
		}
	})
}
