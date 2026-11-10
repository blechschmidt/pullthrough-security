//go:build fuzz
// +build fuzz

// Fuzz targets for the malfeed ingestion parsers (Task 48, mirroring Task 30).
//
// Both surfaces consume bytes from an untrusted source — a remote/mirror malware
// feed (OSV/GHSA JSON) and an operator-transferred offline bundle — so they must
// never panic and must bound their work. The bundle importer additionally
// verifies a signature and digest before trusting any byte of the payload.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzParseOSVStream ./internal/malfeed/
package malfeed

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

// FuzzParseOSVStream fuzzes the OSV/GHSA feed parser and the matcher it feeds.
func FuzzParseOSVStream(f *testing.F) {
	seeds := []string{
		fixtureFeed,
		`{"id":"MAL-1","affected":[{"package":{"ecosystem":"npm","name":"x"}}]}`,
		`{"id":"MAL-2","affected":[{"package":{"ecosystem":"PyPI","name":"y"},"versions":["1.0.0"]}]}`,
		`{"id":"MAL-3","affected":[{"package":{"purl":"pkg:cargo/z@1.0.0"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`,
		`{"affected":[]}`,
		`{"affected":[{"package":{}}]}`,
		`[]`,
		`[{"id":"a"},{"id":"b","affected":[{"package":{"ecosystem":"go","name":"m"}}]}]`,
		`{}`,
		`null`,
		`not json`,
		``,
		`   `,
	}
	for _, s := range seeds {
		f.Add([]byte(s), "fuzz-source")
	}
	f.Fuzz(func(t *testing.T, data []byte, source string) {
		entries, err := ParseOSVStream(data, source)
		if err != nil {
			if entries != nil {
				t.Fatalf("error result returned non-nil entries")
			}
			return
		}
		// The matcher must build and answer queries without panicking, and every
		// indexed entry must carry a normalized name.
		m := NewMatcher(entries)
		_ = m.Match(Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
		for _, e := range m.Entries() {
			if e.ID == "" && e.Name == "" {
				t.Fatalf("indexed an entry with neither id nor name")
			}
		}
	})
}

// FuzzImportBundle fuzzes the offline-bundle importer against arbitrary bytes and
// against tampered variants of a validly-signed bundle. It must reject every
// input that does not verify, and never panic.
func FuzzImportBundle(f *testing.F) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	entries, _ := ParseOSVStream([]byte(fixtureFeed), "fixture")
	valid, _ := ExportBundle(entries, "seed", time.Time{}, priv)

	seeds := [][]byte{
		valid,
		[]byte(`{"algorithm":"ed25519","payload":"","signature":"","publicKey":""}`),
		[]byte(`{"algorithm":"rsa"}`),
		[]byte(`{}`),
		[]byte(`null`),
		[]byte(`not json`),
		{},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// Pinned verification: anything that decodes must verify against pub, or be
		// rejected with an error. Either way: no panic.
		got, err := ImportBundle(data, pub)
		if err == nil {
			// A successful import must reproduce a usable entry set.
			_ = NewMatcher(got)
		}
		// Unpinned verification exercises the embedded-key path.
		_, _ = ImportBundle(data, nil)
	})
}
