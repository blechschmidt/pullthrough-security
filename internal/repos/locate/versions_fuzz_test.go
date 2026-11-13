//go:build fuzz
// +build fuzz

// Fuzz targets for the version listers of the maintenance updater (Task 182):
// npm packuments, Cargo sparse-index files and go.mod requirements come from
// registries and repositories.
//
//	go test -tags fuzz -run='^$' -fuzz=FuzzParseNPMPackument ./internal/repos/locate/
package locate

import "testing"

func FuzzParseNPMPackument(f *testing.F) {
	f.Add([]byte(`{"versions":{"1.0.0":{"dependencies":{"a":"^1"},"dist":{"integrity":"sha512-AAAA sha1-BBBB","shasum":"0000000000000000000000000000000000000000"}}},"time":{"1.0.0":"2025-01-01T00:00:00Z"}}`))
	f.Add([]byte(`{"versions":{"1.0.0":"x","2.0.0":{"scripts":{"install":"x"}}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := ParseNPMPackument(data)
		if err != nil {
			return
		}
		again, err := ParseNPMPackument(data)
		if err != nil || len(again.Releases) != len(l.Releases) {
			t.Fatal("parsing is not deterministic")
		}
		for i, r := range l.Releases {
			if r.Fingerprint != again.Releases[i].Fingerprint {
				t.Fatalf("%s: fingerprints differ between two reads", r.Version)
			}
		}
	})
}

func FuzzParseCargoIndex(f *testing.F) {
	f.Add([]byte(`{"name":"a","vers":"1.0.0","deps":[{"name":"b","req":"^1","kind":"normal"}],"cksum":"` + "0000000000000000000000000000000000000000000000000000000000000000" + `","features":{}}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if l, err := ParseCargoIndex(data, "a"); err == nil {
			for _, r := range l.Releases {
				if r.Version == "" {
					t.Fatal("a release without a version")
				}
			}
		}
	})
}

func FuzzGoModRequires(f *testing.F) {
	f.Add([]byte("module x\nrequire (\n\ta v1.0.0 // indirect\n)\nrequire b v2.0.0\nexclude c v1.0.0\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = GoModRetractions(data)("v1.0.0")
		reqs, fp, err := GoModRequires(data)
		if err != nil {
			return
		}
		_, fp2, _ := GoModRequires(data)
		if fp != fp2 {
			t.Fatal("the fingerprint is not deterministic")
		}
		for p, v := range reqs {
			if p == "" || v == "" {
				t.Fatalf("an empty requirement %q %q", p, v)
			}
		}
	})
}
