//go:build fuzz
// +build fuzz

// Fuzz targets for the Debian/APT pull-through parsers (Task 30, Task 52).
//
// A malicious or compromised APT mirror controls the Release document (the source
// of every index's verification digest) and the Packages indices (the source of
// every .deb's verification digest), and, via the client, the request path. All
// three are parsed on the pull path before any content is cached or served, so the
// parsers must never panic, must not allocate without bound, and must fail closed
// on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzParseRelease ./internal/backends/apt/
package apt

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/pool/main/h/hello/hello_1.0_amd64.deb",
		"/dists/bookworm/InRelease",
		"/dists/bookworm/Release",
		"/dists/bookworm/Release.gpg",
		"/dists/bookworm/main/binary-amd64/Packages.gz",
		"/dists/bookworm/main/i18n/Translation-en",
		"/../etc/passwd.deb",
		"",
		"/",
		"////",
		"/dists//Packages",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		res, ok := classify(path)
		if !ok {
			return
		}
		_ = res.cacheable()
		_ = res.kindLabel()
		_ = res.coordinateName()
		if res.verifiableArtifact() && res.poolPath == "" {
			t.Fatalf("verifiable .deb with empty pool path: %q", path)
		}
	})
}

func FuzzParseRelease(f *testing.F) {
	seeds := []string{
		"Origin: Debian\nSuite: bookworm\nSHA256:\n " +
			"aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff 10 main/Packages\n",
		"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nSHA256:\n " +
			"aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff 10 main/Packages\n" +
			"-----BEGIN PGP SIGNATURE-----\n\nxx==\n-----END PGP SIGNATURE-----\n",
		"SHA256:\n bad line\n",
		"",
		"no fields at all",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		rel, err := ParseRelease(data)
		if err != nil {
			return
		}
		for relPath, hex := range rel.digests {
			if relPath == "" {
				t.Fatal("empty index path retained in digest table")
			}
			if len(hex) != sha256HexLen || !isHex(hex) {
				t.Fatalf("malformed digest survived parsing: %q", hex)
			}
		}
	})
}

func FuzzParsePackages(f *testing.F) {
	seeds := []string{
		"Package: hello\nFilename: pool/main/h/hello/hello_1.0_amd64.deb\nSHA256: " +
			"aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff\n",
		"Package: x\nFilename: pool/x.deb\n",
		"\n\n\n",
		"",
		"Filename: a\nSHA256: short\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := ParsePackages(data)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.Filename == "" {
				t.Fatal("entry with empty filename retained")
			}
			if len(e.SHA256) != sha256HexLen || !isHex(e.SHA256) {
				t.Fatalf("malformed sha256 retained: %q", e.SHA256)
			}
		}
	})
}
