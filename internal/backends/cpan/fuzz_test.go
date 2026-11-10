//go:build fuzz
// +build fuzz

// Fuzz targets for the CPAN pull-through parsers (Task 30, Task 131).
//
// A malicious or compromised upstream mirror controls the CHECKSUMS file body
// and (via the client) the request path. Both are parsed on the pull path before
// any content is cached or served, so the parsers must never panic, must not
// allocate without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/cpan/
package cpan

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/modules/02packages.details.txt.gz",
		"/authors/id/E/ET/ETHER/CHECKSUMS",
		"/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz",
		"/authors/id/A/AB/ABC/Acme-CPANAuthors-Canadian-0.0108.tar.gz",
		"/authors/id/M/MO/MONGER/Foo-v1.2.3.tar.gz",
		"/authors/id/E/ET/ETHER/../../../etc/passwd.tar.gz",
		"/etc/passwd", "", "/", "////",
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
		if res.verifiableFile() {
			if res.filename == "" {
				t.Fatalf("verifiable distribution with empty filename: %q", path)
			}
			// A verifiable distribution with a parsed coordinate must have both a
			// name and a version (an unparsed filename yields an empty coordinate).
			if res.name != "" && res.version == "" {
				t.Fatalf("distribution with name but no version: %q -> %+v", path, res)
			}
		}
	})
}

func FuzzParseChecksums(f *testing.F) {
	seeds := []string{
		"$cksum = {\n  'p-1.0.tar.gz' => {\n    'sha256' => '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',\n    'size' => 1\n  }\n};\n",
		"$cksum = {\n  'p-1.0.tar.gz' => {\n    'sha256' => 'tooshort'\n  }\n};\n",
		"garbage without structure\n",
		"'orphan' => 'value'\n",
		"",
		"   \n\t  ",
		"'k' => {\n'k' => {\n'k' => {\n",
		"}}}}}}\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		cs, err := ParseChecksums(body)
		if err != nil {
			return
		}
		// Every recorded digest must be a valid 64-char hex SHA-256, and lookups
		// must be safe for arbitrary keys.
		for name, d := range cs.sha256 {
			if len(d) != sha256HexLen || !isHex(d) {
				t.Fatalf("index accepted invalid digest %q for %q", d, name)
			}
		}
		_, _ = cs.sha256For("Try-Tiny-0.32.tar.gz")
		_, _ = cs.sha256For("")
	})
}
