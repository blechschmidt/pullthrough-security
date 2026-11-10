//go:build fuzz
// +build fuzz

// Fuzz targets for the RPM/YUM pull-through parsers (Task 30, Task 52).
//
// A malicious or compromised RPM mirror controls repomd.xml (the source of each
// metadata file's verification digest) and primary.xml (the source of each .rpm's
// verification digest), and, via the client, the request path. Both XML documents
// are parsed on the pull path before any content is cached or served, so the
// parsers must never panic, must not allocate without bound, and must fail closed
// on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzParsePrimary ./internal/backends/yum/
package yum

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/Packages/hello-1.0-1.x86_64.rpm",
		"/repodata/repomd.xml",
		"/repodata/repomd.xml.asc",
		"/repodata/abc-primary.xml.gz",
		"/../etc/passwd.rpm",
		"",
		"/",
		"////",
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
		if res.verifiableArtifact() && res.rpmPath == "" {
			t.Fatalf("verifiable .rpm with empty path: %q", path)
		}
	})
}

func FuzzParseRepoMD(f *testing.F) {
	seeds := []string{
		`<repomd><data type="primary"><checksum type="sha256">` +
			`aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff</checksum>` +
			`<location href="repodata/p-primary.xml.gz"/></data></repomd>`,
		`<repomd></repomd>`,
		`<repomd><data><location href="../escape"/></data></repomd>`,
		"not xml",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		rm, err := ParseRepoMD(data)
		if err != nil {
			return
		}
		for _, d := range rm.Data {
			if d.Location == "" {
				t.Fatal("data entry with empty location retained")
			}
			if d.HasSum && (len(d.Checksum.hex) != d.Checksum.alg.hexLen) {
				t.Fatalf("malformed checksum retained: %q", d.Checksum.hex)
			}
		}
	})
}

func FuzzParsePrimary(f *testing.F) {
	seeds := []string{
		`<metadata><package type="rpm"><name>x</name>` +
			`<checksum type="sha256">aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff</checksum>` +
			`<location href="Packages/x-1.0-1.x86_64.rpm"/></package></metadata>`,
		`<metadata><package type="rpm"><location href="x.rpm"/></package></metadata>`,
		`<metadata></metadata>`,
		"not xml",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := ParsePrimary(data)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.Location == "" {
				t.Fatal("entry with empty location retained")
			}
			if len(e.Checksum.hex) != e.Checksum.alg.hexLen {
				t.Fatalf("malformed checksum retained: %q", e.Checksum.hex)
			}
		}
	})
}
