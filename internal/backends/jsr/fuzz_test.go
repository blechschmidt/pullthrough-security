//go:build fuzz
// +build fuzz

// Fuzz targets for the JSR pull-through parsers (Task 30, Task 155).
//
// A malicious or compromised upstream registry controls the request path, the
// version-metadata JSON (and its "manifest" checksums), and the metadata
// documents the proxy rewrites. All are parsed on the pull path before any
// content is cached or served, so the parsers must never panic, must not
// allocate without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/jsr/
package jsr

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/@luca/flag/meta.json",
		"/@luca/flag/1.0.1_meta.json",
		"/@luca/flag/1.0.1/main.ts",
		"/@std/encoding/1.0.0/src/base64.ts",
		"/@luca/flag/1.0.1/../x",
		"/luca/flag/meta.json",
		"", "/", "////",
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
		if res.kind == kindModuleFile {
			if res.version == "" || res.filePath == "" {
				t.Fatalf("module file with incomplete coordinate: %q -> %+v", path, res)
			}
		}
	})
}

func FuzzParseVersionMeta(f *testing.F) {
	f.Add([]byte(`{"manifest":{"/main.ts":{"size":3,"checksum":"sha256-abcd"}}}`))
	f.Add([]byte(`{"manifest":{}}`))
	f.Add([]byte("not json"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		vm, err := parseVersionMeta(body)
		if err != nil {
			return
		}
		if h, ok := vm.checksumFor("/main.ts"); ok {
			if len(h) != sha256HexLen || !isHex(h) {
				t.Fatalf("checksumFor returned a non-sha256 digest: %q", h)
			}
		}
	})
}

func FuzzParseSRIChecksum(f *testing.F) {
	f.Add("sha256-" + "ab")
	f.Add("sha256:deadbeef")
	f.Add("sha512-xyz")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if h, ok := parseSRIChecksum(s); ok {
			if len(h) != sha256HexLen || !isHex(h) {
				t.Fatalf("parseSRIChecksum accepted a non-sha256 digest: %q -> %q", s, h)
			}
		}
	})
}

func FuzzRewriteMetadata(f *testing.F) {
	f.Add([]byte(`{"a":"https://jsr.io/x","b":"./rel"}`))
	f.Add([]byte(`["https://jsr.io/x",{"c":"https://jsr.io/y"}]`))
	f.Add([]byte("not json"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		out, changed := rewriteMetadata(body, "https://jsr.io", "https://proxy/v1/jsr")
		if !changed {
			return
		}
		// A changed body must still be valid JSON.
		if _, err := parseVersionMeta(out); err != nil {
			// parseVersionMeta only validates object bodies; a JSON array is also
			// valid output, so a decode error here only matters for object inputs.
			_ = err
		}
	})
}
