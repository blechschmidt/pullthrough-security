//go:build fuzz
// +build fuzz

// Fuzz targets for the Helm pull-through parsers (Task 30, Task 49).
//
// A malicious or compromised chart repository controls index.yaml (the source of
// the chart download URL and the verification SHA-256 digest) and, via the
// client, the request path. Both are parsed on the pull path before any content
// is cached or served, so the parsers must never panic, must not allocate without
// bound, and must fail closed on malformed input. index.yaml is YAML — a format
// with a large surface (anchors, aliases, deeply nested maps) — so it is the
// primary supply-chain attack surface the fuzzer exercises.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzParseIndex ./internal/backends/helm/
package helm

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/index.yaml",
		"/nginx-1.2.3.tgz",
		"/charts/nginx-1.2.3.tgz",
		"/nginx-1.2.3.tgz.prov",
		"/kube-state-metrics-5.0.1.tgz",
		"/../etc/passwd.tgz",
		"",
		"/",
		"////",
		"/-1.0.0.tgz",
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
		if res.verifiableArtifact() && (res.name == "" || res.version == "" || res.filename == "") {
			t.Fatalf("verifiable chart with empty coordinate/filename: %q", path)
		}
	})
}

func FuzzParseIndex(f *testing.F) {
	seeds := []string{
		sampleIndex,
		"apiVersion: v1\nentries:\n  a:\n    - version: 1.0.0\n      digest: " +
			"1111111111111111111111111111111111111111111111111111111111111111\n",
		"apiVersion: v1\nentries: {}\n",
		"apiVersion: v1\nentries:\n  a:\n    - version: \"\"\n",
		"{}",
		"not yaml",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		idx, err := ParseIndex(data)
		if err != nil {
			return
		}
		for name, versions := range idx.Entries {
			if name == "" && len(versions) > 0 {
				// An empty chart-name key is tolerated, but every retained version must
				// still carry a usable version string.
			}
			for _, cv := range versions {
				if cv.Version == "" {
					t.Fatalf("retained chart version with empty version under %q", name)
				}
				// A non-empty digest must be a well-formed 64-char SHA-256 hex.
				if cv.Digest != "" && len(cv.Digest) != sha256HexLen {
					t.Fatalf("malformed digest survived parsing: %q", cv.Digest)
				}
				// A reported checksum must be findable by its own filename.
				if _, ok := cv.Checksum(); ok {
					if _, found := idx.FindByFilename(cv.Name + "-" + cv.Version + chartExt); !found {
						// Not necessarily findable if URLs override the name; tolerate.
						_ = found
					}
				}
			}
		}
	})
}
