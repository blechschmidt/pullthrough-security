//go:build fuzz
// +build fuzz

// Fuzz targets for the Hugging Face pull-through parsers (Task 30, Task 110).
//
// A malicious or compromised upstream/mirror controls the git-lfs pointer body
// and (via the client) the request path. Both are parsed on the pull path before
// any content is cached or served, so the parsers must never panic, must not
// allocate without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/huggingface/
package huggingface

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/gpt2/resolve/main/config.json",
		"/bigscience/bloom/resolve/0123456789abcdef0123456789abcdef01234567/pytorch_model.bin",
		"/datasets/squad/resolve/main/data/train.parquet",
		"/spaces/o/a/resolve/main/app.py",
		"/api/models/gpt2",
		"/api/datasets/squad/revision/abc",
		"/org/model/resolve/main/../../etc/passwd",
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
		_ = res.baseFilename()
		if res.isResolve() && (res.repoID == "" || res.revision == "" || res.filepath == "") {
			t.Fatalf("accepted resolve with empty component: %q -> %+v", path, res)
		}
	})
}

func FuzzParsePointer(f *testing.F) {
	seeds := []string{
		pointerPrefix + "\noid sha256:5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c592\nsize 42\n",
		pointerPrefix + "\noid sha256:short\nsize 1\n",
		"not a pointer",
		"",
		"   \n\t  ",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		p, ok := parsePointer(body)
		if !ok {
			return
		}
		if !isSHA256Hex(p.oid) {
			t.Fatalf("parsePointer accepted a non-SHA-256 oid %q", p.oid)
		}
		if p.size < 0 {
			t.Fatalf("parsePointer accepted a negative size %d", p.size)
		}
	})
}
