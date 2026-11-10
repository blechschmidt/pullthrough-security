//go:build fuzz
// +build fuzz

// Fuzz targets for the package-content analysis unpack/scan parsers (Task 138,
// mirroring the Task 30 harness).
//
// Every parser here consumes bytes that originate from an untrusted upstream
// artifact — a whole package archive (tar.gz / zip / gem), a file's raw bytes,
// or arbitrary text. They must never panic, must bound their work, and must
// terminate on hostile input (truncated archives, tar/zip bombs, pathological
// minified blobs). The targets assert only "does not panic / does terminate";
// correctness is covered by the deterministic golden tests.
package contentscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"
)

func fuzzOpener(b []byte) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
}

func FuzzAssess(f *testing.F) {
	svc, err := NewService(DefaultConfig())
	if err != nil {
		f.Fatal(err)
	}
	// Seed with a real npm-style tarball, a gem, a zip, and hostile fragments.
	f.Add(tarGzSeed(map[string][]byte{"package/index.js": []byte("eval(atob('x'))"), "package/p.node": {0x7f, 'E', 'L', 'F'}}), "npm")
	f.Add([]byte("not a tar at all"), "pip")
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}, "cargo")
	f.Add([]byte{'P', 'K', 0x03, 0x04}, "composer")
	f.Add([]byte{}, "npm")
	f.Fuzz(func(t *testing.T, data []byte, eco string) {
		rep, aerr := svc.Assess(context.Background(), Artifact{Ecosystem: eco, Name: "x", Version: "1"}, fuzzOpener(data))
		if aerr != nil {
			return
		}
		for i := range rep.Findings {
			_ = rep.Findings[i].Excerpt
		}
		_ = svc.Gate(rep)
	})
}

func FuzzWalkArchive(f *testing.F) {
	f.Add([]byte{0x1f, 0x8b, 0x08})
	f.Add([]byte("random bytes"))
	f.Fuzz(func(t *testing.T, data []byte) {
		b := budget{maxArchiveBytes: 1 << 20, maxFileBytes: 1 << 16, maxFiles: 1000}
		_, _ = walkArchive(context.Background(), bytes.NewReader(data), b, func(wf walkedFile) bool {
			_ = byteEntropy(wf.data)
			return true
		})
	})
}

func FuzzObfuscatedJS(f *testing.F) {
	f.Add("eval(atob('Zm9v'))")
	f.Add("var a=1;")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_, _, _ = obfuscatedJS(s)
		_, _ = minifiedStats(s)
	})
}

func FuzzScanExecLine(f *testing.F) {
	f.Add(".py", "os.system('x')")
	f.Add(".js", "eval(x)")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, ext, line string) {
		_ = scanExecLine(ext, line)
	})
}

func FuzzSynthesizeAddedPatch(f *testing.F) {
	f.Add("a\nb\n")
	f.Add("")
	f.Add("\n\n\n")
	f.Fuzz(func(t *testing.T, s string) {
		_ = synthesizeAddedPatch(s)
		_ = looksTextual([]byte(s))
	})
}

// tarGzSeed builds a seed tarball for the fuzz corpus (the *testing.T helper in
// the main test file is unavailable to a seed expression).
func tarGzSeed(files map[string][]byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, data := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}
