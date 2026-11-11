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
	"os"
	"path/filepath"
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

// FuzzWalkArtifact drives every container the walker understands — tar under
// each compression, zip, ar/.deb, RPM (both payload dialects), cpio, NAR, and
// archives nested in archives — with the options a caller can switch on. It is
// seeded with the fixtures the real packaging tools wrote, so the fuzzer starts
// from valid archives of every format and mutates from there.
//
// Beyond "does not panic, does terminate" it checks the walker's own promises:
// no more members than the limit, no member larger than the per-file cap, and a
// decompressed total within the cap (plus the one read that crossed it).
func FuzzWalkArtifact(f *testing.F) {
	seeds, _ := filepath.Glob(filepath.Join("testdata", "formats", "*"))
	for _, seed := range seeds {
		if data, err := os.ReadFile(seed); err == nil {
			f.Add(data, uint8(2), true)
		}
	}
	f.Add([]byte("!<arch>\ndebian-binary   0           0     0     100644  4         `\n2.0\n"), uint8(1), false)
	f.Add([]byte("07070X00000000\x00\x00"), uint8(0), true)
	f.Add(append(append([]byte(nil), narMagic...), 1, 0, 0, 0, 0, 0, 0, 0, '('), uint8(0), true)
	f.Add([]byte{0xed, 0xab, 0xee, 0xdb, 3, 0}, uint8(4), false)
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xa0, 0x01, 0x00, 0x00}, uint8(0), true)
	f.Add([]byte("\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4F\x02\x00!\x01\x28\x00\x00\x00"), uint8(0), true)

	const (
		maxFiles    = 200
		maxFile     = 4 << 10
		maxUnpacked = 4 << 20
	)
	f.Fuzz(func(t *testing.T, data []byte, nested uint8, single bool) {
		lim := ArchiveLimits{MaxArchiveBytes: 1 << 20, MaxUnpackedBytes: maxUnpacked, MaxFileBytes: maxFile, MaxFiles: maxFiles, MaxCompressionRatio: 100}
		members := 0
		stats, _ := WalkArtifact(context.Background(), bytes.NewReader(data), lim,
			ArchiveOptions{Filename: "artifact.bin.gz", SingleFile: single, NestedDepth: int(nested % 8)},
			func(e ArchiveEntry) bool {
				if !e.Synthetic {
					members++
				}
				if len(e.Data) > maxFile {
					t.Fatalf("member %q holds %d bytes, over the %d-byte cap", e.Name, len(e.Data), maxFile)
				}
				if e.Size < 0 {
					t.Fatalf("member %q has negative size %d", e.Name, e.Size)
				}
				return true
			},
			func(ArchiveLink) {})
		if members > maxFiles {
			t.Fatalf("%d members reported, over the limit of %d", members, maxFiles)
		}
		// One read may cross the cap before the guard stops the stream.
		if stats.UnpackedBytes > maxUnpacked+(1<<20) {
			t.Fatalf("%d bytes decompressed, far over the %d-byte cap", stats.UnpackedBytes, maxUnpacked)
		}
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
