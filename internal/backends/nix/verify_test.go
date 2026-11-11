package nix

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A NAR's name is a content address, and caches differ in what it addresses:
// the file as stored (Nix's own layout, the xz NARs of older channels) or the
// NAR itself, uncompressed (the zstd NARs cache.nixos.org serves for current
// channels, named by the narinfo's NarHash). These tests use NARs written by
// nix-store and compressed by the real tools (the shared unpack layer's
// fixtures), served under both names.

func narFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "contentscan", "testdata", "formats", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return data
}

func b32(data []byte) string {
	sum := sha256.Sum256(data)
	return nixBase32Encode(sum[:])
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestNarNamedByTheHashOfItsUncompressedContent(t *testing.T) {
	nar := narFixture(t, "hello.nar")
	contentHash := b32(nar)

	for _, tc := range []struct {
		ext  string
		file []byte
	}{
		{".zst", narFixture(t, "hello.nar.zst")},
		{".xz", narFixture(t, "hello.nar.xz")},
		{".bz2", narFixture(t, "hello.nar.bz2")},
		{".gz", gzipBytes(t, nar)},
	} {
		t.Run("named by NarHash"+tc.ext, func(t *testing.T) {
			if b32(tc.file) == contentHash {
				t.Fatal("fixture: the compressed file hashes like its content")
			}
			fc := newFakeCache(t)
			path := "/nar/" + contentHash + ".nar" + tc.ext
			fc.files[path] = tc.file
			m := &Metrics{}
			b := newTestBackend(t, fc, nil, m)

			_, body, err := resolveFetch(t, b, path)
			if err != nil {
				t.Fatalf("a NAR named by the hash of its uncompressed content was refused: %v", err)
			}
			if !bytes.Equal(body, tc.file) {
				t.Fatal("the served bytes are not the file")
			}
			if st := m.Stats(); st.NarsVerified != 1 || st.NarsVerifiedByContent != 1 || st.FileHashMismatch != 0 {
				t.Errorf("metrics = %+v, want one NAR verified by its content", st)
			}
		})
		t.Run("named by FileHash"+tc.ext, func(t *testing.T) {
			fc := newFakeCache(t)
			path := "/nar/" + b32(tc.file) + ".nar" + tc.ext
			fc.files[path] = tc.file
			m := &Metrics{}
			b := newTestBackend(t, fc, nil, m)
			if _, _, err := resolveFetch(t, b, path); err != nil {
				t.Fatalf("a NAR named by the hash of the file was refused: %v", err)
			}
			if st := m.Stats(); st.NarsVerified != 1 || st.NarsVerifiedByContent != 0 {
				t.Errorf("metrics = %+v, want one NAR verified by its file hash", st)
			}
		})
	}

	// An uncompressed NAR is its own content.
	fc := newFakeCache(t)
	path := "/nar/" + contentHash + ".nar"
	fc.files[path] = nar
	m := &Metrics{}
	if _, _, err := resolveFetch(t, newTestBackend(t, fc, nil, m), path); err != nil {
		t.Fatalf("uncompressed NAR: %v", err)
	}
	if st := m.Stats(); st.NarsVerified != 1 || st.NarsVerifiedByContent != 0 {
		t.Errorf("metrics = %+v", st)
	}
}

// Accepting two readings of the name must not accept bytes that are neither.
func TestNarThatMatchesNeitherReadingIsRefused(t *testing.T) {
	nar := narFixture(t, "hello.nar")
	contentHash := b32(nar)
	zst := narFixture(t, "hello.nar.zst")
	other := narFixture(t, "single.nar")

	for _, tc := range []struct {
		name        string
		path        string
		file        []byte
		wantContent bool // the error reports the content hash it computed
	}{
		{"another NAR's content under this name", "/nar/" + contentHash + ".nar.gz", gzipBytes(t, other), true},
		{"bytes after the compressed stream", "/nar/" + contentHash + ".nar.zst", append(append([]byte(nil), zst...), "trailing bytes the digest does not cover"...), false},
		{"a compressed stream cut short", "/nar/" + contentHash + ".nar.zst", zst[:len(zst)-9], false},
		{"not compressed at all, despite the name", "/nar/" + contentHash + ".nar.zst", []byte("just some bytes that are no zstd stream"), false},
		{"the right content under a compression the backend does not decode", "/nar/" + contentHash + ".nar.br", zst, false},
		{"an uncompressed name on compressed bytes", "/nar/" + contentHash + ".nar", zst, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeCache(t)
			fc.files[tc.path] = tc.file
			m := &Metrics{}
			b := newTestBackend(t, fc, nil, m)
			_, _, err := resolveFetch(t, b, tc.path)
			var mm *FileHashMismatchError
			if !errors.As(err, &mm) {
				t.Fatalf("error = %v, want *FileHashMismatchError", err)
			}
			if mm.Actual != "sha256:"+b32(tc.file) {
				t.Errorf("the error reports file hash %s, want that of the bytes served", mm.Actual)
			}
			if (mm.ActualContent != "") != tc.wantContent {
				t.Errorf("the error's content hash = %q, want reported: %v", mm.ActualContent, tc.wantContent)
			}
			if st := m.Stats(); st.FileHashMismatch != 1 || st.NarsVerified != 0 || st.NarsVerifiedByContent != 0 {
				t.Errorf("metrics = %+v, want one mismatch", st)
			}
		})
	}
}

// The content is hashed on a goroutine fed through a pipe. A body that is read
// in small pieces, abandoned half-way, or closed twice must neither block nor
// leave that goroutine behind.
func TestNarVerifierDoesNotLeakOrBlock(t *testing.T) {
	zst := narFixture(t, "hello.nar.zst")
	contentHash := b32(narFixture(t, "hello.nar"))
	before := runtime.NumGoroutine()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			// Read to the end, one byte at a time.
			v := newFileHashVerifier(io.NopCloser(bytes.NewReader(zst)), contentHash, "x.nar.zst", "u", ".zst", nil)
			if _, err := io.Copy(io.Discard, iotestOneByte{v}); err != nil {
				t.Errorf("one byte at a time: %v", err)
			}
			_ = v.Close()
			_ = v.Close()

			// Abandoned after the first few bytes.
			v = newFileHashVerifier(io.NopCloser(bytes.NewReader(zst)), contentHash, "x.nar.zst", "u", ".zst", nil)
			_, _ = io.ReadFull(v, make([]byte, 16))
			_ = v.Close()

			// Never read at all.
			v = newFileHashVerifier(io.NopCloser(strings.NewReader("")), contentHash, "x.nar.zst", "u", ".zst", nil)
			_ = v.Close()

			// Bytes that are no compressed stream: the hasher gives up at once, and
			// the rest must still flow through.
			junk := bytes.Repeat([]byte("not zstd "), 4096)
			v = newFileHashVerifier(io.NopCloser(bytes.NewReader(junk)), b32(junk), "x.nar.zst", "u", ".zst", nil)
			if _, err := io.Copy(io.Discard, v); err != nil {
				t.Errorf("a file-hash-named body that does not decompress: %v", err)
			}
			_ = v.Close()
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the verifier blocked")
	}
	// The hashing goroutines have all returned.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+2 {
		t.Errorf("goroutines: %d before, %d after — the content hasher was left running", before, n)
	}
}

// iotestOneByte reads one byte per call.
type iotestOneByte struct{ r io.Reader }

func (o iotestOneByte) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}
