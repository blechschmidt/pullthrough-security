package cache

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

// testKEK returns a random 32-byte KEK with the given id.
func testKEK(t *testing.T, id string) KEK {
	t.Helper()
	key := make([]byte, kekLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return KEK{ID: id, Key: key}
}

// newEncryptCache builds a FilesystemCache over an encrypting store rooted at a
// temp dir, returning the cache and the underlying encrypt/filesystem stores.
func newEncryptCache(t *testing.T, opts EncryptOptions) (*FilesystemCache, *encryptStore, *FilesystemStore) {
	t.Helper()
	dir := t.TempDir()
	fs, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	es, err := NewEncryptStore(fs, opts)
	if err != nil {
		t.Fatalf("NewEncryptStore: %v", err)
	}
	c, err := NewFilesystemCache(FilesystemOptions{Store: es})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, es, fs
}

func TestEncryptRoundTripSizes(t *testing.T) {
	primary := testKEK(t, "primary")
	// Exercise empty, sub-frame, exact-multiple, and multi-frame payloads so the
	// final-frame marking logic is covered in all cases.
	sizes := []int{0, 1, 100, defaultFrameSize - 1, defaultFrameSize, defaultFrameSize + 1, 3 * defaultFrameSize, 3*defaultFrameSize + 123}
	for _, n := range sizes {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			c, es, _ := newEncryptCache(t, EncryptOptions{Primary: primary})
			ctx := context.Background()
			content := make([]byte, n)
			if _, err := rand.Read(content); err != nil {
				t.Fatalf("rand: %v", err)
			}
			stat, err := c.Put(ctx, "obj", bytes.NewReader(content), map[string]string{MetaContentType: "application/octet-stream"})
			if err != nil {
				t.Fatalf("Put: %v", err)
			}
			if stat.Size != int64(n) {
				t.Fatalf("logical size = %d, want %d", stat.Size, n)
			}
			if stat.Metadata[MetaDigest] != sha256Hex(content) {
				t.Fatalf("digest not over plaintext: got %s want %s", stat.Metadata[MetaDigest], sha256Hex(content))
			}
			// The sidecar reserved keys must not leak to the caller.
			for k := range stat.Metadata {
				if strings.HasPrefix(k, pteReservedPrefix) {
					t.Fatalf("encryption sidecar key %q leaked into Stat.Metadata", k)
				}
			}

			entry, err := c.Get(ctx, "obj")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			got, err := io.ReadAll(entry.Content)
			entry.Content.Close()
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), n)
			}
			st := es.EncryptionStats()
			if st.ObjectsEncrypted != 1 || st.ObjectsDecrypted != 1 || st.DEKsWrapped != 1 {
				t.Fatalf("unexpected stats: %+v", st)
			}
			if st.BytesEncrypted != int64(n) {
				t.Fatalf("bytesEncrypted = %d, want %d", st.BytesEncrypted, n)
			}
		})
	}
}

// TestEncryptCiphertextAtRest verifies the bytes actually written to the durable
// store are not the plaintext (and carry the encryption sidecar), while the
// inner record's digest is over ciphertext (not the logical plaintext digest).
func TestEncryptCiphertextAtRest(t *testing.T) {
	primary := testKEK(t, "primary")
	_, _, fs := newEncryptCache(t, EncryptOptions{Primary: primary})
	ctx := context.Background()

	// Write directly through the fs store's sibling encrypt store by going through
	// the cache would be simplest; instead re-open an encrypt store over fs.
	es, err := NewEncryptStore(fs, EncryptOptions{Primary: primary})
	if err != nil {
		t.Fatalf("NewEncryptStore: %v", err)
	}
	content := bytes.Repeat([]byte("SENSITIVE-TOKEN-0123456789"), 500)
	rec := Record{Key: "secret"}
	if _, err := es.Put(ctx, rec, bytes.NewReader(content)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Read the raw bytes straight from the inner filesystem store: they must be
	// ciphertext (the magic header plus framed GCM output), never the plaintext.
	rc, inner, err := fs.Get(ctx, "secret")
	if err != nil {
		t.Fatalf("inner Get: %v", err)
	}
	raw, _ := io.ReadAll(rc)
	rc.Close()
	if bytes.Contains(raw, []byte("SENSITIVE-TOKEN")) {
		t.Fatalf("plaintext found in at-rest bytes")
	}
	if !bytes.HasPrefix(raw, encStreamMagic) {
		t.Fatalf("at-rest bytes missing encryption magic header")
	}
	if inner.Extra[metaEncFmt] != encFmtAES {
		t.Fatalf("inner record missing encryption format marker, got %q", inner.Extra[metaEncFmt])
	}
	if inner.Extra[metaEncDEK] == "" || inner.Extra[metaEncKEK] != "primary" {
		t.Fatalf("inner record missing wrapped DEK/KEK id: %+v", inner.Extra)
	}
	// The inner digest is computed over ciphertext; the outward projection must
	// restore it to the plaintext digest.
	if inner.Digest == sha256Hex(content) {
		t.Fatalf("inner digest unexpectedly equals plaintext digest (should be over ciphertext)")
	}
	out := es.outward(inner)
	if out.Digest != sha256Hex(content) {
		t.Fatalf("outward digest = %s, want plaintext digest %s", out.Digest, sha256Hex(content))
	}
	if out.Size != int64(len(content)) {
		t.Fatalf("outward size = %d, want %d", out.Size, len(content))
	}
}

// TestEncryptTamperDetected verifies a bit-flip in the at-rest ciphertext is
// caught by GCM authentication on read.
func TestEncryptTamperDetected(t *testing.T) {
	primary := testKEK(t, "primary")
	c, es, _ := newEncryptCache(t, EncryptOptions{Primary: primary, FrameSize: 1024})
	ctx := context.Background()
	content := bytes.Repeat([]byte("abcd"), 2000)
	if _, err := c.Put(ctx, "obj", bytes.NewReader(content), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Corrupt the stored blob directly on disk.
	path := blobFilePath(t, es, "obj")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	// Flip a byte well past the magic header (inside the first frame's ciphertext).
	raw[len(encStreamMagic)+8] ^= 0xff
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatalf("write blob: %v", err)
	}

	entry, err := c.Get(ctx, "obj")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_, err = io.ReadAll(entry.Content)
	entry.Content.Close()
	if err == nil {
		t.Fatalf("expected authentication failure reading tampered ciphertext")
	}
	if es.EncryptionStats().DecryptFailures == 0 {
		t.Fatalf("decrypt failure not counted")
	}
}

// blobFilePath returns the on-disk blob path for a key in the encrypt store's
// inner filesystem store.
func blobFilePath(t *testing.T, es *encryptStore, key string) string {
	t.Helper()
	fs, ok := es.inner.(*FilesystemStore)
	if !ok {
		t.Fatalf("inner is not a FilesystemStore")
	}
	name := storageName(key)
	return fs.blobPath(name)
}

// TestEncryptComposesWithCompaction verifies the two decorators compose: encrypt
// innermost, compaction (with dedup) outermost. Content round-trips, the digest
// is over plaintext, dedup still identifies duplicate chunks, and the at-rest
// bytes are encrypted.
func TestEncryptComposesWithCompaction(t *testing.T) {
	primary := testKEK(t, "primary")
	dir := t.TempDir()
	fs, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	es, err := NewEncryptStore(fs, EncryptOptions{Primary: primary})
	if err != nil {
		t.Fatalf("NewEncryptStore: %v", err)
	}
	cs, err := NewCompactStore(es, CompactOptions{Codec: "zstd", Level: 3, Dedup: true})
	if err != nil {
		t.Fatalf("NewCompactStore: %v", err)
	}
	c, err := NewFilesystemCache(FilesystemOptions{Store: cs})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()

	content := compressibleBlob(300 * 1024)
	for i, key := range []string{"a.tar", "b.tar"} { // identical content → dedup
		stat, err := c.Put(ctx, key, bytes.NewReader(content), map[string]string{MetaContentType: "application/x-tar"})
		if err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
		if stat.Size != int64(len(content)) {
			t.Fatalf("logical size = %d, want %d", stat.Size, len(content))
		}
		if stat.Metadata[MetaDigest] != sha256Hex(content) {
			t.Fatalf("digest not over plaintext for %s", key)
		}
		for k := range stat.Metadata {
			if strings.HasPrefix(k, pteReservedPrefix) || strings.HasPrefix(k, ptcReservedPrefix) {
				t.Fatalf("reserved key %q leaked into Stat.Metadata", k)
			}
		}
	}

	// Both keys read back the original content.
	for _, key := range []string{"a.tar", "b.tar"} {
		entry, err := c.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get %s: %v", key, err)
		}
		got, _ := io.ReadAll(entry.Content)
		entry.Content.Close()
		if !bytes.Equal(got, content) {
			t.Fatalf("round-trip mismatch for %s", key)
		}
	}

	// Dedup must have reused chunks (the second identical artifact adds no new
	// unique chunks beyond the first).
	cst := cs.CompactionStats()
	if cst.DedupChunksReused == 0 {
		t.Fatalf("expected chunk reuse across identical artifacts, stats=%+v", cst)
	}

	// Encryption stats forward through the compaction layer.
	est := cs.EncryptionStats()
	if !est.Enabled || est.ObjectsEncrypted == 0 {
		t.Fatalf("encryption stats not forwarded through compaction: %+v", est)
	}

	// At-rest chunk bytes must be ciphertext.
	recs, err := fs.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	sawChunk := false
	for _, rec := range recs {
		if rec.Extra[metaEncFmt] != encFmtAES {
			t.Fatalf("stored object %q is not encrypted at rest", rec.Key)
		}
		if strings.HasPrefix(rec.Key, chunkKeyPrefix) {
			sawChunk = true
		}
	}
	if !sawChunk {
		t.Fatalf("expected dedup chunk entries in the inner store")
	}
}

// TestEncryptCompactionReopen verifies the dedup chunk-index rebuild at startup
// works when the chunks are encrypted at rest: reopening the full
// cache→compaction→encrypt→filesystem stack re-warms the index and serves the
// original content.
func TestEncryptCompactionReopen(t *testing.T) {
	primary := testKEK(t, "primary")
	dir := t.TempDir()
	ctx := context.Background()
	content := compressibleBlob(400 * 1024)

	build := func() (*FilesystemCache, func()) {
		fs, err := NewFilesystemStore(dir)
		if err != nil {
			t.Fatalf("NewFilesystemStore: %v", err)
		}
		es, err := NewEncryptStore(fs, EncryptOptions{Primary: primary})
		if err != nil {
			t.Fatalf("NewEncryptStore: %v", err)
		}
		cs, err := NewCompactStore(es, CompactOptions{Codec: "zstd", Level: 3, Dedup: true})
		if err != nil {
			t.Fatalf("NewCompactStore: %v", err)
		}
		c, err := NewFilesystemCache(FilesystemOptions{Store: cs})
		if err != nil {
			t.Fatalf("NewFilesystemCache: %v", err)
		}
		return c, func() { _ = c.Close() }
	}

	c1, close1 := build()
	if _, err := c1.Put(ctx, "pkg.tar", bytes.NewReader(content), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	close1()

	// Reopen over the existing on-disk store; the dedup index rebuild must walk the
	// encrypted chunk/manifest entries without decrypting them.
	c2, close2 := build()
	defer close2()
	entry, err := c2.Get(ctx, "pkg.tar")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	got, _ := io.ReadAll(entry.Content)
	entry.Content.Close()
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch after reopen")
	}
}

// TestEncryptLegacyPlaintextPassthrough verifies that entries written without
// encryption (e.g. before it was enabled) still read back when the layer is
// later added, since they lack the encryption sidecar.
func TestEncryptLegacyPlaintextPassthrough(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	ctx := context.Background()
	content := []byte("plain legacy content")
	if _, err := fs.Put(ctx, Record{Key: "legacy"}, bytes.NewReader(content)); err != nil {
		t.Fatalf("inner Put: %v", err)
	}

	es, err := NewEncryptStore(fs, EncryptOptions{Primary: testKEK(t, "primary")})
	if err != nil {
		t.Fatalf("NewEncryptStore: %v", err)
	}
	rc, rec, err := es.Get(ctx, "legacy")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, content) {
		t.Fatalf("legacy passthrough mismatch: %q", got)
	}
	if rec.Digest != sha256Hex(content) {
		t.Fatalf("legacy digest mismatch")
	}
}

// TestEncryptKEKRotation verifies that rotating the KEK re-wraps every object's
// data key to the new primary without re-encrypting payloads (ciphertext bytes
// unchanged), and that content still round-trips afterward.
func TestEncryptKEKRotation(t *testing.T) {
	oldKEK := testKEK(t, "2024")
	newKEK := testKEK(t, "2025")
	ctx := context.Background()

	dir := t.TempDir()
	fs, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	// Phase 1: write objects under the old KEK as primary.
	es1, err := NewEncryptStore(fs, EncryptOptions{Primary: oldKEK})
	if err != nil {
		t.Fatalf("NewEncryptStore phase1: %v", err)
	}
	contents := map[string][]byte{}
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("obj-%d", i)
		data := make([]byte, 50*1024+i)
		rand.Read(data)
		contents[key] = data
		if _, err := es1.Put(ctx, Record{Key: key}, bytes.NewReader(data)); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}
	// Capture ciphertext for one object to prove it is unchanged after rotation.
	before, err := os.ReadFile(blobFilePath(t, es1, "obj-0"))
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}

	// Phase 2: new primary KEK, old KEK retained for unwrap. Rotate.
	es2, err := NewEncryptStore(fs, EncryptOptions{Primary: newKEK, Previous: []KEK{oldKEK}})
	if err != nil {
		t.Fatalf("NewEncryptStore phase2: %v", err)
	}
	rep, err := es2.RotateKEK(ctx)
	if err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}
	if rep.Unsupported {
		t.Fatalf("rotation unexpectedly unsupported on filesystem store")
	}
	if rep.Rewrapped != 5 || rep.Errors != 0 {
		t.Fatalf("rotation report = %+v, want 5 rewrapped and 0 errors", rep)
	}

	// Ciphertext payload must be byte-for-byte unchanged (only the sidecar changed).
	after, err := os.ReadFile(blobFilePath(t, es2, "obj-0"))
	if err != nil {
		t.Fatalf("read blob after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("rotation re-encrypted the payload (ciphertext changed)")
	}

	// Every object must now be wrapped by the new KEK and still round-trip.
	recs, _ := fs.List(ctx)
	for _, rec := range recs {
		if rec.Extra[metaEncKEK] != "2025" {
			t.Fatalf("object %q still wrapped by %q after rotation", rec.Key, rec.Extra[metaEncKEK])
		}
	}
	for key, want := range contents {
		rc, _, err := es2.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get %s: %v", key, err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, want) {
			t.Fatalf("content mismatch for %s after rotation", key)
		}
	}

	// A second rotation is a no-op (all already current).
	rep2, err := es2.RotateKEK(ctx)
	if err != nil {
		t.Fatalf("RotateKEK 2: %v", err)
	}
	if rep2.Rewrapped != 0 || rep2.AlreadyCurrent != 5 {
		t.Fatalf("second rotation = %+v, want 0 rewrapped / 5 already current", rep2)
	}
}

// TestEncryptMissingKEKFails verifies that an object whose wrapping KEK is not
// configured cannot be read and is reported as an error during rotation.
func TestEncryptMissingKEKFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fs, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	es1, err := NewEncryptStore(fs, EncryptOptions{Primary: testKEK(t, "ghost")})
	if err != nil {
		t.Fatalf("NewEncryptStore: %v", err)
	}
	if _, err := es1.Put(ctx, Record{Key: "obj"}, bytes.NewReader([]byte("data"))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// New store without the "ghost" key configured.
	es2, err := NewEncryptStore(fs, EncryptOptions{Primary: testKEK(t, "other")})
	if err != nil {
		t.Fatalf("NewEncryptStore: %v", err)
	}
	if _, _, err := es2.Get(ctx, "obj"); err == nil {
		t.Fatalf("expected Get to fail without the wrapping KEK")
	}
	rep, err := es2.RotateKEK(ctx)
	if err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}
	if rep.Errors != 1 || rep.Rewrapped != 0 {
		t.Fatalf("rotation report = %+v, want 1 error", rep)
	}
}

func TestDeriveKEK(t *testing.T) {
	raw := make([]byte, kekLen)
	rand.Read(raw)
	b64 := base64.StdEncoding.EncodeToString(raw)

	k, err := DeriveKEK("id", b64, "base64")
	if err != nil || !bytes.Equal(k, raw) {
		t.Fatalf("base64 derive: %v / equal=%v", err, bytes.Equal(k, raw))
	}
	if _, err := DeriveKEK("id", "short", "base64"); err == nil {
		t.Fatalf("expected error for short base64 key")
	}
	// Passphrase derivation is deterministic per (phrase, id) and 32 bytes.
	p1, err := DeriveKEK("saltA", "correct horse battery staple", "passphrase")
	if err != nil || len(p1) != kekLen {
		t.Fatalf("passphrase derive: %v len=%d", err, len(p1))
	}
	p2, _ := DeriveKEK("saltA", "correct horse battery staple", "passphrase")
	if !bytes.Equal(p1, p2) {
		t.Fatalf("passphrase derivation not deterministic")
	}
	pOther, _ := DeriveKEK("saltB", "correct horse battery staple", "passphrase")
	if bytes.Equal(p1, pOther) {
		t.Fatalf("different salt (id) must yield different key")
	}
	if _, err := DeriveKEK("id", "x", "bogus"); err == nil {
		t.Fatalf("expected error for unknown encoding")
	}
}

func TestNewEncryptStoreValidation(t *testing.T) {
	fs, _ := NewFilesystemStore(t.TempDir())
	// Wrong key length.
	if _, err := NewEncryptStore(fs, EncryptOptions{Primary: KEK{ID: "p", Key: []byte("tooshort")}}); err == nil {
		t.Fatalf("expected error for short primary key")
	}
	// Empty primary id.
	if _, err := NewEncryptStore(fs, EncryptOptions{Primary: KEK{Key: make([]byte, kekLen)}}); err == nil {
		t.Fatalf("expected error for empty primary id")
	}
	// Duplicate id between primary and previous.
	if _, err := NewEncryptStore(fs, EncryptOptions{
		Primary:  KEK{ID: "dup", Key: make([]byte, kekLen)},
		Previous: []KEK{{ID: "dup", Key: make([]byte, kekLen)}},
	}); err == nil {
		t.Fatalf("expected error for duplicate KEK id")
	}
}

// TestEncryptConcurrent exercises concurrent writes, reads, stat/stats reads, and
// a KEK rotation under the race detector.
func TestEncryptConcurrent(t *testing.T) {
	oldKEK := testKEK(t, "v1")
	newKEK := testKEK(t, "v2")
	ctx := context.Background()

	dir := t.TempDir()
	fs, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	// Seed some objects under the old KEK, then open a store with both keys that
	// writes under the new KEK and can unwrap the old.
	seed, err := NewEncryptStore(fs, EncryptOptions{Primary: oldKEK})
	if err != nil {
		t.Fatalf("seed store: %v", err)
	}
	const seeded = 20
	for i := 0; i < seeded; i++ {
		data := []byte(fmt.Sprintf("seed-%d-%s", i, strings.Repeat("x", i*37)))
		if _, err := seed.Put(ctx, Record{Key: fmt.Sprintf("seed-%d", i)}, bytes.NewReader(data)); err != nil {
			t.Fatalf("seed Put: %v", err)
		}
	}

	es, err := NewEncryptStore(fs, EncryptOptions{Primary: newKEK, Previous: []KEK{oldKEK}})
	if err != nil {
		t.Fatalf("NewEncryptStore: %v", err)
	}

	var wg sync.WaitGroup
	// Writers of fresh objects.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				data := []byte(fmt.Sprintf("w%d-i%d-%s", w, i, strings.Repeat("y", (w+i)%200)))
				key := fmt.Sprintf("new-%d-%d", w, i)
				if _, err := es.Put(ctx, Record{Key: key}, bytes.NewReader(data)); err != nil {
					t.Errorf("Put: %v", err)
					return
				}
				rc, _, err := es.Get(ctx, key)
				if err != nil {
					t.Errorf("Get: %v", err)
					return
				}
				got, _ := io.ReadAll(rc)
				rc.Close()
				if !bytes.Equal(got, data) {
					t.Errorf("round-trip mismatch for %s", key)
					return
				}
			}
		}(w)
	}
	// Readers of the seeded objects (wrapped under the old KEK).
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < seeded; i++ {
				rc, _, err := es.Get(ctx, fmt.Sprintf("seed-%d", i))
				if err != nil {
					t.Errorf("seed Get: %v", err)
					return
				}
				io.Copy(io.Discard, rc)
				rc.Close()
			}
		}()
	}
	// Stats samplers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = es.EncryptionStats()
		}
	}()
	// A rotation running concurrently with the above (re-wraps the seeded objects).
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := es.RotateKEK(ctx); err != nil {
			t.Errorf("RotateKEK: %v", err)
		}
	}()

	wg.Wait()

	// After the dust settles, every seeded object must still decrypt (it is either
	// still wrapped by the old KEK — which es can unwrap — or re-wrapped to new).
	for i := 0; i < seeded; i++ {
		rc, _, err := es.Get(ctx, fmt.Sprintf("seed-%d", i))
		if err != nil {
			t.Fatalf("post-rotation seed Get %d: %v", i, err)
		}
		rc.Close()
	}
}
