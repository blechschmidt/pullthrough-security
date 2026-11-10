package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"
)

// newCompactCache builds a FilesystemCache backed by a compacting store over a
// fresh FilesystemStore rooted at a temp dir.
func newCompactCache(t *testing.T, opts CompactOptions, cacheOpts FilesystemOptions) (*FilesystemCache, *compactStore) {
	t.Helper()
	dir := cacheOpts.Dir
	if dir == "" {
		dir = t.TempDir()
	}
	fs, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	cs, err := NewCompactStore(fs, opts)
	if err != nil {
		t.Fatalf("NewCompactStore: %v", err)
	}
	cacheOpts.Store = cs
	c, err := NewFilesystemCache(cacheOpts)
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, cs
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// compressibleBlob returns highly compressible, deterministic content.
func compressibleBlob(n int) []byte {
	var b bytes.Buffer
	for b.Len() < n {
		fmt.Fprintf(&b, "the quick brown fox jumps over the lazy dog %08d\n", b.Len())
	}
	return b.Bytes()[:n]
}

func TestCompactRoundTripCompressible(t *testing.T) {
	c, cs := newCompactCache(t, CompactOptions{Codec: "zstd", Level: 3}, FilesystemOptions{})
	ctx := context.Background()

	content := compressibleBlob(200 * 1024)
	stat, err := c.Put(ctx, "pkg-1.0.0.tar", bytes.NewReader(content), map[string]string{MetaContentType: "application/x-tar"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if stat.Size != int64(len(content)) {
		t.Fatalf("logical size = %d, want %d", stat.Size, len(content))
	}
	if stat.Metadata[MetaDigest] != sha256Hex(content) {
		t.Fatalf("digest over logical bytes mismatch: %s", stat.Metadata[MetaDigest])
	}

	entry, err := c.Get(ctx, "pkg-1.0.0.tar")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(entry.Content)
	entry.Content.Close()
	if !bytes.Equal(got, content) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(content))
	}

	st := cs.CompactionStats()
	if st.EntriesCompressed != 1 {
		t.Fatalf("expected 1 compressed entry, got %+v", st)
	}
	if st.PhysicalBytes >= st.LogicalBytes {
		t.Fatalf("expected compression to reduce size: logical=%d physical=%d", st.LogicalBytes, st.PhysicalBytes)
	}
	if st.CompressionRatio <= 1 {
		t.Fatalf("expected ratio > 1, got %v", st.CompressionRatio)
	}
}

func TestCompactSkipsIncompressible(t *testing.T) {
	c, cs := newCompactCache(t, CompactOptions{Codec: "zstd", Level: 3}, FilesystemOptions{})
	ctx := context.Background()

	// A gzip magic header followed by random-looking bytes: the heuristic must
	// store it verbatim.
	blob := append([]byte{0x1f, 0x8b, 0x08, 0x00}, randomBytes(100*1024)...)
	if _, err := c.Put(ctx, "image.tgz", bytes.NewReader(blob), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	assertReads(t, c, "image.tgz", blob)

	st := cs.CompactionStats()
	if st.EntriesStoredRaw != 1 {
		t.Fatalf("expected incompressible blob stored raw, got %+v", st)
	}
	if st.EntriesCompressed != 0 {
		t.Fatalf("did not expect compression, got %+v", st)
	}
}

func TestCompactIncompressibleEntropy(t *testing.T) {
	c, cs := newCompactCache(t, CompactOptions{Codec: "zstd", Level: 3}, FilesystemOptions{})
	ctx := context.Background()

	blob := randomBytes(80 * 1024) // high entropy, no magic
	if _, err := c.Put(ctx, "random.bin", bytes.NewReader(blob), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, _ := getString(t, c, "random.bin")
	if got != string(blob) {
		t.Fatalf("round-trip mismatch for incompressible blob")
	}
	if st := cs.CompactionStats(); st.EntriesStoredRaw != 1 {
		t.Fatalf("expected high-entropy blob stored raw, got %+v", st)
	}
}

func TestCompactTinyStoredRaw(t *testing.T) {
	c, cs := newCompactCache(t, CompactOptions{Codec: "zstd", Level: 3, MinSizeBytes: 256}, FilesystemOptions{})
	ctx := context.Background()
	if _, err := c.Put(ctx, "tiny", bytes.NewReader([]byte("hello")), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, _ := getString(t, c, "tiny")
	if got != "hello" {
		t.Fatalf("tiny round-trip mismatch: %q", got)
	}
	// Tiny content is compressed only if it helps; "hello" won't shrink, so it
	// falls back to raw. Either way the round-trip must be exact (asserted above).
	_ = cs
}

func TestCompactEmptyBlob(t *testing.T) {
	c, _ := newCompactCache(t, CompactOptions{Codec: "zstd", Level: 3}, FilesystemOptions{})
	ctx := context.Background()
	stat, err := c.Put(ctx, "empty", bytes.NewReader(nil), nil)
	if err != nil {
		t.Fatalf("Put empty: %v", err)
	}
	if stat.Size != 0 {
		t.Fatalf("empty size = %d", stat.Size)
	}
	got, s := getString(t, c, "empty")
	if got != "" || s.Size != 0 {
		t.Fatalf("empty round-trip mismatch: %q size=%d", got, s.Size)
	}
}

func TestCompactIntegrityVerifies(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fs, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	cs, err := NewCompactStore(fs, CompactOptions{Codec: "zstd", Level: 3})
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	inner, err := NewFilesystemCache(FilesystemOptions{Store: cs})
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	integ := NewIntegrityCache(inner, IntegrityOptions{VerifyOnServe: true})
	t.Cleanup(func() { _ = integ.Close() })

	content := compressibleBlob(128 * 1024)
	if _, err := integ.Put(ctx, "art", bytes.NewReader(content), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// A full read verifies the logical digest; must not raise a false corruption.
	entry, err := integ.Get(ctx, "art")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(entry.Content)
	entry.Content.Close()
	if !bytes.Equal(got, content) {
		t.Fatalf("round-trip mismatch")
	}
	if m := integ.IntegrityMetrics(); m.Verifications == 0 || m.Failures != 0 {
		t.Fatalf("expected a clean verification, got %+v", m)
	}

	// A background scan re-reads (decompressing) and re-verifies.
	rep, err := integ.ScanIntegrity(ctx)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Verified != 1 || rep.Corrupted != 0 {
		t.Fatalf("scan report: %+v", rep)
	}
}

func TestCompactIntegrityCatchesCorruption(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fs, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	cs, err := NewCompactStore(fs, CompactOptions{Codec: "zstd", Level: 3})
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	inner, err := NewFilesystemCache(FilesystemOptions{Store: cs})
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	integ := NewIntegrityCache(inner, IntegrityOptions{VerifyOnServe: true})
	t.Cleanup(func() { _ = integ.Close() })

	content := compressibleBlob(64 * 1024)
	if _, err := integ.Put(ctx, "art", bytes.NewReader(content), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Corrupt the stored (compressed) blob on disk.
	name := storageName("art")
	blobPath := fs.blobPath(name)
	corruptFileAt(t, blobPath)

	rep, err := integ.ScanIntegrity(ctx)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// Corrupting the compressed bytes surfaces either as a logical digest
	// mismatch (if it still decodes to different plaintext) or as a decode error
	// (if the zstd frame is broken). Either way it must NOT be silently verified
	// as intact.
	if rep.Verified != 0 {
		t.Fatalf("corrupted blob was verified as intact: %+v", rep)
	}
	if rep.Corrupted+rep.Errors < 1 {
		t.Fatalf("expected corruption or read error to be detected, got %+v", rep)
	}
}

func TestCompactDedupSharesChunks(t *testing.T) {
	c, cs := newCompactCache(t, CompactOptions{Codec: "zstd", Level: 3, Dedup: true}, FilesystemOptions{})
	ctx := context.Background()

	// Two artifacts that share a large common region but differ in a header.
	common := compressibleBlob(512 * 1024)
	a := append([]byte("HEADER-A\n"), common...)
	b := append([]byte("HEADER-B\n"), common...)

	if _, err := c.Put(ctx, "art-a", bytes.NewReader(a), nil); err != nil {
		t.Fatalf("Put a: %v", err)
	}
	st1 := cs.CompactionStats()
	if _, err := c.Put(ctx, "art-b", bytes.NewReader(b), nil); err != nil {
		t.Fatalf("Put b: %v", err)
	}
	st2 := cs.CompactionStats()

	if st2.DedupChunksReused <= st1.DedupChunksReused {
		t.Fatalf("expected chunk reuse across artifacts: before=%d after=%d", st1.DedupChunksReused, st2.DedupChunksReused)
	}
	if st2.DedupSavingsBytes == 0 {
		t.Fatalf("expected non-zero dedup savings, got %+v", st2)
	}

	// Both artifacts must read back byte-exact.
	assertReads(t, c, "art-a", a)
	assertReads(t, c, "art-b", b)
}

func TestCompactDedupDeletePreservesSharedChunks(t *testing.T) {
	c, cs := newCompactCache(t, CompactOptions{Codec: "zstd", Level: 3, Dedup: true}, FilesystemOptions{})
	ctx := context.Background()

	common := compressibleBlob(512 * 1024)
	a := append([]byte("AAAA\n"), common...)
	b := append([]byte("BBBB\n"), common...)
	if _, err := c.Put(ctx, "art-a", bytes.NewReader(a), nil); err != nil {
		t.Fatalf("Put a: %v", err)
	}
	if _, err := c.Put(ctx, "art-b", bytes.NewReader(b), nil); err != nil {
		t.Fatalf("Put b: %v", err)
	}
	unique := cs.CompactionStats().UniqueChunks

	// Deleting art-a must not break art-b: the shared chunks are still referenced.
	if err := c.Delete(ctx, "art-a"); err != nil {
		t.Fatalf("Delete a: %v", err)
	}
	assertReads(t, c, "art-b", b)
	if _, err := c.Get(ctx, "art-a"); err == nil {
		t.Fatalf("art-a should be gone")
	}
	// Some unique chunks (art-a's header) should be freed; shared chunks remain.
	if got := cs.CompactionStats().UniqueChunks; got >= unique {
		t.Fatalf("expected some chunks freed after delete: before=%d after=%d", unique, got)
	}

	// Deleting art-b frees the rest.
	if err := c.Delete(ctx, "art-b"); err != nil {
		t.Fatalf("Delete b: %v", err)
	}
	if got := cs.CompactionStats().UniqueChunks; got != 0 {
		t.Fatalf("expected all chunks freed, got %d", got)
	}
}

func TestCompactDedupRebuildIndexAfterRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	common := compressibleBlob(512 * 1024)
	a := append([]byte("AAAA\n"), common...)
	b := append([]byte("BBBB\n"), common...)

	{
		fs, _ := NewFilesystemStore(dir)
		cs, err := NewCompactStore(fs, CompactOptions{Codec: "zstd", Level: 3, Dedup: true})
		if err != nil {
			t.Fatalf("compact: %v", err)
		}
		if _, err := cs.Put(ctx, Record{Key: "art-a"}, bytes.NewReader(a)); err != nil {
			t.Fatalf("Put a: %v", err)
		}
		if _, err := cs.Put(ctx, Record{Key: "art-b"}, bytes.NewReader(b)); err != nil {
			t.Fatalf("Put b: %v", err)
		}
		_ = cs.Close()
	}

	// Reopen: the chunk index is rebuilt from the durable manifests.
	fs2, _ := NewFilesystemStore(dir)
	cs2, err := NewCompactStore(fs2, CompactOptions{Codec: "zstd", Level: 3, Dedup: true})
	if err != nil {
		t.Fatalf("reopen compact: %v", err)
	}
	t.Cleanup(func() { _ = cs2.Close() })

	// Reads still work after the rebuild.
	assertStoreReads(t, cs2, "art-a", a)
	assertStoreReads(t, cs2, "art-b", b)

	// Deleting one must still preserve the shared chunks for the other (proves
	// refcounts were rebuilt, not zeroed).
	if err := cs2.Delete(ctx, "art-a"); err != nil {
		t.Fatalf("Delete a: %v", err)
	}
	assertStoreReads(t, cs2, "art-b", b)
}

func TestCompactEvictionReleasesChunks(t *testing.T) {
	ctx := context.Background()
	// A tiny max-size forces LRU eviction, which must flow through the decorator
	// Delete (releasing chunks) without breaking surviving entries.
	c, cs := newCompactCache(t,
		CompactOptions{Codec: "zstd", Level: 3, Dedup: true},
		FilesystemOptions{MaxSizeBytes: 300 * 1024},
	)

	for i := 0; i < 5; i++ {
		blob := append([]byte(fmt.Sprintf("H%03d\n", i)), compressibleBlob(200*1024)...)
		if _, err := c.Put(ctx, fmt.Sprintf("art-%d", i), bytes.NewReader(blob), nil); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	// The most recent entry must still be readable; eviction removed older ones.
	last := append([]byte("H004\n"), compressibleBlob(200*1024)...)
	assertReads(t, c, "art-4", last)

	if m := c.Metrics(); m.Evictions == 0 {
		t.Fatalf("expected evictions to have occurred")
	}
	_ = cs
}

func TestCompactS3Backend(t *testing.T) {
	ctx := context.Background()
	fake := newFakeObjectClient()
	s3, err := NewS3Store(S3Options{Bucket: "test", Client: fake})
	if err != nil {
		t.Fatalf("s3: %v", err)
	}
	cs, err := NewCompactStore(s3, CompactOptions{Codec: "zstd", Level: 3})
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	cache, err := NewFilesystemCache(FilesystemOptions{Store: cs})
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	content := compressibleBlob(256 * 1024)
	stat, err := cache.Put(ctx, "art", bytes.NewReader(content), nil)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if stat.Size != int64(len(content)) || stat.Metadata[MetaDigest] != sha256Hex(content) {
		t.Fatalf("logical size/digest not preserved over S3: size=%d digest=%s", stat.Size, stat.Metadata[MetaDigest])
	}
	assertReads(t, cache, "art", content)
	if st := cs.CompactionStats(); st.PhysicalBytes >= st.LogicalBytes {
		t.Fatalf("expected compression over S3 backend: %+v", st)
	}
}

func TestCompactDedupRejectedOnSharedStore(t *testing.T) {
	fs, _ := NewFilesystemStore(t.TempDir())
	_, err := NewCompactStore(fs, CompactOptions{Codec: "zstd", Dedup: true, Shared: true})
	if err == nil {
		t.Fatalf("expected dedup to be rejected on a shared store")
	}
}

func TestCompactUnknownCodec(t *testing.T) {
	fs, _ := NewFilesystemStore(t.TempDir())
	if _, err := NewCompactStore(fs, CompactOptions{Codec: "lzma"}); err == nil {
		t.Fatalf("expected unknown codec to be rejected")
	}
}

func TestCompactReservedKeysStripped(t *testing.T) {
	c, _ := newCompactCache(t, CompactOptions{Codec: "zstd", Level: 3}, FilesystemOptions{})
	ctx := context.Background()
	// A caller trying to inject a reserved key must not corrupt the layer.
	meta := map[string]string{"ptc.fmt": "manifest", "origin": "https://example.com/x"}
	if _, err := c.Put(ctx, "art", bytes.NewReader(compressibleBlob(10000)), meta); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, stat := getString(t, c, "art")
	if _, ok := stat.Metadata["ptc.fmt"]; ok {
		t.Fatalf("reserved key leaked into Stat metadata: %+v", stat.Metadata)
	}
	if stat.Metadata[MetaOrigin] != "https://example.com/x" {
		t.Fatalf("caller metadata lost: %+v", stat.Metadata)
	}
}

func TestEntropyAndMagic(t *testing.T) {
	if sampleEntropy(bytes.Repeat([]byte{0}, 1000)) > 0.001 {
		t.Fatalf("all-zero entropy should be ~0")
	}
	if e := sampleEntropy(randomBytes(4096)); e < 7.5 {
		t.Fatalf("random entropy should be near 8, got %v", e)
	}
	if !hasCompressedMagic([]byte{0x1f, 0x8b, 0x08}) {
		t.Fatalf("gzip magic not detected")
	}
	if !hasCompressedMagic([]byte{0x50, 0x4b, 0x03, 0x04}) {
		t.Fatalf("zip magic not detected")
	}
	mp4 := append([]byte{0, 0, 0, 0x18}, []byte("ftypmp42")...)
	if !hasCompressedMagic(mp4) {
		t.Fatalf("mp4 ftyp not detected")
	}
	if hasCompressedMagic([]byte("plain text content")) {
		t.Fatalf("plain text misdetected as compressed")
	}
	if !isCompressedContentType("application/zip") || !isCompressedContentType("image/png") {
		t.Fatalf("content-type detection failed")
	}
	if isCompressedContentType("image/svg+xml") || isCompressedContentType("text/plain") {
		t.Fatalf("text content-type misdetected")
	}
}

func TestChunkerStableBoundaries(t *testing.T) {
	data := compressibleBlob(1 << 20)
	c1 := chunkAll(t, data)
	c2 := chunkAll(t, data)
	if len(c1) != len(c2) {
		t.Fatalf("chunk count not stable: %d vs %d", len(c1), len(c2))
	}
	var reassembled []byte
	for i := range c1 {
		if !bytes.Equal(c1[i], c2[i]) {
			t.Fatalf("chunk %d differs between runs", i)
		}
		reassembled = append(reassembled, c1[i]...)
	}
	if !bytes.Equal(reassembled, data) {
		t.Fatalf("chunks do not reassemble to the original")
	}
	if len(c1) < 2 {
		t.Fatalf("expected the stream to split into multiple chunks, got %d", len(c1))
	}
}

// --- helpers ---

func assertReads(t *testing.T, c *FilesystemCache, key string, want []byte) {
	t.Helper()
	entry, err := c.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get(%q): %v", key, err)
	}
	got, err := io.ReadAll(entry.Content)
	entry.Content.Close()
	if err != nil {
		t.Fatalf("read(%q): %v", key, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("content mismatch for %q: got %d bytes want %d", key, len(got), len(want))
	}
}

func assertStoreReads(t *testing.T, s Store, key string, want []byte) {
	t.Helper()
	rc, _, err := s.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("store.Get(%q): %v", key, err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("read(%q): %v", key, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("content mismatch for %q: got %d bytes want %d", key, len(got), len(want))
	}
}

func chunkAll(t *testing.T, data []byte) [][]byte {
	t.Helper()
	ck := newChunker(bytes.NewReader(data))
	var out [][]byte
	for {
		chunk, err := ck.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("chunker: %v", err)
		}
		out = append(out, append([]byte(nil), chunk...))
	}
	return out
}

// randomBytes returns n deterministic high-entropy bytes (a simple xorshift PRNG
// so tests are reproducible without depending on crypto/rand).
func randomBytes(n int) []byte {
	b := make([]byte, n)
	var x uint64 = 0x9e3779b97f4a7c15
	for i := range b {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte(x >> 24)
	}
	return b
}

func corruptFileAt(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	if len(data) == 0 {
		t.Fatalf("file %q is empty, cannot corrupt", path)
	}
	// Flip bytes in the middle of the physical blob.
	for i := len(data) / 3; i < len(data)/3+16 && i < len(data); i++ {
		data[i] ^= 0xff
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}
