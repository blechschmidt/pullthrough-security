package mirror

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
)

// newStore returns a fresh filesystem cache store rooted in a temp dir.
func newStore(t *testing.T) *cache.FilesystemStore {
	t.Helper()
	store, err := cache.NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// put writes a blob into a store and returns the stored record.
func put(t *testing.T, store cache.Store, key, content, origin string) cache.Record {
	t.Helper()
	rec := cache.Record{Key: key, Origin: origin, ContentType: "application/octet-stream"}
	stored, err := store.Put(context.Background(), rec, bytes.NewReader([]byte(content)))
	if err != nil {
		t.Fatalf("store.Put(%q): %v", key, err)
	}
	return stored
}

func mustGet(t *testing.T, store cache.Store, key string) (string, cache.Record) {
	t.Helper()
	rc, rec, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("store.Get(%q): %v", key, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read blob %q: %v", key, err)
	}
	return string(data), rec
}

func exportToBuffer(t *testing.T, store cache.Store, links provenance.LinkStore) (*bytes.Buffer, *ExportResult) {
	t.Helper()
	exp, err := NewExporter(store)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	var buf bytes.Buffer
	res, err := exp.Export(context.Background(), &buf, ExportOptions{
		Links:     links,
		CreatedAt: time.Unix(1700000000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return &buf, res
}

func TestExportImportRoundTrip(t *testing.T) {
	src := newStore(t)
	blobs := map[string]string{
		"npm:left-pad/-/left-pad-1.3.0.tgz": "left-pad-content",
		"pip:requests/requests-2.31.0.whl":  "requests-content",
		"docker:alpine:blobs:sha256:abc":    "layer-bytes",
	}
	for k, v := range blobs {
		put(t, src, k, v, "https://upstream/"+k)
	}

	srcLinks := provenance.NewMemoryLinkStore()
	link := &provenance.Link{
		Artifact:          provenance.Artifact{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"},
		RepositoryURL:     "https://github.com/stevemao/left-pad",
		CommitSHA:         "deadbeef",
		Confidence:        provenance.ConfidenceAttested,
		SignatureVerified: true,
		ChainTrusted:      true,
	}
	if err := srcLinks.Put(context.Background(), link); err != nil {
		t.Fatalf("link Put: %v", err)
	}

	buf, res := exportToBuffer(t, src, srcLinks)
	if res.CacheEntries != len(blobs) {
		t.Errorf("exported %d cache entries, want %d", res.CacheEntries, len(blobs))
	}
	if res.ProvenanceLinks != 1 {
		t.Errorf("exported %d links, want 1", res.ProvenanceLinks)
	}
	if res.ManifestDigest == "" {
		t.Error("empty manifest digest")
	}

	// Import into a fresh target store + link store.
	dst := newStore(t)
	dstLinks := provenance.NewMemoryLinkStore()
	imp, err := NewImporter(dst)
	if err != nil {
		t.Fatalf("NewImporter: %v", err)
	}
	ir, err := imp.Import(context.Background(), bytes.NewReader(buf.Bytes()), ImportOptions{
		Links:                  dstLinks,
		ExpectedManifestDigest: res.ManifestDigest,
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if ir.Imported != len(blobs) {
		t.Errorf("imported %d, want %d", ir.Imported, len(blobs))
	}
	if ir.Skipped != 0 {
		t.Errorf("skipped %d on first import, want 0", ir.Skipped)
	}
	if ir.ProvenanceLinks != 1 {
		t.Errorf("imported %d links, want 1", ir.ProvenanceLinks)
	}

	// Content and metadata must survive the round-trip.
	for k, want := range blobs {
		got, rec := mustGet(t, dst, k)
		if got != want {
			t.Errorf("blob %q = %q, want %q", k, got, want)
		}
		if rec.Origin != "https://upstream/"+k {
			t.Errorf("blob %q origin = %q", k, rec.Origin)
		}
	}

	gotLink, err := dstLinks.Get(context.Background(), link.Artifact)
	if err != nil {
		t.Fatalf("dstLinks.Get: %v", err)
	}
	if gotLink.CommitSHA != "deadbeef" || gotLink.Confidence != provenance.ConfidenceAttested {
		t.Errorf("link round-trip mismatch: %+v", gotLink)
	}
}

func TestExportDeterministic(t *testing.T) {
	src := newStore(t)
	put(t, src, "b-key", "two", "")
	put(t, src, "a-key", "one", "")
	put(t, src, "c-key", "three", "")

	buf1, res1 := exportToBuffer(t, src, nil)
	buf2, res2 := exportToBuffer(t, src, nil)

	if res1.ManifestDigest != res2.ManifestDigest {
		t.Errorf("manifest digest not deterministic: %s != %s", res1.ManifestDigest, res2.ManifestDigest)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Error("bundle bytes differ across identical exports")
	}
}

func TestImportResumesBySkipping(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", "one", "")
	put(t, src, "k2", "two", "")
	buf, res := exportToBuffer(t, src, nil)

	dst := newStore(t)
	imp, _ := NewImporter(dst)

	// First import writes everything.
	first, err := imp.Import(context.Background(), bytes.NewReader(buf.Bytes()), ImportOptions{})
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if first.Imported != 2 {
		t.Fatalf("first import wrote %d, want 2", first.Imported)
	}

	// Re-running the same import is idempotent: all entries are skipped.
	second, err := imp.Import(context.Background(), bytes.NewReader(buf.Bytes()), ImportOptions{
		ExpectedManifestDigest: res.ManifestDigest,
	})
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if second.Imported != 0 || second.Skipped != 2 {
		t.Errorf("second import imported=%d skipped=%d, want 0/2", second.Imported, second.Skipped)
	}
}

func TestImportRejectsManifestDigestMismatch(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", "one", "")
	buf, _ := exportToBuffer(t, src, nil)

	dst := newStore(t)
	imp, _ := NewImporter(dst)
	_, err := imp.Import(context.Background(), bytes.NewReader(buf.Bytes()), ImportOptions{
		ExpectedManifestDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	})
	if err == nil {
		t.Fatal("expected manifest digest mismatch error, got nil")
	}
}

func TestImportDetectsBlobTampering(t *testing.T) {
	src := newStore(t)
	put(t, src, "tampered-key", "original-content", "")
	buf, _ := exportToBuffer(t, src, nil)

	// Flip a byte in the blob payload region of the tar. The manifest member comes
	// first; the blob content follows. Corrupt a byte near the end of the archive,
	// which falls inside the (only) blob's data.
	raw := buf.Bytes()
	corrupted := make([]byte, len(raw))
	copy(corrupted, raw)
	// "original-content" appears verbatim in the tar; mutate within it.
	idx := bytes.Index(corrupted, []byte("original-content"))
	if idx < 0 {
		t.Fatal("could not locate blob content in archive")
	}
	corrupted[idx] ^= 0xFF

	dst := newStore(t)
	imp, _ := NewImporter(dst)
	_, err := imp.Import(context.Background(), bytes.NewReader(corrupted), ImportOptions{})
	if err == nil {
		t.Fatal("expected integrity-check failure on tampered blob, got nil")
	}
	// The tampered entry must not be left behind in the target store.
	if _, serr := dst.Stat(context.Background(), "tampered-key"); serr == nil {
		t.Error("tampered blob was retained in target store after failed import")
	}
}

func TestImportRejectsWrongFirstMember(t *testing.T) {
	// An archive that is not a pullthrough bundle (no manifest first) is rejected.
	var buf bytes.Buffer
	imp, _ := NewImporter(newStore(t))
	_, err := imp.Import(context.Background(), &buf, ImportOptions{})
	if err == nil {
		t.Fatal("expected error importing empty/garbage stream, got nil")
	}
}
