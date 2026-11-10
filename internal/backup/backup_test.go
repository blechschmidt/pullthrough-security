package backup

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
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

func put(t *testing.T, store cache.Store, key, content string) cache.Record {
	t.Helper()
	rec := cache.Record{Key: key, Origin: "https://upstream/" + key, ContentType: "application/octet-stream"}
	stored, err := store.Put(context.Background(), rec, bytes.NewReader([]byte(content)))
	if err != nil {
		t.Fatalf("store.Put(%q): %v", key, err)
	}
	return stored
}

func mustGet(t *testing.T, store cache.Store, key string) string {
	t.Helper()
	rc, _, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("store.Get(%q): %v", key, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read blob %q: %v", key, err)
	}
	return string(data)
}

// writeFile writes content under dir/rel, creating parents.
func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %q: %v", p, err)
	}
}

// backupToBuffer runs a backup into a buffer with deterministic timestamp.
func backupToBuffer(t *testing.T, opts Options) (*bytes.Buffer, *Result) {
	t.Helper()
	if opts.CreatedAt.IsZero() {
		opts.CreatedAt = time.Unix(1700000000, 0).UTC()
	}
	var buf bytes.Buffer
	res, err := NewBackuper().Backup(context.Background(), &buf, opts)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	return &buf, res
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	src := newStore(t)
	blobs := map[string]string{
		"npm:left-pad/-/left-pad-1.3.0.tgz": "left-pad-content",
		"pip:requests/requests-2.31.0.whl":  "requests-content",
		"docker:alpine:blobs:sha256:abc":    "layer-bytes",
	}
	for k, v := range blobs {
		put(t, src, k, v)
	}

	// Two metadata sources: a single-file audit log and a directory tree.
	auditDir := t.TempDir()
	writeFile(t, auditDir, "audit.log", "record-1\nrecord-2\n")
	vexDir := t.TempDir()
	writeFile(t, vexDir, "a.vex.json", `{"id":"a"}`)
	writeFile(t, vexDir, "nested/b.vex.json", `{"id":"b"}`)

	sources := []MetadataSource{
		{Name: "audit-log", Path: filepath.Join(auditDir, "audit.log"), Optional: true},
		{Name: "vex", Path: vexDir, Optional: true},
	}

	buf, res := backupToBuffer(t, Options{Cache: src, Sources: sources})
	if res.CacheEntries != 3 {
		t.Fatalf("CacheEntries = %d, want 3", res.CacheEntries)
	}
	if res.MetadataFiles != 3 {
		t.Fatalf("MetadataFiles = %d, want 3", res.MetadataFiles)
	}

	// Restore into fresh targets.
	dst := newStore(t)
	auditDst := t.TempDir()
	vexDst := t.TempDir()
	rres, err := NewRestorer().Restore(context.Background(), bytes.NewReader(buf.Bytes()), RestoreOptions{
		Cache: dst,
		Targets: map[string]string{
			"audit-log": auditDst,
			"vex":       vexDst,
		},
		ExpectedManifestDigest: res.ManifestDigest,
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if rres.CacheImported != 3 {
		t.Fatalf("CacheImported = %d, want 3", rres.CacheImported)
	}
	if rres.MetadataWritten != 3 {
		t.Fatalf("MetadataWritten = %d, want 3", rres.MetadataWritten)
	}

	// Verify cache content survived.
	for k, v := range blobs {
		if got := mustGet(t, dst, k); got != v {
			t.Errorf("blob %q = %q, want %q", k, got, v)
		}
	}
	// Verify metadata files survived at the expected paths.
	if got, _ := os.ReadFile(filepath.Join(auditDst, "audit.log")); string(got) != "record-1\nrecord-2\n" {
		t.Errorf("restored audit.log = %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(vexDst, "nested/b.vex.json")); string(got) != `{"id":"b"}` {
		t.Errorf("restored nested vex = %q", got)
	}
}

func TestBackupDeterministic(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", "v1")
	put(t, src, "k2", "v2")
	dir := t.TempDir()
	writeFile(t, dir, "f.txt", "meta")
	sources := []MetadataSource{{Name: "meta", Path: dir, Optional: true}}

	buf1, r1 := backupToBuffer(t, Options{Cache: src, Sources: sources})
	buf2, r2 := backupToBuffer(t, Options{Cache: src, Sources: sources})
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Error("identical content produced different bytes; backup is not deterministic")
	}
	if r1.ManifestDigest != r2.ManifestDigest {
		t.Errorf("manifest digests differ: %s vs %s", r1.ManifestDigest, r2.ManifestDigest)
	}
}

func TestRestoreRejectsWrongManifestDigest(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", "v1")
	buf, _ := backupToBuffer(t, Options{Cache: src})

	dst := newStore(t)
	_, err := NewRestorer().Restore(context.Background(), bytes.NewReader(buf.Bytes()), RestoreOptions{
		Cache:                  dst,
		ExpectedManifestDigest: "sha256:deadbeef",
	})
	if err == nil || !strings.Contains(err.Error(), "manifest digest mismatch") {
		t.Fatalf("expected manifest digest mismatch, got %v", err)
	}
}

func TestRestoreRejectsCorruptBlob(t *testing.T) {
	src := newStore(t)
	put(t, src, "npm:pkg", "the-real-bytes")
	buf, res := backupToBuffer(t, Options{Cache: src})

	// Corrupt a content byte in the archive body (after the manifest member). The
	// manifest's recorded per-blob digest will no longer match.
	raw := buf.Bytes()
	idx := bytes.Index(raw, []byte("the-real-bytes"))
	if idx < 0 {
		t.Fatal("could not locate blob content in archive")
	}
	raw[idx] = 'X'

	dst := newStore(t)
	_, err := NewRestorer().Restore(context.Background(), bytes.NewReader(raw), RestoreOptions{
		Cache:                  dst,
		ExpectedManifestDigest: res.ManifestDigest,
	})
	if err == nil || !strings.Contains(err.Error(), "integrity check") {
		t.Fatalf("expected integrity-check failure, got %v", err)
	}
	// The poisoned blob must not have been left behind.
	if _, serr := dst.Stat(context.Background(), "npm:pkg"); serr == nil {
		t.Error("corrupt blob was left in the target store")
	}
}

func TestRestoreRejectsTruncatedSnapshot(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", strings.Repeat("a", 1024))
	put(t, src, "k2", strings.Repeat("b", 1024))
	buf, _ := backupToBuffer(t, Options{Cache: src})

	// Truncate the archive mid-stream: the manifest declares members that will be
	// missing, so restore must reject it as incomplete.
	truncated := buf.Bytes()[:buf.Len()/2]
	dst := newStore(t)
	_, err := NewRestorer().Restore(context.Background(), bytes.NewReader(truncated), RestoreOptions{Cache: dst})
	if err == nil {
		t.Fatal("expected restore of truncated snapshot to fail")
	}
}

func TestRestoreRejectsUnknownFormatVersion(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", "v1")
	buf, _ := backupToBuffer(t, Options{Cache: src})

	// Flip the format version inside the manifest JSON.
	raw := bytes.Replace(buf.Bytes(), []byte(`"formatVersion":1`), []byte(`"formatVersion":9`), 1)
	dst := newStore(t)
	_, err := NewRestorer().Restore(context.Background(), bytes.NewReader(raw), RestoreOptions{Cache: dst})
	if err == nil || !strings.Contains(err.Error(), "unsupported snapshot format version") {
		t.Fatalf("expected format-version rejection, got %v", err)
	}
}

func TestBackupMissingRequiredSourceFails(t *testing.T) {
	src := newStore(t)
	sources := []MetadataSource{{Name: "required", Path: "/nonexistent/path", Optional: false}}
	var buf bytes.Buffer
	_, err := NewBackuper().Backup(context.Background(), &buf, Options{Cache: src, Sources: sources})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected missing-source failure, got %v", err)
	}
}

func TestBackupMissingOptionalSourceSucceeds(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", "v1")
	sources := []MetadataSource{{Name: "opt", Path: "/nonexistent/path", Optional: true}}
	_, res := backupToBuffer(t, Options{Cache: src, Sources: sources})
	if res.MetadataFiles != 0 {
		t.Fatalf("MetadataFiles = %d, want 0", res.MetadataFiles)
	}
}

func TestRestoreSkipsUnchangedAndOverwrites(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", "v1")
	metaDir := t.TempDir()
	writeFile(t, metaDir, "f.txt", "original")
	sources := []MetadataSource{{Name: "meta", Path: metaDir, Optional: true}}
	buf, res := backupToBuffer(t, Options{Cache: src, Sources: sources})

	dst := newStore(t)
	put(t, dst, "k1", "v1") // already present, identical size
	metaDst := t.TempDir()
	writeFile(t, metaDst, "f.txt", "original") // already identical

	rres, err := NewRestorer().Restore(context.Background(), bytes.NewReader(buf.Bytes()), RestoreOptions{
		Cache:                  dst,
		Targets:                map[string]string{"meta": metaDst},
		ExpectedManifestDigest: res.ManifestDigest,
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if rres.CacheSkipped != 1 {
		t.Errorf("CacheSkipped = %d, want 1", rres.CacheSkipped)
	}
	if rres.MetadataWritten != 0 {
		t.Errorf("MetadataWritten = %d, want 0 (unchanged file should be skipped)", rres.MetadataWritten)
	}
}

func TestRestoreRejectsPathTraversal(t *testing.T) {
	// safeJoin is the guard; verify it rejects an escaping relative path.
	if _, err := safeJoin("/var/lib/pt/restore", "../../etc/passwd"); err == nil {
		t.Fatal("safeJoin accepted a traversal path")
	}
	if got, err := safeJoin("/var/lib/pt/restore", "sub/file"); err != nil || got != "/var/lib/pt/restore/sub/file" {
		t.Fatalf("safeJoin(sub/file) = %q, %v", got, err)
	}
}
