package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
)

// recordingObserver captures corruption events for assertions.
type recordingObserver struct {
	mu     sync.Mutex
	events []CorruptionEvent
}

func (o *recordingObserver) OnCorruption(_ context.Context, ev CorruptionEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, ev)
}

func (o *recordingObserver) snapshot() []CorruptionEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]CorruptionEvent, len(o.events))
	copy(out, o.events)
	return out
}

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// newIntegrityFSCache builds an IntegrityCache over a real FilesystemCache in a
// temp dir, returning the wrapper, the underlying store (for tampering), and the
// observer.
func newIntegrityFSCache(t *testing.T) (*IntegrityCache, *FilesystemStore, *recordingObserver) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	fc, err := NewFilesystemCache(FilesystemOptions{Store: store})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	obs := &recordingObserver{}
	ic := NewIntegrityCache(fc, IntegrityOptions{VerifyOnServe: true, Observer: obs})
	t.Cleanup(func() { _ = ic.Close() })
	return ic, store, obs
}

// corruptBlob overwrites the on-disk blob for key with new bytes, simulating
// bit-rot or tampering while leaving the metadata (and its digest) intact.
func corruptBlob(t *testing.T, store *FilesystemStore, key string, newContent []byte) {
	t.Helper()
	name := storageName(key)
	path := store.blobPath(name)
	if err := os.WriteFile(path, newContent, 0o640); err != nil {
		t.Fatalf("corruptBlob: %v", err)
	}
}

func drain(t *testing.T, e *Entry) []byte {
	t.Helper()
	defer e.Content.Close()
	b, err := io.ReadAll(e.Content)
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	return b
}

func TestIntegrityServeVerifiesHealthyBlob(t *testing.T) {
	ic, _, obs := newIntegrityFSCache(t)
	ctx := context.Background()

	content := []byte("hello integrity world")
	if _, err := ic.Put(ctx, "k1", bytes.NewReader(content), map[string]string{MetaOrigin: "https://example/x"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	entry, err := ic.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got := drain(t, entry)
	if !bytes.Equal(got, content) {
		t.Fatalf("content = %q, want %q", got, content)
	}

	m := ic.IntegrityMetrics()
	if m.Verifications != 1 {
		t.Errorf("verifications = %d, want 1", m.Verifications)
	}
	if m.Failures != 0 {
		t.Errorf("failures = %d, want 0", m.Failures)
	}
	if evs := obs.snapshot(); len(evs) != 0 {
		t.Errorf("unexpected corruption events: %+v", evs)
	}
}

func TestIntegrityServeDetectsAndQuarantinesCorruption(t *testing.T) {
	ic, store, obs := newIntegrityFSCache(t)
	ctx := context.Background()

	content := []byte("the quick brown fox jumps over the lazy dog")
	if _, err := ic.Put(ctx, "k1", bytes.NewReader(content), map[string]string{MetaOrigin: "https://example/x"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Tamper with the stored bytes, leaving the recorded digest intact.
	tampered := []byte("the quick brown fox jumps over the lazy CAT!!!!!!!!!!!!!")
	corruptBlob(t, store, "k1", tampered)

	entry, err := ic.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// The serve streams the (tampered) bytes; verification fires at EOF/Close.
	_ = drain(t, entry)

	m := ic.IntegrityMetrics()
	if m.Verifications != 1 || m.Failures != 1 {
		t.Errorf("metrics = %+v, want 1 verification / 1 failure", m)
	}
	evs := obs.snapshot()
	if len(evs) != 1 {
		t.Fatalf("corruption events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Key != "k1" || ev.Source != SourceServe || !ev.Quarantined {
		t.Errorf("event = %+v, want key k1 / serve / quarantined", ev)
	}
	if ev.Expected != sha256Digest(content) {
		t.Errorf("expected digest = %q, want %q", ev.Expected, sha256Digest(content))
	}
	if ev.Computed != sha256Digest(tampered) {
		t.Errorf("computed digest = %q, want %q", ev.Computed, sha256Digest(tampered))
	}

	// Quarantine removed the entry: it is gone from the cache.
	if _, err := ic.Stat(ctx, "k1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Stat after quarantine = %v, want ErrNotFound", err)
	}
}

func TestIntegritySelfHealOnNextFetch(t *testing.T) {
	ic, store, _ := newIntegrityFSCache(t)
	ctx := context.Background()

	original := []byte("v1-original-bytes")
	if _, err := ic.Put(ctx, "k1", bytes.NewReader(original), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	corruptBlob(t, store, "k1", []byte("corrupted!!"))

	// First serve detects corruption and quarantines.
	entry, err := ic.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = drain(t, entry)
	if _, err := ic.Stat(ctx, "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("entry not quarantined: %v", err)
	}

	// The next pull misses (because the poisoned entry was removed) and the
	// loader transparently re-fetches a clean copy: self-heal.
	loaderCalls := 0
	loader := func(context.Context) (io.Reader, map[string]string, error) {
		loaderCalls++
		return bytes.NewReader(original), nil, nil
	}
	healed, err := ic.GetOrLoad(ctx, "k1", loader)
	if err != nil {
		t.Fatalf("GetOrLoad: %v", err)
	}
	got := drain(t, healed)
	if loaderCalls != 1 {
		t.Errorf("loader calls = %d, want 1 (self-heal re-fetch)", loaderCalls)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("healed content = %q, want %q", got, original)
	}
	// The healed serve also verified cleanly.
	if m := ic.IntegrityMetrics(); m.Failures != 1 {
		t.Errorf("failures = %d, want 1 (only the original corruption)", m.Failures)
	}
}

func TestIntegrityRangeReadNotFalselyFlagged(t *testing.T) {
	ic, _, obs := newIntegrityFSCache(t)
	ctx := context.Background()

	content := bytes.Repeat([]byte("ABCDEFGHIJ"), 100) // 1000 bytes
	if _, err := ic.Put(ctx, "k1", bytes.NewReader(content), map[string]string{MetaContentType: "application/octet-stream"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	entry, err := ic.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer entry.Content.Close()

	rs, ok := entry.Content.(io.ReadSeeker)
	if !ok {
		t.Fatalf("fs-backed content is not seekable through the verifier")
	}
	// Read only a middle byte-range, as http.ServeContent would for a Range req.
	if _, err := rs.Seek(200, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	buf := make([]byte, 100)
	if _, err := io.ReadFull(rs, buf); err != nil {
		t.Fatalf("read range: %v", err)
	}
	if !bytes.Equal(buf, content[200:300]) {
		t.Errorf("range bytes wrong")
	}
	_ = entry.Content.Close()

	// A partial/range read must NOT render a verdict (no false mismatch, and no
	// spurious verification count).
	if m := ic.IntegrityMetrics(); m.Verifications != 0 || m.Failures != 0 {
		t.Errorf("metrics after range read = %+v, want zero", m)
	}
	if evs := obs.snapshot(); len(evs) != 0 {
		t.Errorf("range read produced corruption events: %+v", evs)
	}
}

// TestIntegrityServeContentFullBody drives the real http.ServeContent path (size
// probe + full copy over a seekable verifier) and confirms a healthy blob
// verifies and a tampered one is caught.
func TestIntegrityServeContentFullBody(t *testing.T) {
	ic, store, obs := newIntegrityFSCache(t)
	ctx := context.Background()

	content := bytes.Repeat([]byte("payload-"), 500)
	if _, err := ic.Put(ctx, "k1", bytes.NewReader(content), map[string]string{MetaContentType: "application/octet-stream"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	serve := func() *httptest.ResponseRecorder {
		entry, err := ic.Get(ctx, "k1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		defer entry.Content.Close()
		rs := entry.Content.(io.ReadSeeker)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/blob", nil)
		req.Header.Set("Content-Type", "application/octet-stream")
		http.ServeContent(rec, req, "", entry.Stat.ModTime, rs)
		return rec
	}

	rec := serve()
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Fatalf("served body mismatch")
	}
	if m := ic.IntegrityMetrics(); m.Verifications != 1 || m.Failures != 0 {
		t.Errorf("healthy ServeContent metrics = %+v, want 1/0", m)
	}

	// Now corrupt and serve again through ServeContent.
	corruptBlob(t, store, "k1", bytes.Repeat([]byte("TAMPERED"), 500))
	_ = serve()
	if m := ic.IntegrityMetrics(); m.Failures != 1 {
		t.Errorf("failures after corrupt ServeContent = %d, want 1", m.Failures)
	}
	if evs := obs.snapshot(); len(evs) != 1 || evs[0].Source != SourceServe {
		t.Errorf("corruption events = %+v", evs)
	}
}

func TestIntegrityScan(t *testing.T) {
	ic, store, obs := newIntegrityFSCache(t)
	ctx := context.Background()

	// Three healthy entries, one of which we then corrupt.
	for _, k := range []string{"a", "b", "c"} {
		if _, err := ic.Put(ctx, k, bytes.NewReader([]byte("content-"+k)), nil); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}
	corruptBlob(t, store, "b", []byte("rotted"))

	report, err := ic.ScanIntegrity(ctx)
	if err != nil {
		t.Fatalf("ScanIntegrity: %v", err)
	}
	if report.Scanned != 3 {
		t.Errorf("scanned = %d, want 3", report.Scanned)
	}
	if report.Verified != 2 {
		t.Errorf("verified = %d, want 2", report.Verified)
	}
	if report.Corrupted != 1 {
		t.Errorf("corrupted = %d, want 1", report.Corrupted)
	}
	if len(report.CorruptKeys) != 1 || report.CorruptKeys[0] != "b" {
		t.Errorf("corruptKeys = %v, want [b]", report.CorruptKeys)
	}
	if report.DurationSeconds < 0 {
		t.Errorf("negative duration")
	}

	// The scan quarantined "b" and notified the observer with SourceScan.
	if _, err := ic.Stat(ctx, "b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("corrupt entry b not quarantined by scan: %v", err)
	}
	evs := obs.snapshot()
	if len(evs) != 1 || evs[0].Key != "b" || evs[0].Source != SourceScan {
		t.Errorf("scan corruption events = %+v", evs)
	}

	// Scan metrics folded into the shared counters.
	if m := ic.IntegrityMetrics(); m.Verifications != 3 || m.Failures != 1 {
		t.Errorf("scan metrics = %+v, want 3 verifications / 1 failure", m)
	}
}

func TestIntegrityScanSkipsEntriesWithoutDigest(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	// Write a record directly with no digest (simulating a pre-upgrade entry).
	ctx := context.Background()
	if _, err := store.Put(ctx, Record{Key: "legacy"}, bytes.NewReader([]byte("x"))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Strip the digest the store just computed, to emulate an older on-disk entry.
	name := storageName("legacy")
	rec, err := store.readMeta(name)
	if err != nil {
		t.Fatalf("readMeta: %v", err)
	}
	rec.Digest = ""
	if err := store.writeMeta(name, rec); err != nil {
		t.Fatalf("writeMeta: %v", err)
	}

	fc, err := NewFilesystemCache(FilesystemOptions{Store: store})
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	ic := NewIntegrityCache(fc, IntegrityOptions{})
	defer ic.Close()

	report, err := ic.ScanIntegrity(ctx)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if report.Scanned != 1 || report.Skipped != 1 || report.Verified != 0 || report.Corrupted != 0 {
		t.Errorf("report = %+v, want scanned 1 / skipped 1", report)
	}
}

func TestIntegrityScanUnsupportedBackend(t *testing.T) {
	// A bare Cache that does not implement Entries cannot be scanned.
	ic := NewIntegrityCache(entrieslessCache{NewMemoryCache()}, IntegrityOptions{})
	_, err := ic.ScanIntegrity(context.Background())
	if !errors.Is(err, ErrIntegrityUnsupported) {
		t.Errorf("err = %v, want ErrIntegrityUnsupported", err)
	}
}

// entrieslessCache wraps a Cache hiding any Entries method so the scan reports
// ErrIntegrityUnsupported.
type entrieslessCache struct{ c Cache }

func (e entrieslessCache) Get(ctx context.Context, k string) (*Entry, error) { return e.c.Get(ctx, k) }
func (e entrieslessCache) Put(ctx context.Context, k string, r io.Reader, m map[string]string) (*Stat, error) {
	return e.c.Put(ctx, k, r, m)
}
func (e entrieslessCache) GetOrLoad(ctx context.Context, k string, l Loader) (*Entry, error) {
	return e.c.GetOrLoad(ctx, k, l)
}
func (e entrieslessCache) Stat(ctx context.Context, k string) (*Stat, error) { return e.c.Stat(ctx, k) }
func (e entrieslessCache) Delete(ctx context.Context, k string) error        { return e.c.Delete(ctx, k) }
func (e entrieslessCache) Close() error                                      { return e.c.Close() }

func TestIntegrityMemoryCacheRecordsDigest(t *testing.T) {
	ctx := context.Background()
	mc := NewMemoryCache()
	content := []byte("memory-content")
	if _, err := mc.Put(ctx, "k", bytes.NewReader(content), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	stat, err := mc.Stat(ctx, "k")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := stat.Metadata[MetaDigest]; got != sha256Digest(content) {
		t.Errorf("digest = %q, want %q", got, sha256Digest(content))
	}
}

func TestIntegrityVerifyOnServeDisabled(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	fc, err := NewFilesystemCache(FilesystemOptions{Store: store})
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	obs := &recordingObserver{}
	ic := NewIntegrityCache(fc, IntegrityOptions{VerifyOnServe: false, Observer: obs})
	defer ic.Close()
	ctx := context.Background()

	if _, err := ic.Put(ctx, "k", bytes.NewReader([]byte("original")), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	corruptBlob(t, store, "k", []byte("tampered-and-longer"))

	entry, err := ic.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = drain(t, entry)

	// Serve-time verification is off: no verdict rendered, nothing quarantined.
	if m := ic.IntegrityMetrics(); m.Verifications != 0 || m.Failures != 0 {
		t.Errorf("metrics = %+v, want zero with VerifyOnServe disabled", m)
	}
	if len(obs.snapshot()) != 0 {
		t.Errorf("unexpected corruption events with verification disabled")
	}
	// But the admin scan still works and catches the corruption.
	rep, err := ic.ScanIntegrity(ctx)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Corrupted != 1 {
		t.Errorf("scan corrupted = %d, want 1", rep.Corrupted)
	}
	if last, ok := ic.LastScan(); !ok || last.Corrupted != 1 {
		t.Errorf("LastScan = %+v (ok=%v), want corrupted 1", last, ok)
	}
}

func TestIntegritySetObserver(t *testing.T) {
	ic, store, _ := newIntegrityFSCache(t)
	ctx := context.Background()

	// Replace the observer after construction (the real startup ordering).
	replacement := &recordingObserver{}
	ic.SetObserver(replacement)

	if _, err := ic.Put(ctx, "k", bytes.NewReader([]byte("content")), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	corruptBlob(t, store, "k", []byte("rot"))
	entry, err := ic.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = drain(t, entry)

	if evs := replacement.snapshot(); len(evs) != 1 {
		t.Errorf("replacement observer received %d events, want 1", len(evs))
	}
}

func TestStoreRecordsContentDigest(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := NewFilesystemStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	content := []byte("blob-bytes-to-hash")
	rec, err := store.Put(ctx, Record{Key: "k"}, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if rec.Digest != sha256Digest(content) {
		t.Errorf("fs store digest = %q, want %q", rec.Digest, sha256Digest(content))
	}
	// Round-trips through metadata read.
	got, err := store.Stat(ctx, "k")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got.Digest != sha256Digest(content) {
		t.Errorf("persisted digest = %q, want %q", got.Digest, sha256Digest(content))
	}
}
