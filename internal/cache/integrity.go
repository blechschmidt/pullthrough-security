package cache

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Integrity verification sources, recorded on a CorruptionEvent and used as the
// audit/metric dimension distinguishing a read-time catch from a scan catch.
const (
	// SourceServe is a corruption detected while a blob was being served to a
	// client (streaming read-time verification).
	SourceServe = "serve"
	// SourceScan is a corruption detected by the admin-triggered background
	// integrity scan re-reading cached entries.
	SourceScan = "scan"
)

// ErrIntegrityUnsupported is returned by ScanIntegrity when the wrapped cache
// cannot enumerate its entries (it does not implement Entries), so a full
// re-verification pass is not possible.
var ErrIntegrityUnsupported = errors.New("cache: backend does not support integrity scanning")

// CorruptionEvent describes a single detected integrity violation: a stored blob
// whose bytes no longer hash to the content digest recorded when it was written.
// It is handed to an IntegrityObserver so the serving layer can emit an audit
// record, a metric, and an operator notification, and (for subsequent pulls)
// self-heal by re-fetching from upstream.
type CorruptionEvent struct {
	// Key is the cache key of the corrupted entry.
	Key string
	// Expected is the stored content digest ("algo:hexdigest") the bytes should
	// have hashed to.
	Expected string
	// Computed is the digest actually computed over the stored bytes.
	Computed string
	// Size is the stored content length in bytes.
	Size int64
	// Origin is the upstream URL/coordinate the content was pulled from, when
	// recorded in metadata; it lets the self-heal path know what to re-fetch.
	Origin string
	// ContentType is the stored MIME type, when recorded.
	ContentType string
	// Source is SourceServe or SourceScan.
	Source string
	// Quarantined reports whether the corrupted entry was successfully removed
	// from the cache (so it is never served again and the next pull re-fetches).
	Quarantined bool
	// DetectedAt is when the mismatch was observed.
	DetectedAt time.Time
}

// IntegrityObserver receives corruption events detected by an IntegrityCache.
// The cache has already quarantined the entry (removed it from the store) before
// the observer is called; implementations layer on the cross-cutting response —
// an audit event, an alert/notification, and any bookkeeping — and may rely on
// the normal pull path to transparently re-fetch the artifact from upstream on
// the next request (self-heal). Implementations must be safe for concurrent use
// and must not block for long; a nil observer is a valid no-op.
type IntegrityObserver interface {
	OnCorruption(ctx context.Context, ev CorruptionEvent)
}

// IntegrityMetricsSnapshot is an immutable view of the integrity counters,
// exported to Prometheus as integrity_verifications_total / integrity_failures_total.
type IntegrityMetricsSnapshot struct {
	// Verifications is the number of complete content verifications performed
	// (read-time plus background scan), whether they passed or failed.
	Verifications int64
	// Failures is the number of those verifications that detected a digest
	// mismatch (corruption/tampering). Always <= Verifications.
	Failures int64
}

// IntegrityReport summarizes one background integrity-scan pass. It is returned
// directly as the admin endpoint's JSON body.
type IntegrityReport struct {
	StartedAt       time.Time `json:"startedAt"`
	CompletedAt     time.Time `json:"completedAt"`
	DurationSeconds float64   `json:"durationSeconds"`
	// Scanned is the number of cached entries examined.
	Scanned int `json:"scanned"`
	// Verified is the number whose stored bytes matched their recorded digest.
	Verified int `json:"verified"`
	// Corrupted is the number whose bytes did not match (each was quarantined).
	Corrupted int `json:"corrupted"`
	// Skipped is the number with no recorded digest (written before digest
	// recording, or an unsupported algorithm) and therefore not verifiable.
	Skipped int `json:"skipped"`
	// Errors is the number of entries that could not be read for verification.
	Errors int `json:"errors"`
	// BytesScanned is the total content bytes re-hashed.
	BytesScanned int64 `json:"bytesScanned"`
	// CorruptKeys is a bounded sample of the keys found corrupted, for triage.
	CorruptKeys []string `json:"corruptKeys,omitempty"`
}

// maxCorruptKeysReported bounds the CorruptKeys sample so a pathological bucket
// (e.g. a wholesale volume failure) cannot produce an unbounded report body.
const maxCorruptKeysReported = 100

// IntegrityCache decorates a Cache with read-time content-integrity
// verification and self-healing. On every fully-served immutable blob it
// streams the bytes through a hash and compares the result against the content
// digest the store recorded at write time (Record.Digest / MetaDigest). A
// mismatch means the content-addressable store has been tampered with or has
// suffered bit-rot: the entry is quarantined (removed), a metric and an observer
// callback fire (audit + notification), and because the poisoned entry is gone
// the next pull transparently re-fetches a clean copy from upstream.
//
// Verification is streaming and bounded-memory: the blob is hashed as it is read
// on its way to the client, never buffered whole. It renders a verdict only for
// a complete, in-order read of the blob; a partial or byte-range read (which
// cannot be checked against the whole-blob digest) is skipped rather than
// raising a false alarm.
//
// It also exposes ScanIntegrity, an admin-triggered pass that re-reads every
// cached entry and re-verifies its digest, quarantining any corruption it finds.
//
// Like SealedCache, it forwards the optional administrative/metrics surfaces so
// the admin API, GC, and Prometheus bridges keep working through the wrapper.
type IntegrityCache struct {
	inner         Cache
	logger        *slog.Logger
	now           func() time.Time
	verifyOnServe bool

	verifications atomic.Int64
	failures      atomic.Int64

	scanMu sync.Mutex // serializes background scans; at most one runs at a time

	mu         sync.RWMutex // guards observer and lastReport
	observer   IntegrityObserver
	lastReport *IntegrityReport
}

// IntegrityOptions configures an IntegrityCache.
type IntegrityOptions struct {
	// VerifyOnServe enables streaming digest verification of every fully-served
	// blob. When false the wrapper is a transparent pass-through on the serve path
	// but ScanIntegrity still works, so operators can keep the admin scan without
	// paying the per-serve hashing cost.
	VerifyOnServe bool
	// Observer receives corruption events (audit + notification + self-heal). It
	// can also be installed later with SetObserver, since the audit/notify
	// subsystems are typically constructed after the cache.
	Observer IntegrityObserver
	// Logger receives integrity warnings/errors. Optional.
	Logger *slog.Logger
	// Now overrides the clock; used in tests. Defaults to time.Now.
	Now func() time.Time
}

var _ Cache = (*IntegrityCache)(nil)

// NewIntegrityCache wraps inner with read-time integrity verification.
func NewIntegrityCache(inner Cache, opts IntegrityOptions) *IntegrityCache {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &IntegrityCache{
		inner:         inner,
		logger:        opts.Logger,
		now:           now,
		verifyOnServe: opts.VerifyOnServe,
		observer:      opts.Observer,
	}
}

// SetObserver installs (or replaces) the corruption observer. It is safe to call
// once at startup after the audit/notification subsystems are constructed, even
// though they are typically built after the cache.
func (c *IntegrityCache) SetObserver(o IntegrityObserver) {
	c.mu.Lock()
	c.observer = o
	c.mu.Unlock()
}

// currentObserver returns the installed observer under the read lock.
func (c *IntegrityCache) currentObserver() IntegrityObserver {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.observer
}

// LastScan returns the most recent completed integrity-scan report, if any.
func (c *IntegrityCache) LastScan() (IntegrityReport, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.lastReport == nil {
		return IntegrityReport{}, false
	}
	return *c.lastReport, true
}

// Get implements Cache, wrapping the served content in a streaming verifier.
func (c *IntegrityCache) Get(ctx context.Context, key string) (*Entry, error) {
	entry, err := c.inner.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	return c.verifyEntry(ctx, entry), nil
}

// GetOrLoad implements Cache. The entry (a cache hit or a freshly filled miss)
// is served through the streaming verifier just like Get.
func (c *IntegrityCache) GetOrLoad(ctx context.Context, key string, loader Loader) (*Entry, error) {
	entry, err := c.inner.GetOrLoad(ctx, key, loader)
	if err != nil {
		return nil, err
	}
	return c.verifyEntry(ctx, entry), nil
}

// Put implements Cache by delegating to the wrapped cache. The store computes
// and records the content digest on write; nothing to verify here.
func (c *IntegrityCache) Put(ctx context.Context, key string, r io.Reader, metadata map[string]string) (*Stat, error) {
	return c.inner.Put(ctx, key, r, metadata)
}

// Stat implements Cache by delegating to the wrapped cache.
func (c *IntegrityCache) Stat(ctx context.Context, key string) (*Stat, error) {
	return c.inner.Stat(ctx, key)
}

// Delete implements Cache by delegating to the wrapped cache.
func (c *IntegrityCache) Delete(ctx context.Context, key string) error {
	return c.inner.Delete(ctx, key)
}

// Close implements Cache by delegating to the wrapped cache.
func (c *IntegrityCache) Close() error {
	return c.inner.Close()
}

// IntegrityMetrics returns the current verification counters for the Prometheus
// bridge.
func (c *IntegrityCache) IntegrityMetrics() IntegrityMetricsSnapshot {
	return IntegrityMetricsSnapshot{
		Verifications: c.verifications.Load(),
		Failures:      c.failures.Load(),
	}
}

// verifyEntry wraps entry.Content in a streaming fixity checker when the entry
// carries a usable content digest. Content without a recorded digest (written
// before digest recording, or an unsupported algorithm) is returned unchanged.
func (c *IntegrityCache) verifyEntry(ctx context.Context, entry *Entry) *Entry {
	if !c.verifyOnServe {
		return entry
	}
	algo, hexsum, ok := splitDigestLower(entry.Stat.Metadata[MetaDigest])
	if !ok {
		return entry
	}
	h, want, ok := newDigestHasher(algo, hexsum)
	if !ok {
		return entry
	}
	stat := entry.Stat
	fc := &fixityChecker{
		hash:     h,
		expected: want,
		algo:     algo,
		end:      -1,
	}
	fc.onVerdict = func(match bool, computed string) {
		c.serveVerdict(ctx, stat, computed, match)
	}
	base := verifyReadCloser{src: entry.Content, fc: fc}
	var content io.ReadCloser = &base
	// Preserve seekability so the range-serving path (http.ServeContent) keeps
	// random access; a forward-only body stays forward-only so the serve layer
	// chooses its streaming/spool path. Either way a complete read is verified.
	if seeker, ok := entry.Content.(io.Seeker); ok {
		content = &verifyReadSeekCloser{verifyReadCloser: base, seeker: seeker}
	}
	return &Entry{Stat: entry.Stat, Content: content}
}

// serveVerdict records a completed read-time verification and, on mismatch,
// quarantines the entry and notifies the observer.
func (c *IntegrityCache) serveVerdict(ctx context.Context, stat Stat, computed string, match bool) {
	c.verifications.Add(1)
	if match {
		return
	}
	c.failures.Add(1)
	c.handleCorruption(ctx, stat, computed, SourceServe)
}

// handleCorruption quarantines a corrupted entry and reports it. It detaches
// from the request context (the client may already have gone away by the time a
// serve-path verdict is rendered) so the quarantine and notification still
// complete, bounded by a short timeout.
func (c *IntegrityCache) handleCorruption(ctx context.Context, stat Stat, computed, source string) {
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	// Bytes that no longer match their digest are removed even when a release
	// pinned the object (Task 180): they are worthless to the release, and the
	// observer has the pin's owner fetch the object again or raise an alert.
	quarantined := true
	if err := c.inner.Delete(WithPinOverride(hctx, "integrity"), stat.Key); err != nil && !errors.Is(err, ErrNotFound) {
		quarantined = false
		if c.logger != nil {
			c.logger.Error("cache integrity: failed to quarantine corrupted entry",
				"key", stat.Key, "error", err)
		}
	}
	if c.logger != nil {
		c.logger.Error("cache integrity violation: stored blob does not match its content digest",
			"key", stat.Key,
			"expected", stat.Metadata[MetaDigest],
			"computed", computed,
			"source", source,
			"quarantined", quarantined)
	}
	if obs := c.currentObserver(); obs != nil {
		obs.OnCorruption(hctx, CorruptionEvent{
			Key:         stat.Key,
			Expected:    stat.Metadata[MetaDigest],
			Computed:    computed,
			Size:        stat.Size,
			Origin:      stat.Metadata[MetaOrigin],
			ContentType: stat.Metadata[MetaContentType],
			Source:      source,
			Quarantined: quarantined,
			DetectedAt:  c.now(),
		})
	}
}

// ScanIntegrity re-reads every cached entry and re-verifies its stored bytes
// against the recorded content digest, quarantining and reporting any
// corruption. It is the admin-triggered background defense against latent
// bit-rot that a never-served entry would otherwise hide. At most one scan runs
// at a time; a concurrent caller blocks until the running scan finishes. The
// scan honors ctx cancellation between entries.
func (c *IntegrityCache) ScanIntegrity(ctx context.Context) (IntegrityReport, error) {
	c.scanMu.Lock()
	defer c.scanMu.Unlock()

	report := IntegrityReport{StartedAt: c.now()}

	lister, ok := c.inner.(interface {
		Entries(context.Context) ([]Stat, error)
	})
	if !ok {
		return report, ErrIntegrityUnsupported
	}
	stats, err := lister.Entries(ctx)
	if err != nil {
		return report, err
	}

	for _, st := range stats {
		if err := ctx.Err(); err != nil {
			report.CompletedAt = c.now()
			report.DurationSeconds = report.CompletedAt.Sub(report.StartedAt).Seconds()
			return report, err
		}
		report.Scanned++

		algo, hexsum, ok := splitDigestLower(st.Metadata[MetaDigest])
		if !ok {
			report.Skipped++
			continue
		}
		match, computed, n, err := c.recompute(ctx, st.Key, algo, hexsum)
		report.BytesScanned += n
		if err != nil {
			// A concurrent delete/eviction is benign; anything else is a read
			// failure worth counting.
			if errors.Is(err, ErrNotFound) {
				report.Skipped++
			} else {
				report.Errors++
				if c.logger != nil {
					c.logger.Warn("cache integrity: could not read entry for verification",
						"key", st.Key, "error", err)
				}
			}
			continue
		}
		c.verifications.Add(1)
		if match {
			report.Verified++
			continue
		}
		report.Corrupted++
		c.failures.Add(1)
		if len(report.CorruptKeys) < maxCorruptKeysReported {
			report.CorruptKeys = append(report.CorruptKeys, st.Key)
		}
		c.handleCorruption(ctx, st, computed, SourceScan)
	}

	report.CompletedAt = c.now()
	report.DurationSeconds = report.CompletedAt.Sub(report.StartedAt).Seconds()
	c.mu.Lock()
	reportCopy := report
	c.lastReport = &reportCopy
	c.mu.Unlock()
	if c.logger != nil {
		c.logger.Info("cache integrity scan complete",
			"scanned", report.Scanned,
			"verified", report.Verified,
			"corrupted", report.Corrupted,
			"skipped", report.Skipped,
			"errors", report.Errors,
			"bytesScanned", report.BytesScanned,
			"durationSeconds", report.DurationSeconds)
	}
	return report, nil
}

// recompute streams the stored blob for key through a fresh hasher and compares
// the result against the expected digest. It reads straight from the durable
// store (OpenRaw) when available so the scan does not distort LRU ordering or
// hit/miss metrics; otherwise it falls back to a normal Get.
func (c *IntegrityCache) recompute(ctx context.Context, key, algo, hexsum string) (match bool, computed string, n int64, err error) {
	rc, err := c.openRaw(ctx, key)
	if err != nil {
		return false, "", 0, err
	}
	defer rc.Close()

	h, want, ok := newDigestHasher(algo, hexsum)
	if !ok {
		// Should not happen: the caller already validated the digest format.
		return false, "", 0, errors.New("cache: unsupported digest algorithm")
	}
	n, err = io.Copy(h, rc)
	if err != nil {
		return false, "", n, err
	}
	sum := h.Sum(nil)
	computed = algo + ":" + hex.EncodeToString(sum)
	return subtle.ConstantTimeCompare(sum, want) == 1, computed, n, nil
}

// openRaw opens a metrics-free content stream when the wrapped cache supports
// OpenRaw, else falls back to Get (which counts as a hit — acceptable for the
// fallback path only).
func (c *IntegrityCache) openRaw(ctx context.Context, key string) (io.ReadCloser, error) {
	if o, ok := c.inner.(interface {
		OpenRaw(context.Context, string) (io.ReadCloser, Stat, error)
	}); ok {
		rc, _, err := o.OpenRaw(ctx, key)
		return rc, err
	}
	entry, err := c.inner.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	return entry.Content, nil
}

// --- forwarded administrative / metrics surfaces (mirrors SealedCache) ---

// Entries forwards the wrapped cache's listing for admin inspection.
func (c *IntegrityCache) Entries(ctx context.Context) ([]Stat, error) {
	if insp, ok := c.inner.(interface {
		Entries(context.Context) ([]Stat, error)
	}); ok {
		return insp.Entries(ctx)
	}
	return nil, nil
}

// GCEntries forwards the wrapped cache's GC-facing listing.
func (c *IntegrityCache) GCEntries(ctx context.Context) ([]GCEntry, error) {
	if insp, ok := c.inner.(interface {
		GCEntries(context.Context) ([]GCEntry, error)
	}); ok {
		return insp.GCEntries(ctx)
	}
	return nil, nil
}

// InFlightKeys forwards the wrapped cache's in-flight set.
func (c *IntegrityCache) InFlightKeys() map[string]struct{} {
	if insp, ok := c.inner.(interface{ InFlightKeys() map[string]struct{} }); ok {
		return insp.InFlightKeys()
	}
	return nil
}

// OpenRaw forwards the wrapped cache's metrics-free raw read.
func (c *IntegrityCache) OpenRaw(ctx context.Context, key string) (io.ReadCloser, Stat, error) {
	if o, ok := c.inner.(interface {
		OpenRaw(context.Context, string) (io.ReadCloser, Stat, error)
	}); ok {
		return o.OpenRaw(ctx, key)
	}
	return nil, Stat{}, ErrNotFound
}

// Metrics forwards the wrapped cache's activity counters so the metrics bridge
// keeps reporting hits/misses/etc. through the wrapper.
func (c *IntegrityCache) Metrics() MetricsSnapshot {
	if src, ok := c.inner.(interface{ Metrics() MetricsSnapshot }); ok {
		return src.Metrics()
	}
	return MetricsSnapshot{}
}

// CompactionStats forwards the wrapped cache's storage-efficiency statistics
// (Task 125) so the admin API and Prometheus bridge keep reporting through the
// integrity wrapper.
func (c *IntegrityCache) CompactionStats() CompactionStats {
	if src, ok := c.inner.(CompactionStatSource); ok {
		return src.CompactionStats()
	}
	return CompactionStats{Enabled: false, Codec: "none"}
}

// --- streaming fixity checker ---

// fixityChecker accumulates a hash over a content stream and renders a single
// pass/fail verdict once the whole blob has been read in order. It renders a
// verdict only when it is confident the complete content was read contiguously
// from the start — detected either by observing EOF or by reaching the end
// offset http.ServeContent discovers with its SeekEnd size probe. It tolerates
// the ServeContent seek pattern (a size probe and a content-type sniff that both
// reposition back to the start) by restarting the hash whenever the reader is
// repositioned to offset 0, and it declines to verify a non-contiguous
// (byte-range) or truncated read rather than report a false mismatch.
//
// Completeness is judged independently of the recorded size, so corruption that
// changes the blob's byte length (not just its contents) is still caught: the
// full actual stream is hashed and compared against the expected digest.
type fixityChecker struct {
	hash      hash.Hash
	expected  []byte
	algo      string
	onVerdict func(match bool, computed string)

	pos    int64 // current read offset
	hashed int64 // contiguous bytes hashed from offset 0
	end    int64 // known end offset of the stream, or -1 if not yet known
	broken bool  // a non-contiguous read occurred; a verdict can't be rendered
	sawEOF bool  // the stream was read through to EOF
	done   bool  // a verdict (or a decision to skip) has been rendered
}

// observe folds a Read result into the running hash and finalizes on EOF.
func (f *fixityChecker) observe(p []byte, n int, err error) {
	if n > 0 {
		if !f.broken && f.pos == f.hashed {
			f.hash.Write(p[:n])
			f.hashed += int64(n)
		} else {
			// Read at a position we have not contiguously hashed (a range read):
			// the whole-blob digest cannot be checked from this stream.
			f.broken = true
		}
		f.pos += int64(n)
	}
	if err == io.EOF {
		f.sawEOF = true
		f.end = f.pos
		f.finish()
	}
}

// seek records a reposition. A move back to the start restarts the hashing pass
// (covering ServeContent's size-probe and sniff-and-rewind). A SeekEnd reveals
// the stream's true end offset, which lets the checker recognize a complete read
// even when the consumer stops exactly at the end without reading the trailing
// EOF (http.ServeContent copies exactly Content-Length bytes). Any other move is
// recorded as the new position and will mark the stream non-contiguous on the
// next read.
func (f *fixityChecker) seek(abs int64, offset int64, whence int) {
	if f.done {
		return
	}
	if whence == io.SeekEnd {
		f.end = abs - offset // end-of-stream offset (offset is 0 for a size probe)
	}
	if abs == 0 {
		f.hash.Reset()
		f.hashed = 0
		f.broken = false
		f.pos = 0
		return
	}
	f.pos = abs
}

// finish renders the verdict exactly once. It reports pass/fail only when the
// entire stream was read contiguously from the start (EOF seen, or the known end
// offset reached); a partial, truncated, or out-of-order read is silently
// skipped (not a corruption signal).
func (f *fixityChecker) finish() {
	if f.done {
		return
	}
	complete := !f.broken && (f.sawEOF || (f.end >= 0 && f.hashed == f.end))
	if !complete {
		return
	}
	f.done = true
	sum := f.hash.Sum(nil)
	computed := f.algo + ":" + hex.EncodeToString(sum)
	match := subtle.ConstantTimeCompare(sum, f.expected) == 1
	if f.onVerdict != nil {
		f.onVerdict(match, computed)
	}
}

// verifyReadCloser is the forward-only verifying wrapper.
type verifyReadCloser struct {
	src io.ReadCloser
	fc  *fixityChecker
}

func (v *verifyReadCloser) Read(p []byte) (int, error) {
	n, err := v.src.Read(p)
	v.fc.observe(p, n, err)
	return n, err
}

func (v *verifyReadCloser) Close() error {
	// ServeContent copies exactly Content-Length bytes and never reads the
	// trailing EOF, so finalize here too; finish() is idempotent.
	v.fc.finish()
	return v.src.Close()
}

// verifyReadSeekCloser adds Seek so the range-serving path keeps random access.
type verifyReadSeekCloser struct {
	verifyReadCloser
	seeker io.Seeker
}

func (v *verifyReadSeekCloser) Seek(offset int64, whence int) (int64, error) {
	abs, err := v.seeker.Seek(offset, whence)
	if err == nil {
		v.fc.seek(abs, offset, whence)
	}
	return abs, err
}

// splitDigestLower parses a "algo:hexdigest" string into a lowercased algorithm
// and hex component. It reports false for an empty or malformed value.
func splitDigestLower(d string) (algo, hexsum string, ok bool) {
	i := strings.IndexByte(d, ':')
	if i <= 0 || i == len(d)-1 {
		return "", "", false
	}
	return strings.ToLower(d[:i]), strings.ToLower(d[i+1:]), true
}

// newDigestHasher returns a fresh hasher and the decoded expected digest bytes
// for a supported algorithm. It reports false for an unsupported algorithm or a
// malformed/short hex digest, so verification is strictly opt-in and never
// treats an unparseable digest as a mismatch.
func newDigestHasher(algo, hexsum string) (hash.Hash, []byte, bool) {
	var h hash.Hash
	switch algo {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return nil, nil, false
	}
	want, err := hex.DecodeString(hexsum)
	if err != nil || len(want) != h.Size() {
		return nil, nil, false
	}
	return h, want, true
}
