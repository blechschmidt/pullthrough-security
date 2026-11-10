package chaos

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// FaultyCache wraps a cache.Cache and injects storage-backend faults: errors on
// Get / Put / GetOrLoad (modeling an S3 timeout or 5xx that the s3client surfaces
// as a non-nil error), added latency, and silent on-read content corruption. It
// is the primitive for the storage-dependency resilience scenarios.
//
// A zero-value field means "do not inject that fault"; the wrapper then behaves
// exactly like the inner cache. FaultyCache is safe for concurrent use.
type FaultyCache struct {
	// Inner is the delegate cache. Required.
	Inner cache.Cache

	mu          sync.Mutex
	getErr      error
	putErr      error
	getOrLoad   error
	corruptRead bool
	latency     time.Duration

	gets atomic.Int64
	puts atomic.Int64
}

var _ cache.Cache = (*FaultyCache)(nil)

// NewFaultyCache wraps inner.
func NewFaultyCache(inner cache.Cache) *FaultyCache {
	return &FaultyCache{Inner: inner}
}

// WithGetError makes Get and GetOrLoad's post-fill re-open fail with err.
func (c *FaultyCache) WithGetError(err error) *FaultyCache {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getErr = err
	return c
}

// WithPutError makes Put (and therefore a cache-filling GetOrLoad) fail with err.
func (c *FaultyCache) WithPutError(err error) *FaultyCache {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putErr = err
	return c
}

// WithGetOrLoadError makes GetOrLoad fail with err before the loader runs,
// modeling a storage backend that is unreachable on the read-through path.
func (c *FaultyCache) WithGetOrLoadError(err error) *FaultyCache {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getOrLoad = err
	return c
}

// WithCorruptReads flips the first byte of every returned content stream,
// modeling silent bit-rot / corruption of a blob at rest. (The proxy performs
// no checksum-on-read, so this documents the boundary of the integrity
// guarantee: corruption is prevented at fill time, not detected at read time.)
func (c *FaultyCache) WithCorruptReads() *FaultyCache {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.corruptRead = true
	return c
}

// WithLatency adds d of (context-cancelable) delay before each operation.
func (c *FaultyCache) WithLatency(d time.Duration) *FaultyCache {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.latency = d
	return c
}

// Gets and Puts report how many times the respective operations were attempted.
func (c *FaultyCache) Gets() int64 { return c.gets.Load() }
func (c *FaultyCache) Puts() int64 { return c.puts.Load() }

func (c *FaultyCache) snapshot() (getErr, putErr, gol error, corrupt bool, latency time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getErr, c.putErr, c.getOrLoad, c.corruptRead, c.latency
}

// delay sleeps for the configured latency, respecting context cancellation.
func (c *FaultyCache) delay(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Get implements cache.Cache.
func (c *FaultyCache) Get(ctx context.Context, key string) (*cache.Entry, error) {
	c.gets.Add(1)
	getErr, _, _, corrupt, latency := c.snapshot()
	if err := c.delay(ctx, latency); err != nil {
		return nil, err
	}
	if getErr != nil {
		return nil, getErr
	}
	entry, err := c.Inner.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if corrupt {
		entry.Content = corruptReader(entry.Content)
	}
	return entry, nil
}

// Put implements cache.Cache.
func (c *FaultyCache) Put(ctx context.Context, key string, r io.Reader, metadata map[string]string) (*cache.Stat, error) {
	c.puts.Add(1)
	_, putErr, _, _, latency := c.snapshot()
	if err := c.delay(ctx, latency); err != nil {
		return nil, err
	}
	if putErr != nil {
		// Drain so a streaming loader is not left blocked on a reader nobody reads.
		_, _ = io.Copy(io.Discard, r)
		return nil, putErr
	}
	return c.Inner.Put(ctx, key, r, metadata)
}

// GetOrLoad implements cache.Cache.
func (c *FaultyCache) GetOrLoad(ctx context.Context, key string, loader cache.Loader) (*cache.Entry, error) {
	getErr, putErr, gol, corrupt, latency := c.snapshot()
	if err := c.delay(ctx, latency); err != nil {
		return nil, err
	}
	if gol != nil {
		return nil, gol
	}
	// A Put fault must surface through the fill path too: run the loader (so the
	// upstream fetch still happens, as it would before the store write) and then
	// fail the commit, modeling a storage write that times out / 5xxs. Nothing is
	// cached, so the entry is never served from a failed fill.
	if putErr != nil {
		r, _, err := loader(ctx)
		if rc, ok := r.(io.Closer); ok {
			_ = rc.Close()
		}
		if err != nil {
			return nil, err
		}
		return nil, putErr
	}
	entry, err := c.Inner.GetOrLoad(ctx, key, loader)
	if err != nil {
		return nil, err
	}
	if getErr != nil {
		_ = entry.Content.Close()
		return nil, getErr
	}
	if corrupt {
		entry.Content = corruptReader(entry.Content)
	}
	return entry, nil
}

// Stat implements cache.Cache.
func (c *FaultyCache) Stat(ctx context.Context, key string) (*cache.Stat, error) {
	return c.Inner.Stat(ctx, key)
}

// Delete implements cache.Cache.
func (c *FaultyCache) Delete(ctx context.Context, key string) error {
	return c.Inner.Delete(ctx, key)
}

// Close implements cache.Cache.
func (c *FaultyCache) Close() error { return c.Inner.Close() }

// corruptReader returns a ReadCloser that flips the first byte of the stream.
func corruptReader(rc io.ReadCloser) io.ReadCloser {
	return &flipReader{rc: rc}
}

type flipReader struct {
	rc      io.ReadCloser
	flipped bool
}

func (f *flipReader) Read(p []byte) (int, error) {
	n, err := f.rc.Read(p)
	if n > 0 && !f.flipped {
		p[0] ^= 0xff
		f.flipped = true
	}
	return n, err
}

func (f *flipReader) Close() error { return f.rc.Close() }

// FaultyUpstream is a fault-injecting HTTP origin for end-to-end gateway
// scenarios. It fronts an httptest.Server whose behavior is controlled by a
// [UpstreamMode], and counts the requests it actually serviced so a test can
// prove singleflight collapsed a herd or the negative cache absorbed a burst.
type FaultyUpstream struct {
	srv  *httptest.Server
	hits atomic.Int64

	// release gates the Slow mode: the handler blocks on it until Release is
	// called, so a test can hold an upstream fetch open while concurrent callers
	// coalesce onto it.
	release chan struct{}
}

// UpstreamMode selects the fault a FaultyUpstream injects.
type UpstreamMode int

const (
	// ModeHealthy serves 200 with the configured body.
	ModeHealthy UpstreamMode = iota
	// ModeNotFound serves 404 (a terminal, negatively-cacheable condition).
	ModeNotFound
	// ModeServerError serves 503 (a transient, retryable condition).
	ModeServerError
	// ModeSlow blocks until Release is called, then serves 200. Use it to hold a
	// fetch open while concurrent callers join the single in-flight leader.
	ModeSlow
	// ModeTruncated serves a Content-Length header larger than the body it then
	// writes, modeling a partial/truncated upstream response.
	ModeTruncated
)

// NewFaultyUpstream starts a FaultyUpstream in the given mode serving body.
func NewFaultyUpstream(mode UpstreamMode, body string) *FaultyUpstream {
	u := &FaultyUpstream{release: make(chan struct{})}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		switch mode {
		case ModeNotFound:
			http.Error(w, "not found", http.StatusNotFound)
		case ModeServerError:
			http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
		case ModeSlow:
			select {
			case <-u.release:
			case <-r.Context().Done():
				return
			}
			_, _ = io.WriteString(w, body)
		case ModeTruncated:
			w.Header().Set("Content-Length", "1048576") // claim 1 MiB...
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, body) // ...then write far less and hang up
		default:
			_, _ = io.WriteString(w, body)
		}
	}))
	return u
}

// URL is the base URL of the upstream server.
func (u *FaultyUpstream) URL() string { return u.srv.URL }

// Hits returns how many requests the upstream has serviced.
func (u *FaultyUpstream) Hits() int64 { return u.hits.Load() }

// Release unblocks all callers waiting in ModeSlow.
func (u *FaultyUpstream) Release() { close(u.release) }

// Close stops the server.
func (u *FaultyUpstream) Close() { u.srv.Close() }
