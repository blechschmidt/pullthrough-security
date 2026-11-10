package chaos

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// TestPoolRetryableClassification is a table-driven sweep of the mirror pool's
// failure classifier: 5xx/429 are retryable (fail over to a mirror), while every
// other status — including 4xx and 3xx — is a terminal answer returned directly
// without failover or a circuit trip. This pins the boundary that decides
// whether a degraded upstream triggers resilience machinery at all.
func TestPoolRetryableClassification(t *testing.T) {
	cases := []struct {
		status       int
		wantFailover bool
	}{
		{http.StatusOK, false},
		{http.StatusMovedPermanently, false},
		{http.StatusBadRequest, false},
		{http.StatusUnauthorized, false},
		{http.StatusForbidden, false},
		{http.StatusNotFound, false},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
	}
	for _, c := range cases {
		c := c
		t.Run(http.StatusText(c.status), func(t *testing.T) {
			primary := StatusDoer(c.status, "primary")
			mirror := HealthyDoer("mirror")
			pool, err := newPool(NewManualClock(), 5, 2, 30*time.Second, primary, mirror)
			if err != nil {
				t.Fatalf("newPool: %v", err)
			}
			resp, err := pool.Do(context.Background(), poolRequest())
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if c.wantFailover {
				if resp.Status != http.StatusOK || mirror.Count() != 1 {
					t.Fatalf("status %d: got resp=%d mirror=%d, want failover to a 200 mirror",
						c.status, resp.Status, mirror.Count())
				}
			} else {
				if resp.Status != c.status || mirror.Count() != 0 {
					t.Fatalf("status %d: got resp=%d mirror=%d, want direct return with no failover",
						c.status, resp.Status, mirror.Count())
				}
			}
		})
	}
}

// TestFaultyCacheFaults is a table-driven check that each injected storage fault
// is surfaced to the caller as an error rather than silently swallowed.
func TestFaultyCacheFaults(t *testing.T) {
	cases := []struct {
		name  string
		apply func(*FaultyCache) *FaultyCache
	}{
		{"get-error", func(c *FaultyCache) *FaultyCache { return c.WithGetError(errInjected) }},
		{"put-error", func(c *FaultyCache) *FaultyCache { return c.WithPutError(errInjected) }},
		{"getorload-error", func(c *FaultyCache) *FaultyCache { return c.WithGetOrLoadError(errInjected) }},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			fc := c.apply(NewFaultyCache(cache.NewMemoryCache()))
			_, err := fc.GetOrLoad(context.Background(), "k", func(context.Context) (io.Reader, map[string]string, error) {
				return readerOf("payload"), nil, nil
			})
			if err == nil {
				t.Fatalf("%s: GetOrLoad returned nil error, want the injected fault surfaced", c.name)
			}
		})
	}
}

// TestFaultyCacheCorruptionBoundary documents the integrity boundary: the proxy
// verifies content digests at fill time (see ST-FILL-INTEGRITY) but performs no
// checksum-on-read, so a blob corrupted at rest is served as-is. The corruption
// primitive exists to make that boundary explicit and testable rather than
// assumed.
func TestFaultyCacheCorruptionBoundary(t *testing.T) {
	ctx := context.Background()
	fc := NewFaultyCache(cache.NewMemoryCache()).WithCorruptReads()
	const body = "CLEAN-BYTES"
	if _, err := fc.Put(ctx, "k", readerOf(body), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	entry, err := fc.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer entry.Content.Close()
	got, err := io.ReadAll(entry.Content)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) == body {
		t.Fatal("corruption primitive did not alter the stream")
	}
	if got[0] != (body[0] ^ 0xff) {
		t.Fatalf("expected first byte flipped, got %#x", got[0])
	}
}

// TestManualClockAdvance verifies the deterministic clock the breaker/TTL
// scenarios depend on.
func TestManualClockAdvance(t *testing.T) {
	c := NewManualClock()
	start := c.Now()
	c.Advance(90 * time.Second)
	if got := c.Now().Sub(start); got != 90*time.Second {
		t.Fatalf("advance = %v, want 90s", got)
	}
}

func readerOf(s string) io.Reader { return io.NopCloser(stringReader(s)) }

type stringReader string

func (s stringReader) Read(p []byte) (int, error) {
	if len(s) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s)
	return n, io.EOF
}
