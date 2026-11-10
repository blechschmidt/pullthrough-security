package cache

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestGCEntriesReportsSizeMetadataAndAccess(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{})
	putString(t, c, "k1", "hello", map[string]string{MetaOrigin: "https://example/x", MetaPin: "true"})
	putString(t, c, "k2", "world!!", nil)

	// Read k1 a couple of times so its access count and recency advance.
	getString(t, c, "k1")
	getString(t, c, "k1")

	entries, err := c.GCEntries(context.Background())
	if err != nil {
		t.Fatalf("GCEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	byKey := map[string]GCEntry{}
	for _, e := range entries {
		byKey[e.Key] = e
	}

	k1 := byKey["k1"]
	if k1.Size != 5 {
		t.Errorf("k1 size = %d, want 5", k1.Size)
	}
	if k1.AccessCount < 2 {
		t.Errorf("k1 access count = %d, want >= 2", k1.AccessCount)
	}
	if k1.Metadata[MetaPin] != "true" {
		t.Errorf("k1 pin metadata not round-tripped: %v", k1.Metadata)
	}
	if k1.Metadata[MetaOrigin] != "https://example/x" {
		t.Errorf("k1 origin metadata missing: %v", k1.Metadata)
	}
	if k1.CreatedAt.IsZero() || k1.AccessedAt.IsZero() {
		t.Errorf("k1 timestamps not set: %+v", k1)
	}
}

func TestInFlightKeysReflectsActiveLoad(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{})

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_, _ = c.GetOrLoad(context.Background(), "slow", func(ctx context.Context) (io.Reader, map[string]string, error) {
			close(started)
			<-release
			return strings.NewReader("payload"), nil, nil
		})
		close(done)
	}()

	<-started
	if keys := c.InFlightKeys(); len(keys) != 1 {
		t.Fatalf("InFlightKeys during load = %v, want 1 key", keys)
	}
	if _, ok := c.InFlightKeys()["slow"]; !ok {
		t.Fatalf("expected 'slow' to be in-flight")
	}
	// GCEntries should mark the in-flight key (it is also visible once written;
	// the flag is what matters for eviction safety).
	close(release)
	<-done
	if keys := c.InFlightKeys(); len(keys) != 0 {
		t.Errorf("InFlightKeys after load = %v, want empty", keys)
	}
}
