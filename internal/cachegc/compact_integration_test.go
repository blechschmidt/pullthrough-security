package cachegc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// TestGCEngineOverCompactingDedupCache exercises the full interaction of the
// garbage-collection engine (Task 39) with the transparent compression +
// deduplication storage layer (Task 125): the engine evicts logical entries
// under size pressure, each eviction flows through the compacting store's
// reference-counted Delete, and chunks shared by surviving entries are never
// lost. It proves eviction does not corrupt deduplicated content.
func TestGCEngineOverCompactingDedupCache(t *testing.T) {
	ctx := context.Background()

	fs, err := cache.NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	cs, err := cache.NewCompactStore(fs, cache.CompactOptions{Codec: "zstd", Level: 3, Dedup: true})
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	c, err := cache.NewFilesystemCache(cache.FilesystemOptions{Store: cs})
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// A large common region shared by every artifact, plus a unique header each.
	var common bytes.Buffer
	for common.Len() < 400*1024 {
		fmt.Fprintf(&common, "shared payload line %08d\n", common.Len())
	}
	blobs := make(map[string][]byte)
	for i := 0; i < 6; i++ {
		key := fmt.Sprintf("art-%d", i)
		body := append([]byte(fmt.Sprintf("UNIQUE-HEADER-%d\n", i)), common.Bytes()...)
		blobs[key] = body
		if _, err := c.Put(ctx, key, bytes.NewReader(body), nil); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}

	st := cs.CompactionStats()
	if st.DedupChunksReused == 0 {
		t.Fatalf("expected chunk reuse across the six artifacts, got %+v", st)
	}

	// Drive the GC engine with a capacity that forces eviction down to the low
	// watermark. Logical size per entry is ~400 KiB; cap at ~1.2 MiB so only a
	// few survive.
	eng, err := New(Config{
		Enabled:          true,
		CapacityBytes:    1200 * 1024,
		HighWatermarkPct: 0.9,
		LowWatermarkPct:  0.5,
		Policy:           PolicyLRU,
	}, c, Options{})
	if err != nil {
		t.Fatalf("New engine: %v", err)
	}
	rep, err := eng.Run(ctx, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.EvictedCount == 0 {
		t.Fatalf("expected the GC engine to evict entries, got report %+v", rep)
	}

	// Every surviving entry must still read back byte-exact: the shared chunks
	// they rely on must not have been deleted along with the evicted entries.
	survivors := 0
	for key, want := range blobs {
		entry, err := c.Get(ctx, key)
		if err != nil {
			continue // evicted
		}
		got, rerr := io.ReadAll(entry.Content)
		entry.Content.Close()
		if rerr != nil {
			t.Fatalf("read survivor %s: %v", key, rerr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("survivor %s content corrupted after GC eviction", key)
		}
		survivors++
	}
	if survivors == 0 {
		t.Fatalf("expected at least one artifact to survive eviction")
	}
	if survivors == len(blobs) {
		t.Fatalf("expected some artifacts to be evicted, all %d survived", survivors)
	}
}
