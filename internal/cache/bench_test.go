package cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"sync/atomic"
	"testing"
)

// Benchmarks for the cache hot paths: content-addressing (key->storage name
// hashing), read/write on both the in-memory and durable filesystem backends,
// and the single-flight de-duplication that prevents thundering-herd upstream
// fetches. See docs/performance.md for captured baselines and how to regress
// check them with benchstat.

// benchPayloads sizes the synthetic blobs used by the read/write benchmarks. A
// 4 KiB blob models a small package-manager metadata document; the larger sizes
// model typical tarball/layer reads. b.SetBytes lets `go test -bench` report the
// achieved throughput (MB/s) per size.
var benchPayloads = []struct {
	name string
	size int
}{
	{"4KiB", 4 << 10},
	{"256KiB", 256 << 10},
	{"4MiB", 4 << 20},
}

func benchBlob(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// BenchmarkContentAddress measures the per-key content-addressing cost: the
// SHA-256 over the cache key that yields a fixed-length, fan-out storage name.
// This runs on every Get/Put/Stat against the filesystem store, so its constant
// cost matters at high request rates.
func BenchmarkContentAddress(b *testing.B) {
	key := "sha256:" + "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = storageName(key)
	}
}

func BenchmarkMemoryCachePut(b *testing.B) {
	for _, p := range benchPayloads {
		blob := benchBlob(p.size)
		b.Run(p.name, func(b *testing.B) {
			c := NewMemoryCache()
			meta := map[string]string{MetaContentType: "application/octet-stream"}
			b.SetBytes(int64(p.size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key := "k" + strconv.Itoa(i)
				if _, err := c.Put(context.Background(), key, bytes.NewReader(blob), meta); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMemoryCacheGet(b *testing.B) {
	for _, p := range benchPayloads {
		blob := benchBlob(p.size)
		b.Run(p.name, func(b *testing.B) {
			c := NewMemoryCache()
			const key = "hot"
			if _, err := c.Put(context.Background(), key, bytes.NewReader(blob), nil); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(p.size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e, err := c.Get(context.Background(), key)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, e.Content); err != nil {
					b.Fatal(err)
				}
				_ = e.Content.Close()
			}
		})
	}
}

func BenchmarkFilesystemCachePut(b *testing.B) {
	for _, p := range benchPayloads {
		blob := benchBlob(p.size)
		b.Run(p.name, func(b *testing.B) {
			c, err := NewFilesystemCache(FilesystemOptions{Dir: b.TempDir()})
			if err != nil {
				b.Fatal(err)
			}
			defer c.Close()
			meta := map[string]string{MetaContentType: "application/octet-stream"}
			b.SetBytes(int64(p.size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key := "k" + strconv.Itoa(i)
				if _, err := c.Put(context.Background(), key, bytes.NewReader(blob), meta); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkFilesystemCacheGet(b *testing.B) {
	for _, p := range benchPayloads {
		blob := benchBlob(p.size)
		b.Run(p.name, func(b *testing.B) {
			c, err := NewFilesystemCache(FilesystemOptions{Dir: b.TempDir()})
			if err != nil {
				b.Fatal(err)
			}
			defer c.Close()
			const key = "hot"
			if _, err := c.Put(context.Background(), key, bytes.NewReader(blob), nil); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(p.size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e, err := c.Get(context.Background(), key)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, e.Content); err != nil {
					b.Fatal(err)
				}
				_ = e.Content.Close()
			}
		})
	}
}

// BenchmarkGetOrLoadHit measures the steady-state cache-hit path through the
// primary proxy entry point: the key is already resident, so the loader never
// runs and the cost is the index lookup plus opening a fresh content stream.
func BenchmarkGetOrLoadHit(b *testing.B) {
	c := NewMemoryCache()
	const key = "hot"
	blob := benchBlob(64 << 10)
	if _, err := c.Put(context.Background(), key, bytes.NewReader(blob), nil); err != nil {
		b.Fatal(err)
	}
	loader := func(ctx context.Context) (io.Reader, map[string]string, error) {
		b.Fatal("loader must not run on a hit")
		return nil, nil, nil
	}
	b.SetBytes(int64(len(blob)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e, err := c.GetOrLoad(context.Background(), key, loader)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, e.Content); err != nil {
			b.Fatal(err)
		}
		_ = e.Content.Close()
	}
}

// BenchmarkSingleflightDo exercises the de-duplication primitive directly. With
// -cpu>1 and RunParallel, many goroutines contend on a single hot key; the
// leader runs fn once per "generation" while the rest coalesce onto its result.
// This is the contention model of a thundering herd hitting an uncached popular
// artifact.
func BenchmarkSingleflightDo(b *testing.B) {
	sf := newSingleflight()
	var calls int64
	stat := &Stat{Key: "hot"}
	fn := func() (*Stat, error) {
		atomic.AddInt64(&calls, 1)
		return stat, nil
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, _, _ = sf.Do("hot", fn); false {
			}
		}
	})
	b.ReportMetric(float64(atomic.LoadInt64(&calls))/float64(b.N), "fn-calls/op")
}

// BenchmarkGetOrLoadContendedMiss models concurrent cold fills across a working
// set of distinct keys: each key is loaded at most once thanks to single-flight,
// then served from cache. It reports the realized loader-invocation ratio so a
// regression in de-duplication shows up as a rising fn-calls/op number.
func BenchmarkGetOrLoadContendedMiss(b *testing.B) {
	const keyspace = 64
	blob := benchBlob(8 << 10)
	var loads int64

	c := NewMemoryCache()
	loader := func(ctx context.Context) (io.Reader, map[string]string, error) {
		atomic.AddInt64(&loads, 1)
		return bytes.NewReader(blob), nil, nil
	}

	b.ReportAllocs()
	b.ResetTimer()
	var ctr int64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n := atomic.AddInt64(&ctr, 1)
			key := fmt.Sprintf("key-%d", n%keyspace)
			e, err := c.GetOrLoad(context.Background(), key, loader)
			if err != nil {
				b.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, e.Content)
			_ = e.Content.Close()
		}
	})
	b.ReportMetric(float64(atomic.LoadInt64(&loads))/float64(b.N), "loads/op")
}
