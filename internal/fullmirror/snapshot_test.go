package fullmirror

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// snapTestRecords is a small index: two packages with versions and files, one
// package-level record, names that need escaping and sort unlike Go strings.
func snapTestRecords() []snapRecord {
	return []snapRecord{
		{Name: "zlib", Version: "1.3.1", Path: "/pool/main/z/zlib/zlib_1.3.1_amd64.deb", Index: "main/binary-amd64", Size: 100, Digest: "aa"},
		{Name: "zlib", Version: "1.3.1", Path: "/pool/main/z/zlib/zlib_1.3.1_arm64.deb", Index: "main/binary-arm64", Size: 101, Digest: "ab"},
		{Name: "zlib", Version: "1.2.13", Path: "/pool/main/z/zlib/zlib_1.2.13_amd64.deb", Index: "main/binary-amd64", Size: 99, Time: 1700000000},
		{Name: "curl", Version: "8.5.0", Path: "/pool/main/c/curl/curl_8.5.0_amd64.deb", Size: 300, Yanked: true},
		{Name: "curl", Time: 1700000001},
		{Name: `quote"d`, Version: "1"},
		{Name: "foo", Version: "1"},
		{Name: "foo!", Version: "2"},
		{Name: `back\slash`, Version: "3"},
	}
}

func buildSnap(t testing.TB, f files, recs []snapRecord, limit int) *snapHeader {
	t.Helper()
	b := f.newSnapBuilder("test")
	if limit > 0 {
		b.limit = limit
	}
	for _, r := range recs {
		b.Add(r)
	}
	h, err := b.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return h
}

func readAll(t testing.TB, f files, h *snapHeader) []snapRecord {
	t.Helper()
	r, err := f.openSnapshot(h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var out []snapRecord
	for r.Next() {
		out = append(out, r.Record())
	}
	if err := r.Err(); err != nil {
		t.Fatalf("reading the copy: %v", err)
	}
	return out
}

// The same records make the same copy, whatever the order they are added in,
// duplicates once; invalid records are dropped; every package reads back.
func TestSnapshotIsCanonical(t *testing.T) {
	f := files{dir: t.TempDir()}
	recs := snapTestRecords()
	h1 := buildSnap(t, f, recs, 0)

	shuffled := append([]snapRecord(nil), recs...)
	shuffled = append(shuffled, recs[0], recs[3]) // duplicates
	rand.New(rand.NewSource(1)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	b := f.newSnapBuilder("test")
	for _, r := range shuffled {
		b.Add(r)
	}
	for _, bad := range []snapRecord{
		{Name: ""}, {Name: "a\nb"}, {Name: "ok", Version: "1\x00"}, {Name: "ok", Path: "relative"},
		{Name: "ok", Path: "/a/../b"}, {Name: "ok", Size: -1}, {Name: "bad\xffutf8"}, {Name: strings.Repeat("x", 1025)},
	} {
		if b.Add(bad) {
			t.Errorf("Add(%+v) kept an invalid record", bad)
		}
	}
	if b.Dropped() != 8 {
		t.Errorf("dropped %d, want 8", b.Dropped())
	}
	h2, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if h1.Digest != h2.Digest {
		t.Fatalf("the same records made two copies: %s and %s", h1.Digest, h2.Digest)
	}
	if h1.Names != 6 || h1.Records != len(recs) {
		t.Errorf("names %d records %d, want 6 and %d", h1.Names, h1.Records, len(recs))
	}
	got := readAll(t, f, h1)
	if len(got) != len(recs) {
		t.Fatalf("read %d records back, want %d", len(got), len(recs))
	}
	// Every package's records come back from a lookup, and only its.
	byName := map[string][]snapRecord{}
	for _, r := range recs {
		byName[r.Name] = append(byName[r.Name], r)
	}
	for name, want := range byName {
		got, err := f.snapLookup(h1, name)
		if err != nil {
			t.Fatalf("lookup %q: %v", name, err)
		}
		sortRecs(got)
		sortRecs(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("lookup %q = %+v, want %+v", name, got, want)
		}
	}
	for _, missing := range []string{"", "a", "zzz", "foo!!", "curl2", `quote`} {
		if got, err := f.snapLookup(h1, missing); err != nil || len(got) != 0 {
			t.Errorf("lookup %q = %v, %v; want nothing", missing, got, err)
		}
	}
}

func sortRecs(rs []snapRecord) {
	sort.Slice(rs, func(i, j int) bool {
		return string(rs[i].appendLine(nil)) < string(rs[j].appendLine(nil))
	})
}

// A copy built in spilled runs is the copy built in memory; lookups find every
// package across many blocks.
func TestSnapshotSpillsRunsAndSplitsBlocks(t *testing.T) {
	f := files{dir: t.TempDir()}
	var recs []snapRecord
	for i := 0; i < 20000; i++ {
		name := fmt.Sprintf("pkg-%05d", i*7919%20000)
		recs = append(recs, snapRecord{Name: name, Version: fmt.Sprintf("1.%d", i%5), Path: "/files/" + name + ".tgz", Size: int64(i)})
	}
	mem := buildSnap(t, f, recs, 0)
	spilled := buildSnap(t, f, recs, 64<<10)
	if mem.Digest != spilled.Digest {
		t.Fatalf("spilled runs made another copy: %s vs %s", spilled.Digest, mem.Digest)
	}
	if len(mem.Blocks) < 10 {
		t.Fatalf("only %d blocks; the test wants many", len(mem.Blocks))
	}
	left, _ := os.ReadDir(f.dir)
	for _, e := range left {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
	for _, i := range []int{0, 1, 7777, 19999} {
		name := fmt.Sprintf("pkg-%05d", i)
		got, err := f.snapLookup(mem, name)
		if err != nil || len(got) != 1 || got[0].Name != name {
			t.Errorf("lookup %s = %+v, %v", name, got, err)
		}
	}
	// Listing pages through every package once, in the copy's order.
	var all []string
	after := ""
	for {
		names, more, err := f.snapListNames(mem, after, 3333)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, names...)
		if !more {
			break
		}
		after = names[len(names)-1]
	}
	if len(all) != 20000 || !sort.StringsAreSorted(all) {
		t.Errorf("listed %d names (sorted: %v)", len(all), sort.StringsAreSorted(all))
	}
}

func diffOf(t *testing.T, f files, a, b *snapHeader) []string {
	t.Helper()
	ra, err := f.openSnapshot(a, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ra.Close()
	rb, err := f.openSnapshot(b, true)
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Close()
	var out []string
	if err := snapDiff(ra, rb, func(c Coordinate) bool {
		s := c.String()
		if c.Deleted {
			s += " (deleted)"
		}
		out = append(out, s)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// The difference of two copies names new packages, gone packages, versions
// added, changed or gone, and a whole package when its package-level records
// changed.
func TestSnapshotDiff(t *testing.T) {
	f := files{dir: t.TempDir()}
	old := buildSnap(t, f, snapTestRecords(), 0)
	recs := snapTestRecords()
	recs[0].Digest = "changed"                                                        // zlib 1.3.1 changed
	recs = append(recs[:2], recs[3:]...)                                              // zlib 1.2.13 gone
	recs = append(recs, snapRecord{Name: "zlib", Version: "1.4.0", Path: "/new.deb"}) // added
	recs[3].Time = 1800000000                                                         // curl's package record moved
	recs = append(recs, snapRecord{Name: "brand-new", Version: "0.1"})
	var kept []snapRecord
	for _, r := range recs {
		if r.Name != "foo!" { // gone
			kept = append(kept, r)
		}
	}
	cur := buildSnap(t, f, kept, 0)
	got := diffOf(t, f, old, cur)
	// Unchanged packages (foo, back\slash, quote"d) are not listed.
	expect := map[string]bool{
		"brand-new":             true,
		"curl":                  true,
		"foo! (deleted)":        true,
		"zlib@1.3.1":            true,
		"zlib@1.4.0":            true,
		"zlib@1.2.13 (deleted)": true,
	}
	if len(got) != len(expect) {
		t.Fatalf("difference %q, want %v", got, expect)
	}
	for _, g := range got {
		if !expect[g] {
			t.Errorf("unexpected difference %q (all: %q)", g, got)
		}
	}
	if d := diffOf(t, f, cur, cur); len(d) != 0 {
		t.Errorf("a copy differs from itself: %q", d)
	}
	// Stopping early stops.
	ra, _ := f.openSnapshot(old, true)
	rb, _ := f.openSnapshot(cur, true)
	n := 0
	_ = snapDiff(ra, rb, func(Coordinate) bool { n++; return false })
	ra.Close()
	rb.Close()
	if n != 1 {
		t.Errorf("emit returned false but the walk went on (%d)", n)
	}
}

// A copy that does not match its name, or whose file was damaged, is never
// trusted.
func TestSnapshotDetectsDamage(t *testing.T) {
	f := files{dir: t.TempDir()}
	var recs []snapRecord
	for i := 0; i < 3000; i++ {
		recs = append(recs, snapRecord{Name: fmt.Sprintf("p%04d", i), Version: "1", Path: fmt.Sprintf("/f/%d", i)})
	}
	h := buildSnap(t, f, recs, 0)
	path := f.path(snapName(h.Digest))
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	restore := func() {
		if err := os.WriteFile(path, orig, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Another adapter's copy, a wrong digest, a missing file.
	if _, err := f.readSnapHeader(h.Digest, "other"); !errors.Is(err, errSnapInvalid) {
		t.Errorf("another kind: %v", err)
	}
	if _, err := f.readSnapHeader(strings.Repeat("0", 64), "test"); !errors.Is(err, errSnapInvalid) {
		t.Errorf("missing: %v", err)
	}
	if _, err := f.readSnapHeader("../x", "test"); !errors.Is(err, errSnapInvalid) {
		t.Errorf("not a digest: %v", err)
	}

	// A flipped byte inside the last block: the block's CRC fails a lookup
	// and a full read.
	damaged := append([]byte(nil), orig...)
	damaged[len(damaged)-20] ^= 0xff
	if err := os.WriteFile(path, damaged, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.snapLookup(h, "p2999"); !errors.Is(err, errSnapInvalid) {
		t.Errorf("lookup in a damaged block: %v", err)
	}
	r, err := f.openSnapshot(h, true)
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
	}
	if !errors.Is(r.Err(), errSnapInvalid) {
		t.Errorf("full read of a damaged copy: %v", r.Err())
	}
	r.Close()
	restore()

	// A truncated file no longer matches its header.
	if err := os.WriteFile(path, orig[:len(orig)-1], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.readSnapHeader(h.Digest, "test"); !errors.Is(err, errSnapInvalid) {
		t.Errorf("truncated: %v", err)
	}
	restore()

	// Another valid copy renamed to this one's name: its records do not match
	// the digest.
	other := buildSnap(t, f, recs[:10], 0)
	data, _ := os.ReadFile(f.path(snapName(other.Digest)))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.readSnapHeader(h.Digest, "test"); !errors.Is(err, errSnapInvalid) {
		t.Errorf("another copy under this name: %v", err)
	}
	restore()
	if got := readAll(t, f, h); len(got) != len(recs) {
		t.Errorf("restored copy reads %d records", len(got))
	}
}

// An empty index is a copy too.
func TestSnapshotEmpty(t *testing.T) {
	f := files{dir: t.TempDir()}
	h := buildSnap(t, f, nil, 0)
	if h.Names != 0 || len(readAll(t, f, h)) != 0 {
		t.Fatalf("empty copy: %+v", h)
	}
	if got, err := f.snapLookup(h, "x"); err != nil || got != nil {
		t.Errorf("lookup in an empty copy: %v %v", got, err)
	}
	if names, more, err := f.snapListNames(h, "", 10); err != nil || len(names) != 0 || more {
		t.Errorf("listing an empty copy: %v %v %v", names, more, err)
	}
}

// Lookups run concurrently (Releases is called from several workers).
func TestSnapshotConcurrentLookups(t *testing.T) {
	f := files{dir: t.TempDir()}
	var recs []snapRecord
	for i := 0; i < 5000; i++ {
		recs = append(recs, snapRecord{Name: fmt.Sprintf("n%d", i), Version: "1"})
	}
	h := buildSnap(t, f, recs, 0)
	var wg sync.WaitGroup
	var bad atomic.Int32
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < 5000; i += 8 {
				got, err := f.snapLookup(h, fmt.Sprintf("n%d", i))
				if err != nil || len(got) != 1 {
					bad.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Errorf("%d lookups failed", bad.Load())
	}
}

// Building a copy of a large index holds a bounded amount of memory: records
// spill to sorted runs instead of accumulating.
func TestSnapshotBuildMemoryIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a large copy")
	}
	f := files{dir: t.TempDir()}
	b := f.newSnapBuilder("test")
	b.limit = 8 << 20
	peak := sampleHeap(t, func() {
		for i := 0; i < 600_000; i++ {
			// ~120 bytes per record: 72 MB of records in all.
			b.Add(snapRecord{
				Name:    fmt.Sprintf("package-%07d", (i*104729)%600_000),
				Version: fmt.Sprintf("%d.%d.%d", i%7, i%11, i%13),
				Path:    fmt.Sprintf("/linux-64/package-%07d-%d.conda", i, i%3),
				Size:    int64(i) * 1000, Digest: fmt.Sprintf("%016x", i),
			})
		}
		h, err := b.Finish()
		if err != nil {
			t.Fatal(err)
		}
		if h.Records != 600_000 {
			t.Errorf("records %d", h.Records)
		}
	})
	const ceiling = 160 << 20
	t.Logf("peak heap while building a copy of 600,000 records: %d MiB", peak>>20)
	if peak > ceiling {
		t.Errorf("building the copy held %d MiB of heap; the bound is %d MiB", peak>>20, ceiling>>20)
	}
}

// sampleHeap runs fn and returns the highest heap in use observed while it
// ran (sampled every millisecond, after a collection before it starts).
func sampleHeap(t testing.TB, fn func()) uint64 {
	t.Helper()
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				runtime.ReadMemStats(&m)
				if m.HeapInuse > base.HeapInuse && m.HeapInuse-base.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse - base.HeapInuse)
				}
			}
		}
	}()
	fn()
	close(stop)
	<-done
	return peak.Load()
}
