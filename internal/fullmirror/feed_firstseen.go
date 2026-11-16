package fullmirror

import (
	"bufio"
	"encoding/binary"
	"io"
	"math/bits"
	"net/http"
	"os"
	"slices"
	"time"
)

// Settling, for the helm, conda and cran feeds (Task 191).
//
// Those feeds read an index (a Helm repository's index.yaml, a conda subdir's
// repodata.json.zst, CRAN's PACKAGES.gz) and report a new file at once; the
// engine fetches it at once, through the backend — which looks the file up in
// the index's plain form, a document a CDN caches on its own and may still
// serve as it was before the file was listed (conda-forge's Cloudflare caches
// repodata.json for 20 minutes, CRAN's CloudFront PACKAGES for 30, GitHub
// Pages a chart index for 10). A file fetched before then is served
// unverified (conda, cran: the backends fail open when the index names no
// digest for it) or not at all (helm: the backend answers 404, which the
// engine does not retry). So these feeds hold a file back until it has been
// listed for a settle period, and report it with a later poll.
//
// The period is measured from when the feed first saw the file listed, on the
// registry's clock (the Date of the response that listed it, unless it is
// more than firstSeenMaxSkew from this host's clock): a record's own time
// says little about when it reached the index — conda's timestamp is when the
// package was built, an hour or more before it is indexed. A firstSeenTable
// keeps, per index document, in a file of the adapter's directory, the 64-bit
// hashes of the record lines the document listed at its last read: of those
// admitted (8 bytes each), and of those held back with when each was first
// seen. A record's line is what the copy keeps of it, so a file republished
// with another digest is settled anew; a record admitted stays admitted while
// it is listed, whatever the settle period is later set to.
//
// Where there is no table yet (the first read; a table lost or of another
// document), a record is taken to have been first seen at its own time — or,
// when that is less than firstSeenIndexLag before the document last changed
// (its Last-Modified), then: it may have been listed only then. A record
// stating no time is not held back.

// Names and bounds of a table's file.
const (
	firstSeenMagic = "PTSEEN2\n"
	// firstSeenMaxKey bounds the key a table names its document by.
	firstSeenMaxKey = 4096
	// firstSeenMaxSkew is how far a response's Date may be from this host's
	// clock to be taken as the registry's clock.
	firstSeenMaxSkew = time.Hour
	// firstSeenIndexLag is how long before a document last changed a record
	// stating its own time may have been made and yet listed only then (a
	// conda package is built, uploaded to a staging channel, validated and
	// copied before its channel indexes it).
	firstSeenIndexLag = 24 * time.Hour
)

// firstSeenHeld is a record held back: its hash and when (Unix seconds, the
// registry's clock) it was first seen.
type firstSeenHeld struct {
	hash uint64
	seen int64
}

func firstSeenCompare(a firstSeenHeld, h uint64) int {
	switch {
	case a.hash < h:
		return -1
	case a.hash > h:
		return 1
	}
	return 0
}

// firstSeenTable is the table of one read of an index document.
type firstSeenTable struct {
	f      files
	name   string
	key    string
	settle int64
	// now is the registry's clock at this read (Unix seconds), and modified
	// when the document last changed (its Last-Modified, at most now; 0 when
	// unknown).
	now      int64
	modified int64
	// settled and held are the previous read's table (sorted by hash), fresh
	// says there was none to use.
	settled []uint64
	held    []firstSeenHeld
	fresh   bool
	// This read's table: listed marks the settled records it lists (a bit
	// per record), added holds the hashes of the records it admits that the
	// previous read did not, holding those it holds back.
	listed  []uint64
	added   []uint64
	holding []firstSeenHeld
	// pending is the earliest moment (the registry's clock) a record held
	// back settles; 0 when none is.
	pending int64
	// line is a scratch buffer for a record's line.
	line []byte
}

// firstSeenOpen starts the table of a read of the document key (its URL, and
// whatever else tells it apart), kept in the file name of the adapter's
// directory (named with the adapter's type). resp is the response the
// document came with: its Date is the registry's clock (local, this host's,
// when it states none or one more than firstSeenMaxSkew away). With settle 0
// every record is admitted and no table is kept.
func firstSeenOpen(f files, name, key string, settle time.Duration, resp *http.Response, local time.Time) *firstSeenTable {
	t := &firstSeenTable{f: f, name: name, key: key, settle: int64(settle / time.Second), now: local.Unix()}
	if resp != nil {
		if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil && d.Unix() > 0 && d.Sub(local).Abs() <= firstSeenMaxSkew {
			t.now = d.Unix()
		}
		if m, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil && m.Unix() > 0 {
			t.modified = min(m.Unix(), t.now)
		}
	}
	if t.settle <= 0 || f.dir == "" {
		t.settle = 0
		return t
	}
	t.settled, t.held, t.fresh = firstSeenLoad(f, name, key)
	t.listed = make([]uint64, (len(t.settled)+63)/64)
	return t
}

// firstSeenHash is the 64-bit FNV-1a hash of a record's line.
func firstSeenHash(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

// admit notes a record this read lists (own: its own time, Unix seconds, 0
// when it states none) and reports whether it has been listed for the settle
// period.
func (t *firstSeenTable) admit(r *snapRecord, own int64) bool {
	if t.settle <= 0 {
		return true
	}
	t.line = r.appendLine(t.line[:0])
	h := firstSeenHash(t.line)
	if i, ok := slices.BinarySearch(t.settled, h); ok {
		t.listed[i/64] |= 1 << (i % 64)
		return true
	}
	seen := t.now
	if i, ok := slices.BinarySearchFunc(t.held, h, firstSeenCompare); ok {
		seen = t.held[i].seen
	} else if t.fresh {
		seen = t.firstRead(own)
	}
	if due := seen + t.settle; seen > 0 && due > t.now {
		t.holding = append(t.holding, firstSeenHeld{hash: h, seen: seen})
		if t.pending == 0 || due < t.pending {
			t.pending = due
		}
		return false
	}
	t.added = append(t.added, h)
	return true
}

// firstRead is when a record is taken to have been first seen where there is
// no table: at its own time (at most now), or when the document last changed
// if its own time is less than firstSeenIndexLag before that; 0 (not held
// back) when it states no time.
func (t *firstSeenTable) firstRead(own int64) int64 {
	if own <= 0 {
		return 0
	}
	seen := min(own, t.now)
	if t.modified > 0 && own > t.modified-int64(firstSeenIndexLag/time.Second) {
		seen = max(seen, t.modified)
	}
	return seen
}

// due is when, on this host's clock, the earliest record held back settles
// (Unix seconds): the document is read again then even if it has not changed.
// 0 when none was held back.
func (t *firstSeenTable) due(local time.Time) int64 {
	if t.pending == 0 {
		return 0
	}
	return local.Unix() + (t.pending - t.now) + 1
}

// save stores this read's table: the records it admitted, and those it held
// back with when each was first seen.
func (t *firstSeenTable) save() error {
	if t.settle <= 0 || len(t.key) > firstSeenMaxKey {
		return nil
	}
	slices.Sort(t.added)
	t.added = slices.Compact(t.added)
	slices.SortFunc(t.holding, func(a, b firstSeenHeld) int {
		if c := firstSeenCompare(a, b.hash); c != 0 {
			return c
		}
		return int(min(max(a.seen-b.seen, -1), 1))
	})
	// The same line listed twice: the first time it was seen.
	t.holding = slices.CompactFunc(t.holding, func(a, b firstSeenHeld) bool { return a.hash == b.hash })
	listed := 0
	for _, w := range t.listed {
		listed += bits.OnesCount64(w)
	}
	return t.f.write(t.name, func(w io.Writer) error {
		bw := bufio.NewWriterSize(w, 256<<10)
		var buf [16]byte
		bw.WriteString(firstSeenMagic)
		binary.BigEndian.PutUint32(buf[:4], uint32(len(t.key)))
		bw.Write(buf[:4])
		bw.WriteString(t.key)
		binary.BigEndian.PutUint64(buf[:8], uint64(listed+len(t.added)))
		binary.BigEndian.PutUint64(buf[8:], uint64(len(t.holding)))
		bw.Write(buf[:])
		// The settled records still listed and those admitted now, merged
		// in order (they are disjoint: added holds no settled hash).
		put := func(h uint64) {
			binary.BigEndian.PutUint64(buf[:8], h)
			bw.Write(buf[:8])
		}
		j := 0
		for i, h := range t.settled {
			if t.listed[i/64]&(1<<(i%64)) == 0 {
				continue
			}
			for ; j < len(t.added) && t.added[j] < h; j++ {
				put(t.added[j])
			}
			put(h)
		}
		for ; j < len(t.added); j++ {
			put(t.added[j])
		}
		for _, e := range t.holding {
			binary.BigEndian.PutUint64(buf[:8], e.hash)
			binary.BigEndian.PutUint64(buf[8:], uint64(e.seen))
			bw.Write(buf[:])
		}
		return bw.Flush()
	})
}

// firstSeenLoad reads the table of document key; fresh is true when there is
// none to use (missing, damaged, of another document).
func firstSeenLoad(f files, name, key string) (settled []uint64, held []firstSeenHeld, fresh bool) {
	fh, err := os.Open(f.path(name))
	if err != nil {
		return nil, nil, true
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, nil, true
	}
	return firstSeenDecode(bufio.NewReaderSize(fh, 256<<10), st.Size(), key)
}

// firstSeenDecode reads a table of size bytes from r, checking that it is one
// save could have written for document key.
func firstSeenDecode(r io.Reader, size int64, key string) ([]uint64, []firstSeenHeld, bool) {
	var head [len(firstSeenMagic) + 4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil || string(head[:len(firstSeenMagic)]) != firstSeenMagic {
		return nil, nil, true
	}
	n := int64(binary.BigEndian.Uint32(head[len(firstSeenMagic):]))
	if n != int64(len(key)) || n > firstSeenMaxKey {
		return nil, nil, true
	}
	k := make([]byte, n)
	if _, err := io.ReadFull(r, k); err != nil || string(k) != key {
		return nil, nil, true
	}
	var counts [16]byte
	if _, err := io.ReadFull(r, counts[:]); err != nil {
		return nil, nil, true
	}
	ns, nh := binary.BigEndian.Uint64(counts[:8]), binary.BigEndian.Uint64(counts[8:])
	body := size - int64(len(head)) - n - int64(len(counts))
	if ns > snapMaxRecords || nh > snapMaxRecords || body != int64(ns)*8+int64(nh)*16 {
		return nil, nil, true
	}
	settled := make([]uint64, ns)
	var buf [16]byte
	for i := range settled {
		if _, err := io.ReadFull(r, buf[:8]); err != nil {
			return nil, nil, true
		}
		settled[i] = binary.BigEndian.Uint64(buf[:8])
		if i > 0 && settled[i] <= settled[i-1] {
			return nil, nil, true
		}
	}
	held := make([]firstSeenHeld, nh)
	for i := range held {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, nil, true
		}
		held[i] = firstSeenHeld{hash: binary.BigEndian.Uint64(buf[:8]), seen: int64(binary.BigEndian.Uint64(buf[8:]))}
		if held[i].seen <= 0 || (i > 0 && held[i].hash <= held[i-1].hash) {
			return nil, nil, true
		}
	}
	return settled, held, false
}
