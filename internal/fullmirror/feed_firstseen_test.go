package fullmirror

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

// firstSeenResponse is a response stating the registry's clock and when the
// document last changed (zero times are left out).
func firstSeenResponse(date, modified time.Time) *http.Response {
	h := http.Header{}
	if !date.IsZero() {
		h.Set("Date", date.UTC().Format(http.TimeFormat))
	}
	if !modified.IsZero() {
		h.Set("Last-Modified", modified.UTC().Format(http.TimeFormat))
	}
	return &http.Response{StatusCode: http.StatusOK, Header: h}
}

// firstSeenRead admits recs (with their own times) in one read and returns
// which were admitted, the table saved.
func firstSeenRead(t *testing.T, f files, key string, settle time.Duration, resp *http.Response, local time.Time, recs []snapRecord, own []int64) ([]bool, *firstSeenTable) {
	t.Helper()
	table := firstSeenOpen(f, "x-firstseen.bin", key, settle, resp, local)
	out := make([]bool, len(recs))
	for i := range recs {
		out[i] = table.admit(&recs[i], own[i])
	}
	if err := table.save(); err != nil {
		t.Fatal(err)
	}
	return out, table
}

func TestFirstSeenTableHoldsNewRecordsForTheSettlePeriod(t *testing.T) {
	f := files{dir: t.TempDir()}
	t0 := time.Date(2026, 11, 16, 6, 0, 0, 0, time.UTC)
	old := snapRecord{Name: "old", Version: "1.0", Path: "/old-1.0.tgz"}
	built := snapRecord{Name: "built", Version: "2.0", Path: "/built-2.0.tgz"}
	timeless := snapRecord{Name: "timeless", Version: "3.0", Path: "/timeless-3.0.tgz"}
	future := snapRecord{Name: "future", Version: "4.0", Path: "/future-4.0.tgz"}
	recs := []snapRecord{old, built, timeless, future}
	// A first read, the document changed a minute ago: a record made long
	// before is admitted; one made two hours before the document changed
	// may have been listed only then; one stating no time is not held; one
	// dated in the future is taken as seen now.
	own := []int64{t0.Add(-72 * time.Hour).Unix(), t0.Add(-2 * time.Hour).Unix(), 0, t0.Add(time.Hour).Unix()}
	got, table := firstSeenRead(t, f, "doc", 30*time.Minute, firstSeenResponse(t0, t0.Add(-time.Minute)), t0, recs, own)
	if want := []bool{true, false, true, false}; !firstSeenEqual(got, want) {
		t.Fatalf("first read: admitted %v, want %v", got, want)
	}
	if !table.fresh {
		t.Errorf("a first read found a table")
	}
	// The earliest held record settles at Last-Modified + 30m = t0 + 29m.
	if due := table.due(t0); due != t0.Add(29*time.Minute).Unix()+1 {
		t.Errorf("due %v, want %v", time.Unix(due, 0).UTC(), t0.Add(29*time.Minute))
	}
	// Ten minutes later, with a table: nothing has settled; a record not
	// listed before is first seen now, whatever its own time.
	newer := snapRecord{Name: "newer", Version: "5.0", Path: "/newer-5.0.tgz"}
	t1 := t0.Add(10 * time.Minute)
	got, table = firstSeenRead(t, f, "doc", 30*time.Minute, firstSeenResponse(t1, t1), t1, append(recs, newer), append(own, t0.Add(-1000*time.Hour).Unix()))
	if want := []bool{true, false, true, false, false}; !firstSeenEqual(got, want) {
		t.Fatalf("second read: admitted %v, want %v", got, want)
	}
	if table.fresh {
		t.Errorf("the second read found no table")
	}
	// At t0 + 30m the records held since the first read have settled;
	// newer (first seen at t1) settles at t1 + 30m.
	t2 := t0.Add(30 * time.Minute)
	got, table = firstSeenRead(t, f, "doc", 30*time.Minute, firstSeenResponse(t2, t1), t2, append(recs, newer), append(own, 0))
	if want := []bool{true, true, true, true, false}; !firstSeenEqual(got, want) {
		t.Fatalf("third read: admitted %v, want %v", got, want)
	}
	if due := table.due(t2); due != t1.Add(30*time.Minute).Unix()+1 {
		t.Errorf("due %v, want %v", time.Unix(due, 0).UTC(), t1.Add(30*time.Minute))
	}
	t3 := t1.Add(30 * time.Minute)
	got, table = firstSeenRead(t, f, "doc", 30*time.Minute, firstSeenResponse(t3, t1), t3, append(recs, newer), append(own, 0))
	if want := []bool{true, true, true, true, true}; !firstSeenEqual(got, want) || table.due(t3) != 0 {
		t.Fatalf("fourth read: admitted %v, want %v; due %d", got, want, table.due(t3))
	}
	// A record republished (another digest) is a new line: settled anew.
	re := old
	re.Digest = "0123abcd"
	t4 := t3.Add(time.Hour)
	got, _ = firstSeenRead(t, f, "doc", 30*time.Minute, firstSeenResponse(t4, t4), t4, []snapRecord{re, built}, []int64{own[0], own[1]})
	if want := []bool{false, true}; !firstSeenEqual(got, want) {
		t.Fatalf("a republished record: admitted %v, want %v", got, want)
	}
	// A record gone from a read is forgotten: listed again, it is new.
	got, _ = firstSeenRead(t, f, "doc", 30*time.Minute, firstSeenResponse(t4, t4), t4, []snapRecord{re, old}, []int64{own[0], own[0]})
	if want := []bool{false, false}; !firstSeenEqual(got, want) {
		t.Fatalf("a record listed again: admitted %v, want %v", got, want)
	}
}

func firstSeenEqual(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The registry's clock is its Date, unless that is more than an hour from
// this host's; settle 0 (or no directory) admits everything and keeps no
// table.
func TestFirstSeenTableClock(t *testing.T) {
	local := time.Date(2026, 11, 16, 6, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		date time.Time
		want time.Time
	}{
		{local.Add(-50 * time.Minute), local.Add(-50 * time.Minute)},
		{local.Add(59 * time.Minute), local.Add(59 * time.Minute)},
		{local.Add(-2 * time.Hour), local},
		{local.Add(30 * 24 * time.Hour), local},
		{time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC), local},
		{time.Time{}, local},
	} {
		table := firstSeenOpen(files{dir: t.TempDir()}, "x-firstseen.bin", "doc", time.Minute, firstSeenResponse(tc.date, time.Time{}), local)
		if table.now != tc.want.Unix() {
			t.Errorf("Date %v: clock %v, want %v", tc.date, time.Unix(table.now, 0).UTC(), tc.want)
		}
	}
	// A Last-Modified ahead of the clock is taken as the clock.
	table := firstSeenOpen(files{dir: t.TempDir()}, "x-firstseen.bin", "doc", time.Minute, firstSeenResponse(local, local.Add(time.Hour)), local)
	if table.modified != local.Unix() {
		t.Errorf("modified %v", time.Unix(table.modified, 0).UTC())
	}
	// Settle 0, or no directory (a feed built to check a configuration):
	// nothing is held, no table is kept.
	dir := t.TempDir()
	rec := snapRecord{Name: "a", Version: "1", Path: "/a-1.tgz"}
	for _, tc := range []struct {
		f      files
		settle time.Duration
	}{{files{dir: dir}, 0}, {files{}, time.Hour}} {
		table := firstSeenOpen(tc.f, "x-firstseen.bin", "doc", tc.settle, firstSeenResponse(local, local), local)
		if !table.admit(&rec, local.Unix()) || table.save() != nil || table.due(local) != 0 {
			t.Errorf("settle %v, dir %q: a record was held", tc.settle, tc.f.dir)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("settle 0 kept a table: %v", entries)
	}
}

// A table that is not one save wrote for the document — another document's,
// truncated, damaged — is no table: the read starts as a first one.
func TestFirstSeenTableDamaged(t *testing.T) {
	dir := t.TempDir()
	f := files{dir: dir}
	local := time.Date(2026, 11, 16, 6, 0, 0, 0, time.UTC)
	// Two records admitted (no time), two held (first seen now).
	recs := []snapRecord{{Name: "a", Version: "1", Path: "/a-1.tgz"}, {Name: "b", Version: "1", Path: "/b-1.tgz"}, {Name: "c", Version: "1", Path: "/c-1.tgz"}, {Name: "d", Version: "1", Path: "/d-1.tgz"}}
	own := []int64{0, 0, local.Unix(), local.Unix()}
	if got, table := firstSeenRead(t, f, "doc", time.Minute, nil, local, recs, own); !table.fresh || !firstSeenEqual(got, []bool{true, true, false, false}) {
		t.Fatalf("the first read: %v, fresh %v", got, table.fresh)
	}
	good, err := os.ReadFile(f.path("x-firstseen.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if settled, held, fresh := firstSeenLoad(f, "x-firstseen.bin", "doc"); fresh || len(settled) != 2 || len(held) != 2 || held[0].seen != local.Unix() {
		t.Fatalf("the table does not read back: %v %v %v", settled, held, fresh)
	}
	if _, _, fresh := firstSeenLoad(f, "x-firstseen.bin", "another doc"); !fresh {
		t.Errorf("another document's table was used")
	}
	counts := len(firstSeenMagic) + 4 + len("doc")
	body := counts + 16
	swapped := func(at, size int) []byte {
		b := bytes.Clone(good)
		copy(b[at:at+size], good[at+size:at+2*size])
		copy(b[at+size:at+2*size], good[at:at+size])
		return b
	}
	set := func(at int, v uint64) []byte {
		b := bytes.Clone(good)
		binary.BigEndian.PutUint64(b[at:], v)
		return b
	}
	for name, data := range map[string][]byte{
		"empty": nil, "magic": append([]byte("PTSEEN1\n"), good[8:]...), "truncated": good[:len(good)-1], "longer": append(bytes.Clone(good), 0),
		"key length":       append(append([]byte(firstSeenMagic), 0xff, 0xff, 0xff, 0xff), good[12:]...),
		"settled unsorted": swapped(body, 8), "held unsorted": swapped(body+16, 16),
		"held unseen": set(body+16+8, 0), "held negative": set(body+16+8, 1<<63),
		"settled count": set(counts, 3), "held count": set(counts+8, 1), "huge count": set(counts, 1<<62),
	} {
		if err := os.WriteFile(f.path("x-firstseen.bin"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if settled, held, fresh := firstSeenLoad(f, "x-firstseen.bin", "doc"); !fresh || settled != nil || held != nil {
			t.Errorf("%s: a damaged table was used: %d, %d entries", name, len(settled), len(held))
		}
	}
	os.Remove(f.path("x-firstseen.bin"))
	if _, _, fresh := firstSeenLoad(f, "x-firstseen.bin", "doc"); !fresh {
		t.Errorf("a missing table")
	}
}

// A record admitted stays admitted while it is listed, whatever the settle
// period is set to later; the table keeps 8 bytes per record admitted.
func TestFirstSeenTableKeepsWhatWasAdmitted(t *testing.T) {
	f := files{dir: t.TempDir()}
	t0 := time.Date(2026, 11, 16, 6, 0, 0, 0, time.UTC)
	var recs []snapRecord
	var own []int64
	for i := 0; i < 1000; i++ {
		recs = append(recs, snapRecord{Name: "p", Version: strconv.Itoa(i), Path: "/p-" + strconv.Itoa(i) + ".tgz"})
		own = append(own, t0.Add(-time.Duration(i)*time.Hour).Unix())
	}
	// No Last-Modified: the own times stand in. Under an hour's period only
	// the newest record (made at t0) is held; under two days, later, the
	// records admitted stay admitted.
	got, _ := firstSeenRead(t, f, "doc", time.Hour, nil, t0, recs, own)
	if got[0] || !got[1] {
		t.Fatalf("an hour's settle: %v", got[:3])
	}
	t1 := t0.Add(30 * time.Minute)
	got, _ = firstSeenRead(t, f, "doc", 48*time.Hour, nil, t1, recs, own)
	for i, ok := range got {
		if ok != (i != 0) {
			t.Fatalf("record %d after the settle period grew: admitted %v", i, ok)
		}
	}
	st, err := os.Stat(f.path("x-firstseen.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(len(firstSeenMagic) + 4 + len("doc") + 16 + 999*8 + 16); st.Size() != want {
		t.Errorf("the table is %d bytes, want %d", st.Size(), want)
	}
}
