package downloadlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// openPersistent opens a persistent log at path on the given clock. The
// background flush is effectively disabled (a very long interval) so tests
// decide when the file is written.
func openPersistent(t *testing.T, path string, c *clock, cfg Config) *Log {
	t.Helper()
	cfg.Enabled = true
	cfg.Path = path
	cfg.Now = c.Now
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	l, err := New(cfg)
	if err != nil {
		t.Fatalf("New(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// fileEntries decodes the on-disk log. Every line must be one JSON entry.
func fileEntries(t *testing.T, path string) []Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var out []Entry
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("%s line %d is not an entry: %v\n%s", path, i+1, err, line)
		}
		out = append(out, e)
	}
	return out
}

func TestPersistenceSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "downloads.jsonl")
	c := newClock()

	l := openPersistent(t, path, c, Config{})
	if !l.Stats().Persistent {
		t.Fatal("Stats().Persistent = false for a log with a path")
	}
	first := entry("10.0.0.5", "cargo", "cfg-if", "1.0.0")
	first.Subject, first.UserAgent, first.Cache, first.Size, first.Digest = "alice", "cargo/1.84.0", "MISS", 7934, "sha256:abc"
	l.Record(first)
	c.Advance(time.Minute)
	blocked := entry("10.0.0.6", "go", "github.com/pkg/errors", "v0.9.1")
	blocked.Outcome, blocked.Status, blocked.Gate, blocked.Code, blocked.Bytes = OutcomeBlocked, 403, "policy", "malicious", 0
	l.Record(blocked)
	before := mustQuery(t, l, Query{}).Entries
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The file is private: it names client addresses and identities.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("log file mode = %o, want 600", perm)
	}
	if dir, err := os.Stat(filepath.Dir(path)); err != nil || dir.Mode().Perm() != 0o700 {
		t.Errorf("created directory mode = %v, %v; want 700", dir.Mode().Perm(), err)
	}

	c.Advance(time.Hour)
	reopened := openPersistent(t, path, c, Config{})
	after := mustQuery(t, reopened, Query{}).Entries
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("entries changed across the restart\nbefore %+v\nafter  %+v", before, after)
	}
	// Recording continues the sequence instead of reusing IDs.
	reopened.Record(entry("10.0.0.7", "cargo", "itoa", "1.0.11"))
	res := mustQuery(t, reopened, Query{})
	if got := ids(res.Entries); !reflect.DeepEqual(got, []uint64{3, 2, 1}) {
		t.Fatalf("IDs after the restart = %v, want [3 2 1]", got)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{1, 2, 3}) {
		t.Fatalf("file holds IDs %v, want [1 2 3] exactly once each", got)
	}
}

// Flush appends only what is new: flushing twice, or flushing and then closing,
// must not write an entry twice.
func TestFlushWritesEachEntryOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{})

	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := fileEntries(t, path); len(got) != 0 {
		t.Fatalf("an empty log wrote %d entries", len(got))
	}

	l.Record(entry("10.0.0.1", "npm", "a", "1"))
	l.Record(entry("10.0.0.1", "npm", "b", "1"))
	for i := 0; i < 3; i++ {
		if err := l.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{1, 2}) {
		t.Fatalf("after repeated flushes the file holds %v, want [1 2]", got)
	}

	l.Record(entry("10.0.0.1", "npm", "c", "1"))
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{1, 2, 3}) {
		t.Fatalf("file holds %v, want [1 2 3]", got)
	}
	st := l.Stats()
	if st.Persisted != 3 || st.PersistErrors != 0 || st.PersistLost != 0 {
		t.Fatalf("persistence counters = %+v", st)
	}
	// Closing twice is harmless.
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// The background loop persists without anyone calling Flush.
func TestBackgroundFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{FlushInterval: 10 * time.Millisecond})
	l.Record(entry("10.0.0.1", "npm", "a", "1"))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && bytes.Count(data, []byte("\n")) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the entry was not written by the background flush within 5s")
}

// A log damaged by a crash or an edit must not keep the proxy from starting:
// unreadable lines are dropped, everything else is kept, and the file is
// rewritten so that it is whole again.
func TestLoadSkipsUnreadableLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	good := func(id uint64, pkg string) string {
		e := entry("10.0.0.1", "npm", pkg, "1.0.0")
		e.ID, e.Time = id, c.Now().Add(-time.Minute)
		b, _ := json.Marshal(e)
		return string(b)
	}
	content := strings.Join([]string{
		good(1, "first"),
		"this is not json",
		`{"id":0,"time":"2026-03-01T11:59:00Z","clientIp":"10.0.0.1"}`, // no ID
		`{"id":7,"clientIp":"10.0.0.1"}`,                               // no time
		"",
		`{"id":8,"time":"2026-03-01T11:59:00Z","clientIp":"10.0.0.1","package":"` + strings.Repeat("x", maxLineBytes) + `"}`, // oversized
		good(2, "second"),
		good(3, "cut-short")[:40], // a line cut short by a crash, with nothing after it
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	l := openPersistent(t, path, c, Config{})
	res := mustQuery(t, l, Query{})
	if got := ids(res.Entries); !reflect.DeepEqual(got, []uint64{2, 1}) {
		t.Fatalf("loaded IDs %v, want [2 1]", got)
	}
	// The file was repaired on load: only the two readable entries remain.
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{1, 2}) {
		t.Fatalf("repaired file holds %v, want [1 2]", got)
	}
	// New entries continue after the highest ID that was readable.
	l.Record(entry("10.0.0.2", "npm", "third", "1.0.0"))
	if got := mustQuery(t, l, Query{}).Entries[0].ID; got != 3 {
		t.Fatalf("next ID = %d, want 3", got)
	}
}

func TestLoadAppliesRetentionAndCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()

	l := openPersistent(t, path, c, Config{Retention: -1})
	for i := 1; i <= 10; i++ {
		l.Record(entry("10.0.0.1", "npm", fmt.Sprintf("p%d", i), "1.0.0"))
		c.Advance(10 * time.Minute)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := len(fileEntries(t, path)); got != 10 {
		t.Fatalf("file holds %d entries, want 10", got)
	}

	// Reopened with a 35-minute retention: entries are 100, 90, … 10 minutes
	// old, so the newest three survive — in memory and on disk.
	l = openPersistent(t, path, c, Config{Retention: 35 * time.Minute})
	if got := ids(mustQuery(t, l, Query{}).Entries); !reflect.DeepEqual(got, []uint64{10, 9, 8}) {
		t.Fatalf("after a retention cut: %v, want [10 9 8]", got)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{8, 9, 10}) {
		t.Fatalf("expired entries are still on disk: %v", got)
	}
	// The sequence continues past the highest ID ever written.
	l.Record(entry("10.0.0.1", "npm", "p11", "1.0.0"))
	if got := mustQuery(t, l, Query{}).Entries[0].ID; got != 11 {
		t.Fatalf("next ID = %d, want 11", got)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopened with a capacity of two: the newest two survive.
	l = openPersistent(t, path, c, Config{Retention: -1, MaxEntries: 2})
	if got := ids(mustQuery(t, l, Query{}).Entries); !reflect.DeepEqual(got, []uint64{11, 10}) {
		t.Fatalf("after a capacity cut: %v, want [11 10]", got)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{10, 11}) {
		t.Fatalf("superseded entries are still on disk: %v", got)
	}
}

// Even when every persisted entry has expired, a restarted log does not hand
// out an ID that the file has already used.
func TestIDsContinueWhenEverythingExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{Retention: time.Hour})
	l.Record(entry("10.0.0.1", "npm", "a", "1"))
	l.Record(entry("10.0.0.1", "npm", "b", "1"))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	c.Advance(2 * time.Hour)
	l = openPersistent(t, path, c, Config{Retention: time.Hour})
	if got := mustQuery(t, l, Query{}).Total; got != 0 {
		t.Fatalf("%d expired entries were loaded", got)
	}
	l.Record(entry("10.0.0.1", "npm", "c", "1"))
	if got := mustQuery(t, l, Query{}).Entries[0].ID; got != 3 {
		t.Fatalf("next ID = %d, want 3", got)
	}
}

// The file is bounded like the log: once it holds about twice what the log
// retains it is rewritten down to the log's contents.
func TestCompactionBoundsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	const capacity = 5
	l := openPersistent(t, path, c, Config{MaxEntries: capacity, Retention: -1})
	l.store.minDead = capacity // compact as soon as half the file is dead

	maxLines := 0
	for i := 1; i <= 200; i++ {
		l.Record(entry("10.0.0.1", "npm", fmt.Sprintf("p%d", i), "1.0.0"))
		if err := l.Flush(); err != nil {
			t.Fatal(err)
		}
		if n := len(fileEntries(t, path)); n > maxLines {
			maxLines = n
		}
	}
	if maxLines > 2*capacity {
		t.Fatalf("the file grew to %d lines; want at most %d for a capacity of %d", maxLines, 2*capacity, capacity)
	}
	// Whatever the file holds, it ends with exactly the log's contents, and a
	// restart reproduces them.
	onDisk := ids(fileEntries(t, path))
	if tail := onDisk[len(onDisk)-capacity:]; !reflect.DeepEqual(tail, []uint64{196, 197, 198, 199, 200}) {
		t.Fatalf("file ends with %v", tail)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openPersistent(t, path, c, Config{MaxEntries: capacity, Retention: -1})
	if got := ids(mustQuery(t, reopened, Query{}).Entries); !reflect.DeepEqual(got, []uint64{200, 199, 198, 197, 196}) {
		t.Fatalf("reloaded %v", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("a temporary file was left behind: %v", err)
	}
}

// The retention bounds what is kept on disk too: expired entries are removed
// from the file without waiting for it to fill up, and without a restart.
func TestExpiredEntriesLeaveTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{Retention: 24 * time.Hour})

	l.Record(entry("10.0.0.1", "npm", "old", "1"))
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	c.Advance(23 * time.Hour)
	l.Record(entry("10.0.0.1", "npm", "new", "1"))
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := len(fileEntries(t, path)); got != 2 {
		t.Fatalf("file holds %d entries, want 2", got)
	}

	// Two hours on, "old" is past the retention. The next flush removes it.
	c.Advance(2 * time.Hour)
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	got := fileEntries(t, path)
	if len(got) != 1 || got[0].Package != "new" {
		t.Fatalf("after expiry the file holds %+v, want only the entry within the retention", got)
	}
	if st := l.Stats(); st.Retained != 1 || st.Expired != 1 {
		t.Fatalf("Stats = %+v", st)
	}

	// When the last entry expires the file is emptied as well.
	c.Advance(48 * time.Hour)
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := fileEntries(t, path); len(got) != 0 {
		t.Fatalf("after everything expired the file still holds %+v", got)
	}
}

// Rewriting for expiry alone is rate-limited: a busy log is not rewritten on
// every flush just because its oldest entry keeps crossing the retention.
func TestExpiryCompactionIsRateLimited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{Retention: 10 * time.Minute})

	for i := 0; i < 5; i++ {
		l.Record(entry("10.0.0.1", "npm", fmt.Sprintf("p%d", i), "1"))
		c.Advance(time.Minute)
	}
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	// Twelve minutes after opening, the first two entries have expired. The log
	// no longer shows them, but the file is not rewritten for it yet.
	c.Advance(7 * time.Minute)
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := mustQuery(t, l, Query{}).Total; got != 3 {
		t.Fatalf("the log shows %d entries, want 3: expired entries must never be returned", got)
	}
	if got := len(fileEntries(t, path)); got != 5 {
		t.Fatalf("file holds %d entries; the expiry rewrite ran before its interval elapsed", got)
	}

	// Still within the interval at 59 minutes: appended to, not rewritten.
	c.Advance(47 * time.Minute)
	l.Record(entry("10.0.0.1", "npm", "p5", "1"))
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := len(fileEntries(t, path)); got != 6 {
		t.Fatalf("file holds %d entries at 59 minutes, want 6", got)
	}

	// At the interval the rewrite happens, and only what is retained remains.
	c.Advance(time.Minute)
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	got := fileEntries(t, path)
	if len(got) != 1 || got[0].Package != "p5" {
		t.Fatalf("after the expiry rewrite the file holds %+v, want only p5", got)
	}
}

// Entries that leave the log before they could be written are counted, not
// silently dropped, and the next flush carries on with what is there.
func TestEntriesLostBeforeFlushAreCounted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{MaxEntries: 3, Retention: -1})
	for i := 1; i <= 10; i++ {
		l.Record(entry("10.0.0.1", "npm", fmt.Sprintf("p%d", i), "1"))
	}
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{8, 9, 10}) {
		t.Fatalf("file holds %v, want the three retained entries", got)
	}
	st := l.Stats()
	if st.PersistLost != 7 || st.Persisted != 3 {
		t.Fatalf("lost %d persisted %d, want 7 and 3", st.PersistLost, st.Persisted)
	}
	// The loss is counted once.
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := l.Stats().PersistLost; got != 7 {
		t.Fatalf("PersistLost = %d after a second flush, want 7", got)
	}
}

// breakWrites swaps the store's append handle for a read-only one, so that every
// write fails, and returns the function that puts the working handle back.
func breakWrites(t *testing.T, l *Log, path string) (restore func()) {
	t.Helper()
	readOnly, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.store.mu.Lock()
	writable := l.store.f
	l.store.f = readOnly
	l.store.mu.Unlock()
	return func() {
		l.store.mu.Lock()
		l.store.f = writable
		l.store.mu.Unlock()
		_ = readOnly.Close()
	}
}

// A failed write is counted and retried; nothing is written twice once the
// file is writable again. Between attempts the log pauses — a second, then two,
// then four — instead of re-encoding everything that is pending every second
// for as long as the disk stays full.
func TestWriteFailureIsRetriedAfterAPause(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{})
	l.Record(entry("10.0.0.1", "npm", "a", "1"))
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}

	restore := breakWrites(t, l, path)
	l.Record(entry("10.0.0.1", "npm", "b", "1"))
	l.Record(entry("10.0.0.1", "npm", "c", "1"))
	failure := l.Flush()
	if failure == nil {
		t.Fatal("Flush succeeded on a read-only file")
	}
	// Within the pause nothing is attempted; the standing failure is reported.
	for i := 0; i < 3; i++ {
		if err := l.Flush(); err == nil || err.Error() != failure.Error() {
			t.Fatalf("Flush during the pause returned %v, want the standing failure %v", err, failure)
		}
	}
	if st := l.Stats(); st.PersistErrors != 1 || st.Persisted != 1 {
		t.Fatalf("errors %d persisted %d, want one attempt (1) and 1", st.PersistErrors, st.Persisted)
	}
	// The pause doubles with every failed attempt: 1s, 2s, 4s.
	for attempt, pause := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		c.Advance(pause - time.Millisecond)
		_ = l.Flush()
		if got := l.Stats().PersistErrors; got != uint64(attempt+1) {
			t.Fatalf("an attempt was made %s into a pause of %s (errors = %d)", pause-time.Millisecond, pause, got)
		}
		c.Advance(time.Millisecond)
		if err := l.Flush(); err == nil {
			t.Fatal("Flush succeeded on a read-only file")
		}
		if got := l.Stats().PersistErrors; got != uint64(attempt+2) {
			t.Fatalf("no attempt was made after a pause of %s (errors = %d)", pause, got)
		}
	}
	// The entries are still served from memory meanwhile.
	if got := mustQuery(t, l, Query{}).Total; got != 3 {
		t.Fatalf("%d entries in memory, want 3", got)
	}

	restore()
	c.Advance(time.Minute)
	if err := l.Flush(); err != nil {
		t.Fatalf("Flush after recovery: %v", err)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{1, 2, 3}) {
		t.Fatalf("file holds %v, want [1 2 3]", got)
	}
	if got := l.Stats(); got.Persisted != 3 || got.PersistLost != 0 {
		t.Fatalf("after recovery: %+v", got)
	}
	// And the pause is over: the next entry is written by the next flush.
	l.Record(entry("10.0.0.1", "npm", "d", "1"))
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{1, 2, 3, 4}) {
		t.Fatalf("file holds %v, want [1 2 3 4]", got)
	}
}

// The pause never grows beyond a minute, however long the disk stays full.
func TestRetryPauseIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{})
	defer breakWrites(t, l, path)()
	l.Record(entry("10.0.0.1", "npm", "a", "1"))
	for i := 0; i < 20; i++ {
		_ = l.Flush()
		c.Advance(maxRetryDelay)
	}
	if got := l.Stats().PersistErrors; got != 20 {
		t.Fatalf("%d attempts in 20 pauses of %s, want one per pause", got, maxRetryDelay)
	}
}

// Shutdown is the last chance to write: Close attempts it even during a pause.
func TestCloseWritesDespiteThePause(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{})
	restore := breakWrites(t, l, path)
	l.Record(entry("10.0.0.1", "npm", "a", "1"))
	if err := l.Flush(); err == nil {
		t.Fatal("Flush succeeded on a read-only file")
	}
	restore()
	// No time has passed: a Flush would still sit out the pause.
	if err := l.Flush(); err == nil {
		t.Fatal("Flush did not sit out the pause")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{1}) {
		t.Fatalf("after Close the file holds %v, want [1]", got)
	}
}

// A store that lost its append handle — the file was replaced but could not be
// reopened — opens it again at the next flush instead of giving up for good.
func TestLostHandleIsReopened(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{})
	l.Record(entry("10.0.0.1", "npm", "a", "1"))
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	l.store.mu.Lock()
	_ = l.store.f.Close()
	l.store.f = nil
	l.store.mu.Unlock()

	l.Record(entry("10.0.0.1", "npm", "b", "1"))
	if err := l.Flush(); err != nil {
		t.Fatalf("Flush with a lost handle: %v", err)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{1, 2}) {
		t.Fatalf("file holds %v, want [1 2]", got)
	}
}

// Recording a download never waits for the disk, and neither does reading the
// log's statistics — the metrics endpoint reads them on every scrape. While a
// write is in progress (here: the store's lock is held, as it is across a
// write, an fsync or a rewrite) both return at once.
func TestRecordAndStatsDoNotWaitForTheDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{})

	l.store.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = l.Stats()
		l.Record(entry("10.0.0.1", "npm", "a", "1"))
		_ = l.Stats()
		_, _ = l.Query(Query{})
		_, _ = l.Summarize(Query{}, 0)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("Stats, Record or Query is waiting for the store's lock, which is held across disk I/O")
	}
	l.store.mu.Unlock()
	<-done
}

// The other half of the same rule: the store never needs the log's lock. It is
// handed a snapshot and writes — and compacts — from that, so a write can
// complete while the log's lock is held by someone else. Together with the test
// above this is what makes a deadlock between the two impossible rather than
// merely unlikely: neither lock is ever waited for while the other is held.
func TestTheStoreNeverNeedsTheLogsLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{MaxEntries: 4, Retention: -1})
	l.store.minDead = 1 // every write below finds the file due for a rewrite
	for i := 0; i < 12; i++ {
		l.Record(entry("10.0.0.1", "npm", fmt.Sprintf("p%d", i), "1"))
		if i == 5 {
			if err := l.Flush(); err != nil {
				t.Fatal(err)
			}
		}
	}

	l.mu.Lock()
	v, upTo := l.cur, l.nextID-1
	done := make(chan error, 1)
	go func() { done <- l.store.sync(v, upTo, time.Time{}, c.Now(), true) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("sync: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the store is waiting for the log's lock while it holds the file")
	}
	l.mu.Unlock()
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{9, 10, 11, 12}) {
		t.Fatalf("the file holds %v, want the four retained entries", got)
	}
}

// The flush, the statistics and recording take their locks in an order that
// cannot deadlock. This is the scenario that did: a flush that compacts the
// file needs the log's contents while it holds the file, and a metrics scrape
// reads the file's counters while it holds the log.
func TestFlushCompactionAndStatsDoNotDeadlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	l, err := New(Config{
		Enabled: true, Path: path, MaxEntries: 8, Retention: -1, FlushInterval: time.Hour,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.store.minDead = 1 // compact whenever the file holds a superseded line

	const rounds = 200
	finished := make(chan string, 3)
	stop := make(chan struct{})
	go func() { // the background flusher
		for i := 0; i < rounds; i++ {
			_ = l.Flush()
		}
		finished <- "flush"
	}()
	go func() { // a metrics scrape, the admin API
		for {
			select {
			case <-stop:
				finished <- "stats"
				return
			default:
				_ = l.Stats()
			}
		}
	}()
	go func() { // client requests completing
		for i := 0; ; i++ {
			select {
			case <-stop:
				finished <- "record"
				return
			default:
				l.Record(entry("10.0.0.1", "npm", fmt.Sprintf("p%d", i), "1.0.0"))
			}
		}
	}()

	watchdog := time.After(60 * time.Second)
	select {
	case <-finished: // the flusher completed its rounds
	case <-watchdog:
		buf := make([]byte, 1<<16)
		t.Fatalf("deadlock: %d flushes did not complete within a minute\n%s", rounds, buf[:runtime.Stack(buf, true)])
	}
	close(stop)
	for i := 0; i < 2; i++ {
		select {
		case <-finished:
		case <-watchdog:
			t.Fatal("deadlock: Stats or Record did not return")
		}
	}
}

// A file whose last line is whole but lacks its line feed — the proxy was
// killed between the entry and its terminator — must not have the next entry
// glued to that line: both would be unreadable at the following start.
func TestUnterminatedLastLineIsRepaired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	first := entry("10.0.0.1", "npm", "first", "1")
	first.ID, first.Time = 1, c.Now().Add(-time.Minute)
	line, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, line, 0o600); err != nil { // no trailing line feed
		t.Fatal(err)
	}

	l := openPersistent(t, path, c, Config{})
	l.Record(entry("10.0.0.2", "npm", "second", "1"))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{1, 2}) {
		t.Fatalf("the file holds %v, want two whole lines [1 2]", got)
	}
	reopened := openPersistent(t, path, c, Config{})
	if got := ids(mustQuery(t, reopened, Query{}).Entries); !reflect.DeepEqual(got, []uint64{2, 1}) {
		t.Fatalf("after a restart the log holds %v, want [2 1]", got)
	}
}

// The log is kept within its bounds by replacing the file through a temporary
// one next to it. Where that cannot be created, the log could only ever grow —
// and would keep expired entries for good. That is refused at startup rather
// than reported by a counter later.
func TestNewFailsWhenTheLogCannotBeCompacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	// Something that is not a file sits where the temporary file goes.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{Enabled: true, Path: path})
	if err == nil {
		t.Fatal("New accepted a log file it cannot compact")
	}
	if !strings.Contains(err.Error(), "temporary file") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

// Entries that reach the file for the first time through a rewrite — the flush
// that carries them finds the file due for compaction — are persisted entries
// like any other.
func TestCompactionCountsTheEntriesItWritesFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{MaxEntries: 4, Retention: -1})
	l.store.minDead = 1
	written := 0
	for round := 0; round < 5; round++ {
		for i := 0; i < 3; i++ {
			l.Record(entry("10.0.0.1", "npm", fmt.Sprintf("p%d-%d", round, i), "1"))
			written++
		}
		if err := l.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	st := l.Stats()
	if st.Persisted != uint64(written) || st.PersistLost != 0 {
		t.Fatalf("persisted %d lost %d, want all %d entries persisted and none lost", st.Persisted, st.PersistLost, written)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{12, 13, 14, 15}) {
		t.Fatalf("the file holds %v, want the four retained entries", got)
	}
}

// A file whose IDs do not increase was not written by one process in order; the
// log renumbers it rather than building on a broken sequence.
func TestLoadRenumbersOutOfOrderIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	var lines []string
	for i, id := range []uint64{5, 3, 9, 9} {
		e := entry("10.0.0.1", "npm", fmt.Sprintf("p%d", i), "1")
		e.ID, e.Time = id, c.Now().Add(time.Duration(i-10)*time.Minute)
		b, _ := json.Marshal(e)
		lines = append(lines, string(b))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := openPersistent(t, path, c, Config{})
	res := mustQuery(t, l, Query{})
	if got := ids(res.Entries); !reflect.DeepEqual(got, []uint64{4, 3, 2, 1}) {
		t.Fatalf("IDs %v, want them renumbered [4 3 2 1]", got)
	}
	if res.Entries[3].Package != "p0" || res.Entries[0].Package != "p3" {
		t.Fatalf("file order was not preserved: %+v", res.Entries)
	}
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{1, 2, 3, 4}) {
		t.Fatalf("file holds %v, want the renumbered entries", got)
	}
}

func TestNewFailsOnUnusablePath(t *testing.T) {
	dir := t.TempDir()
	// The path is a directory.
	if _, err := New(Config{Enabled: true, Path: dir}); err == nil {
		t.Error("New accepted a directory as the log file")
	}
	// The parent is a file.
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Enabled: true, Path: filepath.Join(file, "downloads.jsonl")}); err == nil {
		t.Error("New accepted a path below a regular file")
	}
	// A disabled log never touches its path.
	l, err := New(Config{Enabled: false, Path: filepath.Join(file, "downloads.jsonl")})
	if err != nil || l.Stats().Persistent {
		t.Errorf("a disabled log opened its path: %v", err)
	}
}

// The on-disk line format is the admin API's entry format; a reader must be
// able to rely on the field names.
func TestOnDiskFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	l := openPersistent(t, path, c, Config{})
	e := entry("10.0.0.5", "cargo", "cfg-if", "1.0.0")
	e.ForwardedBy, e.Artifact, e.Digest, e.Cache, e.Size = "10.9.9.9", "cfg-if-1.0.0.crate", "sha256:ab", "MISS", 7934
	e.Subject, e.Tenant, e.AuthMethod, e.UserAgent, e.TraceID, e.DurationMs = "alice", "team-a", "token", "cargo/1.84.0", "4bf92f", 12
	l.Record(e)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":1,"time":"2026-03-01T12:00:00Z","clientIp":"10.0.0.5","forwardedBy":"10.9.9.9",` +
		`"ecosystem":"cargo","upstream":"cargo","package":"cfg-if","version":"1.0.0","artifact":"cfg-if-1.0.0.crate",` +
		`"digest":"sha256:ab","kind":"package","method":"GET","path":"/v1/cargo/cfg-if/1.0.0","status":200,` +
		`"outcome":"served","cache":"MISS","bytes":100,"size":7934,"durationMs":12,"subject":"alice","tenant":"team-a",` +
		`"authMethod":"token","userAgent":"cargo/1.84.0","traceId":"4bf92f"}` + "\n"
	if string(data) != want {
		t.Fatalf("on-disk line\n %s\nwant\n %s", data, want)
	}
}

// The file names client addresses and identities. One this process did not
// create — restored from a backup, laid down by a deployment script — may be
// readable by others; opening it makes it private, as a file the log creates is.
func TestExistingFileIsMadePrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")

	// A file the log creates is private from the start.
	c := newClock()
	l := openPersistent(t, path, c, Config{})
	l.Record(entry("10.0.0.5", "cargo", "cfg-if", "1.0.0"))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if mode := fileMode(t, path); mode != 0o600 {
		t.Fatalf("a file the log created has mode %o, want 600", mode)
	}

	// Someone widened it (or restored it that way).
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	reopened := openPersistent(t, path, c, Config{})
	if mode := fileMode(t, path); mode != 0o600 {
		t.Errorf("after reopening, the file has mode %o, want 600", mode)
	}
	// It is still the same log.
	if res := mustQuery(t, reopened, Query{}); res.Total != 1 || res.Entries[0].Package != "cfg-if" {
		t.Errorf("the reopened log holds %+v", res.Entries)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// writeLogFile writes entries, as given, as the on-disk log.
func writeLogFile(t *testing.T, path string, entries ...Entry) {
	t.Helper()
	var buf bytes.Buffer
	for i := range entries {
		line, err := json.Marshal(entries[i])
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// An ID no log could have counted to is damage. Continuing the sequence from it
// would overflow: the next entry would get ID 0 and be dropped as unreadable at
// the following start.
func TestLoadSkipsImpossibleIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	good := entry("10.0.0.1", "npm", "good", "1")
	good.ID, good.Time = 41, c.Now().Add(-time.Hour)
	huge := entry("10.0.0.2", "npm", "huge", "1")
	huge.ID, huge.Time = ^uint64(0), c.Now().Add(-time.Minute)
	beyond := entry("10.0.0.3", "npm", "beyond", "1")
	beyond.ID, beyond.Time = maxEntryID+1, c.Now().Add(-time.Minute)
	writeLogFile(t, path, good, huge, beyond)

	l := openPersistent(t, path, c, Config{})
	if got := ids(mustQuery(t, l, Query{}).Entries); !reflect.DeepEqual(got, []uint64{41}) {
		t.Fatalf("loaded IDs %v, want only the plausible entry [41]", got)
	}
	l.Record(entry("10.0.0.9", "npm", "next", "1"))
	if got := ids(mustQuery(t, l, Query{}).Entries); !reflect.DeepEqual(got, []uint64{42, 41}) {
		t.Fatalf("after recording, IDs %v, want the sequence continued [42 41]", got)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// The file is whole again, and the new entry survives a restart.
	if got := ids(fileEntries(t, path)); !reflect.DeepEqual(got, []uint64{41, 42}) {
		t.Fatalf("the file holds %v, want [41 42]", got)
	}
	reopened := openPersistent(t, path, c, Config{})
	if res := mustQuery(t, reopened, Query{}); res.Total != 2 || res.Entries[0].Package != "next" {
		t.Fatalf("after a restart the log holds %+v", res.Entries)
	}
}

// An entry dated in the future would never expire — and expiry stops at the
// first entry that has not expired, so it would hold everything recorded after
// it past the retention too. Loading dates it now, and writes that down, so it
// leaves with the retention like everything else.
func TestLoadPullsBackFutureDatedEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	future := entry("10.0.0.1", "npm", "from-the-future", "1")
	future.ID, future.Time = 1, c.Now().Add(1000*24*time.Hour)
	recent := entry("10.0.0.2", "npm", "recent", "1")
	recent.ID, recent.Time = 2, c.Now().Add(-time.Minute)
	writeLogFile(t, path, future, recent)

	const retention = 24 * time.Hour
	l := openPersistent(t, path, c, Config{Retention: retention})
	res := mustQuery(t, l, Query{Package: "from-the-future"})
	if res.Total != 1 || !res.Entries[0].Time.Equal(c.Now()) {
		t.Fatalf("the future-dated entry was loaded as %+v, want it dated now (%s)", res.Entries, c.Now())
	}
	// The repair is on disk: another start does not push the date forward again.
	onDisk := fileEntries(t, path)
	if len(onDisk) != 2 || !onDisk[0].Time.Equal(c.Now()) {
		t.Fatalf("the file still holds %+v", onDisk)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	c.Advance(retention / 2)
	again := openPersistent(t, path, c, Config{Retention: retention})
	if res := mustQuery(t, again, Query{Package: "from-the-future"}); res.Total != 1 || !res.Entries[0].Time.Equal(c.Now().Add(-retention/2)) {
		t.Fatalf("a second start re-dated the entry: %+v", res.Entries)
	}
	// And once the retention has passed, it is gone — and so is what came after.
	c.Advance(retention)
	if res := mustQuery(t, again, Query{}); res.Total != 0 {
		t.Fatalf("%d entries outlived the retention: %+v", res.Total, res.Entries)
	}
}

// A clock stepped back by a time synchronisation leaves the last entries
// slightly in the future. That is not damage: they are left as they are.
func TestLoadToleratesSmallClockSkew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downloads.jsonl")
	c := newClock()
	ahead := entry("10.0.0.1", "npm", "slightly-ahead", "1")
	ahead.ID, ahead.Time = 1, c.Now().Add(maxClockSkew/2)
	writeLogFile(t, path, ahead)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	l := openPersistent(t, path, c, Config{})
	res := mustQuery(t, l, Query{})
	if res.Total != 1 || !res.Entries[0].Time.Equal(ahead.Time) {
		t.Fatalf("loaded %+v, want the entry with its own time %s", res.Entries, ahead.Time)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the file was rewritten for a clock skew of %s", maxClockSkew/2)
	}
}
