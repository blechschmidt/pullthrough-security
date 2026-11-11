package downloadlog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// maxLineBytes bounds one line of the on-disk log. A sanitized entry is a
	// few kilobytes at most; a longer line is not something this package wrote.
	maxLineBytes = 1 << 20
	// minCompactDeadLines is the least number of superseded lines that makes
	// rewriting the file worthwhile for space alone.
	minCompactDeadLines = 1024
	// expiredCompactInterval is how often, at most, the file is rewritten merely
	// because it still holds entries that have outlived the retention. It is
	// what bounds how long an expired entry can linger on disk.
	expiredCompactInterval = time.Hour
	// maxEntryID is the largest entry ID accepted from a file. A log recording a
	// million downloads a second would take a hundred thousand years to count
	// this far, so a larger ID in a file is damage — and continuing the sequence
	// from it would overflow.
	maxEntryID = 1 << 62
	// maxClockSkew is how far ahead of the clock a loaded entry's time may lie
	// before it is taken for damage. A clock that was stepped back by a
	// synchronisation leaves the last entries written slightly in the future;
	// that is not worth a repair, and delays their expiry by no more than this.
	maxClockSkew = 5 * time.Minute
	// minRetryDelay and maxRetryDelay bound the pause after a failed write. A
	// full disk fails every attempt; trying again every second would re-encode
	// everything that is pending — in the end the whole log — every second, for
	// as long as the disk stays full.
	minRetryDelay = time.Second
	maxRetryDelay = time.Minute
	// writeBufferBytes is the buffer entries are encoded through on their way to
	// the file. They are streamed from the log, never collected first.
	writeBufferBytes = 256 << 10
)

// errStoreClosed is returned by a write to a store that has been closed.
var errStoreClosed = errors.New("downloadlog: the on-disk log is closed")

// fileStore is the on-disk copy of the log: a JSON Lines file that is appended
// to as entries are recorded and rewritten when it holds noticeably more than
// the log retains.
//
// Locking. mu serializes everything that touches the file. The store never
// calls back into the log — what it writes it is handed, as a view — and the
// log never calls the store with its own lock held (the counters Stats reads
// are atomic for that reason). The two locks are therefore never held together:
// a write that is stuck on a slow disk delays the next write, and nothing else.
type fileStore struct {
	path   string
	logger *slog.Logger

	mu sync.Mutex
	// f is the append handle. It is nil before start, after close, and while the
	// handle is lost (a reopen after a rewrite failed); sync reopens it.
	f      *os.File
	closed bool
	// size is the file's length after the last successful write; a failed write
	// is rolled back to it.
	size int64
	// lines is how many entries the file holds; oldest is the time of its first.
	lines  int
	oldest time.Time
	// last is the highest entry ID the file accounts for: everything up to it
	// has been written, or has left the log and never will be.
	last        uint64
	lastCompact time.Time
	// minDead and expiredEvery are the compaction thresholds (see
	// wantsCompaction) and retryBase the first pause after a failure; fields
	// rather than constants so tests can lower them.
	minDead      int
	expiredEvery time.Duration
	retryBase    time.Duration

	// failures counts consecutive failed attempts; no attempt is made before
	// retryAt, and standing is what the last one failed with.
	failures int
	retryAt  time.Time
	standing error
	// lastErr de-duplicates the error log: a full disk fails every attempt, and
	// one line per attempt for the same reason is noise.
	lastErr string

	// Cumulative counters; atomic so that reading them needs no lock.
	persisted atomic.Uint64
	errs      atomic.Uint64
	lost      atomic.Uint64
}

// openFileStore prepares the on-disk log at path: it creates the directory and
// the file if needed and verifies, before anything depends on it, that the log
// can be kept the way it is kept — appended to, and replaced through a
// temporary file next to it. A log that could be appended to but not replaced
// would grow without bound and keep expired entries forever; that must be a
// startup error, not something a counter reports a month later.
func openFileStore(path string, now time.Time, logger *slog.Logger) (*fileStore, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		// The log names client addresses and identities: keep it private.
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("downloadlog: creating %s: %w", dir, err)
		}
	}
	s := &fileStore{
		path:         path,
		logger:       logger,
		lastCompact:  now,
		minDead:      minCompactDeadLines,
		expiredEvery: expiredCompactInterval,
		retryBase:    minRetryDelay,
	}
	if err := s.openAppend(); err != nil {
		return nil, err
	}
	tmp := s.tmpPath()
	probe, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = s.f.Close()
		return nil, fmt.Errorf("downloadlog: %s cannot be kept within its bounds: the log is compacted through a temporary file "+
			"next to it, and creating %s failed (the directory must be writable): %w", path, tmp, err)
	}
	_ = probe.Close()
	_ = os.Remove(tmp)
	return s, nil
}

func (s *fileStore) tmpPath() string { return s.path + ".tmp" }

// loaded describes what load found in the file.
type loaded struct {
	// lines is how many well-formed entries the file holds, whether or not they
	// are still within the log's bounds; malformed how many lines could not be
	// read.
	lines, malformed int
	// maxID is the highest entry ID in the file, so the sequence can continue
	// where the previous run stopped even when that entry has expired.
	maxID uint64
	// outOfOrder reports entry IDs that do not increase through the file.
	outOfOrder bool
	// redated reports entries whose time lay in the future and was pulled back.
	redated bool
	// unterminated reports that the file does not end in a line feed: the next
	// entry appended would be glued to its last line, and both would be lost.
	unterminated bool
}

// load reads the file and hands every entry that has not expired to add, in
// file order. Entries are streamed: a file larger than the log is never held in
// memory, the log keeps the newest as they arrive.
//
// The file is the proxy's own, but a crash, a full disk, a restore or an editor
// can leave anything in it, and the log's invariants must hold for what is
// loaded all the same:
//
//   - a line that is not an entry — or carries an ID no log could have reached —
//     is skipped and counted, never fatal: a damaged log must not keep the proxy
//     from starting;
//   - an entry dated in the future (beyond what a clock correction explains) is
//     dated now. Expiry stops at the first entry that has not expired, so one
//     entry claiming to be from the year 9999 would keep itself and everything
//     recorded after it past the retention for as long as it claims;
//   - IDs that do not increase are reported, for the caller to renumber: they
//     order the log and drive the "what is new" bookkeeping.
func (s *fileStore) load(cutoff, now time.Time, add func(Entry)) (loaded, error) {
	var out loaded
	f, err := os.Open(s.path)
	if err != nil {
		return out, fmt.Errorf("downloadlog: opening %s: %w", s.path, err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 64<<10)
	var prev uint64
	for {
		line, tooLong, rerr := readLine(r)
		if len(line) > 0 || tooLong {
			var e Entry
			switch {
			case tooLong:
				out.malformed++
			case json.Unmarshal(line, &e) != nil || e.ID == 0 || e.ID > maxEntryID || e.Time.IsZero():
				out.malformed++
			default:
				out.lines++
				if e.ID > out.maxID {
					out.maxID = e.ID
				}
				if e.Time.After(now.Add(maxClockSkew)) {
					e.Time = now
					out.redated = true
				}
				if cutoff.IsZero() || !e.Time.Before(cutoff) {
					e.sanitize()
					if e.ID <= prev {
						out.outOfOrder = true
					}
					prev = e.ID
					add(e)
				}
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				return loaded{}, fmt.Errorf("downloadlog: reading %s: %w", s.path, rerr)
			}
			break
		}
	}

	if info, err := f.Stat(); err == nil && info.Size() > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], info.Size()-1); err == nil && last[0] != '\n' {
			out.unterminated = true
		}
	}
	return out, nil
}

// readLine reads one line without its terminator. A line longer than
// maxLineBytes is consumed and reported as tooLong instead of being buffered.
func readLine(r *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		chunk, isPrefix, rerr := r.ReadLine()
		if !tooLong {
			if len(line)+len(chunk) > maxLineBytes {
				tooLong = true
				line = nil
			} else {
				line = append(line, chunk...)
			}
		}
		if rerr != nil || !isPrefix {
			return bytes.TrimSpace(line), tooLong, rerr
		}
	}
}

// start puts the store in step with the log after load: v is what the log
// holds, file what load found. When the file holds anything the log does not —
// expired or superseded entries, unreadable lines, entries that were repaired —
// it is rewritten from v, so that the store starts from a file that mirrors the
// log and its line accounting is exact.
func (s *fileStore) start(v view, file loaded, maxID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = file.lines
	s.last = maxID
	if file.malformed > 0 {
		s.logger.Warn("download log: skipped unreadable lines", "path", s.path, "lines", file.malformed)
	}
	if file.outOfOrder || file.redated {
		s.logger.Warn("download log: the on-disk log was inconsistent (entry IDs out of sequence, or times in the future) and has been repaired",
			"path", s.path)
	}
	if file.lines != v.count || file.malformed > 0 || file.outOfOrder || file.redated || file.unterminated {
		_, err := s.rewrite(v)
		return err
	}
	if v.count > 0 {
		s.oldest = v.at(0).Time
	}
	return nil
}

// openAppend opens the log file for appending. The caller holds s.mu or owns s
// exclusively.
func (s *fileStore) openAppend() error {
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("downloadlog: opening %s: %w", s.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("downloadlog: inspecting %s: %w", s.path, err)
	}
	// The log names client addresses and identities. A file this process did not
	// create — restored from a backup, laid down by a deployment script — may be
	// readable by other users. The next rewrite would make it private anyway
	// (the replacement is created 0600); do not leave it exposed until then.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if err := f.Chmod(perm &^ 0o077); err != nil {
			s.logger.Warn("download log: the on-disk log is accessible to other users and could not be made private",
				"path", s.path, "mode", perm.String(), "error", err)
		}
	}
	s.f = f
	s.size = info.Size()
	return nil
}

// counters returns the cumulative persistence counters. It takes no lock.
func (s *fileStore) counters() (persisted, errs, lost uint64) {
	return s.persisted.Load(), s.errs.Load(), s.lost.Load()
}

// sync brings the file up to date with v, a snapshot of the log taken when the
// highest ID assigned was upTo: entries newer than everything the file holds
// are appended, and when the file has come to hold noticeably more than the log
// (or entries that have outlived the retention, whose boundary is cutoff) it is
// rewritten from v instead.
//
// After a failure sync does nothing until a pause has passed, and reports the
// standing failure meanwhile; force overrides the pause (the last write before
// shutdown must be attempted).
func (s *fileStore) sync(v view, upTo uint64, cutoff, now time.Time, force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errStoreClosed
	}

	// Entries are in ascending ID order: find the first one to write.
	lo, hi := 0, v.count
	for lo < hi {
		mid := (lo + hi) / 2
		if v.at(mid).ID <= s.last {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	pending := v.count - lo
	// IDs between what the file accounts for and the first pending entry belong
	// to entries that were evicted or expired before they could be written. They
	// never will be, so the mark moves past them whether or not this attempt
	// writes anything — which is also what counts each loss exactly once.
	next := upTo + 1
	if pending > 0 {
		next = v.at(lo).ID
	}
	if next > s.last+1 {
		s.lost.Add(next - s.last - 1)
		s.last = next - 1
	}

	if !force && now.Before(s.retryAt) {
		return s.standing
	}
	if s.f == nil {
		if err := s.openAppend(); err != nil {
			return s.failed(err, now)
		}
	}

	switch {
	case s.wantsCompaction(v.count, pending, cutoff, now):
		// The rewrite carries the pending entries with it; appending them first
		// would only write them twice.
		replaced, err := s.rewrite(v)
		if replaced {
			s.lastCompact = now
			s.persisted.Add(uint64(pending))
		}
		if err != nil {
			return s.failed(err, now)
		}
	case pending > 0:
		if err := s.appendFrom(v, lo); err != nil {
			return s.failed(err, now)
		}
		s.persisted.Add(uint64(pending))
	}
	s.recovered()
	return nil
}

// appendFrom appends the entries of v from index lo on to the file.
func (s *fileStore) appendFrom(v view, lo int) error {
	out := &countingWriter{w: s.f}
	w := bufio.NewWriterSize(out, writeBufferBytes)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	var err error
	for i := lo; i < v.count && err == nil; i++ {
		err = enc.Encode(v.at(i))
	}
	if err == nil {
		err = w.Flush()
	}
	if err != nil {
		// Do not leave half a line behind: the next entry would be glued to it
		// and both would be unreadable.
		_ = s.f.Truncate(s.size)
		return err
	}
	s.size += out.n
	if s.lines == 0 {
		s.oldest = v.at(lo).Time
	}
	s.lines += v.count - lo
	s.last = v.at(v.count - 1).ID
	// The entries are in the file; whether they have reached the disk yet is a
	// durability question, not a reason to write them a second time. A failed
	// sync is counted and logged, and the write stands.
	if err := s.f.Sync(); err != nil {
		s.errs.Add(1)
		s.logFailure(err)
	}
	return nil
}

// countingWriter counts the bytes written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// wantsCompaction decides whether the file should be rewritten from the log,
// given how many entries the log retains and how many of them are still to be
// written. Two things call for it: the file has grown to about twice what the
// log retains, or it still holds entries that have outlived the retention — the
// retention bounds what is kept on disk, not only what is kept in memory.
func (s *fileStore) wantsCompaction(retained, pending int, cutoff, now time.Time) bool {
	dead := s.lines + pending - retained
	if dead <= 0 {
		return false
	}
	if dead >= s.minDead && dead >= retained {
		return true
	}
	expiredOnDisk := !cutoff.IsZero() && !s.oldest.IsZero() && s.oldest.Before(cutoff)
	return expiredOnDisk && now.Sub(s.lastCompact) >= s.expiredEvery
}

// rewrite replaces the file's contents with the entries of v: written to a
// temporary file in the same directory, synced, and renamed over the log, so a
// crash at any point leaves either the old file or the new one. The entries are
// streamed from the view. The caller holds s.mu or owns s exclusively.
//
// replaced reports that the file now holds v. It can be true together with an
// error: the file was replaced, but could not be reopened for appending.
func (s *fileStore) rewrite(v view) (replaced bool, err error) {
	tmp := s.tmpPath()
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return false, fmt.Errorf("downloadlog: creating %s: %w", tmp, err)
	}
	w := bufio.NewWriterSize(f, writeBufferBytes)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for i := 0; i < v.count && err == nil; i++ {
		err = enc.Encode(v.at(i))
	}
	if err == nil {
		err = w.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("downloadlog: writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("downloadlog: replacing %s: %w", s.path, err)
	}
	syncDir(filepath.Dir(s.path))

	// From here on the file is the new one, whatever happens to the handle: the
	// bookkeeping follows the file, and a handle that cannot be reopened now is
	// reopened by the next sync.
	if s.f != nil {
		_ = s.f.Close()
		s.f = nil
	}
	s.lines = v.count
	s.oldest = time.Time{}
	if v.count > 0 {
		s.oldest = v.at(0).Time
		if id := v.at(v.count - 1).ID; id > s.last {
			s.last = id
		}
	}
	return true, s.openAppend()
}

// failed counts and logs a failed attempt, starts (or lengthens) the pause
// before the next one, and returns the failure.
func (s *fileStore) failed(err error, now time.Time) error {
	s.errs.Add(1)
	s.failures++
	delay := s.retryBase
	for i := 1; i < s.failures && delay < maxRetryDelay; i++ {
		delay *= 2
	}
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	s.retryAt = now.Add(delay)
	s.standing = err
	s.logFailure(err)
	return err
}

// logFailure logs a persistence failure, once per distinct message.
func (s *fileStore) logFailure(err error) {
	if msg := err.Error(); msg != s.lastErr {
		s.lastErr = msg
		s.logger.Warn("download log: writing the on-disk log failed; entries stay in memory and are retried",
			"path", s.path, "error", err)
	}
}

// recovered notes a successful attempt.
func (s *fileStore) recovered() {
	if s.failures > 0 {
		s.logger.Info("download log: the on-disk log is being written again", "path", s.path)
	}
	s.failures = 0
	s.retryAt = time.Time{}
	s.standing = nil
	s.lastErr = ""
}

// close closes the file. Nothing is written to a closed store.
func (s *fileStore) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// syncDir flushes a directory's metadata so a rename in it survives a crash.
// Best effort: not every filesystem supports it.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
