package fullmirror

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// The engine's state lives in a directory of its own (fullMirror.stateDir,
// by default <cache.dir>/fullmirror), next to the proxy's other metadata
// stores, and is backed up with them:
//
//	control.json                    operators' global pause
//	upstreams/<name>/state.json     cursor, phase, feed head and lag, counters,
//	                                budget spent, recent errors, batch progress
//	upstreams/<name>/batch.json     the items of the batch being worked on
//	upstreams/<name>/control.json   operators' pause and resync requests
//	upstreams/<name>/feed/          the adapter's own files (Env.Dir)
//
// Every file is replaced atomically (written aside, synced, renamed), so a
// reader — a restarted engine, another replica, a backup — sees one version
// or the next, never a torn one. Only the leader writes state.json and
// batch.json; control files are written by whichever replica receives the
// operator's request and read by the leader.

// stateFormat is the version of state.json's layout.
const stateFormat = 1

// Phases of a follower.
const (
	phaseBootstrap = "bootstrap"
	phaseFollow    = "follow"
)

// maxRecentErrors bounds the errors kept per upstream.
const maxRecentErrors = 20

// maxCursorBytes bounds a cursor: a feed keeps anything bigger in Env.Dir.
const maxCursorBytes = 64 << 10

// maxBatchItems bounds one batch.
const maxBatchItems = 100_000

// Counters are an upstream's cumulative tallies. Packages and their outcomes
// count the changes a feed reported; Fetched, Refused, Failed and Skipped
// count files.
type Counters struct {
	// Polls and PollErrors count the requests made of the feed.
	Polls      uint64 `json:"polls"`
	PollErrors uint64 `json:"pollErrors"`
	// Batches counts the batches of changes worked through.
	Batches uint64 `json:"batches"`
	// Packages counts the changes dealt with; Excluded those the name
	// patterns left out, Deleted the removals, PackageErrors those whose
	// versions could not be listed.
	Packages      uint64 `json:"packages"`
	Excluded      uint64 `json:"excluded"`
	Deleted       uint64 `json:"deleted"`
	PackageErrors uint64 `json:"packageErrors"`
	// Fetched counts the files the mirror added to the cache, FetchedBytes
	// their size.
	Fetched      uint64 `json:"fetched"`
	FetchedBytes uint64 `json:"fetchedBytes"`
	// Refused counts the files an admission gate refused, by gate in
	// RefusedBy. A refusal is a verdict, not a failure: the file is not
	// fetched again.
	Refused   uint64            `json:"refused"`
	RefusedBy map[string]uint64 `json:"refusedBy,omitempty"`
	// Failed counts the files that could not be fetched.
	Failed uint64 `json:"failed"`
	// Deferred counts the times a gate said "not yet" to a file (a maturity
	// cooldown, a scanner that could not judge it): the file waits in the
	// deferred queue and is asked for again later.
	Deferred uint64 `json:"deferred"`
	// Skipped counts the files not fetched, by reason (SkipCached, …).
	Skipped map[string]uint64 `json:"skipped,omitempty"`
	// Retries counts the requests repeated after a transient failure.
	Retries uint64 `json:"retries"`
}

// Reasons a file is skipped.
const (
	// SkipCached: the cache already holds the file.
	SkipCached = "cached"
	// SkipVersionPolicy: a version the version policy does not keep.
	SkipVersionPolicy = "version-policy"
	// SkipTooLarge: larger than maxArtifactBytes.
	SkipTooLarge = "too-large"
	// SkipNotCacheable: the proxy serves the path without caching it, so a
	// mirror cannot hold it.
	SkipNotCacheable = "not-cacheable"
	// SkipDryRun: it would have been fetched (dryRun is on).
	SkipDryRun = "dry-run"
	// SkipDeferralOverflow: a gate said "not yet", but the deferred queue
	// was full.
	SkipDeferralOverflow = "deferral-overflow"
)

func (c *Counters) skip(reason string, n uint64) {
	if n == 0 {
		return
	}
	if c.Skipped == nil {
		c.Skipped = map[string]uint64{}
	}
	c.Skipped[reason] += n
}

func (c *Counters) refuse(gate string) {
	if c.RefusedBy == nil {
		c.RefusedBy = map[string]uint64{}
	}
	c.Refused++
	c.RefusedBy[gate]++
}

// clone returns a deep copy.
func (c Counters) clone() Counters {
	out := c
	out.RefusedBy = cloneCounts(c.RefusedBy)
	out.Skipped = cloneCounts(c.Skipped)
	return out
}

func cloneCounts(m map[string]uint64) map[string]uint64 {
	if m == nil {
		return nil
	}
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// SkippedTotal sums the skipped files.
func (c Counters) SkippedTotal() uint64 {
	var n uint64
	for _, v := range c.Skipped {
		n += v
	}
	return n
}

// ErrorRecord is one recent error.
type ErrorRecord struct {
	Time time.Time `json:"time"`
	// Package and Path say what was being worked on, when it was a package
	// or one of its files.
	Package string `json:"package,omitempty"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// upstreamState is state.json.
type upstreamState struct {
	Format   int    `json:"format"`
	Upstream string `json:"upstream"`
	Type     string `json:"type"`
	// Generation counts the writes of the file. A writer expects the
	// generation it last read or wrote: finding another means a newer leader
	// has written since, and the stale one stands by instead of overwriting
	// it. (Fencing tokens are not compared: they restart when the lease store
	// does, and a restored backup carries old ones.)
	Generation uint64 `json:"generation"`
	// Fence is the fencing token of the leadership the file was last written
	// under, for diagnostics.
	Fence uint64 `json:"fence,omitempty"`
	// Phase is bootstrap or follow; Cursor what the next poll passes.
	Phase  string `json:"phase"`
	Cursor string `json:"cursor,omitempty"`
	// ResyncHandled is the last operator resync request acted on.
	ResyncHandled     uint64    `json:"resyncHandled,omitempty"`
	BootstrapStarted  time.Time `json:"bootstrapStarted,omitzero"`
	BootstrapFinished time.Time `json:"bootstrapFinished,omitzero"`
	// LastPoll is the last request made of the feed, LastChange the last one
	// that returned changes, LastCommit the last batch worked through.
	LastPoll   time.Time `json:"lastPoll,omitzero"`
	LastChange time.Time `json:"lastChange,omitzero"`
	LastCommit time.Time `json:"lastCommit,omitzero"`
	// The feed's head and the lag behind it, as of the last poll.
	Head       string    `json:"head,omitempty"`
	Lag        int64     `json:"lag,omitempty"`
	LagKnown   bool      `json:"lagKnown,omitempty"`
	HeadTime   time.Time `json:"headTime,omitzero"`
	CursorTime time.Time `json:"cursorTime,omitzero"`
	// Batch is the batch being worked on; BatchSeq numbers batches.
	Batch    *batchProgress `json:"batch,omitempty"`
	BatchSeq uint64         `json:"batchSeq,omitempty"`
	// BudgetUsed is what the mirror added to the cache from this upstream.
	// BudgetExhaustedAt is the budget in force when a file did not fit in
	// what was left of it: the mirror waits until the budget is larger.
	BudgetUsed        int64         `json:"budgetUsed"`
	BudgetExhaustedAt int64         `json:"budgetExhaustedAt,omitempty"`
	Counters          Counters      `json:"counters"`
	RecentErrors      []ErrorRecord `json:"recentErrors,omitempty"`
}

// batchProgress is how far the pending batch has come.
type batchProgress struct {
	Seq uint64 `json:"seq"`
	// Phase and From are the phase and cursor the batch was polled with;
	// Next, More and the head figures what the feed returned with it.
	Phase string `json:"phase"`
	From  string `json:"from,omitempty"`
	Next  string `json:"next"`
	More  bool   `json:"more,omitempty"`
	// Total is the number of items; items [0, Done) are dealt with, and so
	// are the items listed in Ahead (done out of order by another worker
	// while an earlier one was still at work).
	Total  int       `json:"total"`
	Done   int       `json:"done"`
	Ahead  []int     `json:"ahead,omitempty"`
	Polled time.Time `json:"polled"`
}

// queued is how many items of the batch are still to do.
func (b *batchProgress) queued() int {
	if b == nil {
		return 0
	}
	n := b.Total - b.Done - len(b.Ahead)
	if n < 0 {
		return 0
	}
	return n
}

// batchFile is batch.json.
type batchFile struct {
	Seq   uint64       `json:"seq"`
	Items []Coordinate `json:"items"`
}

// maxDeferred bounds an upstream's deferred queue.
const maxDeferred = 20_000

// maxDeferrals is how often one file may be deferred before the gate's
// "not yet" is taken as its verdict.
const maxDeferrals = 30

// deferredItem is a file a gate refused for now — a version still in its
// maturity cooldown, a file its scanner could not judge — to be asked for
// again at NotBefore.
type deferredItem struct {
	Package   string    `json:"package"`
	Version   string    `json:"version,omitempty"`
	Path      string    `json:"path"`
	Accept    string    `json:"accept,omitempty"`
	Size      int64     `json:"size,omitempty"`
	Gate      string    `json:"gate"`
	Code      string    `json:"code,omitempty"`
	NotBefore time.Time `json:"notBefore"`
	Since     time.Time `json:"since"`
	Deferrals int       `json:"deferrals"`
}

// deferredFile is deferred.json.
type deferredFile struct {
	Items []deferredItem `json:"items"`
}

// controlFile is control.json: what operators asked for.
type controlFile struct {
	Paused   bool      `json:"paused,omitempty"`
	PausedBy string    `json:"pausedBy,omitempty"`
	PausedAt time.Time `json:"pausedAt,omitzero"`
	Reason   string    `json:"reason,omitempty"`
	// ResyncSeq counts the resync requests; the follower acts on one it has
	// not handled yet.
	ResyncSeq uint64    `json:"resyncSeq,omitempty"`
	ResyncBy  string    `json:"resyncBy,omitempty"`
	ResyncAt  time.Time `json:"resyncAt,omitzero"`
}

// store reads and writes the state directory.
type store struct{ dir string }

// literalName is an upstream name used as a directory name as it is.
var literalName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// upstreamDirName maps an upstream name onto a directory name: the name
// itself when it is a plain one, otherwise "_" and a digest of it (no plain
// name starts with "_", so the two never collide).
func upstreamDirName(name string) string {
	if literalName.MatchString(name) && name != "." && name != ".." {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return "_" + hex.EncodeToString(sum[:16])
}

func (s store) upstreamDir(name string) string {
	return filepath.Join(s.dir, "upstreams", upstreamDirName(name))
}

func (s store) feedDir(name string) string { return filepath.Join(s.upstreamDir(name), "feed") }

func (s store) globalControlPath() string { return filepath.Join(s.dir, "control.json") }

func (s store) controlPath(name string) string {
	return filepath.Join(s.upstreamDir(name), "control.json")
}

func (s store) statePath(name string) string { return filepath.Join(s.upstreamDir(name), "state.json") }

func (s store) batchPath(name string) string { return filepath.Join(s.upstreamDir(name), "batch.json") }

func (s store) deferredPath(name string) string {
	return filepath.Join(s.upstreamDir(name), "deferred.json")
}

// errNoFile is returned for a file that does not exist.
var errNoFile = errors.New("fullmirror: no such state file")

// maxStateFile bounds a state file read back.
const maxStateFile = 256 << 20

// readJSON decodes a state file.
func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return errNoFile
	}
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() > maxStateFile {
		return fmt.Errorf("fullmirror: %s is larger than %d bytes", path, maxStateFile)
	}
	dec := json.NewDecoder(f)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("fullmirror: reading %s: %w", path, err)
	}
	return nil
}

// writeJSON replaces a state file atomically.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'))
}

// writeFileAtomic writes data aside, syncs it and renames it over path, then
// syncs the directory, so that path holds the old content or the new one.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if name != "" {
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o640); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	name = ""
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func (s store) loadState(name string) (upstreamState, error) {
	var st upstreamState
	err := readJSON(s.statePath(name), &st)
	if err != nil {
		return upstreamState{}, err
	}
	if st.Format != stateFormat {
		return upstreamState{}, fmt.Errorf("fullmirror: %s has format %d, this version reads %d", s.statePath(name), st.Format, stateFormat)
	}
	if st.Phase != phaseBootstrap && st.Phase != phaseFollow {
		return upstreamState{}, fmt.Errorf("fullmirror: %s names an unknown phase %q", s.statePath(name), st.Phase)
	}
	if st.Batch != nil && (st.Batch.Done < 0 || st.Batch.Done > st.Batch.Total) {
		return upstreamState{}, fmt.Errorf("fullmirror: %s: the batch's progress %d/%d is impossible", s.statePath(name), st.Batch.Done, st.Batch.Total)
	}
	return st, nil
}

// errFenced reports that another replica has written the state under a newer
// leadership.
var errFenced = errors.New("fullmirror: another replica leads the full mirror now")

// saveState writes state.json as generation expect+1, unless the file has
// moved past generation expect: another writer has written it since. A file
// that cannot be read is overwritten — the follower writes only state it
// loaded, or a fresh one after an operator's resync.
func (s store) saveState(name string, st upstreamState, expect uint64) error {
	var cur upstreamState
	err := readJSON(s.statePath(name), &cur)
	if err == nil && cur.Generation != expect {
		return errFenced
	}
	st.Format = stateFormat
	st.Generation = expect + 1
	return writeJSON(s.statePath(name), st)
}

func (s store) loadBatch(name string) (batchFile, error) {
	var b batchFile
	err := readJSON(s.batchPath(name), &b)
	return b, err
}

func (s store) saveBatch(name string, b batchFile) error { return writeJSON(s.batchPath(name), b) }

func (s store) removeBatch(name string) error {
	err := os.Remove(s.batchPath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (s store) loadDeferred(name string) (deferredFile, error) {
	var d deferredFile
	err := readJSON(s.deferredPath(name), &d)
	return d, err
}

func (s store) saveDeferred(name string, d deferredFile) error {
	return writeJSON(s.deferredPath(name), d)
}

func (s store) loadControl(path string) (controlFile, error) {
	var c controlFile
	err := readJSON(path, &c)
	if errors.Is(err, errNoFile) {
		return controlFile{}, nil
	}
	return c, err
}

func (s store) saveControl(path string, c controlFile) error { return writeJSON(path, c) }

// credentialsInURL matches the user-information part of a URL.
var credentialsInURL = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@`)

// maxErrorMessage bounds a recorded error message.
const maxErrorMessage = 400

// cleanMessage prepares an error for the status page and the state file: no
// credentials in URLs, no control characters, bounded length.
func cleanMessage(msg string) string {
	msg = credentialsInURL.ReplaceAllString(msg, "${1}***@")
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)
	if len(msg) > maxErrorMessage {
		cut := maxErrorMessage
		for cut > 0 && !utf8Start(msg[cut]) {
			cut--
		}
		msg = msg[:cut] + "…"
	}
	return msg
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
