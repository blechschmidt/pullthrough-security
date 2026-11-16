package fullscan

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// stateFormat is the version of state.json's layout.
const stateFormat = 1

// Counters are one upstream's cumulative tallies of what the full scan did.
// They are persisted, so they carry over restarts.
type Counters struct {
	// Scans counts the readings the full scan obtained with a model call;
	// CachedVerdicts those the verdict cache answered (no model call).
	Scans          uint64 `json:"scans"`
	CachedVerdicts uint64 `json:"cachedVerdicts"`
	// Verdicts counts the full scan's readings by the gate's disposition
	// (benign, suspicious, malicious); Unscanned its readings without a
	// verdict, by reason code.
	Verdicts  map[string]uint64 `json:"verdicts,omitempty"`
	Unscanned map[string]uint64 `json:"unscanned,omitempty"`
	// Mirrored and ClientPulls count the readings the full mirror's fetches
	// and clients' pulls reported.
	Mirrored    uint64 `json:"mirrored"`
	ClientPulls uint64 `json:"clientPulls"`
	// Refused counts the readings the configured action refuses (a malicious
	// verdict under block or quarantine, a suspicious one under quarantine);
	// Evicted those whose object the ladder removed from the cache.
	Refused uint64 `json:"refused"`
	Evicted uint64 `json:"evicted"`
	// Retries counts attempts repeated after a reading that was worth
	// retrying; Errors failed attempts; Gone artifacts that left the cache.
	Retries uint64 `json:"retries"`
	Errors  uint64 `json:"errors"`
	Gone    uint64 `json:"gone"`
	// Rescans counts the artifacts put back into the queue, by reason
	// ("version": the scan signature changed; "operator": a re-scan request).
	Rescans map[string]uint64 `json:"rescans,omitempty"`
	// GateRefusals counts the artifacts another admission gate refused in a
	// gate pass, by gate.
	GateRefusals map[string]uint64 `json:"gateRefusals,omitempty"`
	// SpentUSD is what the full scan's model calls for this upstream cost.
	SpentUSD float64 `json:"spentUsd"`
}

func (c *Counters) clone() Counters {
	out := *c
	out.Verdicts = cloneCounts(c.Verdicts)
	out.Unscanned = cloneCounts(c.Unscanned)
	out.Rescans = cloneCounts(c.Rescans)
	out.GateRefusals = cloneCounts(c.GateRefusals)
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

func bump(m *map[string]uint64, key string, n uint64) {
	if n == 0 || key == "" {
		return
	}
	if *m == nil {
		*m = map[string]uint64{}
	}
	(*m)[key] += n
}

// stateFile is state.json.
type stateFile struct {
	Format int `json:"format"`
	// Generation counts the writes of the file. A writer expects the
	// generation it last read or wrote: finding another means another
	// replica has taken over, and the stale one stands by.
	Generation uint64 `json:"generation"`
	// Snapshot and Journal name the live inventory files.
	Snapshot string `json:"snapshot,omitempty"`
	Journal  string `json:"journal,omitempty"`
	// Seq numbers the queue's entries.
	Seq uint64 `json:"seq"`
	// Signature is the scan signature the inventory was last checked against.
	Signature string `json:"signature,omitempty"`
	// RescanHandled is the last operator re-scan request acted on.
	RescanHandled uint64 `json:"rescanHandled,omitempty"`
	// The last backfill sweep.
	LastSweep         time.Time `json:"lastSweep,omitzero"`
	LastSweepFinished time.Time `json:"lastSweepFinished,omitzero"`
	LastSweepError    string    `json:"lastSweepError,omitempty"`
	// Untracked counts, per upstream, the cached objects of the last sweep the
	// full scan could not attribute (no fill metadata); "" counts the ones of
	// no upstream at all.
	Untracked map[string]int       `json:"untracked,omitempty"`
	Ledger    Ledger               `json:"ledger"`
	Counters  map[string]*Counters `json:"counters,omitempty"`
	// Published is the status as of the write, for replicas that do not lead.
	Published *Status `json:"published,omitempty"`
}

// errNoFile is returned for a state file that does not exist.
var errNoFile = errors.New("fullscan: no such state file")

// errFenced reports that another replica has written the state since.
var errFenced = errors.New("fullscan: another replica leads the full scan now")

// maxStateFile bounds state.json and control.json when read back.
const maxStateFile = 64 << 20

// maxItemLine bounds one line of the snapshot or the journal.
const maxItemLine = 64 << 10

// store reads and writes the state directory.
type store struct{ dir string }

func (s store) statePath() string   { return filepath.Join(s.dir, "state.json") }
func (s store) controlPath() string { return filepath.Join(s.dir, "control.json") }
func (s store) inboxDir() string    { return filepath.Join(s.dir, "inbox") }

// inventoryName matches the snapshot and journal files the store writes.
var inventoryName = regexp.MustCompile(`^items-[0-9]+-[0-9a-f]{8}\.(snap|log)$`)

func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return errNoFile
	}
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateFile+1))
	if err != nil {
		return err
	}
	if len(data) > maxStateFile {
		return fmt.Errorf("fullscan: %s is larger than %d bytes", path, maxStateFile)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("fullscan: reading %s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'))
}

// writeFileAtomic writes data aside, syncs it and renames it over path, then
// syncs the directory.
func writeFileAtomic(path string, data []byte) error {
	return writeAtomic(path, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

func writeAtomic(path string, write func(io.Writer) error) error {
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
	bw := bufio.NewWriterSize(tmp, 256<<10)
	if err := write(bw); err != nil {
		tmp.Close()
		return err
	}
	if err := bw.Flush(); err != nil {
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
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

func (s store) loadState() (stateFile, error) {
	var st stateFile
	if err := readJSON(s.statePath(), &st); err != nil {
		return stateFile{}, err
	}
	if st.Format != stateFormat {
		return stateFile{}, fmt.Errorf("fullscan: %s has format %d, this version reads %d", s.statePath(), st.Format, stateFormat)
	}
	for _, name := range []string{st.Snapshot, st.Journal} {
		if name != "" && !inventoryName.MatchString(name) {
			return stateFile{}, fmt.Errorf("fullscan: %s names an invalid inventory file %q", s.statePath(), name)
		}
	}
	return st, nil
}

// saveState writes state.json as generation expect+1, unless another writer
// has moved it past generation expect.
func (s store) saveState(st stateFile, expect uint64) (uint64, error) {
	cur, err := s.loadState()
	switch {
	case err == nil && cur.Generation != expect:
		return 0, errFenced
	case err != nil && !errors.Is(err, errNoFile) && expect != 0:
		// The file we wrote last cannot be read back: do not guess.
		return 0, fmt.Errorf("fullscan: re-reading the state before writing it: %w", err)
	}
	st.Format = stateFormat
	st.Generation = expect + 1
	if err := writeJSON(s.statePath(), st); err != nil {
		return 0, err
	}
	return st.Generation, nil
}

// logLine is one line of the journal: an item put, or a key deleted.
type logLine struct {
	Del string `json:"del,omitempty"`
	Item
}

// loadInventory reads the snapshot and replays the journal over it. A torn
// last line (a crash in the middle of an append) is ignored; a damaged line
// elsewhere is skipped and counted.
func (s store) loadInventory(st stateFile) (map[string]*Item, int, error) {
	items := map[string]*Item{}
	skipped := 0
	read := func(name string, journal bool) error {
		if name == "" {
			return nil
		}
		f, err := os.Open(filepath.Join(s.dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			if journal {
				return nil // nothing was appended before the crash
			}
			return fmt.Errorf("fullscan: the inventory snapshot %s is missing", name)
		}
		if err != nil {
			return err
		}
		defer f.Close()
		r := bufio.NewReaderSize(f, 256<<10)
		for {
			line, err := readLine(r)
			if len(line) > 0 {
				var ln logLine
				if jerr := json.Unmarshal(line, &ln); jerr != nil || (ln.Del == "" && !validItem(&ln.Item)) {
					if !(journal && errors.Is(err, io.EOF)) {
						skipped++
					}
				} else if ln.Del != "" {
					delete(items, ln.Del)
				} else {
					it := ln.Item
					it.hq, it.hi = -1, -1
					items[it.Key] = &it
				}
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}
	if err := read(st.Snapshot, false); err != nil {
		return nil, skipped, err
	}
	if err := read(st.Journal, true); err != nil {
		return nil, skipped, err
	}
	return items, skipped, nil
}

// readLine reads one line, refusing one longer than maxItemLine (it is read
// to its end and returned empty).
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > maxItemLine {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if tooLong {
			return []byte("{"), err // unparseable: counted as damaged
		}
		return bytes.TrimSpace(buf), err
	}
}

// validItem checks an item read back.
func validItem(it *Item) bool {
	if it.Key == "" || it.Upstream == "" || !strings.HasPrefix(it.Path, "/") {
		return false
	}
	switch it.State {
	case StatePending, StateScanned, StateUnscannable, StateNotApplicable, StateError:
	default:
		return false
	}
	return it.Priority >= 0 && it.Priority < numPriorities
}

// newInventoryNames returns fresh snapshot and journal names for a
// generation.
func newInventoryNames(gen uint64) (snap, journal string) {
	var b [4]byte
	_, _ = rand.Read(b[:])
	base := fmt.Sprintf("items-%d-%s", gen, hex.EncodeToString(b[:]))
	return base + ".snap", base + ".log"
}

// writeSnapshot writes the inventory, one item per line, sorted by key.
func (s store) writeSnapshot(name string, items map[string]*Item) error {
	keys := make([]string, 0, len(items))
	for k := range items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return writeAtomic(filepath.Join(s.dir, name), func(w io.Writer) error {
		enc := json.NewEncoder(w)
		for _, k := range keys {
			if err := enc.Encode(items[k]); err != nil {
				return err
			}
		}
		return nil
	})
}

// removeStale deletes inventory files no state names: the previous
// generation's, and those of a replica that lost a race to take over (once
// they are older than a minute, so as not to race a replica writing them).
func (s store) removeStale(keep ...string) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	kept := map[string]bool{}
	for _, k := range keep {
		kept[k] = true
	}
	for _, e := range entries {
		name := e.Name()
		if kept[name] || !inventoryName.MatchString(name) {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) < time.Minute {
			continue
		}
		_ = os.Remove(filepath.Join(s.dir, name))
	}
}

// journal appends the inventory's changes to the live journal file.
type journal struct {
	f       *os.File
	w       *bufio.Writer
	records int
	pending bool
}

func (s store) openJournal(name string) (*journal, error) {
	f, err := os.OpenFile(filepath.Join(s.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return &journal{f: f, w: bufio.NewWriterSize(f, 64<<10)}, nil
}

func (j *journal) put(it *Item) error {
	data, err := json.Marshal(it)
	if err != nil {
		return err
	}
	return j.append(data)
}

func (j *journal) del(key string) error {
	data, err := json.Marshal(map[string]string{"del": key})
	if err != nil {
		return err
	}
	return j.append(data)
}

func (j *journal) append(data []byte) error {
	if j == nil {
		return nil
	}
	data = append(data, '\n')
	if _, err := j.w.Write(data); err != nil {
		return err
	}
	j.records++
	j.pending = true
	return nil
}

// flush writes the buffered changes and syncs them.
func (j *journal) flush() error {
	if j == nil || !j.pending {
		return nil
	}
	if err := j.w.Flush(); err != nil {
		return err
	}
	if err := j.f.Sync(); err != nil {
		return err
	}
	j.pending = false
	return nil
}

func (j *journal) close() error {
	if j == nil {
		return nil
	}
	err := j.flush()
	if cerr := j.f.Close(); err == nil {
		err = cerr
	}
	return err
}
