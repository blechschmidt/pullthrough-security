package fullscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Notes: what the server learns about cached artifacts in scope outside the
// full scan's own scans — the gate's readings of the full mirror's fetches and
// of clients' pulls, and the cached files the mirror skips. Note never blocks:
// it hands the note to the loop, which records it on the leader. A replica
// that does not lead passes on, through the inbox, only what the leader must
// act on — an artifact still without a verdict — and drops the rest: the
// leader learns it again from the sweep or the verdict cache, at no cost.

// Note records what the server learned about a cached artifact. Notes about
// upstreams outside the scope, or without a cache key or a request path, are
// ignored. Safe on nil.
func (s *Service) Note(n Note) {
	if !s.Enabled() || !s.inScope(n.Artifact.Upstream) || !validArtifact(n.Artifact) {
		return
	}
	if n.Reading != nil {
		r := *n.Reading
		n.Reading = &r
	}
	select {
	case s.notes <- n:
		s.kick()
	default:
		s.dropped.Add(1)
	}
}

// validArtifact checks an artifact a note or the inbox names.
func validArtifact(a Artifact) bool {
	return a.Key != "" && len(a.Key) <= 4096 && a.Upstream != "" &&
		strings.HasPrefix(a.Path, "/") && len(a.Path) <= 2048 && len(a.Accept) <= 2048 &&
		!strings.ContainsAny(a.Path+a.Accept+a.Key+a.Tenant, "\r\n\x00")
}

// needsScan reports a note the leader must act on: an artifact without a
// verdict that is worth trying for.
func (n Note) needsScan() bool {
	if n.Reading == nil {
		return n.Source == SourceSeen
	}
	return n.Reading.Kind == ReadingUnscanned && (n.Reading.Retryable || !n.Reading.Content)
}

// applyNotes records the notes waiting (leader).
func (s *Service) applyNotes() {
	for i := 0; i < maxNotesPerStep; i++ {
		select {
		case n := <-s.notes:
			s.mu.Lock()
			if s.loaded {
				s.applyNoteLocked(n)
			}
			s.mu.Unlock()
		default:
			return
		}
	}
}

// applyNoteLocked records one note.
func (s *Service) applyNoteLocked(n Note) {
	now := s.now()
	a := n.Artifact
	it := s.items[a.Key]
	if it == nil {
		if len(s.items) >= s.opts.MaxItems {
			s.dropped.Add(1)
			return
		}
		it = s.newItem(a, now)
		s.items[a.Key] = it
		if n.Reading == nil {
			s.enqueueLocked(it, PriorityBackfill, now, time.Time{})
			return
		}
	} else if a.Digest != "" && it.Digest != "" && a.Digest != it.Digest && !it.busy {
		// Other bytes under the same key: what was known is about the old
		// ones — their verdict, and who pulled them.
		it.Digest, it.Size, it.Evicted = a.Digest, a.Size, false
		it.Gates, it.Gate = "", ""
		it.Tenants = nil
		if n.Source == SourceClient || n.Source == SourceMirror {
			it.Tenant = a.Tenant
		}
		if n.Reading == nil {
			s.enqueueLocked(it, PriorityBackfill, now, time.Time{})
			return
		}
	}
	if n.Attribution {
		// Only who pulled it: the replica that served the pull had nothing
		// else for the leader.
		if it.addTenant(a.Tenant) {
			s.putLocked(it)
		}
		return
	}
	if (n.Source == SourceClient || n.Source == SourceMirror) && it.addTenant(a.Tenant) {
		// Another tenant pulled it: journalled whatever else the note
		// changes (a second write of the item is harmless).
		defer s.putLocked(it)
	}
	if it.busy {
		return // its scan is running; that result is recorded
	}
	if n.Reading != nil && it.Refresh && it.State == StatePending && !n.Reading.Fresh {
		// An operator asked for a new model call: a reading the verdict
		// cache gave a client (or the mirror) does not answer that.
		s.countNoteLocked(it, n.Source)
		return
	}
	if n.Reading == nil {
		// The mirror found it cached: an artifact the ladder evicted is back.
		if it.Evicted {
			it.Evicted = false
			s.enqueueLocked(it, PriorityBackfill, now, time.Time{})
		}
		return
	}
	s.countNoteLocked(it, n.Source)
	if sameReading(it, *n.Reading) {
		// A pull of an artifact whose reading is on record already: nothing
		// changes, nothing is written — unless the reading names the
		// coordinate an older record lacks.
		if it.learnCoordinate(*n.Reading) {
			s.putLocked(it)
		}
		s.dirty = true
		return
	}
	if it.Evicted && !n.Reading.Evicted {
		it.Evicted = false // the object is cached again
	}
	s.applyReadingLocked(it, *n.Reading, now, n.Source)
}

// countNoteLocked counts a reading a note brought.
func (s *Service) countNoteLocked(it *Item, src Source) {
	c := s.countersLocked(it.Upstream)
	switch src {
	case SourceClient:
		c.ClientPulls++
	case SourceMirror:
		c.Mirrored++
	}
	s.dirty = true
}

// sameReading reports a reading that says what the item records already.
func sameReading(it *Item, r Reading) bool {
	if it.Evicted != r.Evicted || (r.Digest != "" && r.Digest != it.Digest) || (r.Gates != "" && r.Gates != it.Gates) {
		return false
	}
	switch r.Kind {
	case ReadingVerdict:
		return it.State == StateScanned && it.Verdict == r.Disposition && it.Signature == r.Signature
	case ReadingNotApplicable:
		return it.State == StateNotApplicable && it.Code == r.Code
	case ReadingUnscanned:
		if r.Content && !r.Retryable {
			return it.State == StateUnscannable && it.Code == r.Code
		}
		return it.State == StatePending && it.Priority == PriorityClient
	}
	return false
}

// forwardNotes passes on, from a replica that does not lead, the notes the
// leader must act on (through the inbox), and once per artifact and tenant
// who pulled it (for the figures per tenant); it drops the rest.
func (s *Service) forwardNotes() {
	for i := 0; i < maxNotesPerStep; i++ {
		select {
		case n := <-s.notes:
			if n.needsScan() {
				if err := s.writeInbox(n); err != nil {
					s.log.Debug("fullscan: writing to the inbox", "error", err)
				}
			}
			if (n.Source == SourceClient || n.Source == SourceMirror) && n.Artifact.Tenant != "" && s.firstAttribution(n.Artifact) {
				a := n
				a.Attribution, a.Reading = true, nil
				if err := s.writeInbox(a); err != nil {
					s.log.Debug("fullscan: writing to the inbox", "error", err)
				}
			}
		default:
			return
		}
	}
}

// maxAttributed bounds the attributions a replica remembers having
// forwarded; when full it forgets them (the leader ignores a repeated one).
const maxAttributed = 100_000

// firstAttribution reports whether this replica has not yet forwarded that
// the artifact's tenant pulled it, and remembers that it now has.
func (s *Service) firstAttribution(a Artifact) bool {
	key := a.Key + "\x00" + a.Tenant
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.attributed[key]; ok {
		return false
	}
	if s.attributed == nil || len(s.attributed) >= maxAttributed {
		s.attributed = map[string]struct{}{}
	}
	s.attributed[key] = struct{}{}
	return true
}

// Inbox bounds.
const (
	// maxInbox is the most files the inbox holds; a replica writes no more.
	maxInbox = 10_000
	// maxInboxFile bounds one inbox file.
	maxInboxFile = 16 << 10
	// maxInboxPerStep bounds the files the leader reads in one step.
	maxInboxPerStep = 2000
)

// inboxEntry is one file of the inbox.
type inboxEntry struct {
	Source   Source   `json:"source"`
	Artifact Artifact `json:"artifact"`
	Code     string   `json:"code,omitempty"`
	// Attribution marks an entry that says only who pulled the artifact.
	Attribution bool `json:"attribution,omitempty"`
}

var inboxCount struct {
	sync.Mutex
	n  int
	at time.Time
}

// writeInbox writes a note for the leader. The file is named after the cache
// key, so a second note about the same artifact replaces the first; an
// attribution after the key and the tenant, so each tenant's survives.
func (s *Service) writeInbox(n Note) error {
	dir := s.store.inboxDir()
	inboxCount.Lock()
	if time.Since(inboxCount.at) > time.Minute {
		inboxCount.n, inboxCount.at = 0, time.Now()
		if entries, err := os.ReadDir(dir); err == nil {
			inboxCount.n = len(entries)
		}
	}
	full := inboxCount.n >= maxInbox
	if !full {
		inboxCount.n++
	}
	inboxCount.Unlock()
	if full {
		s.dropped.Add(1)
		return errors.New("fullscan: the inbox is full")
	}
	e := inboxEntry{Source: n.Source, Artifact: n.Artifact, Attribution: n.Attribution}
	if n.Reading != nil {
		e.Code = n.Reading.Code
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	name := n.Artifact.Key
	if n.Attribution {
		name += "\x00" + n.Artifact.Tenant
	}
	sum := sha256.Sum256([]byte(name))
	return writeFileAtomic(filepath.Join(dir, hex.EncodeToString(sum[:20])+".json"), data)
}

// ingestInbox reads what other replicas left for the leader.
func (s *Service) ingestInbox() {
	now := s.now()
	s.mu.Lock()
	due := now.Sub(s.lastInbox) >= s.opts.InboxInterval
	if due {
		s.lastInbox = now
	}
	s.mu.Unlock()
	if !due {
		return
	}
	dir := s.store.inboxDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.log.Warn("fullscan: reading the inbox", "error", err)
		}
		return
	}
	n := 0
	for _, de := range entries {
		if n >= maxInboxPerStep {
			break
		}
		name := de.Name()
		if strings.HasPrefix(name, ".tmp-") {
			// A write a crash cut short: gone after a while.
			if info, err := de.Info(); err == nil && time.Since(info.ModTime()) > time.Minute {
				_ = os.Remove(filepath.Join(dir, name))
			}
			continue
		}
		if !strings.HasSuffix(name, ".json") || !de.Type().IsRegular() {
			continue
		}
		n++
		// Claim the file before reading it: a newer note a follower writes
		// meanwhile lands under the name again and is read next time.
		path := filepath.Join(dir, name)
		claimed := path + ".claimed"
		if err := os.Rename(path, claimed); err != nil {
			continue
		}
		e, ok := readInboxEntry(claimed)
		_ = os.Remove(claimed)
		if !ok || !s.inScope(e.Artifact.Upstream) || !validArtifact(e.Artifact) {
			continue
		}
		note := Note{Source: e.Source, Artifact: e.Artifact, Attribution: e.Attribution}
		if e.Source != SourceSeen && !e.Attribution {
			note.Reading = &Reading{Kind: ReadingUnscanned, Code: e.Code, Retryable: true}
		}
		s.mu.Lock()
		if s.loaded {
			s.applyNoteLocked(note)
		}
		s.mu.Unlock()
	}
}

func readInboxEntry(path string) (inboxEntry, bool) {
	f, err := os.Open(path)
	if err != nil {
		return inboxEntry{}, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxInboxFile+1))
	if err != nil || len(data) > maxInboxFile {
		return inboxEntry{}, false
	}
	var e inboxEntry
	if json.Unmarshal(data, &e) != nil {
		return inboxEntry{}, false
	}
	switch e.Source {
	case SourceClient, SourceMirror, SourceSeen:
	default:
		return inboxEntry{}, false
	}
	return e, true
}
