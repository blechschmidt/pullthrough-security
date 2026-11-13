package repos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Object names of the state (see Store).
func repoObject(name string) string    { return "repos/" + name }
func liveObject(name string) string    { return "live/" + name }
func historyPrefix(name string) string { return "history/" + name + "/" }
func historyObject(name string, seq uint64) string {
	return fmt.Sprintf("history/%s/%012d", name, seq)
}
func manifestObject(repo, commit string) string { return "manifests/" + repo + "/" + commit }

// hashRecord computes a record's chained hash: SHA-256 over a versioned,
// canonical serialisation of the record — its fields in a fixed order, each
// length-prefixed, times in UTC RFC 3339 with nanoseconds — that includes the
// previous record's hash. It does not depend on how the record is encoded as
// JSON, so a change of JSON tags or of the struct cannot silently change what
// the chain covers; a change of what it covers needs a new version prefix.
func hashRecord(r TagRecord) string {
	h := sha256.New()
	field := func(s string) {
		fmt.Fprintf(h, "%d:%s\n", len(s), s)
	}
	stamp := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	field("pullthrough-tag-record-v1")
	field(r.Prev)
	field(strconv.FormatUint(r.Seq, 10))
	field(r.Repo)
	field(r.Tag)
	field(r.Kind)
	field(r.Commit)
	field(r.Object)
	field(stamp(r.At))
	field(strconv.FormatUint(r.Supersedes, 10))
	field(r.PreviousCommit)
	field(stamp(r.PreviousLastSeen))
	field(strconv.FormatBool(r.Initial))
	field(r.Trigger)
	return hex.EncodeToString(h.Sum(nil))
}

// ErrHistoryTampered reports a history whose chain does not verify.
var ErrHistoryTampered = errors.New("repos: the tag history does not verify")

// verifyChain checks that records are numbered 1, 2, … without a gap, that
// each links to its predecessor's hash, and that each hash is right.
func verifyChain(repo string, records []TagRecord) error {
	prev := ""
	for i, r := range records {
		want := uint64(i + 1)
		switch {
		case r.Seq != want:
			return fmt.Errorf("%w: %s: record %d is missing (found %d)", ErrHistoryTampered, repo, want, r.Seq)
		case r.Repo != repo:
			return fmt.Errorf("%w: %s: record %d belongs to %q", ErrHistoryTampered, repo, r.Seq, r.Repo)
		case r.Prev != prev:
			return fmt.Errorf("%w: %s: record %d does not link to record %d", ErrHistoryTampered, repo, r.Seq, r.Seq-1)
		case hashRecord(r) != r.Hash:
			return fmt.Errorf("%w: %s: record %d was altered", ErrHistoryTampered, repo, r.Seq)
		}
		prev = r.Hash
	}
	return nil
}

// loadHistory reads a repository's tag history in order and verifies it.
func loadHistory(ctx context.Context, st Store, repo string) ([]TagRecord, error) {
	names, err := st.List(ctx, historyPrefix(repo))
	if err != nil {
		return nil, err
	}
	records := make([]TagRecord, 0, len(names))
	for _, n := range names {
		data, err := st.Get(ctx, n)
		if err != nil {
			return nil, err
		}
		var r TagRecord
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("%w: %s: %s is not a record: %v", ErrHistoryTampered, repo, n, err)
		}
		seq, perr := strconv.ParseUint(n[strings.LastIndexByte(n, '/')+1:], 10, 64)
		if perr != nil || seq != r.Seq {
			return nil, fmt.Errorf("%w: %s: %s holds record %d", ErrHistoryTampered, repo, n, r.Seq)
		}
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Seq < records[j].Seq })
	if err := verifyChain(repo, records); err != nil {
		return records, err
	}
	return records, nil
}

// liveTag is the tracker's view of one current tag.
type liveTag struct {
	Commit    string    `json:"commit"`
	Object    string    `json:"object,omitempty"`
	Seq       uint64    `json:"seq"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// liveState is what the tracker knows about a repository between syncs. Its
// tags and chain head follow from the history; what the history does not hold
// — when each current association was last seen, how the last sync went — is
// persisted as live/<repo>, and is volatile: the tracker rebuilds it from the
// history when it is missing or does not match.
type liveState struct {
	// mu guards the fields below. Only a sync writes them, and syncs of a
	// repository are serialized by the repository's lock, so the sync reads
	// them without mu and takes it only to write; every other reader takes a
	// snapshot under the read lock.
	mu sync.RWMutex

	Repo     string             `json:"repo"`
	HeadSeq  uint64             `json:"headSeq"`
	HeadHash string             `json:"headHash"`
	Tags     map[string]liveTag `json:"tags"`
	// Synced reports that a first sync completed: tags found later are
	// creations, not the initial inventory.
	Synced      bool      `json:"synced"`
	LastSync    time.Time `json:"lastSync,omitzero"`
	LastSuccess time.Time `json:"lastSuccess,omitzero"`
	LastError   string    `json:"lastError,omitempty"`
	// HistoryError is set when the history did not verify.
	HistoryError string `json:"historyError,omitempty"`
}

// snapshot returns a copy a reader may use without locking.
func (l *liveState) snapshot() *liveState {
	l.mu.RLock()
	defer l.mu.RUnlock()
	cp := &liveState{
		Repo: l.Repo, HeadSeq: l.HeadSeq, HeadHash: l.HeadHash, Synced: l.Synced,
		LastSync: l.LastSync, LastSuccess: l.LastSuccess, LastError: l.LastError, HistoryError: l.HistoryError,
		Tags: make(map[string]liveTag, len(l.Tags)),
	}
	for k, v := range l.Tags {
		cp.Tags[k] = v
	}
	return cp
}

// update applies fn to the live state under its write lock.
func (l *liveState) update(fn func(l *liveState)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fn(l)
}

// replay rebuilds a live state from a verified history.
func replay(repo string, records []TagRecord) *liveState {
	st := &liveState{Repo: repo, Tags: map[string]liveTag{}}
	for _, r := range records {
		switch r.Kind {
		case TagCreated, TagMoved:
			st.Tags[r.Tag] = liveTag{Commit: r.Commit, Object: r.Object, Seq: r.Seq, FirstSeen: r.At, LastSeen: r.At}
		case TagDeleted:
			delete(st.Tags, r.Tag)
		}
		st.HeadSeq, st.HeadHash = r.Seq, r.Hash
	}
	st.Synced = len(records) > 0
	return st
}

// loadLive rebuilds a repository's live state from its history and overlays
// the persisted last-seen times when they describe the same history.
func loadLive(ctx context.Context, st Store, repo string) (*liveState, []TagRecord, error) {
	records, herr := loadHistory(ctx, st, repo)
	if herr != nil && !errors.Is(herr, ErrHistoryTampered) {
		return nil, nil, herr
	}
	live := replay(repo, records)
	if data, err := st.Get(ctx, liveObject(repo)); err == nil {
		var saved liveState
		if json.Unmarshal(data, &saved) == nil && herr == nil {
			herr = checkAnchor(repo, records, saved.HeadSeq, saved.HeadHash)
		}
		if herr == nil && saved.HeadSeq == live.HeadSeq && saved.HeadHash == live.HeadHash {
			for tag, t := range live.Tags {
				if s, ok := saved.Tags[tag]; ok && s.Commit == t.Commit && s.Seq == t.Seq && s.LastSeen.After(t.LastSeen) {
					t.LastSeen = s.LastSeen
					live.Tags[tag] = t
				}
			}
			live.Synced = live.Synced || saved.Synced
			live.LastSync, live.LastSuccess, live.LastError = saved.LastSync, saved.LastSuccess, saved.LastError
		}
	} else if !errors.Is(err, ErrNotFound) {
		return nil, nil, err
	}
	if herr != nil {
		live.HistoryError = herr.Error()
	}
	return live, records, nil
}

// head returns the sequence number of the last record the state follows from.
func (l *liveState) head() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.HeadSeq
}

// checkAnchor checks a verified history against a head it was seen to have
// (seq, hash): the history must still hold that record, unchanged. A chain
// whose last records were removed, or rewritten and re-hashed consistently,
// verifies on its own; the head seen before tells.
func checkAnchor(repo string, records []TagRecord, seq uint64, hash string) error {
	if seq == 0 {
		return nil
	}
	if seq > uint64(len(records)) {
		return fmt.Errorf("%w: %s: the history ends at record %d, but it was seen ending at record %d: records were removed (after a restore from a backup, remove the live/%s state object)",
			ErrHistoryTampered, repo, len(records), seq, repo)
	}
	if records[seq-1].Hash != hash {
		return fmt.Errorf("%w: %s: record %d is not the one seen before: the history was rewritten", ErrHistoryTampered, repo, seq)
	}
	return nil
}

// checkSavedAnchor checks a history against the head the saved live state
// records, if there is one.
func checkSavedAnchor(ctx context.Context, st Store, repo string, records []TagRecord) error {
	data, err := st.Get(ctx, liveObject(repo))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved liveState
	if json.Unmarshal(data, &saved) != nil {
		return nil
	}
	return checkAnchor(repo, records, saved.HeadSeq, saved.HeadHash)
}

// appendRecords chains and writes new records after the live head. A record
// is created, never replaced: a concurrent writer that got there first makes
// this fail rather than fork the history.
func appendRecords(ctx context.Context, st Store, live *liveState, recs []TagRecord) ([]TagRecord, error) {
	out := make([]TagRecord, 0, len(recs))
	seq, prev := live.HeadSeq, live.HeadHash
	for _, r := range recs {
		seq++
		r.Seq, r.Repo, r.Prev = seq, live.Repo, prev
		r.Hash = hashRecord(r)
		data, err := json.Marshal(r)
		if err != nil {
			return out, err
		}
		if err := st.Create(ctx, historyObject(live.Repo, seq), data); err != nil {
			if errors.Is(err, ErrExists) {
				return out, fmt.Errorf("repos: %s: history record %d was written by someone else; the next sync re-reads the history", live.Repo, seq)
			}
			return out, err
		}
		prev = r.Hash
		live.update(func(l *liveState) { l.HeadSeq, l.HeadHash = seq, r.Hash })
		out = append(out, r)
	}
	return out, nil
}

// associations turns a history into its tag-to-commit associations, newest
// first, filling last-seen times of current ones from the live state.
func associations(records []TagRecord, live *liveState, tag string) []TagAssociation {
	type open struct {
		idx int
	}
	var out []TagAssociation
	current := map[string]open{}
	for _, r := range records {
		if tag != "" && r.Tag != tag {
			continue
		}
		if o, ok := current[r.Tag]; ok {
			a := &out[o.idx]
			a.SupersededBy, a.SupersededAt = r.Seq, r.At
			if !r.PreviousLastSeen.IsZero() {
				a.LastSeen = r.PreviousLastSeen
			}
			if r.Kind == TagDeleted {
				a.State = AssocDeleted
			} else {
				a.State, a.NextCommit = AssocMoved, r.Commit
			}
			delete(current, r.Tag)
		}
		if r.Kind == TagDeleted {
			continue
		}
		out = append(out, TagAssociation{
			Tag: r.Tag, Commit: r.Commit, Object: r.Object, FirstSeen: r.At, LastSeen: r.At,
			State: AssocCurrent, Seq: r.Seq, Initial: r.Initial,
		})
		current[r.Tag] = open{idx: len(out) - 1}
	}
	if live != nil {
		for t, o := range current {
			if lt, ok := live.Tags[t]; ok && lt.Seq == out[o.idx].Seq && lt.LastSeen.After(out[o.idx].LastSeen) {
				out[o.idx].LastSeen = lt.LastSeen
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq > out[j].Seq })
	return out
}
