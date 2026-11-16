package fullmirror

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIndex is an indexSource over records held in memory, in two parts ("a"
// and "b"), each with its own validator: a read copies an unchanged part from
// the previous copy, as APT's adapter does for an unchanged Packages file.
type fakeIndex struct {
	mu     sync.Mutex
	parts  map[string][]snapRecord
	etags  map[string]string
	reads  int
	copied []string
	fail   error
}

type fakeIndexState struct {
	ETags map[string]string `json:"etags"`
}

func newFakeIndex() *fakeIndex {
	return &fakeIndex{parts: map[string][]snapRecord{}, etags: map[string]string{}}
}

func (s *fakeIndex) set(part string, recs ...snapRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range recs {
		recs[i].Index = part
	}
	s.parts[part] = recs
	s.etags[part] = fmt.Sprintf("%s-%d", part, time.Now().UnixNano())
}

func (s *fakeIndex) readIndex(_ context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.fail != nil {
		return indexRead{}, s.fail
	}
	var st fakeIndexState
	if prev != nil {
		if err := json.Unmarshal(prev, &st); err != nil {
			return indexRead{}, err
		}
	}
	same := 0
	var unchanged []string
	for part, etag := range s.etags {
		if old != nil && st.ETags[part] == etag {
			same++
			unchanged = append(unchanged, part)
		}
	}
	if old != nil && same == len(s.etags) && len(st.ETags) == len(s.etags) {
		return indexRead{Unchanged: true}, nil
	}
	keep := map[string]bool{}
	for _, p := range unchanged {
		keep[p] = true
	}
	if old != nil && len(keep) > 0 {
		sort.Strings(unchanged)
		s.copied = append(s.copied, unchanged...)
		if err := b.CopyFrom(old, func(r *snapRecord) bool { return keep[r.Index] }); err != nil {
			return indexRead{}, err
		}
	}
	for part, recs := range s.parts {
		if keep[part] {
			continue
		}
		for _, r := range recs {
			b.Add(r)
		}
	}
	etags := map[string]string{}
	for k, v := range s.etags {
		etags[k] = v
	}
	state, _ := json.Marshal(fakeIndexState{ETags: etags})
	return indexRead{State: state, Head: "rev", HeadTime: time.Unix(1700000000, 0)}, nil
}

// testIndexFeed is an adapter made of an indexFeed and Releases from its copy.
type testIndexFeed struct{ *indexFeed }

func (f testIndexFeed) Releases(_ context.Context, name string) ([]Release, error) {
	recs, err := f.lookup(name)
	if err != nil {
		return nil, err
	}
	return snapReleases(recs), nil
}

func newTestIndexFeed(t *testing.T, src indexSource, page int) testIndexFeed {
	f := newIndexFeed("test", Env{Dir: t.TempDir()}, src)
	f.page = page
	return testIndexFeed{f}
}

func pkgs(names ...string) []snapRecord {
	var out []snapRecord
	for _, n := range names {
		name, version, _ := strings.Cut(n, "@")
		out = append(out, snapRecord{Name: name, Version: version, Path: "/f/" + name + "-" + version})
	}
	return out
}

func drainBootstrap(t *testing.T, f Feed) ([]string, string) {
	t.Helper()
	var all []string
	cursor := ""
	for i := 0; ; i++ {
		b, err := f.Bootstrap(context.Background(), cursor)
		if err != nil {
			t.Fatalf("Bootstrap(%q): %v", cursor, err)
		}
		if err := validateBatch(b); err != nil {
			t.Fatal(err)
		}
		all = append(all, names(b.Items)...)
		cursor = b.Next
		if !b.More {
			return all, cursor
		}
		if i > 1000 {
			t.Fatal("Bootstrap does not end")
		}
	}
}

func drainChanges(t *testing.T, f Feed, cursor string) ([]string, string) {
	t.Helper()
	var all []string
	for i := 0; ; i++ {
		b, err := f.Changes(context.Background(), cursor)
		if err != nil {
			t.Fatalf("Changes: %v", err)
		}
		if err := validateBatch(b); err != nil {
			t.Fatal(err)
		}
		for _, c := range b.Items {
			s := c.String()
			if c.Deleted {
				s += " (deleted)"
			}
			all = append(all, s)
		}
		cursor = b.Next
		if !b.More {
			return all, cursor
		}
		if i > 1000 {
			t.Fatal("Changes does not end")
		}
	}
}

func TestIndexFeedBootstrapChangesReleases(t *testing.T) {
	src := newFakeIndex()
	src.set("a", pkgs("alpha@1", "alpha@2", "beta@1", "gamma@1")...)
	src.set("b", pkgs("delta@1", "epsilon@3")...)
	f := newTestIndexFeed(t, src, 2)

	listed, cursor := drainBootstrap(t, f)
	sort.Strings(listed)
	if strings.Join(listed, ",") != "alpha,beta,delta,epsilon,gamma" {
		t.Fatalf("Bootstrap listed %v", listed)
	}
	rels, err := f.Releases(context.Background(), "alpha")
	if err != nil || len(rels) != 2 || rels[0].Artifacts[0].Path != "/f/alpha-1" {
		t.Fatalf("Releases(alpha) = %+v, %v", rels, err)
	}
	if _, err := f.Releases(context.Background(), "nope"); !IsPermanent(err) {
		t.Errorf("an unknown package: %v", err)
	}

	// Nothing changed: one read, nothing reported, the cursor stays.
	got, next := drainChanges(t, f, cursor)
	if len(got) != 0 || next != cursor {
		t.Errorf("unchanged index reported %v (cursor moved: %v)", got, next != cursor)
	}

	// Part a changes: a version added, a package gone, a package new; part b
	// is copied from the previous copy, not read again.
	src.set("a", pkgs("alpha@1", "alpha@2", "alpha@3", "gamma@1", "zeta@1")...)
	got, next = drainChanges(t, f, cursor)
	sort.Strings(got)
	if strings.Join(got, ",") != "alpha@3,beta (deleted),zeta" {
		t.Errorf("Changes reported %v", got)
	}
	if strings.Join(src.copied, ",") != "b" {
		t.Errorf("parts copied from the previous copy: %v", src.copied)
	}
	if rels, _ := f.Releases(context.Background(), "alpha"); len(rels) != 3 {
		t.Errorf("Releases reads the newest copy: %+v", rels)
	}
	if rels, _ := f.Releases(context.Background(), "delta"); len(rels) != 1 {
		t.Errorf("a copied part's package: %+v", rels)
	}

	// The engine may ask again from the cursor it stored before (a restart
	// before the batch was committed): the same difference comes back.
	again, next2 := drainChanges(t, f, cursor)
	sort.Strings(again)
	if strings.Join(again, ",") != "alpha@3,beta (deleted),zeta" || next2 != next {
		t.Errorf("asked again: %v (same cursor: %v)", again, next2 == next)
	}

	// Copies no cursor names are pruned once the engine moves on.
	if got, _ := drainChanges(t, f, next); len(got) != 0 {
		t.Errorf("after the difference: %v", got)
	}
	entries, _ := os.ReadDir(f.files.dir)
	copies := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), snapSuffix) {
			copies++
		}
	}
	if copies > 2 {
		t.Errorf("%d copies kept", copies)
	}
}

// A difference larger than a batch is reported over several batches, each
// continuing where the last stopped.
func TestIndexFeedPagesALargeDifference(t *testing.T) {
	src := newFakeIndex()
	src.set("a", pkgs("p0@1")...)
	f := newTestIndexFeed(t, src, 3)
	_, cursor := drainBootstrap(t, f)
	var recs []snapRecord
	for i := 0; i < 10; i++ {
		recs = append(recs, pkgs(fmt.Sprintf("p%d@2", i))...)
	}
	src.set("a", recs...)
	b, err := f.Changes(context.Background(), cursor)
	if err != nil || !b.More || len(b.Items) != 3 {
		t.Fatalf("first page: %+v %v", b, err)
	}
	got, _ := drainChanges(t, f, cursor)
	if len(got) != 11 { // p0@2, p0@1 gone, p1…p9
		t.Errorf("reported %d differences: %v", len(got), got)
	}
}

// A cursor whose copy is gone, or that is not this feed's, makes the engine
// enumerate again.
func TestIndexFeedInvalidCursors(t *testing.T) {
	src := newFakeIndex()
	src.set("a", pkgs("x@1")...)
	f := newTestIndexFeed(t, src, 10)
	_, cursor := drainBootstrap(t, f)
	for name, c := range map[string]string{
		"garbage":       "{",
		"other adapter": `{"format":"npm/1","snap":"` + strings.Repeat("a", 64) + `"}`,
		"no copy":       `{"format":"test/1","snap":"` + strings.Repeat("a", 64) + `"}`,
		"not a digest":  `{"format":"test/1","snap":"../../x"}`,
		"listing":       strings.Replace(cursor, `"snap"`, `"listing":true,"snap"`, 1),
	} {
		if _, err := f.Changes(context.Background(), c); !errors.Is(err, ErrCursorInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.Bootstrap(context.Background(), cursor); !errors.Is(err, ErrCursorInvalid) {
		t.Errorf("Bootstrap with a follow cursor: %v", err)
	}
	// The copy deleted behind the feed's back.
	var c indexCursor
	_ = json.Unmarshal([]byte(cursor), &c)
	os.Remove(f.files.path(snapName(c.Snap)))
	if _, err := f.Changes(context.Background(), cursor); !errors.Is(err, ErrCursorInvalid) {
		t.Errorf("a deleted copy: %v", err)
	}
	// A failing read is the source's error, retried by the engine.
	src.fail = errors.New("boom")
	if _, err := f.Bootstrap(context.Background(), ""); err == nil || errors.Is(err, ErrCursorInvalid) {
		t.Errorf("a failing read: %v", err)
	}
}

// A feed built to validate the configuration does nothing.
func TestIndexFeedValidationOnly(t *testing.T) {
	f := newIndexFeed("test", Env{}, newFakeIndex())
	if _, err := f.Bootstrap(context.Background(), ""); !errors.Is(err, errValidationOnly) {
		t.Errorf("Bootstrap: %v", err)
	}
	if _, err := f.lookup("x"); !errors.Is(err, errValidationOnly) {
		t.Errorf("lookup: %v", err)
	}
}

// Releases groups a package's records by version.
func TestSnapReleases(t *testing.T) {
	rels := snapReleases([]snapRecord{
		{Name: "a", Time: 5},
		{Name: "a", Version: "1", Path: "/x", Size: 3, Time: 20},
		{Name: "a", Version: "1", Path: "/x", Index: "other"},
		{Name: "a", Version: "1", Path: "/y", Time: 10, Yanked: true},
		{Name: "a", Version: "2"},
	})
	if len(rels) != 2 || len(rels[0].Artifacts) != 2 || !rels[0].Yanked || rels[0].Published.Unix() != 10 || len(rels[1].Artifacts) != 0 {
		t.Errorf("snapReleases = %+v", rels)
	}
}
