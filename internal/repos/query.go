package repos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// States of a release in the API (ReleaseView.State).
const (
	// ReleaseCurrent: a tag points at the commit.
	ReleaseCurrent = "current"
	// ReleaseHistorical: no tag points at the commit any more; its pins stay
	// so the release remains reproducible.
	ReleaseHistorical = "historical"
)

// RepoView is a registration as the API shows it, with what was tracked.
type RepoView struct {
	Repo
	// State is "tracked" or "removed".
	State     string    `json:"state"`
	RemovedAt time.Time `json:"removedAt,omitzero"`
	// Tags counts the current tags; Releases the release manifests, and
	// FullyPinned how many of them are.
	Tags        int `json:"tags"`
	Releases    int `json:"releases"`
	FullyPinned int `json:"fullyPinned"`
	// LastSync, LastSuccess and LastError say how tracking goes.
	LastSync     time.Time `json:"lastSync,omitzero"`
	LastSuccess  time.Time `json:"lastSuccess,omitzero"`
	LastError    string    `json:"lastError,omitempty"`
	HistoryError string    `json:"historyError,omitempty"`
}

// TagView is a current tag with the state of the release it names.
type TagView struct {
	Tag       string    `json:"tag"`
	Commit    string    `json:"commit"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	// Release is the status of the commit's manifest ("not-pinned" when the
	// commit has none: a tag found at the first sync beyond the backfill).
	Release     string `json:"release"`
	FullyPinned bool   `json:"fullyPinned"`
}

// RepoDetail is one repository with its current tags.
type RepoDetail struct {
	RepoView
	CurrentTags []TagView `json:"currentTags"`
}

// ReleaseView is a release manifest with its place in the tag history.
type ReleaseView struct {
	Repo   string `json:"repo"`
	Tenant string `json:"tenant,omitempty"`
	Commit string `json:"commit"`
	// State is ReleaseCurrent or ReleaseHistorical.
	State string `json:"state"`
	// CurrentTags point at the commit now; FormerTags did once.
	CurrentTags []string     `json:"currentTags,omitempty"`
	FormerTags  []string     `json:"formerTags,omitempty"`
	Status      string       `json:"status"`
	FullyPinned bool         `json:"fullyPinned"`
	Reason      string       `json:"reason,omitempty"`
	Summary     Summary      `json:"summary"`
	CreatedAt   time.Time    `json:"createdAt"`
	UpdatedAt   time.Time    `json:"updatedAt"`
	Attempts    int          `json:"attempts"`
	NextAttempt time.Time    `json:"nextAttempt,omitzero"`
	Manifest    *Manifest    `json:"manifest,omitempty"`
	Matches     []Dependency `json:"matches,omitempty"`
}

// tagMap says, per commit, which tags point at it and which once did.
type tagMap struct {
	current map[string][]string
	former  map[string][]string
	tags    []TagAssociation
}

func (s *Service) tagsOf(ctx context.Context, name string) (*tagMap, *liveState, error) {
	live, err := s.liveSnapshot(ctx, name)
	if err != nil {
		return nil, nil, err
	}
	records, err := loadHistory(ctx, s.st, name)
	if err != nil && !errors.Is(err, ErrHistoryTampered) {
		return nil, nil, err
	}
	tm := &tagMap{current: map[string][]string{}, former: map[string][]string{}}
	tm.tags = associations(records, live, "")
	for _, a := range tm.tags {
		if a.State == AssocCurrent {
			tm.current[a.Commit] = appendUniqueString(tm.current[a.Commit], a.Tag)
		} else {
			tm.former[a.Commit] = appendUniqueString(tm.former[a.Commit], a.Tag)
		}
	}
	for c := range tm.former {
		// A tag that left the commit and came back is current, not former.
		var keep []string
		for _, t := range tm.former[c] {
			if !contains(tm.current[c], t) {
				keep = append(keep, t)
			}
		}
		sort.Strings(keep)
		tm.former[c] = keep
	}
	for c := range tm.current {
		sort.Strings(tm.current[c])
	}
	return tm, live, nil
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// List returns the registrations visible to tenant ("" sees all).
func (s *Service) List(ctx context.Context, tenant string) ([]RepoView, error) {
	s.mu.RLock()
	names := make([]string, 0, len(s.repos))
	for n, reg := range s.repos {
		if tenant == "" || reg.Tenant == tenant {
			names = append(names, n)
		}
	}
	s.mu.RUnlock()
	sort.Strings(names)
	out := make([]RepoView, 0, len(names))
	for _, n := range names {
		v, err := s.view(ctx, tenant, n)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Service) view(ctx context.Context, tenant, name string) (RepoView, error) {
	reg, ok := s.registration(tenant, name)
	if !ok {
		return RepoView{}, ErrNotFound
	}
	v := RepoView{Repo: reg.Repo, State: "tracked"}
	if reg.Removed {
		v.State, v.RemovedAt = "removed", reg.RemovedAt
	}
	live, err := s.liveSnapshot(ctx, name)
	if err != nil {
		return v, err
	}
	v.Tags = len(live.Tags)
	v.LastSync, v.LastSuccess, v.LastError, v.HistoryError = live.LastSync, live.LastSuccess, live.LastError, live.HistoryError
	for _, m := range s.manifestHeads(name) {
		v.Releases++
		if m.FullyPinned {
			v.FullyPinned++
		}
	}
	return v, nil
}

// Show returns a repository with its current tags.
func (s *Service) Show(ctx context.Context, tenant, name string) (*RepoDetail, error) {
	v, err := s.view(ctx, tenant, name)
	if err != nil {
		return nil, err
	}
	live, err := s.liveSnapshot(ctx, name)
	if err != nil {
		return nil, err
	}
	d := &RepoDetail{RepoView: v, CurrentTags: []TagView{}}
	tags := make([]string, 0, len(live.Tags))
	for t := range live.Tags {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	for _, t := range tags {
		lt := live.Tags[t]
		tv := TagView{Tag: t, Commit: lt.Commit, FirstSeen: lt.FirstSeen, LastSeen: lt.LastSeen, Release: "not-pinned"}
		s.mu.RLock()
		head, ok := s.summaries[manifestObject(name, lt.Commit)]
		s.mu.RUnlock()
		if ok {
			tv.Release, tv.FullyPinned = head.Status, head.FullyPinned
		}
		d.CurrentTags = append(d.CurrentTags, tv)
	}
	return d, nil
}

// TagHistory returns a repository's tag-to-commit associations, newest first:
// every commit a tag pointed at, current and historical. tag narrows it to
// one tag.
func (s *Service) TagHistory(ctx context.Context, tenant, name, tag string) ([]TagAssociation, error) {
	if _, ok := s.registration(tenant, name); !ok {
		return nil, ErrNotFound
	}
	live, err := s.liveSnapshot(ctx, name)
	if err != nil {
		return nil, err
	}
	records, err := loadHistory(ctx, s.st, name)
	if err != nil && !errors.Is(err, ErrHistoryTampered) {
		return nil, err
	}
	out := associations(records, live, tag)
	if out == nil {
		out = []TagAssociation{}
	}
	return out, err
}

// VerifyHistory checks a repository's history chain.
func (s *Service) VerifyHistory(ctx context.Context, tenant, name string) (int, error) {
	if _, ok := s.registration(tenant, name); !ok {
		return 0, ErrNotFound
	}
	records, err := loadHistory(ctx, s.st, name)
	if err == nil {
		err = checkSavedAnchor(ctx, s.st, name, records)
	}
	if err == nil {
		// The head this replica last saw anchors it too.
		s.mu.RLock()
		live := s.live[name]
		s.mu.RUnlock()
		if live != nil {
			l := live.snapshot()
			err = checkAnchor(name, records, l.HeadSeq, l.HeadHash)
		}
	}
	return len(records), err
}

// ReleaseQuery selects releases.
type ReleaseQuery struct {
	// Repo narrows to one repository; empty searches every repository the
	// tenant sees (a commit is then required).
	Repo string
	// Tag selects every commit the tag ever pointed at: the current one and
	// the historical ones.
	Tag string
	// Commit selects one commit (a prefix of at least 7 hex digits).
	Commit string
	// Full includes each release's manifest.
	Full bool
}

var commitPrefixRE = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// Releases returns the releases a query selects, newest first.
func (s *Service) Releases(ctx context.Context, tenant string, q ReleaseQuery) ([]ReleaseView, error) {
	q.Commit = strings.ToLower(strings.TrimSpace(q.Commit))
	if q.Commit != "" && !commitPrefixRE.MatchString(q.Commit) {
		return nil, &ValidationError{Err: errors.New("a commit is 7 to 64 hexadecimal digits")}
	}
	var repos []string
	if q.Repo != "" {
		if _, ok := s.registration(tenant, q.Repo); !ok {
			return nil, ErrNotFound
		}
		repos = []string{q.Repo}
	} else {
		if q.Commit == "" {
			return nil, &ValidationError{Err: errors.New("name a repository or a commit")}
		}
		s.mu.RLock()
		for n, reg := range s.repos {
			if tenant == "" || reg.Tenant == tenant {
				repos = append(repos, n)
			}
		}
		s.mu.RUnlock()
		sort.Strings(repos)
	}
	var out []ReleaseView
	for _, name := range repos {
		tm, _, err := s.tagsOf(ctx, name)
		if err != nil {
			return nil, err
		}
		var commits map[string]bool
		if q.Tag != "" {
			commits = map[string]bool{}
			for _, a := range tm.tags {
				if a.Tag == q.Tag {
					commits[a.Commit] = true
				}
			}
		}
		for _, head := range s.manifestHeads(name) {
			if q.Commit != "" && !strings.HasPrefix(head.Commit, q.Commit) {
				continue
			}
			if commits != nil && !commits[head.Commit] {
				continue
			}
			if tenant != "" && head.Tenant != tenant {
				continue
			}
			m := &head
			if q.Full {
				full, err := s.readManifest(ctx, head.Repo, head.Commit)
				if err != nil {
					continue
				}
				m = full
			}
			out = append(out, releaseView(m, tm, q.Full))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if out == nil {
		out = []ReleaseView{}
	}
	return out, nil
}

func releaseView(m *Manifest, tm *tagMap, full bool) ReleaseView {
	v := ReleaseView{
		Repo: m.Repo, Tenant: m.Tenant, Commit: m.Commit, Status: m.Status, FullyPinned: m.FullyPinned,
		Reason: m.Reason, Summary: m.Summary, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
		Attempts: m.Attempts, NextAttempt: m.NextAttempt,
		CurrentTags: tm.current[m.Commit], FormerTags: tm.former[m.Commit],
	}
	v.State = ReleaseHistorical
	if len(v.CurrentTags) > 0 {
		v.State = ReleaseCurrent
	}
	if full {
		v.Manifest = m
	}
	return v
}

// LookupQuery selects the releases containing a dependency or an object.
type LookupQuery struct {
	// Type, Name and Version name a dependency ("npm", "lodash", "4.17.21");
	// without a version every version of the package matches.
	Type    string
	Name    string
	Version string
	// Digest names an object or a lock-file digest ("sha256:…").
	Digest string
}

// ParseCoordinate reads "type/name@version" (or "type/name"). The name may
// itself contain "/" and "@" (npm scopes, Go modules).
func ParseCoordinate(s string) (LookupQuery, error) {
	s = strings.TrimSpace(s)
	t, rest, ok := strings.Cut(s, "/")
	if !ok || t == "" || rest == "" {
		return LookupQuery{}, errors.New(`a coordinate is "type/name@version" or "type/name"`)
	}
	q := LookupQuery{Type: lockfiles.CanonicalType(t), Name: rest}
	if i := strings.LastIndexByte(rest, '@'); i > 0 {
		q.Name, q.Version = rest[:i], rest[i+1:]
	}
	return q, nil
}

// Lookup returns the releases containing a coordinate or a digest, with the
// matching dependencies.
func (s *Service) Lookup(ctx context.Context, tenant string, q LookupQuery) ([]ReleaseView, error) {
	q.Digest = strings.TrimSpace(q.Digest)
	if q.Digest == "" && (q.Type == "" || q.Name == "") {
		return nil, &ValidationError{Err: errors.New("give a coordinate (type, name, optional version) or a digest")}
	}
	ids := s.idx.lookup(tenant, q.Type, q.Name, q.Version, q.Digest)
	maps := map[string]*tagMap{}
	out := []ReleaseView{}
	for _, id := range ids {
		repo, commit := splitManifestID(id)
		m, err := s.readManifest(ctx, repo, commit)
		if err != nil {
			continue
		}
		tm := maps[repo]
		if tm == nil {
			if tm, _, err = s.tagsOf(ctx, repo); err != nil {
				continue
			}
			maps[repo] = tm
		}
		v := releaseView(m, tm, false)
		for _, d := range m.Dependencies {
			if dependencyMatches(d, q) {
				v.Matches = append(v.Matches, d)
			}
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func dependencyMatches(d Dependency, q LookupQuery) bool {
	if q.Digest != "" {
		algo, v, _ := strings.Cut(q.Digest, ":")
		want := digestKey(algo, v)
		for _, dg := range d.LockDigests {
			if digestKey(dg.Algorithm, dg.Value) == want {
				return true
			}
		}
		for _, o := range d.Objects {
			if a, val, ok := strings.Cut(o.Digest, ":"); ok && digestKey(a, val) == want {
				return true
			}
		}
		return false
	}
	if lockfiles.CanonicalType(d.Type) != lockfiles.CanonicalType(q.Type) || !strings.EqualFold(d.Name, q.Name) {
		return false
	}
	return q.Version == "" || strings.EqualFold(d.Version, q.Version)
}

// Stats is a summary for metrics and the admin overview.
type Stats struct {
	Repositories  int   `json:"repositories"`
	PinnedObjects int   `json:"pinnedObjects"`
	PinnedBytes   int64 `json:"pinnedBytes"`
	Queued        int   `json:"queued"`
}

// Stats returns the service's summary.
func (s *Service) Stats() Stats {
	objects, bytes := s.idx.stats()
	s.qmu.Lock()
	queued := len(s.queued)
	s.qmu.Unlock()
	return Stats{Repositories: s.countTracked(), PinnedObjects: objects, PinnedBytes: bytes, Queued: queued}
}

// PinnedKeys returns every pinned cache key (air-gap exports carry them).
func (s *Service) PinnedKeys() []string { return s.idx.keys() }

// PinnedBy returns the releases ("repo/commit") pinning a cache key.
func (s *Service) PinnedBy(key string) []string { return s.idx.pinnedBy(key) }

// RawManifest is a stored manifest as it is kept, for export.
type RawManifest struct {
	Repo   string
	Commit string
	Data   []byte
}

// ExportManifests returns every stored release manifest, for an air-gap
// bundle, with the cache keys the manifests pin.
func (s *Service) ExportManifests(ctx context.Context) ([]RawManifest, []string, error) {
	names, err := s.st.List(ctx, "manifests/")
	if err != nil {
		return nil, nil, err
	}
	var out []RawManifest
	for _, n := range names {
		data, err := s.st.Get(ctx, n)
		if err != nil {
			return nil, nil, err
		}
		m, _, err := s.readManifestObject(ctx, n)
		if err != nil {
			continue
		}
		out = append(out, RawManifest{Repo: m.Repo, Commit: m.Commit, Data: data})
	}
	return out, s.idx.keys(), nil
}

// ImportManifest stores a release manifest an air-gap bundle carried, which
// pins its objects here too. A release this instance already has a manifest of
// is left as it is; imported reports whether the manifest was stored.
func (s *Service) ImportManifest(ctx context.Context, data []byte) (bool, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return false, fmt.Errorf("repos: not a release manifest: %w", err)
	}
	if !ValidName(m.Repo) || !validCommit(m.Commit) {
		return false, fmt.Errorf("repos: the manifest names no valid repository and commit")
	}
	unlock := s.locks.lock(manifestLock(m.Repo, m.Commit))
	if _, err := s.readManifest(ctx, m.Repo, m.Commit); err == nil {
		unlock()
		return false, nil
	} else if !errors.Is(err, ErrNotFound) {
		unlock()
		return false, err
	}
	m.settle()
	err := s.writeManifest(ctx, &m)
	unlock()
	if err != nil {
		return false, err
	}
	s.refreshPinMetrics()
	s.notifyRelease(ctx, m.Repo, m.Commit)
	return true, nil
}

// ReleaseObserver is told about a release whenever its manifest or the tags
// pointing at it change; the provenance graph keeps "shipped in release X"
// from it.
type ReleaseObserver interface {
	ObserveRelease(ctx context.Context, v ReleaseView)
}

// notifyRelease announces one release to the observer. It must not be called
// with a manifest lock held (it takes the repository's lock to read tags).
func (s *Service) notifyRelease(ctx context.Context, repo, commit string) {
	if s.opts.Observer == nil {
		return
	}
	m, err := s.readManifest(ctx, repo, commit)
	if err != nil {
		return
	}
	tm, _, err := s.tagsOf(ctx, repo)
	if err != nil {
		return
	}
	s.opts.Observer.ObserveRelease(ctx, releaseView(m, tm, true))
}

// replayReleases announces every stored release (the provenance graph is
// rebuilt in memory at each start).
func (s *Service) replayReleases(ctx context.Context) {
	if s.opts.Observer == nil {
		return
	}
	names, err := s.st.List(ctx, "manifests/")
	if err != nil {
		return
	}
	maps := map[string]*tagMap{}
	for _, n := range names {
		if ctx.Err() != nil {
			return
		}
		m, _, err := s.readManifestObject(ctx, n)
		if err != nil {
			continue
		}
		tm := maps[m.Repo]
		if tm == nil {
			if tm, _, err = s.tagsOf(ctx, m.Repo); err != nil {
				continue
			}
			maps[m.Repo] = tm
		}
		s.opts.Observer.ObserveRelease(ctx, releaseView(m, tm, true))
	}
}
