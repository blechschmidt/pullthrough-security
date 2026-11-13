package repos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
	"github.com/blechschmidt/pullthrough-security/internal/scan/watch"
)

// --- fakes ------------------------------------------------------------------

type fakeRefs struct {
	mu    sync.Mutex
	tags  map[string]map[string]Tip
	times map[string]time.Time
	kept  map[string]bool
	fail  error
	// calls counts Tags calls; gate, when set, holds each one until it is
	// closed (entered is told first).
	calls   int
	gate    chan struct{}
	entered chan struct{}
}

func newFakeRefs() *fakeRefs {
	return &fakeRefs{tags: map[string]map[string]Tip{}, times: map[string]time.Time{}, kept: map[string]bool{}}
}

func (f *fakeRefs) set(repo, tag, commit string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tags[repo] == nil {
		f.tags[repo] = map[string]Tip{}
	}
	f.tags[repo][tag] = Tip{Commit: commit}
}

func (f *fakeRefs) del(repo, tag string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.tags[repo], tag)
}

func (f *fakeRefs) Tags(_ context.Context, repo Repo, _ Credential) (map[string]Tip, error) {
	f.mu.Lock()
	f.calls++
	gate, entered := f.gate, f.entered
	f.mu.Unlock()
	if gate != nil {
		if entered != nil {
			entered <- struct{}{}
		}
		<-gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	out := map[string]Tip{}
	for k, v := range f.tags[repo.Name] {
		out[k] = v
	}
	return out, nil
}

func (f *fakeRefs) Keep(_ context.Context, _ Repo, commit string) error {
	f.mu.Lock()
	f.kept[commit] = true
	f.mu.Unlock()
	return nil
}

func (f *fakeRefs) CommitTime(_ context.Context, _ Repo, commit string) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.times[commit], nil
}

type fakeScanner struct {
	mu      sync.Mutex
	reports map[string][]lockfiles.Dependency // commit -> deps of package-lock.json
	fail    map[string]error
}

func (f *fakeScanner) Scan(_ context.Context, _ Repo, commit string, _ lockfiles.Options) (*lockfiles.Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail[commit]; err != nil {
		return nil, err
	}
	deps := f.reports[commit]
	return &lockfiles.Report{Commit: commit, Files: []*lockfiles.File{{
		Path: "package-lock.json", Type: "npm", Format: "package-lock.json", Dependencies: deps,
	}}}, nil
}

type fakeObject struct {
	body   []byte
	gate   string
	status int
}

// fakeFetcher plays the gateway: a map of objects by upstream+path; the cache
// key of an object is "<tenant>/<upstream><path>".
type fakeFetcher struct {
	mu      sync.Mutex
	objects map[string]fakeObject
	calls   []FetchRequest
}

func (f *fakeFetcher) put(upstream, path string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objects == nil {
		f.objects = map[string]fakeObject{}
	}
	f.objects[upstream+path] = fakeObject{body: body}
}

func (f *fakeFetcher) refuse(upstream, path, gate string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[upstream+path] = fakeObject{gate: gate}
}

func (f *fakeFetcher) Fetch(_ context.Context, req FetchRequest, body io.Writer) (FetchResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req)
	obj, ok := f.objects[req.Upstream+req.Path]
	f.mu.Unlock()
	switch {
	case !ok:
		return FetchResult{Status: 404, Reason: "not found"}, nil
	case obj.gate != "":
		return FetchResult{Status: 403, Gate: obj.gate, Code: "blocked", Reason: "denied by test",
			Verdicts: []GateVerdict{{Gate: obj.gate, Outcome: "refuse"}}}, nil
	}
	key := req.Tenant + "/" + req.Upstream + req.Path
	if req.Hold != nil {
		req.Hold(key)
	}
	sum := sha256.Sum256(obj.body)
	_, _ = body.Write(obj.body)
	return FetchResult{Status: 200, Cache: "MISS", CacheKey: key, Digest: "sha256:" + hex.EncodeToString(sum[:]),
		Size: int64(len(obj.body)), Verdicts: []GateVerdict{{Gate: "vulnscan", Outcome: "pass"}}}, nil
}

type fakeNotifier struct {
	mu     sync.Mutex
	events []notify.Event
}

func (n *fakeNotifier) Emit(_ context.Context, ev notify.Event) {
	n.mu.Lock()
	n.events = append(n.events, ev)
	n.mu.Unlock()
}

func (n *fakeNotifier) types() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for _, e := range n.events {
		out = append(out, string(e.Type)+":"+e.Fields["event"]+e.Fields["status"])
	}
	return out
}

// --- harness -------------------------------------------------------------------

const (
	commitA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	commitB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	commitC = "cccccccccccccccccccccccccccccccccccccccc"
)

type harness struct {
	t       *testing.T
	svc     *Service
	store   Store
	refs    *fakeRefs
	scanner *fakeScanner
	fetcher *fakeFetcher
	sink    *audit.MemorySink
	notes   *fakeNotifier
	repos   []Repo
	nowMu   sync.Mutex
	now     time.Time
}

func npmDep(name, version string, body []byte) lockfiles.Dependency {
	sum := sha512.Sum512(body)
	return lockfiles.Dependency{Type: "npm", Name: name, Version: version, Registry: "https://registry.npmjs.org",
		Digests: []lockfiles.Digest{{Algorithm: "sha512", Value: hex.EncodeToString(sum[:])}}, File: "package-lock.json", Line: 7}
}

func tarball(name, version string) []byte { return []byte("tarball of " + name + "@" + version) }

func newHarness(t *testing.T, store Store, repos ...Repo) *harness {
	t.Helper()
	h := &harness{t: t, store: store, refs: newFakeRefs(), scanner: &fakeScanner{reports: map[string][]lockfiles.Dependency{}, fail: map[string]error{}},
		fetcher: &fakeFetcher{objects: map[string]fakeObject{}}, sink: audit.NewMemorySink(), notes: &fakeNotifier{},
		now: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)}
	h.start(repos...)
	return h
}

func (h *harness) clock() time.Time {
	h.nowMu.Lock()
	defer h.nowMu.Unlock()
	h.now = h.now.Add(time.Second)
	return h.now
}

func (h *harness) start(repos ...Repo) {
	t := h.t
	h.repos = repos
	logger, err := audit.NewLogger(context.Background(), audit.Options{Key: []byte("k"), Sink: h.sink})
	if err != nil {
		t.Fatal(err)
	}
	all := -1
	svc, err := New(context.Background(), Config{
		Repos: repos, AllowedSchemes: []string{"https", "file"}, BackfillTags: &all, RetryInterval: time.Hour,
	}, Options{
		Store: h.store, Refs: h.refs, Scanner: h.scanner, Fetcher: h.fetcher, Audit: logger, Notify: h.notes,
		Upstreams: []locate.Upstream{
			{Name: "npm", Type: "npm", URLs: []string{"https://registry.npmjs.org"}},
			{Name: "central", Type: "maven", URLs: []string{"https://repo.maven.apache.org/maven2"}},
		},
		Now: func() time.Time { return h.clock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
}

// restart opens a second service over the same store and fakes, with the
// registrations the first one was started with.
func (h *harness) restart(repos ...Repo) *harness {
	h.t.Helper()
	if len(repos) == 0 {
		repos = h.repos
	}
	h.nowMu.Lock()
	now := h.now
	h.nowMu.Unlock()
	h2 := &harness{t: h.t, store: h.store, refs: h.refs, scanner: h.scanner, fetcher: h.fetcher, sink: audit.NewMemorySink(), notes: &fakeNotifier{}, now: now}
	h2.start(repos...)
	return h2
}

// sync syncs and pins synchronously (the service is not started: the queue is
// drained here, in the test's goroutine).
func (h *harness) sync(name string) SyncResult {
	h.t.Helper()
	res, err := h.svc.Sync(context.Background(), name, "manual")
	if err != nil {
		h.t.Fatalf("sync %s: %v", name, err)
	}
	h.drain()
	return res
}

func (h *harness) drain() {
	h.t.Helper()
	for {
		select {
		case j := <-h.svc.queue:
			if err := h.svc.Pin(context.Background(), j.repo, j.commit); err != nil {
				h.t.Fatalf("pin %s: %v", j.key(), err)
			}
			h.svc.dequeued(j)
		default:
			return
		}
	}
}

func (h *harness) release(name, commit string) *Manifest {
	h.t.Helper()
	m, err := h.svc.readManifest(context.Background(), name, commit)
	if err != nil {
		h.t.Fatalf("manifest %s@%s: %v", name, commit, err)
	}
	return m
}

func (h *harness) auditTypes() map[string]int {
	out := map[string]int{}
	for _, r := range h.sink.Records() {
		out[string(r.Event.Type)+":"+fmtDetail(r.Event.Detail["event"])]++
	}
	return out
}

func fmtDetail(v any) string {
	s, _ := v.(string)
	return s
}

var widgets = Repo{Name: "widgets", URL: "https://git.example/acme/widgets.git", Tenant: "team-a"}

func (h *harness) commitDeps(commit string, deps ...lockfiles.Dependency) {
	h.scanner.mu.Lock()
	h.scanner.reports[commit] = deps
	h.scanner.mu.Unlock()
}

func (h *harness) publish(name, version string) lockfiles.Dependency {
	body := tarball(name, version)
	h.fetcher.put("npm", "/"+name+"/-/"+name+"-"+version+".tgz", body)
	return npmDep(name, version, body)
}

// --- tests -------------------------------------------------------------------

// The acceptance scenario of Task 180 at unit level: a tag is created and
// pinned, force-moved to another commit and pinned again; both commits keep
// their manifests and their pins, the history keeps both associations and
// never rewrites the first, and the API shows the old commit as historical.
func TestMovedTagKeepsBothReleasesPinned(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	h.commitDeps(commitA, h.publish("left-pad", "1.0.0"), h.publish("is-odd", "2.0.0"))
	h.commitDeps(commitB, h.publish("left-pad", "1.1.0"), h.publish("is-odd", "2.0.0"))

	h.refs.set("widgets", "v1.0", commitA)
	res := h.sync("widgets")
	if res.Created != 1 || res.Queued != 1 {
		t.Fatalf("first sync: %+v", res)
	}
	a := h.release("widgets", commitA)
	if a.Status != ReleasePinned || !a.FullyPinned || a.Summary.Pinned != 2 || a.Summary.PinnedObjects != 2 {
		t.Fatalf("release A: %s %s %+v", a.Status, a.Reason, a.Summary)
	}
	for _, d := range a.Dependencies {
		o := d.Objects[0]
		if o.Check == nil || o.Check.Status != locate.CheckVerified || len(o.Verdicts) == 0 || o.CacheKey == "" {
			t.Fatalf("object of %s: %+v", d.Coordinate(), o)
		}
	}
	firstRecord, _ := h.store.Get(context.Background(), historyObject("widgets", 1))

	// Force-move the tag.
	h.refs.set("widgets", "v1.0", commitB)
	res = h.sync("widgets")
	if res.Moved != 1 || res.Queued != 1 {
		t.Fatalf("moving sync: %+v", res)
	}
	b := h.release("widgets", commitB)
	if !b.FullyPinned {
		t.Fatalf("release B: %s %s", b.Status, b.Reason)
	}
	// Both releases' objects stay pinned.
	for _, m := range []*Manifest{a, b} {
		for _, o := range m.pinnedObjects() {
			if !h.svc.IsPinned(o.CacheKey) {
				t.Fatalf("%s of %s is not pinned", o.CacheKey, m.Commit)
			}
		}
	}
	// The first record is untouched; the move is a new record superseding it.
	again, _ := h.store.Get(context.Background(), historyObject("widgets", 1))
	if !bytes.Equal(firstRecord, again) {
		t.Fatal("the first history record was rewritten")
	}
	assoc, err := h.svc.TagHistory(context.Background(), "", "widgets", "v1.0")
	if err != nil || len(assoc) != 2 {
		t.Fatalf("history: %v %+v", err, assoc)
	}
	if assoc[0].Commit != commitB || assoc[0].State != AssocCurrent ||
		assoc[1].Commit != commitA || assoc[1].State != AssocMoved || assoc[1].SupersededBy != assoc[0].Seq || assoc[1].NextCommit != commitB {
		t.Fatalf("associations: %+v", assoc)
	}
	// The API: B current, A historical, both pinned.
	rel, err := h.svc.Releases(context.Background(), "", ReleaseQuery{Repo: "widgets", Tag: "v1.0"})
	if err != nil || len(rel) != 2 {
		t.Fatalf("releases: %v %+v", err, rel)
	}
	states := map[string]string{}
	for _, r := range rel {
		states[r.Commit] = r.State
		if !r.FullyPinned {
			t.Errorf("%s is not fully pinned", r.Commit)
		}
	}
	if states[commitA] != ReleaseHistorical || states[commitB] != ReleaseCurrent {
		t.Fatalf("states: %v", states)
	}
	// Audit events for created and moved; a notification for the move.
	at := h.auditTypes()
	if at["release_tag:created"] != 1 || at["release_tag:moved"] != 1 {
		t.Fatalf("audit: %v", at)
	}
	if !strings.Contains(strings.Join(h.notes.types(), " "), "release_tag:moved") {
		t.Fatalf("notifications: %v", h.notes.types())
	}
	// The mirror keeps both commits.
	if !h.refs.kept[commitA] || !h.refs.kept[commitB] {
		t.Fatalf("kept: %v", h.refs.kept)
	}
}

func TestDeletedTagAddsARecordAndKeepsThePins(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	h.commitDeps(commitA, h.publish("left-pad", "1.0.0"))
	h.refs.set("widgets", "v1.0", commitA)
	h.sync("widgets")
	key := h.release("widgets", commitA).pinnedObjects()[0].CacheKey

	h.refs.del("widgets", "v1.0")
	if res := h.sync("widgets"); res.Deleted != 1 {
		t.Fatalf("delete: %+v", res)
	}
	if !h.svc.IsPinned(key) {
		t.Fatal("a deleted tag's release lost its pin")
	}
	assoc, _ := h.svc.TagHistory(context.Background(), "", "widgets", "")
	if len(assoc) != 1 || assoc[0].State != AssocDeleted {
		t.Fatalf("history: %+v", assoc)
	}
	// Re-created at the same commit: a new association, not a revival.
	h.refs.set("widgets", "v1.0", commitA)
	if res := h.sync("widgets"); res.Created != 1 {
		t.Fatalf("re-create: %+v", res)
	}
	assoc, _ = h.svc.TagHistory(context.Background(), "", "widgets", "")
	if len(assoc) != 2 || assoc[0].State != AssocCurrent {
		t.Fatalf("history: %+v", assoc)
	}
	if n, err := h.svc.VerifyHistory(context.Background(), "", "widgets"); err != nil || n != 3 {
		t.Fatalf("verify: %d %v", n, err)
	}
	if h.auditTypes()["release_tag:deleted"] != 1 {
		t.Fatalf("audit: %v", h.auditTypes())
	}
}

// What is refused, mismatched or cannot be fetched is recorded with the
// reason, and the release is then not fully pinned.
func TestRefusedAndUnfetchableDependenciesAreRecorded(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	good := h.publish("left-pad", "1.0.0")
	refused := h.publish("evil", "6.6.6")
	h.fetcher.refuse("npm", "/evil/-/evil-6.6.6.tgz", "malfeed")
	tampered := h.publish("tampered", "1.0.0")
	tampered.Digests[0].Value = strings.Repeat("0", 128)
	missing := npmDep("missing", "1.0.0", []byte("x"))
	unsupported := lockfiles.Dependency{Type: "composer", Name: "monolog/monolog", Version: "3.7.0", Unverified: true}
	otherRegistry := npmDep("private", "1.0.0", []byte("y"))
	otherRegistry.Registry = "https://npm.evil.example"
	h.commitDeps(commitA, good, refused, tampered, missing, unsupported, otherRegistry)
	h.refs.set("widgets", "v2.0", commitA)
	h.sync("widgets")

	m := h.release("widgets", commitA)
	if m.Status != ReleasePartial || m.FullyPinned || m.Reason == "" {
		t.Fatalf("status %s %q", m.Status, m.Reason)
	}
	by := map[string]Dependency{}
	for _, d := range m.Dependencies {
		by[d.Name] = d
	}
	if d := by["evil"]; d.Status != StatusRefused || d.Objects[0].Gate != "malfeed" || !strings.Contains(d.Reason, "malfeed") {
		t.Fatalf("refused: %+v", d)
	}
	if d := by["tampered"]; d.Status != StatusMismatch || h.svc.IsPinned(d.Objects[0].CacheKey) {
		t.Fatalf("a mismatch must not stay pinned: %+v", d)
	}
	if d := by["missing"]; d.Status != StatusFailed || !strings.Contains(d.Reason, "not found") {
		t.Fatalf("missing: %+v", d)
	}
	if d := by["monolog/monolog"]; d.Status != StatusUnsupported || d.Reason == "" {
		t.Fatalf("unsupported: %+v", d)
	}
	if d := by["private"]; d.Status != StatusUnsupported || !strings.Contains(d.Reason, "npm.evil.example") {
		t.Fatalf("another registry: %+v", d)
	}
	if d := by["left-pad"]; d.Status != StatusPinned || !h.svc.IsPinned(d.Objects[0].CacheKey) {
		t.Fatalf("good: %+v", d)
	}
	s := m.Summary
	if s.Pinned != 1 || s.Refused != 1 || s.Mismatched != 1 || s.Failed != 1 || s.Unsupported != 2 {
		t.Fatalf("summary: %+v", s)
	}
	if m.NextAttempt.IsZero() {
		t.Fatal("a partial release is retried")
	}
	// The job's holds are gone once the manifest is stored: only what it pins
	// stays pinned.
	if len(h.svc.idx.held) != 0 {
		t.Fatalf("holds leaked: %v", h.svc.idx.held)
	}

	// Retry: the refusal was lifted. The pinned dependency is not fetched
	// again; the refused one is.
	h.fetcher.put("npm", "/evil/-/evil-6.6.6.tgz", tarball("evil", "6.6.6"))
	calls := len(h.fetcher.calls)
	if err := h.svc.Pin(context.Background(), "widgets", commitA); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.fetcher.calls[calls:] {
		if strings.Contains(c.Path, "left-pad") {
			t.Fatal("a pinned dependency was fetched again")
		}
	}
	m = h.release("widgets", commitA)
	if m.Attempts != 2 || m.Summary.Refused != 0 || m.Summary.Pinned != 2 {
		t.Fatalf("retry: %d %+v", m.Attempts, m.Summary)
	}
	if !strings.Contains(strings.Join(h.notes.types(), " "), "release_pin:digest-mismatch") {
		t.Fatalf("a digest mismatch must alert: %v", h.notes.types())
	}
}

func TestLockfilesUnreadableFailTheRelease(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	h.scanner.fail[commitA] = errors.New("object not found")
	h.refs.set("widgets", "v1", commitA)
	h.sync("widgets")
	m := h.release("widgets", commitA)
	if m.Status != ReleaseFailed || !strings.Contains(m.Reason, "object not found") {
		t.Fatalf("%s %q", m.Status, m.Reason)
	}
}

// Restart persistence: a new service over the same state directory has the
// same history, releases and pins — and keeps tracking where it stopped.
func TestStatePersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDirStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, store, widgets)
	h.commitDeps(commitA, h.publish("left-pad", "1.0.0"))
	h.commitDeps(commitB, h.publish("left-pad", "1.1.0"))
	h.refs.set("widgets", "v1", commitA)
	h.sync("widgets")
	h.refs.set("widgets", "v1", commitB)
	h.sync("widgets")
	keys := append(h.release("widgets", commitA).pinnedObjects(), h.release("widgets", commitB).pinnedObjects()...)

	// "Restart": a fresh store and service over the directory.
	store2, err := NewDirStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2 := &harness{t: t, store: store2, refs: h.refs, scanner: h.scanner, fetcher: h.fetcher, sink: audit.NewMemorySink(), notes: &fakeNotifier{}, now: h.now}
	h2.start(widgets)
	for _, o := range keys {
		if !h2.svc.IsPinned(o.CacheKey) {
			t.Fatalf("%s lost its pin across the restart", o.CacheKey)
		}
	}
	assoc, err := h2.svc.TagHistory(context.Background(), "", "widgets", "v1")
	if err != nil || len(assoc) != 2 {
		t.Fatalf("history after restart: %v %+v", err, assoc)
	}
	// No change: a sync after the restart writes nothing.
	if res := h2.sync("widgets"); res.Created+res.Moved+res.Deleted != 0 {
		t.Fatalf("a restart must not re-record tags: %+v", res)
	}
	// And picks up a change made while it was down.
	h.refs.del("widgets", "v1")
	if res := h2.sync("widgets"); res.Deleted != 1 {
		t.Fatalf("delete after restart: %+v", res)
	}
	if n, err := h2.svc.VerifyHistory(context.Background(), "", "widgets"); err != nil || n != 3 {
		t.Fatalf("verify: %d %v", n, err)
	}
}

// Tenant isolation: each tenant sees its own repositories, releases and
// reverse lookups, and its dependencies are fetched as itself.
func TestTenantIsolation(t *testing.T) {
	gadgets := Repo{Name: "gadgets", URL: "https://git.example/other/gadgets.git", Tenant: "team-b"}
	h := newHarness(t, NewMemoryStore(), widgets, gadgets)
	h.commitDeps(commitA, h.publish("left-pad", "1.0.0"))
	h.commitDeps(commitC, h.publish("left-pad", "1.0.0"))
	h.refs.set("widgets", "v1", commitA)
	h.refs.set("gadgets", "v9", commitC)
	h.sync("widgets")
	h.sync("gadgets")

	ctx := context.Background()
	list, _ := h.svc.List(ctx, "team-a")
	if len(list) != 1 || list[0].Name != "widgets" {
		t.Fatalf("team-a sees %+v", list)
	}
	if _, err := h.svc.Show(ctx, "team-a", "gadgets"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("team-a sees gadgets: %v", err)
	}
	if _, err := h.svc.Releases(ctx, "team-b", ReleaseQuery{Repo: "widgets"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("team-b sees widgets' releases: %v", err)
	}
	if _, err := h.svc.TagHistory(ctx, "team-b", "widgets", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("team-b sees widgets' tags: %v", err)
	}
	// The same coordinate is in both tenants' releases; each sees only its own.
	for tenant, want := range map[string]string{"team-a": "widgets", "team-b": "gadgets"} {
		hits, err := h.svc.Lookup(ctx, tenant, LookupQuery{Type: "npm", Name: "left-pad", Version: "1.0.0"})
		if err != nil || len(hits) != 1 || hits[0].Repo != want {
			t.Fatalf("%s lookup: %v %+v", tenant, err, hits)
		}
	}
	all, _ := h.svc.Lookup(ctx, "", LookupQuery{Type: "npm", Name: "left-pad"})
	if len(all) != 2 {
		t.Fatalf("an unscoped lookup sees both: %+v", all)
	}
	// By commit across repositories: scoped too.
	if rel, _ := h.svc.Releases(ctx, "team-a", ReleaseQuery{Commit: commitC[:10]}); len(rel) != 0 {
		t.Fatalf("team-a sees team-b's commit: %+v", rel)
	}
	// Each tenant's dependencies were fetched as that tenant.
	for _, c := range h.fetcher.calls {
		if c.Tenant != "team-a" && c.Tenant != "team-b" {
			t.Fatalf("fetched as %q", c.Tenant)
		}
	}
	keyA := h.release("widgets", commitA).pinnedObjects()[0].CacheKey
	keyB := h.release("gadgets", commitC).pinnedObjects()[0].CacheKey
	if keyA == keyB || !strings.HasPrefix(keyA, "team-a/") || !strings.HasPrefix(keyB, "team-b/") {
		t.Fatalf("tenants share cache keys: %s %s", keyA, keyB)
	}
}

func TestBackfillPinsTheNewestTagsOnly(t *testing.T) {
	store := NewMemoryStore()
	two := 2
	repo := widgets
	repo.BackfillTags = &two
	h := newHarness(t, store, repo)
	for i, c := range []string{commitA, commitB, commitC} {
		h.commitDeps(c, h.publish("left-pad", "1.0.0"))
		h.refs.times[c] = time.Date(2026, 1, i+1, 0, 0, 0, 0, time.UTC)
	}
	h.refs.set("widgets", "v1", commitA)
	h.refs.set("widgets", "v2", commitB)
	h.refs.set("widgets", "v3", commitC)
	res := h.sync("widgets")
	if res.Created != 3 || res.Queued != 2 || !res.Initial {
		t.Fatalf("%+v", res)
	}
	if _, err := h.svc.readManifest(context.Background(), "widgets", commitA); !errors.Is(err, ErrNotFound) {
		t.Fatal("the oldest tag was pinned beyond the backfill")
	}
	// Pinned on request.
	if err := h.svc.Repin(context.Background(), "", "widgets", commitA); err != nil {
		t.Fatal(err)
	}
	h.drain()
	if !h.release("widgets", commitA).FullyPinned {
		t.Fatal("repin")
	}
	// A later tag is pinned whatever the backfill.
	h.refs.set("widgets", "v4", commitA)
	if res := h.sync("widgets"); res.Created != 1 || res.Initial {
		t.Fatalf("%+v", res)
	}
	if err := h.svc.Repin(context.Background(), "", "widgets", strings.Repeat("d", 40)); err == nil {
		t.Fatal("a commit no tag named cannot be pinned")
	}
}

// A history whose records were altered is detected, and nothing is appended
// to it.
func TestTamperedHistoryIsDetected(t *testing.T) {
	store := NewMemoryStore()
	h := newHarness(t, store, widgets)
	h.commitDeps(commitA, h.publish("left-pad", "1.0.0"))
	h.refs.set("widgets", "v1", commitA)
	h.sync("widgets")

	data, _ := store.Get(context.Background(), historyObject("widgets", 1))
	var r TagRecord
	_ = json.Unmarshal(data, &r)
	r.Commit = commitC // point the tag elsewhere after the fact
	forged, _ := json.Marshal(r)
	_ = store.Put(context.Background(), historyObject("widgets", 1), forged)

	h2 := &harness{t: t, store: store, refs: h.refs, scanner: h.scanner, fetcher: h.fetcher, sink: audit.NewMemorySink(), notes: &fakeNotifier{}, now: h.now}
	h2.start(widgets)
	if _, err := h2.svc.VerifyHistory(context.Background(), "", "widgets"); !errors.Is(err, ErrHistoryTampered) {
		t.Fatalf("verify: %v", err)
	}
	h.refs.set("widgets", "v2", commitA)
	if _, err := h2.svc.Sync(context.Background(), "widgets", "manual"); err == nil {
		t.Fatal("a sync appended to a history that does not verify")
	}
	if names, _ := store.List(context.Background(), historyPrefix("widgets")); len(names) != 1 {
		t.Fatalf("records: %v", names)
	}
}

// The history's chain verifies on its own even with its last records removed,
// or rewritten and re-hashed; the head the tracker saw before tells.
func TestHistoryHeadIsAnchored(t *testing.T) {
	ctx := context.Background()
	build := func() (*harness, Store) {
		store := NewMemoryStore()
		h := newHarness(t, store, widgets)
		h.commitDeps(commitA, h.publish("left-pad", "1.0.0"))
		h.refs.set("widgets", "v1", commitA)
		h.sync("widgets")
		h.refs.set("widgets", "v2", commitA)
		h.sync("widgets")
		return h, store
	}

	// The last record removed.
	h, store := build()
	if err := store.Delete(ctx, historyObject("widgets", 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.VerifyHistory(ctx, "", "widgets"); !errors.Is(err, ErrHistoryTampered) {
		t.Fatalf("a truncated history verifies on the running replica: %v", err)
	}
	again := h.restart()
	if _, err := again.svc.VerifyHistory(ctx, "", "widgets"); !errors.Is(err, ErrHistoryTampered) {
		t.Fatalf("a truncated history verifies after a restart: %v", err)
	}
	if _, err := again.svc.Sync(ctx, "widgets", "manual"); err == nil {
		t.Fatal("a sync appended to a truncated history")
	}

	// The last record rewritten, its hash recomputed.
	h, store = build()
	data, _ := store.Get(ctx, historyObject("widgets", 2))
	var r TagRecord
	_ = json.Unmarshal(data, &r)
	r.Commit = commitC
	r.Hash = hashRecord(r)
	forged, _ := json.Marshal(r)
	_ = store.Put(ctx, historyObject("widgets", 2), forged)
	if _, err := h.restart().svc.VerifyHistory(ctx, "", "widgets"); !errors.Is(err, ErrHistoryTampered) {
		t.Fatalf("a rewritten head verifies: %v", err)
	}

	// Without a saved state (a restore from a backup) there is no anchor:
	// the history is taken as it is.
	h, store = build()
	_ = store.Delete(ctx, liveObject("widgets"))
	if n, err := h.restart().svc.VerifyHistory(ctx, "", "widgets"); err != nil || n != 2 {
		t.Fatalf("history without a saved state: %d %v", n, err)
	}
}

// Replicas share the registry's state: what one registers, removes or syncs,
// the others follow; only the leader pins.
func TestReplicasShareTheRegistry(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	leader := newHarness(t, store, widgets)
	follower := leader.restart()
	follower.svc.SetLeaderGate(func() bool { return false })
	leader.commitDeps(commitA, leader.publish("left-pad", "1.0.0"))

	// A registration through the follower's API is tracked by the leader
	// once it re-reads the shared state; a removal likewise.
	tools := Repo{Name: "tools", URL: "https://git.example/acme/tools.git", Tenant: "team-a"}
	if _, err := follower.svc.Add(ctx, tools, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := leader.svc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := leader.svc.registration("", "tools"); !ok {
		t.Fatal("the leader does not track a registration made through another replica")
	}
	if err := follower.svc.Remove(ctx, "", "tools", "alice"); err != nil {
		t.Fatal(err)
	}
	_ = leader.svc.Refresh(ctx)
	if reg, _ := leader.svc.registration("", "tools"); reg == nil || !reg.Removed {
		t.Fatalf("the leader still tracks a registration removed through another replica: %+v", reg)
	}

	// A sync through the follower records the tag; the leader's next sync
	// catches up instead of recording it again (or failing).
	leader.refs.set("widgets", "v1", commitA)
	if _, err := follower.svc.Sync(ctx, "widgets", "manual"); err != nil {
		t.Fatal(err)
	}
	if res, err := leader.svc.Sync(ctx, "widgets", "poll"); err != nil || res.Created+res.Moved+res.Deleted != 0 {
		t.Fatalf("the leader's sync after the follower's: %+v %v", res, err)
	}
	if n, err := leader.svc.VerifyHistory(ctx, "", "widgets"); err != nil || n != 1 {
		t.Fatalf("history: %d %v", n, err)
	}

	// The follower does not pin: its worker leaves the release to the
	// leader, whose sweep finds it pending in the shared state.
	follower.svc.Start(ctx)
	for len(follower.svc.queue) > 0 {
		time.Sleep(time.Millisecond)
	}
	_ = follower.svc.Close()
	leader.fetcher.mu.Lock()
	calls := len(leader.fetcher.calls)
	leader.fetcher.mu.Unlock()
	if calls != 0 {
		t.Fatalf("the follower fetched %d dependencies", calls)
	}
	if m := leader.release("widgets", commitA); m.Status != ReleasePending {
		t.Fatalf("release left by the follower: %s", m.Status)
	}
	_ = leader.svc.Refresh(ctx)
	leader.svc.sweepPending(ctx)
	leader.drain()
	if m := leader.release("widgets", commitA); m.Status != ReleasePinned || !leader.svc.IsPinned(m.pinnedObjects()[0].CacheKey) {
		t.Fatalf("release pinned by the leader: %s", m.Status)
	}
	// And the follower's pin set follows once it re-reads the manifests.
	if err := follower.svc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if key := leader.release("widgets", commitA).pinnedObjects()[0].CacheKey; !follower.svc.IsPinned(key) {
		t.Fatal("the follower does not enforce the leader's pins")
	}
}

// countingStore counts the manifests read from a DirStore.
type countingStore struct {
	*DirStore
	mu    sync.Mutex
	reads int
}

func (c *countingStore) Get(ctx context.Context, name string) ([]byte, error) {
	if strings.HasPrefix(name, "manifests/") {
		c.mu.Lock()
		c.reads++
		c.mu.Unlock()
	}
	return c.DirStore.Get(ctx, name)
}

func (c *countingStore) manifestReads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// A replica re-reading the shared state every minute reads only the
// manifests that changed since it last did.
func TestRefreshReadsOnlyChangedManifests(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ds, err := NewDirStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	writer := newHarness(t, ds, widgets)
	writer.commitDeps(commitA, writer.publish("left-pad", "1.0.0"))
	writer.commitDeps(commitB, writer.publish("is-odd", "1.0.0"))
	writer.refs.set("widgets", "v1", commitA)
	writer.refs.set("widgets", "v2", commitB)
	writer.sync("widgets")

	ds2, err := NewDirStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cs := &countingStore{DirStore: ds2}
	reader := &harness{t: t, store: cs, refs: writer.refs, scanner: writer.scanner, fetcher: writer.fetcher, sink: audit.NewMemorySink(), notes: &fakeNotifier{}, now: writer.now}
	reader.start(widgets)
	if err := reader.svc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	first := cs.manifestReads()
	if err := reader.svc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if n := cs.manifestReads() - first; n != 0 {
		t.Fatalf("an unchanged state cost %d manifest reads", n)
	}
	// One release changes: one read, and its new state is seen.
	if err := writer.svc.Repin(ctx, "", "widgets", commitA); err != nil {
		t.Fatal(err)
	}
	before := cs.manifestReads()
	if err := reader.svc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if n := cs.manifestReads() - before; n != 1 {
		t.Fatalf("one changed manifest cost %d reads", n)
	}
	reader.svc.mu.RLock()
	head := reader.svc.summaries[manifestObject("widgets", commitA)]
	reader.svc.mu.RUnlock()
	if head.Attempts != 1 || !head.NextAttempt.IsZero() {
		t.Fatalf("the reader did not see the change: %+v", head)
	}
}

func TestStaleMirrorIsNotReadAsDeletion(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	h.commitDeps(commitA, h.publish("left-pad", "1.0.0"))
	h.refs.set("widgets", "v1", commitA)
	h.sync("widgets")
	h.refs.fail = errors.Join(ErrStale, errors.New("network down"))
	if _, err := h.svc.Sync(context.Background(), "widgets", "poll"); err == nil {
		t.Fatal("a failed fetch must be an error")
	}
	if names, _ := h.store.List(context.Background(), historyPrefix("widgets")); len(names) != 1 {
		t.Fatalf("a stale mirror wrote records: %v", names)
	}
	v, _ := h.svc.Show(context.Background(), "", "widgets")
	if v.LastError == "" || len(v.CurrentTags) != 1 {
		t.Fatalf("show: %+v", v)
	}
}

func TestRegistrationRules(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	ctx := context.Background()
	bad := []Repo{
		{Name: "Upper", URL: "https://x/y.git"},
		{Name: "x", URL: "ext::sh -c id"},
		{Name: "x", URL: "--upload-pack=touch /tmp/pwned"},
		{Name: "x", URL: "https://user:pass@git.example/x.git"},
		{Name: "x", URL: "http://git.example/x.git"},
		{Name: "x", URL: "https://git.example/x.git", CredentialsRef: "ghp_plaintexttoken"},
		{Name: "x", URL: "https://git.example/x.git", CredentialsRef: "literal://ghp_plaintext"},
		{Name: "x", URL: "git@git.example:x.git", CredentialsRef: "env://TOKEN"},
		{Name: "x", URL: "https://git.example/x.git", Lockfiles: []string{"a/**b/c"}},
		{Name: "x", URL: "https://git.example/x.git", Tags: []string{"[v"}},
	}
	for _, r := range bad {
		if _, err := h.svc.Add(ctx, r, "test"); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	good := Repo{Name: "tools", URL: "https://git.example/tools.git", CredentialsRef: "env://TOOLS_TOKEN", Tenant: "team-a", Lockfiles: []string{"**/go.*"}}
	if _, err := h.svc.Add(ctx, good, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Add(ctx, good, "alice"); err == nil {
		t.Fatal("registered twice")
	}
	if _, err := h.svc.Add(ctx, Repo{Name: "widgets", URL: "https://x/y.git"}, "alice"); err == nil {
		t.Fatal("an API registration replaced a configured one")
	}
	if err := h.svc.Remove(ctx, "", "widgets", "alice"); err == nil {
		t.Fatal("removed a configured repository")
	}
	if err := h.svc.Remove(ctx, "team-b", "tools", "mallory"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant removed it: %v", err)
	}
	if err := h.svc.Remove(ctx, "", "tools", "alice"); err != nil {
		t.Fatal(err)
	}
	// A removed registration's name is not reusable for another URL.
	if _, err := h.svc.Add(ctx, Repo{Name: "tools", URL: "https://git.example/other.git", Tenant: "team-a"}, "alice"); err == nil {
		t.Fatal("reused a removed name for another URL")
	}
	if _, err := h.svc.Add(ctx, good, "alice"); err != nil {
		t.Fatalf("restoring a removed registration: %v", err)
	}
	at := h.auditTypes()
	if at["repository:"] != 3 {
		t.Fatalf("registration audit: %v", at)
	}
}

// A repository dropped from the configuration keeps its name bound to its
// tenant and URL: another tenant cannot register the name and read the
// history and releases left under it.
func TestConfiguredNameStaysReserved(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	ctx := context.Background()
	h.commitDeps(commitA, h.publish("left-pad", "1.0.0"))
	h.refs.set("widgets", "v1", commitA)
	h.sync("widgets")

	dropped := h.restart(Repo{Name: "gadgets", URL: "https://git.example/acme/gadgets.git", Tenant: "team-b"})
	list, err := dropped.svc.List(ctx, "team-a")
	if err != nil || len(list) != 1 || list[0].Name != "widgets" || list[0].State != "removed" {
		t.Fatalf("team-a's list after the repository left the configuration: %v %+v", err, list)
	}
	for _, r := range []Repo{
		{Name: "widgets", URL: widgets.URL, Tenant: "team-b"},
		{Name: "widgets", URL: "https://git.example/mallory/widgets.git", Tenant: "team-a"},
	} {
		var conflict *ConflictError
		if _, err := dropped.svc.Add(ctx, r, "mallory"); !errors.As(err, &conflict) {
			t.Fatalf("registered %+v over the dropped configured repository: %v", r, err)
		}
	}
	if _, err := dropped.svc.TagHistory(ctx, "team-b", "widgets", "v1"); err == nil {
		t.Fatal("team-b reads team-a's tag history")
	}
	// Its own tenant may take it over through the API, history and all.
	if _, err := dropped.svc.Add(ctx, Repo{Name: "widgets", URL: widgets.URL, Tenant: "team-a"}, "alice"); err != nil {
		t.Fatalf("team-a re-registering its repository: %v", err)
	}
	if assoc, err := dropped.svc.TagHistory(ctx, "team-a", "widgets", "v1"); err != nil || len(assoc) != 1 {
		t.Fatalf("history after the take-over: %v %+v", err, assoc)
	}

	// History with no registration to say whose it is (restored without the
	// registry) does not free the name either.
	st := NewMemoryStore()
	if err := st.Create(ctx, historyObject("orphan", 1), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	orphan := newHarness(t, st)
	var conflict *ConflictError
	if _, err := orphan.svc.Add(ctx, Repo{Name: "orphan", URL: "https://git.example/x.git", Tenant: "team-b"}, "mallory"); !errors.As(err, &conflict) {
		t.Fatalf("registered over orphaned history: %v", err)
	}
}

// The release pinner fetches a repository's dependencies with the
// repository's roles, or the service default; with access control on, a
// registration needs roles it can fetch with, and known ones.
func TestReleasePinnerRoles(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, NewMemoryStore(), widgets, Repo{Name: "gadgets", URL: "https://git.example/acme/gadgets.git", Tenant: "team-a", Roles: []string{"gadget-reader"}})
	h.svc.cfg.Roles = []string{"reader"}
	h.commitDeps(commitA, h.publish("left-pad", "1.0.0"))
	h.commitDeps(commitB, h.publish("is-odd", "1.0.0"))
	h.refs.set("widgets", "v1", commitA)
	h.refs.set("gadgets", "v1", commitB)
	h.sync("widgets")
	h.sync("gadgets")
	h.fetcher.mu.Lock()
	calls := append([]FetchRequest(nil), h.fetcher.calls...)
	h.fetcher.mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("fetches: %+v", calls)
	}
	for _, c := range calls {
		want := "reader"
		if strings.Contains(c.Path, "is-odd") {
			want = "gadget-reader"
		}
		if len(c.Roles) != 1 || c.Roles[0] != want || c.Subject != "system:release-pinner" || c.Tenant != "team-a" {
			t.Fatalf("fetch %s as %s %v of %s, want role %s", c.Path, c.Subject, c.Roles, c.Tenant, want)
		}
	}

	known := map[string]bool{"reader": true}
	svc, err := New(ctx, Config{KnownRole: func(r string) bool { return known[r] }}, Options{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	var verr *ValidationError
	if _, err := svc.Add(ctx, Repo{Name: "a", URL: "https://git.example/a.git"}, "alice"); !errors.As(err, &verr) {
		t.Fatalf("a registration without roles, with access control on and no default: %v", err)
	}
	if _, err := svc.Add(ctx, Repo{Name: "a", URL: "https://git.example/a.git", Roles: []string{"admin"}}, "alice"); !errors.As(err, &verr) {
		t.Fatalf("an undefined role: %v", err)
	}
	if _, err := svc.Add(ctx, Repo{Name: "a", URL: "https://git.example/a.git", Roles: []string{"reader", "reader"}}, "alice"); !errors.As(err, &verr) {
		t.Fatalf("a duplicate role: %v", err)
	}
	if _, err := svc.Add(ctx, Repo{Name: "a", URL: "https://git.example/a.git", Roles: []string{"reader"}}, "alice"); err != nil {
		t.Fatal(err)
	}
}

// Background syncs of a repository are coalesced: a burst of requests while
// one runs makes it run once more, not once each.
func TestBackgroundSyncsAreCoalesced(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	gate, entered := make(chan struct{}), make(chan struct{}, 8)
	h.refs.mu.Lock()
	h.refs.gate, h.refs.entered = gate, entered
	h.refs.mu.Unlock()

	h.svc.goSync("widgets", "webhook")
	<-entered // the first sync is fetching
	for i := 0; i < 20; i++ {
		h.svc.goSync("widgets", "webhook")
	}
	close(gate)
	calls := func() int {
		h.refs.mu.Lock()
		defer h.refs.mu.Unlock()
		return h.refs.calls
	}
	idle := func() bool {
		h.svc.syncMu.Lock()
		defer h.svc.syncMu.Unlock()
		return len(h.svc.syncing) == 0
	}
	deadline := time.Now().Add(10 * time.Second)
	for !idle() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := calls(); n != 2 || !idle() {
		t.Fatalf("%d syncs ran for a burst of 21 requests, want 2", n)
	}
	// Once closed, nothing more is started.
	_ = h.svc.Close()
	h.svc.goSync("widgets", "webhook")
	if n := calls(); n != 2 || !idle() {
		t.Fatalf("a sync was started after Close (%d)", n)
	}
}

func TestWebhookNeedsASecret(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	if h.svc.WebhookHandler() != nil {
		t.Fatal("a webhook receiver without a secret accepts anyone's deliveries")
	}
}

func TestWebhook(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	h.svc.cfg.WebhookSecret = "s3cret"
	handler := h.svc.WebhookHandler()
	post := func(event string, payload map[string]any, sign bool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/webhooks/repos", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", event)
		if sign {
			req.Header.Set("X-Hub-Signature-256", watch.SignBody("s3cret", body))
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	repo := map[string]any{"full_name": "acme/widgets", "clone_url": "https://git.example/acme/widgets.git"}
	if rec := post("push", map[string]any{"ref": "refs/tags/v1", "repository": repo}, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned: %d", rec.Code)
	}
	if rec := post("ping", map[string]any{}, true); rec.Code != http.StatusOK {
		t.Fatalf("ping: %d", rec.Code)
	}
	if rec := post("push", map[string]any{"ref": "refs/heads/main", "repository": repo}, true); rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), "ignored") {
		t.Fatalf("branch push: %d %s", rec.Code, rec.Body)
	}
	other := map[string]any{"full_name": "evil/other", "clone_url": "https://git.example/evil/other.git"}
	if rec := post("push", map[string]any{"ref": "refs/tags/v1", "repository": other}, true); rec.Code != http.StatusNotFound {
		t.Fatalf("unregistered: %d", rec.Code)
	}
	h.commitDeps(commitA, h.publish("left-pad", "1.0.0"))
	h.refs.set("widgets", "v1", commitA)
	if rec := post("push", map[string]any{"ref": "refs/tags/v1", "repository": repo}, true); rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), "accepted") {
		t.Fatalf("tag push: %d %s", rec.Code, rec.Body)
	}
	h.svc.wg.Wait() // the sync runs in the background
	h.drain()
	if !h.release("widgets", commitA).FullyPinned {
		t.Fatal("the webhook's sync did not pin the release")
	}
	// Not the leader: deferred.
	h.svc.SetLeaderGate(func() bool { return false })
	if rec := post("push", map[string]any{"ref": "refs/tags/v2", "repository": repo}, true); !strings.Contains(rec.Body.String(), "deferred") {
		t.Fatalf("follower: %s", rec.Body)
	}
}

func TestRepairPinned(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	h.commitDeps(commitA, h.publish("left-pad", "1.0.0"))
	h.refs.set("widgets", "v1", commitA)
	h.sync("widgets")
	key := h.release("widgets", commitA).pinnedObjects()[0].CacheKey

	if !h.svc.RepairPinned(key) {
		t.Fatal("a pinned key is repaired")
	}
	h.svc.wg.Wait()
	o := h.release("widgets", commitA).pinnedObjects()[0]
	if o.Repairs != 1 {
		t.Fatalf("repairs %d", o.Repairs)
	}
	// Upstream now serves other bytes: the repair alerts, and the release no
	// longer pins the key — the cache must not keep the wrong bytes forever.
	h.fetcher.put("npm", "/left-pad/-/left-pad-1.0.0.tgz", []byte("something else"))
	h.svc.RepairPinned(key)
	h.svc.wg.Wait()
	if !strings.Contains(strings.Join(h.notes.types(), " "), "release_pin:pin-lost") {
		t.Fatalf("notifications: %v", h.notes.types())
	}
	if h.svc.IsPinned(key) {
		t.Fatal("a key whose object was lost is still pinned")
	}
	m := h.release("widgets", commitA)
	if m.FullyPinned || m.Status == StatusPinned || len(m.pinnedObjects()) != 0 {
		t.Fatalf("release after the loss: %s fully=%v pinned=%d", m.Status, m.FullyPinned, len(m.pinnedObjects()))
	}
	if o := m.Dependencies[0].Objects[0]; o.Status != StatusFailed || !strings.Contains(o.Reason, "lost") {
		t.Fatalf("lost object recorded as %s %q", o.Status, o.Reason)
	}
	// A restart does not pin it again.
	again := h.restart()
	if again.svc.IsPinned(key) {
		t.Fatal("the lost key is pinned again after a restart")
	}
	if h.svc.RepairPinned("not/pinned") {
		t.Fatal("an unpinned key is not repaired")
	}
}

func TestExportImportManifests(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	h.commitDeps(commitA, h.publish("left-pad", "1.0.0"))
	h.refs.set("widgets", "v1", commitA)
	h.sync("widgets")
	raw, keys, err := h.svc.ExportManifests(context.Background())
	if err != nil || len(raw) != 1 || len(keys) != 1 {
		t.Fatalf("export: %v %d %d", err, len(raw), len(keys))
	}
	other := newHarness(t, NewMemoryStore())
	ok, err := other.svc.ImportManifest(context.Background(), raw[0].Data)
	if err != nil || !ok {
		t.Fatalf("import: %v %v", ok, err)
	}
	if !other.svc.IsPinned(keys[0]) {
		t.Fatal("an imported manifest pins its objects")
	}
	if ok, _ := other.svc.ImportManifest(context.Background(), raw[0].Data); ok {
		t.Fatal("imported twice")
	}
	if _, err := other.svc.ImportManifest(context.Background(), []byte(`{"repo":"../x","commit":"a"}`)); err == nil {
		t.Fatal("imported an invalid manifest")
	}
}

func TestDirStoreAppendOnlyCreate(t *testing.T) {
	st, err := NewDirStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := st.Create(ctx, "history/x/000000000001", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := st.Create(ctx, "history/x/000000000001", []byte("two")); !errors.Is(err, ErrExists) {
		t.Fatalf("a record was replaced: %v", err)
	}
	if got, _ := st.Get(ctx, "history/x/000000000001"); string(got) != "one" {
		t.Fatalf("content %q", got)
	}
	for _, bad := range []string{"../etc/passwd", "history/../../x", "a", "a/b/c/d", "a/.hidden", "A/b"} {
		if err := st.Put(ctx, bad, []byte("x")); err == nil {
			t.Errorf("accepted name %q", bad)
		}
	}
	names, err := st.List(ctx, "history/")
	if err != nil || len(names) != 1 || names[0] != "history/x/000000000001" {
		t.Fatalf("list: %v %v", err, names)
	}
}

// A gate refusing the registry document a dependency is found through (its
// POM) refuses the dependency.
func TestRefusedIndexDocumentRefusesTheDependency(t *testing.T) {
	h := newHarness(t, NewMemoryStore(), widgets)
	h.fetcher.objects["central/com/acme/lib/1.0/lib-1.0.pom"] = fakeObject{gate: "malfeed"}
	h.commitDeps(commitA, lockfiles.Dependency{Type: "maven", Name: "com.acme:lib", Version: "1.0", Unverified: true})
	h.refs.set("widgets", "v1", commitA)
	h.sync("widgets")
	d := h.release("widgets", commitA).Dependencies[0]
	if d.Status != StatusRefused || !strings.Contains(d.Reason, "malfeed") {
		t.Fatalf("dependency %+v", d)
	}
}

// The chain hash is a fixed, versioned serialisation of a record: this value
// changing means records written before the change no longer verify.
func TestHistoryHashIsStable(t *testing.T) {
	r := TagRecord{Seq: 2, Repo: "widgets", Tag: "v1.0", Kind: TagMoved, Commit: commitB, At: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC),
		Supersedes: 1, PreviousCommit: commitA, PreviousLastSeen: time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), Trigger: "webhook", Prev: "abc"}
	const want = "fb661879cbd3108a9122bf0fe9d865fc93f10210b50db817b96cf5232e2f745f"
	if got := hashRecord(r); got != want {
		t.Fatalf("the record hash changed: %s (records already written would no longer verify)", got)
	}
	// The same instant in another zone is the same record.
	r.At = r.At.In(time.FixedZone("CET", 3600))
	if got := hashRecord(r); got != want {
		t.Fatalf("the hash depends on the time zone: %s", got)
	}
	// Every field is covered.
	r2 := r
	r2.Initial = true
	if hashRecord(r2) == want {
		t.Fatal("Initial is not covered by the hash")
	}
}
