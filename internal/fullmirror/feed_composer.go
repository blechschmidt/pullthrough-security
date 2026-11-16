package fullmirror

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/composer"
)

// composer follows Packagist's metadata change log.
//
// `metadata/changes.json?since=<t>` (t in 1/10000 s) lists what changed in
// the last 24 hours: `update` and `delete` actions naming a package, and the
// position to continue from (`timestamp`). Without since Packagist answers 400
// with the current timestamp: where a mirror starts. A since older than the log
// is answered with a `resync` action: the cursor is reported invalid and the
// registry enumerated again. An update is package-level, so it is reported by
// name and the engine considers every version its policy keeps; a delete is
// reported as Deleted. A package whose name ends in "~dev" is the
// dev-branch document: its versions are branch heads, mutable by nature, and
// are not mirrored. Bootstrap takes the start position first, then lists every
// package name with `packages/list.json` — stored in Env.Dir and handed out
// page by page — and continues with that position.
//
// Releases reads the package's v2 metadata, `/p2/<vendor>/<package>.json`,
// through the gated pipeline (the document a client reads, its dist URLs
// rewritten into the proxy) and names each version's archive by the backend's
// own builder, composer.DistPath — the path the backend wrote into that
// document — taking only dists the backend did route through the proxy. Dev
// versions, versions without a dist and dists the proxy cannot address are
// left out. Packagist lists versions newest first; Releases returns them
// oldest first. The metadata states release times (Published) but neither
// sizes nor yanks.
//
// Packagist asks mirrors to hold the metadata of an updated package to the
// update: its Last-Modified must be at least the action's time, or the CDN
// still serves the copy from before ("wait a few seconds and retry"). The
// gated pipeline does not hand Releases the response's headers, so for a
// package Changes reported updated (the times are remembered while the process
// runs, for at most composerMaxTimes packages) Releases first asks the
// upstream with a HEAD request; metadata older than the update is a transient
// error the engine retries.
//
// The public repository (repo.packagist.org) is followed with
// https://packagist.org's change log. No other repository software publishes
// this feed and a package list together — Satis, Artifactory, Nexus and Private
// Packagist repositories have neither — so any other upstream needs the feed
// option "url": the base of a Packagist-compatible site serving
// /metadata/changes.json and /packages/list.json.

const composerFeedVersion = 1

const (
	// composerPublicFeed is where Packagist publishes its change log and
	// package list.
	composerPublicFeed = "https://packagist.org"
	// composerNamesPerBatch is how many packages one Bootstrap batch lists:
	// few enough that a batch is dealt with well within the 24 hours the
	// change log reaches back (every batch moves the log position on).
	composerNamesPerBatch = 10_000
	// composerStartMargin is how far before the change log's position at the
	// start of a listing the follower continues from: the package list is
	// served from a CDN that caches it for minutes, and a package created
	// meanwhile is in neither the list nor a log that starts later.
	composerStartMargin = 15 * 60 * 10000
	// composerMaxItems is how many packages one Changes batch reports.
	composerMaxItems = 50_000
	// composerMaxMetadata bounds a package's v2 metadata (the backend's
	// own bound).
	composerMaxMetadata = 16 << 20
	// composerMaxTimes bounds the update times remembered for the
	// Last-Modified check.
	composerMaxTimes = 100_000
	// composerListPrefix names the package lists Bootstrap keeps in Env.Dir.
	composerListPrefix = "composer-list-"
)

// composerPublicHosts are the public repository's names; every host under
// packagist.org (its regional metadata mirrors among them) is Packagist's.
var composerPublicHosts = []string{"repo.packagist.org", "packagist.org"}

type composerFeed struct {
	k kit
	// feed is the base of the change log and the package list.
	feed  *url.URL
	files files
	// page is how many packages a Bootstrap batch lists, maxItems how many a
	// Changes batch reports.
	page, maxItems int

	mu sync.Mutex
	// times maps a package to the time (Unix seconds) of the latest update
	// Changes reported for it.
	times map[string]int64
}

func composerNewFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	var feed *url.URL
	switch {
	case opts["url"] != "":
		if feed, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	case composerIsPackagist(k.upstream):
		feed, _ = url.Parse(composerPublicFeed)
	default:
		return nil, fmt.Errorf("upstream %s is not Packagist, whose change log is known: set fullMirror.feed.url to a Packagist-compatible site "+
			"that serves /metadata/changes.json and /packages/list.json (Satis, Artifactory, Nexus and Private Packagist repositories serve neither)",
			k.upstream.Redacted())
	}
	return &composerFeed{k: k, feed: feed, files: files{dir: env.Dir}, page: composerNamesPerBatch, maxItems: composerMaxItems, times: map[string]int64{}}, nil
}

func init() { Register("composer", composerNewFeed) }

// composerIsPackagist reports whether an upstream is Packagist's public
// repository.
func composerIsPackagist(u *url.URL) bool {
	return hostIs(u, composerPublicHosts...) || strings.HasSuffix(strings.ToLower(u.Hostname()), ".packagist.org")
}

// composerCursor is the Composer feed's position.
type composerCursor struct {
	Format string `json:"format"`
	// Since is the position in the change log, in 1/10000 s as Packagist
	// counts it.
	Since int64 `json:"since"`
	// Listing marks Bootstrap's listing: Offset packages of the list stored
	// for it have been listed, Count is its length and Digest its SHA-256.
	// Started is the log position the listing began at, which names the
	// stored list (Since moves on as the listing reads the log).
	Listing bool   `json:"listing,omitempty"`
	Offset  int    `json:"offset,omitempty"`
	Count   int    `json:"count,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Started int64  `json:"started,omitempty"`
}

func (c *composerCursor) cursorFormat() string { return c.Format }

func (f *composerFeed) format() string { return cursorFormat("composer", composerFeedVersion) }

func (f *composerFeed) cursor(c composerCursor) string {
	c.Format = f.format()
	return encodeCursor(&c)
}

// Bootstrap lists every package name, continuing with the change log from
// where it stood before the listing.
func (f *composerFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	var (
		c     composerCursor
		names []string
	)
	if cursor == "" {
		start, err := f.start(ctx)
		if err != nil {
			return Batch{}, err
		}
		if start > composerStartMargin {
			start -= composerStartMargin
		}
		if names, err = f.list(ctx); err != nil {
			return Batch{}, err
		}
		f.files.pruneKeepingNewest(composerListPrefix, 1)
		digest, err := f.saveList(start, names)
		if err != nil {
			return Batch{}, fmt.Errorf("storing the package list: %w", err)
		}
		c = composerCursor{Since: start, Listing: true, Count: len(names), Digest: digest, Started: start}
	} else {
		if err := decodeCursor(cursor, f.format(), &c); err != nil {
			return Batch{}, err
		}
		if !c.Listing {
			return Batch{}, fmt.Errorf("%w: the Composer cursor does not continue a listing", ErrCursorInvalid)
		}
		var err error
		if names, err = f.loadList(c); err != nil {
			return Batch{}, err
		}
	}
	if c.Since <= 0 || c.Offset < 0 || c.Offset > len(names) {
		return Batch{}, fmt.Errorf("%w: the Composer listing cursor is out of range", ErrCursorInvalid)
	}
	// The change log reaches back 24 hours, and listing Packagist's packages
	// takes longer than that at modest request rates: every batch after the
	// first reads the log from the listing's position, adds what changed to
	// its packages and moves the position on — the listing then ends with a
	// position the log still knows.
	var changed []Coordinate
	if cursor != "" {
		log, err := f.logAfter(ctx, c.Since)
		if err != nil {
			return Batch{}, err
		}
		items, cut := f.items(log.Actions, f.maxItems)
		changed = items
		switch {
		case cut > 0 && cut*10000-1 > c.Since:
			c.Since = cut*10000 - 1
		case cut == 0 && log.Timestamp > c.Since:
			c.Since = log.Timestamp
		}
	}
	page, next, more := pageItems(names, c.Offset, f.page)
	b := Batch{Items: make([]Coordinate, 0, len(page)+len(changed)), More: more, Head: strconv.FormatInt(c.Since, 10)}
	listed := make(map[string]bool, len(page))
	for _, n := range page {
		b.Items = append(b.Items, Coordinate{Name: n})
		listed[n] = true
	}
	for _, co := range changed {
		if !listed[co.Name] {
			b.Items = append(b.Items, co)
		}
	}
	if more {
		nc := c
		nc.Offset = next
		b.Next = f.cursor(nc)
		return b, nil
	}
	b.Next = f.cursor(composerCursor{Since: c.Since})
	b.CursorTime = composerTime(c.Since)
	return b, nil
}

// Changes reads the change log after the cursor.
func (f *composerFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	var c composerCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil {
		return Batch{}, err
	}
	if c.Listing || c.Since <= 0 {
		return Batch{}, fmt.Errorf("%w: the Composer cursor names no position in the change log", ErrCursorInvalid)
	}
	// A listing's package list is of no further use once the log is followed.
	f.files.pruneKeepingNewest(composerListPrefix, 1)
	log, err := f.logAfter(ctx, c.Since)
	if err != nil {
		return Batch{}, err
	}
	items, cut := f.items(log.Actions, f.maxItems)
	if cut > 0 && cut*10000-1 <= c.Since {
		// A batch could only end inside the second it starts in.
		return Batch{}, fmt.Errorf("%w: more than %d packages changed within one second of the change log; enumerating the registry again",
			ErrCursorInvalid, f.maxItems)
	}
	b := Batch{Items: items, Head: strconv.FormatInt(log.Timestamp, 10), HeadTime: composerTime(log.Timestamp)}
	next := log.Timestamp
	if cut > 0 {
		// More packages changed than a batch carries: the next batch reads
		// the log again from the second of the first action left out
		// (since is exclusive: one before that second's first position).
		next, b.More = cut*10000-1, true
	}
	b.Next = f.cursor(composerCursor{Since: next})
	b.CursorTime = composerTime(next)
	b.LagKnown = !b.More
	return b, nil
}

// items maps the log's actions, oldest first, to one change per package where
// its last action stands, leaving out dev-branch documents and names the
// backend does not route, and remembers the update times for Releases. Past
// limit packages it stops and returns the time (Unix seconds) of the first
// action left out.
func (f *composerFeed) items(actions []composerAction, limit int) ([]Coordinate, int64) {
	var out []Coordinate
	at := map[string]int{}
	var cut int64
	for _, a := range actions {
		if a.Type != "update" && a.Type != "delete" {
			continue
		}
		if strings.HasSuffix(a.Package, "~dev") {
			continue // dev versions are not mirrored
		}
		if _, _, ok := composer.SplitPackageName(a.Package); !ok {
			continue
		}
		i, seen := at[a.Package]
		if !seen && len(at) >= limit {
			cut = a.Time
			break
		}
		c := Coordinate{Name: a.Package, Deleted: a.Type == "delete"}
		if seen {
			out[i].Name = "" // superseded by this later action
		}
		at[a.Package] = len(out)
		out = append(out, c)
		if a.Type == "update" {
			f.noteUpdate(a.Package, a.Time)
		}
	}
	kept := out[:0]
	for _, c := range out {
		if c.Name != "" {
			kept = append(kept, c)
		}
	}
	return kept, cut
}

// noteUpdate remembers the latest update time of a package, within
// composerMaxTimes packages: past that, the oldest half is forgotten.
func (f *composerFeed) noteUpdate(name string, t int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t <= f.times[name] {
		return
	}
	if _, known := f.times[name]; !known && len(f.times) >= composerMaxTimes {
		all := make([]int64, 0, len(f.times))
		for _, v := range f.times {
			all = append(all, v)
		}
		sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
		median := all[len(all)/2]
		for k, v := range f.times {
			if v <= median {
				delete(f.times, k)
			}
		}
	}
	f.times[name] = t
}

// composerAction is one action of the change log.
type composerAction struct {
	Type    string `json:"type"`
	Package string `json:"package"`
	Time    int64  `json:"time"`
}

// logAfter reads the change log after since, its actions oldest first. A
// position the log no longer knows — refused, a resync asked for, a log that
// went back, or one too big to read (a mass re-dump: a resync is the only way
// on) — invalidates the cursor.
func (f *composerFeed) logAfter(ctx context.Context, since int64) (composerLog, error) {
	log, status, err := f.changes(ctx, since)
	if err != nil {
		if errors.Is(err, errTooLarge) || errors.Is(err, composerErrTooManyActions) {
			return composerLog{}, fmt.Errorf("%w: the change log after since=%d is too big to read (%v)", ErrCursorInvalid, since, err)
		}
		return composerLog{}, err
	}
	if status == http.StatusBadRequest {
		return composerLog{}, fmt.Errorf("%w: the change log refuses since=%d: %s", ErrCursorInvalid, since, cleanMessage(truncate(log.Error, 256)))
	}
	for _, a := range log.Actions {
		if a.Type == "resync" {
			return composerLog{}, fmt.Errorf("%w: the change log no longer reaches back to since=%d (it keeps 24 hours) and asks for a resync", ErrCursorInvalid, since)
		}
	}
	if log.Timestamp <= 0 {
		return composerLog{}, Permanent(fmt.Errorf("the change log states no timestamp to continue from"))
	}
	if log.Timestamp < since {
		return composerLog{}, fmt.Errorf("%w: the change log went back from since=%d to %d", ErrCursorInvalid, since, log.Timestamp)
	}
	sort.SliceStable(log.Actions, func(i, j int) bool { return log.Actions[i].Time < log.Actions[j].Time })
	return log, nil
}

// composerErrTooManyActions reports a change log with more actions than are read.
var composerErrTooManyActions = errors.New("the change log lists more actions than are read")

// composerLog is a changes.json answer.
type composerLog struct {
	Actions   []composerAction
	Timestamp int64
	Error     string
}

// changes reads changes.json after since (0: without since, which Packagist
// answers 400 with the current timestamp). It returns the answer's status,
// 200 or 400.
func (f *composerFeed) changes(ctx context.Context, since int64) (composerLog, int, error) {
	u := join(f.feed, "metadata/changes.json")
	if since > 0 {
		u += "?since=" + strconv.FormatInt(since, 10)
	}
	resp, err := f.k.do(ctx, http.MethodGet, u, nil, http.Header{"Accept": {"application/json"}})
	if err != nil {
		return composerLog{}, 0, fmt.Errorf("reading the Packagist change log: %w", err)
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
		return composerLog{}, resp.StatusCode, httpStatusError(u, resp)
	}
	body, err := readLimited(resp.Body, maxFeedPage)
	if err != nil {
		return composerLog{}, resp.StatusCode, fmt.Errorf("reading the Packagist change log: %w", err)
	}
	log, err := composerParseChanges(body)
	if err != nil {
		if resp.StatusCode == http.StatusBadRequest {
			return composerLog{}, resp.StatusCode, Permanent(fmt.Errorf("the Packagist change log answered %s", resp.Status))
		}
		return composerLog{}, resp.StatusCode, Permanent(fmt.Errorf("the Packagist change log: %w", err))
	}
	return log, resp.StatusCode, nil
}

// composerParseChanges reads a changes.json answer: its actions, its
// timestamp and, on a 400, its error. Actions that do not read are left out.
func composerParseChanges(body []byte) (composerLog, error) {
	var doc struct {
		Actions   []json.RawMessage `json:"actions"`
		Timestamp json.Number       `json:"timestamp"`
		Error     string            `json:"error"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return composerLog{}, err
	}
	log := composerLog{Error: doc.Error}
	if doc.Timestamp != "" {
		ts, err := strconv.ParseInt(doc.Timestamp.String(), 10, 64)
		if err != nil || ts <= 0 {
			return composerLog{}, fmt.Errorf("timestamp %q is not a position", truncate(doc.Timestamp.String(), 32))
		}
		log.Timestamp = ts
	}
	if len(doc.Actions) > maxBatchItems*10 {
		return composerLog{}, fmt.Errorf("%w (%d)", composerErrTooManyActions, len(doc.Actions))
	}
	for _, raw := range doc.Actions {
		var a composerAction
		if json.Unmarshal(raw, &a) != nil || a.Type == "" || (a.Type != "resync" && !cleanName(a.Package)) || a.Time < 0 {
			continue
		}
		log.Actions = append(log.Actions, a)
	}
	return log, nil
}

// start reads the change log's current position: what Packagist answers a
// request without since (400, with the timestamp to start from).
func (f *composerFeed) start(ctx context.Context) (int64, error) {
	log, _, err := f.changes(ctx, 0)
	if err != nil {
		return 0, err
	}
	if log.Timestamp <= 0 {
		return 0, Permanent(fmt.Errorf("the Packagist change log states no timestamp to start from"))
	}
	return log.Timestamp, nil
}

// list reads every package name from packages/list.json.
func (f *composerFeed) list(ctx context.Context) ([]string, error) {
	u := join(f.feed, "packages/list.json")
	body, _, err := f.k.get(ctx, u, http.Header{"Accept": {"application/json"}}, maxFeedPage)
	if err != nil {
		return nil, fmt.Errorf("listing the Packagist packages: %w", err)
	}
	names, err := composerParseList(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the Packagist package list: %w", err))
	}
	return names, nil
}

// composerParseList reads packages/list.json: the names the backend routes,
// each once, in the list's order.
func composerParseList(body []byte) ([]string, error) {
	var doc struct {
		PackageNames []string `json:"packageNames"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.PackageNames == nil {
		return nil, fmt.Errorf("it lists no packageNames")
	}
	out := make([]string, 0, len(doc.PackageNames))
	seen := make(map[string]bool, len(doc.PackageNames))
	for _, n := range doc.PackageNames {
		if _, _, ok := composer.SplitPackageName(n); ok && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

// composerListFile names the package list stored for a listing.
func composerListFile(since int64) string {
	return composerListPrefix + strconv.FormatInt(since, 10) + ".txt"
}

// saveList stores a listing's package names, one per line, and returns the
// file's SHA-256.
func (f *composerFeed) saveList(since int64, names []string) (string, error) {
	data := []byte(strings.Join(names, "\n"))
	sum := sha256.Sum256(data)
	err := f.files.write(composerListFile(since), func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
	return hex.EncodeToString(sum[:]), err
}

// loadList reads the package list a listing cursor names; one that is missing
// or does not match the cursor invalidates it.
func (f *composerFeed) loadList(c composerCursor) ([]string, error) {
	if f.files.dir == "" {
		return nil, errValidationOnly
	}
	started := c.Started
	if started == 0 {
		started = c.Since
	}
	fh, err := os.Open(f.files.path(composerListFile(started)))
	if err != nil {
		return nil, fmt.Errorf("%w: the package list is not stored (%v)", ErrCursorInvalid, err)
	}
	defer fh.Close()
	data, err := readLimited(fh, maxFeedPage)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the package list: %v", ErrCursorInvalid, err)
	}
	sum := sha256.Sum256(data)
	var names []string
	if len(data) > 0 {
		names = strings.Split(string(data), "\n")
	}
	if hex.EncodeToString(sum[:]) != c.Digest || len(names) != c.Count {
		return nil, fmt.Errorf("%w: the stored package list does not match the cursor", ErrCursorInvalid)
	}
	return names, nil
}

// composerTime converts a change-log position (1/10000 s) to a time.
func composerTime(since int64) time.Time {
	return time.Unix(since/10000, (since%10000)*100_000).UTC()
}

// Releases reads the package's v2 metadata through the gated pipeline.
func (f *composerFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	vendor, pkg, ok := composer.SplitPackageName(name)
	if !ok {
		return nil, Permanent(fmt.Errorf("%q is not a Composer package name", name))
	}
	if err := f.current(ctx, name, vendor, pkg); err != nil {
		return nil, err
	}
	body, err := f.k.read(ctx, "/p2/"+vendor+"/"+pkg+".json", "application/json", composerMaxMetadata)
	if err != nil {
		return nil, err
	}
	md, err := composer.ParseMetadata(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the metadata of %s: %w", name, err))
	}
	versions, ok := md.Packages[name]
	if !ok {
		return nil, Permanent(fmt.Errorf("the metadata of %s does not list the package", name))
	}
	times, err := composer.ReleaseTimes(body, name)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the metadata of %s: %w", name, err))
	}
	var rels []Release
	seen := map[string]bool{}
	for _, v := range versions {
		if v.Version == "" || seen[v.Version] || composer.IsDevVersion(v.Version) || v.Dist.URL == "" {
			continue
		}
		seen[v.Version] = true
		p, ok := composer.DistPath(vendor, pkg, v.Version, v.Dist.Reference, v.Dist.Type)
		if !ok || !validArtifactPath(p) || !f.routed(v.Dist.URL, p) {
			continue
		}
		rels = append(rels, Release{Version: v.Version, Published: times[v.Version], Artifacts: []Artifact{{Path: p}}})
	}
	// Packagist lists versions newest first, by version.
	for i, j := 0, len(rels)-1; i < j; i, j = i+1, j-1 {
		rels[i], rels[j] = rels[j], rels[i]
	}
	return rels, nil
}

// routed reports whether the dist URL the metadata names is the backend's dist
// path p under the proxy: the backend leaves a dist it cannot serve (one
// whose URL is not http(s)) as the upstream listed it.
func (f *composerFeed) routed(distURL, p string) bool {
	got, ok := f.k.proxyPath(distURL)
	if !ok {
		return false
	}
	a, errA := url.PathUnescape(got)
	b, errB := url.PathUnescape(p)
	return errA == nil && errB == nil && a == b
}

// current holds a package Changes reported updated to Packagist's rule: its
// metadata must have been modified at or after the update, or the CDN still
// serves the copy from before and the read is tried again later. Without a
// remembered update, or a Last-Modified to compare, there is nothing to hold
// it to.
func (f *composerFeed) current(ctx context.Context, name, vendor, pkg string) error {
	f.mu.Lock()
	t, ok := f.times[name]
	f.mu.Unlock()
	if !ok {
		return nil
	}
	u := join(f.k.upstream, "p2/"+vendor+"/"+pkg+".json")
	resp, err := f.k.do(ctx, http.MethodHead, u, nil, nil)
	if err != nil {
		return fmt.Errorf("checking that the metadata of %s is current: %w", name, err)
	}
	drain(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return httpStatusError(u, resp)
	}
	modified, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		return nil
	}
	if modified.Unix() < t {
		return fmt.Errorf("the metadata of %s was last modified at %s, before its update at %s: the CDN has not caught up yet",
			name, modified.UTC().Format(time.RFC3339), time.Unix(t, 0).UTC().Format(time.RFC3339))
	}
	f.mu.Lock()
	if f.times[name] == t {
		delete(f.times, name)
	}
	f.mu.Unlock()
	return nil
}
