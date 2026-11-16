package fullmirror

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// npm follows the registry's CouchDB-style replication feed.
//
// Changes reads `_changes?since=<seq>`: every result names a package (and
// whether it was deleted) in the order of an integer sequence, without the
// version — the engine then considers every version its policy keeps, and
// what the cache holds already costs a lookup. Before each poll the feed's
// root is read for its update_seq: a stored sequence beyond it means the
// registry reset its sequence (npm did in 2021), and the cursor is reported
// invalid so the registry is enumerated again. Bootstrap lists every package
// name with `_all_docs`, page by page in key order, and continues with the
// sequence the registry stood at when the listing began.
//
// Releases reads the package's abbreviated packument through the gated
// pipeline, as npm does, and takes each version's tarball path from the URL
// the backend rewrote into it, with repos/locate's npm locator.
//
// The public registry's feed is https://replicate.npmjs.com; any other
// upstream is taken to serve `_changes` and `_all_docs` at its own root, as a
// CouchDB-backed registry does. Verdaccio, Artifactory, Nexus and GitHub
// Packages do not: their upstreams cannot be followed unless the feed option
// "url" names a replica that does.

const npmFeedVersion = 1

// npmPublicHosts are the public registry's names.
var npmPublicHosts = []string{"registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com"}

// npmPublicFeed is the public registry's replication endpoint.
const npmPublicFeed = "https://replicate.npmjs.com"

// npmMaxLimit is the most changes or names one request asks for (the
// replication endpoint refuses more).
const npmMaxLimit = 10000

type npmFeed struct {
	k    kit
	feed *url.URL
	// limit is how many changes, and names, one request asks for.
	limit int
}

func newNPMFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	feed := k.upstream
	switch {
	case opts["url"] != "":
		if feed, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	case hostIs(k.upstream, npmPublicHosts...):
		feed, _ = url.Parse(npmPublicFeed)
	}
	return &npmFeed{k: k, feed: feed, limit: npmMaxLimit}, nil
}

func init() { Register("npm", newNPMFeed) }

// npmCursor is the npm feed's position.
type npmCursor struct {
	Format string `json:"format"`
	// Since is the change sequence the next Changes continues after, as the
	// registry spells it (an integer for npm; CouchDB 2 uses opaque strings).
	Since string `json:"since"`
	// Listing is set while Bootstrap lists the package names; After is the
	// last name listed.
	Listing bool   `json:"listing,omitempty"`
	After   string `json:"after,omitempty"`
}

func (c *npmCursor) cursorFormat() string { return c.Format }

func (f *npmFeed) format() string { return cursorFormat("npm", npmFeedVersion) }

// Bootstrap lists every package name with _all_docs.
func (f *npmFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	var c npmCursor
	if cursor == "" {
		head, err := f.head(ctx)
		if err != nil {
			return Batch{}, err
		}
		c = npmCursor{Format: f.format(), Since: head, Listing: true}
	} else if err := decodeCursor(cursor, f.format(), &c); err != nil {
		return Batch{}, err
	} else if !c.Listing {
		return Batch{}, fmt.Errorf("%w: the npm cursor does not continue a listing", ErrCursorInvalid)
	}
	q := url.Values{"limit": {strconv.Itoa(f.limit)}}
	if c.After != "" {
		key, _ := json.Marshal(c.After)
		q.Set("startkey", string(key))
		// startkey is inclusive: the name listed last comes back first.
		q.Set("limit", strconv.Itoa(f.limit+1))
	}
	body, _, err := f.k.get(ctx, join(f.feed, "_all_docs")+"?"+q.Encode(), nil, maxFeedPage)
	if err != nil {
		return Batch{}, fmt.Errorf("listing the npm registry: %w", err)
	}
	ids, err := parseNPMAllDocs(body)
	if err != nil {
		return Batch{}, Permanent(fmt.Errorf("listing the npm registry: %w", err))
	}
	full := len(ids) == f.limit
	if c.After != "" {
		full = len(ids) == f.limit+1
		if len(ids) > 0 && ids[0] == c.After {
			ids = ids[1:]
		}
	}
	b := Batch{Head: c.Since}
	last := c.After
	for _, id := range ids {
		last = id
		if isNPMPackageName(id) {
			b.Items = append(b.Items, Coordinate{Name: id})
		}
	}
	if full && c.After != "" && last <= c.After {
		// _all_docs is in raw key order: a page that ends at or before
		// where it started would have the listing loop (a server that
		// ignores startkey).
		return Batch{}, Permanent(fmt.Errorf("listing the npm registry: the page after %q ends at %q and does not advance", c.After, last))
	}
	if full {
		b.More = true
		b.Next = encodeCursor(&npmCursor{Format: f.format(), Since: c.Since, Listing: true, After: last})
		return b, nil
	}
	b.Next = encodeCursor(&npmCursor{Format: f.format(), Since: c.Since})
	return b, nil
}

// Changes reads _changes after the cursor's sequence.
func (f *npmFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	var c npmCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil {
		return Batch{}, err
	}
	if c.Listing || c.Since == "" {
		return Batch{}, fmt.Errorf("%w: the npm cursor names no change sequence", ErrCursorInvalid)
	}
	head, err := f.head(ctx)
	if err != nil {
		return Batch{}, err
	}
	since, sinceOK := parseSeq(c.Since)
	headN, headOK := parseSeq(head)
	if sinceOK && headOK && since > headN {
		return Batch{}, fmt.Errorf("%w: the stored sequence %d is beyond the registry's current %d (the registry reset its sequence)", ErrCursorInvalid, since, headN)
	}
	q := url.Values{"since": {c.Since}, "limit": {strconv.Itoa(f.limit)}}
	body, _, err := f.k.get(ctx, join(f.feed, "_changes")+"?"+q.Encode(), nil, maxFeedPage)
	if err != nil {
		return Batch{}, fmt.Errorf("reading the npm change feed: %w", err)
	}
	changes, last, err := parseNPMChanges(body)
	if err != nil {
		return Batch{}, Permanent(fmt.Errorf("reading the npm change feed: %w", err))
	}
	if last == "" {
		last = c.Since
	}
	if lastN, ok := parseSeq(last); ok && sinceOK && lastN < since {
		return Batch{}, fmt.Errorf("%w: the change feed went back from sequence %d to %d", ErrCursorInvalid, since, lastN)
	}
	b := Batch{Head: head, Next: encodeCursor(&npmCursor{Format: f.format(), Since: last}), More: len(changes) >= f.limit}
	for _, ch := range changes {
		if isNPMPackageName(ch.ID) {
			b.Items = append(b.Items, Coordinate{Name: ch.ID, Deleted: ch.Deleted})
		}
	}
	if lastN, ok := parseSeq(last); ok && headOK {
		if lag := headN - lastN; lag >= 0 {
			b.Lag, b.LagKnown = lag, true
		}
	}
	return b, nil
}

// head reads the feed's current sequence (the root document's update_seq).
func (f *npmFeed) head(ctx context.Context) (string, error) {
	body, _, err := f.k.get(ctx, join(f.feed, ""), nil, 1<<20)
	if err != nil {
		return "", fmt.Errorf("reading the npm feed's current sequence: %w", err)
	}
	var root struct {
		UpdateSeq json.RawMessage `json:"update_seq"`
	}
	if err := json.Unmarshal(body, &root); err != nil {
		return "", Permanent(fmt.Errorf("the npm feed's root is not the JSON document expected: %w", err))
	}
	seq, ok := seqString(root.UpdateSeq)
	if !ok {
		return "", Permanent(fmt.Errorf("the npm feed's root states no update_seq"))
	}
	return seq, nil
}

// npmChange is one result of _changes.
type npmChange struct {
	ID      string
	Deleted bool
}

// parseNPMChanges reads a _changes response: its results and last_seq.
func parseNPMChanges(body []byte) ([]npmChange, string, error) {
	var doc struct {
		Results []struct {
			ID      string          `json:"id"`
			Seq     json.RawMessage `json:"seq"`
			Deleted bool            `json:"deleted"`
		} `json:"results"`
		LastSeq json.RawMessage `json:"last_seq"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", err
	}
	if doc.Results == nil {
		return nil, "", fmt.Errorf("the response has no results")
	}
	last, ok := seqString(doc.LastSeq)
	if !ok && len(doc.LastSeq) > 0 && string(doc.LastSeq) != "null" {
		return nil, "", fmt.Errorf("last_seq %s is not a sequence", truncate(string(doc.LastSeq), 64))
	}
	out := make([]npmChange, 0, len(doc.Results))
	for _, r := range doc.Results {
		out = append(out, npmChange{ID: r.ID, Deleted: r.Deleted})
	}
	return out, last, nil
}

// parseNPMAllDocs reads an _all_docs response's ids, in order.
func parseNPMAllDocs(body []byte) ([]string, error) {
	var doc struct {
		Rows []struct {
			ID string `json:"id"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Rows == nil {
		return nil, fmt.Errorf("the response has no rows")
	}
	out := make([]string, 0, len(doc.Rows))
	for _, r := range doc.Rows {
		out = append(out, r.ID)
	}
	return out, nil
}

// seqString renders a sequence: a JSON integer as its digits, a JSON string
// as itself.
func seqString(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return "", false
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" || len(s) > 4096 {
			return "", false
		}
		return s, true
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n < 0 {
		return "", false
	}
	return strconv.FormatInt(n, 10), true
}

// parseSeq reads an integer sequence (npm's); CouchDB 2's opaque strings do
// not parse and are not compared.
func parseSeq(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n >= 0
}

// isNPMPackageName reports whether an id of the replication feed is a package
// the registry serves: not a design document, a name of at most 214
// characters without spaces or control characters, a scope only in the
// "@scope/name" form.
func isNPMPackageName(id string) bool {
	if !cleanName(id) || len(id) > 214 || strings.HasPrefix(id, "_") || strings.ContainsAny(id, " \\%?#") {
		return false
	}
	if strings.HasPrefix(id, "@") {
		scope, name, ok := strings.Cut(id[1:], "/")
		return ok && scope != "" && name != "" && !strings.Contains(name, "/")
	}
	return !strings.Contains(id, "/")
}

// npmAccept is what npm itself asks for: the abbreviated packument.
const npmAccept = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"

// Releases reads the package's packument through the gated pipeline.
func (f *npmFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !isNPMPackageName(name) {
		return nil, Permanent(fmt.Errorf("%q is not an npm package name", name))
	}
	body, err := f.k.read(ctx, "/"+name, npmAccept, maxMetadataDoc)
	if err != nil {
		return nil, err
	}
	versions, err := parseNPMPackument(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the packument of %s: %w", name, err))
	}
	rels := make([]Release, 0, len(versions))
	for _, v := range versions {
		arts, err := f.k.locate(ctx, lockfiles.Dependency{Name: name, Version: v.Version, URL: v.Tarball}, nil)
		if err != nil {
			if IsPermanent(err) {
				continue // a version whose tarball the proxy cannot serve
			}
			return nil, err
		}
		rels = append(rels, Release{Version: v.Version, Artifacts: arts})
	}
	orderReleases("npm", rels)
	return rels, nil
}

// npmVersion is one version of a packument.
type npmVersion struct {
	Version string
	Tarball string
}

// parseNPMPackument reads a packument's versions and their tarball URLs,
// sorted by version string (orderReleases puts them in version order).
func parseNPMPackument(body []byte) ([]npmVersion, error) {
	var doc struct {
		Versions map[string]struct {
			Dist struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Versions == nil {
		return nil, fmt.Errorf("it lists no versions")
	}
	out := make([]npmVersion, 0, len(doc.Versions))
	for v, m := range doc.Versions {
		if !cleanName(v) || len(v) > 256 || strings.ContainsAny(v, "/ ") || m.Dist.Tarball == "" {
			continue
		}
		out = append(out, npmVersion{Version: v, Tarball: m.Dist.Tarball})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// truncate shortens s to at most n bytes for a message.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
