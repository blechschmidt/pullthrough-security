package fullmirror

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// cargo follows a Cargo registry's Git index.
//
// The sparse index the cargo backend fronts has no listing and no change feed,
// so the feed is the registry's Git index: one file per crate, laid out by the
// crate's name, changed by every publish and yank. Changes diffs the stored
// head's trees against the new head's (gitfeed_tree.go) and reports each crate
// whose index file changed — by name, since a file names no single version;
// the engine then considers the versions its policy keeps, and the cache
// check makes the ones already held cheap. A deleted index file is a deleted
// crate. Bootstrap lists every crate file of the head.
//
// Releases reads the crate's index file from the sparse index through the
// gated pipeline (what cargo reads) and takes each version's download path
// from repos/locate's cargo locator: "/api/v1/crates/<name>/<version>/download",
// which the backend rewrote config.json's "dl" to.
//
// The public registry's Git index is rust-lang/crates.io-index on GitHub. A
// private registry's must be named with the feed option "url" (Artifactory,
// Cloudsmith and self-hosted registries that keep one); a registry that only
// serves a sparse index cannot be followed.

// cargoPublicIndex is crates.io's Git index.
const cargoPublicIndex = "https://github.com/rust-lang/crates.io-index.git"

// cargoPublicHosts are the names of crates.io's sparse index and API.
var cargoPublicHosts = []string{"index.crates.io", "crates.io", "static.crates.io"}

type cargoFeed struct {
	k   kit
	git *gitIndex
}

func newCargoFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "branch")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	var repo *url.URL
	switch {
	case opts["url"] != "":
		if repo, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	case hostIs(k.upstream, cargoPublicHosts...):
		repo, _ = url.Parse(cargoPublicIndex)
	default:
		return nil, fmt.Errorf("upstream %s is not crates.io, whose Git index is known: set fullMirror.feed.url to the registry's Git index (a registry that serves only a sparse index cannot be followed)", k.upstream.Redacted())
	}
	g, err := newGitIndex(k, gitIndexSpec{typ: "cargo", area: cargoArea, coordinate: cargoCoordinate}, repo, opts["branch"])
	if err != nil {
		return nil, err
	}
	return &cargoFeed{k: k, git: g}, nil
}

func init() { Register("cargo", newCargoFeed) }

// cargoArea admits the index's directories: "1", "2", "3/<c>" and
// "<ab>/<cd>" — never a dot directory (".github").
func cargoArea(dir string) bool {
	if dir == "" {
		return true
	}
	parts := strings.Split(dir, "/")
	if len(parts) > 2 || strings.HasPrefix(parts[0], ".") {
		return false
	}
	switch parts[0] {
	case "1", "2":
		return len(parts) == 1
	case "3":
		return len(parts) == 1 || len(parts[1]) == 1
	}
	return len(parts[0]) == 2 && (len(parts) == 1 || len(parts[1]) == 2)
}

// cargoIndexPath is where the index keeps a crate's file (the sparse index
// and the Git index share the layout): by the lower-cased name's length and
// first characters.
func cargoIndexPath(name string) string {
	n := strings.ToLower(name)
	switch len(n) {
	case 0:
		return ""
	case 1:
		return "1/" + n
	case 2:
		return "2/" + n
	case 3:
		return "3/" + n[:1] + "/" + n
	}
	return n[:2] + "/" + n[2:4] + "/" + n
}

// isCrateName reports whether s is a crate name the index can hold: ASCII
// letters, digits, "-" and "_", at most 64 characters.
func isCrateName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// cargoCoordinate maps a changed index file to its crate.
func cargoCoordinate(p string, c gitChange) (Coordinate, bool) {
	name := p[strings.LastIndexByte(p, '/')+1:]
	if !isCrateName(name) || cargoIndexPath(name) != p {
		return Coordinate{}, false // config.json, a README, a stray file
	}
	return Coordinate{Name: name, Deleted: c == gitDeleted}, true
}

func (f *cargoFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	return f.git.bootstrap(ctx, cursor)
}

func (f *cargoFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	return f.git.changes(ctx, cursor)
}

// Releases reads the crate's sparse index file through the gated pipeline.
func (f *cargoFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !isCrateName(name) {
		return nil, Permanent(fmt.Errorf("%q is not a crate name", name))
	}
	body, err := f.k.read(ctx, "/"+cargoIndexPath(name), "", maxMetadataDoc)
	if err != nil {
		return nil, err
	}
	entries, err := parseCargoIndexFile(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the index file of %s: %w", name, err))
	}
	rels := make([]Release, 0, len(entries))
	for _, e := range entries {
		if !strings.EqualFold(e.Name, name) {
			// An index file speaks for its own crate only: a line naming
			// another would have the mirror fetch that crate around the
			// name patterns.
			continue
		}
		arts, err := f.k.locate(ctx, lockfiles.Dependency{Name: e.Name, Version: e.Version}, nil)
		if err != nil {
			if IsPermanent(err) {
				continue
			}
			return nil, err
		}
		rels = append(rels, Release{Version: e.Version, Published: e.Published, Yanked: e.Yanked, Artifacts: arts})
	}
	return rels, nil
}

// cargoIndexEntry is one version line of an index file.
type cargoIndexEntry struct {
	Name      string
	Version   string
	Yanked    bool
	Published time.Time
}

// parseCargoIndexFile reads an index file: one JSON object per line, in
// publication order. Lines that do not name a version are skipped; a file
// none of whose lines parse is an error.
func parseCargoIndexFile(body []byte) ([]cargoIndexEntry, error) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	var out []cargoIndexEntry
	lines := 0
	seen := map[string]bool{}
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		lines++
		var e struct {
			Name    string `json:"name"`
			Vers    string `json:"vers"`
			Yanked  bool   `json:"yanked"`
			Pubtime string `json:"pubtime"`
		}
		if json.Unmarshal(line, &e) != nil || !isCrateName(e.Name) || e.Vers == "" || len(e.Vers) > 256 ||
			strings.ContainsAny(e.Vers, "/ \\?#%") || !cleanName(e.Vers) || seen[e.Vers] {
			continue
		}
		seen[e.Vers] = true
		entry := cargoIndexEntry{Name: e.Name, Version: e.Vers, Yanked: e.Yanked}
		if t, err := time.Parse(time.RFC3339, e.Pubtime); err == nil {
			entry.Published = t
		}
		out = append(out, entry)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if lines > 0 && len(out) == 0 {
		return nil, fmt.Errorf("none of its %d lines names a version", lines)
	}
	return out, nil
}
