package fullmirror

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/homebrew"
)

// homebrew follows homebrew-core's Git history.
//
// formulae.brew.sh is generated from Homebrew/homebrew-core, where every
// formula is a Ruby file "Formula/<shard>/<name>.rb" (the shard is the
// name's first letter, or "lib") — "Formula/<name>.rb" before the sharding —
// whose bottle block is committed once its bottles are on ghcr.io. The feed
// diffs the trees of two head commits (gitfeed_tree.go), only "Formula" and
// its shards, and reports each formula whose file changed, by name; a
// deleted file is a deleted formula. Casks live in another repository and
// are not served by the proxy: they are not followed. Commits are reported
// once they have settled (option "settle", default 30 minutes:
// formulae.brew.sh is regenerated from the repository and cached for ten
// minutes; see feed_gitsettle.go). Bootstrap lists every formula of the head.
//
// Releases reads the formula's JSON document ("/api/formula/<name>.json")
// through the gated pipeline, in which the backend has rewritten each
// bottle's URL to its synthetic "/bottle/<name>/<version>/v2/<repo>/blobs/
// sha256:<digest>" endpoint, and lists one release: the formula's current
// version, spelt as the backend spells it in those paths (versions.stable —
// without the formula's revision or the bottle's rebuild), with one artifact
// per bottle. The JSON API knows only a formula's current version, so older
// versions are never listed. The option "platforms" (comma-separated bottle
// tags, "arm64_sequoia,x86_64_linux") keeps those bottles and the "all"
// bottle a platform-independent formula has; by default every bottle is
// mirrored. A deprecated formula is mirrored (brew installs it, with a
// warning); a disabled one is not (brew refuses to install it). Both bottle
// paths — the synthetic one listed here and the registry-native one brew
// requests — share one digest-keyed cache entry in the backend.
//
// The public registry's repository is Homebrew/homebrew-core on GitHub.
// Homebrew mirrors (HOMEBREW_API_DOMAIN, HOMEBREW_BOTTLE_DOMAIN) are static
// copies without history: the Git history is followed for them with the feed
// option "url", a clone of homebrew-core — or the mirror's own formula index
// (Task 191).
//
// Index mode follows the JSON API's formula index instead,
// "<upstream>/api/formula.json": every formula with its current version and
// its bottles' URLs, regenerated within minutes of a homebrew-core change. The
// feed reads it conditionally (an unchanged index costs a 304; a changed one
// 5 MB compressed, 32 MB of JSON, 8,731 formulae on 2026-11-16), as a stream,
// a formula at a time, and keeps a record per bottle followed (of the
// platforms the option "platforms" keeps, and an "all" bottle): the formula,
// its current version and the bottle's path — the synthetic bottle endpoint
// the backend rewrites the bottle's URL to in the formula documents it serves
// (homebrew.BottlePath). Changes reports each version added and each version
// rebottled (by name and version: a bottle's path names its digest), each new
// formula and what is gone; Releases answers from the copy, without a
// request. The two cannot disagree — the formula's own document, which git
// mode reads, is cached apart from the index (ten minutes each on
// formulae.brew.sh) and rebuilt apart by mirrors, and may name an older
// version than the index for a while. A disabled formula is not followed
// (brew refuses to install it); a deprecated one is. The unsigned index is
// read rather than formula.jws.json, the signed form brew downloads: the same
// formulae, but as one JSON string, which cannot be read as a stream, and a
// signature that adds nothing here — a bottle's path names the digest the
// backend verifies it against. The index's homebrew-core commit
// ("tap_git_head") is the feed's head, its Last-Modified the head time.
//
// The option "mode" chooses: "auto" (the default) follows the Git history for
// formulae.brew.sh or when the option "url" is set, and the index otherwise (a
// mirror of the JSON API, which serves the index beneath the same URL); "git"
// and "index" choose one. In index mode the option "url" names another
// formula index to read (…/api/formula.json; the signed formula.jws.json is
// not one); "branch" and "settle" apply to the Git history only.

// homebrewPublicRepo is homebrew-core's Git repository.
const homebrewPublicRepo = "https://github.com/Homebrew/homebrew-core.git"

// homebrewPublicHosts are the names of the formulae JSON API.
var homebrewPublicHosts = []string{"formulae.brew.sh"}

// Defaults and bounds of the homebrew feed.
const (
	// homebrewDefaultSettle is how old a commit must be before it is
	// reported.
	homebrewDefaultSettle = 30 * time.Minute
	// homebrewMaxFormula bounds a formula document (a few KB).
	homebrewMaxFormula = 16 << 20
	// homebrewMaxBottles bounds the bottles of a formula (about ten).
	homebrewMaxBottles = 256
)

// Modes of the homebrew feed (option "mode").
const (
	homebrewModeAuto  = "auto"
	homebrewModeGit   = "git"
	homebrewModeIndex = "index"
)

type homebrewFeed struct {
	k      kit
	git    *gitIndex
	settle time.Duration
	now    func() time.Time
	// platforms are the bottle tags kept; nil keeps every bottle.
	platforms map[string]bool
	// index follows the formula index instead of the Git history (index
	// mode); nil in Git mode.
	index *indexFeed
}

func newHomebrewFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "branch", "settle", "platforms", "mode")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	mode, err := opts.oneOf("mode", homebrewModeAuto, homebrewModeGit, homebrewModeIndex)
	if err != nil {
		return nil, err
	}
	if mode == homebrewModeAuto {
		mode = homebrewModeIndex
		if opts["url"] != "" || hostIs(k.upstream, homebrewPublicHosts...) {
			mode = homebrewModeGit
		}
	}
	if mode == homebrewModeIndex {
		return newHomebrewIndexFeed(env, k, opts)
	}
	var repo *url.URL
	switch {
	case opts["url"] != "":
		if repo, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	case hostIs(k.upstream, homebrewPublicHosts...):
		repo, _ = url.Parse(homebrewPublicRepo)
	default:
		return nil, fmt.Errorf("upstream %s is not formulae.brew.sh, whose repository is known: set fullMirror.feed.url to a clone of homebrew-core (a Homebrew mirror's static copy has no history: follow its formula index with the feed option mode: index)", k.upstream.Redacted())
	}
	settle, err := gitSettleOption(opts, homebrewDefaultSettle)
	if err != nil {
		return nil, err
	}
	platforms, err := homebrewParsePlatforms(opts["platforms"])
	if err != nil {
		return nil, err
	}
	g, err := newGitIndex(k, gitIndexSpec{typ: "homebrew", area: homebrewArea, coordinate: homebrewCoordinate}, repo, opts["branch"])
	if err != nil {
		return nil, err
	}
	return &homebrewFeed{k: k, git: g, settle: settle, now: time.Now, platforms: platforms}, nil
}

func init() { Register("homebrew", newHomebrewFeed) }

// homebrewParsePlatforms reads the "platforms" option: bottle tags separated
// by commas.
func homebrewParsePlatforms(v string) (map[string]bool, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	out := map[string]bool{}
	for _, tag := range strings.Split(v, ",") {
		tag = strings.TrimSpace(tag)
		if !homebrewValidTag(tag) {
			return nil, fmt.Errorf("option platforms: %q is not a bottle tag (like arm64_sequoia or x86_64_linux)", tag)
		}
		out[tag] = true
	}
	return out, nil
}

// homebrewValidTag reports whether s is a bottle tag: lower-case letters,
// digits and "_".
func homebrewValidTag(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// homebrewArea admits the root, "Formula" and its shards.
func homebrewArea(dir string) bool {
	if dir == "" || dir == "Formula" {
		return true
	}
	shard, ok := strings.CutPrefix(dir, "Formula/")
	return ok && shard != "" && !strings.Contains(shard, "/") && !strings.HasPrefix(shard, ".")
}

// homebrewCoordinate maps a changed formula file — "Formula/<shard>/<name>.rb"
// or the unsharded "Formula/<name>.rb" — to the formula.
func homebrewCoordinate(p string, c gitChange) (Coordinate, bool) {
	rest, ok := strings.CutPrefix(p, "Formula/")
	if !ok {
		return Coordinate{}, false
	}
	if shard, file, nested := strings.Cut(rest, "/"); nested {
		if shard == "" || strings.Contains(file, "/") {
			return Coordinate{}, false
		}
		rest = file
	}
	name, ok := strings.CutSuffix(rest, ".rb")
	if !ok || !homebrewValidName(name) {
		return Coordinate{}, false
	}
	return Coordinate{Name: name, Deleted: c == gitDeleted}, true
}

// homebrewValidName reports whether s is a formula name the backend serves a
// document for: lower-case letters, digits and "+", "-", "_", ".", "@",
// starting with a letter or digit ("openssl@3", "libxml++").
func homebrewValidName(s string) bool {
	if len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("+-_.@", c) >= 0) {
			return false
		}
	}
	_, ok := homebrew.FormulaDocumentPath(s)
	return ok
}

func (f *homebrewFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	if f.index != nil {
		return f.index.Bootstrap(ctx, cursor)
	}
	return f.git.bootstrap(ctx, cursor)
}

// Changes diffs the stored commit against the newest settled one (in index
// mode: the stored copy of the index against the index read now).
func (f *homebrewFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	if f.index != nil {
		return f.index.Changes(ctx, cursor)
	}
	b, err := gitSettleChanges(ctx, f.git, cursor, f.settle, f.now())
	if err != nil {
		return Batch{}, err
	}
	b.Items = homebrewDropMoved(b.Items)
	return b, nil
}

// homebrewDropMoved drops the removal of a formula whose file moved (into a
// shard, or from one to another): the formula is still there, changed.
func homebrewDropMoved(items []Coordinate) []Coordinate {
	present := map[string]bool{}
	for _, c := range items {
		if !c.Deleted {
			present[c.Name] = true
		}
	}
	out := items[:0:0]
	for _, c := range items {
		if !c.Deleted || !present[c.Name] {
			out = append(out, c)
		}
	}
	return out
}

// Releases reads the formula's JSON document through the gated pipeline: its
// current version, with the bottles the backend rewrote through the proxy. In
// index mode it answers from the copy of the index: the version and bottles
// the change was reported for.
func (f *homebrewFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !homebrewValidName(name) {
		return nil, Permanent(fmt.Errorf("%q is not a formula name", name))
	}
	if f.index != nil {
		recs, err := f.index.lookup(name)
		if err != nil {
			return nil, err
		}
		return withArtifacts(snapReleases(recs)), nil
	}
	doc, _ := homebrew.FormulaDocumentPath(name)
	body, err := f.k.read(ctx, doc, "", homebrewMaxFormula)
	if err != nil {
		return nil, err
	}
	fm, err := homebrewParseFormula(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the formula document of %s: %w", name, err))
	}
	if fm.disabled {
		return nil, nil // brew refuses to install it
	}
	if fm.version == "" {
		return nil, Permanent(fmt.Errorf("the formula document of %s states no stable version", name))
	}
	var arts []Artifact
	for _, b := range fm.bottles {
		if f.platforms != nil && b.tag != "all" && !f.platforms[b.tag] {
			continue
		}
		if p, ok := f.bottlePath(b.url, name, fm.version); ok {
			arts = append(arts, Artifact{Path: p})
		}
	}
	if len(arts) == 0 {
		return nil, nil // no bottle (of the platforms kept) the proxy serves
	}
	return []Release{{Version: fm.version, Artifacts: arts}}, nil
}

// bottlePath maps a bottle URL the backend rewrote to the synthetic bottle
// path it serves, for the formula and version the document is of. A URL the
// backend left pointing at its origin (a bottle on another host than the
// bottle registry) is not one the proxy serves.
func (f *homebrewFeed) bottlePath(raw, name, version string) (string, bool) {
	p, ok := f.k.proxyPath(raw)
	if !ok {
		return "", false
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(segs) < 4 || segs[0] != "bottle" {
		return "", false
	}
	n, err1 := url.PathUnescape(segs[1])
	v, err2 := url.PathUnescape(segs[2])
	if err1 != nil || err2 != nil || n != name || v != version {
		return "", false
	}
	return p, true
}

// homebrewFormula is what Releases reads from a formula document.
type homebrewFormula struct {
	name     string
	version  string
	disabled bool
	// bottles are sorted by tag.
	bottles []homebrewBottle
}

// homebrewBottle is one bottle: its tag and its (rewritten) URL.
type homebrewBottle struct {
	tag string
	url string
}

// homebrewParseFormula reads a formula document: its name, its stable
// version, whether it is disabled, and its bottles' URLs by tag.
func homebrewParseFormula(body []byte) (homebrewFormula, error) {
	var doc struct {
		Name     string `json:"name"`
		Versions *struct {
			Stable *string `json:"stable"`
		} `json:"versions"`
		Disabled bool `json:"disabled"`
		Bottle   struct {
			Stable struct {
				Files map[string]struct {
					URL string `json:"url"`
				} `json:"files"`
			} `json:"stable"`
		} `json:"bottle"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return homebrewFormula{}, err
	}
	if doc.Name == "" || doc.Versions == nil {
		return homebrewFormula{}, fmt.Errorf("it is not a formula (no name or versions)")
	}
	fm := homebrewFormula{name: doc.Name, disabled: doc.Disabled}
	if s := doc.Versions.Stable; s != nil {
		if v := strings.TrimSpace(*s); v != "" && len(v) <= 256 && cleanName(v) && !strings.Contains(v, "/") {
			fm.version = v
		}
	}
	if len(doc.Bottle.Stable.Files) > homebrewMaxBottles {
		return homebrewFormula{}, fmt.Errorf("it lists %d bottles; at most %d are followed", len(doc.Bottle.Stable.Files), homebrewMaxBottles)
	}
	for tag, file := range doc.Bottle.Stable.Files {
		if homebrewValidTag(tag) && file.URL != "" {
			fm.bottles = append(fm.bottles, homebrewBottle{tag: tag, url: file.URL})
		}
	}
	sort.Slice(fm.bottles, func(i, j int) bool { return fm.bottles[i].tag < fm.bottles[j].tag })
	return fm, nil
}

// Bounds of the homebrew feed's index mode.
const (
	// homebrewMaxIndex bounds the formula index, as served and decompressed
	// (formulae.brew.sh's is 32 MB of JSON, 5 MB gzipped).
	homebrewMaxIndex = 512 << 20
	// homebrewMaxIndexEntry bounds what one formula of the index may make the
	// decoder hold (the largest is 43 KB).
	homebrewMaxIndexEntry = homebrewMaxFormula
)

// newHomebrewIndexFeed builds the feed of index mode.
func newHomebrewIndexFeed(env Env, k kit, opts options) (Feed, error) {
	for _, key := range []string{"branch", "settle"} {
		if opts[key] != "" {
			return nil, fmt.Errorf("the option %s applies to the Git history (mode git); this feed follows the formula index (mode index)", key)
		}
	}
	index := join(k.upstream, "api/formula.json")
	if opts["url"] != "" {
		u, err := parseBaseURL("the feed option url", opts["url"])
		if err != nil {
			return nil, err
		}
		if !strings.HasSuffix(u.Path, ".json") || strings.HasSuffix(u.Path, ".jws.json") {
			return nil, fmt.Errorf("in index mode the feed option url names the formula index to read (…/api/formula.json, not the signed formula.jws.json), not %s", u.Redacted())
		}
		index = u.String()
	}
	platforms, err := homebrewParsePlatforms(opts["platforms"])
	if err != nil {
		return nil, err
	}
	src := &homebrewIndexSource{k: k, url: index, platforms: platforms, registry: env.Settings["bottleRegistryUrl"]}
	return &homebrewFeed{k: k, now: time.Now, platforms: platforms, index: newIndexFeed("homebrew", env, src)}, nil
}

// homebrewIndexSource reads a Homebrew JSON API's formula index.
type homebrewIndexSource struct {
	k   kit
	url string
	// platforms are the bottle tags followed; nil follows every bottle.
	platforms map[string]bool
	// registry is the upstream's bottleRegistryUrl setting: the registry
	// whose bottle URLs the backend rewrites.
	registry string
}

// readIndex reads the formula index into a record per bottle followed.
func (s *homebrewIndexSource) readIndex(ctx context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error) {
	var val httpValidators
	if old == nil || len(prev) == 0 || json.Unmarshal(prev, &val) != nil || !homebrewUsableValidators(val) {
		// Without a copy to fall back on, or validators to send, the index
		// is read in full.
		val = httpValidators{}
	}
	hdr := http.Header{"Accept": {"application/json"}, "Accept-Encoding": {"gzip"}}
	val.set(hdr)
	resp, body, err := s.k.getStream(ctx, s.url, hdr, homebrewMaxIndex)
	if errors.Is(err, errNotModified) {
		if old == nil {
			return indexRead{}, fmt.Errorf("the formula index answered an unconditional request with 304")
		}
		return indexRead{Unchanged: true}, nil
	}
	if err != nil {
		return indexRead{}, fmt.Errorf("reading the formula index: %w", err)
	}
	defer body.Close()
	content, release, err := openContent(body, s.url, homebrewMaxIndex)
	defer release()
	if err != nil {
		return indexRead{}, err
	}
	head, err := homebrewParseIndex(content, func(e homebrewIndexEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, r := range homebrewIndexRecords(e, s.platforms, s.registry) {
			b.Add(r)
		}
		return nil
	})
	if err != nil {
		return indexRead{}, err
	}
	state, err := json.Marshal(validatorsOf(resp))
	if err != nil {
		return indexRead{}, err
	}
	rd := indexRead{State: state, Head: head}
	if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		rd.HeadTime = t.UTC()
	}
	return rd, nil
}

// homebrewUsableValidators reports whether validators kept in a cursor —
// which is not trusted — can go back into a request header.
func homebrewUsableValidators(v httpValidators) bool {
	for _, h := range []string{v.ETag, v.LastModified} {
		if len(h) > 512 {
			return false
		}
		for i := 0; i < len(h); i++ {
			if c := h[i]; c < 0x20 && c != '\t' || c == 0x7f {
				return false
			}
		}
	}
	return true
}

// homebrewIndexEntry is what the feed keeps of a formula of the index.
type homebrewIndexEntry struct {
	name     string
	version  string
	disabled bool
	// bottles are the bottles' tags and URLs, sorted by tag.
	bottles []homebrewIndexBottle
}

// homebrewIndexBottle is one bottle of a formula of the index.
type homebrewIndexBottle struct {
	tag, url string
}

// homebrewIndexRecords are a formula's records: a record per bottle followed
// (every bottle when platforms is nil; else those tags and "all"), at the path
// the backend rewrites the bottle's URL to in the documents it serves — of a
// bottle on the upstream's bottle registry (registry, the bottleRegistryUrl
// setting). A disabled formula, or one without a stable version, has none.
func homebrewIndexRecords(e homebrewIndexEntry, platforms map[string]bool, registry string) []snapRecord {
	if e.disabled || e.version == "" {
		return nil
	}
	var out []snapRecord
	for _, b := range e.bottles {
		if platforms != nil && b.tag != "all" && !platforms[b.tag] {
			continue
		}
		if p, ok := homebrew.BottlePath(registry, b.url, e.name, e.version); ok {
			out = append(out, snapRecord{Name: e.name, Version: e.version, Path: p})
		}
	}
	return out
}

// homebrewIndexFormula is the part of a formula of the index the feed reads.
type homebrewIndexFormula struct {
	Name     string `json:"name"`
	Versions struct {
		Stable *string `json:"stable"`
	} `json:"versions"`
	Disabled   bool   `json:"disabled"`
	TapGitHead string `json:"tap_git_head"`
	Bottle     struct {
		Stable *struct {
			Files map[string]struct {
				URL string `json:"url"`
			} `json:"files"`
		} `json:"stable"`
	} `json:"bottle"`
}

// entry checks a formula of the index; ok is false for one the feed does not
// follow (a name the backend serves no document for, too many bottles).
func (f homebrewIndexFormula) entry() (homebrewIndexEntry, bool) {
	if !homebrewValidName(f.Name) {
		return homebrewIndexEntry{}, false
	}
	e := homebrewIndexEntry{name: f.Name, disabled: f.Disabled}
	if s := f.Versions.Stable; s != nil {
		if v := strings.TrimSpace(*s); v != "" && len(v) <= 256 && cleanName(v) && !strings.Contains(v, "/") {
			e.version = v
		}
	}
	if st := f.Bottle.Stable; st != nil {
		if len(st.Files) > homebrewMaxBottles {
			return homebrewIndexEntry{}, false
		}
		for tag, file := range st.Files {
			if homebrewValidTag(tag) && file.URL != "" && len(file.URL) <= 4096 {
				e.bottles = append(e.bottles, homebrewIndexBottle{tag: tag, url: file.URL})
			}
		}
		sort.Slice(e.bottles, func(i, j int) bool { return e.bottles[i].tag < e.bottles[j].tag })
	}
	return e, true
}

// homebrewIndexGuard is the index's reader under the JSON decoder: it bounds
// what the decoder holds for one formula — it buffers a value whole — and
// keeps the error of the stream itself (a network error is retried, a
// malformed index is not).
type homebrewIndexGuard struct {
	r io.Reader
	// read is how many bytes the decoder has been given, start the offset in
	// the stream where the value being decoded began.
	read, start int64
	err         error
}

func (g *homebrewIndexGuard) Read(p []byte) (int, error) {
	// The decoder reads in chunks that grow with its buffer: each read is
	// cut to what the value may still take, so the bound holds to the byte.
	left := homebrewMaxIndexEntry - (g.read - g.start)
	if left < 0 {
		g.err = Permanent(fmt.Errorf("a formula of the index is larger than %d bytes", homebrewMaxIndexEntry))
		return 0, g.err
	}
	if int64(len(p)) > left+1 {
		p = p[:left+1]
	}
	n, err := g.r.Read(p)
	g.read += int64(n)
	if err != nil && err != io.EOF {
		g.err = err
	}
	return n, err
}

// homebrewParseIndex reads a formula index — a JSON array of formulae — as a
// stream, one formula at a time, and calls fn for each one the feed follows;
// it returns the homebrew-core commit the index was generated from, when it
// says. A formula of another shape is skipped; an index that is not a JSON
// array of formulae is a permanent error. An error fn returns stops the read
// and is returned.
func homebrewParseIndex(r io.Reader, fn func(homebrewIndexEntry) error) (string, error) {
	g := &homebrewIndexGuard{r: r}
	dec := json.NewDecoder(g)
	fail := func(err error) (string, error) {
		if g.err != nil {
			return "", g.err
		}
		return "", Permanent(fmt.Errorf("the formula index does not read as JSON: %w", err))
	}
	tok, err := dec.Token()
	if err != nil {
		return fail(err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return "", Permanent(errors.New("the formula index is not a JSON array"))
	}
	head := ""
	for dec.More() {
		g.start = dec.InputOffset()
		var f homebrewIndexFormula
		if err := dec.Decode(&f); err != nil {
			var te *json.UnmarshalTypeError
			if errors.As(err, &te) && g.err == nil {
				// A formula of another shape (the decoder has read past
				// it): not followed.
				continue
			}
			return fail(err)
		}
		e, ok := f.entry()
		if !ok {
			continue
		}
		if head == "" && homebrewValidCommit(f.TapGitHead) {
			head = f.TapGitHead
		}
		if err := fn(e); err != nil {
			return "", err
		}
	}
	g.start = dec.InputOffset()
	if _, err := dec.Token(); err != nil {
		return fail(err)
	}
	return head, nil
}

// homebrewValidCommit reports whether s is a Git commit id (40 lower-case
// hex digits).
func homebrewValidCommit(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
