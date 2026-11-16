package fullmirror

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/conan"
)

// conan follows ConanCenter through conan-center-index's Git history.
//
// A Conan v2 remote has a recipe search and per-reference revision pointers,
// but no change feed. ConanCenter's recipes live in conan-center-index — one
// directory per recipe, "recipes/<name>/config.yml" mapping its versions to
// recipe folders ("all", "1.x", …) — and a merged change is promoted to
// center2.conan.io as a new recipe revision. The feed diffs the trees of two
// head commits (gitfeed_tree.go) and reports each recipe whose directory
// changed, by name only: one change can bring a new recipe revision of every
// version the recipe serves. The removal of a recipe's config.yml is the
// recipe's removal. The test packages ("test_package", "test_v1_package", …)
// are not exported with a recipe and do not change its revision: they lie
// outside the trees followed. Commits are reported once they have settled
// (option "settle", default one hour: ConanCenter promotes a merged change's
// packages "within a few minutes" and serves the revision pointers from a
// CDN; see feed_gitsettle.go). Bootstrap lists every recipe of the head.
//
// Releases asks the remote which versions it serves: its recipe search for
// the name ("GET /v2/conans/search?q=<name>/*", sent to the upstream
// directly — the gated pipeline reads paths without a query — with the
// upstream's credentials), keeping the references of exactly that name
// without a user and channel. The versions are ordered as Conan orders them
// (conanVersionCompare); the search lists them as strings. Then, through the
// gated pipeline, each version's latest recipe revision and its file list:
// the files of that revision are the version's artifacts (conanfile.py,
// conanmanifest.txt, conan_export.tgz, conan_sources.tgz — the backend
// checks each against the revision's manifest or the remote's checksum
// header). Older recipe revisions, which a lock file may pin, are fetched by
// the first client that asks.
//
// Binary packages follow the option "binaries": "none" (the default), "all",
// or a filter over the package search of the recipe revision — alternatives
// separated by ";", each a ","-separated list of setting=value conditions
// that must all hold ("options.<name>=value" tests an option), values
// compared without regard to case: "os=Linux,arch=x86_64;os=Macos,arch=armv8".
// Each selected package's latest package revision and its files
// (conaninfo.txt, conanmanifest.txt, conan_package.tgz) are artifacts too.
//
// Requests per version: two reads through the pipeline for the recipe (the
// latest pointer, served live; the file list, cached by the proxy once
// read), plus with binaries one package search and two reads per selected
// package (its latest pointer; its file list, cached). And one search per
// Releases call.
//
// The public remote's recipes are conan-io/conan-center-index on GitHub.
// Artifactory, Nexus and conan_server remotes have no feed: they need the
// feed option "url", a Git repository laid out as conan-center-index (the
// repository a local-recipes-index remote serves is one), or cannot be
// followed.

// conanPublicRepo is ConanCenter's recipe repository.
const conanPublicRepo = "https://github.com/conan-io/conan-center-index.git"

// conanPublicHosts are the names of ConanCenter's Conan 2 remote.
var conanPublicHosts = []string{"center2.conan.io"}

// Defaults and bounds of the conan feed.
const (
	// conanDefaultSettle is how old a commit must be before it is reported.
	conanDefaultSettle = time.Hour
	// conanMaxSearch bounds a search response (every recipe of the remote
	// is about 220 KB).
	conanMaxSearch = 16 << 20
	// conanMaxDoc bounds a revision pointer, a file list or a package
	// search.
	conanMaxDoc = 16 << 20
	// conanMaxVersions bounds the versions of one recipe.
	conanMaxVersions = 4096
	// conanMaxFiles bounds the files of one revision.
	conanMaxFiles = 1024
	// conanMaxPackages bounds the binary packages of one recipe revision.
	conanMaxPackages = 4096
)

type conanFeed struct {
	k        kit
	git      *gitIndex
	settle   time.Duration
	now      func() time.Time
	binaries conanBinaries
}

func newConanFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "branch", "settle", "binaries")
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
	case hostIs(k.upstream, conanPublicHosts...):
		repo, _ = url.Parse(conanPublicRepo)
	default:
		return nil, fmt.Errorf("upstream %s is not ConanCenter, whose recipe repository is known: set fullMirror.feed.url to a Git repository laid out as conan-center-index (Artifactory, Nexus and conan_server remotes have no feed of their own)", k.upstream.Redacted())
	}
	settle, err := gitSettleOption(opts, conanDefaultSettle)
	if err != nil {
		return nil, err
	}
	bins, err := conanParseBinaries(opts["binaries"])
	if err != nil {
		return nil, err
	}
	g, err := newGitIndex(k, gitIndexSpec{typ: "conan", area: conanArea, coordinate: conanCoordinate}, repo, opts["branch"])
	if err != nil {
		return nil, err
	}
	return &conanFeed{k: k, git: g, settle: settle, now: time.Now, binaries: bins}, nil
}

func init() { Register("conan", newConanFeed) }

// conanArea admits the root, "recipes" and everything beneath a recipe's
// directory except the test packages inside its folders, which are not
// exported with the recipe.
func conanArea(dir string) bool {
	if dir == "" || dir == "recipes" {
		return true
	}
	rest, ok := strings.CutPrefix(dir, "recipes/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	if !conanValidPart(parts[0]) {
		return false
	}
	for _, d := range parts[min(len(parts), 2):] {
		if strings.HasPrefix(d, "test_") {
			return false
		}
	}
	return true
}

// conanCoordinate maps a changed file beneath "recipes/<name>/" to the
// recipe. Only the removal of config.yml removes the recipe; any other
// change, a removed patch included, can change its revision.
func conanCoordinate(p string, c gitChange) (Coordinate, bool) {
	parts := strings.Split(p, "/")
	if len(parts) < 3 || parts[0] != "recipes" || !conanValidPart(parts[1]) {
		return Coordinate{}, false
	}
	if c == gitDeleted && len(parts) == 3 && parts[2] == "config.yml" {
		return Coordinate{Name: parts[1], Deleted: true}, true
	}
	return Coordinate{Name: parts[1]}, true
}

// conanValidPart reports whether s is a name or a version as Conan 2 accepts
// them: a letter, digit or "_", then 1 to 100 of those or "+", ".", "-".
func conanValidPart(s string) bool {
	if len(s) < 2 || len(s) > 101 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		case (c == '+' || c == '.' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

func (f *conanFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	return f.git.bootstrap(ctx, cursor)
}

// Changes diffs the stored commit against the newest settled one.
func (f *conanFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	b, err := gitSettleChanges(ctx, f.git, cursor, f.settle, f.now())
	if err != nil {
		return Batch{}, err
	}
	b.Items = conanDropRemoved(b.Items)
	return b, nil
}

// conanDropRemoved reports a removed recipe once, as removed: the removal of
// its other files does not also make it a changed one.
func conanDropRemoved(items []Coordinate) []Coordinate {
	removed := map[string]bool{}
	for _, c := range items {
		if c.Deleted {
			removed[c.Name] = true
		}
	}
	if len(removed) == 0 {
		return items
	}
	out := items[:0:0]
	for _, c := range items {
		if c.Deleted || !removed[c.Name] {
			out = append(out, c)
		}
	}
	return out
}

// Releases lists the versions the remote serves of a recipe, each with the
// files of its latest recipe revision (and of the binary packages the
// "binaries" option selects).
func (f *conanFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !conanValidPart(name) {
		return nil, Permanent(fmt.Errorf("%q is not a Conan recipe name", name))
	}
	q := url.Values{"q": {name + "/*"}}
	body, _, err := f.k.get(ctx, join(f.k.upstream, conan.RecipeSearchPath())+"?"+q.Encode(), http.Header{"Accept": {"application/json"}}, conanMaxSearch)
	if err != nil {
		return nil, fmt.Errorf("searching the remote for %s: %w", name, err)
	}
	versions, err := conanParseSearch(name, body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the remote's search for %s: %w", name, err))
	}
	if len(versions) == 0 {
		return nil, Permanent(fmt.Errorf("the remote has no recipe %s (not found)", name))
	}
	rels := make([]Release, 0, len(versions))
	var first error
	for _, v := range versions {
		r, err := f.release(ctx, name, v)
		if err != nil {
			if IsPermanent(err) {
				if first == nil {
					first = err
				}
				continue // a version whose recipe the proxy cannot serve
			}
			return nil, err
		}
		rels = append(rels, r)
	}
	if len(rels) == 0 && first != nil {
		return nil, first
	}
	return rels, nil
}

// release reads a version's latest recipe revision and its files.
func (f *conanFeed) release(ctx context.Context, name, version string) (Release, error) {
	lp, ok := conan.RecipeLatestPath(name, version)
	if !ok {
		return Release{}, Permanent(fmt.Errorf("%s %s is not a reference the remote's layout can hold", name, version))
	}
	rev, err := f.revision(ctx, lp)
	if err != nil {
		return Release{}, err
	}
	fp, ok := conan.RecipeFilesPath(name, version, rev.id)
	if !ok {
		return Release{}, Permanent(fmt.Errorf("recipe revision %q of %s %s", rev.id, name, version))
	}
	files, err := f.files(ctx, fp)
	if err != nil {
		return Release{}, err
	}
	var arts []Artifact
	for _, file := range files {
		if p, ok := conan.RecipeFilePath(name, version, rev.id, file); ok {
			arts = append(arts, Artifact{Path: p})
		}
	}
	if len(arts) == 0 {
		return Release{}, Permanent(fmt.Errorf("recipe revision %s of %s %s lists no file", rev.id, name, version))
	}
	if f.binaries.mode != conanBinariesNone {
		pkgs, err := f.packages(ctx, name, version, rev.id)
		if err != nil {
			return Release{}, err
		}
		arts = append(arts, pkgs...)
	}
	return Release{Version: version, Published: rev.time, Artifacts: arts}, nil
}

// packages lists the files of the binary packages of a recipe revision the
// "binaries" option selects. A package search or package the remote does
// not serve (or a gate refuses) leaves those binaries out; the recipe is
// still mirrored.
func (f *conanFeed) packages(ctx context.Context, name, version, rrev string) ([]Artifact, error) {
	sp, ok := conan.PackageSearchPath(name, version, rrev)
	if !ok {
		return nil, nil
	}
	body, err := f.k.read(ctx, sp, "", conanMaxDoc)
	if err != nil {
		if IsPermanent(err) {
			return nil, nil
		}
		return nil, err
	}
	pkgs, err := conanParsePackages(body)
	if err != nil {
		return nil, nil
	}
	var arts []Artifact
	for _, p := range pkgs {
		if !f.binaries.selects(p) {
			continue
		}
		lp, ok := conan.PackageLatestPath(name, version, rrev, p.id)
		if !ok {
			continue
		}
		rev, err := f.revision(ctx, lp)
		if err != nil {
			if IsPermanent(err) {
				continue
			}
			return nil, err
		}
		fp, ok := conan.PackageFilesPath(name, version, rrev, p.id, rev.id)
		if !ok {
			continue
		}
		files, err := f.files(ctx, fp)
		if err != nil {
			if IsPermanent(err) {
				continue
			}
			return nil, err
		}
		for _, file := range files {
			if path, ok := conan.PackageFilePath(name, version, rrev, p.id, rev.id, file); ok {
				arts = append(arts, Artifact{Path: path})
			}
		}
	}
	return arts, nil
}

// revision reads a latest-revision pointer through the gated pipeline.
func (f *conanFeed) revision(ctx context.Context, path string) (conanRevision, error) {
	body, err := f.k.read(ctx, path, "", conanMaxDoc)
	if err != nil {
		return conanRevision{}, err
	}
	rev, err := conanParseRevision(body)
	if err != nil {
		return conanRevision{}, Permanent(fmt.Errorf("%s: %w", path, err))
	}
	return rev, nil
}

// files reads a revision's file list through the gated pipeline.
func (f *conanFeed) files(ctx context.Context, path string) ([]string, error) {
	body, err := f.k.read(ctx, path, "", conanMaxDoc)
	if err != nil {
		return nil, err
	}
	files, err := conanParseFiles(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("%s: %w", path, err))
	}
	return files, nil
}

// conanParseSearch reads a recipe search response ({"results":
// ["name/version@user/channel", …]}) and returns the versions of the
// references named exactly name without a user and channel ("@_/_" or none),
// in Conan's version order.
func conanParseSearch(name string, body []byte) ([]string, error) {
	var doc struct {
		Results *[]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Results == nil {
		return nil, fmt.Errorf("the response has no results")
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range *doc.Results {
		var ref string
		if json.Unmarshal(raw, &ref) != nil {
			continue
		}
		n, rest, ok := strings.Cut(ref, "/")
		if !ok || n != name {
			continue
		}
		v, uc, _ := strings.Cut(rest, "@")
		if (uc != "" && uc != "_/_") || !conanValidPart(v) || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) > conanMaxVersions {
			return nil, fmt.Errorf("it lists more than %d versions of %s", conanMaxVersions, name)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return conanVersionCompare(out[i], out[j]) < 0 })
	return out, nil
}

// conanRevision is a revision pointer: the revision and when it was made.
type conanRevision struct {
	id   string
	time time.Time
}

// conanParseRevision reads a latest-revision pointer ({"revision": "<hex>",
// "time": "…"}).
func conanParseRevision(body []byte) (conanRevision, error) {
	var doc struct {
		Revision string `json:"revision"`
		Time     string `json:"time"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return conanRevision{}, err
	}
	if !conanValidHex(doc.Revision) {
		return conanRevision{}, fmt.Errorf("it names no revision")
	}
	rev := conanRevision{id: doc.Revision}
	for _, layout := range []string{"2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05-0700", time.RFC3339Nano} {
		if t, err := time.Parse(layout, doc.Time); err == nil {
			rev.time = t.UTC()
			break
		}
	}
	return rev, nil
}

// conanValidHex reports whether s is a revision or package ID: 1 to 64
// lower-case hex digits.
func conanValidHex(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// conanParseFiles reads a revision's file list ({"files": {"<name>": {}, …}})
// and returns its flat file names, sorted. Nested names (a revision's
// "metadata/…" files, which a plain install does not download) are left out.
func conanParseFiles(body []byte) ([]string, error) {
	var doc struct {
		Files map[string]json.RawMessage `json:"files"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Files == nil {
		return nil, fmt.Errorf("it lists no files")
	}
	if len(doc.Files) > conanMaxFiles {
		return nil, fmt.Errorf("it lists %d files; at most %d are followed", len(doc.Files), conanMaxFiles)
	}
	out := make([]string, 0, len(doc.Files))
	for name := range doc.Files {
		if conanValidFile(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// conanValidFile reports whether s is a flat file name a revision holds:
// letters, digits, ".", "_" and "-", not a dot segment.
func conanValidFile(s string) bool {
	if s == "" || len(s) > 255 || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// conanPackage is one binary package of a recipe revision.
type conanPackage struct {
	id       string
	settings map[string]string
	options  map[string]string
}

// conanParsePackages reads a recipe revision's package search ({"<package
// id>": {"settings": {…}, "options": {…}, …}}) and returns its packages,
// sorted by ID. Settings and options that are not strings are left out.
func conanParsePackages(body []byte) ([]conanPackage, error) {
	var doc map[string]struct {
		Settings map[string]json.RawMessage `json:"settings"`
		Options  map[string]json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if len(doc) > conanMaxPackages {
		return nil, fmt.Errorf("it lists %d packages; at most %d are followed", len(doc), conanMaxPackages)
	}
	strs := func(m map[string]json.RawMessage) map[string]string {
		out := make(map[string]string, len(m))
		for k, raw := range m {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				out[k] = s
			}
		}
		return out
	}
	out := make([]conanPackage, 0, len(doc))
	for id, p := range doc {
		if conanValidHex(id) {
			out = append(out, conanPackage{id: id, settings: strs(p.Settings), options: strs(p.Options)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

// Binary package selection.
const (
	conanBinariesNone = iota
	conanBinariesAll
	conanBinariesFilter
)

// conanBinaries is the "binaries" option: none, all, or a filter.
type conanBinaries struct {
	mode int
	// any are the filter's alternatives, each a list of conditions that must
	// all hold.
	any [][]conanCondition
}

// conanCondition is one setting=value (or options.<name>=value) condition.
type conanCondition struct {
	key, value string
	option     bool
}

// Bounds of a binaries filter.
const (
	conanMaxAlternatives = 64
	conanMaxConditions   = 32
)

// conanParseBinaries reads the "binaries" option.
func conanParseBinaries(v string) (conanBinaries, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "none":
		return conanBinaries{mode: conanBinariesNone}, nil
	case "all":
		return conanBinaries{mode: conanBinariesAll}, nil
	}
	b := conanBinaries{mode: conanBinariesFilter}
	for _, alt := range strings.Split(v, ";") {
		alt = strings.TrimSpace(alt)
		if alt == "" {
			continue
		}
		var conds []conanCondition
		for _, cond := range strings.Split(alt, ",") {
			k, val, ok := strings.Cut(strings.TrimSpace(cond), "=")
			k, val = strings.TrimSpace(k), strings.TrimSpace(val)
			if !ok || !conanValidSettingKey(k) || val == "" || len(val) > 128 || !cleanName(val) || strings.ContainsAny(val, "=") {
				return conanBinaries{}, fmt.Errorf("option binaries: %q is not a setting=value condition (none, all, or conditions like \"os=Linux,arch=x86_64;os=Macos,arch=armv8\")", strings.TrimSpace(cond))
			}
			c := conanCondition{key: k, value: val}
			if name, ok := strings.CutPrefix(k, "options."); ok {
				c.key, c.option = name, true
			}
			conds = append(conds, c)
		}
		if len(conds) > conanMaxConditions {
			return conanBinaries{}, fmt.Errorf("option binaries: an alternative has %d conditions; at most %d", len(conds), conanMaxConditions)
		}
		b.any = append(b.any, conds)
	}
	if len(b.any) == 0 || len(b.any) > conanMaxAlternatives {
		return conanBinaries{}, fmt.Errorf("option binaries: %d alternatives; want between 1 and %d (or none, all)", len(b.any), conanMaxAlternatives)
	}
	return b, nil
}

// conanValidSettingKey reports whether s names a setting ("os",
// "compiler.version") or an option ("options.shared").
func conanValidSettingKey(s string) bool {
	if s == "" || len(s) > 64 || s == "options." || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// selects reports whether the option keeps a package.
func (b conanBinaries) selects(p conanPackage) bool {
	switch b.mode {
	case conanBinariesNone:
		return false
	case conanBinariesAll:
		return true
	}
	for _, conds := range b.any {
		all := true
		for _, c := range conds {
			m := p.settings
			if c.option {
				m = p.options
			}
			if got, ok := m[c.key]; !ok || !strings.EqualFold(got, c.value) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// conanVersionCompare orders two versions as Conan 2's Version class does:
// the dot-separated items of the version proper, numbers by value and
// anything else as text (trailing zero items do not count, so 1.0 and 1.0.0
// tie), then a pre-release ("-…") ahead of the release, then build metadata
// ("+…") after none. Ties are broken by the text, so the order is total.
func conanVersionCompare(a, b string) int {
	if c := conanVersionCmp(a, b, 0); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func conanVersionCmp(a, b string, depth int) int {
	if depth > 8 {
		return strings.Compare(a, b)
	}
	split := func(s string) (main, pre, build string) {
		main = s
		if i := strings.LastIndexByte(main, '+'); i >= 0 {
			main, build = main[:i], main[i+1:]
		}
		if i := strings.LastIndexByte(main, '-'); i >= 0 {
			main, pre = main[:i], main[i+1:]
		}
		return main, pre, build
	}
	am, ap, ab := split(a)
	bm, bp, bb := split(b)
	if c := conanItemsCmp(am, bm); c != 0 {
		return c
	}
	switch {
	case ap != "" && bp == "":
		return -1
	case ap == "" && bp != "":
		return 1
	case ap != "" && bp != "":
		if c := conanVersionCmp(ap, bp, depth+1); c != 0 {
			return c
		}
	}
	switch {
	case ab == "" && bb != "":
		return -1
	case ab != "" && bb == "":
		return 1
	case ab != "" && bb != "":
		return conanVersionCmp(ab, bb, depth+1)
	}
	return 0
}

// conanItemsCmp compares the dot-separated items of two versions proper.
func conanItemsCmp(a, b string) int {
	trim := func(items []string) []string {
		for len(items) > 0 && conanZero(items[len(items)-1]) {
			items = items[:len(items)-1]
		}
		return items
	}
	ai, bi := trim(strings.Split(a, ".")), trim(strings.Split(b, "."))
	for i := 0; i < len(ai) && i < len(bi); i++ {
		x, y := ai[i], bi[i]
		var c int
		if conanDigits(x) && conanDigits(y) {
			// By value: without leading zeros, the longer number is the
			// larger one, and numbers of one length compare as text.
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if c = len(x) - len(y); c == 0 {
				c = strings.Compare(x, y)
			}
		} else {
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case len(ai) < len(bi):
		return -1
	case len(ai) > len(bi):
		return 1
	}
	return 0
}

// conanDigits reports whether s is a non-empty run of ASCII digits.
func conanDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// conanZero reports whether an item is the number zero.
func conanZero(s string) bool { return conanDigits(s) && strings.Trim(s, "0") == "" }
