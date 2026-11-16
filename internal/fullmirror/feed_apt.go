package fullmirror

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// apt follows the suites of one APT archive: an archive root with the "dists"
// layout (https://deb.debian.org/debian, http://archive.ubuntu.com/ubuntu, an
// aptly, reprepro, Pulp, Artifactory or Nexus repository). An archive holds
// dozens of suites, so the option "suites" (required) names those followed,
// "components" their components (default "main") and "architectures" the
// architectures (default "amd64").
//
// Every poll reads each suite's dists/<suite>/InRelease — or its Release, for
// an archive that publishes no InRelease — conditionally, with the ETag and
// Last-Modified the cursor keeps: a suite that answers 304 costs one small
// request. The Release file lists every index of the suite with its size and
// SHA-256. For each component and architecture the feed reads the Packages
// index the Release lists in the smallest compressed form it can decode (xz,
// gzip, bzip2 or zstd; uncompressed only where none is listed or served:
// Debian and Ubuntu list an uncompressed Packages they do not publish), by
// its hash when the Release says "Acquire-By-Hash: yes"
// (…/binary-<arch>/by-hash/SHA256/<hex>: a file that does not change while
// the archive is updated), verifying the size and SHA-256 of the file as the
// bytes arrive and, as it decompresses, those the Release states for the
// uncompressed index. The index is parsed as a stream of Deb822 stanzas. An
// index whose content the Release states unchanged since the last poll (the
// same SHA-256) is not read again: its records are copied from the stored
// copy. pdiffs (Packages.diff/) are not used: a changed index is read whole
// (Debian trixie's main/binary-amd64/Packages.xz is 9.7 MB).
//
// Architecture "all": Debian's Release files say "No-Support-for-Architecture-
// all: Packages" — the packages of architecture all are listed in every
// binary-<arch>/Packages (and again in binary-all, for clients that read it)
// — and Ubuntu publishes no binary-all, so the architectures configured
// suffice. A Release that lists "all" among its architectures without that
// field keeps those packages in binary-all only: binary-all is then read too.
// Listing "all" in the option reads binary-all wherever the Release lists it;
// a Release that lists no binary-all (Ubuntu's) keeps those packages in the
// binary-<arch> indexes, and "all" is skipped there.
//
// Each package file becomes a record of the stored copy (snapshot.go): its
// package name, its version as the index spells it (with its epoch), its path
// — "/" + the stanza's Filename, which the backend serves as it is — its size,
// and its SHA-256 (in full). The copy is diffed against the previous one: a
// version added or changed is reported as name@version, one gone as deleted.
// Packages lists the versions current in a suite only; a mirror keeps what it
// fetched.
//
// Releases answers from the copy: a package's versions in dpkg's version
// order, oldest first, each with its files (one per architecture and suite
// that lists it).
//
// The feed checks no signature: it verifies each Packages index it reads
// against the Release that lists it, and only chooses paths. Every file it
// lists is fetched through the proxy's gated pipeline exactly as a client's
// request: a forged Release or Packages file read here can make the mirror
// ask for a path — which any client may do — but cannot hand the backend a
// digest. The backend, though, verifies a .deb only against a digest it took
// from a Packages index it served by name (plain, gzip or bzip2); the
// indexes APT reads by hash, or as xz, record none, and this feed reads its
// indexes itself. So the .debs the mirror fetches are cached unverified
// (apt.checksumVerified "none") — unless a client happened to read their
// index by name through the proxy — as they are for clients reading by hash:
// the open finding under "How the entries were checked" in
// docs/full-mirroring.md. The records keep each file's full SHA-256 (Digest
// "sha256:<hex>") for a fetch that will check it.
//
// The feed is read from the upstream's own URL — a private archive serves the
// same layout — or from the archive root the option "url" names.

// Bounds of the apt feed.
const (
	// aptMaxRelease bounds a Release file (Ubuntu's noble: 256 KB; the
	// backend's bound).
	aptMaxRelease = 32 << 20
	// aptMaxPackagesFile bounds a compressed Packages index.
	aptMaxPackagesFile = 256 << 20
	// aptMaxPackagesBytes bounds a decompressed Packages index (Debian
	// trixie's main/binary-amd64: 56.6 MB).
	aptMaxPackagesBytes = 1 << 30
	// aptMaxSuites, and aptMaxParts the Packages indexes of all of them, bound
	// what the cursor keeps the digests of.
	aptMaxSuites = 16
	aptMaxParts  = 128
	// aptMaxLine bounds a line of a Packages index that is read whole (the
	// longest in Debian's are 75 KB): a longer one is skipped.
	aptMaxLine = 1 << 20
	// aptMaxField bounds a field the feed keeps.
	aptMaxField = 4 << 10
	// aptMaxEntries bounds the Packages entries a Release may list.
	aptMaxEntries = 100_000
	// aptMaxValidator bounds an ETag or Last-Modified kept in the cursor.
	aptMaxValidator = 128
	// aptMaxState bounds the state the cursor keeps, at its largest (every
	// validator as long as kept, each character escaped — yumKeepValidators
	// keeps none that JSON spells longer): a configuration that could exceed
	// it is refused when it is loaded.
	aptMaxState = 24 << 10
	// aptMinTime and aptMaxTime bound the dates taken from a Release.
	aptMinTime = 946684800
	aptMaxTime = 4102444800
)

// aptCompressions are the forms of a Packages index the feed decodes, by its
// file name's suffix.
var aptCompressions = []string{".xz", ".gz", ".bz2", ".zst", ""}

type aptFeed struct {
	*indexFeed
}

// aptSource reads the Packages indexes of the suites followed.
type aptSource struct {
	k          kit
	root       *url.URL
	suites     []string
	components []string
	archs      []string
	// config fingerprints the suites, components and architectures
	// followed: a cursor kept for others is not trusted to say what is
	// unchanged.
	config string
}

func newAptFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "suites", "components", "architectures")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	root := k.upstream
	if opts["url"] != "" {
		if root, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	}
	if opts["suites"] == "" {
		return nil, errors.New(`the apt feed needs the option suites: the suites to follow, comma-separated (like "trixie,trixie-updates" or "noble,noble-updates,noble-security")`)
	}
	src := &aptSource{k: k, root: root}
	if src.suites, err = aptTokens("suites", opts["suites"], "suite name (like trixie or noble-updates)", aptValidDist); err != nil {
		return nil, err
	}
	if src.components, err = aptTokens("components", opts.get("components", "main"), "component (like main or universe)", aptValidDist); err != nil {
		return nil, err
	}
	if src.archs, err = aptTokens("architectures", opts.get("architectures", "amd64"), "architecture (like amd64, arm64 or all)", aptValidArch); err != nil {
		return nil, err
	}
	if len(src.suites) > aptMaxSuites {
		return nil, fmt.Errorf("option suites names %d suites; the feed follows at most %d (configure another upstream for the rest)", len(src.suites), aptMaxSuites)
	}
	archs := len(src.archs)
	if !aptHas(src.archs, "all") {
		archs++ // binary-all, which a Release may call for
	}
	if n := len(src.suites) * len(src.components) * archs; n > aptMaxParts {
		return nil, fmt.Errorf("the suites, components and architectures configured make up to %d Packages indexes; the feed follows at most %d", n, aptMaxParts)
	}
	if n := src.stateBound(); n > aptMaxState {
		return nil, fmt.Errorf("the suites, components and architectures configured need up to %d bytes of cursor state; the feed keeps at most %d (follow fewer, or split them over upstreams)", n, aptMaxState)
	}
	sum := sha256.Sum256([]byte(strings.Join(src.suites, ",") + "|" + strings.Join(src.components, ",") + "|" + strings.Join(src.archs, ",")))
	src.config = hex.EncodeToString(sum[:8])
	return &aptFeed{indexFeed: newIndexFeed("apt", env, src)}, nil
}

// stateBound is the most bytes the source's state (aptState, as JSON) can
// take: each suite's entry with its validators as long as they are kept and
// every character escaped, and each index's name with its digest — binary-all
// counted for every suite and component, as a Release may call for it.
func (s *aptSource) stateBound() int {
	archs := append([]string(nil), s.archs...)
	if !aptHas(archs, "all") {
		archs = append(archs, "all")
	}
	n := len(`{"config":"0123456789abcdef","suites":[]}`)
	for _, suite := range s.suites {
		n += len(`{"suite":"","file":"InRelease","validators":{"etag":"","lastModified":""},"date":4102444800,"parts":{}},`) + len(suite) + 4*aptMaxValidator
		for _, c := range s.components {
			for _, a := range archs {
				n += len(`"/binary-":"",`) + len(c) + len(a) + sha256.Size*2
			}
		}
	}
	return n
}

func init() { Register("apt", newAptFeed) }

// aptTokens reads a comma-separated option, each token checked, duplicates
// dropped.
func aptTokens(opt, v, what string, valid func(string) bool) ([]string, error) {
	var out []string
	for _, tok := range strings.Split(v, ",") {
		tok = strings.TrimSpace(tok)
		if !valid(tok) {
			return nil, fmt.Errorf("option %s: %q is not a %s", opt, tok, what)
		}
		if !aptHas(out, tok) {
			out = append(out, tok)
		}
	}
	return out, nil
}

func aptHas(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// aptValidDist reports whether s names a suite or a component: segments of
// letters, digits and "._+~-" (each starting with a letter or a digit)
// separated by "/".
func aptValidDist(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case i > 0 && strings.IndexByte("._+~-", c) >= 0:
			default:
				return false
			}
		}
	}
	return true
}

// aptValidArch reports whether s is an architecture name ("amd64",
// "kfreebsd-amd64", "all").
func aptValidArch(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && c == '-':
		default:
			return false
		}
	}
	return true
}

// Releases lists a package's versions from the newest copy, oldest first by
// dpkg's version order.
func (f *aptFeed) Releases(_ context.Context, name string) ([]Release, error) {
	if !aptValidPackage(name) {
		return nil, Permanent(fmt.Errorf("%q is not a Debian package name", truncate(name, 200)))
	}
	recs, err := f.lookup(name)
	if err != nil {
		return nil, err
	}
	rels := snapReleases(recs)
	aptSortReleases(rels)
	return rels, nil
}

// aptState is what the next read is conditioned on.
type aptState struct {
	// Config is the source's config when the state was written.
	Config string          `json:"config"`
	Suites []aptSuiteState `json:"suites"`
}

// aptSuiteState is one suite's part of the state.
type aptSuiteState struct {
	Suite string `json:"suite"`
	// File is the Release file read ("InRelease" or "Release"), Validators
	// its validators.
	File       string         `json:"file"`
	Validators httpValidators `json:"validators"`
	// Date is the Release's date (Unix seconds), when it states one.
	Date int64 `json:"date,omitempty"`
	// Parts maps each Packages index read ("main/binary-amd64") to the
	// SHA-256 of its content.
	Parts map[string]string `json:"parts"`
}

// aptPart is one Packages index of a suite.
type aptPart struct {
	// name is the index's directory below the suite ("main/binary-amd64").
	name string
	// key is the SHA-256 of its content: the uncompressed index's when the
	// Release lists it, else that of the smallest file.
	key string
	// files are the forms the Release lists, the compressed ones smallest
	// first, then the uncompressed one; plain is the uncompressed index's
	// entry (zero when it lists none).
	files []aptFile
	plain aptFileEntry
}

// aptFile is one form of a Packages index.
type aptFile struct {
	name string
	aptFileEntry
}

// aptSuitePlan is what a poll does with one suite.
type aptSuitePlan struct {
	state  aptSuiteState
	byHash bool
	read   []aptPart
}

func (s *aptSource) readIndex(ctx context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error) {
	var ps aptState
	if old != nil && prev != nil && json.Unmarshal(prev, &ps) != nil {
		// Not a state this source wrote: read every suite afresh.
		ps = aptState{}
	}
	sameConfig := old != nil && ps.Config == s.config
	prevSuites := map[string]aptSuiteState{}
	if old != nil {
		for _, st := range ps.Suites {
			prevSuites[st.Suite] = st
		}
	}
	changed := !sameConfig
	copyParts := map[string]bool{}
	plans := make([]aptSuitePlan, 0, len(s.suites))
	for _, suite := range s.suites {
		pst, had := prevSuites[suite]
		rel, st, notModified, err := s.readRelease(ctx, suite, pst, had && sameConfig)
		if err != nil {
			return indexRead{}, err
		}
		if notModified {
			for part := range pst.Parts {
				copyParts[suite+"/"+part] = true
			}
			plans = append(plans, aptSuitePlan{state: pst})
			continue
		}
		parts, err := s.parts(suite, rel)
		if err != nil {
			return indexRead{}, err
		}
		plan := aptSuitePlan{state: st, byHash: rel.ByHash}
		plan.state.Parts = map[string]string{}
		for _, p := range parts {
			plan.state.Parts[p.name] = p.key
			if had && pst.Parts[p.name] == p.key {
				copyParts[suite+"/"+p.name] = true
			} else {
				plan.read = append(plan.read, p)
			}
		}
		if len(plan.read) > 0 || len(pst.Parts) != len(plan.state.Parts) {
			changed = true
		}
		plans = append(plans, plan)
	}

	state := aptState{Config: s.config}
	var newest int64
	for _, p := range plans {
		state.Suites = append(state.Suites, p.state)
		if p.state.Date > newest {
			newest = p.state.Date
		}
	}
	st, err := json.Marshal(state)
	if err != nil {
		return indexRead{}, err
	}
	if len(st) > indexMaxState {
		return indexRead{}, Permanent(fmt.Errorf("the Release files list %d bytes of digests for the indexes followed; the cursor keeps at most %d", len(st), indexMaxState))
	}
	rd := indexRead{State: st}
	if newest > 0 {
		rd.HeadTime = unixTime(newest)
		rd.Head = rd.HeadTime.Format(time.RFC3339)
	}
	if old != nil && !changed {
		rd.Unchanged = true
		return rd, nil
	}
	if old != nil && len(copyParts) > 0 {
		// A copy that does not read is the cursor's fault: the toolkit
		// tells it from an I/O error.
		if err := b.CopyFrom(old, func(r *snapRecord) bool { return copyParts[r.Index] }); err != nil {
			return indexRead{}, err
		}
	}
	for _, p := range plans {
		for _, part := range p.read {
			if err := s.readPackages(ctx, p.state.Suite, part, p.byHash, b); err != nil {
				return indexRead{}, err
			}
		}
	}
	return rd, nil
}

// readRelease reads a suite's InRelease, or its Release where it has none —
// conditionally when the state of the previous read applies. notModified
// reports a 304: the suite is as the previous read found it.
func (s *aptSource) readRelease(ctx context.Context, suite string, prev aptSuiteState, conditional bool) (*aptRelease, aptSuiteState, bool, error) {
	st := aptSuiteState{Suite: suite}
	for _, file := range []string{"InRelease", "Release"} {
		u := join(s.root, "dists/"+suite+"/"+file)
		hdr := http.Header{}
		if conditional && prev.File == file {
			prev.Validators.set(hdr)
		}
		resp, body, err := s.k.getStream(ctx, u, hdr, aptMaxRelease)
		if errors.Is(err, errNotModified) {
			if len(hdr) == 0 {
				return nil, st, false, fmt.Errorf("suite %s: %s answered 304 Not Modified to a request that was not conditional", suite, u)
			}
			return nil, prev, true, nil
		}
		if err != nil {
			if resp != nil && file == "InRelease" && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusForbidden) {
				continue
			}
			if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone) {
				break
			}
			return nil, st, false, fmt.Errorf("suite %s: %w", suite, err)
		}
		data, err := readLimited(body, aptMaxRelease)
		body.Close()
		if err != nil {
			return nil, st, false, fmt.Errorf("suite %s: reading %s: %w", suite, u, err)
		}
		rel, err := aptParseRelease(data)
		if err != nil {
			return nil, st, false, Permanent(fmt.Errorf("suite %s: %s: %w", suite, u, err))
		}
		st.File, st.Validators = file, yumKeepValidators(validatorsOf(resp), aptMaxValidator)
		if !rel.Date.IsZero() {
			st.Date = rel.Date.Unix()
		}
		return rel, st, false, nil
	}
	return nil, st, false, Permanent(fmt.Errorf("suite %s: the archive at %s has neither dists/%s/InRelease nor dists/%s/Release: the suite is misspelt, or gone from the archive "+
		"(an end-of-life release moves to archive.debian.org or old-releases.ubuntu.com) — remove it from fullMirror.feed.suites (no suite is followed while it is listed), "+
		"or check that the upstream URL is the archive's root", suite, s.root.Redacted(), suite, suite))
}

// parts lists the Packages indexes of a suite the feed reads.
func (s *aptSource) parts(suite string, rel *aptRelease) ([]aptPart, error) {
	if rel.Components != nil {
		for _, c := range s.components {
			if !aptHas(rel.Components, c) {
				return nil, Permanent(fmt.Errorf("suite %s has no component %s (its Release lists: %s)", suite, c, truncate(strings.Join(rel.Components, " "), 200)))
			}
		}
	}
	archs := append([]string(nil), s.archs...)
	if rel.Architectures != nil {
		for _, a := range archs {
			// "all" is read where the Release lists binary-all indexes:
			// elsewhere (Ubuntu) its packages are in binary-<arch>.
			if a != "all" && !aptHas(rel.Architectures, a) {
				return nil, Permanent(fmt.Errorf("suite %s has no architecture %s (its Release lists: %s)", suite, a, truncate(strings.Join(rel.Architectures, " "), 200)))
			}
		}
	}
	implicitAll := !aptHas(archs, "all") && !rel.NoArchAll && aptHas(rel.Architectures, "all")
	if implicitAll {
		archs = append(archs, "all")
	}
	var parts []aptPart
	for _, c := range s.components {
		for _, a := range archs {
			p := aptPart{name: c + "/binary-" + a}
			for _, ext := range aptCompressions {
				if e, ok := rel.Files[p.name+"/Packages"+ext]; ok {
					p.files = append(p.files, aptFile{name: "Packages" + ext, aptFileEntry: e})
				}
			}
			if len(p.files) == 0 {
				// The suite publishes no index for it (an empty component,
				// an architecture it does not build).
				continue
			}
			// The compressed forms by size, the uncompressed one last: Debian
			// and Ubuntu list it without serving it (APT reads it only where
			// nothing else is listed).
			sort.SliceStable(p.files, func(i, j int) bool {
				pi, pj := p.files[i].name == "Packages", p.files[j].name == "Packages"
				if pi != pj {
					return pj
				}
				return p.files[i].Size < p.files[j].Size
			})
			p.key = p.files[0].SHA256
			if e, ok := rel.Files[p.name+"/Packages"]; ok {
				p.plain, p.key = e, e.SHA256
			}
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return nil, Permanent(fmt.Errorf("suite %s lists no Packages index of the components (%s) and architectures (%s) followed",
			suite, strings.Join(s.components, ","), strings.Join(archs, ",")))
	}
	return parts, nil
}

// errAptMissing marks an index file the archive does not have.
var errAptMissing = errors.New("the archive does not have the file")

// readPackages reads a Packages index into b: the smallest form the archive
// has, by its hash when the archive serves files so.
func (s *aptSource) readPackages(ctx context.Context, suite string, part aptPart, byHash bool, b *snapBuilder) error {
	dir := "dists/" + suite + "/" + part.name + "/"
	for _, f := range part.files {
		urls := []string{join(s.root, dir+f.name)}
		if byHash {
			urls = append([]string{join(s.root, dir+"by-hash/SHA256/"+f.SHA256)}, urls...)
		}
		for _, u := range urls {
			err := s.readPackagesFile(ctx, suite+"/"+part.name, u, f, part.plain, b)
			if !errors.Is(err, errAptMissing) {
				return err
			}
		}
	}
	return fmt.Errorf("suite %s: the archive has none of the forms of %sPackages its Release lists", suite, dir)
}

// readPackagesFile reads one form of a Packages index. Nothing is added
// before the file's first byte: a missing file (errAptMissing) leaves b as it
// was.
func (s *aptSource) readPackagesFile(ctx context.Context, index, u string, f aptFile, plain aptFileEntry, b *snapBuilder) error {
	what := "dists/" + index + "/" + f.name
	if f.Size > aptMaxPackagesFile || plain.Size > aptMaxPackagesBytes {
		return Permanent(fmt.Errorf("%s is %d bytes (%d uncompressed); the feed reads at most %d (%d)", what, f.Size, plain.Size, aptMaxPackagesFile, aptMaxPackagesBytes))
	}
	// The file's digest is of its bytes as published: ask for them as they
	// are (net/http would otherwise ask for gzip and undo a Content-Encoding
	// a server put on a .gz file).
	resp, body, err := s.k.getStream(ctx, u, http.Header{"Accept-Encoding": {"identity"}}, aptMaxPackagesFile)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone) {
			return errAptMissing
		}
		return fmt.Errorf("reading %s: %w", what, err)
	}
	defer body.Close()
	// What fails below is the archive's fault only if the file is the one its
	// Release declared: the file is read to its end and verified before a
	// failure is called permanent. A failed read (the network, the context)
	// is returned as it is.
	file := newAptDigest(body, f.aptFileEntry)
	fault := func(err error) error {
		if file.err == nil {
			if _, rerr := io.Copy(io.Discard, file); rerr != nil && file.err == nil {
				file.err = rerr
			}
		}
		if file.err != nil {
			return fmt.Errorf("reading %s: %w", what, file.err)
		}
		if verr := file.verify(what); verr != nil {
			return verr
		}
		if IsPermanent(err) {
			return err
		}
		return Permanent(fmt.Errorf("%s: %w", what, err))
	}
	content, release, err := openContent(file, what, aptMaxPackagesBytes)
	if err != nil {
		return fault(err)
	}
	defer release()
	doc := newAptDigest(content, plain)
	err = aptParsePackages(doc, func(st *aptStanza) {
		if rec, ok := aptRecord(st, index); ok {
			b.Add(rec)
		}
	})
	if err != nil {
		return fault(err)
	}
	if err := doc.verify(what + " (uncompressed)"); err != nil {
		return fault(err)
	}
	if _, err := io.Copy(io.Discard, file); err != nil {
		return fmt.Errorf("reading %s: %w", what, err)
	}
	return file.verify(what)
}

// aptRecord makes a package file's record: nothing for a stanza the proxy
// cannot fetch or name.
func aptRecord(st *aptStanza, index string) (snapRecord, bool) {
	if !aptValidPackage(st.Package) || !aptValidVersion(st.Version) {
		return snapRecord{}, false
	}
	p, ok := aptPath(st.Filename)
	if !ok {
		return snapRecord{}, false
	}
	rec := snapRecord{Name: st.Package, Version: st.Version, Path: p, Index: index}
	if n, err := strconv.ParseInt(st.Size, 10, 64); err == nil && n > 0 {
		rec.Size = n
	}
	if sum := strings.ToLower(st.SHA256); len(sum) == sha256.Size*2 && yumIsHex(sum) {
		rec.Digest = "sha256:" + sum
	}
	return rec, true
}

// aptValidPackage reports whether s is a Debian package name: lower-case
// letters, digits and "+.-", starting with a letter or a digit (Debian
// policy 5.6.7).
func aptValidPackage(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && (c == '+' || c == '.' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// aptValidVersion reports whether s is a Debian version: letters, digits and
// ".+~:-", any epoch (before the first ":") numeric (Debian policy 5.6.12).
func aptValidVersion(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(".+~:-", c) >= 0) {
			return false
		}
	}
	if i := strings.IndexByte(s, ':'); i >= 0 && !yumAllDigits(s[:i]) {
		return false
	}
	return true
}

// aptPath maps a stanza's Filename to the path the backend serves the package
// at: the Filename below the archive root, a .deb (or .udeb, .ddeb).
func aptPath(filename string) (string, bool) {
	filename = strings.TrimLeft(filename, "/")
	if filename == "" || len(filename) > 1024 || strings.ContainsAny(filename, "?#\\%") || strings.Contains(filename, "://") {
		return "", false
	}
	if !strings.HasSuffix(filename, ".deb") && !strings.HasSuffix(filename, ".udeb") && !strings.HasSuffix(filename, ".ddeb") {
		return "", false
	}
	for _, seg := range strings.Split(filename, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false
		}
	}
	p := (&url.URL{Path: "/" + filename}).EscapedPath()
	return p, validArtifactPath(p)
}

// --- Release files -----------------------------------------------------------

// aptRelease is what the feed reads from a Release file.
type aptRelease struct {
	Date      time.Time
	ByHash    bool
	NoArchAll bool
	// Architectures and Components are the fields' values; nil when the
	// Release states none.
	Architectures []string
	Components    []string
	// Files are the SHA256 entries of Packages indexes, by their path below
	// the suite.
	Files map[string]aptFileEntry
}

// aptFileEntry is a file's SHA-256 and size as a Release lists them.
type aptFileEntry struct {
	SHA256 string
	Size   int64
}

// aptDateLayouts are the forms a Release's Date takes (RFC 2822: Debian's
// "Sat, 12 Sep 2026 07:55:41 UTC"; others write a numeric zone or a day
// without its leading zero).
var aptDateLayouts = []string{time.RFC1123, time.RFC1123Z, "Mon, 2 Jan 2006 15:04:05 MST", "Mon, 2 Jan 2006 15:04:05 -0700"}

// aptParseRelease reads a Release or InRelease file (the latter's signature
// armour stripped, not checked).
func aptParseRelease(data []byte) (*aptRelease, error) {
	body := aptStripClearsign(data)
	rel := &aptRelease{Files: map[string]aptFileEntry{}}
	field := ""
	fields := 0
	for n := 1; len(body) > 0; n++ {
		var line []byte
		if i := bytes.IndexByte(body, '\n'); i >= 0 {
			line, body = body[:i], body[i+1:]
		} else {
			line, body = body, nil
		}
		line = bytes.TrimRight(line, "\r")
		if len(bytes.TrimSpace(line)) == 0 {
			if fields > 0 {
				break // the end of the paragraph
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if field == "sha256" {
				rel.addFile(line)
			}
			continue
		}
		if line[0] == '#' {
			continue
		}
		i := bytes.IndexByte(line, ':')
		if i <= 0 {
			return nil, fmt.Errorf("line %d is not a field: %.60q", n, line)
		}
		fields++
		field = strings.ToLower(string(bytes.TrimSpace(line[:i])))
		val := string(bytes.TrimSpace(line[i+1:]))
		switch field {
		case "date":
			for _, layout := range aptDateLayouts {
				if t, err := time.Parse(layout, val); err == nil && t.Unix() > aptMinTime && t.Unix() < aptMaxTime {
					rel.Date = t.UTC()
					break
				}
			}
		case "acquire-by-hash":
			rel.ByHash = strings.EqualFold(val, "yes")
		case "no-support-for-architecture-all":
			rel.NoArchAll = aptHas(strings.Fields(val), "Packages")
		case "architectures":
			rel.Architectures = aptFields(val)
		case "components":
			rel.Components = aptFields(val)
		}
	}
	if fields == 0 {
		return nil, errors.New("it is not a Release file (no field)")
	}
	if len(rel.Files) == 0 {
		return nil, errors.New("it lists no Packages index with a SHA256 digest")
	}
	return rel, nil
}

// aptFields splits a field's value into its words, bounded.
func aptFields(v string) []string {
	out := strings.Fields(v)
	if len(out) > 1000 {
		out = out[:1000]
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// addFile reads a line of the SHA256 field ("<hex> <size> <path>"), keeping
// the entries of Packages indexes.
func (rel *aptRelease) addFile(line []byte) {
	f := strings.Fields(string(line))
	if len(f) != 3 || len(rel.Files) >= aptMaxEntries {
		return
	}
	sum := strings.ToLower(f[0])
	size, err := strconv.ParseInt(f[1], 10, 64)
	p := f[2]
	base := p[strings.LastIndexByte(p, '/')+1:]
	if len(sum) != sha256.Size*2 || !yumIsHex(sum) || err != nil || size < 0 || !strings.HasPrefix(base, "Packages") ||
		strings.HasPrefix(p, "/") || strings.Contains(p, "..") || len(p) > 512 {
		return
	}
	rel.Files[p] = aptFileEntry{SHA256: sum, Size: size}
}

// aptStripClearsign returns the signed text of a clearsigned document (an
// InRelease), dash-escaping undone; a document that is not clearsigned is
// returned as it is.
func aptStripClearsign(data []byte) []byte {
	const begin, sig = "-----BEGIN PGP SIGNED MESSAGE-----", "-----BEGIN PGP SIGNATURE-----"
	i := bytes.Index(data, []byte(begin))
	if i < 0 {
		return data
	}
	rest := data[i+len(begin):]
	// The rest of the marker's line, then the armour headers ("Hash:
	// SHA512") up to the first empty line.
	j := bytes.IndexByte(rest, '\n')
	if j < 0 {
		return nil
	}
	rest = rest[j+1:]
	for {
		j := bytes.IndexByte(rest, '\n')
		if j < 0 {
			return nil
		}
		line := bytes.TrimSpace(rest[:j])
		rest = rest[j+1:]
		if len(line) == 0 {
			break
		}
	}
	switch k := bytes.Index(rest, []byte("\n"+sig)); {
	case bytes.HasPrefix(rest, []byte(sig)):
		return nil
	case k >= 0:
		rest = rest[:k+1]
	}
	if !bytes.Contains(rest, []byte("\n- ")) && !bytes.HasPrefix(rest, []byte("- ")) {
		return rest
	}
	out := bytes.ReplaceAll(rest, []byte("\n- "), []byte("\n"))
	return bytes.TrimPrefix(out, []byte("- "))
}

// --- Packages indexes ----------------------------------------------------------

// aptStanza is what the feed reads from a Packages stanza.
type aptStanza struct {
	Package, Version, Architecture, Filename, Size, SHA256 string
	// seen marks the fields read, and bad a stanza whose fields repeat or
	// run past the bound.
	seen uint8
	bad  bool
}

// errAptNotPackages marks a document that is not a Packages index.
var errAptNotPackages = errors.New("it is not a Packages index (no stanza names a package)")

// aptParsePackages reads a (decompressed) Packages index as a stream of Deb822
// stanzas and calls fn with each one that names a package and whose fields do
// not repeat. Continuation lines and the fields not kept are skipped; a line
// longer than aptMaxLine is skipped too (it marks its stanza bad when it is a
// field the feed keeps). A document with content but no stanza naming a
// package is not a Packages index.
func aptParsePackages(r io.Reader, fn func(*aptStanza)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	buf := make([]byte, 0, 4096)
	var st aptStanza
	content, named := false, false
	emit := func() {
		if st.Package != "" {
			named = true
			if !st.bad {
				fn(&st)
			}
		}
		st = aptStanza{}
	}
	for {
		line, long, err := aptReadLine(br, buf[:0])
		buf = line[:0]
		switch {
		case len(bytes.TrimSpace(line)) == 0:
			// A paragraph's end (a line of spaces and tabs is one too).
			emit()
		case line[0] == ' ' || line[0] == '\t' || line[0] == '#':
			// A continuation line, or a comment: nothing the feed keeps.
		default:
			content = true
			st.read(line, long)
		}
		if err == io.EOF {
			emit()
			if content && !named {
				return errAptNotPackages
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// The fields a stanza keeps, as bits of aptStanza.seen.
const (
	aptFieldPackage uint8 = 1 << iota
	aptFieldVersion
	aptFieldArchitecture
	aptFieldFilename
	aptFieldSize
	aptFieldSHA256
)

// read takes a field line into the stanza.
func (st *aptStanza) read(line []byte, long bool) {
	i := bytes.IndexByte(line, ':')
	if i <= 0 {
		return // not a field: left out
	}
	key := bytes.TrimSpace(line[:i])
	var bit uint8
	var dst *string
	switch {
	case bytes.EqualFold(key, []byte("Package")):
		bit, dst = aptFieldPackage, &st.Package
	case bytes.EqualFold(key, []byte("Version")):
		bit, dst = aptFieldVersion, &st.Version
	case bytes.EqualFold(key, []byte("Architecture")):
		bit, dst = aptFieldArchitecture, &st.Architecture
	case bytes.EqualFold(key, []byte("Filename")):
		bit, dst = aptFieldFilename, &st.Filename
	case bytes.EqualFold(key, []byte("Size")):
		bit, dst = aptFieldSize, &st.Size
	case bytes.EqualFold(key, []byte("SHA256")):
		bit, dst = aptFieldSHA256, &st.SHA256
	default:
		return
	}
	val := bytes.TrimSpace(line[i+1:])
	if st.seen&bit != 0 || long || len(val) > aptMaxField {
		st.bad = true
	}
	st.seen |= bit
	if !st.bad {
		*dst = string(val)
	} else if bit == aptFieldPackage {
		// Still a stanza that names a package (the document is a Packages
		// index), just not one the feed keeps.
		st.Package = "-"
	}
}

// aptReadLine reads a line without its end of line, appending at most
// aptMaxLine bytes of it to buf; long reports a longer line, whose start is
// returned and the rest skipped. err is io.EOF with the last line.
func aptReadLine(br *bufio.Reader, buf []byte) (line []byte, long bool, err error) {
	for {
		chunk, err := br.ReadSlice('\n')
		if room := aptMaxLine - len(buf); len(chunk) <= room {
			buf = append(buf, chunk...)
		} else {
			if room > 0 {
				buf = append(buf, chunk[:room]...)
			}
			long = true
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		buf = bytes.TrimRight(buf, "\r\n")
		return buf, long, err
	}
}

// --- verifying what was read ---------------------------------------------------

// aptDigest hashes and counts what is read through it, fails a read past the
// size the Release states, and keeps the first error its reader returned. An
// entry without a digest (the Release lists no uncompressed index) checks
// nothing.
type aptDigest struct {
	r   io.Reader
	e   aptFileEntry
	h   hash.Hash
	n   int64
	err error
}

func newAptDigest(r io.Reader, e aptFileEntry) *aptDigest {
	d := &aptDigest{r: r, e: e}
	if e.SHA256 != "" {
		d.h = sha256.New()
	}
	return d
}

func (d *aptDigest) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	n, err := d.r.Read(p)
	d.n += int64(n)
	if d.h != nil {
		d.h.Write(p[:n])
		if d.n > d.e.Size {
			err = fmt.Errorf("more than the %d bytes the Release states (the archive changed while it was read?)", d.e.Size)
		}
	}
	if err != nil && err != io.EOF {
		d.err = err
	}
	return n, err
}

// verify checks the size and the SHA-256 of what was read. A mismatch is worth
// retrying: the archive was updated while it was read, or a cache served a
// damaged copy.
func (d *aptDigest) verify(what string) error {
	if d.h == nil {
		return nil
	}
	if d.n != d.e.Size {
		return fmt.Errorf("%s: read %d bytes, the Release states %d (the archive changed while it was read?)", what, d.n, d.e.Size)
	}
	if got := hex.EncodeToString(d.h.Sum(nil)); got != d.e.SHA256 {
		return fmt.Errorf("%s: SHA-256 %s, the Release states %s (the archive changed while it was read?)", what, got, d.e.SHA256)
	}
	return nil
}

// --- version order -------------------------------------------------------------

// aptSortReleases orders releases oldest first by dpkg's version comparison.
func aptSortReleases(rels []Release) {
	sort.SliceStable(rels, func(i, j int) bool { return aptCompareVersions(rels[i].Version, rels[j].Version) < 0 })
}

// aptCompareVersions compares two Debian versions as dpkg does: the epochs as
// numbers, then the upstream versions, then the revisions (after the last
// "-"), each by verrevcmp.
func aptCompareVersions(a, b string) int {
	ea, ua, ra := aptSplitVersion(a)
	eb, ub, rb := aptSplitVersion(b)
	if c := yumCompareDigits(ea, eb); c != 0 {
		return c
	}
	if c := aptVerrevcmp(ua, ub); c != 0 {
		return c
	}
	return aptVerrevcmp(ra, rb)
}

// aptSplitVersion splits "[epoch:]upstream[-revision]"; the epoch is "0" when
// absent.
func aptSplitVersion(s string) (epoch, upstream, revision string) {
	epoch = "0"
	if i := strings.IndexByte(s, ':'); i > 0 && yumAllDigits(s[:i]) {
		epoch, s = s[:i], s[i+1:]
	}
	upstream = s
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		upstream, revision = s[:i], s[i+1:]
	}
	return epoch, upstream, revision
}

// aptOrder is dpkg's weight of a character in a version's non-digit part:
// "~" before the end of the part, the end before letters, letters before
// everything else.
func aptOrder(c byte, end bool) int {
	switch {
	case end:
		return 0
	case c >= '0' && c <= '9':
		return 0
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

// aptVerrevcmp is dpkg's verrevcmp: alternating runs of non-digits, compared
// character by character by aptOrder, and of digits, compared as numbers.
func aptVerrevcmp(a, b string) int {
	isDigit := func(s string, i int) bool { return i < len(s) && s[i] >= '0' && s[i] <= '9' }
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a, i)) || (j < len(b) && !isDigit(b, j)) {
			var ca, cb byte
			if i < len(a) {
				ca = a[i]
			}
			if j < len(b) {
				cb = b[j]
			}
			ac, bc := aptOrder(ca, i >= len(a)), aptOrder(cb, j >= len(b))
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		first := 0
		for isDigit(a, i) && isDigit(b, j) {
			if first == 0 {
				first = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(a, i) {
			return 1
		}
		if isDigit(b, j) {
			return -1
		}
		if first != 0 {
			if first < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}
