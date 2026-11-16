package fullmirror

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1" //nolint:gosec // Git object ids
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// gitTestRepo is a Git repository built in memory for the Git feeds' tests:
// commits of flat file maps, with the trees Git would store for them. Blobs
// are never stored — the feeds fetch without them.
type gitTestRepo struct {
	mu      sync.Mutex
	objects map[gitOID]gitObject
	parents map[gitOID][]gitOID
	roots   map[gitOID]gitOID
	head    gitOID
	branch  string
}

func newGitTestRepo() *gitTestRepo {
	return &gitTestRepo{objects: map[gitOID]gitObject{}, parents: map[gitOID][]gitOID{}, roots: map[gitOID]gitOID{}, branch: "main"}
}

// tree stores the tree of a flat file map (path → content) and returns its id.
func (r *gitTestRepo) tree(files map[string]string, dir string) gitOID {
	type ent struct {
		name string
		mode uint32
		id   gitOID
	}
	var ents []ent
	subdirs := map[string]bool{}
	for p, content := range files {
		rel := p
		if dir != "" {
			if !strings.HasPrefix(p, dir+"/") {
				continue
			}
			rel = strings.TrimPrefix(p, dir+"/")
		}
		if i := strings.IndexByte(rel, '/'); i >= 0 {
			subdirs[rel[:i]] = true
			continue
		}
		ents = append(ents, ent{name: rel, mode: 0o100644, id: hashObject(gitBlob, []byte(content))})
	}
	for d := range subdirs {
		ents = append(ents, ent{name: d, mode: gitModeTree, id: r.tree(files, joinPath(dir, d))})
	}
	// Git sorts tree entries by name, a directory as if it ended in "/".
	sort.Slice(ents, func(i, j int) bool {
		a, b := ents[i].name, ents[j].name
		if ents[i].mode == gitModeTree {
			a += "/"
		}
		if ents[j].mode == gitModeTree {
			b += "/"
		}
		return a < b
	})
	var buf bytes.Buffer
	for _, e := range ents {
		fmt.Fprintf(&buf, "%o %s\x00", e.mode, e.name)
		buf.Write(e.id[:])
	}
	id := hashObject(gitTree, buf.Bytes())
	r.objects[id] = gitObject{typ: gitTree, data: buf.Bytes()}
	return id
}

// commit records a commit of files on top of the head (or of no parent when
// orphan is set) and moves the branch to it.
func (r *gitTestRepo) commit(files map[string]string, when time.Time, orphan bool) gitOID {
	r.mu.Lock()
	defer r.mu.Unlock()
	root := r.tree(files, "")
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "tree %s\n", root)
	var parents []gitOID
	if !orphan && r.head != (gitOID{}) {
		parents = []gitOID{r.head}
		fmt.Fprintf(&buf, "parent %s\n", r.head)
	}
	fmt.Fprintf(&buf, "author T <t@example.org> %d +0000\ncommitter T <t@example.org> %d +0000\n\nchange\n", when.Unix(), when.Unix())
	id := hashObject(gitCommit, buf.Bytes())
	r.objects[id] = gitObject{typ: gitCommit, data: buf.Bytes()}
	r.parents[id] = parents
	r.roots[id] = root
	r.head = id
	return id
}

// reachable lists the commits reachable from c.
func (r *gitTestRepo) reachable(c gitOID) map[gitOID]bool {
	out := map[gitOID]bool{}
	stack := []gitOID{c}
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if out[x] {
			continue
		}
		if _, ok := r.objects[x]; !ok {
			continue
		}
		out[x] = true
		stack = append(stack, r.parents[x]...)
	}
	return out
}

// treesOf lists the trees reachable from a root.
func (r *gitTestRepo) treesOf(root gitOID, into map[gitOID]bool) {
	if into[root] {
		return
	}
	into[root] = true
	entries, _ := parseGitTree(r.objects[root].data)
	for _, e := range entries {
		if e.isTree() {
			r.treesOf(e.id, into)
		}
	}
}

// gitTestServer serves a gitTestRepo over smart HTTP, protocol v2.
type gitTestServer struct {
	t       *testing.T
	repo    *gitTestRepo
	srv     *httptest.Server
	mu      sync.Mutex
	fetches []gitTestFetch
	// deltas has the server send every other tree as an offset delta.
	deltas bool
}

// gitTestFetch is what one fetch asked for and got.
type gitTestFetch struct {
	want, have string
	deepen     bool
	objects    int
}

func newGitTestServer(t *testing.T, repo *gitTestRepo) *gitTestServer {
	s := &gitTestServer{t: t, repo: repo}
	s.srv = httptest.NewServer(s)
	t.Cleanup(s.srv.Close)
	return s
}

// URL is the repository's URL.
func (s *gitTestServer) URL() string { return s.srv.URL + "/registry/index.git" }

func (s *gitTestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/registry/index.git/info/refs":
		if r.URL.Query().Get("service") != "git-upload-pack" || r.Header.Get("Git-Protocol") != "version=2" {
			http.Error(w, "v2 only", 400)
			return
		}
		var b bytes.Buffer
		b.Write(pktLine("# service=git-upload-pack\n"))
		b.Write(pktFlush)
		for _, l := range []string{"version 2\n", "agent=test\n", "ls-refs=unborn\n", "fetch=shallow wait-for-done filter\n", "object-format=sha1\n"} {
			b.Write(pktLine(l))
		}
		b.Write(pktFlush)
		w.Write(b.Bytes())
	case r.Method == http.MethodPost && r.URL.Path == "/registry/index.git/git-upload-pack":
		s.command(w, r)
	default:
		s.t.Errorf("unexpected Git request %s %s", r.Method, r.URL)
		http.Error(w, "no", 404)
	}
}

func (s *gitTestServer) command(w http.ResponseWriter, r *http.Request) {
	pr := newPktReader(r.Body)
	var cmd string
	var args []string
	inArgs := false
	for {
		kind, payload, err := pr.next()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if kind == pktKindFlush {
			break
		}
		if kind == pktKindDelim {
			inArgs = true
			continue
		}
		line := strings.TrimSuffix(string(payload), "\n")
		if !inArgs {
			if c, ok := strings.CutPrefix(line, "command="); ok {
				cmd = c
			}
			continue
		}
		args = append(args, line)
	}
	s.repo.mu.Lock()
	defer s.repo.mu.Unlock()
	var out bytes.Buffer
	switch cmd {
	case "ls-refs":
		head := s.repo.head.String()
		for _, a := range args {
			switch a {
			case "ref-prefix HEAD":
				out.Write(pktLine(head + " HEAD symref-target:refs/heads/" + s.repo.branch + "\n"))
			case "ref-prefix refs/heads/" + s.repo.branch:
				out.Write(pktLine(head + " refs/heads/" + s.repo.branch + "\n"))
			}
		}
		out.Write(pktFlush)
	case "fetch":
		var want, have gitOID
		deepen, filtered := false, false
		for _, a := range args {
			switch {
			case strings.HasPrefix(a, "want "):
				want, _ = parseOID(strings.TrimPrefix(a, "want "))
			case strings.HasPrefix(a, "have "):
				have, _ = parseOID(strings.TrimPrefix(a, "have "))
			case a == "deepen 1":
				deepen = true
			case a == "filter blob:none":
				filtered = true
			}
		}
		if !filtered {
			http.Error(w, "the test server serves blob-less fetches only", 400)
			return
		}
		if _, ok := s.repo.objects[want]; !ok {
			out.Write(pktLine("ERR upload-pack: not our ref " + want.String()))
			w.Write(out.Bytes())
			return
		}
		var commits []gitOID
		trees := map[gitOID]bool{}
		if deepen {
			commits = []gitOID{want}
			s.repo.treesOf(s.repo.roots[want], trees)
		} else {
			skip := map[gitOID]bool{}
			skipTrees := map[gitOID]bool{}
			if _, ok := s.repo.objects[have]; ok {
				skip = s.repo.reachable(have)
				for c := range skip {
					s.repo.treesOf(s.repo.roots[c], skipTrees)
				}
			}
			for c := range s.repo.reachable(want) {
				if skip[c] {
					continue
				}
				commits = append(commits, c)
				s.repo.treesOf(s.repo.roots[c], trees)
			}
			for t := range skipTrees {
				delete(trees, t)
			}
		}
		objs := make([]gitObject, 0, len(commits)+len(trees))
		for _, c := range commits {
			objs = append(objs, s.repo.objects[c])
		}
		ids := make([]gitOID, 0, len(trees))
		for id := range trees {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return string(ids[i][:]) < string(ids[j][:]) })
		for _, id := range ids {
			objs = append(objs, s.repo.objects[id])
		}
		s.mu.Lock()
		s.fetches = append(s.fetches, gitTestFetch{want: want.String(), have: have.String(), deepen: deepen, objects: len(objs)})
		s.mu.Unlock()
		pack := buildTestPack(objs, s.deltas)
		out.Write(pktLine("packfile\n"))
		for len(pack) > 0 {
			n := len(pack)
			if n > 8000 {
				n = 8000
			}
			out.Write(pktLine("\x01" + string(pack[:n])))
			pack = pack[n:]
		}
		out.Write(pktFlush)
	default:
		http.Error(w, "unknown command", 400)
		return
	}
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	w.Write(out.Bytes())
}

func (s *gitTestServer) lastFetch() gitTestFetch {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.fetches) == 0 {
		return gitTestFetch{}
	}
	return s.fetches[len(s.fetches)-1]
}

// packHeader encodes an object header of a pack.
func packHeader(typ int, size int) []byte {
	var out []byte
	c := byte(typ<<4) | byte(size&15)
	size >>= 4
	for size > 0 {
		out = append(out, c|0x80)
		c = byte(size & 0x7f)
		size >>= 7
	}
	return append(out, c)
}

func zlibBytes(data []byte) []byte {
	var b bytes.Buffer
	zw := zlib.NewWriter(&b)
	zw.Write(data)
	zw.Close()
	return b.Bytes()
}

// deltaVarint encodes a delta size field.
func deltaVarint(n int) []byte {
	var out []byte
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, c)
		}
		out = append(out, c|0x80)
	}
}

// makeDelta builds a delta from base to target: a copy of their common
// prefix, then inserts.
func makeDelta(base, target []byte) []byte {
	d := append(deltaVarint(len(base)), deltaVarint(len(target))...)
	common := 0
	for common < len(base) && common < len(target) && common < 0xffff && base[common] == target[common] {
		common++
	}
	rest := target
	if common >= 4 {
		// copy: offset 0 (no offset bytes), size in two bytes
		d = append(d, 0x80|0x10|0x20, byte(common), byte(common>>8))
		rest = target[common:]
	}
	for len(rest) > 0 {
		n := len(rest)
		if n > 127 {
			n = 127
		}
		d = append(d, byte(n))
		d = append(d, rest[:n]...)
		rest = rest[n:]
	}
	return d
}

// buildTestPack writes a pack of objs; with deltas, every other tree is an
// offset delta against the tree before it.
func buildTestPack(objs []gitObject, deltas bool) []byte {
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(len(objs)))
	prevTree, prevOff := -1, 0
	for i, o := range objs {
		off := b.Len()
		if deltas && o.typ == gitTree && prevTree >= 0 && i%2 == 0 {
			d := makeDelta(objs[prevTree].data, o.data)
			b.Write(packHeader(gitOfsDelta, len(d)))
			// offset encoding
			rel := off - prevOff
			enc := []byte{byte(rel & 0x7f)}
			for rel >>= 7; rel > 0; rel >>= 7 {
				rel--
				enc = append([]byte{byte(0x80 | (rel & 0x7f))}, enc...)
			}
			b.Write(enc)
			b.Write(zlibBytes(d))
		} else {
			b.Write(packHeader(o.typ, len(o.data)))
			b.Write(zlibBytes(o.data))
		}
		if o.typ == gitTree {
			prevTree, prevOff = i, off
		}
	}
	sum := sha1.Sum(b.Bytes()) //nolint:gosec // Git's pack checksum
	b.Write(sum[:])
	return b.Bytes()
}

func TestPktLinesAndTheRecordedAdvertisement(t *testing.T) {
	caps, err := parseGitCapabilities(fixture(t, "git", "info-refs.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if caps["fetch"] != "shallow wait-for-done filter" || caps["object-format"] != "sha1" {
		t.Errorf("capabilities %v", caps)
	}
	refs, err := parseLsRefs(bytes.NewReader(fixture(t, "git", "ls-refs.bin")))
	if err != nil || refs["HEAD"] != "4410f9ba1bf91c2edae641c93b511f3010ded389" {
		t.Errorf("refs %v (%v)", refs, err)
	}
	for _, bad := range []string{"", "0008abc", "zzzz", "0003", "000bversion 1\n0000", "0010# service=x\n0000"} {
		if _, err := parseGitCapabilities([]byte(bad)); err == nil {
			t.Errorf("capabilities %q accepted", bad)
		}
	}
	for _, bad := range []string{"0012nothex HEAD\n0000", "0009x\n0000", "0001", ""} {
		if _, err := parseLsRefs(strings.NewReader(bad)); err == nil {
			t.Errorf("ls-refs %q accepted", bad)
		}
	}
}

func TestTheRecordedIncrementalFetchDiffsAgainstTheStoredTrees(t *testing.T) {
	// A real fetch of the Bazel Central Registry's head 4410f9ba with its
	// parent 9ee49c80 as have (recorded 2026-11-16): one commit and the 24
	// trees it added. The stored trees are the parent's root and modules
	// trees — all the diff reads, since every changed module is new.
	pack, err := readFetchResponse(bytes.NewReader(fixture(t, "git", "fetch-incremental.bin")), maxGitPack)
	if err != nil {
		t.Fatal(err)
	}
	objs, err := parsePack(pack)
	if err != nil {
		t.Fatal(err)
	}
	head, _ := parseOID("4410f9ba1bf91c2edae641c93b511f3010ded389")
	co, ok := objs.get(head)
	if !ok || co.typ != gitCommit {
		t.Fatalf("the head commit is not in the pack (%d objects)", len(objs.objs))
	}
	ci, err := parseGitCommit(co.data)
	if err != nil || ci.committed.Format(time.RFC3339) != "2026-11-15T18:16:25Z" {
		t.Fatalf("commit %+v (%v)", ci, err)
	}
	dir := t.TempDir()
	parent, _ := parseOID("9ee49c80e1216155e15ee08c43525438b2e17ffc")
	if err := os.WriteFile(dir+"/"+gitStoreName("trees-", parent), fixture(t, "git", "bcr-parent-trees.gz"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := loadGitTreeStore(files{dir: dir}, "trees-", parent)
	if err != nil {
		t.Fatal(err)
	}
	look := func(id gitOID) ([]byte, bool) {
		if o, ok := objs.get(id); ok {
			return o.data, true
		}
		return st.lookup(id)
	}
	var changes []string
	err = diffGitTrees(look, func(string) bool { return true }, st.root, ci.tree, "", func(p string, c gitChange) error {
		changes = append(changes, fmt.Sprintf("%d %s", c, p))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "git", "bcr-incremental-diff", changes)
}

func TestPacksWithDeltas(t *testing.T) {
	a := gitObject{typ: gitBlob, data: []byte("hello, world: the first version of the file\n")}
	b := gitObject{typ: gitBlob, data: []byte("hello, world: the second version of the file, longer\n")}
	// An offset delta and a reference delta of b against a.
	for _, ref := range []bool{false, true} {
		var buf bytes.Buffer
		buf.WriteString("PACK")
		binary.Write(&buf, binary.BigEndian, uint32(2))
		binary.Write(&buf, binary.BigEndian, uint32(2))
		offA := buf.Len()
		buf.Write(packHeader(gitBlob, len(a.data)))
		buf.Write(zlibBytes(a.data))
		d := makeDelta(a.data, b.data)
		if ref {
			buf.Write(packHeader(gitRefDelta, len(d)))
			id := hashObject(gitBlob, a.data)
			buf.Write(id[:])
		} else {
			rel := buf.Len() - offA
			buf.Write(packHeader(gitOfsDelta, len(d)))
			buf.WriteByte(byte(rel)) // < 128
		}
		buf.Write(zlibBytes(d))
		sum := sha1.Sum(buf.Bytes()) //nolint:gosec
		buf.Write(sum[:])
		objs, err := parsePack(buf.Bytes())
		if err != nil {
			t.Fatalf("ref=%v: %v", ref, err)
		}
		got, ok := objs.get(hashObject(gitBlob, b.data))
		if !ok || !bytes.Equal(got.data, b.data) {
			t.Errorf("ref=%v: the delta did not rebuild the object", ref)
		}
	}
}

func TestMalformedPacksAndDeltas(t *testing.T) {
	good := buildTestPack([]gitObject{{typ: gitBlob, data: []byte("x")}}, false)
	corrupt := func(edit func([]byte) []byte) []byte {
		p := append([]byte(nil), good...)
		p = edit(p)
		body := p[:len(p)-20]
		sum := sha1.Sum(body) //nolint:gosec
		return append(append([]byte(nil), body...), sum[:]...)
	}
	cases := map[string][]byte{
		"short":         []byte("PACK"),
		"magic":         append([]byte("KCAP"), good[4:]...),
		"checksum":      append(append([]byte(nil), good[:len(good)-1]...), good[len(good)-1]^1),
		"version":       corrupt(func(p []byte) []byte { p[7] = 9; return p }),
		"count":         corrupt(func(p []byte) []byte { p[11] = 2; return p }),
		"type 5":        corrupt(func(p []byte) []byte { p[12] = (p[12] & 0x8f) | 5<<4; return p }),
		"trailing data": corrupt(func(p []byte) []byte { return append(p[:len(p)-20], append([]byte{0}, p[len(p)-20:]...)...) }),
		"size mismatch": corrupt(func(p []byte) []byte { p[12] = (p[12] & 0xf0) | 2; return p }),
	}
	for name, p := range cases {
		if _, err := parsePack(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	base := []byte("0123456789")
	for name, d := range map[string][]byte{
		"base size":    {5, 3, 3, 'a', 'b', 'c'},
		"copy beyond":  {10, 4, 0x90 | 0x01, 8, 4},
		"opcode 0":     {10, 1, 0},
		"short insert": {10, 4, 4, 'a'},
		"too long":     {10, 1, 2, 'a', 'b'},
		"too short":    {10, 3, 1, 'a'},
		"bad varint":   {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80},
	} {
		if _, err := applyDelta(base, d); err == nil {
			t.Errorf("delta %s: accepted", name)
		}
	}
	if out, err := applyDelta(base, []byte{10, 4, 0x91, 2, 4}); err != nil || string(out) != "2345" {
		t.Errorf("copy: %q %v", out, err)
	}
	for _, bad := range [][]byte{[]byte("40000 \x00" + strings.Repeat("x", 20)), []byte("100644 a/b\x00" + strings.Repeat("x", 20)), []byte("100644 a\x00short"), []byte("9 a\x00" + strings.Repeat("x", 20)), []byte("x")} {
		if _, err := parseGitTree(bad); err == nil {
			t.Errorf("tree %q accepted", bad)
		}
	}
	if _, err := parseGitCommit([]byte("author x\n\nmessage")); err == nil {
		t.Errorf("a commit without a tree accepted")
	}
}

// testGitSpec follows "pkgs/<name>/<version>" files in a gitTestRepo.
var testGitSpec = gitIndexSpec{
	typ: "test",
	area: func(dir string) bool {
		return dir == "" || dir == "pkgs" || strings.HasPrefix(dir, "pkgs/")
	},
	coordinate: func(p string, c gitChange) (Coordinate, bool) {
		parts := strings.Split(p, "/")
		if len(parts) != 3 || parts[0] != "pkgs" {
			return Coordinate{}, false
		}
		return Coordinate{Name: parts[1], Version: parts[2], Deleted: c == gitDeleted}, true
	},
}

func newTestGitIndex(t *testing.T, repoURL string) *gitIndex {
	t.Helper()
	k, err := newKit(Env{Upstream: "t", Type: "test", URL: "https://registry.example", HTTP: http.DefaultClient, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(repoURL)
	g, err := newGitIndex(k, testGitSpec, u, "")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGitIndexBootstrapsThenFollowsTreeDifferences(t *testing.T) {
	repo := newGitTestRepo()
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	files := map[string]string{"README.md": "registry", "pkgs/alpha/1.0": "a1", "pkgs/alpha/1.1": "a11", "pkgs/beta/0.1": "b", "pkgs/gamma/2.0": "g", "ci/config.yml": "x"}
	repo.commit(files, t0, false)
	srv := newGitTestServer(t, repo)
	srv.deltas = true
	g := newTestGitIndex(t, srv.URL())
	g.page = 3
	ctx := context.Background()

	b1, err := g.bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if !b1.More || len(b1.Items) != 3 || !srv.lastFetch().deepen {
		t.Fatalf("first page %+v, fetch %+v", b1, srv.lastFetch())
	}
	b2, err := g.bootstrap(ctx, b1.Next)
	if err != nil {
		t.Fatal(err)
	}
	if b2.More || len(b2.Items) != 1 || b2.Items[0] != (Coordinate{Name: "gamma", Version: "2.0"}) {
		t.Fatalf("second page %+v", b2)
	}
	if !b2.HeadTime.Equal(t0) {
		t.Errorf("head time %v", b2.HeadTime)
	}

	// Nothing new: no fetch, the cursor stays.
	fetches := len(srv.fetches)
	b3, err := g.changes(ctx, b2.Next)
	if err != nil || len(b3.Items) != 0 || b3.Next != b2.Next || len(srv.fetches) != fetches {
		t.Fatalf("idle poll %+v %v", b3, err)
	}

	// A new version, a removed one, a changed file outside the area.
	files["pkgs/beta/0.2"] = "b2"
	delete(files, "pkgs/alpha/1.0")
	files["ci/config.yml"] = "y"
	repo.commit(files, t0.Add(time.Hour), false)
	b4, err := g.changes(ctx, b2.Next)
	if err != nil {
		t.Fatal(err)
	}
	want := []Coordinate{{Name: "alpha", Version: "1.0", Deleted: true}, {Name: "beta", Version: "0.2"}}
	if fmt.Sprint(b4.Items) != fmt.Sprint(want) || b4.More {
		t.Errorf("changes %+v, want %+v", b4.Items, want)
	}
	if f := srv.lastFetch(); f.deepen || f.have == "" || f.objects > 6 { // the commit and the 5 trees it changed
		t.Errorf("the fetch was not incremental: %+v", f)
	}

	// The engine may ask again from the same cursor after a restart: the
	// stored commit's trees are kept until the cursor moves on.
	again, err := g.changes(ctx, b2.Next)
	if err != nil || fmt.Sprint(again.Items) != fmt.Sprint(want) {
		t.Errorf("asking again: %+v %v", again, err)
	}

	// The history is squashed into an unrelated commit with the same trees
	// plus one version: the difference is just that version.
	files["pkgs/delta/1.0"] = "d"
	repo.commit(files, t0.Add(2*time.Hour), true)
	b5, err := g.changes(ctx, b4.Next)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(b5.Items) != fmt.Sprint([]Coordinate{{Name: "delta", Version: "1.0"}}) {
		t.Errorf("after the squash %+v", b5.Items)
	}
	// Only the stores of the cursor in use and of the new head are kept.
	entries, _ := os.ReadDir(g.files.dir)
	stores := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), gitStorePrefix) {
			stores++
		}
	}
	if stores != 2 {
		t.Errorf("%d tree stores kept", stores)
	}
}

func TestGitIndexLongDifferencesSpanBatches(t *testing.T) {
	repo := newGitTestRepo()
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	files := map[string]string{"pkgs/a/1": "x"}
	repo.commit(files, t0, false)
	g := newTestGitIndex(t, newGitTestServer(t, repo).URL())
	ctx := context.Background()
	b, err := g.bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		files[fmt.Sprintf("pkgs/n%d/1", i)] = "y"
	}
	repo.commit(files, t0.Add(time.Minute), false)
	g.page = 3
	var got []string
	cur := b.Next
	for i := 0; i < 5; i++ {
		nb, err := g.changes(ctx, cur)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, names(nb.Items)...)
		cur = nb.Next
		if !nb.More {
			break
		}
	}
	if len(got) != 7 {
		t.Errorf("changes over batches: %v", got)
	}
	var c gitCursor
	_ = decodeCursor(cur, g.format(), &c)
	if c.Commit != repo.head.String() || c.To != "" {
		t.Errorf("final cursor %+v", c)
	}
}

func TestGitIndexCursorWithoutStoredTreesIsInvalid(t *testing.T) {
	repo := newGitTestRepo()
	repo.commit(map[string]string{"pkgs/a/1": "x"}, time.Now(), false)
	g := newTestGitIndex(t, newGitTestServer(t, repo).URL())
	_, err := g.changes(context.Background(), g.cursor(gitCursor{Commit: strings.Repeat("ab", 20)}))
	mustErr(t, err, false, true, "not stored")
	_, err = g.changes(context.Background(), g.cursor(gitCursor{Commit: "nothex"}))
	mustErr(t, err, false, true, "")
	// A damaged store is no better than a missing one.
	b, err := g.bootstrap(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	name := g.files.path(gitStoreName(gitStorePrefix, repo.head))
	data, _ := os.ReadFile(name)
	os.WriteFile(name, data[:len(data)/2], 0o644)
	_, err = g.changes(context.Background(), b.Next)
	mustErr(t, err, false, true, "not stored")
}

func TestGitIndexFallsBackToASnapshotWhenTreesAreMissing(t *testing.T) {
	// The server takes the follower to hold every tree of the stored commit's
	// history; a store that lacks one (the area grew, a tree of an older
	// commit came back) must not end the feed: a snapshot is fetched.
	repo := newGitTestRepo()
	t0 := time.Now().Add(-time.Hour)
	repo.commit(map[string]string{"pkgs/a/1": "x", "pkgs/b/1": "y"}, t0, false)
	srv := newGitTestServer(t, repo)
	g := newTestGitIndex(t, srv.URL())
	ctx := context.Background()
	b, err := g.bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	// Drop pkgs/b's tree from the store: the next head keeps it unchanged,
	// so the incremental fetch will not send it.
	st, _ := loadGitTreeStore(g.files, gitStorePrefix, repo.head)
	entries, _ := parseGitTree(st.trees[st.root])
	pk, _ := parseGitTree(st.trees[entries[0].id])
	for _, e := range pk {
		if e.name == "b" {
			delete(st.trees, e.id)
		}
	}
	if err := saveGitTreeStore(g.files, gitStorePrefix, st); err != nil {
		t.Fatal(err)
	}
	repo.commit(map[string]string{"pkgs/a/1": "x", "pkgs/a/2": "z", "pkgs/b/1": "y"}, t0.Add(time.Minute), false)
	nb, err := g.changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(nb.Items) != fmt.Sprint([]Coordinate{{Name: "a", Version: "2"}}) {
		t.Errorf("items %+v", nb.Items)
	}
	if f := srv.lastFetch(); !f.deepen {
		t.Errorf("no snapshot was fetched after the miss: %+v", f)
	}
}

func TestGitFetchErrors(t *testing.T) {
	ctx := context.Background()
	srv := newFixtureServer(t)
	k, _ := newKit(Env{URL: "https://registry.example", HTTP: http.DefaultClient})
	u, _ := url.Parse(srv.URL() + "/repo")
	g := newGitRemote(k, u)
	// A v0/v1 server.
	srv.on("GET", "/repo/info/refs").reply(200, append(pktLine("# service=git-upload-pack\n"), append(pktFlush, pktLine("abc HEAD\x00caps\n")...)...))
	_, err := g.head(ctx, "")
	mustErr(t, err, true, false, "version 2")
	// A server reporting an error on the side band.
	g = newGitRemote(k, u)
	srv.on("GET", "/repo/info/refs").reply(200, fixture(t, "git", "info-refs.bin"))
	srv.on("POST", "/repo/git-upload-pack").reply(200, append(append(pktLine("packfile\n"), pktLine("\x03fatal: repository broken\n")...), pktFlush...))
	_, err = g.fetchTrees(ctx, strings.Repeat("a", 40), "")
	if err == nil || !strings.Contains(err.Error(), "repository broken") {
		t.Errorf("side-band error: %v", err)
	}
	// Packfile URIs are refused; an unknown section too.
	srv.on("POST", "/repo/git-upload-pack").reply(200, append(pktLine("packfile-uris\n"), pktFlush...))
	_, err = g.fetchTrees(ctx, strings.Repeat("a", 40), "")
	if err == nil {
		t.Errorf("packfile URIs accepted")
	}
	// An incremental fetch past its bound asks for a snapshot.
	big := pktLine("packfile\n")
	chunk := pktLine("\x01" + strings.Repeat("x", 60000))
	for n := 0; n <= maxGitIncremental/60000; n++ {
		big = append(big, chunk...)
	}
	srv.on("POST", "/repo/git-upload-pack").reply(200, append(big, pktFlush...))
	_, err = g.fetchTrees(ctx, strings.Repeat("a", 40), strings.Repeat("b", 40))
	if !errors.Is(err, errGitIncrementalTooLarge) {
		t.Errorf("an oversized incremental fetch: %v", err)
	}
	// A 404 is permanent; the repository URL is not a v2 server at all.
	srv.on("GET", "/repo/info/refs").reply(404, nil)
	g = newGitRemote(k, u)
	_, err = g.head(ctx, "")
	mustErr(t, err, true, false, "not found")
	_ = io.EOF
	_ = path.Base
}
