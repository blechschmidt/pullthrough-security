package repos

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
	"github.com/blechschmidt/pullthrough-security/internal/repos/sandbox"
	"github.com/blechschmidt/pullthrough-security/internal/repos/update"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

func TestIgnoreList(t *testing.T) {
	repo := Repo{Name: "r", Update: &RepoUpdate{Ignore: []string{
		"npm/lodash", "pip/Django@>=5.0", "cargo/serde@1.0.200", "*/internal-*", "npm/@scope/pkg@^2",
	}}}
	list, err := parseIgnores(repo)
	if err != nil {
		t.Fatal(err)
	}
	if ig, _ := list.dependency("npm", "lodash"); !ig {
		t.Error("npm/lodash: every version is ignored")
	}
	if ig, _ := list.dependency("npm", "lodash-es"); ig {
		t.Error("npm/lodash-es is not named")
	}
	if ig, _ := list.dependency("go", "internal-tools"); !ig {
		t.Error("*/internal-* matches any type")
	}
	check := func(typ, name, v string, want bool) {
		t.Helper()
		sch, _ := versions.For(typ)
		pv, err := sch.Parse(v)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := list.version(sch, typ, name, pv); got != want {
			t.Errorf("%s/%s@%s ignored %v, want %v", typ, name, v, got, want)
		}
	}
	check("pip", "django", "5.0.1", true)
	check("pip", "django", "4.2.9", false)
	check("cargo", "serde", "1.0.200", true)
	check("cargo", "serde", "1.0.201", false)
	check("npm", "@scope/pkg", "2.3.0", true)
	check("npm", "@scope/pkg", "3.0.0", false)
	for _, bad := range []string{"lodash", "npm/", "/x", "pip/requests@not a version ^^"} {
		if _, err := parseIgnore(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestValidateUpdate(t *testing.T) {
	ok := Repo{Name: "r", Branch: "main", Update: &RepoUpdate{Branch: "deps/maintenance", MaxBump: "patch", Forge: "GitHub",
		ForgeTokenRef: "env://GH_TOKEN", ForgeAPI: "https://ghe.example/api/v3", Ignore: []string{"npm/x"}}}
	if err := ok.validateUpdate(); err != nil || ok.Update.Forge != "github" {
		t.Fatalf("valid settings refused: %v", err)
	}
	for name, u := range map[string]RepoUpdate{
		"branch":         {Branch: "../x"},
		"followed":       {Branch: "main"},
		"maxBump":        {MaxBump: "major"},
		"forge":          {Forge: "bitbucket"},
		"literal token":  {ForgeTokenRef: "ghp_secret"},
		"api scheme":     {ForgeAPI: "ftp://x"},
		"api userinfo":   {ForgeAPI: "https://u:p@x"},
		"ignore":         {Ignore: []string{"nonsense"}},
		"forge repo nul": {ForgeRepo: "a\x00b"},
	} {
		u := u
		r := Repo{Name: "r", Branch: "main", Update: &u}
		if err := r.validateUpdate(); err == nil {
			t.Errorf("%s: invalid settings accepted", name)
		}
	}
}

func TestCommitMessage(t *testing.T) {
	run := &UpdateRun{ID: "20261113t000000.000z-0a0b0c0d", BaseBranch: "main", Base: strings.Repeat("a", 40),
		Updates: []AppliedUpdate{{Type: "npm", Name: "left-pad", From: "1.0.0", To: "1.0.1", Bump: "patch", Method: "native",
			Verdict: "benign", ScanIDs: []string{"abc-123"}}},
		Skipped: []SkippedCandidate{{Type: "npm", Name: "left-pad", From: "1.0.0", To: "1.1.0", Code: SkipMalicious,
			Reason: "package: judged malicious\n\x1b[31mINJECTED"}},
	}
	msg := commitMessage(run)
	for _, want := range []string{"Update left-pad from 1.0.0 to 1.0.1\n", "- npm/left-pad 1.0.0 -> 1.0.1 (patch, native): verdict benign, scan abc-123",
		"- npm/left-pad 1.0.0 -> 1.1.0: malicious: package: judged malicious", "Pullthrough-Run: " + run.ID} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "\x1b") || strings.Contains(msg, "malicious\n\x1b") {
		t.Errorf("control characters from a reason reached the message: %q", msg)
	}
	body := pullRequestBody(run)
	if !strings.Contains(body, "| `npm/left-pad` | `1.0.0` | `1.0.1` |") || strings.Contains(body, "\x1b") {
		t.Errorf("pull request body:\n%s", body)
	}
}

func TestFilterPackument(t *testing.T) {
	doc := `{"name":"x","dist-tags":{"latest":"2.0.0"},"versions":{"1.0.0":{},"1.0.1":{},"1.1.0":{},"2.0.0":{}},"time":{"1.0.0":"t"}}`
	sch, _ := versions.For("npm")
	out, err := filterPackument([]byte(doc), sch, "1.0.1", map[string]bool{"1.1.0": true})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Tags     map[string]string          `json:"dist-tags"`
		Versions map[string]json.RawMessage `json:"versions"`
		Time     map[string]string          `json:"time"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Versions) != 2 || got.Versions["1.0.0"] == nil || got.Versions["1.0.1"] == nil || got.Tags["latest"] != "1.0.1" || got.Time != nil {
		t.Fatalf("filtered: %s", out)
	}
}

func TestRestoreNPMResolved(t *testing.T) {
	before := []byte(`{"packages":{"":{},"node_modules/a":{"resolved":"https://registry.example/npm/a/-/a-1.0.0.tgz"},
		"node_modules/@s/b":{"resolved":"https://registry.example/npm/@s/b/-/b-2.0.0.tgz"},
		"node_modules/c":{"resolved":"https://other.example/c/-/c-1.0.0.tgz"}}}`)
	if base := npmRegistryBase(before); base != "https://registry.example/npm/" {
		t.Fatalf("base %q", base)
	}
	after := []byte(`{"resolved": "` + sandbox.BaseURL + `/v1/npm/a/-/a-1.0.1.tgz"}`)
	got := string(restoreNPMResolved(after, "npm", before))
	if got != `{"resolved": "https://registry.example/npm/a/-/a-1.0.1.tgz"}` {
		t.Fatalf("restored: %s", got)
	}
}

func TestLooksLikeArchive(t *testing.T) {
	for name, b := range map[string][]byte{"gzip": {0x1f, 0x8b, 8}, "zip": []byte("PK\x03\x04rest"), "xz": {0xfd, '7', 'z', 'X', 'Z', 0}} {
		if !looksLikeArchive(b) {
			t.Errorf("%s not recognised", name)
		}
	}
	tar := make([]byte, 512)
	copy(tar[257:], "ustar")
	if !looksLikeArchive(tar) || looksLikeArchive([]byte(`{"versions":{}}`)) {
		t.Error("tar / json")
	}
}

func TestGoModExcludes(t *testing.T) {
	got := goModExcludes([]byte("module x\nexclude example.com/a v1.2.0\nexclude (\n\texample.com/b v0.3.0 // broken\n)\n"))
	if strings.Join(got, ",") != "example.com/a@v1.2.0,example.com/b@v0.3.0" {
		t.Fatalf("excludes: %v", got)
	}
}

func TestCatalogCoversEveryLockFileFormat(t *testing.T) {
	for _, f := range update.Formats() {
		if f.Reason == "" || f.Type == "" || f.Format == "" {
			t.Errorf("%s/%s: incomplete entry %+v", f.Type, f.Format, f)
		}
		if f.Method == update.Native && update.NativeUpdater(f.Type+"/"+f.Format) == nil {
			t.Errorf("%s/%s is said to be updated natively, and has no native updater", f.Type, f.Format)
		}
		if (f.Method == update.Sandbox || f.Fallback == update.Sandbox) && f.Tool == "" {
			t.Errorf("%s/%s falls back to the sandbox without naming a tool", f.Type, f.Format)
		}
	}
}

// scriptedFetcher answers fetches by path.
type scriptedFetcher map[string]FetchResult

func (f scriptedFetcher) Fetch(_ context.Context, req FetchRequest, body io.Writer) (FetchResult, error) {
	res, ok := f[req.Path]
	if !ok {
		return FetchResult{Status: http.StatusNotFound}, nil
	}
	if res.ContentType == "archive" {
		_, _ = body.Write([]byte{0x1f, 0x8b, 8, 0, 0, 0})
		res.ContentType = "application/octet-stream"
	} else {
		_, _ = body.Write([]byte(`{"dist":{"tarball":"https://proxy.example/v1/npm/a/-/a-1.0.1.tgz"},"versions":{"1.0.0":{},"1.0.1":{},"1.1.0":{}}}`))
	}
	return res, nil
}

// scriptedScanner answers ScanObject by cache key.
type scriptedScanner map[string]ObjectScan

func (s scriptedScanner) Status() ScannerStatus               { return ScannerStatus{Enabled: true} }
func (s scriptedScanner) Scope(string, string) (bool, string) { return true, "" }
func (s scriptedScanner) ScanObject(_ context.Context, req ObjectScanRequest) (ObjectScan, error) {
	return s[req.CacheKey], nil
}

func TestSandboxSessionServesOnlyScannedBenign(t *testing.T) {
	benign := &ObjectScan{Applicable: true, Verdict: VerdictBenign}
	malicious := &ObjectScan{Applicable: true, Verdict: VerdictMalicious}
	unscanned := &ObjectScan{Applicable: true, Verdict: VerdictUnscanned, Unscanned: &UnscannedInfo{Code: "scanner-busy"}}
	notPkg := &ObjectScan{NotApplicable: "not-package-content"}
	outOfScope := &ObjectScan{NotApplicable: UnscannedOutOfScope}
	s := &Service{opts: Options{
		Fetcher: scriptedFetcher{
			"/a/-/a-1.0.1.tgz": {Status: 200, ContentType: "archive", CacheKey: "k1", Digest: "sha256:1", LLM: benign},
			"/a/-/a-1.1.0.tgz": {Status: 200, ContentType: "archive", CacheKey: "k2", LLM: malicious},
			"/a/-/a-1.2.0.tgz": {Status: 200, ContentType: "archive", CacheKey: "k3", LLM: unscanned},
			"/b/-/b-1.0.0.tgz": {Status: 200, ContentType: "archive", CacheKey: "k4", LLM: outOfScope},
			"/c/-/c-1.0.0.tgz": {Status: 200, ContentType: "archive", CacheKey: "k5"}, // no reading on the way
			"/d/-/d-1.0.0.tgz": {Status: 200, ContentType: "archive"},                 // uncached, unjudged archive
			"/a":               {Status: 200, ContentType: "application/json", LLM: notPkg},
			"/blocked":         {Status: 403, Gate: "nameguard", Code: "typosquat", Reason: "too close to lodash"},
		},
		Scans: scriptedScanner{"k5": {Applicable: true, Verdict: VerdictBenign}},
	}}
	s.cfg = s.cfg.withDefaults()
	sch, _ := versions.For("npm")
	ss := &sandboxSession{s: s, repo: Repo{Name: "r", Tenant: "t"}, upstreams: map[string]bool{"npm": true},
		targets: map[string]string{"a": "1.0.1"}, rejected: map[string]map[string]bool{"a": {"1.1.0": true}},
		scheme: sch, ecosys: "npm", publicPrefix: "https://proxy.example/v1/", sem: make(chan struct{}, 2)}
	get := func(method, path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		ss.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
		return rr
	}
	for path, want := range map[string]int{
		"/v1/npm/a/-/a-1.0.1.tgz": 200, "/v1/npm/a/-/a-1.1.0.tgz": 403, "/v1/npm/a/-/a-1.2.0.tgz": 403,
		"/v1/npm/b/-/b-1.0.0.tgz": 403, "/v1/npm/c/-/c-1.0.0.tgz": 200, "/v1/npm/d/-/d-1.0.0.tgz": 403,
		"/v1/npm/blocked": 403, "/v1/npm/missing": 404, "/v1/pypi/a": 403, "/v1/npm/a": 200,
	} {
		if rr := get(http.MethodGet, path); rr.Code != want {
			t.Errorf("%s: %d, want %d (%s)", path, rr.Code, want, strings.TrimSpace(rr.Body.String()))
		}
	}
	if rr := get(http.MethodPost, "/v1/npm/a"); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rr.Code)
	}
	if rr := get(http.MethodGet, "/v1/npm/a?write=true"); rr.Code != http.StatusBadRequest {
		t.Errorf("query: %d", rr.Code)
	}
	for _, p := range []string{"/v1/npm/a/../../admin", "/v1/npm/a//b", "/v1/npm/./a", "/v1/npm/a%5cb"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = strings.ReplaceAll(p, "%5c", "\\")
		ss.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", p, rr.Code)
		}
	}
	// Metadata: links to the public URL point at the sandbox, and the
	// updated package's packument offers nothing newer than the vetted
	// version, and not the version the updater skipped.
	body := get(http.MethodGet, "/v1/npm/a").Body.String()
	if !strings.Contains(body, sandbox.BaseURL+"/v1/npm/a/-/a-1.0.1.tgz") || strings.Contains(body, "proxy.example") ||
		strings.Contains(body, `"1.1.0"`) || !strings.Contains(body, `"latest":"1.0.1"`) {
		t.Errorf("metadata: %s", body)
	}
	if len(ss.served) != 2 || len(ss.refusals()) < 5 {
		t.Errorf("served %v refused %v", ss.served, ss.refusals())
	}
}

func TestOwnCommit(t *testing.T) {
	commit := func(parents int, committer, message string) []byte {
		var b strings.Builder
		b.WriteString("tree " + strings.Repeat("a", 40) + "\n")
		for i := 0; i < parents; i++ {
			b.WriteString("parent " + strings.Repeat("b", 40) + "\n")
		}
		b.WriteString("author x <x@example.com> 1700000000 +0000\ncommitter " + committer + " 1700000000 +0000\n\n" + message)
		return []byte(b.String())
	}
	ours := "pullthrough-security <pullthrough@localhost>"
	trailer := "Update 1 dependency\n\nPullthrough-Run: 20261113t000000.000z-0a0b0c0d\n"
	for name, tc := range map[string]struct {
		raw  []byte
		want bool
	}{
		"ours":              {commit(1, ours, trailer), true},
		"another committer": {commit(1, "Dev <dev@example.com>", trailer), false},
		"no trailer":        {commit(1, ours, "Update\n"), false},
		"bad run id":        {commit(1, ours, "x\n\nPullthrough-Run: ../../x\n"), false},
		"a merge":           {commit(2, ours, trailer), false},
		"no header end":     {[]byte("tree x"), false},
	} {
		s := &Service{opts: Options{Branches: commitObjectsOf{raw: tc.raw}}}
		s.cfg = s.cfg.withDefaults()
		if got := s.ownCommit(context.Background(), Repo{Name: "r"}, strings.Repeat("c", 40)); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// commitObjectsOf answers CommitObject with fixed bytes.
type commitObjectsOf struct {
	BranchSource
	raw []byte
}

func (c commitObjectsOf) CommitObject(context.Context, Repo, string) ([]byte, error) {
	return c.raw, nil
}

// TestVetResolutionHoldsEntriesToTheVettedBytes: an entry a sandboxed
// resolution writes must record a digest of the bytes vetted, and a download
// URL the upstream serves — never one elsewhere, never none.
func TestVetResolutionHoldsEntriesToTheVettedBytes(t *testing.T) {
	sum := strings.Repeat("ab", 64) // the vetted bytes' SHA-512, hex
	sri := "sha512-" + base64.StdEncoding.EncodeToString(mustHex(t, sum))
	lock := func(resolved, integrity string) []byte {
		e := map[string]any{"version": "1.0.1"}
		if resolved != "" {
			e["resolved"] = resolved
		}
		if integrity != "" {
			e["integrity"] = integrity
		}
		doc, _ := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": map[string]any{"": map[string]any{}, "node_modules/a": e}})
		return doc
	}
	before := map[string][]byte{"package-lock.json": []byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-AAAA"}}}`)}
	plan := &plannedUpdate{dep: Dependency{Type: "npm", Name: "a", Version: "1.0.0"}, to: "1.0.1", upstream: "npm",
		change: update.Change{Type: "npm", Name: "a", From: "1.0.0", To: "1.0.1", Artifacts: []update.Artifact{{Role: "package", SHA512: sum}}}}
	s := &Service{opts: Options{Upstreams: []locate.Upstream{{Name: "npm", Type: "npm", URLs: []string{"https://registry.npmjs.org"}}}}}
	s.cfg = s.cfg.withDefaults()
	env := locate.Env{Upstreams: s.opts.Upstreams}
	lf := LockFile{Path: "package-lock.json", Type: "npm", Format: "package-lock.json"}
	for name, tc := range map[string]struct {
		after    []byte
		wantCode string
	}{
		"vetted":      {lock("https://registry.npmjs.org/a/-/a-1.0.1.tgz", sri), ""},
		"foreign URL": {lock("https://evil.example/a/-/a-1.0.1.tgz", sri), SkipResolution},
		"no digest":   {lock("https://registry.npmjs.org/a/-/a-1.0.1.tgz", ""), SkipResolution},
		"other bytes": {lock("https://registry.npmjs.org/a/-/a-1.0.1.tgz", "sha512-"+base64.StdEncoding.EncodeToString(mustHex(t, strings.Repeat("cd", 64)))), SkipResolution},
	} {
		code, why := s.vetResolution(context.Background(), Repo{Name: "r"}, env, lf, before,
			map[string][]byte{"package-lock.json": tc.after}, []*plannedUpdate{plan})
		if code != tc.wantCode {
			t.Errorf("%s: %q (%s), want %q", name, code, why, tc.wantCode)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// filesOf answers ReadFiles from a map.
type filesOf struct {
	BranchSource
	files map[string][]byte
}

func (f filesOf) ReadFiles(_ context.Context, _ Repo, _ string, paths []string, _ int64) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, p := range paths {
		if d, ok := f.files[p]; ok {
			out[p] = d
		}
	}
	return out, nil
}

// ListFiles answers from the map's paths, as the tree listing does: sorted,
// at most max+1.
func (f filesOf) ListFiles(_ context.Context, _ Repo, _, dir string, match func(string) bool, max int) ([]string, error) {
	var out []string
	for p := range f.files {
		if (dir == "" || dir == "." || strings.HasPrefix(p, dir+"/")) && (match == nil || match(p)) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	if len(out) > max+1 {
		out = out[:max+1]
	}
	return out, nil
}

// TestRedirectedDependenciesAreNotUpdated: what the repository says besides
// the lock file — a vendored tree, a replace directive of go.mod or of a
// workspace, a Cargo patch or source replacement, an npm override, a package
// source for a pin without a hash — keeps the updater from moving what it
// redirects: the new version may be what the redirection names.
func TestRedirectedDependenciesAreNotUpdated(t *testing.T) {
	hashed := []lockfiles.Digest{{Algorithm: "sha256", Value: strings.Repeat("a", 64)}}
	plan := func(typ, name string, digests []lockfiles.Digest) *plannedUpdate {
		return &plannedUpdate{dep: Dependency{Type: typ, Name: name, Version: "1.0.0", LockDigests: digests, Unverified: len(digests) == 0}}
	}
	for _, tc := range []struct {
		name  string
		files map[string]string
		lf    LockFile
		plans []*plannedUpdate
		// all: the reason refusing every update; refused: the names refused.
		all     string
		code    string
		refused []string
	}{
		{name: "go vendored", files: map[string]string{"svc/go.mod": "module x\n", "svc/vendor/modules.txt": "# example.com/a v1.0.0\n"},
			lf: LockFile{Path: "svc/go.mod", Type: "go", Format: "go.mod"}, plans: []*plannedUpdate{plan("go", "example.com/a", hashed)},
			all: "vendors its dependencies", code: SkipNotWritable},
		{name: "go plain", files: map[string]string{"go.mod": "module x\n\nrequire example.com/a v1.0.0\n"},
			lf: LockFile{Path: "go.mod", Type: "go", Format: "go.mod"}, plans: []*plannedUpdate{plan("go", "example.com/a", hashed)}},
		{name: "go.mod replace", files: map[string]string{"go.mod": "module x\n\nrequire example.com/a v1.0.0\nreplace example.com/a v1.0.1 => ./evil\n"},
			lf: LockFile{Path: "go.mod", Type: "go", Format: "go.sum"}, plans: []*plannedUpdate{plan("go", "example.com/a", hashed), plan("go", "example.com/b", hashed)},
			refused: []string{"example.com/a"}, code: SkipRedirected},
		{name: "workspace replace", files: map[string]string{
			"svc/go.mod": "module x\n", "go.work": "go 1.22\n\nuse (\n\t./svc\n\t./lib\n)\n\nreplace example.com/a v1.0.1 => ./evil\n",
			"lib/go.mod": "module example.com/b\n\nreplace example.com/c => ../c\n"},
			lf:      LockFile{Path: "svc/go.mod", Type: "go", Format: "go.mod"},
			plans:   []*plannedUpdate{plan("go", "example.com/a", hashed), plan("go", "example.com/b", hashed), plan("go", "example.com/c", hashed), plan("go", "example.com/d", hashed)},
			refused: []string{"example.com/a", "example.com/b", "example.com/c"}, code: SkipRedirected},
		{name: "a workspace without the module", files: map[string]string{
			"svc/go.mod": "module x\n", "other/go.work": "go 1.22\nuse ./lib\nreplace example.com/a => ./evil\n"},
			lf: LockFile{Path: "svc/go.mod", Type: "go", Format: "go.mod"}, plans: []*plannedUpdate{plan("go", "example.com/a", hashed)}},

		{name: "cargo patch unused", files: map[string]string{"Cargo.toml": "[package]\nname = \"app\"\n",
			"Cargo.lock": "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[patch.unused]]\nname = \"itoa\"\nversion = \"1.0.11\"\n"},
			lf: LockFile{Path: "Cargo.lock", Type: "cargo", Format: "Cargo.lock"}, plans: []*plannedUpdate{plan("cargo", "itoa", hashed), plan("cargo", "ryu", hashed)},
			refused: []string{"itoa"}, code: SkipRedirected},
		{name: "cargo manifest patch", files: map[string]string{"rust/Cargo.toml": "[package]\nname = \"app\"\n\n[patch.crates-io]\nitoa = { path = \"evil-itoa\" }\n",
			"rust/Cargo.lock": "version = 4\n"},
			lf: LockFile{Path: "rust/Cargo.lock", Type: "cargo", Format: "Cargo.lock"}, plans: []*plannedUpdate{plan("cargo", "itoa", hashed), plan("cargo", "ryu", hashed)},
			refused: []string{"itoa"}, code: SkipRedirected},
		{name: "cargo vendored", files: map[string]string{"rust/Cargo.lock": "version = 4\n",
			"rust/.cargo/config.toml": "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory=\"vendor\"\n"},
			lf: LockFile{Path: "rust/Cargo.lock", Type: "cargo", Format: "Cargo.lock"}, plans: []*plannedUpdate{plan("cargo", "itoa", hashed)},
			all: "a source replacement", code: SkipRedirected},
		{name: "cargo configuration above and below", files: map[string]string{"rust/Cargo.lock": "version = 4\n",
			".cargo/config.toml": "[source.crates-io]\nreplace-with = \"mirror\"\n\n[source.mirror]\nregistry = \"https://m.example/index\"\n"},
			lf: LockFile{Path: "rust/Cargo.lock", Type: "cargo", Format: "Cargo.lock"}, plans: []*plannedUpdate{plan("cargo", "itoa", hashed)},
			all: ".cargo/config.toml redirects every crate", code: SkipRedirected},
		{name: "cargo member's patch", files: map[string]string{"rust/Cargo.lock": "version = 4\n",
			"rust/member/.cargo/config": "[patch.crates-io]\nitoa = { path = \"x\" }\n", "other/.cargo/config.toml": "paths = [\"../x\"]\n"},
			lf: LockFile{Path: "rust/Cargo.lock", Type: "cargo", Format: "Cargo.lock"}, plans: []*plannedUpdate{plan("cargo", "itoa", hashed), plan("cargo", "ryu", hashed)},
			refused: []string{"itoa"}, code: SkipRedirected},

		{name: "npm override", files: map[string]string{"web/package.json": `{"name":"web","overrides":{"left-pad@1.0.1":"file:./evil"}}`, "web/package-lock.json": "{}"},
			lf: LockFile{Path: "web/package-lock.json", Type: "npm", Format: "package-lock.json"}, plans: []*plannedUpdate{plan("npm", "left-pad", hashed), plan("npm", "ms", hashed)},
			refused: []string{"left-pad"}, code: SkipRedirected},

		{name: "pip unhashed with local wheels", files: map[string]string{"requirements.txt": "-f ./wheels\ntinyutil==1.0.0\nsafe==1.0.0 --hash=sha256:" + strings.Repeat("a", 64) + "\n"},
			lf: LockFile{Path: "requirements.txt", Type: "pip", Format: "requirements.txt"}, plans: []*plannedUpdate{plan("pip", "tinyutil", nil), plan("pip", "safe", hashed)},
			refused: []string{"tinyutil"}, code: SkipRedirected},
		{name: "pip unhashed through the proxy and the registry", files: map[string]string{"requirements.txt": "-i https://proxy.example.com/v1/pypi/simple/\n--extra-index-url https://pypi.org/simple\ntinyutil==1.0.0\n"},
			lf: LockFile{Path: "requirements.txt", Type: "pip", Format: "requirements.txt"}, plans: []*plannedUpdate{plan("pip", "tinyutil", nil)}},
		{name: "pip include names another index", files: map[string]string{"py/requirements.txt": "-r base.txt\ntinyutil==1.0.0\n", "py/base.txt": "--extra-index-url https://evil.example/simple\n"},
			lf: LockFile{Path: "py/requirements.txt", Type: "pip", Format: "requirements.txt"}, plans: []*plannedUpdate{plan("pip", "tinyutil", nil)},
			refused: []string{"tinyutil"}, code: SkipRedirected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string][]byte{}
			for k, v := range tc.files {
				files[k] = []byte(v)
			}
			s := &Service{opts: Options{Branches: filesOf{files: files},
				Upstreams: []locate.Upstream{{Name: "pypi", Type: "pip", URLs: []string{"https://pypi.org/simple"}}}}}
			s.cfg.Lockfiles.Proxy = &lockfiles.Proxy{PublicURLs: []string{"https://proxy.example.com"},
				Upstreams: map[string]lockfiles.ProxyUpstream{"pypi": {Type: "pip", URL: "https://pypi.org/simple"}}}
			key := tc.lf.Type + "/" + tc.lf.Format
			r := s.redirects(context.Background(), Repo{Name: "r"}, strings.Repeat("a", 40), key, tc.lf, files, tc.plans)
			if (tc.all == "") != (r.all == "") || !strings.Contains(r.all, tc.all) {
				t.Fatalf("all: %q, want %q", r.all, tc.all)
			}
			var refused []string
			for n := range r.byName {
				refused = append(refused, n)
			}
			sort.Strings(refused)
			if strings.Join(refused, ",") != strings.Join(tc.refused, ",") {
				t.Fatalf("refused %v (%v), want %v", refused, r.byName, tc.refused)
			}
			if (r.all != "" || len(r.byName) > 0) && r.code != tc.code {
				t.Fatalf("code %q, want %q", r.code, tc.code)
			}
		})
	}
}
