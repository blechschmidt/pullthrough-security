package repos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
	"github.com/blechschmidt/pullthrough-security/internal/repos/sandbox"
	"github.com/blechschmidt/pullthrough-security/internal/repos/update"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// Re-resolution in the sandbox (Task 182).
//
// When an update needs the dependency graph resolved again, the ecosystem's
// real package manager does it in a network-less container (internal/repos/
// sandbox). Its only way out is a session of this proxy bound to the
// "scanned-benign-only" policy: registry metadata is served through the
// admission gates, and package content only when every gate admits it and the
// LLM package-content scan judged those exact bytes benign (scanned now when
// there is no verdict yet). The tool therefore cannot unpack, build or run a
// byte that has not been vetted. Lock-only resolvers do not download what
// they resolve, so every entry the resolution adds or changes is vetted the
// same way afterwards, and its recorded digests held to the bytes the proxy
// serves; one that fails makes the whole lock file's update fail.

// sandboxSession is the proxy as one sandboxed run sees it.
type sandboxSession struct {
	s         *Service
	repo      Repo
	upstreams map[string]bool
	// targets maps a package name to the version it is updated to; its
	// metadata lists no newer version and none the updater skipped, so a
	// resolver that picks "the newest allowed" picks the vetted one.
	targets  map[string]string
	rejected map[string]map[string]bool
	scheme   versions.Scheme
	ecosys   string
	// publicPrefix is the proxy's public URL followed by "/v1/": links to it
	// in metadata are pointed at the sandbox's own address.
	publicPrefix string
	spoolDir     string

	mu      sync.Mutex
	served  []string
	refused []string
	// sem bounds the requests served at once; relayed counts the bytes
	// relayed so far, held to maxSessionBytes.
	sem     chan struct{}
	relayed int64
}

// Bounds of a session: one response, all of them together, and the requests
// served at once (each may wait for an LLM scan and spool a package).
const (
	maxSandboxBody     = 1 << 30
	maxSessionBytes    = 4 << 30
	maxSessionRequests = 8
)

func (ss *sandboxSession) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case ss.sem <- struct{}{}:
		defer func() { <-ss.sem }()
	case <-r.Context().Done():
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "the sandbox session serves reads only", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "the sandbox session serves no queries", http.StatusBadRequest)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/")
	upstream, p, found := strings.Cut(rest, "/")
	if !ok || !found || !ss.upstreams[upstream] {
		ss.refuse(r.URL.Path, "not an upstream of this session")
		http.Error(w, "the sandbox session serves only the upstreams of the update", http.StatusForbidden)
		return
	}
	p = "/" + p
	if !plainSessionPath(p) {
		ss.refuse(r.URL.Path, "not a plain registry path")
		http.Error(w, "the sandbox session serves plain registry paths only", http.StatusBadRequest)
		return
	}
	spool, err := os.CreateTemp(ss.spoolDir, "ptsb-body-*")
	if err != nil {
		http.Error(w, "spooling the response failed", http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = spool.Close()
		_ = os.Remove(spool.Name())
	}()
	ctx := r.Context()
	lw := &limitWriter{w: spool, max: maxSandboxBody}
	res, err := ss.s.opts.Fetcher.Fetch(ctx, FetchRequest{Upstream: upstream, Path: p, Accept: r.Header.Get("Accept"),
		Tenant: ss.repo.Tenant, Subject: ss.s.cfg.Update.Subject, Roles: ss.s.rolesFor(ss.repo), DeferLLMRefusal: true}, lw)
	switch {
	case err != nil:
		http.Error(w, "the proxy could not fetch it: "+err.Error(), http.StatusBadGateway)
		return
	case res.Gate != "":
		ss.refuse(r.URL.Path, refusalReason(res))
		http.Error(w, refusalReason(res), http.StatusForbidden)
		return
	case res.Status != http.StatusOK:
		http.Error(w, http.StatusText(res.Status), res.Status)
		return
	}
	head := make([]byte, 512)
	n, _ := spool.ReadAt(head, 0)
	head = head[:n]

	// The scanned-benign-only policy.
	content, why := ss.vetResponse(ctx, upstream, p, res, head)
	if why != "" {
		ss.refuse(r.URL.Path, why)
		http.Error(w, "not served in the sandbox: "+why, http.StatusForbidden)
		return
	}
	ss.mu.Lock()
	over := ss.relayed+lw.n > maxSessionBytes
	if !over {
		ss.relayed += lw.n
	}
	ss.mu.Unlock()
	if over {
		ss.refuse(r.URL.Path, "the session relayed more than it may")
		http.Error(w, "the sandbox session relayed more than it may", http.StatusForbidden)
		return
	}
	var body io.Reader
	size := lw.n // what was spooled is what is relayed
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "reading the response failed", http.StatusInternalServerError)
		return
	}
	body = spool
	if !content {
		data, err := io.ReadAll(io.LimitReader(spool, 256<<20))
		if err != nil {
			http.Error(w, "reading the response failed", http.StatusInternalServerError)
			return
		}
		data = ss.rewriteMetadata(p, data)
		body, size = bytes.NewReader(data), int64(len(data))
	} else {
		ss.mu.Lock()
		ss.served = append(ss.served, r.URL.Path+" "+res.Digest)
		ss.mu.Unlock()
	}
	if res.ContentType != "" {
		w.Header().Set("Content-Type", res.ContentType)
	}
	if size > 0 {
		w.Header().Set("Content-Length", fmt.Sprint(size))
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = io.Copy(w, body)
	}
}

// plainSessionPath reports whether a decoded request path is a plain path:
// no dot segment, no empty segment, no backslash or control character. A tool
// in the sandbox has no business asking for anything else.
func plainSessionPath(p string) bool {
	if len(p) > 2048 || !strings.HasPrefix(p, "/") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return false
		}
	}
	segs := strings.Split(p[1:], "/")
	for i, seg := range segs {
		if seg == "." || seg == ".." || (seg == "" && i != len(segs)-1) {
			return false
		}
	}
	return true
}

// refusals returns what the session refused, so far.
func (ss *sandboxSession) refusals() []string {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return append([]string(nil), ss.refused...)
}

func (ss *sandboxSession) refuse(p, why string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if len(ss.refused) < 200 {
		ss.refused = append(ss.refused, p+": "+why)
	}
}

// vetResponse applies the policy: it reports whether the response is package
// content, and why it may not be served ("" when it may).
func (ss *sandboxSession) vetResponse(ctx context.Context, upstream, p string, res FetchResult, head []byte) (bool, string) {
	reading := res.LLM
	if reading == nil && res.CacheKey != "" && ss.s.opts.Scans != nil {
		// Cached, and the gate said nothing on the way: ask it (the stored
		// verdict, or a scan now).
		r, err := ss.s.opts.Scans.ScanObject(ctx, ObjectScanRequest{Upstream: upstream, Path: p,
			CacheKey: res.CacheKey, Digest: res.Digest, Tenant: ss.repo.Tenant, Subject: ss.s.cfg.Update.Subject, Roles: ss.s.rolesFor(ss.repo)})
		if err != nil {
			return true, "it could not be put before the LLM package scan: " + err.Error()
		}
		reading = &r
	}
	switch {
	case reading != nil && reading.Applicable:
		if reading.Verdict != VerdictBenign {
			v := reading.Verdict
			if v == "" {
				v = VerdictUnscanned
			}
			return true, "the LLM package scan's reading of these bytes is " + v + ", not benign"
		}
		return true, ""
	case reading != nil && reading.NotApplicable == UnscannedOutOfScope:
		return true, "the LLM package scan does not cover it: no benign verdict can be had"
	case reading != nil:
		return false, ""
	}
	// Not cached and not judged: a metadata document — unless its bytes say
	// it is an archive, which is never served unscanned.
	if looksLikeArchive(head) {
		return true, "an archive no LLM package scan has judged"
	}
	return false, ""
}

// looksLikeArchive reports archive magic: gzip, zip, xz, bzip2, zstd, tar.
func looksLikeArchive(b []byte) bool {
	switch {
	case bytes.HasPrefix(b, []byte{0x1f, 0x8b}), bytes.HasPrefix(b, []byte("PK\x03\x04")),
		bytes.HasPrefix(b, []byte{0xfd, '7', 'z', 'X', 'Z', 0}), bytes.HasPrefix(b, []byte("BZh")),
		bytes.HasPrefix(b, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return true
	case len(b) >= 262 && string(b[257:262]) == "ustar":
		return true
	}
	return false
}

// rewriteMetadata points links at the proxy's public URL at the sandbox, and
// filters an npm packument of a package being updated.
func (ss *sandboxSession) rewriteMetadata(p string, data []byte) []byte {
	if ss.publicPrefix != "" {
		data = bytes.ReplaceAll(data, []byte(ss.publicPrefix), []byte(sandbox.BaseURL+"/v1/"))
	}
	if ss.ecosys == "npm" {
		name := strings.TrimPrefix(p, "/")
		if to, ok := ss.targets[name]; ok {
			if out, err := filterPackument(data, ss.scheme, to, ss.rejected[name]); err == nil {
				return out
			}
		}
	}
	return data
}

// filterPackument keeps the versions of a packument up to the vetted one and
// none the updater skipped, and points "latest" at the vetted one.
func filterPackument(data []byte, scheme versions.Scheme, to string, rejected map[string]bool) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, err
	}
	var vs map[string]json.RawMessage
	if err := json.Unmarshal(top["versions"], &vs); err != nil {
		return nil, err
	}
	max, err := scheme.Parse(to)
	if err != nil {
		return nil, err
	}
	for v := range vs {
		pv, err := scheme.Parse(v)
		if err != nil || scheme.Compare(pv, max) > 0 || rejected[v] {
			delete(vs, v)
		}
	}
	raw, err := json.Marshal(vs)
	if err != nil {
		return nil, err
	}
	top["versions"] = raw
	tags, _ := json.Marshal(map[string]string{"latest": to})
	top["dist-tags"] = tags
	delete(top, "time")
	return json.Marshal(top)
}

type limitWriter struct {
	w   io.Writer
	max int64
	n   int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n+int64(len(p)) > l.max {
		return 0, fmt.Errorf("the response is larger than %d bytes", l.max)
	}
	l.n += int64(len(p))
	return l.w.Write(p)
}

// --- the job ------------------------------------------------------------------

// maxSandboxFiles and maxSandboxBytes bound the project files a sandboxed run
// is given.
const (
	maxSandboxFiles = 20000
	maxSandboxBytes = 256 << 20
)

// sandboxFileRole says what the sandboxed tool is given of a project file: its
// content (the manifests and lock files resolution reads), an empty
// placeholder (a file whose existence it checks: Cargo's targets), or nothing.
// A repository's own registry configuration (.npmrc, .cargo/config.toml) and
// toolchain pins (rust-toolchain, go.work's toolchain lines aside) are never
// given: they would point the tool elsewhere, carry credentials, or make it
// fetch a toolchain.
func sandboxFileRole(tool, p string) (content, placeholder bool) {
	base := path.Base(p)
	switch tool {
	case "npm":
		return base == "package.json" || base == "package-lock.json" || base == "npm-shrinkwrap.json", false
	case "cargo":
		switch {
		case base == "Cargo.toml" || base == "Cargo.lock":
			return true, false
		case strings.HasSuffix(base, ".rs"):
			return false, true
		}
	case "go":
		return base == "go.mod" || base == "go.sum" || base == "go.work" || base == "go.work.sum", false
	}
	return false, false
}

// sandboxConfigDir holds the files the job adds to the project (the tool's
// registry configuration). It is never collected back.
const sandboxConfigDir = ".pullthrough-sandbox"

// resolveInSandbox re-resolves a lock file for the updates with the real
// package manager and vets what the resolution changed. It returns the files
// after, or a skip code and the reason.
func (s *Service) resolveInSandbox(ctx context.Context, repo Repo, run *UpdateRun, m *Manifest, lf LockFile,
	support update.FormatSupport, current map[string][]byte, plans []*plannedUpdate) (map[string][]byte, string, string) {
	dir := path.Dir(lf.Path)
	if dir == "." {
		dir = ""
	}
	rel := func(p string) string {
		if dir == "" {
			return p
		}
		return strings.TrimPrefix(p, dir+"/")
	}
	// The project below the lock file's directory as the tool needs it: the
	// manifests and lock files it resolves from (with the rewrites so far), an
	// empty placeholder where it only checks that a file exists, and nothing
	// else — no source, no registry configuration of the repository's own.
	tool := support.Tool
	paths, err := s.opts.Branches.ListFiles(ctx, repo, run.Base, dir, func(p string) bool {
		content, placeholder := sandboxFileRole(tool, p)
		return content || placeholder
	}, maxSandboxFiles+1)
	if err != nil {
		return nil, SkipNotWritable, "listing the project's files: " + err.Error()
	}
	if len(paths) > maxSandboxFiles {
		return nil, SkipNotWritable, fmt.Sprintf("the project below %s has more than %d files the sandboxed %s reads", firstNonEmpty(dir, "the root"), maxSandboxFiles, tool)
	}
	var read []string
	files := map[string][]byte{}
	for _, p := range paths {
		if content, _ := sandboxFileRole(tool, p); content {
			read = append(read, p)
		} else {
			files[rel(p)] = []byte{}
		}
	}
	contents, err := s.opts.Branches.ReadFiles(ctx, repo, run.Base, read, maxSandboxBytes)
	if err != nil {
		return nil, SkipNotWritable, "reading the project's manifests: " + err.Error()
	}
	for p, data := range contents {
		files[rel(p)] = data
	}
	for p, data := range current {
		files[rel(p)] = data
	}

	env := s.updateLocateEnv(repo)
	scheme, _ := versions.For(plans[0].dep.Type)
	sess := &sandboxSession{s: s, repo: repo, upstreams: map[string]bool{}, targets: map[string]string{},
		rejected: map[string]map[string]bool{}, scheme: scheme, ecosys: plans[0].dep.Type, publicPrefix: s.cfg.Update.PublicURLPrefix,
		spoolDir: s.cfg.SpoolDir, sem: make(chan struct{}, maxSessionRequests)}
	for _, p := range plans {
		sess.upstreams[p.upstream] = true
		sess.targets[p.dep.Name] = p.to
	}
	for _, sk := range run.Skipped {
		if sk.To != "" && sk.Code != SkipIncompatible {
			if sess.rejected[sk.Name] == nil {
				sess.rejected[sk.Name] = map[string]bool{}
			}
			sess.rejected[sk.Name][sk.To] = true
		}
	}
	upstream := plans[0].upstream
	job, err := sandboxJob(support.Tool, upstream, lf, rel(lf.Path), plans, files)
	if err != nil {
		return nil, SkipNotWritable, err.Error()
	}
	job.Handler = sess
	res, err := s.opts.Sandbox.Run(ctx, job)
	if err != nil {
		why := err.Error()
		if res != nil && res.Output != "" {
			why += ": " + lastLines(res.Output, 6)
		}
		if refused := sess.refusals(); len(refused) > 0 {
			why += "; the session refused: " + strings.Join(firstN(refused, 3), "; ")
		}
		return nil, SkipResolution, "the sandboxed " + support.Tool + " failed: " + why
	}
	after := map[string][]byte{}
	for k, v := range current {
		after[k] = v
	}
	for p, data := range res.Files {
		full := p
		if dir != "" {
			full = dir + "/" + p
		}
		if support.Tool == "npm" {
			data = restoreNPMResolved(data, upstream, current[lf.Path])
		}
		after[full] = data
	}
	if code, why := s.vetResolution(ctx, repo, env, lf, current, after, plans); code != "" {
		return nil, code, why
	}
	return after, "", ""
}

// sandboxJob builds the tool's job: its registry configuration pointing at the
// session, and the commands that update the lock file.
func sandboxJob(tool, upstream string, lf LockFile, lockRel string, plans []*plannedUpdate, files map[string][]byte) (sandbox.Job, error) {
	reg := sandbox.BaseURL + "/v1/" + upstream + "/"
	job := sandbox.Job{Tool: tool, Files: files, Dir: path.Dir(lockRel), Collect: []string{lockRel}}
	if job.Dir == "." {
		job.Dir = ""
	}
	switch tool {
	case "npm":
		// "--" ends the options: no name is ever read as one.
		args := []string{"npm", "update", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--save=false", "--"}
		for _, p := range plans {
			args = append(args, p.dep.Name)
		}
		job.Commands = [][]string{args}
		job.Env = []string{"npm_config_registry=" + reg, "npm_config_cache=/tmp/npm-cache", "npm_config_update_notifier=false",
			"npm_config_userconfig=/tmp/npmrc", "npm_config_globalconfig=/tmp/npmrc-global", "npm_config_replace_registry_host=never"}
	case "cargo":
		for _, p := range plans {
			if !isCratesIO(p.dep.Registry) {
				return job, fmt.Errorf("the sandboxed cargo updates crates.io dependencies only; %s comes from %s", p.dep.Name, firstNonEmpty(p.dep.Registry, "another registry"))
			}
		}
		cfg := "[source.crates-io]\nreplace-with = \"pullthrough\"\n\n[source.pullthrough]\nregistry = \"sparse+" + reg + "\"\n"
		job.Files[sandboxConfigDir+"/cargo.toml"] = []byte(cfg)
		cfgPath := "/work/" + sandboxConfigDir + "/cargo.toml"
		for _, p := range plans {
			job.Commands = append(job.Commands, []string{"cargo", "--config", cfgPath, "update", "--package", p.dep.Name + "@" + p.dep.Version, "--precise", p.to})
		}
		job.Env = []string{"CARGO_HOME=/tmp/cargo", "CARGO_NET_OFFLINE=false", "CARGO_TERM_COLOR=never"}
	case "go":
		args := []string{"go", "get", "--"}
		for _, p := range plans {
			args = append(args, p.dep.Name+"@"+p.to)
		}
		job.Commands = [][]string{args}
		job.Env = []string{"GOPROXY=" + strings.TrimSuffix(reg, "/"), "GOSUMDB=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local",
			"GOPATH=/tmp/go", "GOCACHE=/tmp/go-cache", "GOTELEMETRY=off", "GOPRIVATE=", "GONOPROXY=", "GONOSUMDB="}
		dir := path.Dir(lockRel)
		gosum := "go.sum"
		if dir != "." {
			gosum = dir + "/go.sum"
		}
		job.Collect = []string{lockRel, gosum}
	default:
		return job, fmt.Errorf("the sandbox has no recipe for %s", tool)
	}
	return job, nil
}

func isCratesIO(registry string) bool {
	r := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(registry, "registry+"), "sparse+"), "/")
	return r == "" || r == "https://github.com/rust-lang/crates.io-index" || r == "https://index.crates.io"
}

// restoreNPMResolved points the "resolved" URLs npm wrote at the sandbox's
// address back at the registry base the lock file used before.
func restoreNPMResolved(data []byte, upstream string, before []byte) []byte {
	sandboxBase := sandbox.BaseURL + "/v1/" + upstream + "/"
	base := npmRegistryBase(before)
	if base == "" {
		base = "https://registry.npmjs.org/"
	}
	return bytes.ReplaceAll(data, []byte(sandboxBase), []byte(base))
}

// npmRegistryBase is the most common registry base of a package-lock.json's
// "resolved" URLs: the part before "<name>/-/".
func npmRegistryBase(lock []byte) string {
	var top struct {
		Packages map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"packages"`
	}
	if json.Unmarshal(lock, &top) != nil {
		return ""
	}
	count := map[string]int{}
	for p, e := range top.Packages {
		at := strings.LastIndex(p, "node_modules/")
		if at < 0 {
			continue // the project, or a workspace folder
		}
		name := p[at+len("node_modules/"):]
		if i := strings.Index(e.Resolved, "/"+name+"/-/"); i > 0 {
			count[e.Resolved[:i+1]]++
		}
	}
	best, n := "", 0
	for b, c := range count {
		if c > n || (c == n && b < best) {
			best, n = b, c
		}
	}
	return best
}

// vetResolution holds a sandboxed resolution to the updater's bar: each update
// landed at its vetted version with the digests of the bytes vetted, and every
// other entry the resolution added or changed passes vetting itself — every
// gate, a benign verdict for its exact bytes, and the digests the lock file now
// records matching those bytes.
func (s *Service) vetResolution(ctx context.Context, repo Repo, env locate.Env, lf LockFile, before, after map[string][]byte, plans []*plannedUpdate) (string, string) {
	old, err := lockDependencies(before, lf.Path, s.cfg.Lockfiles.Proxy)
	if err != nil {
		return SkipVerify, "the lock file before the resolution could not be read: " + err.Error()
	}
	now, err := lockDependencies(after, lf.Path, s.cfg.Lockfiles.Proxy)
	if err != nil {
		return SkipVerify, "the resolved lock file could not be read: " + err.Error()
	}
	target := map[string]*plannedUpdate{}
	for _, p := range plans {
		target[p.dep.Name+"@"+p.to] = p
		landed, stale := false, false
		for _, d := range now {
			if d.Name != p.dep.Name {
				continue
			}
			switch d.Version {
			case p.to:
				landed = true
			case p.dep.Version:
				stale = true
			}
		}
		if !landed {
			return SkipResolution, fmt.Sprintf("the resolution did not move %s to %s", p.dep.Name, p.to)
		}
		if stale && lf.Type != "go" {
			return SkipResolution, fmt.Sprintf("the resolution kept %s %s next to %s", p.dep.Name, p.dep.Version, p.to)
		}
	}
	keys := make([]string, 0, len(now))
	for k := range now {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		d := now[k]
		if o, ok := old[k]; ok && sameDigests(o.Digests, d.Digests) && o.URL == d.URL {
			continue // unchanged
		}
		if d.Source != lockfiles.SourceRegistry {
			return SkipResolution, fmt.Sprintf("the resolution brought in %s from %s, which the updater cannot vet", d.Name, firstNonEmpty(d.Source, "elsewhere"))
		}
		// Whatever the tool wrote must be held to bytes the proxy serves:
		// an entry that records no digest, or a download URL the upstream
		// does not serve, would have the client fetch bytes nobody vetted.
		if d.Unverified && !metadataOnly(d) {
			return SkipResolution, fmt.Sprintf("the resolution recorded %s %s without a digest of its content", d.Name, d.Version)
		}
		if why := s.servedThroughPlan(env, d, plans); why != "" {
			return SkipResolution, why
		}
		if p, ok := target[d.Name+"@"+d.Version]; ok {
			if why := digestsMatch(d, p.change); why != "" {
				return SkipResolution, why
			}
			continue
		}
		if why := s.vetEntry(ctx, repo, env, d); why != "" {
			return SkipResolution, fmt.Sprintf("the resolution brought in %s %s, which is not vetted: %s", d.Name, d.Version, why)
		}
	}
	return "", ""
}

// servedThroughPlan checks that an entry of a re-resolved lock file is served
// by the upstream the updates were vetted through: it is located through that
// upstream, and a download URL it records is one that upstream serves.
func (s *Service) servedThroughPlan(env locate.Env, d lockfiles.Dependency, plans []*plannedUpdate) string {
	up, _, err := locate.SelectUpstream(env, d)
	if err != nil {
		return fmt.Sprintf("the resolution brought in %s %s from a registry the updater cannot vet it through: %v", d.Name, d.Version, err)
	}
	ok := false
	for _, p := range plans {
		if p.upstream == up.Name {
			ok = true
		}
	}
	if !ok {
		return fmt.Sprintf("the resolution brought in %s %s through upstream %s, not the one the updates were vetted through", d.Name, d.Version, up.Name)
	}
	if d.URL != "" && !locate.ServedBy(up, d.URL) {
		return fmt.Sprintf("the resolution recorded a download URL for %s %s that upstream %s does not serve", d.Name, d.Version, up.Name)
	}
	return ""
}

// sameDigests compares two digest lists as sets.
func sameDigests(a, b []lockfiles.Digest) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, d := range a {
		set[strings.ToLower(d.String())] = true
	}
	for _, d := range b {
		if !set[strings.ToLower(d.String())] {
			return false
		}
	}
	return true
}

// digestsMatch holds the digests a lock entry records for a vetted version to
// the digests of the bytes vetted: it must record one, and every one it
// records must be of those bytes.
func digestsMatch(d lockfiles.Dependency, ch update.Change) string {
	if len(d.Digests) == 0 {
		return fmt.Sprintf("the resolution recorded %s %s without a digest", d.Name, d.Version)
	}
	have := map[string]bool{}
	for _, a := range ch.Artifacts {
		for _, v := range []string{a.SHA256, a.SHA512, a.SHA1, a.H1} {
			if v != "" {
				have[strings.ToLower(v)] = true
			}
		}
	}
	for _, dg := range d.Digests {
		if !have[strings.ToLower(dg.Value)] {
			return fmt.Sprintf("the resolution recorded a %s digest for %s %s that is not the digest of the bytes vetted", dg.Algorithm, d.Name, d.Version)
		}
	}
	return ""
}

// vetEntry vets a lock entry the resolution added: located and fetched through
// the gates with the lock file's digests as the expectation, every object the
// LLM package scan examines judged benign. It returns why not, or "".
func (s *Service) vetEntry(ctx context.Context, repo Repo, env locate.Env, d lockfiles.Dependency) string {
	if s.opts.Policy != nil {
		if ok, _, reason := s.opts.Policy.CheckCandidate(repo.Tenant, d.Type, d.Name, d.Version); !ok {
			return reason
		}
	}
	plan, err := locate.Locate(ctx, env, d)
	if err != nil {
		return "it could not be located: " + err.Error()
	}
	benign := 0
	for _, art := range plan.Artifacts {
		obj, llm := s.fetchArtifact(ctx, repo, art, fetchOptions{subject: s.cfg.Update.Subject, deferLLM: true})
		if obj.HTTPStatus == http.StatusNotFound && art.Fallback != "" {
			art.Path = art.Fallback
			obj, llm = s.fetchArtifact(ctx, repo, art, fetchOptions{subject: s.cfg.Update.Subject, deferLLM: true})
		}
		if art.Optional && obj.Status != StatusPinned {
			continue
		}
		if obj.Status != StatusPinned {
			return firstNonEmpty(art.File, art.Role) + ": " + firstNonEmpty(obj.Reason, obj.Status)
		}
		var reading ObjectScan
		switch {
		case llm != nil:
			reading = *llm
		case s.opts.Scans == nil:
			return "the LLM package-content scan gate is off"
		default:
			reading = s.scanCachedObject(ctx, repo, d.Type, obj).ObjectScan
		}
		if !reading.Applicable {
			if reading.NotApplicable == UnscannedOutOfScope {
				return "the LLM package scan does not cover it"
			}
			continue
		}
		if reading.Verdict != VerdictBenign {
			return "the LLM package scan's reading of it is " + firstNonEmpty(reading.Verdict, VerdictUnscanned)
		}
		benign++
	}
	if benign == 0 && !metadataOnly(d) {
		return "none of its objects is package content the LLM package scan judged benign"
	}
	return ""
}

// metadataOnly reports a lock entry that pins only a document next to the
// package — a Go module of the graph whose go.mod alone go.sum hashes: the
// build reads its requirements and never its code, so there is no package
// content to judge (its go.mod is still fetched through the gates and held to
// the recorded hash).
func metadataOnly(d lockfiles.Dependency) bool {
	if len(d.Digests) == 0 {
		return false
	}
	for _, dg := range d.Digests {
		if dg.Of != "go.mod" {
			return false
		}
	}
	return true
}

// lastLines returns the last n lines of a tool's output.
func lastLines(out string, n int) string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return oneLine(strings.Join(lines, " | "))
}
