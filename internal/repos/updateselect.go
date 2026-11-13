package repos

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
	"github.com/blechschmidt/pullthrough-security/internal/repos/update"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// plannedUpdate is a dependency with the newer version chosen for it: vetted,
// fetched, its digests computed over the cached bytes.
type plannedUpdate struct {
	dep        Dependency
	to         string
	bump       versions.Level
	constraint string
	upstream   string
	change     update.Change
	scanIDs    []string
	digest     string
	model      string
	// sameDeps reports that the new version declares the same dependencies
	// as the old one: its lock entry can be rewritten in place. sameDepsWhy
	// says why not, otherwise.
	sameDeps    bool
	sameDepsWhy string
}

// maxManifestBytes bounds the bytes of the manifests and lock files one read
// of the updater takes from a commit (a lock file and its siblings, a
// workspace's Cargo.toml files).
const maxManifestBytes = 64 << 20

// declared holds what the project declares about its dependencies' versions,
// read once per run from the lock files and their manifests.
type declared struct {
	// ranges are the constraints declared on a dependency at a version
	// ("type/name@version" → the expressions), from the manifests and from
	// the other packages that depend on it.
	ranges map[string][]string
	// unknown names dependencies some dependent's requirement on which could
	// not be read ("type/name@version" → why): the candidate cannot be shown to
	// satisfy it.
	unknown map[string]string
	// excluded are go.mod exclude directives ("module@version").
	excluded map[string]bool
}

func declKey(t, name, version string) string { return t + "/" + name + "@" + version }

// updateLocateEnv is the locating environment of the updater: documents are
// read as the updater, and the LLM gate's refusals of what it fetches are its
// own to act on (a candidate it refuses is skipped, not an error).
func (s *Service) updateLocateEnv(repo Repo) locate.Env {
	env := s.locateEnv(repo)
	env.Fetch = documentFetcher{s: s, tenant: repo.Tenant, roles: s.rolesFor(repo), deferLLM: true, subject: s.cfg.Update.Subject}
	return env
}

// selectUpdates chooses, for every dependency of the head's lock files, the
// newest version that is compatible and vetted. It fills run.Skipped and
// returns the plan.
func (s *Service) selectUpdates(ctx context.Context, repo Repo, run *UpdateRun, m *Manifest) ([]*plannedUpdate, error) {
	env := s.updateLocateEnv(repo)
	maxBump := s.cfg.Update.MaxBump
	if repo.Update != nil {
		switch strings.TrimSpace(repo.Update.MaxBump) {
		case "patch":
			maxBump = versions.LevelPatch
		case "minor":
			maxBump = versions.LevelMinor
		}
	}
	ignore, err := parseIgnores(repo)
	if err != nil {
		return nil, err
	}

	// The dependencies whose versions are listed: registry dependencies of a
	// type whose versions can be listed, of a lock-file format the updater can
	// write. Those it then examines leave out the ignored ones and, unless
	// configured, development dependencies — but their listings count: a Cargo
	// crate's dependents state their requirements on it in their own.
	var listed, deps []Dependency
	examine := map[int]bool{}
	for _, d := range m.Dependencies {
		if d.Source != lockfiles.SourceRegistry || !locate.Listable(d.Type) || !s.writable(m, d) {
			continue
		}
		if !plainName(d.Name) || !plainName(d.Version) {
			// No ecosystem names a package or a version like this; a lock
			// file that does would have it read as an option by a sandboxed
			// tool's command line.
			continue
		}
		if d.Type == "go" && !inGoMod(d) {
			// Listed in go.sum only: a module of the graph the build does not
			// compile, whose go.mod hash is all go.sum keeps.
			continue
		}
		listed = append(listed, d)
		if d.Dev && !*s.cfg.Update.IncludeDev {
			continue
		}
		if ig, why := ignore.dependency(d.Type, d.Name); ig {
			run.Skipped = append(run.Skipped, SkippedCandidate{Type: d.Type, Name: d.Name, From: d.Version, Code: SkipIgnored, Reason: why})
			continue
		}
		examine[len(listed)-1] = true
	}

	listings := make([]*locate.Listing, len(listed))
	listErrs := make([]error, len(listed))
	s.parallel(ctx, len(listed), func(i int) {
		listings[i], listErrs[i] = locate.ListVersions(ctx, env, listed[i].lock)
	})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	byName := map[string]*locate.Listing{}
	var depListings []*locate.Listing
	var depErrs []error
	for i, d := range listed {
		if listings[i] != nil {
			byName[d.Type+"/"+d.Name] = listings[i]
		}
		if examine[i] {
			deps = append(deps, d)
			depListings = append(depListings, listings[i])
			depErrs = append(depErrs, listErrs[i])
		}
	}
	listings, listErrs = depListings, depErrs
	run.Dependencies = len(deps)
	decl := s.readDeclared(ctx, repo, run.Base, m, byName)

	plans := make([]*plannedUpdate, len(deps))
	skips := make([][]SkippedCandidate, len(deps))
	s.parallel(ctx, len(deps), func(i int) {
		d := deps[i]
		if err := listErrs[i]; err != nil {
			code := SkipListingFailed
			var refused *locate.RefusedError
			switch {
			case locate.IsUnsupported(err):
				code = SkipUnsupported
			case errors.As(err, &refused):
				code = SkipRefused
			}
			skips[i] = []SkippedCandidate{{Type: d.Type, Name: d.Name, From: d.Version, Code: code, Reason: "its versions could not be listed: " + err.Error()}}
			return
		}
		plans[i], skips[i] = s.planDependency(ctx, repo, env, d, listings[i], decl, ignore, maxBump)
	})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var out []*plannedUpdate
	for i := range deps {
		run.Skipped = append(run.Skipped, skips[i]...)
		if plans[i] != nil {
			out = append(out, plans[i])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dep.Coordinate() < out[j].dep.Coordinate() })
	if len(out) > s.cfg.Update.MaxUpdates {
		for _, p := range out[s.cfg.Update.MaxUpdates:] {
			run.Skipped = append(run.Skipped, SkippedCandidate{Type: p.dep.Type, Name: p.dep.Name, From: p.dep.Version, To: p.to,
				Code: SkipLimit, Reason: fmt.Sprintf("a run proposes at most %d updates (repositories.updates.maxUpdates)", s.cfg.Update.MaxUpdates)})
		}
		out = out[:s.cfg.Update.MaxUpdates]
	}
	return out, nil
}

// plainName reports whether a package name or version is plain text: not
// empty, not starting with "-", without whitespace or control characters.
func plainName(s string) bool {
	if s == "" || s[0] == '-' || len(s) > 512 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// parallel runs fn for 0..n-1 with the updater's concurrency.
func (s *Service) parallel(ctx context.Context, n int, fn func(i int)) {
	sem := make(chan struct{}, s.cfg.Update.Concurrency)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

// writable reports whether some lock file pinning d is of a format the
// updater writes (natively or through the sandbox).
func (s *Service) writable(m *Manifest, d Dependency) bool {
	for _, f := range d.Files {
		lf, ok := lockFileOf(m, f)
		if !ok {
			continue
		}
		if fs, ok := update.Format(lockfileKey(lf)); ok && fs.Method != update.Unsupported {
			return true
		}
	}
	return false
}

// lockFileOf returns the lock file of a "path:line" location.
func lockFileOf(m *Manifest, loc string) (LockFile, bool) {
	p := loc
	if i := strings.LastIndexByte(loc, ':'); i > 0 {
		p = loc[:i]
	}
	for _, lf := range m.LockFiles {
		if lf.Path == p {
			return lf, true
		}
	}
	return LockFile{}, false
}

// inGoMod reports whether a Go dependency is required by a go.mod.
func inGoMod(d Dependency) bool {
	for _, f := range d.Files {
		p := f
		if i := strings.LastIndexByte(f, ':'); i > 0 {
			p = f[:i]
		}
		if path.Base(p) == "go.mod" {
			return true
		}
	}
	return false
}

// planDependency chooses the newest compatible newer version of d that passes
// vetting. It returns nil and the candidates skipped when there is none.
func (s *Service) planDependency(ctx context.Context, repo Repo, env locate.Env, d Dependency, l *locate.Listing,
	decl *declared, ignore ignoreList, maxBump versions.Level) (*plannedUpdate, []SkippedCandidate) {
	var skipped []SkippedCandidate
	skip := func(to, code, reason string) {
		skipped = append(skipped, SkippedCandidate{Type: d.Type, Name: d.Name, From: d.Version, To: to, Code: code, Reason: reason})
	}
	scheme, ok := versions.For(d.Type)
	if !ok {
		skip("", SkipUnsupported, "the updater does not order "+d.Type+" versions")
		return nil, skipped
	}
	from, err := scheme.Parse(d.Version)
	if err != nil {
		skip("", SkipUnsupported, fmt.Sprintf("the pinned version %q is not a %s version: %v", d.Version, d.Type, err))
		return nil, skipped
	}
	key := declKey(d.Type, d.Name, d.Version)
	if why, unknown := decl.unknown[key]; unknown {
		skip("", SkipUnknownConstr, "the requirements on it cannot all be read, so no newer version can be shown to satisfy them: "+why)
		return nil, skipped
	}

	// The constraint: what the project and every dependent declare, or for
	// a Go module its major version; without one, the default policy.
	var cons []versions.Constraint
	var consText []string
	for _, expr := range decl.ranges[key] {
		c, err := scheme.ParseConstraint(expr)
		if err != nil {
			if errors.Is(err, versions.ErrNoConstraint) {
				continue
			}
			skip("", SkipUnknownConstr, fmt.Sprintf("the requirement %q on it cannot be evaluated: %v", expr, err))
			return nil, skipped
		}
		cons = append(cons, c)
		consText = appendUniqueString(consText, expr)
	}
	if d.Type == "go" {
		cons = append(cons, versions.SameMajor(scheme, from))
		consText = append(consText, "same major version (minimal version selection)")
	}

	type cand struct {
		v   versions.Version
		rel locate.Release
	}
	var cands []cand
	for _, rel := range l.Releases {
		v, err := scheme.Parse(rel.Version)
		if err != nil || scheme.Compare(v, from) <= 0 {
			continue
		}
		cands = append(cands, cand{v, rel})
	}
	sort.Slice(cands, func(i, j int) bool { return scheme.Compare(cands[i].v, cands[j].v) > 0 })

	oldRel, _ := l.Release(d.Version)
	vetted := 0
	notedIncompatible := false
	for _, c := range cands {
		to := c.rel.Version
		if c.v.Prerelease() && !from.Prerelease() {
			continue
		}
		if c.rel.Yanked {
			continue
		}
		allowed := true
		if len(cons) > 0 {
			for _, con := range cons {
				if !con.Allows(c.v) {
					allowed = false
					break
				}
			}
		} else {
			allowed = versions.Within(scheme, from, c.v, maxBump)
		}
		if !allowed {
			if !notedIncompatible {
				notedIncompatible = true
				why := "outside the declared constraint " + strings.Join(consText, " and ")
				if len(cons) == 0 {
					why = fmt.Sprintf("a %s update, and no constraint is declared: updates stay within %s", versions.Bump(scheme, from, c.v), policyText(maxBump))
				}
				skip(to, SkipIncompatible, why)
			}
			continue
		}
		if d.Type == "go" && decl.excluded[d.Name+"@"+to] {
			skip(to, SkipIncompatible, "go.mod excludes it")
			continue
		}
		if ig, why := ignore.version(scheme, d.Type, d.Name, c.v); ig {
			skip(to, SkipIgnored, why)
			continue
		}
		if s.opts.Policy != nil {
			if ok, code, reason := s.opts.Policy.CheckCandidate(repo.Tenant, d.Type, d.Name, to); !ok {
				skip(to, code, reason)
				continue
			}
		}
		if vetted >= s.cfg.Update.MaxCandidates {
			skip(to, SkipLimit, fmt.Sprintf("%d newer compatible versions were vetted without success; older ones are not examined (repositories.updates.maxCandidates)", vetted))
			break
		}
		vetted++
		p, sk := s.vetCandidate(ctx, repo, env, d, to, oldRel, c.rel)
		if sk != nil {
			skipped = append(skipped, *sk)
			continue
		}
		p.bump = versions.Bump(scheme, from, c.v)
		p.constraint = strings.Join(consText, " and ")
		return p, skipped
	}
	return nil, skipped
}

func policyText(l versions.Level) string {
	if l == versions.LevelPatch {
		return "patch updates (repositories.updates.maxBump: patch)"
	}
	return "the same major version"
}

// computeFor lists the digests a lock file of the type records besides the
// SHA-256 every check computes.
func computeFor(t string, a locate.Artifact) []string {
	switch {
	case t == "npm" && a.Role == "package":
		return []string{"sha512", "sha1"}
	case t == "go" && (a.Role == "package" || a.Role == "go.mod"):
		return []string{"h1"}
	}
	return nil
}

// vetCandidate fetches a candidate version through the gated pipeline and
// holds it to the updater's bar: every object admitted and cached, every
// object the LLM package-content scan examines judged benign — the stored
// verdict for those bytes, or a scan made now — and the bytes those the
// registry metadata states. It returns the plan, or why the candidate is
// skipped.
func (s *Service) vetCandidate(ctx context.Context, repo Repo, env locate.Env, d Dependency, to string, oldRel, rel locate.Release) (*plannedUpdate, *SkippedCandidate) {
	sk := func(code, reason string) *SkippedCandidate {
		return &SkippedCandidate{Type: d.Type, Name: d.Name, From: d.Version, To: to, Code: code, Reason: reason}
	}
	cand := d.lock
	cand.Version, cand.Digests, cand.URL, cand.Unverified, cand.UnverifiedReason = to, nil, "", false, ""
	plan, err := locate.Locate(ctx, env, cand)
	if err != nil {
		var refused *locate.RefusedError
		switch {
		case errors.As(err, &refused):
			return nil, sk(SkipRefused, "an admission gate refused it: "+err.Error())
		case locate.IsUnsupported(err):
			return nil, sk(SkipUnsupported, err.Error())
		}
		return nil, sk(SkipFetchFailed, "it could not be located: "+err.Error())
	}
	p := &plannedUpdate{dep: d, to: to, upstream: plan.Upstream,
		change: update.Change{Type: d.Type, Name: d.Name, From: d.Version, To: to}}
	benign := 0
	for _, art := range plan.Artifacts {
		if ctx.Err() != nil {
			return nil, sk(SkipFetchFailed, ctx.Err().Error())
		}
		art.Compute = computeFor(d.Type, art)
		fo := fetchOptions{subject: s.cfg.Update.Subject, deferLLM: true}
		obj, llm := s.fetchArtifact(ctx, repo, art, fo)
		if obj.HTTPStatus == 404 && art.Fallback != "" {
			art.Path = art.Fallback
			obj, llm = s.fetchArtifact(ctx, repo, art, fo)
		}
		if art.Optional && obj.Status != StatusPinned {
			continue
		}
		label := firstNonEmpty(art.File, art.Role)
		switch obj.Status {
		case StatusPinned:
		case StatusRefused:
			out := sk(SkipRefused, label+": "+obj.Reason)
			if r := readingOf(llm); r != nil {
				out.Verdict, out.Digest = r.Verdict, r.Digest
			}
			return nil, out
		case StatusMismatch:
			return nil, sk(SkipDigest, label+": "+obj.Reason)
		case StatusUncached:
			return nil, sk(SkipUnscanned, label+": the proxy serves it without caching it, so no verdict can be bound to its bytes")
		default:
			return nil, sk(SkipFetchFailed, label+": "+firstNonEmpty(obj.Reason, obj.Status))
		}
		if obj.Check == nil || obj.Check.ComputeError != "" {
			why := "its digests could not be computed"
			if obj.Check != nil {
				why = obj.Check.ComputeError
			}
			return nil, sk(SkipDigest, label+": "+why)
		}
		// The gate's reading of the bytes: what it said on the way, or a
		// reading asked for now (the stored verdict, or a scan).
		var reading ObjectScan
		switch {
		case llm != nil:
			reading = *llm
		case s.opts.Scans == nil || !s.opts.Scans.Status().Enabled:
			return nil, sk(SkipUnscanned, "the LLM package-content scan gate is off: no candidate can be judged benign")
		default:
			reading = s.scanCachedObject(ctx, repo, d.Type, obj).ObjectScan
		}
		if reading.NotApplicable == UnscannedOutOfScope {
			// The gate does not cover it: no benign verdict can be had.
			return nil, sk(SkipUnscanned, label+": "+firstNonEmpty(reading.NotApplicableReason, "the LLM package scan does not cover it"))
		}
		if reading.Applicable {
			scanID, model := "", ""
			if reading.Detail != nil {
				scanID, model = reading.Detail.ScanID, reading.Detail.Model
			}
			switch reading.Verdict {
			case VerdictBenign:
				benign++
				p.scanIDs = append(p.scanIDs, scanID)
				if p.model == "" {
					p.model = model
				}
			case VerdictMalicious, VerdictSuspicious:
				code := SkipMalicious
				if reading.Verdict == VerdictSuspicious {
					code = SkipSuspicious
				}
				out := sk(code, label+": the LLM package-content scan judges it "+reading.Verdict)
				out.Verdict, out.ScanID, out.Digest = reading.Verdict, scanID, obj.Digest
				return nil, out
			default:
				why := "no verdict"
				if reading.Unscanned != nil {
					why = reading.Unscanned.Code + ": " + reading.Unscanned.Reason
				}
				out := sk(SkipUnscanned, label+": "+why)
				out.Verdict, out.Digest = VerdictUnscanned, obj.Digest
				return nil, out
			}
		}
		a := update.Artifact{Role: art.Role, File: art.File, Size: obj.Size, SHA256: strings.TrimPrefix(obj.Digest, "sha256:")}
		if c := obj.Check.Computed; c != nil {
			a.SHA512, a.SHA1, a.H1 = c["sha512"], c["sha1"], c["h1"]
		}
		if art.Role == "package" || art.Role == "file" {
			if p.digest == "" {
				p.digest = obj.Digest
			}
		}
		p.change.Artifacts = append(p.change.Artifacts, a)
	}
	if benign == 0 {
		return nil, sk(SkipUnscanned, "none of its objects is package content the LLM package scan judged benign")
	}
	if why := registryMismatch(d.Type, rel, p.change); why != "" {
		return nil, sk(SkipDigest, why)
	}
	p.sameDeps, p.sameDepsWhy = s.sameDependencies(ctx, env, d, oldRel, rel)
	return p, nil
}

// registryMismatch compares the digests the registry metadata states for a
// version with those of the bytes the proxy served. They must agree: the lock
// file's other consumers (npm's integrity check against the packument, cargo's
// against the index) read the metadata.
func registryMismatch(t string, rel locate.Release, ch update.Change) string {
	// Python: each distribution file against the hash the index lists for it.
	for _, f := range ch.ArtifactsOf("file") {
		for _, want := range rel.Integrity {
			if want.Of == f.File && want.Algorithm == "sha256" && !strings.EqualFold(want.Value, f.SHA256) {
				return fmt.Sprintf("the bytes served for %s are not those the index lists for it", f.File)
			}
		}
	}
	pkg := ch.ArtifactsOf("package")
	if len(pkg) == 0 {
		return ""
	}
	for _, want := range rel.Integrity {
		got := ""
		switch want.Algorithm {
		case "sha512":
			got = pkg[0].SHA512
		case "sha1":
			got = pkg[0].SHA1
		case "sha256":
			got = pkg[0].SHA256
		default:
			continue
		}
		if got != "" && !strings.EqualFold(got, want.Value) {
			return fmt.Sprintf("the bytes served have another %s digest than the %s registry's metadata states for %s", want.Algorithm, t, ch.To)
		}
	}
	return ""
}

// sameDependencies reports whether the candidate declares the same
// dependencies as the pinned version — what a native rewrite of its lock entry
// needs — and why not.
func (s *Service) sameDependencies(ctx context.Context, env locate.Env, d Dependency, oldRel, newRel locate.Release) (bool, string) {
	switch d.Type {
	case "npm", "cargo":
		if oldRel.Fingerprint == "" || newRel.Fingerprint == "" {
			return false, "the registry's metadata does not state both versions' dependencies"
		}
		if oldRel.Fingerprint != newRel.Fingerprint {
			return false, "the new version declares other dependencies (or other installation metadata) than " + d.Version
		}
		return true, ""
	case "go":
		oldMod, err := locate.ModFile(ctx, env, d.lock, d.Version)
		if err != nil {
			return false, "the go.mod of " + d.Version + " could not be read: " + err.Error()
		}
		newMod, err := locate.ModFile(ctx, env, d.lock, newRel.Version)
		if err != nil {
			return false, "the go.mod of " + newRel.Version + " could not be read: " + err.Error()
		}
		_, a, errA := locate.GoModRequires(oldMod)
		_, b, errB := locate.GoModRequires(newMod)
		if errA != nil || errB != nil {
			return false, "a go.mod could not be read"
		}
		if a != b {
			return false, "the new version's go.mod requires other modules or versions"
		}
		return true, ""
	case "pip":
		_, a, knownA, errA := locate.PythonRequirements(ctx, env, d.lock, d.Version)
		_, b, knownB, errB := locate.PythonRequirements(ctx, env, d.lock, newRel.Version)
		if errA != nil || errB != nil || !knownA || !knownB {
			return false, "the registry does not state both versions' requirements (Requires-Dist)"
		}
		if a != b {
			return false, "the new version declares other requirements (Requires-Dist) than " + d.Version
		}
		return true, ""
	}
	return false, "the updater cannot compare " + d.Type + " versions' dependencies"
}

// --- declared constraints --------------------------------------------------------

// readDeclared reads the constraints the project and its dependents declare,
// for every lock file of the plan.
func (s *Service) readDeclared(ctx context.Context, repo Repo, commit string, m *Manifest, listings map[string]*locate.Listing) *declared {
	decl := &declared{ranges: map[string][]string{}, unknown: map[string]string{}, excluded: map[string]bool{}}
	add := func(t, name, version, expr string) {
		k := declKey(t, name, version)
		decl.ranges[k] = appendUniqueString(decl.ranges[k], strings.TrimSpace(expr))
	}
	for _, lf := range m.LockFiles {
		if lf.Error != "" {
			continue
		}
		dir := path.Dir(lf.Path)
		if dir == "." {
			dir = ""
		}
		join := func(name string) string {
			if dir == "" {
				return name
			}
			return dir + "/" + name
		}
		switch lockfileKey(lf) {
		case "npm/package-lock.json", "npm/npm-shrinkwrap.json":
			files, err := s.opts.Branches.ReadFiles(ctx, repo, commit, []string{lf.Path, join("package.json")}, maxManifestBytes)
			if err != nil || files[lf.Path] == nil {
				s.markUnknown(decl, m, lf.Path, "the lock file could not be read again")
				continue
			}
			reqs, err := lockfiles.NPMRequirements(files[lf.Path], files[join("package.json")])
			if err != nil {
				s.markUnknown(decl, m, lf.Path, err.Error())
				continue
			}
			for _, r := range reqs {
				if r.Position == "" || r.Version == "" {
					continue
				}
				add("npm", r.Package, r.Version, r.Range)
			}
		case "cargo/Cargo.lock":
			s.readCargoDeclared(ctx, repo, commit, lf, dir, decl, listings, add, m)
		case "pip/requirements.txt":
			s.readPipDeclared(ctx, repo, commit, lf, dir, decl, m, add)
		case "go/go.mod":
			files, err := s.opts.Branches.ReadFiles(ctx, repo, commit, []string{lf.Path}, maxManifestBytes)
			if err == nil {
				for _, ex := range goModExcludes(files[lf.Path]) {
					decl.excluded[ex] = true
				}
			}
		}
	}
	return decl
}

// markUnknown marks every dependency of a lock file as one whose requirements
// cannot be read.
func (s *Service) markUnknown(decl *declared, m *Manifest, lockPath, why string) {
	for _, d := range m.Dependencies {
		for _, f := range d.Files {
			if strings.HasPrefix(f, lockPath+":") {
				decl.unknown[declKey(d.Type, d.Name, d.Version)] = lockPath + ": " + why
			}
		}
	}
}

// readCargoDeclared reads the requirements on each crate of a Cargo.lock: those
// of the workspace's Cargo.toml files, and those of every crate that depends on
// it (from the dependents' index entries). Whatever cannot be read leaves the
// requirements on the crates it concerns unknown: a newer version could break a
// requirement nobody saw.
func (s *Service) readCargoDeclared(ctx context.Context, repo Repo, commit string, lf LockFile, dir string,
	decl *declared, listings map[string]*locate.Listing, add func(t, name, version, expr string), m *Manifest) {
	files, err := s.opts.Branches.ReadFiles(ctx, repo, commit, []string{lf.Path}, maxManifestBytes)
	if err != nil || files[lf.Path] == nil {
		s.markUnknown(decl, m, lf.Path, "the lock file could not be read again")
		return
	}
	pkgs, err := lockfiles.CargoLockPackages(files[lf.Path])
	if err != nil {
		s.markUnknown(decl, m, lf.Path, "the lock file could not be parsed: "+err.Error())
		return
	}
	// Where each reference resolves: "name" alone names the only version of
	// the crate in the lock file.
	versionsOf := map[string][]cargoRef{}
	for _, p := range pkgs {
		versionsOf[p.Name] = append(versionsOf[p.Name], cargoRef{version: p.Version, source: p.Source})
	}
	resolve := func(ref string) (string, string, bool) {
		name, version := lockfiles.CargoDependencyRef(ref)
		if version != "" {
			return name, version, true
		}
		if vs := versionsOf[name]; len(vs) == 1 {
			return name, vs[0].version, true
		}
		return name, "", false
	}
	// The workspace's own manifests: every Cargo.toml below the lock file,
	// by the package each declares.
	const maxManifests = 500
	manifests, err := s.opts.Branches.ListFiles(ctx, repo, commit, dir, func(p string) bool { return path.Base(p) == "Cargo.toml" }, maxManifests)
	if err != nil || len(manifests) > maxManifests {
		s.markUnknown(decl, m, lf.Path, "the workspace's Cargo.toml files could not be listed")
		return
	}
	contents, err := s.opts.Branches.ReadFiles(ctx, repo, commit, manifests, maxManifestBytes)
	if err != nil {
		s.markUnknown(decl, m, lf.Path, "the workspace's Cargo.toml files could not be read: "+err.Error())
		return
	}
	memberReqs := map[string][]lockfiles.CargoRequirement{} // package name → its requirements
	var wsReqs []lockfiles.CargoRequirement                 // [workspace.dependencies] and virtual manifests
	for _, mf := range manifests {
		data := contents[mf]
		reqs, err := lockfiles.CargoManifestRequirements(data)
		if err != nil {
			s.markUnknown(decl, m, lf.Path, mf+" could not be parsed: "+err.Error())
			return
		}
		name, _ := lockfiles.CargoManifestName(data)
		var own []lockfiles.CargoRequirement
		for _, r := range reqs {
			if r.Table == "workspace.dependencies" || name == "" {
				wsReqs = append(wsReqs, r)
			} else {
				own = append(own, r)
			}
		}
		if name != "" {
			memberReqs[name] = append(memberReqs[name], own...)
		}
	}
	unknown := func(name, version, why string) {
		k := declKey("cargo", name, version)
		if _, already := decl.unknown[k]; !already {
			decl.unknown[k] = why
		}
	}
	for _, p := range pkgs {
		for _, ref := range p.Dependencies {
			name, version, ok := resolve(ref)
			if !ok {
				continue
			}
			if p.Source == "" {
				// A member of the workspace (or a path package): its
				// requirements are in its Cargo.toml — which must have been
				// read, or they are unknown.
				reqs, found := memberReqs[p.Name]
				if !found {
					unknown(name, version, "the manifest of "+p.Name+", which depends on it, is not below "+firstNonEmpty(dir, "the repository's root")+" or could not be read")
					continue
				}
				for _, r := range append(reqs, wsReqs...) {
					if r.Name == name {
						add("cargo", name, version, r.Requirement)
					}
				}
				continue
			}
			l := listings["cargo/"+p.Name]
			if l == nil {
				unknown(name, version, "the index entry of "+p.Name+" "+p.Version+", which depends on it, could not be read")
				continue
			}
			rel, found := l.Release(p.Version)
			if !found {
				unknown(name, version, "the index does not list "+p.Name+" "+p.Version+", which depends on it")
				continue
			}
			for _, r := range rel.Requires {
				if r.Name == name && r.Kind != "dev" {
					add("cargo", name, version, r.Constraint)
				}
			}
		}
	}
}

// cargoRef is a crate version and its source in a Cargo.lock.
type cargoRef struct{ version, source string }

// readPipDeclared reads the specifiers on each requirement of a requirements
// file: those of its pip-tools input file (and the files it includes), of a
// pyproject.toml next to it, and those every other pinned project of the file
// declares on it. Whatever cannot be read leaves the requirements unknown.
func (s *Service) readPipDeclared(ctx context.Context, repo Repo, commit string, lf LockFile, dir string,
	decl *declared, m *Manifest, add func(t, name, version, expr string)) {
	join := func(base, name string) string {
		if base == "" {
			return name
		}
		return base + "/" + name
	}
	pinned := map[string]string{} // name → version pinned by this file
	var inThisFile []Dependency
	for _, d := range m.Dependencies {
		if d.Type != "pip" {
			continue
		}
		for _, f := range d.Files {
			if strings.HasPrefix(f, lf.Path+":") {
				pinned[d.Name] = d.Version
				inThisFile = append(inThisFile, d)
			}
		}
	}
	base := path.Base(lf.Path)
	inFile := join(dir, strings.TrimSuffix(base, path.Ext(base))+".in")
	var top []lockfiles.PythonRequirement
	// The pip-tools input and what it includes, a bounded number of files.
	queue, seen := []string{inFile}, map[string]bool{}
	for len(queue) > 0 && len(seen) < 32 {
		f := queue[0]
		queue = queue[1:]
		if seen[f] {
			continue
		}
		seen[f] = true
		files, err := s.opts.Branches.ReadFiles(ctx, repo, commit, []string{f}, maxManifestBytes)
		if err != nil {
			s.markUnknown(decl, m, lf.Path, f+" could not be read: "+err.Error())
			return
		}
		data, ok := files[f]
		if !ok {
			if f != inFile {
				s.markUnknown(decl, m, lf.Path, "the requirements file "+f+" it includes is not in the repository")
				return
			}
			continue // no pip-tools input: the requirements file stands alone
		}
		top = append(top, lockfiles.PythonRequirementsIn(data)...)
		for _, inc := range lockfiles.PythonIncludes(data) {
			target := path.Clean(join(path.Dir(f), inc))
			if strings.HasPrefix(inc, "/") || strings.Contains(inc, "://") || target == ".." || strings.HasPrefix(target, "../") {
				s.markUnknown(decl, m, lf.Path, f+" includes "+inc+", which is outside the repository")
				return
			}
			queue = append(queue, target)
		}
	}
	if len(queue) > 0 {
		s.markUnknown(decl, m, lf.Path, "the requirements files include more files than are read")
		return
	}
	pyproject := join(dir, "pyproject.toml")
	if files, err := s.opts.Branches.ReadFiles(ctx, repo, commit, []string{pyproject}, maxManifestBytes); err != nil {
		s.markUnknown(decl, m, lf.Path, "pyproject.toml could not be read: "+err.Error())
		return
	} else if data, ok := files[pyproject]; ok {
		reqs, err := lockfiles.PyProjectRequirements(data)
		if err != nil {
			s.markUnknown(decl, m, lf.Path, "pyproject.toml could not be parsed: "+err.Error())
			return
		}
		top = append(top, reqs...)
	}
	for _, r := range top {
		if v, ok := pinned[r.Name]; ok && r.Specifier != "" {
			add("pip", r.Name, v, r.Specifier)
		}
	}
	// What the other pinned projects require of each: read from their
	// metadata. Without it a newer version could break a dependent's bound.
	// A requirement behind an extra or a marker counts too: whether the
	// extra is asked for, or the marker holds, is not decided here.
	env := s.updateLocateEnv(repo)
	for _, dependent := range inThisFile {
		reqs, _, known, err := locate.PythonRequirements(ctx, env, dependent.lock, dependent.Version)
		if err != nil || !known {
			why := "the requirements of " + dependent.Name + " " + dependent.Version + " are not stated by the registry"
			if err != nil {
				why = "the requirements of " + dependent.Name + " " + dependent.Version + " could not be read: " + err.Error()
			}
			for name, v := range pinned {
				if name != dependent.Name {
					k := declKey("pip", name, v)
					if _, already := decl.unknown[k]; !already {
						decl.unknown[k] = why
					}
				}
			}
			continue
		}
		for _, line := range reqs {
			r, ok := lockfiles.PythonRequirementLine(line)
			if !ok || r.Specifier == "" {
				continue
			}
			if v, ok := pinned[r.Name]; ok {
				add("pip", r.Name, v, r.Specifier)
			}
		}
	}
}

// goModExcludes reads the exclude directives of a go.mod ("module@version").
func goModExcludes(mod []byte) []string {
	var out []string
	block := false
	for _, raw := range strings.Split(string(mod), "\n") {
		line := raw
		if c := strings.Index(line, "//"); c >= 0 {
			line = line[:c]
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case block && f[0] == ")":
			block = false
		case block && len(f) == 2:
			out = append(out, f[0]+"@"+f[1])
		case f[0] == "exclude" && len(f) == 2 && f[1] == "(":
			block = true
		case f[0] == "exclude" && len(f) == 3:
			out = append(out, f[1]+"@"+f[2])
		}
	}
	return out
}

// --- ignore lists -----------------------------------------------------------------

// ignoreRule is one entry of a repository's ignore list.
type ignoreRule struct {
	raw        string
	typ, name  string // "*" type matches every type; name may end in "*"
	constraint string // "" every version
}

type ignoreList []ignoreRule

// parseIgnores reads a repository's ignore list.
func parseIgnores(r Repo) (ignoreList, error) {
	if r.Update == nil {
		return nil, nil
	}
	var out ignoreList
	for _, raw := range r.Update.Ignore {
		rule, err := parseIgnore(raw)
		if err != nil {
			return nil, &ValidationError{Err: fmt.Errorf("repository %q: updates.ignore: %w", r.Name, err)}
		}
		out = append(out, rule)
	}
	return out, nil
}

func parseIgnore(raw string) (ignoreRule, error) {
	s := strings.TrimSpace(raw)
	typ, rest, ok := strings.Cut(s, "/")
	if !ok || typ == "" || rest == "" {
		return ignoreRule{}, fmt.Errorf("%q is not type/name[@version-or-constraint]", raw)
	}
	name, constraint := rest, ""
	// The version part follows the last "@" that is not the first character
	// (npm scopes start with "@").
	if i := strings.LastIndex(rest, "@"); i > 0 {
		name, constraint = rest[:i], strings.TrimSpace(rest[i+1:])
	}
	if typ != "*" {
		typ = lockfiles.CanonicalType(typ)
	}
	if constraint != "" && typ != "*" {
		if sch, ok := versions.For(typ); ok {
			if _, err := sch.Parse(constraint); err != nil {
				if _, err := sch.ParseConstraint(constraint); err != nil {
					return ignoreRule{}, fmt.Errorf("%q: %q is neither a version nor a constraint: %v", raw, constraint, err)
				}
			}
		}
	}
	return ignoreRule{raw: s, typ: typ, name: name, constraint: constraint}, nil
}

func (r ignoreRule) matchesName(t, name string) bool {
	if r.typ != "*" && r.typ != t {
		return false
	}
	if strings.HasSuffix(r.name, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(r.name, "*"))
	}
	if t == "pip" {
		return pipName(r.name) == pipName(name)
	}
	return r.name == name
}

func pipName(n string) string {
	n = strings.ToLower(n)
	return strings.NewReplacer("_", "-", ".", "-").Replace(n)
}

// dependency reports whether every version of a dependency is ignored.
func (l ignoreList) dependency(t, name string) (bool, string) {
	for _, r := range l {
		if r.constraint == "" && r.matchesName(t, name) {
			return true, "the repository's ignore list names it (" + r.raw + ")"
		}
	}
	return false, ""
}

// version reports whether a version of a dependency is ignored.
func (l ignoreList) version(scheme versions.Scheme, t, name string, v versions.Version) (bool, string) {
	for _, r := range l {
		if r.constraint == "" || !r.matchesName(t, name) {
			continue
		}
		if exact, err := scheme.Parse(r.constraint); err == nil {
			if scheme.Compare(exact, v) == 0 {
				return true, "the repository's ignore list names it (" + r.raw + ")"
			}
			continue
		}
		if c, err := scheme.ParseConstraint(r.constraint); err == nil && c.Allows(v) {
			return true, "the repository's ignore list names it (" + r.raw + ")"
		}
	}
	return false, ""
}
