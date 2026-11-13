package repos

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// What in a repository redirects a dependency its lock file pins (Task 182).
//
// The updater moves a dependency to a version whose exact bytes the proxy
// vetted. Files besides the lock file may have a client build something else
// for that version: a replace directive of go.mod or of a workspace (go.work),
// a Cargo [patch] or [replace], a Cargo source replacement or path override,
// an npm override, a package source a requirements file names for a pin that
// carries no hash. Such a redirection may name the new version only, and lie
// dormant — doing nothing at the version the lock file pins — until the
// update lands: the update's pull request shows a version bump, and the build
// takes the redirection's code, which nobody vetted. The updater does not
// update what such a file redirects, natively or in the sandbox (which is not
// given these files either, so its resolution would not even see them).

// Bounds of what the check reads.
const (
	// maxRedirectFiles is how many go.work or .cargo/config files are read.
	maxRedirectFiles = 64
	// maxRedirectFileBytes bounds each.
	maxRedirectFileBytes = 1 << 20
)

// redirected is the outcome of the check for one lock file: code and all
// refuse every update of the lock file (a vendored tree, a source
// replacement); byName refuses the updates of the dependencies it names.
type redirected struct {
	code, all string
	byName    map[string]string
}

func (r *redirected) name(name, why string) {
	if r.byName == nil {
		r.byName = map[string]string{}
	}
	if _, ok := r.byName[name]; !ok {
		r.byName[name] = why
	}
}

// redirects checks a lock file's updates against what the repository says
// besides the lock file. files holds the lock file (and its siblings) as read
// for the rewrite.
func (s *Service) redirects(ctx context.Context, repo Repo, commit, key string, lf LockFile, files map[string][]byte, plans []*plannedUpdate) redirected {
	changed := map[string]bool{}
	for _, p := range plans {
		changed[p.dep.Name] = true
	}
	dir := path.Dir(lf.Path)
	var r redirected
	switch key {
	case "go/go.mod", "go/go.sum":
		s.goRedirects(ctx, repo, commit, dir, changed, &r)
	case "cargo/Cargo.lock":
		s.cargoRedirects(ctx, repo, commit, dir, files[lf.Path], changed, &r)
	case "npm/package-lock.json", "npm/npm-shrinkwrap.json":
		s.npmRedirects(ctx, repo, commit, dir, changed, &r)
	case "pip/requirements.txt":
		s.pipRedirects(ctx, repo, commit, lf.Path, plans, &r)
	}
	return r
}

// readOne reads one file of the commit; ok is false when it is not there.
func (s *Service) readOne(ctx context.Context, repo Repo, commit, p string) ([]byte, bool, error) {
	got, err := s.opts.Branches.ReadFiles(ctx, repo, commit, []string{p}, maxRedirectFileBytes)
	if err != nil {
		return nil, false, err
	}
	data, ok := got[p]
	return data, ok, nil
}

// listRedirectFiles lists the files of the commit match accepts, bounded.
func (s *Service) listRedirectFiles(ctx context.Context, repo Repo, commit string, match func(string) bool) ([]string, error) {
	list, err := s.opts.Branches.ListFiles(ctx, repo, commit, "", match, maxRedirectFiles)
	if err != nil {
		return nil, err
	}
	if len(list) > maxRedirectFiles {
		return nil, fmt.Errorf("more than %d of them", maxRedirectFiles)
	}
	sort.Strings(list)
	return list, nil
}

func joinDir(dir, name string) string {
	if dir == "." || dir == "" {
		return name
	}
	return dir + "/" + name
}

// --- Go ------------------------------------------------------------------------

// goRedirects: a vendored module (the build reads vendor/, which only go mod
// vendor updates); a replace directive of the module's go.mod; and a workspace
// (go.work, wherever in the repository: the go command uses the one in the
// directory it runs in or above) that uses the module and replaces a changed
// module, or uses another module that is one, or whose go.mod replaces one.
func (s *Service) goRedirects(ctx context.Context, repo Repo, commit, dir string, changed map[string]bool, r *redirected) {
	if _, ok, err := s.readOne(ctx, repo, commit, joinDir(dir, "vendor/modules.txt")); err != nil {
		r.code, r.all = SkipNotWritable, "whether the module vendors its dependencies could not be read: "+err.Error()
		return
	} else if ok {
		r.code, r.all = SkipNotWritable, "the module vendors its dependencies (vendor/modules.txt): the update needs go mod vendor, which the updater does not run"
		return
	}
	r.code = SkipRedirected
	gomod := joinDir(dir, "go.mod")
	if data, ok, err := s.readOne(ctx, repo, commit, gomod); err != nil || !ok {
		r.all = gomod + " could not be read"
		return
	} else if _, replaced, err := lockfiles.GoModReplaced(data); err != nil {
		r.all = gomod + " could not be read: " + err.Error()
		return
	} else {
		for _, m := range replaced {
			if changed[m] {
				r.name(m, gomod+" replaces it (a replace directive)")
			}
		}
	}
	works, err := s.listRedirectFiles(ctx, repo, commit, func(p string) bool { return path.Base(p) == "go.work" })
	if err != nil {
		r.all = "the repository's go.work files could not be listed: " + err.Error()
		return
	}
	for _, w := range works {
		data, ok, err := s.readOne(ctx, repo, commit, w)
		if err != nil || !ok {
			r.all = w + " could not be read"
			return
		}
		uses, replaced, err := lockfiles.GoWork(data)
		if err != nil {
			r.all = w + " could not be read: " + err.Error()
			return
		}
		wdir := path.Dir(w)
		var used []string
		inWorkspace := false
		for _, u := range uses {
			if strings.HasPrefix(u, "/") {
				continue // outside the repository
			}
			p := path.Clean(path.Join(wdir, u))
			if p == ".." || strings.HasPrefix(p, "../") {
				continue
			}
			if p == path.Clean(dir) {
				inWorkspace = true
			} else {
				used = append(used, p)
			}
		}
		if !inWorkspace {
			continue // the go command refuses to build the module in that workspace
		}
		for _, m := range replaced {
			if changed[m] {
				r.name(m, w+" replaces it (a workspace replace directive)")
			}
		}
		if len(used) > maxRedirectFiles {
			r.all = w + " uses more than " + fmt.Sprint(maxRedirectFiles) + " modules"
			return
		}
		for _, u := range used {
			mod := joinDir(u, "go.mod")
			data, ok, err := s.readOne(ctx, repo, commit, mod)
			if err != nil {
				r.all = mod + " could not be read: " + err.Error()
				return
			}
			if !ok {
				continue // the go command fails on a workspace module without one
			}
			module, replaced, err := lockfiles.GoModReplaced(data)
			if err != nil {
				r.all = mod + " could not be read: " + err.Error()
				return
			}
			if changed[module] {
				r.name(module, w+" builds it from "+u+" (a workspace module)")
			}
			for _, m := range replaced {
				if changed[m] {
					r.name(m, mod+", a module of the workspace "+w+", replaces it")
				}
			}
		}
	}
}

// --- Cargo ---------------------------------------------------------------------

// cargoRedirects: a [patch] or [replace] of the workspace's root manifest
// (next to Cargo.lock), a patch Cargo.lock records as not used yet, and the
// configuration files Cargo reads when run in the workspace or below it
// (.cargo/config.toml or .cargo/config in that directory or any above it): a
// source replacement (vendored sources, a local registry, a mirror), path
// overrides or another crates.io index redirect every crate; a [patch] the
// crates it names.
func (s *Service) cargoRedirects(ctx context.Context, repo Repo, commit, dir string, lock []byte, changed map[string]bool, r *redirected) {
	r.code = SkipRedirected
	if unused, err := lockfiles.CargoPatchUnused(lock); err != nil {
		r.all = "Cargo.lock could not be read: " + err.Error()
		return
	} else {
		for _, n := range unused {
			if changed[n] {
				r.name(n, "the workspace patches it ([[patch.unused]] in Cargo.lock): at the version the patch provides, Cargo builds the patch")
			}
		}
	}
	manifest := joinDir(dir, "Cargo.toml")
	if data, ok, err := s.readOne(ctx, repo, commit, manifest); err != nil {
		r.all = manifest + " could not be read: " + err.Error()
		return
	} else if ok {
		patched, err := lockfiles.CargoPatched(data)
		if err != nil {
			r.all = manifest + " could not be read: " + err.Error()
			return
		}
		for _, n := range patched {
			if changed[n] {
				r.name(n, manifest+" patches or replaces it ([patch] or [replace])")
			}
		}
	}
	root := path.Clean(dir)
	configs, err := s.listRedirectFiles(ctx, repo, commit, func(p string) bool {
		base := path.Base(p)
		if (base != "config.toml" && base != "config") || path.Base(path.Dir(p)) != ".cargo" {
			return false
		}
		at := path.Dir(path.Dir(p)) // the directory the configuration applies in
		return at == "." || root == "." || at == root || strings.HasPrefix(root, at+"/") || strings.HasPrefix(at, root+"/")
	})
	if err != nil {
		r.all = "the repository's Cargo configuration files could not be listed: " + err.Error()
		return
	}
	for _, c := range configs {
		data, ok, err := s.readOne(ctx, repo, commit, c)
		if err != nil || !ok {
			r.all = c + " could not be read"
			return
		}
		redirect, patched, err := lockfiles.CargoConfigRedirects(data)
		if err != nil {
			r.all = c + " could not be read: " + err.Error()
			return
		}
		if redirect != "" {
			r.all = c + " redirects every crate (" + redirect + "): the build would not read the crates the proxy vetted"
			return
		}
		for _, n := range patched {
			if changed[n] {
				r.name(n, c+" patches it ([patch])")
			}
		}
	}
}

// --- npm -----------------------------------------------------------------------

// npmRedirects: an override of the project's package.json naming the package
// (npm replaces whatever resolves for it).
func (s *Service) npmRedirects(ctx context.Context, repo Repo, commit, dir string, changed map[string]bool, r *redirected) {
	r.code = SkipRedirected
	manifest := joinDir(dir, "package.json")
	data, ok, err := s.readOne(ctx, repo, commit, manifest)
	if err != nil {
		r.all = manifest + " could not be read: " + err.Error()
		return
	}
	if !ok {
		return
	}
	names, err := lockfiles.NPMOverrides(data)
	if err != nil {
		r.all = manifest + " could not be read: " + err.Error()
		return
	}
	for _, n := range names {
		if changed[n] {
			r.name(n, manifest+" overrides it (overrides)")
		}
	}
}

// --- pip -----------------------------------------------------------------------

// maxRequirementFiles bounds the -r / -c includes followed.
const maxRequirementFiles = 32

// pipRedirects: a pin without a hash takes whatever its sources serve for the
// version, so a package source the requirements file (or one it includes)
// names other than the proxy and the registry the proxy fetched from — an
// index, a page or directory of files — may serve the new version with other
// bytes. Pins with hashes are checked by pip against the vetted bytes.
func (s *Service) pipRedirects(ctx context.Context, repo Repo, commit, lockPath string, plans []*plannedUpdate, r *redirected) {
	r.code = SkipRedirected
	var unhashed []*plannedUpdate
	for _, p := range plans {
		if len(p.dep.LockDigests) == 0 || p.dep.Unverified {
			unhashed = append(unhashed, p)
		}
	}
	if len(unhashed) == 0 {
		return
	}
	queue, seen := []string{lockPath}, map[string]bool{lockPath: true}
	other := ""
	for len(queue) > 0 && other == "" {
		f := queue[0]
		queue = queue[1:]
		data, ok, err := s.readOne(ctx, repo, commit, f)
		if err != nil || !ok {
			other = f + " could not be read"
			break
		}
		for _, src := range lockfiles.PythonSources(data) {
			if !s.vettedSource(src.Value) {
				other = f + " names another package source (" + src.Option + " " + src.Value + ")"
				break
			}
		}
		for _, inc := range lockfiles.PythonIncludes(data) {
			if strings.Contains(inc, "://") || strings.HasPrefix(inc, "/") {
				other = f + " includes " + inc + ", which the updater does not read"
				break
			}
			p := path.Clean(path.Join(path.Dir(f), inc))
			if p == ".." || strings.HasPrefix(p, "../") {
				other = f + " includes " + inc + ", outside the repository"
				break
			}
			if !seen[p] {
				if len(seen) >= maxRequirementFiles {
					other = f + " includes more than " + fmt.Sprint(maxRequirementFiles) + " files"
					break
				}
				seen[p] = true
				queue = append(queue, p)
			}
		}
	}
	if other == "" {
		return
	}
	for _, p := range unhashed {
		r.name(p.dep.Name, "it is pinned without a hash, and "+other+": pip would take what that source serves for the new version")
	}
}

// vettedSource reports whether a package source a requirements file names is
// this proxy, or a registry the proxy fetches from (its bytes are those the
// proxy vets).
func (s *Service) vettedSource(raw string) bool {
	if s.cfg.Lockfiles.Proxy.Serves(raw) {
		return true
	}
	u := strings.TrimRight(strings.ToLower(strings.TrimSpace(raw)), "/")
	if u == "" {
		return false
	}
	for _, up := range s.opts.Upstreams {
		for _, base := range up.URLs {
			b := strings.TrimRight(strings.ToLower(base), "/")
			if b != "" && (u == b || strings.HasPrefix(u, b+"/")) {
				return true
			}
		}
	}
	return false
}
