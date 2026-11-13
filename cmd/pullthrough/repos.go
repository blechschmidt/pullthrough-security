package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/cachegc"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/dossier"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/git"
	"github.com/blechschmidt/pullthrough-security/internal/gitsign"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/maturity"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/repos"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
	"github.com/blechschmidt/pullthrough-security/internal/repos/sandbox"
	"github.com/blechschmidt/pullthrough-security/internal/scan/watch"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// buildRepos opens the repository registry (Task 180) from its state
// directory: registrations, tag histories, release manifests — and with them
// the pin set. It is built before the cache so that the very first eviction
// decision honours the pins; its fetcher, Git mirror and observers are attached
// once the gateway exists (wireRepos). It returns nil when the registry is off.
func buildRepos(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*repos.Service, error) {
	rc := cfg.Repositories
	if !rc.Enabled {
		return nil, nil
	}
	store, err := repos.NewDirStore(cfg.RepositoriesStateDir())
	if err != nil {
		return nil, err
	}
	rcfg, err := reposConfig(cfg)
	if err != nil {
		return nil, err
	}
	svc, err := repos.New(ctx, rcfg, repos.Options{Store: store, Logger: logger.With("component", "repos")})
	if err != nil {
		return nil, err
	}
	st := svc.Stats()
	logger.Info("repository registry enabled", "stateDir", cfg.RepositoriesStateDir(),
		"repos", st.Repositories, "pinnedObjects", st.PinnedObjects, "pinnedBytes", st.PinnedBytes)
	return svc, nil
}

// openReposOffline opens the registry's state for an offline command (export,
// import, prewarm): the pins, so that those commands' own cache writes never
// evict a pinned object. It starts nothing and fetches nothing.
func openReposOffline(cfg *config.Config, logger *slog.Logger) (*repos.Service, error) {
	if !cfg.Repositories.Enabled || cfg.RepositoriesStateDir() == "" {
		return nil, nil
	}
	if _, err := os.Stat(cfg.RepositoriesStateDir()); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return buildRepos(context.Background(), cfg, logger)
}

// reposConfig translates the configuration into the service's.
func reposConfig(cfg *config.Config) (repos.Config, error) {
	rc := cfg.Repositories
	pc := rc.Pinning
	out := repos.Config{
		PollInterval:              cfg.RepositoriesPollInterval(),
		WebhookSecret:             rc.WebhookSecret,
		AllowedSchemes:            rc.AllowedSchemes,
		Workers:                   pc.Workers,
		Concurrency:               pc.Concurrency,
		MaxDependencies:           pc.MaxDependencies,
		MaxArtifactsPerDependency: pc.MaxObjectsPerDependency,
		IncludeDev:                pc.IncludeDev,
		RetryInterval:             pc.RetryInterval,
		MaxAttempts:               pc.MaxAttempts,
		SpoolDir:                  pc.SpoolDir,
		Lockfiles:                 lockfiles.Options{Proxy: lockfileProxy(cfg)},
		Roles:                     rc.Roles,
		Replicated:                cfg.Coordination.Enabled,
		Scan: repos.ScanConfig{
			// The scans run through the LLM package-content scan gate; without
			// it there is nothing to scan with.
			Enabled:       rc.Scan.ScanEnabledOrDefault() && cfg.LLMPackageScan.Enabled,
			Releases:      rc.Scan.Releases,
			DefaultBranch: rc.Scan.DefaultBranch,
			Interval:      rc.Scan.Interval,
			Workers:       rc.Scan.Workers,
			Concurrency:   rc.Scan.Concurrency,
			RetryInterval: rc.Scan.RetryInterval,
			MaxAttempts:   rc.Scan.MaxAttempts,
		},
	}
	upd, err := updateConfig(cfg)
	if err != nil {
		return out, err
	}
	out.Update = upd
	if cfg.Auth.Enabled {
		defined := map[string]bool{}
		for _, r := range cfg.Auth.Roles {
			defined[strings.TrimSpace(r.Name)] = true
		}
		out.KnownRole = func(name string) bool { return defined[name] }
	}
	out.BackfillTags = rc.BackfillTags
	for _, p := range pc.Platforms {
		pl, err := locate.ParsePlatform(p)
		if err != nil {
			return out, err
		}
		out.Platforms = append(out.Platforms, pl)
	}
	for _, r := range rc.Repos {
		repo := repos.Repo{
			Name: r.Name, URL: r.URL, Username: r.Username, CredentialsRef: r.CredentialsRef,
			Tenant: r.Tenant, Lockfiles: r.Lockfiles, Tags: r.Tags, Upstreams: r.Upstreams,
			FullName: r.FullName, BackfillTags: r.BackfillTags, Roles: r.Roles, Branch: r.Branch, Source: repos.SourceConfig,
		}
		if u := r.Updates; u != nil {
			repo.Update = &repos.RepoUpdate{Disabled: u.Disabled, Branch: u.Branch, MaxBump: u.MaxBump, Ignore: u.Ignore,
				Forge: u.Forge, ForgeAPI: u.ForgeAPI, ForgeRepo: u.ForgeRepo, ForgeTokenRef: u.ForgeTokenRef}
		}
		out.Repos = append(out.Repos, repo)
	}
	return out, nil
}

// updateConfig translates the maintenance updater's configuration (Task 182).
func updateConfig(cfg *config.Config) (repos.UpdateConfig, error) {
	u := cfg.Repositories.Updates
	out := repos.UpdateConfig{
		Enabled: u.Enabled, Interval: u.Interval, Branch: u.Branch, IncludeDev: u.IncludeDev,
		MaxCandidates: u.MaxCandidates, MaxUpdates: u.MaxUpdates, Concurrency: u.Concurrency,
		AuthorName: u.AuthorName, AuthorEmail: u.AuthorEmail, RunTimeout: u.RunTimeout,
		PullRequests: repos.PullRequestConfig{Enabled: u.PullRequests.Enabled, Labels: u.PullRequests.Labels, Draft: u.PullRequests.Draft},
	}
	if strings.TrimSpace(u.MaxBump) == "patch" {
		out.MaxBump = versions.LevelPatch
	}
	if pub := strings.TrimRight(strings.TrimSpace(cfg.Server.PublicURL), "/"); pub != "" {
		out.PublicURLPrefix = pub + "/v1/"
	}
	if key := strings.TrimSpace(u.SigningKey); key != "" {
		var pass []byte
		if u.SigningKeyPassphrase != "" {
			pass = []byte(u.SigningKeyPassphrase)
		}
		signer, err := gitsign.NewSSHSigner([]byte(key), pass)
		if err != nil {
			return out, fmt.Errorf("repositories.updates.signingKey: %w", err)
		}
		out.Signer = signer
	}
	return out, nil
}

// lockfileProxy is what a lock-file scan needs to map URLs that point at this
// proxy back to its upstreams.
func lockfileProxy(cfg *config.Config) *lockfiles.Proxy {
	p := &lockfiles.Proxy{
		LinkPrefix:      cfg.UserLinks.PathPrefix,
		RegistryDefault: cfg.Server.Registry.DefaultUpstream,
		Upstreams:       map[string]lockfiles.ProxyUpstream{},
	}
	if u := strings.TrimSpace(cfg.Server.PublicURL); u != "" {
		p.PublicURLs = append(p.PublicURLs, u)
	}
	for name, up := range cfg.Upstreams {
		if up.Enabled != nil && !*up.Enabled {
			continue
		}
		p.Upstreams[name] = lockfiles.ProxyUpstream{Type: up.Type, URL: up.URL}
	}
	return p
}

// locateUpstreams lists the configured upstreams for locating dependencies.
func locateUpstreams(cfg *config.Config) []locate.Upstream {
	names := make([]string, 0, len(cfg.Upstreams))
	for n := range cfg.Upstreams {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []locate.Upstream
	for _, n := range names {
		up := cfg.Upstreams[n]
		if up.Enabled != nil && !*up.Enabled {
			continue
		}
		u := locate.Upstream{Name: n, Type: up.Type, URLs: []string{up.URL}, Settings: up.Settings}
		for _, m := range up.Mirrors {
			if m.URL != "" {
				u.URLs = append(u.URLs, m.URL)
			}
		}
		out = append(out, u)
	}
	return out
}

// wireRepos attaches the registry's collaborators once the gateway exists and
// starts it.
func wireRepos(ctx context.Context, svc *repos.Service, cfg *config.Config, gw *proxy.Gateway, deps reposDeps) error {
	if svc == nil {
		return nil
	}
	gs, err := watch.NewGitSource(watch.GitSourceOptions{
		Root: cfg.RepositoriesMirrorDir(),
		// A bare repository fetching branches and tags, not a "clone --mirror":
		// the refs that keep released commits reachable survive refreshes.
		Refspecs:         []string{"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"},
		AllowedProtocols: allowedGitProtocols(cfg.Repositories.AllowedSchemes),
		Logger:           deps.logger,
	})
	if err != nil {
		return fmt.Errorf("repositories: %w", err)
	}
	var m *repos.Metrics
	if deps.collector != nil {
		m = repos.NewMetrics(deps.collector.Registry())
	}
	svc.Attach(repos.Options{
		Refs:      mirrorRefs{gs: gs},
		Scanner:   mirrorScanner{gs: gs},
		Fetcher:   gatewayReleaseFetcher{gw: gw},
		Upstreams: locateUpstreams(cfg),
		Secrets:   deps.secrets,
		Audit:     deps.audit,
		Notify:    deps.notify,
		Cache:     cacheProbe{c: deps.cache},
		Metrics:   m,
		Observer:  releaseGraph(deps.graph),
		// The dependency scans (Task 181): the LLM gate through the gateway,
		// and the findings layer their reports feed.
		Scans:    newObjectScanner(gw, deps.llmScan, ecosystemMap(cfg)),
		Findings: newScanFindingsSink(deps.findings, deps.findingsMetrics, deps.suppressions, deps.siem),
		// The maintenance updater (Task 182): the branch it builds in the
		// mirror, the coordinate policies, the sandbox.
		Branches: mirrorBranches{gs: gs},
		Policy:   candidatePolicy{firewall: deps.firewall, maturity: deps.maturity},
	})
	if sc := cfg.Repositories.Updates.Sandbox; cfg.Repositories.Updates.Enabled && strings.TrimSpace(sc.Runtime) != "" {
		runner, err := sandbox.New(sandbox.Config{Runtime: sc.Runtime, Images: sc.Images, Forwarder: sc.Forwarder,
			Timeout: sc.Timeout, Memory: sc.Memory, User: sc.User, TempDir: sc.TempDir})
		if err != nil {
			// Updates that need a lock file re-resolved are skipped, with
			// this reason; the rest go ahead.
			deps.logger.Warn("the maintenance updater's sandbox is not available", "error", err)
		} else {
			svc.Attach(repos.Options{Sandbox: runner})
		}
	}
	if st, on := svc.ScanStatus(); on {
		deps.logger.Info("repository dependency scans enabled", "model", st.Model, "action", st.Action,
			"releases", cfg.Repositories.Scan.Releases == nil || *cfg.Repositories.Scan.Releases,
			"defaultBranch", cfg.Repositories.Scan.DefaultBranch == nil || *cfg.Repositories.Scan.DefaultBranch)
	} else if cfg.Repositories.Scan.ScanEnabledOrDefault() && !cfg.LLMPackageScan.Enabled {
		deps.logger.Info("repository dependency scans are off: they need the LLM package-content scan gate (llmPackageScan.enabled)")
	}
	if deps.leader != nil {
		svc.SetLeaderGate(deps.leader)
	}
	svc.Start(ctx)
	return nil
}

// reposDeps are the collaborators wireRepos attaches.
type reposDeps struct {
	cache     cache.Cache
	secrets   repos.SecretResolver
	audit     repos.AuditLogger
	notify    notify.Emitter
	collector *metrics.Collector
	graph     *provgraph.Service
	leader    func() bool
	logger    *slog.Logger
	// The dependency scans' gate and findings layer (Task 181).
	llmScan         *llmpkgscan.Service
	findings        *findings.Store
	findingsMetrics *findings.Metrics
	suppressions    *findings.SuppressionLedger
	siem            proxy.SIEMForwarder
	// The maintenance updater's coordinate policies (Task 182).
	firewall *depfirewall.Service
	maturity *maturity.Service
}

// allowedGitProtocols maps the accepted URL schemes onto git's transports.
func allowedGitProtocols(schemes []string) []string {
	if len(schemes) == 0 {
		schemes = []string{"https", "ssh"}
	}
	var out []string
	for _, s := range schemes {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}

// releaseGCSource is the garbage collector's view of the pins: a pinned key
// is never evicted, and the pins are re-read from the state directory before
// each pass (another replica may have pinned something since).
func releaseGCSource(svc *repos.Service) cachegc.ReferenceSource {
	return cachegc.NewFuncSource("release-pin", svc.IsPinned, svc.Refresh)
}

// --- adapters ---------------------------------------------------------------

// repoRef is the commit watcher's view of a repository.
func repoRef(r repos.Repo, cred repos.Credential) watch.RepoRef {
	return watch.RepoRef{Name: r.Name, URL: r.URL, FullName: r.FullName, Username: cred.Username, Token: cred.Token}
}

// mirrorRefs tracks tags with the commit watcher's mirror machinery.
type mirrorRefs struct{ gs *watch.GitSource }

func (m mirrorRefs) Tags(ctx context.Context, r repos.Repo, cred repos.Credential) (map[string]repos.Tip, error) {
	refs, err := m.gs.RefSnapshot(ctx, repoRef(r, cred), []string{"refs/tags/"})
	if err != nil {
		// Whether the mirror is stale or missing, nothing new is known.
		return nil, fmt.Errorf("%w: %s", repos.ErrStale, git.RedactURLSecrets(err.Error()))
	}
	out := make(map[string]repos.Tip, len(refs))
	for ref, tip := range refs {
		name := strings.TrimPrefix(ref, "refs/tags/")
		t := repos.Tip{Commit: tip.Commit}
		if tip.Annotated {
			t.Object = tip.Object
		}
		out[name] = t
	}
	return out, nil
}

func (m mirrorRefs) Keep(ctx context.Context, r repos.Repo, commit string) error {
	return m.gs.KeepCommit(ctx, repoRef(r, repos.Credential{}), commit)
}

func (m mirrorRefs) CommitTime(ctx context.Context, r repos.Repo, commit string) (time.Time, error) {
	return m.gs.CommitTime(ctx, repoRef(r, repos.Credential{}), commit)
}

// DefaultHead is the default branch's head in the mirror (Task 181).
func (m mirrorRefs) DefaultHead(ctx context.Context, r repos.Repo, cred repos.Credential) (repos.Head, error) {
	branch, commit, err := m.gs.DefaultHead(ctx, repoRef(r, cred), r.Branch)
	if err != nil {
		return repos.Head{Branch: branch}, fmt.Errorf("%s", git.RedactURLSecrets(err.Error()))
	}
	return repos.Head{Branch: branch, Commit: commit}, nil
}

// ResolveRevision names a revision's commit in the mirror (Task 181).
func (m mirrorRefs) ResolveRevision(ctx context.Context, r repos.Repo, rev string) (string, error) {
	return m.gs.ResolveRevision(ctx, repoRef(r, repos.Credential{}), rev)
}

// mirrorScanner reads the lock files of a commit in a repository's mirror.
type mirrorScanner struct{ gs *watch.GitSource }

func (m mirrorScanner) Scan(ctx context.Context, r repos.Repo, commit string, opts lockfiles.Options) (*lockfiles.Report, error) {
	dir := m.gs.MirrorDir(repoRef(r, repos.Credential{}))
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		return nil, fmt.Errorf("the repository's mirror is not there yet: %w", err)
	}
	reader, err := git.OpenObjectReader(dir, git.ObjectReaderOptions{})
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return lockfiles.Scan(ctx, reader, commit, opts)
}

// gatewayReleaseFetcher drives the registry's requests through the gateway's
// gated serve pipeline as a system principal.
type gatewayReleaseFetcher struct{ gw *proxy.Gateway }

func (f gatewayReleaseFetcher) Fetch(ctx context.Context, req repos.FetchRequest, body io.Writer) (repos.FetchResult, error) {
	res, err := f.gw.SystemFetch(ctx, proxy.SystemFetchRequest{
		Backend: req.Upstream, Path: req.Path, Accept: req.Accept,
		Tenant: req.Tenant, Subject: req.Subject, Roles: req.Roles,
		Hold: req.Hold, DeferLLMRefusal: req.DeferLLMRefusal,
	}, body)
	out := repos.FetchResult{
		Status: res.Status, Cache: res.Cache, CacheKey: res.CacheKey, Digest: res.Digest, Size: res.Size,
		ContentType: res.ContentType, Gate: res.Gate, Code: res.Code, Reason: res.Reason,
		LLM: objectScanPtr(res.LLMScan),
	}
	for _, v := range res.Verdicts {
		out.Verdicts = append(out.Verdicts, repos.GateVerdict{Gate: v.Gate, Outcome: v.Outcome, Detail: v.Detail})
	}
	return out, err
}

// mirrorBranches is the maintenance updater's Git side (Task 182): the files of
// a commit read from the repository's mirror, the commit built there, and the
// remote's branches.
type mirrorBranches struct{ gs *watch.GitSource }

func (m mirrorBranches) objects(r repos.Repo) (*git.ObjectReader, error) {
	dir := m.gs.MirrorDir(repoRef(r, repos.Credential{}))
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		return nil, fmt.Errorf("the repository's mirror is not there yet: %w", err)
	}
	return git.OpenObjectReader(dir, git.ObjectReaderOptions{})
}

func (m mirrorBranches) ReadFiles(ctx context.Context, r repos.Repo, commit string, paths []string, maxBytes int64) (map[string][]byte, error) {
	reader, err := m.objects(r)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return repos.ReadTreeFiles(ctx, reader, commit, paths, maxBytes)
}

func (m mirrorBranches) ListFiles(ctx context.Context, r repos.Repo, commit, dir string, match func(string) bool, max int) ([]string, error) {
	reader, err := m.objects(r)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return repos.ListTreeFiles(ctx, reader, commit, dir, match, max)
}

func (m mirrorBranches) BuildCommit(ctx context.Context, r repos.Repo, spec repos.CommitSpec) (string, string, error) {
	paths := make([]string, 0, len(spec.Files))
	for p := range spec.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	req := watch.CommitRequest{Base: spec.Base, Message: spec.Message,
		Author:    watch.Signature{Name: spec.Author, Email: spec.Email, When: spec.When},
		Committer: watch.Signature{Name: spec.Author, Email: spec.Email, When: spec.When}}
	for _, p := range paths {
		req.Files = append(req.Files, watch.FileChange{Path: p, Content: spec.Files[p]})
	}
	if spec.Signer != nil {
		req.Signer = spec.Signer
	}
	return m.gs.BuildCommit(ctx, repoRef(r, repos.Credential{}), req)
}

func (m mirrorBranches) CommitInfo(ctx context.Context, r repos.Repo, commit string) (string, []string, error) {
	return m.gs.CommitInfo(ctx, repoRef(r, repos.Credential{}), commit)
}

func (m mirrorBranches) CommitObject(ctx context.Context, r repos.Repo, commit string) ([]byte, error) {
	return m.gs.CommitObject(ctx, repoRef(r, repos.Credential{}), commit)
}

func (m mirrorBranches) RemoteBranch(ctx context.Context, r repos.Repo, cred repos.Credential, branch string) (string, error) {
	sha, err := m.gs.RemoteBranch(ctx, repoRef(r, cred), branch)
	if err != nil {
		return "", fmt.Errorf("%s", git.RedactURLSecrets(err.Error()))
	}
	return sha, nil
}

func (m mirrorBranches) PushBranch(ctx context.Context, r repos.Repo, cred repos.Credential, branch, commit, expect string) error {
	err := m.gs.PushBranch(ctx, repoRef(r, cred), branch, commit, expect)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, watch.ErrLeaseRejected):
		return fmt.Errorf("%w: %s", repos.ErrLeaseRejected, git.RedactURLSecrets(err.Error()))
	}
	return fmt.Errorf("%s", git.RedactURLSecrets(err.Error()))
}

func (m mirrorBranches) DeleteBranch(ctx context.Context, r repos.Repo, cred repos.Credential, branch, expect string) error {
	err := m.gs.DeleteBranch(ctx, repoRef(r, cred), branch, expect)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, watch.ErrLeaseRejected):
		return fmt.Errorf("%w: %s", repos.ErrLeaseRejected, git.RedactURLSecrets(err.Error()))
	}
	return fmt.Errorf("%s", git.RedactURLSecrets(err.Error()))
}

// candidatePolicy holds a maintenance candidate to the dependency firewall and
// the maturity cooldown before it is fetched (Task 182). Both services admit
// everything when they are off.
type candidatePolicy struct {
	firewall *depfirewall.Service
	maturity *maturity.Service
}

func (p candidatePolicy) CheckCandidate(tenant, ecosystem, name, version string) (bool, string, string) {
	if d := p.firewall.Check(tenant, depfirewall.Coordinate{Ecosystem: ecosystem, Name: name, Version: version}); d.Blocked {
		return false, repos.SkipFirewall, "the dependency firewall refuses it: " + d.Reason
	}
	if d := p.maturity.Check(tenant, maturity.Coordinate{Ecosystem: ecosystem, Name: name, Version: version}); d.Cooling {
		return false, repos.SkipCooldown, d.Reason
	}
	return true, "", ""
}

// cacheProbe tells whether a cache object is present.
type cacheProbe struct{ c cache.Cache }

func (p cacheProbe) Exists(ctx context.Context, key string) (bool, error) {
	if p.c == nil {
		return true, nil
	}
	_, err := p.c.Stat(ctx, key)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, cache.ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

// pinChecker returns the registry's pin set for the cache and the gateway, or
// nil (an untyped nil, so "no pins" is not a non-nil interface holding nil).
func pinChecker(svc *repos.Service) cache.PinChecker {
	if svc == nil {
		return nil
	}
	return svc
}

// repoWebhookHandler returns the registry's push-webhook receiver, or nil:
// without a webhook secret there is none.
func repoWebhookHandler(svc *repos.Service, cfg *config.Config, logger *slog.Logger) http.Handler {
	if svc == nil {
		return nil
	}
	h := svc.WebhookHandler()
	if h == nil {
		logger.Warn("repositories.webhookSecret is not set: the push webhook is not served; tags are tracked by polling",
			"path", cfg.RepositoriesWebhookPath(), "pollInterval", cfg.RepositoriesPollInterval())
	}
	return h
}

// dossierReleases answers the dossier's "shipped in release X" (Task 180).
type dossierReleases struct{ svc *repos.Service }

func (d dossierReleases) ReleasesShipping(ctx context.Context, tenant, ecosystem, name, version string) ([]dossier.ReleaseRef, error) {
	views, err := d.svc.Lookup(ctx, tenant, repos.LookupQuery{Type: ecosystem, Name: name, Version: version})
	if err != nil {
		return nil, err
	}
	out := make([]dossier.ReleaseRef, 0, len(views))
	for _, v := range views {
		ref := dossier.ReleaseRef{Repo: v.Repo, Commit: v.Commit, State: v.State, Tags: v.CurrentTags,
			FormerTags: v.FormerTags, FullyPinned: v.FullyPinned, Status: v.Status}
		for _, m := range v.Matches {
			ref.Version, ref.Status = m.Version, m.Status
			if m.Status == repos.StatusPinned {
				break
			}
		}
		out = append(out, ref)
	}
	return out, nil
}

// graphReleases feeds the provenance graph's release nodes (Task 180).
type graphReleases struct{ g *provgraph.Service }

// releaseGraph returns the provenance graph's release observer, or nil.
func releaseGraph(g *provgraph.Service) repos.ReleaseObserver {
	if g == nil {
		return nil
	}
	return graphReleases{g: g}
}

func (o graphReleases) ObserveRelease(_ context.Context, v repos.ReleaseView) {
	ev := provgraph.ReleaseEvent{Repo: v.Repo, Commit: v.Commit, Tenant: v.Tenant, Tags: v.CurrentTags,
		State: v.State, Status: v.Status}
	if v.Manifest != nil {
		for _, d := range v.Manifest.Dependencies {
			digest := ""
			for _, obj := range d.Objects {
				if obj.Role == "package" || obj.Role == "file" || obj.Role == "index" || obj.Role == "manifest" {
					digest = obj.Digest
					break
				}
			}
			ev.Dependencies = append(ev.Dependencies, provgraph.ArtifactRef{Ecosystem: d.Type, Name: d.Name, Version: d.Version, Digest: digest})
			ev.Statuses = append(ev.Statuses, d.Status)
		}
	}
	o.g.IngestRelease(ev)
}
