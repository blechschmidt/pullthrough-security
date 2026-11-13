// Package repos is the repository registry of Task 180: per-repository tag
// tracking and permanent release-artifact pinning.
//
// A repository is registered by configuration or through the admin API (URL,
// a credentials reference resolved through the secrets provider, the owning
// tenant, the lock files that make up a release). The tracker follows its tags
// with the machinery of the incremental commit scanner (Task 108): a bare
// mirror per repository, refreshed by a leader-gated poll and by push webhooks
// signed like the commit scanner's.
//
// Every tag-to-commit association ever seen is kept in an append-only,
// hash-chained history: a tag that is created, force-moved or deleted adds a
// record and never rewrites one. Each change is written to the audit log.
//
// When a tag appears or moves, the commit it names is pinned: the tracker reads
// the lock files at the commit (internal/lockfiles), fetches every dependency
// they pin through the proxy's own gated serve pipeline as a system principal
// of the repository's tenant — every admission gate, digest verification and
// the download log apply — checks the bytes against the lock file's digests,
// and stores a release manifest keyed by (repository, commit): the lock files,
// the dependencies, the cache objects with their digests and gate verdicts.
// The cache objects are then pinned: the cache, the garbage collector and the
// negative cache never delete them, tiering may only demote them, and a pinned
// object whose bytes go bad is fetched again (or an alert raised). A commit no
// tag points at any more keeps its manifest and pins; the API calls it
// historical. A dependency that is refused or cannot be fetched is recorded
// with the reason, and the release is then not fully pinned.
package repos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
)

// Credential is what a repository is fetched with over HTTPS.
type Credential struct {
	Username string
	Token    string
}

// Tip is a tag's state: the commit it resolves to and, for an annotated tag,
// the tag object.
type Tip struct {
	Commit string `json:"commit"`
	Object string `json:"object,omitempty"`
}

// ErrStale is wrapped by RefSource.Tags when the mirror could not be refreshed.
var ErrStale = errors.New("repos: the repository could not be fetched")

// RefSource is the Git side of tracking: a mirror per repository.
type RefSource interface {
	// Tags refreshes the repository's mirror and returns its tags by short
	// name. When the refresh fails it returns an error wrapping ErrStale.
	Tags(ctx context.Context, repo Repo, cred Credential) (map[string]Tip, error)
	// Keep keeps commit reachable in the mirror after its tag moves.
	Keep(ctx context.Context, repo Repo, commit string) error
	// CommitTime returns the commit's committer date.
	CommitTime(ctx context.Context, repo Repo, commit string) (time.Time, error)
}

// LockfileScanner reads the lock files of a commit of a repository's mirror.
type LockfileScanner interface {
	Scan(ctx context.Context, repo Repo, commit string, opts lockfiles.Options) (*lockfiles.Report, error)
}

// FetchRequest is one request the tracker drives through the proxy's serve
// pipeline.
type FetchRequest struct {
	Upstream string
	// Path is the backend-relative path ("/lodash/-/lodash-4.17.21.tgz").
	Path   string
	Accept string
	// Tenant is the tenant the request is made as; Subject the system
	// principal; Roles the access-control roles it holds.
	Tenant  string
	Subject string
	Roles   []string
	// Hold, when set, is called with the object's cache key once every
	// admission gate has admitted it and before it is served: from then on
	// the object is held against eviction until the job's manifest pins it.
	Hold func(cacheKey string)
}

// FetchResult is what the proxy did with a FetchRequest.
type FetchResult struct {
	// Status is the HTTP status answered.
	Status int
	// Cache is HIT, MISS, COALESCED-HIT or BYPASS (served uncached).
	Cache string
	// CacheKey and Digest identify the cache object served ("" when the
	// response did not come from the cache); Size is its length.
	CacheKey    string
	Digest      string
	Size        int64
	ContentType string
	// Gate, Code and Reason explain a refusal.
	Gate   string
	Code   string
	Reason string
	// Verdicts are the admission gates that judged the object.
	Verdicts []GateVerdict
}

// Fetcher drives requests through the proxy's gated serve pipeline as a system
// principal; the response body is written to body.
type Fetcher interface {
	Fetch(ctx context.Context, req FetchRequest, body io.Writer) (FetchResult, error)
}

// SecretResolver resolves credential references (*secrets.Resolver).
type SecretResolver interface {
	Resolve(ctx context.Context, value string) (string, error)
}

// AuditLogger records tag and pin events (*audit.Logger).
type AuditLogger interface {
	Log(ctx context.Context, ev audit.Event) error
}

// CacheProbe tells whether a cache object exists (cache.Cache satisfies it).
type CacheProbe interface {
	Exists(ctx context.Context, key string) (bool, error)
}

// Config tunes the service.
type Config struct {
	// Repos are the registrations from the configuration.
	Repos []Repo
	// PollInterval is the period between syncs of every repository; zero
	// leaves tracking to webhooks and manual syncs.
	PollInterval time.Duration
	// WebhookSecret verifies push webhooks (X-Hub-Signature-256); without
	// one there is no webhook receiver.
	WebhookSecret string
	// BackfillTags is how many tags found at a repository's first sync are
	// pinned, the most recently committed first; -1 is all, 0 none. Nil is
	// the default, 10.
	BackfillTags *int
	// AllowedSchemes are the URL schemes registrations may use; default
	// https and ssh.
	AllowedSchemes []string
	// Workers is how many releases are pinned at a time (default 2);
	// Concurrency how many dependencies of one release are fetched at a time
	// (default 4).
	Workers     int
	Concurrency int
	// MaxDependencies bounds the dependencies of one release (default 10000);
	// a release with more is not fully pinned.
	MaxDependencies int
	// MaxArtifactsPerDependency bounds the objects one dependency expands to
	// (an image index, a wheel per platform).
	MaxArtifactsPerDependency int
	// IncludeDev pins development dependencies too (default true).
	IncludeDev *bool
	// Platforms selects the platforms of container images and Terraform
	// providers (default: every platform an image index lists; linux/amd64
	// for providers).
	Platforms []locate.Platform
	// RetryInterval is the wait before what a release could not pin is tried
	// again, doubling per attempt (default 1h); MaxAttempts bounds the
	// attempts (default 5).
	RetryInterval time.Duration
	MaxAttempts   int
	// RefreshInterval is how often a replica re-reads manifests other
	// replicas wrote to a shared state directory (default 1m; negative off).
	RefreshInterval time.Duration
	// Lockfiles are the base options of the lock-file scans (proxy URL map,
	// skip globs, limits); each repository's lock-file globs are added.
	Lockfiles lockfiles.Options
	// SpoolDir holds temporary copies of Go module zips while they are
	// hashed; empty is the system's temporary directory.
	SpoolDir string
	// Subject is the system principal pins are fetched as (default
	// "system:release-pinner").
	Subject string
	// Roles are the access-control roles the system principal holds for a
	// repository that names none of its own.
	Roles []string
	// KnownRole, when set, reports whether a role is defined; registrations
	// naming another are refused. Nil accepts any name (access control off).
	KnownRole func(string) bool
}

func (c Config) withDefaults() Config {
	if c.BackfillTags == nil {
		n := 10
		c.BackfillTags = &n
	}
	if len(c.AllowedSchemes) == 0 {
		c.AllowedSchemes = []string{"https", "ssh"}
	}
	if c.Workers <= 0 {
		c.Workers = 2
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.MaxDependencies <= 0 {
		c.MaxDependencies = 10000
	}
	if c.IncludeDev == nil {
		t := true
		c.IncludeDev = &t
	}
	if c.RetryInterval <= 0 {
		c.RetryInterval = time.Hour
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 5
	}
	if c.RefreshInterval == 0 {
		c.RefreshInterval = time.Minute
	}
	if c.Subject == "" {
		c.Subject = "system:release-pinner"
	}
	return c
}

// Options are the service's collaborators.
type Options struct {
	Store     Store
	Refs      RefSource
	Scanner   LockfileScanner
	Fetcher   Fetcher
	Upstreams []locate.Upstream
	Secrets   SecretResolver
	Audit     AuditLogger
	Notify    notify.Emitter
	Cache     CacheProbe
	Metrics   *Metrics
	// Observer is told about releases (the provenance graph).
	Observer ReleaseObserver
	Logger   *slog.Logger
	Now      func() time.Time
}

// Service is the repository registry, tag tracker and release pinner.
type Service struct {
	cfg  Config
	opts Options
	st   Store
	idx  *pinIndex
	log  *slog.Logger
	now  func() time.Time

	mu    sync.RWMutex
	repos map[string]*registration
	live  map[string]*liveState
	// manifestVersions remembers the content of every manifest loaded, so a
	// refresh re-reads only what changed; summaries keeps each manifest's
	// header, so that listings do not read every manifest from the store.
	manifestVersions map[string]string
	summaries        map[string]Manifest

	locks keyedMutex

	qmu    sync.Mutex
	queued map[string]bool
	queue  chan pinJob

	repairMu  sync.Mutex
	repairing map[string]bool

	// syncing coalesces background syncs: one runs per repository at a
	// time, and requests meanwhile make it run once more.
	syncMu  sync.Mutex
	syncing map[string]*bool

	leader func() bool

	runCtx    context.Context
	runCancel context.CancelFunc
	stopOnce  sync.Once
	started   bool
	// lifeMu guards closing: no goroutine is started once Close waits.
	lifeMu  sync.Mutex
	closing bool
	wg      sync.WaitGroup
}

// registration is a repository and its bookkeeping.
type registration struct {
	Repo
	// Removed marks an API registration that was removed: it is no longer
	// tracked, but its history and releases (and their pins) remain.
	Removed   bool      `json:"removed,omitempty"`
	RemovedAt time.Time `json:"removedAt,omitempty"`
	RemovedBy string    `json:"removedBy,omitempty"`
}

// New opens the service: it loads the registrations, the histories and the
// manifests, and indexes the pins. It starts nothing; see Start.
func New(ctx context.Context, cfg Config, opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("repos: a state store is required")
	}
	cfg = cfg.withDefaults()
	s := &Service{
		cfg:              cfg,
		opts:             opts,
		st:               opts.Store,
		idx:              newPinIndex(),
		log:              opts.Logger,
		now:              opts.Now,
		repos:            map[string]*registration{},
		live:             map[string]*liveState{},
		manifestVersions: map[string]string{},
		summaries:        map[string]Manifest{},
		locks:            newKeyedMutex(),
		queued:           map[string]bool{},
		queue:            make(chan pinJob, 4096),
		repairing:        map[string]bool{},
		syncing:          map[string]*bool{},
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.runCtx, s.runCancel = context.WithCancel(context.Background())
	for i := range cfg.Repos {
		r := cfg.Repos[i].clone()
		r.Source = SourceConfig
		if err := r.Validate(cfg.AllowedSchemes); err != nil {
			return nil, err
		}
		if _, dup := s.repos[r.Name]; dup {
			return nil, fmt.Errorf("repos: repository %q is configured twice", r.Name)
		}
		s.repos[r.Name] = &registration{Repo: r}
	}
	if err := s.loadRegistrations(ctx); err != nil {
		return nil, err
	}
	s.recordConfigRegistrations(ctx)
	if err := s.loadManifests(ctx); err != nil {
		return nil, err
	}
	s.metrics().setRepos(s.countTracked())
	return s, nil
}

// Attach supplies collaborators that are built after the service — the
// pin set must exist before the cache, the gateway's fetcher only after it. A
// nil field keeps the current one. Call it before Start.
func (s *Service) Attach(o Options) {
	if o.Refs != nil {
		s.opts.Refs = o.Refs
	}
	if o.Scanner != nil {
		s.opts.Scanner = o.Scanner
	}
	if o.Fetcher != nil {
		s.opts.Fetcher = o.Fetcher
	}
	if o.Upstreams != nil {
		s.opts.Upstreams = o.Upstreams
	}
	if o.Secrets != nil {
		s.opts.Secrets = o.Secrets
	}
	if o.Audit != nil {
		s.opts.Audit = o.Audit
	}
	if o.Notify != nil {
		s.opts.Notify = o.Notify
	}
	if o.Cache != nil {
		s.opts.Cache = o.Cache
	}
	if o.Observer != nil {
		s.opts.Observer = o.Observer
	}
	if o.Metrics != nil {
		s.opts.Metrics = o.Metrics
		s.opts.Metrics.setRepos(s.countTracked())
		s.refreshPinMetrics()
	}
}

// Pins returns the pin set, for the cache, the garbage collector and the
// gateway (it satisfies cache.PinChecker).
func (s *Service) Pins() interface{ IsPinned(string) bool } { return s.idx }

// IsPinned reports whether a release pins the cache key.
func (s *Service) IsPinned(key string) bool { return s.idx.IsPinned(key) }

// SetLeaderGate installs the HA leader gate: only the leader polls, retries
// and acts on webhooks. A nil gate means always.
func (s *Service) SetLeaderGate(isLeader func() bool) { s.leader = isLeader }

func (s *Service) isLeader() bool { return s.leader == nil || s.leader() }

func (s *Service) metrics() *Metrics { return s.opts.Metrics }

// loadRegistrations reads the API registrations.
func (s *Service) loadRegistrations(ctx context.Context) error {
	names, err := s.st.List(ctx, "repos/")
	if err != nil {
		return err
	}
	for _, n := range names {
		data, err := s.st.Get(ctx, n)
		if err != nil {
			return err
		}
		if err := s.applyRegistration(n, data, true); err != nil {
			return err
		}
	}
	return nil
}

// refreshRegistrations re-reads the stored registrations: one made or removed
// through another replica's API is tracked, or no longer tracked, here too.
func (s *Service) refreshRegistrations(ctx context.Context) error {
	names, err := s.st.List(ctx, "repos/")
	if err != nil {
		return err
	}
	for _, n := range names {
		data, err := s.st.Get(ctx, n)
		if err != nil {
			continue
		}
		if err := s.applyRegistration(n, data, false); err != nil {
			s.log.Warn("stored repository registration unreadable", "object", n, "error", err)
		}
	}
	s.metrics().setRepos(s.countTracked())
	return nil
}

// applyRegistration takes a stored registration into the registry. The
// configuration wins over a stored record of a name it defines.
func (s *Service) applyRegistration(object string, data []byte, startup bool) error {
	var reg registration
	if err := json.Unmarshal(data, &reg); err != nil {
		return fmt.Errorf("repos: reading %s: %w", object, err)
	}
	if repoObject(reg.Name) != object {
		return fmt.Errorf("repos: %s holds the registration of %q", object, reg.Name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.repos[reg.Name]; ok && existing.Source == SourceConfig && s.configured(reg.Name) {
		switch {
		case !startup:
		case reg.Source != SourceConfig:
			s.log.Warn("repository registered through the API is also configured; the configuration wins", "repo", reg.Name)
		case reg.URL != existing.URL || reg.Tenant != existing.Tenant:
			s.log.Warn("configured repository changed its URL or tenant; its history continues under the new one",
				"repo", reg.Name, "url", existing.URL, "previousURL", reg.URL, "tenant", existing.Tenant, "previousTenant", reg.Tenant)
		}
		return nil
	}
	if reg.Source == SourceConfig {
		// A repository the configuration no longer defines. Its history and
		// releases are kept, and its name stays bound to its tenant and URL
		// like a removed API registration's: nobody else can register the
		// name and read them.
		if !reg.Removed {
			reg.Removed, reg.RemovedBy = true, "configuration"
		}
	} else {
		reg.Source = SourceAPI
	}
	if err := reg.Repo.Validate(s.cfg.AllowedSchemes); err != nil {
		if startup {
			s.log.Error("stored repository registration is invalid; not tracked", "repo", reg.Name, "error", err)
		}
		reg.Removed = true
	}
	s.repos[reg.Name] = &reg
	return nil
}

// configured reports whether the configuration defines a repository. The
// caller holds s.mu.
func (s *Service) configured(name string) bool {
	for _, r := range s.cfg.Repos {
		if strings.TrimSpace(r.Name) == name {
			return true
		}
	}
	return false
}

// dropLive forgets the cached live states; they are re-read when next needed.
func (s *Service) dropLive() {
	s.mu.Lock()
	s.live = map[string]*liveState{}
	s.mu.Unlock()
}

// recordConfigRegistrations stores a record of every configured repository —
// its name, URL and tenant — unless the store holds one already: the name stays
// bound to them when the repository is later dropped from the configuration,
// so an API registration of the name by another tenant cannot take over its
// history. An API registration of the same name is left as it is (the
// configuration wins while it defines the name).
func (s *Service) recordConfigRegistrations(ctx context.Context) {
	for _, r := range s.cfg.Repos {
		name := strings.TrimSpace(r.Name)
		s.mu.RLock()
		reg := s.repos[name]
		s.mu.RUnlock()
		if reg == nil {
			continue
		}
		data, err := s.st.Get(ctx, repoObject(name))
		if err == nil {
			var stored registration
			if json.Unmarshal(data, &stored) == nil && (stored.Source != SourceConfig ||
				(stored.URL == reg.URL && stored.Tenant == reg.Tenant && !stored.Removed)) {
				continue
			}
		} else if !errors.Is(err, ErrNotFound) {
			s.log.Warn("reading a repository registration failed", "repo", name, "error", err)
			continue
		}
		rec := registration{Repo: reg.Repo.clone()}
		rec.CreatedAt = s.now().UTC()
		rec.CreatedBy = "configuration"
		out, err := json.MarshalIndent(&rec, "", "  ")
		if err == nil {
			err = s.st.Put(ctx, repoObject(name), out)
		}
		if err != nil {
			s.log.Warn("recording a configured repository failed; its name is not reserved if it is dropped from the configuration", "repo", name, "error", err)
		}
	}
}

// loadManifests indexes every stored manifest.
func (s *Service) loadManifests(ctx context.Context) error {
	names, err := s.st.List(ctx, "manifests/")
	if err != nil {
		return err
	}
	for _, n := range names {
		m, version, err := s.readManifestObject(ctx, n)
		if err != nil {
			s.log.Error("release manifest unreadable; its pins are not enforced until it is repaired", "object", n, "error", err)
			continue
		}
		s.indexManifest(n, version, m)
	}
	return nil
}

// indexManifest records a manifest read or written: its pins, its version and
// its header.
func (s *Service) indexManifest(name, version string, m *Manifest, drop ...string) {
	s.idx.apply(m, drop...)
	head := *m
	head.Dependencies, head.LockFiles, head.Skipped, head.Submodule = nil, nil, nil, nil
	s.mu.Lock()
	s.manifestVersions[name] = version
	s.summaries[name] = head
	s.mu.Unlock()
}

// manifestHeads returns the headers of a repository's manifests (every
// repository's when repo is empty), newest first.
func (s *Service) manifestHeads(repo string) []Manifest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Manifest
	for _, m := range s.summaries {
		if repo == "" || m.Repo == repo {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Commit < out[j].Commit
	})
	return out
}

// Refresh re-reads the manifests another replica wrote to a shared state
// directory since the last read. The garbage collector calls it before each
// sweep, so that a pin written anywhere is honoured everywhere.
func (s *Service) Refresh(ctx context.Context) error {
	if err := s.refreshRegistrations(ctx); err != nil {
		return err
	}
	names, err := s.st.List(ctx, "manifests/")
	if err != nil {
		return err
	}
	for _, n := range names {
		data, err := s.st.Get(ctx, n)
		if err != nil {
			continue
		}
		version := contentVersion(data)
		s.mu.RLock()
		known := s.manifestVersions[n]
		s.mu.RUnlock()
		if known == version {
			continue
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil || m.Repo == "" || !validCommit(m.Commit) || manifestObject(m.Repo, m.Commit) != n {
			continue
		}
		s.indexManifest(n, version, &m)
	}
	return nil
}

func (s *Service) readManifestObject(ctx context.Context, name string) (*Manifest, string, error) {
	data, err := s.st.Get(ctx, name)
	if err != nil {
		return nil, "", err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, "", err
	}
	if m.Repo == "" || !validCommit(m.Commit) || manifestObject(m.Repo, m.Commit) != name {
		return nil, "", fmt.Errorf("repos: %s does not hold the manifest its name says", name)
	}
	return &m, contentVersion(data), nil
}

// readManifest returns the stored manifest of a release, or ErrNotFound.
func (s *Service) readManifest(ctx context.Context, repo, commit string) (*Manifest, error) {
	m, _, err := s.readManifestObject(ctx, manifestObject(repo, commit))
	return m, err
}

// writeManifest stores a manifest and indexes its pins. Pins only grow — a
// key an earlier version of the manifest pinned stays pinned — except the
// keys in drop: objects the release lost.
func (s *Service) writeManifest(ctx context.Context, m *Manifest, drop ...string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	name := manifestObject(m.Repo, m.Commit)
	if err := s.st.Put(ctx, name, data); err != nil {
		return err
	}
	s.indexManifest(name, contentVersion(data), m, drop...)
	return nil
}

// contentVersion identifies an object's content.
func contentVersion(data []byte) string {
	return fmt.Sprintf("%d:%x", len(data), fnv64(data))
}

func fnv64(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

// --- registry ---------------------------------------------------------------

// Add registers a repository through the API. A name used by a configured
// repository is refused; a removed API registration of the same URL is
// restored.
func (s *Service) Add(ctx context.Context, r Repo, by string) (Repo, error) {
	r = r.clone()
	r.Source = SourceAPI
	if err := r.Validate(s.cfg.AllowedSchemes); err != nil {
		return Repo{}, &ValidationError{Err: err}
	}
	// An upstream the registration names must exist and be of the type it is
	// named for, as the configuration requires of configured repositories.
	if s.opts.Upstreams != nil {
		for t, name := range r.Upstreams {
			found := false
			for _, up := range s.opts.Upstreams {
				if up.Name == name && lockfiles.CanonicalType(up.Type) == lockfiles.CanonicalType(t) {
					found = true
				}
			}
			if !found {
				return Repo{}, &ValidationError{Err: fmt.Errorf("repository %q: upstreams.%s names %q, which is not a configured %s upstream", r.Name, t, name, t)}
			}
		}
	}
	if s.cfg.KnownRole != nil {
		// Access control is on: the release pinner fetches with roles, and
		// a registration it would hold none for could pin nothing.
		for _, role := range r.Roles {
			if !s.cfg.KnownRole(role) {
				return Repo{}, &ValidationError{Err: fmt.Errorf("repository %q: role %q is not defined (auth.roles)", r.Name, role)}
			}
		}
		if len(r.Roles) == 0 && len(s.cfg.Roles) == 0 {
			return Repo{}, &ValidationError{Err: fmt.Errorf("repository %q: access control is on; name the roles the release pinner fetches the repository's dependencies with (roles), or configure repositories.roles", r.Name)}
		}
	}
	r.CreatedAt = s.now().UTC()
	r.CreatedBy = by
	s.mu.RLock()
	_, known := s.repos[r.Name]
	s.mu.RUnlock()
	if !known {
		// History under the name with no registration to say whose it is
		// (state restored without its registry): the name is not free.
		if names, err := s.st.List(ctx, historyPrefix(r.Name)); err != nil {
			return Repo{}, err
		} else if len(names) > 0 {
			return Repo{}, &ConflictError{Msg: fmt.Sprintf("the name %q has the history of an earlier registration; choose another name", r.Name)}
		}
	}
	s.mu.Lock()
	if existing, ok := s.repos[r.Name]; ok {
		switch {
		case existing.Source == SourceConfig && !existing.Removed:
			s.mu.Unlock()
			return Repo{}, &ConflictError{Msg: fmt.Sprintf("repository %q is defined in the configuration", r.Name)}
		case !existing.Removed:
			s.mu.Unlock()
			return Repo{}, &ConflictError{Msg: fmt.Sprintf("repository %q is already registered", r.Name)}
		case existing.URL != r.URL:
			s.mu.Unlock()
			return Repo{}, &ConflictError{Msg: fmt.Sprintf("the name %q belongs to a removed registration of another URL, whose history and releases are kept; choose another name", r.Name)}
		case existing.Tenant != r.Tenant:
			s.mu.Unlock()
			return Repo{}, &ConflictError{Msg: fmt.Sprintf("the name %q belongs to a removed registration of another tenant", r.Name)}
		}
	}
	reg := &registration{Repo: r}
	s.mu.Unlock()
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return Repo{}, err
	}
	if err := s.st.Put(ctx, repoObject(r.Name), data); err != nil {
		return Repo{}, err
	}
	s.mu.Lock()
	s.repos[r.Name] = reg
	s.mu.Unlock()
	s.metrics().setRepos(s.countTracked())
	s.auditRepo(ctx, "registered", r, by)
	if s.started && s.isLeader() {
		s.goSync(r.Name, "registration")
	}
	return r.clone(), nil
}

// Remove stops tracking an API registration. Its history, its release
// manifests and their pins are kept: removing a repository does not make its
// releases irreproducible.
func (s *Service) Remove(ctx context.Context, tenant, name, by string) error {
	s.mu.Lock()
	reg, ok := s.repos[name]
	if !ok || reg.Removed || (tenant != "" && reg.Tenant != tenant) {
		s.mu.Unlock()
		return ErrNotFound
	}
	if reg.Source == SourceConfig {
		s.mu.Unlock()
		return &ConflictError{Msg: fmt.Sprintf("repository %q is defined in the configuration; remove it there", name)}
	}
	removed := *reg
	removed.Removed, removed.RemovedAt, removed.RemovedBy = true, s.now().UTC(), by
	s.mu.Unlock()
	data, err := json.MarshalIndent(&removed, "", "  ")
	if err != nil {
		return err
	}
	if err := s.st.Put(ctx, repoObject(name), data); err != nil {
		return err
	}
	s.mu.Lock()
	s.repos[name] = &removed
	s.mu.Unlock()
	s.metrics().setRepos(s.countTracked())
	s.auditRepo(ctx, "removed", removed.Repo, by)
	return nil
}

// ValidationError is a registration the service refuses as invalid.
type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

// ConflictError is a registration that clashes with an existing one.
type ConflictError struct{ Msg string }

func (e *ConflictError) Error() string { return e.Msg }

// registration returns a tracked or removed repository visible to tenant.
func (s *Service) registration(tenant, name string) (*registration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	reg, ok := s.repos[name]
	if !ok || (tenant != "" && reg.Tenant != tenant) {
		return nil, false
	}
	cp := *reg
	cp.Repo = reg.Repo.clone()
	return &cp, true
}

// tracked returns the repositories being tracked, sorted by name.
func (s *Service) tracked() []Repo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Repo, 0, len(s.repos))
	for _, reg := range s.repos {
		if !reg.Removed {
			out = append(out, reg.Repo.clone())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Service) countTracked() int { return len(s.tracked()) }

// credential resolves a repository's credentials reference.
func (s *Service) credential(ctx context.Context, r Repo) (Credential, error) {
	if r.CredentialsRef == "" {
		return Credential{}, nil
	}
	if s.opts.Secrets == nil {
		return Credential{}, errors.New("no secrets provider is configured to resolve credentialsRef")
	}
	tok, err := s.opts.Secrets.Resolve(ctx, r.CredentialsRef)
	if err != nil {
		return Credential{}, err
	}
	user := r.Username
	if user == "" {
		user = "x-access-token"
	}
	return Credential{Username: user, Token: tok}, nil
}

// --- lifecycle --------------------------------------------------------------

// Start launches the pin workers, the poll loop and the retry sweep, and
// queues the releases a previous run left pending. ctx bounds them; Close stops
// them.
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
			s.runCancel()
		case <-s.runCtx.Done():
		}
	}()
	for i := 0; i < s.cfg.Workers; i++ {
		s.spawn(s.worker)
	}
	s.spawn(s.loop)
	s.log.Info("repository tracking started", "repos", s.countTracked(),
		"pollInterval", s.cfg.PollInterval, "workers", s.cfg.Workers)
}

// Close stops the loops and waits for running jobs to end.
func (s *Service) Close() error {
	s.lifeMu.Lock()
	s.closing = true
	s.lifeMu.Unlock()
	s.stopOnce.Do(func() { s.runCancel() })
	s.wg.Wait()
	return nil
}

// spawn runs fn in a goroutine Close waits for. Once Close has begun nothing
// is started (a WaitGroup must not grow while it is waited on); it then
// reports false.
func (s *Service) spawn(fn func()) bool {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if s.closing {
		return false
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		fn()
	}()
	return true
}

// loop polls, retries and refreshes.
func (s *Service) loop() {
	ctx := s.runCtx
	// The provenance graph lives in memory: tell it about every release.
	s.replayReleases(ctx)
	// The first pass resumes what a previous run left pending and syncs
	// every repository.
	if s.isLeader() {
		s.sweepPending(ctx)
		if s.cfg.PollInterval > 0 {
			s.SyncAll(ctx, "poll")
		}
	}
	tick := time.Minute
	if s.cfg.PollInterval > 0 && s.cfg.PollInterval < tick {
		tick = s.cfg.PollInterval
	}
	if s.cfg.RefreshInterval > 0 && s.cfg.RefreshInterval < tick {
		tick = s.cfg.RefreshInterval
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	lastPoll, lastRefresh := s.now(), s.now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := s.now()
		leader := s.isLeader()
		// Every replica re-reads what the others wrote to the shared state:
		// registrations made through another replica's API, the manifests
		// (pins) the leader stores, the releases a sync on another replica
		// left pending for the leader.
		if s.cfg.RefreshInterval > 0 && now.Sub(lastRefresh) >= s.cfg.RefreshInterval {
			lastRefresh = now
			if err := s.Refresh(ctx); err != nil {
				s.log.Warn("re-reading the registry's shared state failed", "error", err)
			}
			if !leader {
				// The leader's syncs move the tags; a replica that does
				// not sync re-reads them when next asked.
				s.dropLive()
			}
		}
		if leader && s.cfg.PollInterval > 0 && now.Sub(lastPoll) >= s.cfg.PollInterval {
			lastPoll = now
			s.SyncAll(ctx, "poll")
		}
		if leader {
			s.sweepPending(ctx)
		}
	}
}

// SyncAll syncs every tracked repository.
func (s *Service) SyncAll(ctx context.Context, trigger string) {
	for _, r := range s.tracked() {
		if ctx.Err() != nil {
			return
		}
		if _, err := s.Sync(ctx, r.Name, trigger); err != nil {
			s.log.Warn("repository sync failed", "repo", r.Name, "error", err)
		}
	}
}

// goSync syncs one repository in the background.
//
// Syncs are coalesced: while one of the repository runs, any number of further
// requests (a burst of webhook deliveries) make it run once more afterwards,
// not once each.
func (s *Service) goSync(name, trigger string) {
	s.syncMu.Lock()
	if again := s.syncing[name]; again != nil {
		*again = true
		s.syncMu.Unlock()
		return
	}
	again := new(bool)
	s.syncing[name] = again
	s.syncMu.Unlock()
	started := s.spawn(func() {
		for {
			if _, err := s.Sync(s.runCtx, name, trigger); err != nil {
				s.log.Warn("repository sync failed", "repo", name, "trigger", trigger, "error", err)
			}
			s.syncMu.Lock()
			if !*again || s.runCtx.Err() != nil {
				delete(s.syncing, name)
				s.syncMu.Unlock()
				return
			}
			*again = false
			s.syncMu.Unlock()
		}
	})
	if !started {
		s.syncMu.Lock()
		delete(s.syncing, name)
		s.syncMu.Unlock()
	}
}

// --- audit and notifications ---------------------------------------------

func (s *Service) auditLog(ctx context.Context, ev audit.Event) {
	if s.opts.Audit == nil {
		return
	}
	if err := s.opts.Audit.Log(ctx, ev); err != nil {
		s.log.Error("audit log write failed", "type", ev.Type, "resource", ev.Resource, "error", err)
	}
}

func (s *Service) auditRepo(ctx context.Context, action string, r Repo, by string) {
	s.auditLog(ctx, audit.Event{
		Type:     audit.EventRepository,
		Subject:  by,
		Team:     r.Tenant,
		Resource: "repo/" + r.Name,
		Decision: audit.DecisionAllow,
		Reason:   "repository " + action,
		Detail: map[string]any{
			"action":   action,
			"repo":     r.Name,
			"url":      redactURL(r.URL),
			"source":   r.Source,
			"tenant":   r.Tenant,
			"hasCreds": r.CredentialsRef != "",
		},
	})
}

func (s *Service) emit(ctx context.Context, ev notify.Event) {
	if s.opts.Notify != nil {
		s.opts.Notify.Emit(ctx, ev)
	}
}

// redactURL drops credentials and query from a URL for logs and events.
func redactURL(raw string) string {
	if i := strings.Index(raw, "://"); i > 0 {
		rest := raw[i+3:]
		if at := strings.LastIndex(strings.SplitN(rest, "/", 2)[0], "@"); at >= 0 {
			rest = rest[at+1:]
		}
		raw = raw[:i+3] + rest
	}
	if q := strings.IndexAny(raw, "?#"); q >= 0 {
		raw = raw[:q]
	}
	return raw
}

// --- keyed locking ------------------------------------------------------------

type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*refLock
}

type refLock struct {
	mu   sync.Mutex
	refs int
}

func newKeyedMutex() keyedMutex { return keyedMutex{locks: map[string]*refLock{}} }

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	l := k.locks[key]
	if l == nil {
		l = &refLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		if l.refs--; l.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
