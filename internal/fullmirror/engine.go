package fullmirror

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/ratelimit"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// The full-mirror engine (Task 189) follows the registries of the upstreams
// configured for it and fetches every new file ahead of any client request.
//
// One follower per upstream runs on the HA leader only: it polls the feed
// (Bootstrap until the registry has been enumerated once, Changes after that),
// stores the batch it got, and works through it with a few workers. A worker
// applies the name patterns and the version policy, asks the cache whether it
// already holds each file, and fetches the rest through the proxy's gated
// serve pipeline (Fetcher, which is Gateway.SystemFetch) as the mirror's
// system principal — the same resolution, admission gates, digest checks and
// cache fill as a client pull, recorded in the download log with via=system.
// The engine never writes to the cache itself.
//
// The cursor is stored only once the whole batch has been dealt with, and the
// batch's progress is persisted as it goes: a restart, a lost leadership, a
// pause, the end of the off-peak window or a spent byte budget leaves the
// batch to be resumed where it stopped. A file is fetched at most once per
// round; what a resumed batch finds in the cache is not fetched again.
//
// A refusal by an admission gate is a verdict: it is counted as refused, by
// gate, and the file is not asked for again. A transient failure (a 5xx, a
// 429, a network error) is retried with exponential backoff, honouring the
// upstream's Retry-After for every request to that upstream; a file that
// keeps failing stops the round, the upstream is backed off, and after a few
// rounds the file is counted as failed so that one broken file cannot stall
// the feed.

// FetchRequest is one file the engine asks the proxy for.
type FetchRequest struct {
	// Upstream is the upstream's name, Path the request path relative to its
	// mount, Accept the Accept header.
	Upstream string
	Path     string
	Accept   string
	// MaxBytes refuses a file larger than this before it is cached (0: no
	// limit): the fetch is cut off and nothing is admitted.
	MaxBytes int64
}

// LookupResult says what the proxy would serve for a request, and whether its
// cache already holds it. A lookup fetches nothing and runs no gate.
type LookupResult struct {
	// Cacheable is false for a path the proxy serves without caching it.
	Cacheable bool
	// Cached reports that the cache holds the object.
	Cached bool
	// Size is the cached object's size, when Cached.
	Size int64
}

// CodeTooLarge is the refusal code of a fetch cut off at MaxBytes.
const CodeTooLarge = "too-large"

// FetchResult is what the proxy's gated serve pipeline did with a request.
type FetchResult struct {
	// Status is the HTTP status the pipeline answered with.
	Status int
	// Cache is HIT, MISS, COALESCED-HIT or BYPASS (served without caching).
	Cache string
	// Admitted reports that every admission gate admitted the object into the
	// cache; Size is its size then.
	Admitted bool
	Size     int64
	// Gate, Code and Reason explain a refusal: the admission gate that refused
	// the object, its reason code and its explanation. A fetch cut off at
	// MaxBytes has Code CodeTooLarge and no gate. Action is the gate's action
	// ("fail-closed" when it could not judge the object).
	Gate   string
	Code   string
	Reason string
	Action string
	// RetryAfter is the wait the answer asked for (a relayed 429 or 503).
	RetryAfter time.Duration
}

// Fetcher is the proxy's gated serve pipeline as the engine uses it. The
// server implements it with Gateway.SystemLookup and Gateway.SystemFetch, as
// the mirror's system principal.
type Fetcher interface {
	Lookup(ctx context.Context, req FetchRequest) (LookupResult, error)
	Fetch(ctx context.Context, req FetchRequest, body io.Writer) (FetchResult, error)
}

// AuditLogger records the engine's events in the audit log (*audit.Logger
// satisfies it).
type AuditLogger interface {
	Log(ctx context.Context, ev audit.Event) error
}

// Admitter is the proxy's rate limiter (*ratelimit.Limiter): every file the
// mirror fetches is admitted as the mirror's tenant, so the instance's
// per-tenant and global limits hold for the mirror as for any client.
type Admitter interface {
	Admit(ctx context.Context, tenant string) (ratelimit.Reservation, ratelimit.Decision)
}

// Upstream is one upstream the engine mirrors.
type Upstream struct {
	Settings Settings
	// Feed follows the registry. When nil the adapter registered for the
	// type is built (NewFeed) with an Env made of the fields below.
	Feed Feed
	// URL, Config (the upstream's settings), HTTP (a client using the
	// upstream's outbound transport) and UserAgent are handed to the adapter.
	URL       string
	Config    map[string]string
	HTTP      *http.Client
	UserAgent string
}

// Options configure the engine.
type Options struct {
	// Dir is the state directory (fullMirror.stateDir).
	Dir string
	// Upstreams are the upstreams with full mirroring enabled.
	Upstreams []Upstream
	// Tenant is the tenant the mirror fetches as; it is what the proxy's rate
	// limiter admits.
	Tenant string
	Logger *slog.Logger
	Audit  AuditLogger
	// Now is the clock (tests).
	Now func() time.Time

	// Tuning; zero values take the defaults.
	// MaxAttempts is how often one request is tried within a round (5).
	MaxAttempts int
	// BaseBackoff and MaxBackoff bound the wait between two attempts
	// (2s, doubling, at most 1m).
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	// MaxRounds is how many rounds a file (or a package's version list) may
	// stop before it is counted as failed (3). RoundBackoff is the upstream's
	// wait after the first failed round (1m, doubling, at most 30m).
	MaxRounds    int
	RoundBackoff time.Duration
	// PollBackoff is the wait after the first failed poll (30s, doubling, at
	// most 1h).
	PollBackoff time.Duration
	// ControlRefresh is how often a running batch re-reads the operators'
	// control files (5s); PersistInterval how often its progress is written
	// (2s); StandbyInterval how often a replica that does not lead checks
	// again (15s); PollTimeout bounds one feed request (10m).
	ControlRefresh  time.Duration
	PersistInterval time.Duration
	StandbyInterval time.Duration
	PollTimeout     time.Duration
}

func (o Options) withDefaults() Options {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 5
	}
	if o.MaxRounds <= 0 {
		o.MaxRounds = 3
	}
	def(&o.BaseBackoff, 2*time.Second)
	def(&o.MaxBackoff, time.Minute)
	def(&o.RoundBackoff, time.Minute)
	def(&o.PollBackoff, 30*time.Second)
	def(&o.ControlRefresh, 5*time.Second)
	def(&o.PersistInterval, 2*time.Second)
	def(&o.StandbyInterval, 15*time.Second)
	def(&o.PollTimeout, 10*time.Minute)
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Subject is the system principal the mirror fetches as; it is what the
// download log and the audit log name.
const Subject = "system:full-mirror"

// maxReasonLength bounds an operator's pause reason.
const maxReasonLength = 500

// paceMaxWait is how long a request waits for its turn under the upstream's
// requestsPerSecond before it is treated as throttled.
const paceMaxWait = 10 * time.Minute

// Engine is the full-mirror engine.
type Engine struct {
	opts      Options
	log       *slog.Logger
	now       func() time.Time
	store     store
	followers []*follower
	byName    map[string]*follower
	// pace holds every upstream's requestsPerSecond, keyed by upstream name.
	pace *ratelimit.Limiter

	mu       sync.Mutex
	fetcher  Fetcher
	leader   func() bool
	fence    func() uint64
	kill     func() (bool, string)
	limiter  Admitter
	global   controlFile
	globalAt time.Time
	globalOK bool
	started  bool
	stopped  bool
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// ErrUnknownUpstream is returned for an upstream the engine does not mirror.
var ErrUnknownUpstream = errors.New("fullmirror: full mirroring is not enabled for that upstream")

// New builds the engine and its followers. Nothing runs before Start; no
// state is read before a follower first leads.
func New(opts Options) (*Engine, error) {
	opts = opts.withDefaults()
	if strings.TrimSpace(opts.Dir) == "" {
		return nil, errors.New("fullmirror: a state directory is required")
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("fullmirror: creating the state directory: %w", err)
	}
	e := &Engine{
		opts:   opts,
		log:    opts.Logger,
		now:    opts.Now,
		store:  store{dir: opts.Dir},
		byName: map[string]*follower{},
	}
	policies := map[string]ratelimit.Policy{}
	for _, u := range opts.Upstreams {
		s := u.Settings.withDefaults()
		if s.Upstream == "" {
			return nil, errors.New("fullmirror: an upstream without a name")
		}
		if _, dup := e.byName[s.Upstream]; dup {
			return nil, fmt.Errorf("fullmirror: upstream %q is listed twice", s.Upstream)
		}
		if s.ByteBudget <= 0 {
			return nil, fmt.Errorf("fullmirror: %s: a byte budget is required", s.Upstream)
		}
		if s.MaxArtifactBytes < 0 {
			return nil, fmt.Errorf("fullmirror: %s: maxArtifactBytes must not be negative", s.Upstream)
		}
		policies[s.Upstream] = ratelimit.Policy{RPS: s.RequestsPerSecond}
		f := &follower{e: e, s: s, wake: make(chan struct{}, 1)}
		if entry, ok := Lookup(s.Type); ok {
			f.tier = entry.Tier
			f.s.Type = entry.Type
		}
		if sc, ok := versions.For(f.s.Type); ok {
			f.scheme = sc
		}
		e.byName[s.Upstream] = f
		e.followers = append(e.followers, f)
		f.upstream = u
	}
	sort.Slice(e.followers, func(i, j int) bool { return e.followers[i].s.Upstream < e.followers[j].s.Upstream })
	e.pace = ratelimit.New(ratelimit.Options{PerTenant: policies, MaxWait: paceMaxWait, Now: opts.Now})
	for _, f := range e.followers {
		feed := f.upstream.Feed
		if feed == nil {
			env := e.adapterEnv(f)
			if err := os.MkdirAll(env.Dir, 0o750); err != nil {
				return nil, fmt.Errorf("fullmirror: %s: creating the adapter's directory: %w", f.s.Upstream, err)
			}
			var err error
			if feed, err = NewFeed(env); err != nil {
				return nil, err
			}
		}
		f.feed = feed
	}
	return e, nil
}

// adapterEnv is the environment a follower's adapter is built with.
func (e *Engine) adapterEnv(f *follower) Env {
	u := f.upstream
	base := http.DefaultTransport
	client := &http.Client{}
	if u.HTTP != nil {
		*client = *u.HTTP
		if u.HTTP.Transport != nil {
			base = u.HTTP.Transport
		}
	}
	name := f.s.Upstream
	client.Transport = pacedTransport{base: base, admit: func(ctx context.Context) error { return e.paceAdmit(ctx, name) }}
	dir := e.store.feedDir(name)
	return Env{
		Upstream:  name,
		Type:      f.s.Type,
		URL:       u.URL,
		Settings:  u.Config,
		HTTP:      client,
		UserAgent: u.UserAgent,
		Dir:       dir,
		Read: func(ctx context.Context, path, accept string, w io.Writer) (FetchResult, error) {
			fetcher := e.currentFetcher()
			if fetcher == nil {
				return FetchResult{}, errors.New("fullmirror: the engine is not attached to the gateway yet")
			}
			if err := e.paceAdmit(ctx, name); err != nil {
				return FetchResult{}, err
			}
			return fetcher.Fetch(ctx, FetchRequest{Upstream: name, Path: path, Accept: accept}, w)
		},
	}
}

// pacedTransport admits every request of an adapter under the upstream's
// requestsPerSecond.
type pacedTransport struct {
	base  http.RoundTripper
	admit func(context.Context) error
}

func (t pacedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := t.admit(r.Context()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(r)
}

// errThrottled reports a request the pacing did not admit in time.
type errThrottled struct{ after time.Duration }

func (e errThrottled) Error() string {
	return fmt.Sprintf("fullmirror: throttled; retry in %s", e.after.Round(time.Second))
}

// paceAdmit waits for the upstream's next request slot.
func (e *Engine) paceAdmit(ctx context.Context, upstream string) error {
	res, dec := e.pace.Admit(ctx, upstream)
	res.Release()
	if !dec.Allowed {
		if err := ctx.Err(); err != nil {
			return err
		}
		return errThrottled{after: dec.RetryAfter}
	}
	return nil
}

// Enabled reports whether any upstream is mirrored. Safe on nil.
func (e *Engine) Enabled() bool { return e != nil && len(e.followers) > 0 }

// Attach hands the engine the proxy's gated serve pipeline. Call it once the
// gateway exists, before Start.
func (e *Engine) Attach(f Fetcher) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.fetcher = f
	e.mu.Unlock()
	e.wakeAll()
}

// SetLeaderGate installs the HA leadership predicate and the fencing token of
// the lease held (coord.Guard's IsLeader and FencingToken). Only the leader
// polls and fetches. Nil leaves the engine always leading.
func (e *Engine) SetLeaderGate(isLeader func() bool, fence func() uint64) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.leader, e.fence = isLeader, fence
	e.mu.Unlock()
}

// SetKillSwitch installs the emergency lockdown predicate: while it reports an
// active lockdown, the mirror fetches nothing (any mode: an incident is under
// way, and a freeze forbids upstream fetches anyway).
func (e *Engine) SetKillSwitch(fn func() (active bool, mode string)) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.kill = fn
	e.mu.Unlock()
}

// SetLimiter installs the proxy's rate limiter.
func (e *Engine) SetLimiter(l Admitter) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.limiter = l
	e.mu.Unlock()
}

func (e *Engine) currentFetcher() Fetcher {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fetcher
}

func (e *Engine) isLeader() bool {
	e.mu.Lock()
	fn := e.leader
	e.mu.Unlock()
	return fn == nil || fn()
}

func (e *Engine) fenceToken() uint64 {
	e.mu.Lock()
	fn := e.fence
	e.mu.Unlock()
	if fn == nil {
		return 0
	}
	return fn()
}

func (e *Engine) killSwitch() (bool, string) {
	e.mu.Lock()
	fn := e.kill
	e.mu.Unlock()
	if fn == nil {
		return false, ""
	}
	return fn()
}

func (e *Engine) admitter() Admitter {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.limiter
}

// Start launches a follower per upstream. It is a no-op when nothing is
// mirrored or the engine runs already.
func (e *Engine) Start(ctx context.Context) {
	if !e.Enabled() {
		return
	}
	e.mu.Lock()
	if e.started || e.stopped {
		e.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	e.started, e.cancel = true, cancel
	for _, f := range e.followers {
		e.wg.Add(1)
		go func(f *follower) {
			defer e.wg.Done()
			f.run(ctx)
		}(f)
	}
	e.mu.Unlock()
	names := make([]string, 0, len(e.followers))
	for _, f := range e.followers {
		names = append(names, f.s.Upstream)
	}
	e.log.Info("full mirroring started", "upstreams", strings.Join(names, ","), "stateDir", e.opts.Dir)
}

// Close stops the followers, waits for them and writes their state. Safe on
// nil and more than once.
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return nil
	}
	e.stopped = true
	cancel := e.cancel
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	e.wg.Wait()
	var errs []error
	for _, f := range e.followers {
		if err := f.flush(); err != nil && !errors.Is(err, errFenced) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) wakeAll() {
	for _, f := range e.followers {
		f.kick()
	}
}

// globalControl returns the operators' global control file, re-read at most
// every ControlRefresh unless force.
func (e *Engine) globalControl(force bool) controlFile {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	if !force && e.globalOK && now.Sub(e.globalAt) < e.opts.ControlRefresh {
		return e.global
	}
	c, err := e.store.loadControl(e.store.globalControlPath())
	if err != nil {
		// An unreadable control file must not unpause the mirror: keep the
		// last one read.
		e.log.Warn("fullmirror: reading the control file", "error", err)
		return e.global
	}
	e.global, e.globalAt, e.globalOK = c, now, true
	return c
}

// audit records an engine event.
func (e *Engine) audit(ctx context.Context, f *follower, action, subject string, detail map[string]any) {
	if e.opts.Audit == nil {
		return
	}
	if subject == "" {
		subject = Subject
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["action"] = action
	ev := audit.Event{
		Type:     audit.EventFullMirror,
		Subject:  subject,
		Decision: audit.DecisionAllow,
		Reason:   "fullmirror:" + action,
		Detail:   detail,
	}
	if f != nil {
		ev.Backend = f.s.Upstream
		ev.Ecosystem = f.s.Type
	}
	if err := e.opts.Audit.Log(context.WithoutCancel(ctx), ev); err != nil {
		e.log.Warn("fullmirror: writing an audit event", "action", action, "error", err)
	}
}

// follower resolves an upstream name ("" and "*" mean every upstream).
func (e *Engine) targets(upstream string) ([]*follower, bool, error) {
	upstream = strings.TrimSpace(upstream)
	if upstream == "" || upstream == "*" {
		return e.followers, true, nil
	}
	f, ok := e.byName[upstream]
	if !ok {
		return nil, false, fmt.Errorf("%w: %q", ErrUnknownUpstream, upstream)
	}
	return []*follower{f}, false, nil
}

// Pause stops the mirror of one upstream, or of every upstream when upstream
// is empty, until Resume. Work in flight finishes its current file; a batch is
// resumed where it stopped. The pause is persisted and holds across restarts
// and on every replica.
func (e *Engine) Pause(ctx context.Context, upstream, by, reason string) error {
	if !e.Enabled() {
		return ErrUnknownUpstream
	}
	reason = cleanMessage(strings.TrimSpace(reason))
	if len(reason) > maxReasonLength {
		return fmt.Errorf("fullmirror: the reason is longer than %d bytes", maxReasonLength)
	}
	targets, all, err := e.targets(upstream)
	if err != nil {
		return err
	}
	now := e.now().UTC()
	if all {
		if err := e.updateControl(e.store.globalControlPath(), func(c *controlFile) {
			c.Paused, c.PausedBy, c.PausedAt, c.Reason = true, by, now, reason
		}); err != nil {
			return err
		}
		e.globalControl(true)
		e.audit(ctx, nil, "paused", by, map[string]any{"upstream": "*", "reason": reason})
	} else {
		f := targets[0]
		if err := e.updateControl(e.store.controlPath(f.s.Upstream), func(c *controlFile) {
			c.Paused, c.PausedBy, c.PausedAt, c.Reason = true, by, now, reason
		}); err != nil {
			return err
		}
		e.audit(ctx, f, "paused", by, map[string]any{"reason": reason})
	}
	for _, f := range targets {
		f.refreshControl(now, true)
		f.kick()
	}
	e.log.Info("full mirroring paused", "upstream", firstNonEmpty(upstream, "*"), "by", by, "reason", reason)
	return nil
}

// Resume lifts a pause: of one upstream, or — when upstream is empty — the
// global pause and every upstream's.
func (e *Engine) Resume(ctx context.Context, upstream, by string) error {
	if !e.Enabled() {
		return ErrUnknownUpstream
	}
	targets, all, err := e.targets(upstream)
	if err != nil {
		return err
	}
	unpause := func(c *controlFile) { c.Paused, c.PausedBy, c.PausedAt, c.Reason = false, "", time.Time{}, "" }
	if all {
		if err := e.updateControl(e.store.globalControlPath(), unpause); err != nil {
			return err
		}
		e.globalControl(true)
	}
	for _, f := range targets {
		if err := e.updateControl(e.store.controlPath(f.s.Upstream), unpause); err != nil {
			return err
		}
	}
	now := e.now()
	if all {
		e.audit(ctx, nil, "resumed", by, map[string]any{"upstream": "*"})
	} else {
		e.audit(ctx, targets[0], "resumed", by, nil)
	}
	for _, f := range targets {
		f.refreshControl(now, true)
		f.kick()
	}
	e.log.Info("full mirroring resumed", "upstream", firstNonEmpty(upstream, "*"), "by", by)
	return nil
}

// Resync has an upstream's follower forget its cursor and enumerate the
// registry again with Bootstrap. What is in the cache is not fetched again;
// the counters and the byte budget spent are kept.
func (e *Engine) Resync(ctx context.Context, upstream, by string) error {
	if !e.Enabled() {
		return ErrUnknownUpstream
	}
	if strings.TrimSpace(upstream) == "" || strings.TrimSpace(upstream) == "*" {
		return fmt.Errorf("fullmirror: name the upstream to resync")
	}
	targets, _, err := e.targets(upstream)
	if err != nil {
		return err
	}
	f := targets[0]
	now := e.now().UTC()
	var seq uint64
	if err := e.updateControl(e.store.controlPath(f.s.Upstream), func(c *controlFile) {
		c.ResyncSeq++
		c.ResyncBy, c.ResyncAt = by, now
		seq = c.ResyncSeq
	}); err != nil {
		return err
	}
	e.audit(ctx, f, "resync-requested", by, map[string]any{"request": seq})
	f.refreshControl(now, true)
	f.kick()
	e.log.Info("full mirroring resync requested", "upstream", upstream, "by", by)
	return nil
}

// controlMu serializes this process's read-modify-write of control files.
var controlMu sync.Mutex

func (e *Engine) updateControl(path string, edit func(*controlFile)) error {
	controlMu.Lock()
	defer controlMu.Unlock()
	c, err := e.store.loadControl(path)
	if err != nil {
		return err
	}
	edit(&c)
	return e.store.saveControl(path, c)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
