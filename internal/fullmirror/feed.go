package fullmirror

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// This file is the contract between the full-mirror engine (engine.go) and the
// feed adapters that follow one registry each (Tasks 190 and 191). An adapter
// reports what changed in its registry — Bootstrap enumerates it once, Changes
// follows it from a cursor — and lists a package's versions and their files
// (Releases). The engine does the rest: name filters, the version policy, the
// cache check, the byte budget, pacing, retries, and the fetch of every file
// through the proxy's own gated serve pipeline, exactly as a client pull. An
// adapter never fetches an artifact itself and never writes to the cache.

// Coordinate is one change a feed reports: a package, and the version when the
// feed names one.
type Coordinate struct {
	// Name is the package name as the registry spells it.
	Name string `json:"name"`
	// Version is the version the change concerns. Empty means the feed says
	// only that the package changed (npm's _changes does): the engine then
	// considers every version the version policy keeps.
	Version string `json:"version,omitempty"`
	// Deleted marks a removal: the package (or the version) is gone from the
	// registry. Nothing is fetched for it.
	Deleted bool `json:"deleted,omitempty"`
}

// String renders the coordinate as name@version (or the name alone).
func (c Coordinate) String() string {
	if c.Version == "" {
		return c.Name
	}
	return c.Name + "@" + c.Version
}

// Batch is one page of a feed: the changes it returned and where to continue.
type Batch struct {
	// Items are the changes, oldest first. They are processed in order; a
	// package may appear more than once.
	Items []Coordinate
	// Next is the cursor to pass to the following call. The engine stores it
	// once every item of the batch has been dealt with, and not before: a batch
	// interrupted by a restart, a pause or the end of the off-peak window is
	// resumed where it stopped. It must not be empty.
	Next string
	// More reports that the feed has more to give right away: the engine asks
	// again without waiting for the poll interval. The last Bootstrap batch
	// has More false; its Next is the change-feed cursor Changes continues
	// from, taken when the enumeration began so that nothing published during
	// it is missed.
	More bool
	// Head is the feed's newest position when the registry states it (npm's
	// update_seq). It is shown, never interpreted.
	Head string
	// Lag is how many changes lie between Next and Head, when LagKnown.
	Lag      int64
	LagKnown bool
	// HeadTime is when the newest change in the registry was made, and
	// CursorTime when the last change of this batch was, when the feed says.
	// Their difference is the lag in time.
	HeadTime   time.Time
	CursorTime time.Time
}

// Release is one version of a package.
type Release struct {
	// Version is the version as the registry spells it.
	Version string
	// Published is when the version was published, when the registry says.
	Published time.Time
	// Yanked marks a version the registry withdrew but still serves. A yanked
	// version is mirrored under the "all" version policy and never counts
	// towards "latest N".
	Yanked bool
	// Artifacts are the files of the version a client downloads.
	Artifacts []Artifact
}

// Artifact is one file of a release, as a client would request it through
// the proxy.
type Artifact struct {
	// Path is the request path relative to the upstream's mount, starting with
	// "/": the proxy serves it as /v1/<upstream><Path>. It carries no query.
	Path string `json:"path"`
	// Accept is the Accept header the request needs, if any (OCI manifests).
	Accept string `json:"accept,omitempty"`
	// Size is the file's size in bytes when the registry states it; zero when
	// it does not. A stated size lets the engine apply maxArtifactBytes and the
	// byte budget before anything is fetched.
	Size int64 `json:"size,omitempty"`
}

// Feed follows one upstream's registry. The engine calls one method at a time
// per feed (never concurrently with itself, except Releases, which is called
// from several workers at once).
type Feed interface {
	// Bootstrap enumerates the registry for a follower that starts from
	// nothing. cursor is "" on the first call and then the Next of the
	// previous batch; the batch with More false ends the enumeration.
	Bootstrap(ctx context.Context, cursor string) (Batch, error)
	// Changes returns the changes made after cursor, a cursor that Bootstrap
	// or Changes returned. A cursor the registry no longer knows (npm reset
	// its sequence; Packagist keeps only a day of changes) is reported with an
	// error wrapping ErrCursorInvalid: the engine starts over with Bootstrap.
	Changes(ctx context.Context, cursor string) (Batch, error)
	// Releases lists a package's versions, oldest first by the registry's own
	// version order, each with its files. An unknown package is a Permanent
	// error.
	Releases(ctx context.Context, name string) ([]Release, error)
}

// ErrCursorInvalid is what a feed's Changes returns (wrapped) for a cursor the
// registry no longer knows. The engine records an audit event and enumerates
// the registry again with Bootstrap.
var ErrCursorInvalid = errors.New("fullmirror: the registry no longer knows the cursor")

// permanentError marks an error retrying will not fix.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// Permanent marks err as one that retrying will not fix: a package the
// registry does not have, a malformed document. The engine records it and
// moves on instead of backing off. A nil err stays nil.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

// IsPermanent reports whether err was marked with Permanent.
func IsPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

// retryAfterError carries the wait a registry asked for.
type retryAfterError struct {
	err   error
	after time.Duration
}

func (e *retryAfterError) Error() string { return e.err.Error() }
func (e *retryAfterError) Unwrap() error { return e.err }

// RetryAfter wraps err with the wait the registry asked for (a 429's or a
// 503's Retry-After). The engine waits at least that long before it asks the
// upstream again — for anything, not only for this request. A nil err stays
// nil.
func RetryAfter(err error, d time.Duration) error {
	if err == nil {
		return nil
	}
	return &retryAfterError{err: err, after: d}
}

// RetryAfterOf returns the wait an error carries, if any.
func RetryAfterOf(err error) (time.Duration, bool) {
	var r *retryAfterError
	if errors.As(err, &r) && r.after > 0 {
		return r.after, true
	}
	return 0, false
}

// Env is what an adapter is built with.
type Env struct {
	// Upstream is the upstream's name (the key under `upstreams`), Type its
	// canonical type, URL its configured base URL and Settings its settings.
	Upstream string
	Type     string
	URL      string
	Settings map[string]string
	// HTTP is the client for the feed's own requests to the registry. It goes
	// through the proxy's outbound transport — the egress allowlist, the TLS
	// policy and pins of the upstream — and is paced by the upstream's
	// requestsPerSecond, like the engine's artifact fetches.
	HTTP *http.Client
	// UserAgent identifies the proxy in the feed's requests.
	UserAgent string
	// Dir is a directory the adapter may keep files in (a copy of an index to
	// diff the next one against). It is created for the adapter, lives with
	// the engine's state and is backed up with it — file by file, not
	// atomically with the cursor: a cursor that does not match the files must
	// be detected and answered with ErrCursorInvalid, never trusted.
	Dir string
	// Read fetches a path of the upstream's mount through the proxy's gated
	// serve pipeline, as the mirror's system principal, and writes the body to
	// w: a metadata document as the backend rewrites it for clients (npm's
	// packument with tarball links into the proxy). It is available once the
	// engine is attached to the gateway.
	Read func(ctx context.Context, path, accept string, w io.Writer) (FetchResult, error)
}

// Factory builds the feed adapter for one upstream.
type Factory func(Env) (Feed, error)

var (
	adaptersMu sync.RWMutex
	adapters   = map[string]Factory{}
)

// Register makes f the feed adapter of an upstream type (its canonical name,
// as the catalog lists it) and returns a function that removes the
// registration again. Adapters register from an init function of this
// package, so that every binary that validates configuration — the proxy,
// ptctl, the tests — knows the same set; config validation refuses full
// mirroring of a type nothing is registered for, and a test holds the set to
// the catalog's implementation status.
func Register(upstreamType string, f Factory) (unregister func()) {
	if f == nil {
		panic("fullmirror: Register with a nil factory")
	}
	adaptersMu.Lock()
	defer adaptersMu.Unlock()
	if _, dup := adapters[upstreamType]; dup {
		panic(fmt.Sprintf("fullmirror: a feed adapter for %q is already registered", upstreamType))
	}
	adapters[upstreamType] = f
	return func() {
		adaptersMu.Lock()
		defer adaptersMu.Unlock()
		delete(adapters, upstreamType)
	}
}

// Adapters lists the upstream types a feed adapter is registered for, sorted.
func Adapters() []string {
	adaptersMu.RLock()
	defer adaptersMu.RUnlock()
	out := make([]string, 0, len(adapters))
	for t := range adapters {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Followable reports whether full mirroring can be enabled for an upstream
// type (or an alias of one). The error says why not: the type has no catalog
// entry, its registry cannot be enumerated (tier d), or no feed adapter for
// its tier has been written yet.
func Followable(upstreamType string) error {
	e, ok := Lookup(upstreamType)
	if !ok {
		return fmt.Errorf("full mirroring knows no upstream type %q", upstreamType)
	}
	if e.Tier == TierNone {
		return fmt.Errorf("%s cannot be followed: its tier is (%s), %s (see docs/full-mirroring.md#%s)", e.Title, e.Tier, e.Tier.Title(), e.Type)
	}
	adaptersMu.RLock()
	_, ok = adapters[e.Type]
	adaptersMu.RUnlock()
	if !ok {
		return fmt.Errorf("no feed adapter follows %s yet (tier (%s), %s; implementation status: %s; see docs/full-mirroring.md#%s)",
			e.Title, e.Tier, e.Tier.Title(), statusText(e.Status), e.Type)
	}
	return nil
}

// NewFeed builds the registered adapter for env.Type.
func NewFeed(env Env) (Feed, error) {
	if err := Followable(env.Type); err != nil {
		return nil, err
	}
	e, _ := Lookup(env.Type)
	adaptersMu.RLock()
	f := adapters[e.Type]
	adaptersMu.RUnlock()
	env.Type = e.Type
	feed, err := f(env)
	if err != nil {
		return nil, fmt.Errorf("fullmirror: %s: building the %s feed adapter: %w", env.Upstream, e.Type, err)
	}
	return feed, nil
}
