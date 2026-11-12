package userlinks

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults of a Registry.
const (
	// DefaultLinkTTL is how long a link works when the configuration does not
	// say: ninety days.
	DefaultLinkTTL = 90 * 24 * time.Hour
	// DefaultMaxLinksPerUser is how many working links one user may hold.
	DefaultMaxLinksPerUser = 10
	// DefaultSyncInterval is how often a replica refreshes the registry from the
	// store — and therefore how long a revocation performed on one replica can
	// take to reach another.
	DefaultSyncInterval = 15 * time.Second
	// usageFlushInterval is how often a replica writes down when links were last
	// used.
	usageFlushInterval = 30 * time.Second
	// retainEnded is how long the record of an expired or revoked link is kept
	// before it is deleted, so that "what was this link" still has an answer for
	// a while after it stopped working.
	retainEnded = 30 * 24 * time.Hour
	// staleUsageAge is how long a replica's usage object may go unwritten before
	// the replica is taken to be gone and what it saw is folded into another's.
	staleUsageAge = 7 * 24 * time.Hour
	// storeTimeout bounds one refresh or one write.
	storeTimeout = 30 * time.Second
)

// Reason says why a token did not resolve to a working link.
type Reason string

const (
	// ReasonMalformed: the text is not spelled like a token.
	ReasonMalformed Reason = "malformed"
	// ReasonUnknown: no link has this token.
	ReasonUnknown Reason = "unknown"
	// ReasonExpired: the link's lifetime is over.
	ReasonExpired Reason = "expired"
	// ReasonRevoked: the link was revoked.
	ReasonRevoked Reason = "revoked"
	// ReasonUnavailable: the registry could not be consulted. The link may well
	// be valid; the request should be retried, not the link replaced.
	ReasonUnavailable Reason = "unavailable"
)

// ResolveError is returned by Resolve for a token that names no working link.
type ResolveError struct {
	Reason Reason
	// Link is the link the token belongs to, when there is one: an expired or a
	// revoked link is still a known one, and the record of a refused request
	// can say whose it was.
	Link *Link
}

func (e *ResolveError) Error() string {
	switch e.Reason {
	case ReasonMalformed:
		return "the personal link is not valid: it is not spelled like one (was it cut short?)"
	case ReasonExpired:
		return "the personal link has expired"
	case ReasonRevoked:
		return "the personal link has been revoked"
	case ReasonUnavailable:
		return "personal links cannot be verified at the moment"
	default:
		return "the personal link is not valid"
	}
}

// Errors of the registry's management operations.
var (
	// ErrNoSuchLink: no link has that identifier.
	ErrNoSuchLink = errors.New("userlinks: no such link")
	// ErrTooManyLinks: the user already holds as many working links as allowed.
	ErrTooManyLinks = errors.New("userlinks: the user already has the maximum number of links")
	// ErrSessionEnded: the sign-in session a link is created in was ended by a
	// revocation of everything issued to its user — perhaps on another replica,
	// a moment ago.
	ErrSessionEnded = errors.New("userlinks: the sign-in session has ended")
)

// RegistryConfig configures a Registry.
type RegistryConfig struct {
	// Store holds the records. Required.
	Store Store
	// LinkTTL is how long a link works. Zero means DefaultLinkTTL; a negative
	// value means links do not expire.
	LinkTTL time.Duration
	// MaxLinksPerUser bounds how many working links one user may hold. Zero
	// means DefaultMaxLinksPerUser; a negative value means no bound.
	MaxLinksPerUser int
	// SyncInterval is how often the registry is refreshed from the store. Zero
	// means DefaultSyncInterval.
	SyncInterval time.Duration
	// SessionTTL is how long a sign-in session lasts. It only bounds how long a
	// Block has to be remembered.
	SessionTTL time.Duration
	// Node names this replica. It is the name of the object this replica records
	// link usage in, so it should be stable across restarts and distinct between
	// replicas. Replicas that share a name share the object: they merge what
	// each other wrote instead of erasing it, at the price of writing more often.
	Node string
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
	// Logger receives the registry's diagnostics. Nil means slog.Default.
	Logger *slog.Logger
}

// Registry knows every personal link. It is the answer to "whose is this
// token" on the path of every request that carries one, so that question is
// answered from memory; the Store behind it is read in the background.
type Registry struct {
	store  Store
	now    func() time.Time
	logger *slog.Logger

	linkTTL  time.Duration // 0 = links do not expire
	maxLinks int           // 0 = no bound
	interval time.Duration
	sessTTL  time.Duration
	node     string

	// syncMu serializes refreshes. It is never taken while mu is held.
	syncMu sync.Mutex
	// issueMu serializes the creation of links on this replica, so that the
	// per-user bound is checked and the link written as one step. It is held
	// across the store write, and never while mu is held.
	issueMu sync.Mutex

	// mu guards the in-memory registry. It is held to look something up or to
	// swap in what a refresh found — never across a call to the store.
	mu      sync.RWMutex
	byHash  map[string]*entry
	byID    map[string]*entry
	revoked map[string]*revocationEntry
	blocks  map[string]*blockEntry // by subject key
	// remoteUsage is what the other replicas have seen of each link, by node.
	remoteUsage map[string]remoteUsage
	// skipped remembers the version of each object that could not be used, so a
	// damaged record is reported once and not re-read on every refresh.
	skipped map[string]string
	// gen counts refreshes. Whatever is added to memory carries the current
	// generation, which is how a refresh tells "deleted from the store" from
	// "created while I was listing it".
	gen uint64
	// ownUsageRead reports that this replica knows what its own usage object in
	// the store says — it must, before it writes over it — and ownUsageVersion
	// is the version of the object it last read ("" when there was none).
	ownUsageRead    bool
	ownUsageVersion string
	synced          bool
	// lastSync and lastSyncErr describe the most recent refresh.
	lastSync    time.Time
	lastSyncErr error

	// usageMu guards this replica's own observations of link use.
	usageMu    sync.Mutex
	usage      map[string]Usage
	usageDirty bool

	// missMu guards the bookkeeping of tokens the registry does not know.
	missMu   sync.Mutex
	unknown  map[string]time.Time // token hash → when the answer may be asked again
	missLeft float64
	missAt   time.Time

	// leader reports whether this replica should delete records whose time is
	// up. Nil means it should.
	leader atomic.Pointer[func() bool]

	stats registryCounters
}

// entry is a link in memory. gen is the refresh generation during which this
// replica learned of it (see Sync).
type entry struct {
	link Link
	gen  uint64
}

type revocationEntry struct {
	rev Revocation
	gen uint64
}

// blockEntry is a block in memory. version is the version of the stored object
// it was read from, and empty for one this replica set itself and has not read
// back yet.
//
// fallback marks a watermark this replica made up because the stored record
// could not be used — unreadable at the moment, or damaged: "nothing issued
// before now counts", the reading that cannot let a revoked link through. A
// fallback refuses links like any block, but it is no knowledge of when the
// user's links really ended: it is replaced by the first real reading of the
// record, however much earlier that is, and it never decides that a link may
// be deleted from the store.
type blockEntry struct {
	block    Block
	version  string
	gen      uint64
	fallback bool
}

type remoteUsage struct {
	version   string
	updatedAt time.Time
	links     map[string]Usage
}

// registryCounters are the registry's cumulative counters.
type registryCounters struct {
	issued      atomic.Uint64
	revoked     atomic.Uint64
	blocked     atomic.Uint64
	syncs       atomic.Uint64
	syncErrors  atomic.Uint64
	storeErrors atomic.Uint64
	lookups     atomic.Uint64 // tokens looked up in the store because memory did not know them
	deleted     atomic.Uint64
	skipped     atomic.Uint64
}

// Limits on the bookkeeping of unknown tokens.
const (
	// maxUnknownTokens bounds how many unknown token hashes are remembered.
	maxUnknownTokens = 16384
	// missBurst and missPerSecond bound how often an unknown token may send the
	// registry to the store. A token nobody knows costs its sender one request
	// and must not cost the store one each, without limit.
	missBurst     = 64
	missPerSecond = 32
)

// NewRegistry opens the registry over cfg.Store and loads what the store holds.
// A store that cannot be read at this moment is not an error: the registry
// starts empty, refuses every link as unverifiable (ReasonUnavailable), and
// recovers with the first refresh that succeeds.
func NewRegistry(cfg RegistryConfig) (*Registry, error) {
	if cfg.Store == nil {
		return nil, errors.New("userlinks: the registry needs a store")
	}
	r := &Registry{
		store:       cfg.Store,
		now:         cfg.Now,
		logger:      cfg.Logger,
		linkTTL:     cfg.LinkTTL,
		maxLinks:    cfg.MaxLinksPerUser,
		interval:    cfg.SyncInterval,
		sessTTL:     cfg.SessionTTL,
		node:        nodeName(cfg.Node),
		byHash:      map[string]*entry{},
		byID:        map[string]*entry{},
		revoked:     map[string]*revocationEntry{},
		blocks:      map[string]*blockEntry{},
		remoteUsage: map[string]remoteUsage{},
		skipped:     map[string]string{},
		usage:       map[string]Usage{},
		unknown:     map[string]time.Time{},
		missLeft:    missBurst,
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.logger == nil {
		r.logger = slog.Default()
	}
	switch {
	case r.linkTTL == 0:
		r.linkTTL = DefaultLinkTTL
	case r.linkTTL < 0:
		r.linkTTL = 0
	}
	switch {
	case r.maxLinks == 0:
		r.maxLinks = DefaultMaxLinksPerUser
	case r.maxLinks < 0:
		r.maxLinks = 0
	}
	if r.interval <= 0 {
		r.interval = DefaultSyncInterval
	}
	r.missAt = r.now()

	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := r.Sync(ctx); err != nil {
		r.mu.RLock()
		synced := r.synced
		r.mu.RUnlock()
		if synced {
			r.logger.Warn("personal links: some records of the registry could not be read; "+
				"a link among them is answered as unavailable until it can be", "error", err)
		} else {
			r.logger.Warn("personal links: the registry could not be loaded; links are refused until it can be",
				"error", err)
		}
	}
	return r, nil
}

// LinkTTL returns how long a new link works; zero means it does not expire.
func (r *Registry) LinkTTL() time.Duration { return r.linkTTL }

// MaxLinksPerUser returns how many working links a user may hold; zero means
// there is no bound.
func (r *Registry) MaxLinksPerUser() int { return r.maxLinks }

// SyncInterval returns how often the registry is refreshed from the store.
func (r *Registry) SyncInterval() time.Duration { return r.interval }

// SetLeaderGate makes the deletion of records whose time is up conditional on
// fn: in a multi-replica deployment only the replica holding the lease cleans
// up. Deleting is idempotent, so this is thrift, not correctness.
func (r *Registry) SetLeaderGate(fn func() bool) {
	if fn == nil {
		r.leader.Store(nil)
		return
	}
	r.leader.Store(&fn)
}

// Run refreshes the registry from the store and writes down link usage until
// ctx ends, and then writes the usage one last time.
func (r *Registry) Run(ctx context.Context) {
	refresh := time.NewTicker(r.interval)
	defer refresh.Stop()
	flush := time.NewTicker(usageFlushInterval)
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			r.flushUsage(context.Background())
			return
		case <-refresh.C:
			sctx, cancel := context.WithTimeout(ctx, storeTimeout)
			if err := r.Sync(sctx); err != nil && ctx.Err() == nil {
				r.logger.Warn("personal links: refreshing the registry failed; continuing with what is known",
					"error", err)
			}
			cancel()
		case <-flush.C:
			r.flushUsage(ctx)
		}
	}
}

// --- resolving --------------------------------------------------------------

// Resolve returns the link a token names. Any error is a *ResolveError.
//
// It is called for every request that carries a token and answers from memory.
// Only a token this replica has never seen sends it to the store — once, and
// within a budget — because the link may have been created on another replica
// a moment ago.
func (r *Registry) Resolve(ctx context.Context, token string) (*Link, error) {
	if !WellFormed(token) {
		return nil, &ResolveError{Reason: ReasonMalformed}
	}
	hash := hashToken(token)

	r.mu.RLock()
	e := r.byHash[hash]
	synced := r.synced
	r.mu.RUnlock()

	if e == nil {
		if !synced {
			// Nothing is known because nothing could be read, not because there
			// is nothing: say so, rather than calling a valid link invalid.
			return nil, &ResolveError{Reason: ReasonUnavailable}
		}
		var err error
		if e, err = r.lookupUnknown(ctx, hash); err != nil {
			return nil, &ResolveError{Reason: ReasonUnavailable}
		}
		if e == nil {
			return nil, &ResolveError{Reason: ReasonUnknown}
		}
	}
	return r.usable(e)
}

// usable returns the link of e when it works, and the reason when it does not.
// The order is the order of what an operator would want to read: a link that
// was revoked is reported as revoked even after it has also expired.
func (r *Registry) usable(e *entry) (*Link, error) {
	// A copy, roles included: callers cannot change the registry's record.
	link := e.link
	link.Roles = append([]string(nil), link.Roles...)
	r.mu.RLock()
	_, revoked := r.revoked[link.ID]
	block := r.blocks[subjectKey(link.Subject)]
	r.mu.RUnlock()
	switch {
	case revoked, block != nil && !link.CreatedAt.After(block.block.NotBefore):
		return nil, &ResolveError{Reason: ReasonRevoked, Link: &link}
	case link.expired(r.now()):
		return nil, &ResolveError{Reason: ReasonExpired, Link: &link}
	}
	return &link, nil
}

// lookupUnknown asks the store about a token hash memory does not know. It
// returns (nil, nil) for a token that is unknown to the store as well — or that
// may not be asked about right now — and an error when the store could not
// answer.
func (r *Registry) lookupUnknown(ctx context.Context, hash string) (*entry, error) {
	now := r.now()
	r.missMu.Lock()
	if until, ok := r.unknown[hash]; ok && now.Before(until) {
		r.missMu.Unlock()
		return nil, nil
	}
	// Refill the budget for the time that has passed, then spend one.
	r.missLeft += now.Sub(r.missAt).Seconds() * missPerSecond
	if r.missLeft > missBurst {
		r.missLeft = missBurst
	}
	r.missAt = now
	if r.missLeft < 1 {
		r.missMu.Unlock()
		// Over budget: the store is not asked. That is not a "no" — the link
		// may have been created a moment ago on another replica, and is found by
		// the next refresh at the latest — so the answer is "ask again", never
		// "unknown", which a package manager takes as final.
		return nil, errLookupBudget
	}
	r.missLeft--
	r.missMu.Unlock()

	r.stats.lookups.Add(1)
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()

	data, err := r.store.Get(ctx, linkObject(hash))
	if errors.Is(err, ErrNotFound) {
		r.rememberUnknown(hash, now)
		return nil, nil
	}
	if err != nil {
		r.stats.storeErrors.Add(1)
		return nil, err
	}
	var link Link
	if err := json.Unmarshal(data, &link); err != nil || link.validate(hash) != nil {
		r.rememberUnknown(hash, now)
		return nil, nil
	}

	// A link found this way is one this replica has not synchronized yet, and
	// neither, then, has it seen what was said about the link since: whether it
	// was revoked, whether its user was blocked. Ask before trusting it.
	var rev *Revocation
	switch data, err := r.store.Get(ctx, revokedObject(link.ID)); {
	case err == nil:
		rev = &Revocation{ID: link.ID}
		_ = json.Unmarshal(data, rev)
		rev.ID = link.ID
	case !errors.Is(err, ErrNotFound):
		r.stats.storeErrors.Add(1)
		return nil, err
	}
	var block *Block
	blockFallback := false
	switch data, err := r.store.Get(ctx, blockObject(link.Subject)); {
	case err == nil:
		var b Block
		if json.Unmarshal(data, &b) != nil || b.NotBefore.IsZero() || b.Subject != link.Subject {
			// A block record that cannot be read is read as a refresh reads
			// one: everything issued to the user so far is revoked.
			b = Block{Subject: link.Subject, NotBefore: now.UTC(), Reason: "the block record could not be read"}
			blockFallback = true
		}
		block = &b
	case !errors.Is(err, ErrNotFound):
		r.stats.storeErrors.Add(1)
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.byHash[hash]
	if e == nil {
		e = &entry{link: link, gen: r.gen}
		r.byHash[hash] = e
		r.byID[link.ID] = e
	}
	if rev != nil {
		if rev.RevokedAt.IsZero() {
			rev.RevokedAt = now.UTC()
		}
		if _, known := r.revoked[link.ID]; !known {
			r.revoked[link.ID] = &revocationEntry{rev: *rev, gen: r.gen}
		}
	}
	if block != nil {
		key := subjectKey(link.Subject)
		if cur := r.blocks[key]; cur == nil || block.NotBefore.After(cur.block.NotBefore) {
			// The version is left empty, so the next refresh reads the object
			// again and records the version it has then.
			r.blocks[key] = &blockEntry{block: *block, gen: r.gen, fallback: blockFallback}
		}
	}
	return e, nil
}

// errLookupBudget is the answer of lookupUnknown when the store may not be
// asked about another unknown token right now.
var errLookupBudget = errors.New("userlinks: the budget for looking up unknown links is spent")

func (r *Registry) rememberUnknown(hash string, now time.Time) {
	r.missMu.Lock()
	defer r.missMu.Unlock()
	if len(r.unknown) >= maxUnknownTokens {
		// Forgetting everything is cheaper than choosing what to forget, and
		// costs at most one more store lookup per token (within the budget).
		r.unknown = map[string]time.Time{}
	}
	r.unknown[hash] = now.Add(r.interval)
}

// SessionValid reports whether a sign-in session of subject that started at
// issuedAt is still good: it is not when everything issued to the user up to a
// later moment has been revoked (see Block).
func (r *Registry) SessionValid(subject string, issuedAt time.Time) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	block := r.blocks[subjectKey(subject)]
	return block == nil || issuedAt.After(block.block.NotBefore)
}

// --- issuing and revoking ---------------------------------------------------

// IssueOptions describes a link to create.
type IssueOptions struct {
	// Label is the name the user gives the link.
	Label string
	// TTL is how long the link should work. Zero means the registry's LinkTTL;
	// a longer one is cut to it.
	TTL time.Duration
	// From is the client address the link is created from.
	From string
	// IssuedBy names the administrator creating the link for the user; empty
	// when the user creates it themselves.
	IssuedBy string
	// SessionIssuedAt is when the sign-in session the user creates the link in
	// began. When set, the store is asked whether everything issued to the
	// user was revoked since — on any replica, also one whose revocation has
	// not reached this replica yet — and the link is then not created.
	SessionIssuedAt time.Time
}

// Issue creates a link for id and returns its token. This is the only moment
// the token exists outside its owner's hands: the registry keeps its hash.
func (r *Registry) Issue(ctx context.Context, id Identity, opts IssueOptions) (string, Info, error) {
	id, err := id.normalize()
	if err != nil {
		return "", Info{}, err
	}
	// The bound is checked and the link written as one step: two requests at
	// once must not both find room for one more link. (Replicas do not share
	// this lock; across replicas the page's creation rate limit bounds what a
	// race can add.)
	r.issueMu.Lock()
	defer r.issueMu.Unlock()
	now := r.now()

	if !opts.SessionIssuedAt.IsZero() {
		if err := r.checkSession(ctx, id.Subject, opts.SessionIssuedAt, now); err != nil {
			return "", Info{}, err
		}
	}
	if r.maxLinks > 0 && r.activeLinks(id.Subject, now) >= r.maxLinks {
		return "", Info{}, ErrTooManyLinks
	}

	token, err := NewToken()
	if err != nil {
		return "", Info{}, err
	}
	hash := hashToken(token)
	link := Link{
		ID:          linkIDFromHash(hash),
		TokenHash:   hash,
		Identity:    id,
		Label:       cleanText(opts.Label, maxLabelLen),
		CreatedAt:   now.UTC(),
		CreatedFrom: cleanText(opts.From, maxAddrLen),
		IssuedBy:    cleanText(opts.IssuedBy, maxSubjectLen),
	}
	ttl := opts.TTL
	if ttl <= 0 || (r.linkTTL > 0 && ttl > r.linkTTL) {
		ttl = r.linkTTL
	}
	if ttl > 0 {
		link.ExpiresAt = now.Add(ttl).UTC()
	}

	data, err := json.Marshal(link)
	if err != nil {
		return "", Info{}, errorf("encoding the link: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	if err := r.store.Put(ctx, linkObject(hash), data); err != nil {
		r.stats.storeErrors.Add(1)
		return "", Info{}, err
	}

	r.mu.Lock()
	e := &entry{link: link, gen: r.gen}
	r.byHash[hash] = e
	r.byID[link.ID] = e
	r.mu.Unlock()
	r.missMu.Lock()
	delete(r.unknown, hash)
	r.missMu.Unlock()
	r.stats.issued.Add(1)
	return token, r.info(e, now), nil
}

// checkSession reads subject's block record from the store and reports
// ErrSessionEnded when it ends a session that began at issuedAt. Memory is not
// enough: the revocation may have been made on another replica since this one
// last refreshed, and a link created now would be dated after it — and work.
// What is read is remembered, as a refresh would.
func (r *Registry) checkSession(ctx context.Context, subject string, issuedAt, now time.Time) error {
	if !r.SessionValid(subject, issuedAt) {
		return ErrSessionEnded
	}
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	data, err := r.store.Get(ctx, blockObject(subject))
	switch {
	case errors.Is(err, ErrNotFound):
		return nil
	case err != nil:
		r.stats.storeErrors.Add(1)
		return err
	}
	var b Block
	fallback := false
	if json.Unmarshal(data, &b) != nil || b.NotBefore.IsZero() || b.Subject != subject {
		// Damaged: read as a refresh reads it.
		b, fallback = Block{Subject: subject, NotBefore: now.UTC(), Reason: "the block record could not be read"}, true
	}
	key := subjectKey(subject)
	r.mu.Lock()
	if cur := r.blocks[key]; cur == nil || b.NotBefore.After(cur.block.NotBefore) {
		r.blocks[key] = &blockEntry{block: b, gen: r.gen, fallback: fallback}
	}
	r.mu.Unlock()
	if !issuedAt.After(b.NotBefore) {
		return ErrSessionEnded
	}
	return nil
}

// activeLinks counts the working links of a subject.
func (r *Registry) activeLinks(subject string, now time.Time) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, e := range r.byID {
		if e.link.Subject == subject && r.stateLocked(e, now) == StateActive {
			n++
		}
	}
	return n
}

// Revoke revokes one link. by names who does it; reason is free text for the
// record. Revoking a link that is already revoked changes nothing and returns
// the existing record.
func (r *Registry) Revoke(ctx context.Context, id, by, reason string) (Info, error) {
	if !ValidLinkID(id) {
		return Info{}, ErrNoSuchLink
	}
	e := r.entryByID(id)
	if e == nil {
		// Created on another replica since the last refresh, perhaps.
		sctx, cancel := context.WithTimeout(ctx, storeTimeout)
		_ = r.Sync(sctx)
		cancel()
		if e = r.entryByID(id); e == nil {
			return Info{}, ErrNoSuchLink
		}
	}
	now := r.now()

	r.mu.RLock()
	_, already := r.revoked[id]
	r.mu.RUnlock()
	if already {
		return r.info(e, now), nil
	}

	rev := Revocation{
		ID:        id,
		Subject:   e.link.Subject,
		RevokedAt: now.UTC(),
		By:        cleanText(by, maxSubjectLen),
		Reason:    cleanText(reason, maxReasonLen),
	}
	data, err := json.Marshal(rev)
	if err != nil {
		return Info{}, errorf("encoding the revocation: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	if err := r.store.Put(ctx, revokedObject(id), data); err != nil {
		r.stats.storeErrors.Add(1)
		return Info{}, err
	}
	r.mu.Lock()
	if _, raced := r.revoked[id]; !raced {
		r.revoked[id] = &revocationEntry{rev: rev, gen: r.gen}
	}
	r.mu.Unlock()
	r.stats.revoked.Add(1)
	return r.info(e, now), nil
}

// RevokeUser invalidates everything issued to subject so far: every link, and
// every sign-in session. It returns how many working links that ended, and the
// moment up to which things are invalid.
//
// It does not need the links to be known here. A link of the user that another
// replica created a second ago, and that this one has not seen, ends with the
// others.
func (r *Registry) RevokeUser(ctx context.Context, subject, by, reason string) (int, time.Time, error) {
	subject = r.knownSubject(CanonicalSubject(subject))
	if subject == "" {
		return 0, time.Time{}, ErrBadSubject
	}
	now := r.now().UTC()
	affected := r.activeLinks(subject, now)
	key := subjectKey(subject)

	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()

	// The watermark only ever moves forward. Should another replica — its clock
	// ahead of this one — already have set a later one, that one stands; the
	// store is asked, because this replica may not have seen it yet. For the
	// same reason it is never earlier than the creation of any link of the user
	// this replica knows: a link created by a replica whose clock runs ahead —
	// or before this replica's clock was set back — carries a creation time
	// later than "now", and "everything issued so far" includes it.
	notBefore := now
	r.mu.RLock()
	if cur := r.blocks[key]; cur != nil && !cur.fallback && cur.block.NotBefore.After(notBefore) {
		notBefore = cur.block.NotBefore
	}
	for _, e := range r.byID {
		if e.link.Subject == subject && e.link.CreatedAt.After(notBefore) {
			notBefore = e.link.CreatedAt.UTC()
		}
	}
	r.mu.RUnlock()
	switch data, err := r.store.Get(ctx, blockObject(subject)); {
	case err == nil:
		var stored Block
		if json.Unmarshal(data, &stored) == nil && stored.Subject == subject && stored.NotBefore.After(notBefore) {
			notBefore = stored.NotBefore
		}
	case !errors.Is(err, ErrNotFound):
		r.stats.storeErrors.Add(1)
		return 0, time.Time{}, err
	}

	block := Block{
		Subject:   subject,
		NotBefore: notBefore,
		By:        cleanText(by, maxSubjectLen),
		Reason:    cleanText(reason, maxReasonLen),
	}
	data, err := json.Marshal(block)
	if err != nil {
		return 0, time.Time{}, errorf("encoding the block: %w", err)
	}
	if err := r.store.Put(ctx, blockObject(subject), data); err != nil {
		r.stats.storeErrors.Add(1)
		return 0, time.Time{}, err
	}
	r.mu.Lock()
	if cur := r.blocks[key]; cur == nil || cur.fallback || !cur.block.NotBefore.After(notBefore) {
		r.blocks[key] = &blockEntry{block: block, gen: r.gen}
	}
	r.mu.Unlock()
	r.stats.blocked.Add(1)
	return affected, notBefore, nil
}

// knownSubject returns the spelling under which the registry knows subject.
// Subjects are compared exactly — an identity provider's "sub" is
// case-sensitive — but an operator who types "Bob@example.com" for the user the
// registry knows as "bob@example.com" means that user: when no link is held
// under the subject as given, and the links of exactly one subject match it
// but for case, that subject is returned. Otherwise subject is returned as it
// is.
func (r *Registry) knownSubject(subject string) string {
	if subject == "" {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	match := ""
	for _, e := range r.byID {
		switch known := e.link.Subject; {
		case known == subject:
			return subject
		case strings.EqualFold(known, subject):
			if match != "" && match != known {
				return subject // ambiguous: only the exact spelling is meant
			}
			match = known
		}
	}
	if match != "" {
		return match
	}
	return subject
}

func (r *Registry) entryByID(id string) *entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}

// --- listing ----------------------------------------------------------------

// Filter selects links for List. The zero Filter selects all.
type Filter struct {
	// Subject selects one user's links, exactly.
	Subject string
	// State selects by state.
	State State
	// Search is a free-text filter over subject, name, e-mail, team, label and
	// identifier, ignoring case.
	Search string
}

// List returns the links f selects, newest first.
func (r *Registry) List(f Filter) []Info {
	now := r.now()
	search := strings.ToLower(strings.TrimSpace(f.Search))
	subject := CanonicalSubject(f.Subject)

	r.mu.RLock()
	entries := make([]*entry, 0, len(r.byID))
	for _, e := range r.byID {
		if subject != "" && e.link.Subject != subject {
			continue
		}
		entries = append(entries, e)
	}
	r.mu.RUnlock()

	out := make([]Info, 0, len(entries))
	for _, e := range entries {
		info := r.info(e, now)
		if f.State != "" && info.State != f.State {
			continue
		}
		if search != "" && !infoMatches(info, search) {
			continue
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get returns one link by its identifier.
func (r *Registry) Get(id string) (Info, bool) {
	e := r.entryByID(id)
	if e == nil {
		return Info{}, false
	}
	return r.info(e, r.now()), true
}

func infoMatches(info Info, lowerTerm string) bool {
	for _, field := range [...]string{info.Subject, info.Name, info.Email, info.Team, info.Label, info.ID, info.LastAddr} {
		if field != "" && strings.Contains(strings.ToLower(field), lowerTerm) {
			return true
		}
	}
	return false
}

// stateLocked returns e's state. The caller holds mu.
func (r *Registry) stateLocked(e *entry, now time.Time) State {
	if _, revoked := r.revoked[e.link.ID]; revoked {
		return StateRevoked
	}
	if block := r.blocks[subjectKey(e.link.Subject)]; block != nil && !e.link.CreatedAt.After(block.block.NotBefore) {
		return StateRevoked
	}
	if e.link.expired(now) {
		return StateExpired
	}
	return StateActive
}

// info renders e for the outside.
func (r *Registry) info(e *entry, now time.Time) Info {
	link := e.link
	info := Info{
		ID:          link.ID,
		Identity:    link.Identity,
		Label:       link.Label,
		CreatedAt:   link.CreatedAt,
		ExpiresAt:   timePtr(link.ExpiresAt),
		CreatedFrom: link.CreatedFrom,
		IssuedBy:    link.IssuedBy,
	}
	info.Roles = append([]string(nil), link.Roles...)

	r.mu.RLock()
	info.State = r.stateLocked(e, now)
	if rev := r.revoked[link.ID]; rev != nil {
		info.RevokedAt = timePtr(rev.rev.RevokedAt)
		info.RevokedBy = rev.rev.By
		info.RevokeReason = rev.rev.Reason
	} else if block := r.blocks[subjectKey(link.Subject)]; block != nil && !link.CreatedAt.After(block.block.NotBefore) {
		info.RevokedAt = timePtr(block.block.NotBefore)
		info.RevokedBy = block.block.By
		info.RevokeReason = block.block.Reason
		if info.RevokeReason == "" {
			info.RevokeReason = "all of the user's links were revoked"
		}
	}
	var used Usage
	for _, remote := range r.remoteUsage {
		used = used.merge(remote.links[link.ID])
	}
	r.mu.RUnlock()

	r.usageMu.Lock()
	used = used.merge(r.usage[link.ID])
	r.usageMu.Unlock()
	if !used.LastUsedAt.IsZero() {
		info.LastUsedAt = timePtr(used.LastUsedAt)
		info.LastAddr = used.LastAddr
		info.LastAgent = used.LastAgent
	}
	return info
}

// --- usage ------------------------------------------------------------------

// Touch notes that a link was just used, from which address and by which
// client tool. It is called for every request served through a link and only
// touches memory.
func (r *Registry) Touch(id, addr, agent string) {
	u := Usage{LastUsedAt: r.now().UTC(), LastAddr: cleanText(addr, maxAddrLen), LastAgent: cleanText(agent, maxAgentLen)}
	r.usageMu.Lock()
	r.usage[id] = u
	r.usageDirty = true
	r.usageMu.Unlock()
}

// flushUsage writes this replica's observations of link use to its usage
// object, when there is something new.
func (r *Registry) flushUsage(ctx context.Context) {
	now := r.now()
	// What the object said before this replica was restarted is merged in by the
	// first refresh that can read it. Until then, writing would erase it.
	r.mu.RLock()
	ready := r.ownUsageRead
	r.mu.RUnlock()
	if !ready {
		return
	}
	r.usageMu.Lock()
	if !r.usageDirty {
		r.usageMu.Unlock()
		return
	}
	// A link that is gone from the registry takes its usage with it.
	r.mu.RLock()
	for id := range r.usage {
		if _, known := r.byID[id]; !known {
			delete(r.usage, id)
		}
	}
	r.mu.RUnlock()
	file := usageFile{Node: r.node, UpdatedAt: now.UTC(), Links: make(map[string]Usage, len(r.usage))}
	for id, u := range r.usage {
		file.Links[id] = u
	}
	r.usageDirty = false
	r.usageMu.Unlock()

	data, err := json.Marshal(file)
	if err == nil {
		ctx, cancel := context.WithTimeout(ctx, storeTimeout)
		err = r.store.Put(ctx, usageObject(r.node), data)
		cancel()
	}
	if err != nil {
		r.stats.storeErrors.Add(1)
		r.usageMu.Lock()
		r.usageDirty = true // try again with the next flush
		r.usageMu.Unlock()
		r.logger.Debug("personal links: writing link usage failed", "error", err)
	}
}

// Close writes down what is still only in memory. It does not close the store.
func (r *Registry) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	r.flushUsage(ctx)
}

// --- statistics -------------------------------------------------------------

// Stats is a snapshot of the registry for metrics and the console.
type Stats struct {
	// Active, Expired and Revoked count the links the registry holds, by state;
	// Users counts the distinct users with a working link.
	Active  int `json:"active"`
	Expired int `json:"expired"`
	Revoked int `json:"revoked"`
	Users   int `json:"users"`

	// Issued, RevokedTotal and UserRevocations count what this replica did since
	// it started.
	Issued          uint64 `json:"issued"`
	RevokedTotal    uint64 `json:"revokedTotal"`
	UserRevocations uint64 `json:"userRevocations"`
	// Syncs and SyncErrors count refreshes from the store; StoreErrors every
	// failed store operation; StoreLookups the tokens looked up in the store
	// because memory did not know them; Deleted the records removed after their
	// time was up; Skipped the stored records that could not be used.
	Syncs        uint64 `json:"syncs"`
	SyncErrors   uint64 `json:"syncErrors"`
	StoreErrors  uint64 `json:"storeErrors"`
	StoreLookups uint64 `json:"storeLookups"`
	Deleted      uint64 `json:"deleted"`
	Skipped      uint64 `json:"skipped"`

	// Synced reports that the registry has been read from the store at least
	// once; until then every link is refused as unverifiable. LastSync is when
	// it was last read successfully, LastSyncError what the latest attempt
	// failed with.
	Synced        bool       `json:"synced"`
	LastSync      *time.Time `json:"lastSync,omitempty"`
	LastSyncError string     `json:"lastSyncError,omitempty"`
}

// Stats returns a snapshot of the registry.
func (r *Registry) Stats() Stats {
	now := r.now()
	st := Stats{
		Issued:          r.stats.issued.Load(),
		RevokedTotal:    r.stats.revoked.Load(),
		UserRevocations: r.stats.blocked.Load(),
		Syncs:           r.stats.syncs.Load(),
		SyncErrors:      r.stats.syncErrors.Load(),
		StoreErrors:     r.stats.storeErrors.Load(),
		StoreLookups:    r.stats.lookups.Load(),
		Deleted:         r.stats.deleted.Load(),
		Skipped:         r.stats.skipped.Load(),
	}
	users := map[string]struct{}{}
	r.mu.RLock()
	for _, e := range r.byID {
		switch r.stateLocked(e, now) {
		case StateActive:
			st.Active++
			users[e.link.Subject] = struct{}{}
		case StateExpired:
			st.Expired++
		default:
			st.Revoked++
		}
	}
	st.Synced = r.synced
	st.LastSync = timePtr(r.lastSync)
	if r.lastSyncErr != nil {
		st.LastSyncError = r.lastSyncErr.Error()
	}
	r.mu.RUnlock()
	st.Users = len(users)
	return st
}
