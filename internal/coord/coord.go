// Package coord provides a lease-based distributed lock / leader-election
// primitive for HA proxy deployments (Task 56). With the shared S3 cache backend
// enabling horizontal scaling, multiple replicas would otherwise each run the
// same scheduled background jobs — CVE-drift re-scan, the backup scheduler, the
// malfeed feed refresh, audit Merkle checkpoint signing — duplicating work,
// racing on quarantine state, and emitting N× notifications.
//
// The package exposes a small Coordinator interface (AcquireLease, RenewLease,
// Resign, IsLeader) over a pluggable compare-and-swap backend: an in-memory store
// (single-node default), an S3 object-store store reusing the cache's SigV4
// client, and a file-lease store for shared volumes. A higher-level Service wraps
// the Coordinator with a per-job campaign loop (Guard) that continuously acquires
// and renews a named lease so a scheduler can gate its work on holding it, and
// gracefully steps down when the lease is lost.
//
// Correctness rests on two ideas: a lease has a TTL and is renewed by a heartbeat
// well within that TTL, so a crashed leader's lease expires and is taken over;
// and every acquisition carries a monotonically increasing fencing token, so a
// process that pauses (GC, scheduling) past its lease expiry and resumes
// believing it is still leader will carry a stale, lower token than the node that
// took over — letting downstream resources reject its writes and avoid
// split-brain.
package coord

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrLeaseHeld reports that a live lease for the name is currently held by a
	// different node, so it could not be acquired.
	ErrLeaseHeld = errors.New("coord: lease currently held by another node")
	// ErrLeaseLost reports that a renewal failed because this node no longer holds
	// the lease (it expired and was taken over, or was administratively cleared).
	ErrLeaseLost = errors.New("coord: lease no longer held by this node")
	// ErrInvalidTTL reports a non-positive lease TTL.
	ErrInvalidTTL = errors.New("coord: lease ttl must be positive")
)

// Lease is a held, time-bounded grant of a named lease to this node. It is opaque
// to callers except for the fields below; RenewLease and Resign take it back to
// identify the grant being operated on. FencingToken strictly increases across
// acquisitions of the same lease and can be threaded into downstream writes to
// fence off a stale former leader.
type Lease struct {
	Name         string    `json:"name"`
	Holder       string    `json:"holder"`
	FencingToken uint64    `json:"fencingToken"`
	AcquiredAt   time.Time `json:"acquiredAt"`
	ExpiresAt    time.Time `json:"expiresAt"`

	// version is the backend CAS token captured at acquisition/renewal, used to
	// drive the next conditional renew or resign. It is unexported so it never
	// leaks into JSON or the public surface.
	version string
}

// expired reports whether the lease is at or past its expiry as of now.
func (l *Lease) expired(now time.Time) bool { return !now.Before(l.ExpiresAt) }

// Coordinator is the lease-based distributed-lock primitive. Implementations are
// safe for concurrent use.
type Coordinator interface {
	// AcquireLease attempts to acquire (or, when this node already holds it, renew)
	// the named lease for ttl. It returns the held Lease on success, ErrLeaseHeld
	// when another node holds a live lease, or a backend error.
	AcquireLease(ctx context.Context, name string, ttl time.Duration) (*Lease, error)
	// RenewLease extends a held lease for a further ttl, returning the refreshed
	// Lease. It returns ErrLeaseLost when this node no longer holds it.
	RenewLease(ctx context.Context, lease *Lease, ttl time.Duration) (*Lease, error)
	// Resign voluntarily releases a held lease so another node can take over
	// immediately rather than waiting for expiry. It is idempotent and tolerant of
	// a lease already taken over by another node.
	Resign(ctx context.Context, lease *Lease) error
	// IsLeader reports whether this node currently holds a live (unexpired) lease
	// for name, from its local view (no I/O).
	IsLeader(name string) bool
}

// coordinator is the backend-agnostic implementation of Coordinator. All lease
// lifecycle and fencing logic lives here; backends only supply the CAS store.
type coordinator struct {
	backend backend
	nodeID  string
	now     func() time.Time

	mu   sync.Mutex
	held map[string]*Lease // name -> lease this node currently holds
}

var _ Coordinator = (*coordinator)(nil)

// newCoordinator constructs a coordinator over the given backend.
func newCoordinator(b backend, nodeID string, now func() time.Time) *coordinator {
	if now == nil {
		now = time.Now
	}
	return &coordinator{
		backend: b,
		nodeID:  nodeID,
		now:     now,
		held:    make(map[string]*Lease),
	}
}

func (c *coordinator) AcquireLease(ctx context.Context, name string, ttl time.Duration) (*Lease, error) {
	if ttl <= 0 {
		return nil, ErrInvalidTTL
	}
	now := c.now()
	rec, version, found, err := c.backend.load(ctx, name)
	if err != nil {
		return nil, err
	}

	switch {
	case !found:
		// No current holder: create a fresh lease at fencing token 1.
		nr := record{
			Name:         name,
			Holder:       c.nodeID,
			FencingToken: 1,
			AcquiredAt:   now,
			RenewedAt:    now,
			ExpiresAt:    now.Add(ttl),
		}
		nv, err := c.backend.create(ctx, name, nr)
		if err != nil {
			if errors.Is(err, ErrConflict) {
				return nil, ErrLeaseHeld
			}
			return nil, err
		}
		return c.remember(nr, nv), nil

	case rec.Holder == c.nodeID:
		// We already own the record (live or just-expired-but-untaken): renew it in
		// place, preserving the fencing token.
		nr := rec
		nr.RenewedAt = now
		nr.ExpiresAt = now.Add(ttl)
		nv, err := c.backend.update(ctx, name, version, nr)
		if err != nil {
			if errors.Is(err, ErrConflict) {
				c.forget(name)
				return nil, ErrLeaseHeld
			}
			return nil, err
		}
		return c.remember(nr, nv), nil

	case now.Before(rec.ExpiresAt):
		// A different node holds a live lease.
		return nil, ErrLeaseHeld

	default:
		// The lease has expired and is held by another (or former) node: steal it,
		// incrementing the fencing token so the previous holder is fenced off.
		nr := record{
			Name:         name,
			Holder:       c.nodeID,
			FencingToken: rec.FencingToken + 1,
			AcquiredAt:   now,
			RenewedAt:    now,
			ExpiresAt:    now.Add(ttl),
		}
		nv, err := c.backend.update(ctx, name, version, nr)
		if err != nil {
			if errors.Is(err, ErrConflict) {
				return nil, ErrLeaseHeld
			}
			return nil, err
		}
		return c.remember(nr, nv), nil
	}
}

func (c *coordinator) RenewLease(ctx context.Context, lease *Lease, ttl time.Duration) (*Lease, error) {
	if lease == nil {
		return nil, ErrLeaseLost
	}
	if ttl <= 0 {
		return nil, ErrInvalidTTL
	}
	now := c.now()
	rec, version, found, err := c.backend.load(ctx, lease.Name)
	if err != nil {
		return nil, err
	}
	// The lease is ours only if the record still names us with the same fencing
	// token. A higher token means another node stole it after our expiry.
	if !found || rec.Holder != c.nodeID || rec.FencingToken != lease.FencingToken {
		c.forget(lease.Name)
		return nil, ErrLeaseLost
	}
	nr := rec
	nr.RenewedAt = now
	nr.ExpiresAt = now.Add(ttl)
	nv, err := c.backend.update(ctx, lease.Name, version, nr)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			// Someone changed the record between our load and update: we have lost it.
			c.forget(lease.Name)
			return nil, ErrLeaseLost
		}
		return nil, err
	}
	return c.remember(nr, nv), nil
}

func (c *coordinator) Resign(ctx context.Context, lease *Lease) error {
	if lease == nil {
		return nil
	}
	c.forget(lease.Name)
	rec, version, found, err := c.backend.load(ctx, lease.Name)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if rec.Holder != c.nodeID || rec.FencingToken != lease.FencingToken {
		// Already taken over by another node; nothing of ours to release.
		return nil
	}
	// Release by expiring the record in place rather than deleting it, preserving
	// the fencing token so the next holder's token strictly increases. Deleting
	// would reset the counter to 1 and break fencing monotonicity across a clean
	// handoff. The next acquirer sees an expired lease and steals it at token+1.
	now := c.now()
	rec.RenewedAt = now
	rec.ExpiresAt = now
	if _, err := c.backend.update(ctx, lease.Name, version, rec); err != nil {
		if errors.Is(err, ErrConflict) {
			// Lost a race with a concurrent takeover; that node now owns it.
			return nil
		}
		return err
	}
	return nil
}

func (c *coordinator) IsLeader(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	l := c.held[name]
	return l != nil && !l.expired(c.now())
}

// remember records a freshly (re)acquired lease in the local held map and returns
// a copy for the caller. The version is retained for the next conditional write.
func (c *coordinator) remember(rec record, version string) *Lease {
	l := &Lease{
		Name:         rec.Name,
		Holder:       rec.Holder,
		FencingToken: rec.FencingToken,
		AcquiredAt:   rec.AcquiredAt,
		ExpiresAt:    rec.ExpiresAt,
		version:      version,
	}
	c.mu.Lock()
	c.held[rec.Name] = l
	c.mu.Unlock()
	cp := *l
	return &cp
}

// forget drops the local belief that we hold the named lease.
func (c *coordinator) forget(name string) {
	c.mu.Lock()
	delete(c.held, name)
	c.mu.Unlock()
}
