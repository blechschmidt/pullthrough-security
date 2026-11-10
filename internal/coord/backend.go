package coord

import (
	"context"
	"errors"
	"time"
)

// ErrConflict is returned by a backend's conditional (compare-and-swap)
// operations when the precondition fails: another writer created or modified the
// lease record concurrently. The coordinator treats it as "lost the race" — a
// normal, expected outcome of contention — rather than a hard error.
var ErrConflict = errors.New("coord: lease record changed concurrently")

// record is the serialized lease state every backend persists. It is the single
// source of truth for who holds a named lease and until when. FencingToken is a
// monotonically increasing counter, incremented on every successful acquisition
// (including a steal of an expired lease), so a delayed former leader always
// carries a strictly lower token than the current one and can be fenced off by
// any resource that records the highest token it has seen.
type record struct {
	Name         string    `json:"name"`
	Holder       string    `json:"holder"`
	FencingToken uint64    `json:"fencingToken"`
	AcquiredAt   time.Time `json:"acquiredAt"`
	RenewedAt    time.Time `json:"renewedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// backend is the storage primitive the coordinator builds lease semantics on top
// of: a conditional, compare-and-swap key/value store keyed by lease name. The
// opaque version string is a backend-specific CAS token (an object-store ETag, an
// in-memory generation counter, a file content hash) that the coordinator
// round-trips without interpreting.
//
// Implementations must be safe for concurrent use.
type backend interface {
	// load returns the current record and its version. found is false when no
	// record exists yet (version is then "").
	load(ctx context.Context, name string) (rec record, version string, found bool, err error)
	// create stores rec only if no record currently exists for name, returning the
	// new version. It returns ErrConflict if a record already exists.
	create(ctx context.Context, name string, rec record) (version string, err error)
	// update replaces the record only if the stored version still equals
	// expectedVersion, returning the new version. It returns ErrConflict otherwise.
	update(ctx context.Context, name, expectedVersion string, rec record) (version string, err error)
	// remove deletes the record only if the stored version still equals
	// expectedVersion. A missing record is not an error. It returns ErrConflict if
	// the record exists with a different version.
	remove(ctx context.Context, name, expectedVersion string) error
	// close releases backend resources.
	close() error
}
