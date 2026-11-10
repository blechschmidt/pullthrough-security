package ratelimit

import (
	"errors"
	"time"
)

// errReservedKey is returned by SetPolicy when the reserved global key is used
// as a tenant name.
var errReservedKey = errors.New("ratelimit: " + GlobalKey + " is reserved; use SetGlobalPolicy")

// Snapshot is a point-in-time view of the limiter's enforcement state, used for
// the Prometheus bridge and the admin API.
type Snapshot struct {
	// Allowed and Throttled are process-wide cumulative counters.
	Allowed   int64 `json:"allowed"`
	Throttled int64 `json:"throttled"`
	// ThrottledByReason breaks throttled down by limit type (rps|concurrency|bytes).
	ThrottledByReason map[string]int64 `json:"throttledByReason"`
	// Global is the snapshot of the process-wide policy/state.
	Global TenantSnapshot `json:"global"`
	// Tenants holds one row per tenant the limiter has observed, sorted by name.
	Tenants []TenantSnapshot `json:"tenants"`
}

// TenantSnapshot is the per-tenant (or global) enforcement view.
type TenantSnapshot struct {
	Tenant    string `json:"tenant"`
	Policy    Policy `json:"policy"`
	Allowed   int64  `json:"allowed"`
	Throttled int64  `json:"throttled"`
	// InFlight is the number of concurrency slots currently held.
	InFlight int `json:"inFlight"`
	// BytesUsed is the bytes consumed in the current quota window.
	BytesUsed int64 `json:"bytesUsed"`
	// WindowEnds is when the current byte-quota window resets (zero when unknown
	// or no byte quota applies).
	WindowEnds time.Time `json:"windowEnds,omitempty"`
}
