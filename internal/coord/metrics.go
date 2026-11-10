package coord

import (
	"sync/atomic"
	"time"
)

// jobStats holds the cumulative per-job counters surfaced as Prometheus metrics.
// All fields are updated from the single campaign goroutine for that job and read
// concurrently at scrape time, so they are atomics.
type jobStats struct {
	acquisitions     atomic.Int64
	renewals         atomic.Int64
	losses           atomic.Int64
	acquireContended atomic.Int64
	errors           atomic.Int64
}

// JobStatus is a point-in-time view of one coordinated job's leadership state and
// counters, consumed by the metrics bridge and the admin endpoint.
type JobStatus struct {
	Job                 string    `json:"job"`
	IsLeader            bool      `json:"isLeader"`
	FencingToken        uint64    `json:"fencingToken"`
	AcquiredAt          time.Time `json:"acquiredAt,omitempty"`
	ExpiresAt           time.Time `json:"expiresAt,omitempty"`
	Acquisitions        int64     `json:"acquisitions"`
	Renewals            int64     `json:"renewals"`
	Losses              int64     `json:"losses"`
	AcquireContended    int64     `json:"acquireContended"`
	Errors              int64     `json:"errors"`
	TimeAsLeaderSeconds float64   `json:"timeAsLeaderSeconds"`
}

// Snapshot is the whole coordination subsystem's local state, for the metrics
// bridge and the admin overview. It performs no I/O.
type Snapshot struct {
	Enabled bool        `json:"enabled"`
	Mode    string      `json:"mode"`
	NodeID  string      `json:"nodeId"`
	Jobs    []JobStatus `json:"jobs"`
}

// Leaseholder is the observed owner of a named lease as read from the
// coordination backend — the cross-replica view powering the admin "who is the
// leader" endpoint, which a follower can answer for the whole cluster.
type Leaseholder struct {
	Job          string    `json:"job"`
	Held         bool      `json:"held"`
	Holder       string    `json:"holder,omitempty"`
	FencingToken uint64    `json:"fencingToken,omitempty"`
	AcquiredAt   time.Time `json:"acquiredAt,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt,omitempty"`
	Expired      bool      `json:"expired"`
	Self         bool      `json:"self"`
}
