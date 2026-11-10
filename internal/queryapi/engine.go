package queryapi

import (
	"strings"
	"sync"
	"time"
)

// Default bounds for the engine. They cap result size and the amount of work a
// single query can do, so a hostile or careless query cannot exhaust the proxy.
const (
	DefaultLimit    = 100
	DefaultMaxLimit = 500
	DefaultMaxScan  = 50000
)

// Config tunes the query engine's result bounds and clock.
type Config struct {
	// DefaultLimit is the page size applied when a query omits "limit" (or sets
	// it to 0). Clamped to MaxLimit.
	DefaultLimit int
	// MaxLimit is the largest page a query may request.
	MaxLimit int
	// MaxScan bounds the number of model records a query may consider. Beyond it
	// the result is marked truncated.
	MaxScan int
	// Now overrides the clock for deterministic age computation in tests.
	Now func() time.Time
}

// Engine is the read-only federated query engine. It is safe for concurrent use.
type Engine struct {
	providers    Providers
	defaultLimit int
	maxLimit     int
	maxScan      int
	now          func() time.Time

	mu      sync.Mutex
	metrics MetricsSnapshot
}

// New constructs an Engine over the given providers. Unset Config fields fall
// back to the package defaults.
func New(cfg Config, providers Providers) *Engine {
	e := &Engine{
		providers:    providers,
		defaultLimit: cfg.DefaultLimit,
		maxLimit:     cfg.MaxLimit,
		maxScan:      cfg.MaxScan,
		now:          cfg.Now,
	}
	if e.defaultLimit <= 0 {
		e.defaultLimit = DefaultLimit
	}
	if e.maxLimit <= 0 {
		e.maxLimit = DefaultMaxLimit
	}
	if e.defaultLimit > e.maxLimit {
		e.defaultLimit = e.maxLimit
	}
	if e.maxScan <= 0 {
		e.maxScan = DefaultMaxScan
	}
	if e.now == nil {
		e.now = time.Now
	}
	return e
}

// Enabled reports whether the engine is usable. The endpoint is always usable
// once constructed (it degrades to an empty model when no provider is wired).
func (e *Engine) Enabled() bool { return e != nil }

// Schema returns the stable, self-describing query schema.
func (e *Engine) Schema() Schema { return e.schema() }

// Result is the response to a query: the projected rows plus the bookkeeping a
// caller needs for pagination and cost transparency.
type Result struct {
	Rows        []map[string]any `json:"rows"`
	Fields      []string         `json:"fields"`
	Total       int              `json:"total"`    // records matching the filter (pre-pagination)
	Returned    int              `json:"returned"` // rows in this page
	Offset      int              `json:"offset"`
	Limit       int              `json:"limit"`
	Truncated   bool             `json:"truncated"` // more matched than returned, or the scan hit MaxScan
	Scanned     int              `json:"scanned"`   // records considered
	Cost        int              `json:"cost"`      // query cost units (see CostUnits)
	GeneratedAt time.Time        `json:"generatedAt"`
}

// MetricsSnapshot is the engine's cumulative telemetry, surfaced to Prometheus
// via the metrics bridge. Average cost is derivable as CostUnitsTotal/QueriesTotal.
type MetricsSnapshot struct {
	QueriesTotal      int64 `json:"queriesTotal"`
	RejectedTotal     int64 `json:"rejectedTotal"`
	CostUnitsTotal    int64 `json:"costUnitsTotal"`
	RowsScannedTotal  int64 `json:"rowsScannedTotal"`
	RowsReturnedTotal int64 `json:"rowsReturnedTotal"`
	TruncatedTotal    int64 `json:"truncatedTotal"`
	MaxCost           int64 `json:"maxCost"`
	LastCost          int64 `json:"lastCost"`
}

// Snapshot returns a copy of the engine's cumulative telemetry.
func (e *Engine) Snapshot() MetricsSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.metrics
}

// Query validates, executes, and paginates a federated query, returning the
// projected page plus cost/pagination bookkeeping. A validation failure returns
// a *QueryError (the caller maps it to HTTP 400) and is counted as rejected.
func (e *Engine) Query(q Query) (Result, error) {
	sel, predicates, err := q.validate(e)
	if err != nil {
		e.recordRejected()
		return Result{}, err
	}

	limit := q.Limit
	if limit <= 0 {
		limit = e.defaultLimit
	}
	if limit > e.maxLimit {
		limit = e.maxLimit
	}
	offset := q.Offset

	now := e.now()
	model := e.providers.build(now)

	// Apply the implicit tenant shorthand as an outer AND with the explicit
	// filter, so callers can scope without composing a predicate.
	where := q.Where
	if t := strings.TrimSpace(q.Tenant); t != "" {
		tenantPred := Filter{Field: "tenant", Op: "eq", Value: t}
		if where == nil {
			where = &tenantPred
		} else {
			where = &Filter{And: []Filter{tenantPred, *where}}
		}
	}

	scanned := 0
	scanTruncated := false
	matched := make([]*Record, 0, len(model))
	for _, r := range model {
		if scanned >= e.maxScan {
			scanTruncated = true
			break
		}
		scanned++
		if where == nil || where.eval(r) {
			matched = append(matched, r)
		}
	}

	total := len(matched)
	orderRecords(matched, q.OrderBy)

	// Pagination window.
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	page := matched[start:end]

	rows := make([]map[string]any, 0, len(page))
	for _, r := range page {
		rows = append(rows, project(r, sel))
	}

	res := Result{
		Rows:        rows,
		Fields:      sel,
		Total:       total,
		Returned:    len(rows),
		Offset:      offset,
		Limit:       limit,
		Truncated:   scanTruncated || end < total,
		Scanned:     scanned,
		GeneratedAt: now,
	}
	res.Cost = costUnits(scanned, predicates, len(rows), len(sel))
	e.recordQuery(res)
	return res, nil
}

// costUnits is the deterministic query-cost model exposed to operators and
// Prometheus: the records scanned, plus the predicate work over them, plus the
// projection work (cells emitted). It approximates the engine effort a query
// costs so operators can spot and budget expensive queries.
func costUnits(scanned, predicates, returned, fields int) int {
	return scanned + scanned*predicates + returned*fields
}

func (e *Engine) recordQuery(res Result) {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := &e.metrics
	m.QueriesTotal++
	m.CostUnitsTotal += int64(res.Cost)
	m.RowsScannedTotal += int64(res.Scanned)
	m.RowsReturnedTotal += int64(res.Returned)
	if res.Truncated {
		m.TruncatedTotal++
	}
	m.LastCost = int64(res.Cost)
	if int64(res.Cost) > m.MaxCost {
		m.MaxCost = int64(res.Cost)
	}
}

func (e *Engine) recordRejected() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.metrics.RejectedTotal++
}
