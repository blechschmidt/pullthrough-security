package metering

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TenantSnapshot is a tenant's cumulative-since-start usage.
type TenantSnapshot struct {
	Tenant string `json:"tenant"`
	Counters
}

// Snapshot is the current live read-model: cumulative per-tenant usage plus the
// subsystem's configuration and rollup metadata. It backs the admin status
// endpoint and Prometheus binding.
type Snapshot struct {
	GeneratedAt       time.Time        `json:"generatedAt"`
	Enabled           bool             `json:"enabled"`
	RollupIntervalSec float64          `json:"rollupIntervalSec"`
	RetentionHours    int              `json:"retentionHours"`
	Rollups           int              `json:"rollups"`
	BudgetAlerts      uint64           `json:"budgetAlerts"`
	Tenants           []TenantSnapshot `json:"tenants"`
	Grand             Counters         `json:"grand"`
}

// Snapshot returns the current cumulative per-tenant usage. A nil/disabled meter
// returns an empty, disabled snapshot.
func (m *Meter) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := Snapshot{
		GeneratedAt:       m.now().UTC(),
		Enabled:           m.enabled,
		RollupIntervalSec: m.rollupInterval.Seconds(),
		RetentionHours:    m.retentionHours,
		Rollups:           len(m.history),
		BudgetAlerts:      m.budgetAlerts.Load(),
	}
	for _, t := range sortedTenants(m.live) {
		c := m.live[t].clone()
		snap.Tenants = append(snap.Tenants, TenantSnapshot{Tenant: t, Counters: c})
		snap.Grand.add(c)
	}
	return snap
}

// TenantTotals is the flat cumulative usage for one tenant, used by the
// federated query layer to stamp coordinate rows.
type TenantTotals struct {
	Tenant          string `json:"tenant"`
	Requests        int64  `json:"requests"`
	BytesServed     int64  `json:"bytesServed"`
	StorageBytes    int64  `json:"storageBytes"`
	ScanInvocations int64  `json:"scanInvocations"`
	ScanCostMicros  int64  `json:"scanCostMicros"`
	Blocked         int64  `json:"blocked"`
	Quarantined     int64  `json:"quarantined"`
}

// TenantUsage returns a tenant's cumulative totals. The bool is false when the
// tenant has no recorded usage. An empty tenant resolves to the unscoped bucket.
func (m *Meter) TenantUsage(tenant string) (TenantTotals, bool) {
	if m == nil || !m.enabled {
		return TenantTotals{}, false
	}
	t := normalizeTenant(tenant)
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.live[t]
	if c == nil {
		return TenantTotals{}, false
	}
	return TenantTotals{
		Tenant:          t,
		Requests:        c.Requests,
		BytesServed:     c.BytesServed(),
		StorageBytes:    c.StorageBytes,
		ScanInvocations: c.ScanInvocations,
		ScanCostMicros:  c.ScanCostMicros,
		Blocked:         c.Blocked,
		Quarantined:     c.Quarantined,
	}, true
}

// Tenants returns the tenants with recorded usage, sorted.
func (m *Meter) Tenants() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return sortedTenants(m.live)
}

// ReportRequest selects the slice of usage a chargeback report covers.
type ReportRequest struct {
	// Tenant restricts the report to one tenant; empty covers all tenants.
	Tenant string
	// Start/End bound the period (inclusive of overlapping rollups). A zero Start
	// means "from the earliest retained rollup"; a zero End means "now".
	Start time.Time
	End   time.Time
	// Granularity buckets rows: "hour", "day", or "total" (default "day").
	Granularity string
}

// ReportRow is one (tenant, period) aggregation in a chargeback report.
type ReportRow struct {
	Tenant      string    `json:"tenant"`
	PeriodStart time.Time `json:"periodStart"`
	PeriodEnd   time.Time `json:"periodEnd"`
	Counters
}

// UsageReport is a time-ranged, tenant-scoped chargeback report.
type UsageReport struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	Tenant      string           `json:"tenant,omitempty"`
	Start       time.Time        `json:"start"`
	End         time.Time        `json:"end"`
	Granularity string           `json:"granularity"`
	Rows        []ReportRow      `json:"rows"`
	Totals      []TenantSnapshot `json:"totals"` // per-tenant total over the range
	Grand       Counters         `json:"grand"`
}

// Report assembles a chargeback report over the retained rollups (plus the
// pending, not-yet-rolled-up delta) for the requested tenant and time range.
func (m *Meter) Report(req ReportRequest) UsageReport {
	now := time.Now().UTC()
	if m != nil {
		now = m.now().UTC()
	}
	gran := normalizeGranularity(req.Granularity)
	end := req.End.UTC()
	if end.IsZero() || end.After(now) {
		end = now
	}
	start := req.Start.UTC()

	rep := UsageReport{
		GeneratedAt: now,
		Tenant:      strings.TrimSpace(req.Tenant),
		Start:       start,
		End:         end,
		Granularity: gran,
		Rows:        []ReportRow{},
		Totals:      []TenantSnapshot{},
	}
	if m == nil || !m.enabled {
		return rep
	}

	tenantFilter := normalizeTenantFilter(req.Tenant)

	m.mu.Lock()
	rollups := make([]Rollup, 0, len(m.history)+len(m.live))
	rollups = append(rollups, m.history...)
	rollups = append(rollups, m.pendingLocked(now)...)
	m.mu.Unlock()

	// Aggregate into (tenant, period-bucket) cells and per-tenant totals.
	type cellKey struct {
		tenant string
		bucket int64
	}
	cells := map[cellKey]*Counters{}
	totals := map[string]*Counters{}
	var earliest time.Time

	for i := range rollups {
		ru := &rollups[i]
		if tenantFilter != "" && ru.Tenant != tenantFilter {
			continue
		}
		if !start.IsZero() && ru.End.Before(start) {
			continue
		}
		// Skip only rollups that begin strictly after the range end. Using a
		// strict comparison keeps the synthetic pending rollup (whose Start can
		// equal the report end when the clock has not advanced since the last
		// rollup) inside the range rather than dropping current usage.
		if ru.Start.After(end) {
			continue
		}
		if earliest.IsZero() || ru.Start.Before(earliest) {
			earliest = ru.Start
		}
		bucket := truncatePeriod(ru.Start, gran)
		ck := cellKey{tenant: ru.Tenant, bucket: bucket.UnixNano()}
		c := cells[ck]
		if c == nil {
			c = &Counters{}
			cells[ck] = c
		}
		c.add(ru.Counters)
		tt := totals[ru.Tenant]
		if tt == nil {
			tt = &Counters{}
			totals[ru.Tenant] = tt
		}
		tt.add(ru.Counters)
	}

	if start.IsZero() {
		rep.Start = earliest
	}

	// Emit rows sorted by (tenant, period).
	keys := make([]cellKey, 0, len(cells))
	for k := range cells {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].tenant != keys[j].tenant {
			return keys[i].tenant < keys[j].tenant
		}
		return keys[i].bucket < keys[j].bucket
	})
	for _, k := range keys {
		ps := time.Unix(0, k.bucket).UTC()
		rep.Rows = append(rep.Rows, ReportRow{
			Tenant:      k.tenant,
			PeriodStart: ps,
			PeriodEnd:   periodEnd(ps, gran),
			Counters:    *cells[k],
		})
	}

	// Per-tenant totals and grand total.
	tnames := make([]string, 0, len(totals))
	for t := range totals {
		tnames = append(tnames, t)
	}
	sort.Strings(tnames)
	for _, t := range tnames {
		c := totals[t].clone()
		rep.Totals = append(rep.Totals, TenantSnapshot{Tenant: t, Counters: c})
		rep.Grand.add(c)
	}
	return rep
}

// CSV renders the report's per-(tenant, period) rows as CSV for a chargeback
// spreadsheet.
func (rep UsageReport) CSV() string {
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write([]string{
		"tenant", "period_start", "period_end", "requests",
		"bytes_cache_hit", "bytes_upstream", "bytes_served", "storage_bytes",
		"scan_invocations", "scan_cost_micros", "blocked", "quarantined",
	})
	for _, row := range rep.Rows {
		_ = w.Write([]string{
			row.Tenant,
			row.PeriodStart.Format(time.RFC3339),
			row.PeriodEnd.Format(time.RFC3339),
			strconv.FormatInt(row.Requests, 10),
			strconv.FormatInt(row.BytesCacheHit, 10),
			strconv.FormatInt(row.BytesUpstream, 10),
			strconv.FormatInt(row.BytesServed(), 10),
			strconv.FormatInt(row.StorageBytes, 10),
			strconv.FormatInt(row.ScanInvocations, 10),
			strconv.FormatInt(row.ScanCostMicros, 10),
			strconv.FormatInt(row.Blocked, 10),
			strconv.FormatInt(row.Quarantined, 10),
		})
	}
	w.Flush()
	return sb.String()
}

// Markdown renders the report as a human-readable chargeback summary: a
// per-tenant totals table over the range followed by the period breakdown.
func (rep UsageReport) Markdown() string {
	var sb strings.Builder
	scope := "all tenants"
	if rep.Tenant != "" {
		scope = "tenant " + rep.Tenant
	}
	fmt.Fprintf(&sb, "# Usage & chargeback report (%s)\n\n", scope)
	fmt.Fprintf(&sb, "- Range: %s → %s\n", rep.Start.Format(time.RFC3339), rep.End.Format(time.RFC3339))
	fmt.Fprintf(&sb, "- Granularity: %s\n", rep.Granularity)
	fmt.Fprintf(&sb, "- Generated: %s\n\n", rep.GeneratedAt.Format(time.RFC3339))

	sb.WriteString("## Totals by tenant\n\n")
	sb.WriteString("| Tenant | Requests | Bytes served | Storage | Scans | Scan cost | Blocked | Quarantined |\n")
	sb.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, t := range rep.Totals {
		fmt.Fprintf(&sb, "| %s | %d | %s | %s | %d | %s | %d | %d |\n",
			t.Tenant, t.Requests, humanBytes(t.BytesServed()), humanBytes(t.StorageBytes),
			t.ScanInvocations, formatCost(t.ScanCostMicros), t.Blocked, t.Quarantined)
	}
	fmt.Fprintf(&sb, "| **grand total** | %d | %s | %s | %d | %s | %d | %d |\n\n",
		rep.Grand.Requests, humanBytes(rep.Grand.BytesServed()), humanBytes(rep.Grand.StorageBytes),
		rep.Grand.ScanInvocations, formatCost(rep.Grand.ScanCostMicros), rep.Grand.Blocked, rep.Grand.Quarantined)

	if len(rep.Rows) > 0 {
		sb.WriteString("## Breakdown by period\n\n")
		sb.WriteString("| Tenant | Period start | Requests | Bytes served | Scans | Scan cost | Blocked |\n")
		sb.WriteString("|---|---|---:|---:|---:|---:|---:|\n")
		for _, row := range rep.Rows {
			fmt.Fprintf(&sb, "| %s | %s | %d | %s | %d | %s | %d |\n",
				row.Tenant, row.PeriodStart.Format(time.RFC3339), row.Requests,
				humanBytes(row.BytesServed()), row.ScanInvocations, formatCost(row.ScanCostMicros), row.Blocked)
		}
	}
	return sb.String()
}

// --- Prometheus metrics snapshot --------------------------------------------

// TenantMetric is one tenant's cumulative counters for the Prometheus bridge.
type TenantMetric struct {
	Tenant string
	Counters
}

// Metrics is the meter's cumulative telemetry surfaced to Prometheus.
type Metrics struct {
	Tenants      []TenantMetric
	RollupsTotal uint64
	BudgetAlerts uint64
}

// MetricsSnapshot returns the per-tenant cumulative counters plus the meter's
// own telemetry. A nil meter returns the zero value.
func (m *Meter) MetricsSnapshot() Metrics {
	if m == nil {
		return Metrics{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := Metrics{
		RollupsTotal: m.rollupsTotal.Load(),
		BudgetAlerts: m.budgetAlerts.Load(),
	}
	for _, t := range sortedTenants(m.live) {
		out.Tenants = append(out.Tenants, TenantMetric{Tenant: t, Counters: m.live[t].clone()})
	}
	return out
}

// --- persistence ------------------------------------------------------------

// persistState is the on-disk schema for the rollup history.
type persistState struct {
	Version int      `json:"version"`
	SavedAt string   `json:"savedAt"`
	History []Rollup `json:"history"`
}

// save atomically writes the rollup history to the configured state path.
func (m *Meter) save(history []Rollup) error {
	if m.statePath == "" {
		return nil
	}
	st := persistState{Version: 1, SavedAt: m.now().UTC().Format(time.RFC3339), History: history}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(m.statePath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := m.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath)
}

// load reads a previously-persisted rollup history, seeding the in-memory store
// so usage survives a restart. A missing file is not an error.
func (m *Meter) load() error {
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		return err
	}
	var st persistState
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	m.mu.Lock()
	m.history = st.History
	m.mu.Unlock()
	return nil
}

// --- formatting helpers -----------------------------------------------------

func normalizeGranularity(g string) string {
	switch strings.ToLower(strings.TrimSpace(g)) {
	case "hour", "hourly":
		return "hour"
	case "total", "all":
		return "total"
	default:
		return "day"
	}
}

// normalizeTenantFilter resolves the report's tenant filter to a live-bucket
// key. An empty filter means "all tenants".
func normalizeTenantFilter(tenant string) string {
	t := strings.TrimSpace(tenant)
	if t == "" {
		return ""
	}
	return normalizeTenant(t)
}

// truncatePeriod buckets t to the start of its granularity period (UTC).
func truncatePeriod(t time.Time, gran string) time.Time {
	t = t.UTC()
	switch gran {
	case "hour":
		return t.Truncate(time.Hour)
	case "total":
		return time.Time{}
	default: // day
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	}
}

func periodEnd(start time.Time, gran string) time.Time {
	switch gran {
	case "hour":
		return start.Add(time.Hour)
	case "total":
		return time.Time{}
	default:
		return start.AddDate(0, 0, 1)
	}
}

// humanBytes renders a byte count in a compact, human-readable unit.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// formatCost renders a micro-unit cost as a fixed-point unit value.
func formatCost(micros int64) string {
	return fmt.Sprintf("%.4f", float64(micros)/1_000_000)
}
