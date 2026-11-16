//go:build integration
// +build integration

package fullmirror

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// column is one property the suite asserts for an upstream type.
type column struct {
	// ID is the column's stable name (JSON key, Markdown header).
	ID string
	// Asserts says, in one sentence, what a pass means.
	Asserts string
}

// The columns. A cell passes only if every assertion made under it held; see
// runner.go for each.
var (
	colMirrored = column{ID: "mirrored",
		Asserts: "with no client request, the mirror fetched every file of the package published before it started (the enumeration) and of the benign package published after (a poll of the feed) into the cache; a client's pull is then served from the cache (200, X-Cache: HIT), byte for byte, without a fetch from the registry"}
	colScanned = column{ID: "scanned",
		Asserts: "the LLM package scan read those packages on their way into the cache — the mock LLM was shown each one's own content token — and the proxy holds a benign verdict on their bytes; the full scan counts them scanned and benign with nothing pending; the client's pull carries X-LLMPkgScan-Verdict: benign and costs no model call"}
	colBlocked = column{ID: "blocked",
		Asserts: "the malicious package published beside the benign one was fetched and refused by the gate (llmpkgscan): it is not in the cache, the mirror counts it refused, the full scan counts it malicious and removed; a client's pull is refused (403, X-Policy-Code: llm-package-malicious) from the stored verdict, without a model call"}
	colLogged = column{ID: "logged",
		Asserts: "the mirror's status counts (fetched, refused, failed) are exactly the files fetched and refused, and the download log holds, for every one of them, an entry with via=system, the mirror's subject and user agent, and the outcome (served, or blocked by llmpkgscan); it holds no entry of a client request before the suite made one"}
	colResumed = column{ID: "resumed",
		Asserts: "after a restart the mirror continued from the cursor it had stored — no new enumeration of the registry — found the package published while it was stopped, fetched it, and fetched nothing it had fetched before"}
)

// columns lists the columns in display order.
var columns = []column{colMirrored, colScanned, colBlocked, colLogged, colResumed}

// Cell states.
const (
	cellPass = "pass"
	cellFail = "fail"
	// cellNotRun: the column was never reached (the row stopped before).
	cellNotRun = "not-run"
)

// cell is one outcome.
type cell struct {
	State string `json:"state"`
	// Detail says why a cell failed (the first failed assertion).
	Detail string `json:"detail,omitempty"`
}

// rowResult is one upstream type's results.
type rowResult struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	Tier  string `json:"tier"`
	// Status is the catalog's implementation status of the type.
	Status string `json:"status"`
	// Feed is what the stub served as the registry's feed; Format the
	// artifact the packages are.
	Feed   string `json:"feed"`
	Format string `json:"artifact,omitempty"`
	// Cells maps column ID to outcome.
	Cells map[string]*cell `json:"columns"`
	// Fetched and Refused are the mirror's counts at the end of the row;
	// Files the files of the four packages the row expected it to fetch.
	Fetched uint64 `json:"fetched"`
	Refused uint64 `json:"refused"`
	Files   int    `json:"files"`
	// LLMCalls is the number of package scans the mock LLM answered.
	LLMCalls int `json:"llmCalls"`
	// Seconds is how long the row took.
	Seconds float64 `json:"seconds"`
	// Notes are remarks worth keeping with the row.
	Notes []string `json:"notes,omitempty"`

	mu sync.Mutex
}

func newRowResult(typ string) *rowResult {
	r := &rowResult{Type: typ, Cells: map[string]*cell{}}
	for _, c := range columns {
		r.Cells[c.ID] = &cell{State: cellNotRun}
	}
	return r
}

// pass marks a column passed, unless it already failed: a failure is sticky.
func (r *rowResult) pass(c column) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Cells[c.ID].State != cellFail {
		r.Cells[c.ID] = &cell{State: cellPass}
	}
}

// fail marks a column failed with the first reason given.
func (r *rowResult) fail(c column, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Cells[c.ID].State != cellFail {
		r.Cells[c.ID] = &cell{State: cellFail, Detail: detail}
	}
}

// note keeps a remark.
func (r *rowResult) note(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}

// covered reports whether every column passed.
func (r *rowResult) covered() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range columns {
		if r.Cells[c.ID].State != cellPass {
			return false
		}
	}
	return true
}

// refusal is the outcome for a type nothing can follow: full mirroring must be
// refused when the configuration is validated.
type refusal struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Tier   string `json:"tier"`
	Status string `json:"status"`
	// Refused reports that the proxy refused the configuration with the
	// reason expected; Error is the first line it gave.
	Refused bool   `json:"refused"`
	Error   string `json:"error,omitempty"`
	// Control reports that the same configuration without fullMirror started.
	Control bool `json:"control"`
	// Detail says why the check failed.
	Detail string `json:"detail,omitempty"`
}

// matrix is the suite's report.
type matrix struct {
	GeneratedAt time.Time `json:"generatedAt"`
	// Partial marks a run restricted to a selection of types.
	Partial bool `json:"partial"`
	Columns []struct {
		ID      string `json:"id"`
		Asserts string `json:"asserts"`
	} `json:"columns"`
	Rows     []*rowResult `json:"rows"`
	Refusals []*refusal   `json:"refusals"`
	// Uncovered lists the types that must be covered and are not: no row, or
	// a row with a column that did not pass. Unrefused lists the types
	// nothing can follow whose configuration the proxy accepted.
	Uncovered []string `json:"uncovered"`
	Unrefused []string `json:"unrefused"`

	mu sync.Mutex
}

func newMatrix() *matrix {
	m := &matrix{GeneratedAt: time.Now().UTC()}
	for _, c := range columns {
		m.Columns = append(m.Columns, struct {
			ID      string `json:"id"`
			Asserts string `json:"asserts"`
		}{c.ID, c.Asserts})
	}
	return m
}

func (m *matrix) add(r *rowResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Rows = append(m.Rows, r)
}

func (m *matrix) addRefusal(r *refusal) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Refusals = append(m.Refusals, r)
}

// finalize sorts the rows and computes what is uncovered: every type of want
// (the types that must have a row) without a row whose every column passed,
// and every type of mustRefuse whose refusal was not shown.
func (m *matrix) finalize(want, mustRefuse []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sort.Slice(m.Rows, func(i, j int) bool { return m.Rows[i].Type < m.Rows[j].Type })
	sort.Slice(m.Refusals, func(i, j int) bool { return m.Refusals[i].Type < m.Refusals[j].Type })
	byType := map[string]*rowResult{}
	for _, r := range m.Rows {
		byType[r.Type] = r
	}
	m.Uncovered = nil
	for _, t := range want {
		if r := byType[t]; r == nil || !r.covered() {
			m.Uncovered = append(m.Uncovered, t)
		}
	}
	sort.Strings(m.Uncovered)
	shown := map[string]bool{}
	for _, r := range m.Refusals {
		if r.Refused && r.Control {
			shown[r.Type] = true
		}
	}
	m.Unrefused = nil
	for _, t := range mustRefuse {
		if !shown[t] {
			m.Unrefused = append(m.Unrefused, t)
		}
	}
	sort.Strings(m.Unrefused)
}

// JSON renders the matrix.
func (m *matrix) JSON() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return []byte(fmt.Sprintf(`{"error": %q}`, err.Error()))
	}
	return append(b, '\n')
}

// Markdown renders the matrix for a CI job summary.
func (m *matrix) Markdown() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	title := "Full mirror and full scan, every followed upstream type"
	if m.Partial {
		title += " (partial run)"
	}
	b.WriteString("## " + title + "\n\n")
	switch {
	case len(m.Uncovered) > 0 || len(m.Unrefused) > 0:
		b.WriteString("**CI FAIL**")
		if len(m.Uncovered) > 0 {
			b.WriteString(" — not proven for: " + strings.Join(m.Uncovered, ", ") + ".")
		}
		if len(m.Unrefused) > 0 {
			b.WriteString(" — full mirroring not refused for: " + strings.Join(m.Unrefused, ", ") + ".")
		}
		b.WriteString("\n\n")
	default:
		fmt.Fprintf(&b, "Every followed upstream type passed every column (%d rows).\n\n", len(m.Rows))
	}
	b.WriteString("Real `pullthrough` binary, a stub registry per type serving its feed, a mock LLM; no client request until the mirror has fetched.\n\n")
	b.WriteString("| Type | Tier | Feed served | ")
	for _, c := range columns {
		b.WriteString(c.ID + " | ")
	}
	b.WriteString("Files fetched / refused | LLM calls | s |\n|---|---|---|")
	for range columns {
		b.WriteString("---|")
	}
	b.WriteString("---|---|---|\n")
	for _, r := range m.Rows {
		fmt.Fprintf(&b, "| `%s` | %s | %s | ", r.Type, r.Tier, mdEscape(r.Feed))
		for _, c := range columns {
			b.WriteString(cellMark(r.Cells[c.ID]) + " | ")
		}
		fmt.Fprintf(&b, "%d / %d | %d | %.0f |\n", r.Fetched, r.Refused, r.LLMCalls, r.Seconds)
	}
	b.WriteString("\n")
	var failures []string
	for _, r := range m.Rows {
		for _, c := range columns {
			if cl := r.Cells[c.ID]; cl.State == cellFail {
				failures = append(failures, fmt.Sprintf("- `%s` %s: %s", r.Type, c.ID, mdEscape(cl.Detail)))
			}
		}
	}
	if len(failures) > 0 {
		b.WriteString("### Failures\n\n" + strings.Join(failures, "\n") + "\n\n")
	}
	if len(m.Refusals) > 0 {
		b.WriteString("### Types nothing can follow: refused at configuration validation\n\n| Type | Tier | Refused | Proxy's reason |\n|---|---|---|---|\n")
		for _, r := range m.Refusals {
			mark := "✅"
			if !r.Refused || !r.Control {
				mark = "❌ " + mdEscape(r.Detail)
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", r.Type, r.Tier, mark, mdEscape(r.Error))
		}
		b.WriteString("\n")
	}
	var notes []string
	for _, r := range m.Rows {
		for _, n := range r.Notes {
			notes = append(notes, fmt.Sprintf("- `%s`: %s", r.Type, mdEscape(n)))
		}
	}
	if len(notes) > 0 {
		b.WriteString("### Notes\n\n" + strings.Join(notes, "\n") + "\n\n")
	}
	b.WriteString("### Columns\n\n")
	for _, c := range columns {
		fmt.Fprintf(&b, "- **%s** — %s.\n", c.ID, c.Asserts)
	}
	return b.String()
}

func cellMark(c *cell) string {
	switch c.State {
	case cellPass:
		return "✅"
	case cellFail:
		return "❌"
	default:
		return "—"
	}
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}
