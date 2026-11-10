//go:build integration
// +build integration

package e2e

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// gateColumns is the ordered set of pipeline capabilities the efficacy matrix
// reports per ecosystem. Each is a distinct cross-cutting behavior the
// whole-pipeline suite exercises end-to-end.
var gateColumns = []string{
	"routing",       // index pull routed and served live from the replayed upstream
	"cache",         // artifact cached: a repeat pull is served without a 2nd upstream hit
	"digest-verify", // the fill-time content-digest verifier accepted matching bytes
	"digest-tamper", // the verifier rejected a mismatching (tampered) fill
	"vulnscan",      // the vulnerability gate ran (SBOM built, clean verdict)
	"riskscore",     // the risk engine scored the artifact (X-Risk-Band emitted)
	"findings",      // a SARIF findings document was recorded for the coordinate
	"sarif",         // that document rendered to a non-empty SARIF 2.1.0 log
	"dossier",       // a per-coordinate security dossier was assembled
	"risk-block",    // the risk threshold forced a block (403, SARIF explains it)
	"malfeed-block", // the known-malicious gate hard-blocked the coordinate (403)
}

// cell is a single matrix outcome: covered, not-covered, or not-applicable.
type cell int

const (
	cellNA cell = iota
	cellPass
	cellFail
)

func (c cell) mark() string {
	switch c {
	case cellPass:
		return "✓"
	case cellFail:
		return "✗"
	default:
		return "–"
	}
}

// row is one ecosystem's end-to-end coverage.
type row struct {
	Ecosystem  string          `json:"ecosystem"`
	Backend    string          `json:"backend"`
	Label      string          `json:"label"`
	Coordinate string          `json:"coordinate"`
	Cells      map[string]cell `json:"-"`
	// Gates mirrors Cells as strings for the JSON artifact.
	Gates map[string]string `json:"gates"`
	// EndToEnd reports whether this ecosystem has non-zero end-to-end coverage
	// (the CI gate fails when any supported backend is false here).
	EndToEnd bool     `json:"endToEnd"`
	Notes    []string `json:"notes,omitempty"`
}

func newRow(f fixtureMeta) *row {
	r := &row{
		Ecosystem:  f.id,
		Backend:    f.backend,
		Label:      f.label,
		Coordinate: f.coordinate,
		Cells:      map[string]cell{},
	}
	for _, g := range gateColumns {
		r.Cells[g] = cellNA
	}
	return r
}

// fixtureMeta is the subset of testset.Fixture the report retains.
type fixtureMeta struct {
	id         string
	backend    string
	label      string
	coordinate string
}

func (r *row) set(gate string, pass bool) {
	if pass {
		r.Cells[gate] = cellPass
	} else {
		r.Cells[gate] = cellFail
	}
}

// matrix is the full ecosystem × gates-exercised efficacy report.
type matrix struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Rows        []*row    `json:"rows"`
}

func newMatrix() *matrix { return &matrix{GeneratedAt: time.Now().UTC()} }

func (m *matrix) add(r *row) { m.Rows = append(m.Rows, r) }

// finalize fills the serialization-friendly string views and sorts rows.
func (m *matrix) finalize() {
	sort.Slice(m.Rows, func(i, j int) bool { return m.Rows[i].Ecosystem < m.Rows[j].Ecosystem })
	for _, r := range m.Rows {
		r.Gates = map[string]string{}
		for _, g := range gateColumns {
			r.Gates[g] = r.Cells[g].mark()
		}
	}
}

// uncovered returns the ecosystems with zero end-to-end coverage (the CI-fail
// set).
func (m *matrix) uncovered() []string {
	var out []string
	for _, r := range m.Rows {
		if !r.EndToEnd {
			out = append(out, r.Ecosystem)
		}
	}
	sort.Strings(out)
	return out
}

// exercised counts how many (ecosystem, gate) pairs passed, over how many were
// applicable — the headline efficacy number.
func (m *matrix) exercised() (pass, applicable int) {
	for _, r := range m.Rows {
		for _, g := range gateColumns {
			switch r.Cells[g] {
			case cellPass:
				pass++
				applicable++
			case cellFail:
				applicable++
			}
		}
	}
	return pass, applicable
}

// JSON renders the matrix as an indented JSON artifact.
func (m *matrix) JSON() []byte {
	b, _ := json.MarshalIndent(m, "", "  ")
	return append(b, '\n')
}

// Markdown renders the matrix as a human-readable coverage/efficacy table.
func (m *matrix) Markdown() string {
	var b strings.Builder
	pass, applicable := m.exercised()
	fmt.Fprintf(&b, "# End-to-end supply-chain integration coverage matrix\n\n")
	fmt.Fprintf(&b, "_Generated %s (Task 144)._\n\n", m.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Every row is a real ecosystem fixture from `internal/testset`, driven through a live in-process "+
		"proxy gateway (admission gates + SARIF findings + risk engine + vulnerability scanner + dossier) fronted by "+
		"a recorded/replayed upstream — no network.\n\n")
	fmt.Fprintf(&b, "**Efficacy: %d/%d applicable (ecosystem × gate) checks passed across %d ecosystems.**\n\n",
		pass, applicable, len(m.Rows))

	// Header.
	b.WriteString("| ecosystem | coordinate |")
	for _, g := range gateColumns {
		fmt.Fprintf(&b, " %s |", g)
	}
	b.WriteString(" e2e |\n")
	b.WriteString("|---|---|")
	for range gateColumns {
		b.WriteString("---|")
	}
	b.WriteString("---|\n")

	for _, r := range m.Rows {
		fmt.Fprintf(&b, "| `%s` | `%s` |", r.Ecosystem, r.Coordinate)
		for _, g := range gateColumns {
			fmt.Fprintf(&b, " %s |", r.Cells[g].mark())
		}
		e2e := "✓"
		if !r.EndToEnd {
			e2e = "✗"
		}
		fmt.Fprintf(&b, " %s |\n", e2e)
	}

	b.WriteString("\nLegend: ✓ covered · ✗ failed · – not applicable (e.g. git exposes no cacheable artifact).\n")
	if un := m.uncovered(); len(un) > 0 {
		fmt.Fprintf(&b, "\n**CI FAIL — ecosystems with zero end-to-end coverage: %s**\n", strings.Join(un, ", "))
	}
	return b.String()
}
