package testset

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PullResult is the end-to-end outcome of one representative pull.
type PullResult struct {
	Kind   string `json:"kind"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Desc   string `json:"desc"`
	// Status is the gateway HTTP status (0 when the pull was not driven).
	Status int `json:"status,omitempty"`
	// Served reports whether the gateway routed the pull and returned 2xx.
	Served bool `json:"served"`
	// Cached, for artifact pulls, reports whether the repeat fetch was served
	// from cache (no second upstream hit). nil for index/non-driven pulls.
	Cached *bool `json:"cached,omitempty"`
	// Documented marks a pull that is catalogued but not driven by the hermetic
	// harness (e.g. git's POST pack negotiation).
	Documented bool `json:"documented,omitempty"`
	// Detail explains the outcome.
	Detail string `json:"detail,omitempty"`
}

// ok reports whether the pull is a success (or a documented-only pull).
func (p PullResult) ok() bool {
	if p.Documented {
		return true
	}
	if !p.Served {
		return false
	}
	if p.Cached != nil {
		return *p.Cached
	}
	return true
}

// FixtureResult is the aggregate outcome for one fixture.
type FixtureResult struct {
	ID         string       `json:"id"`
	Ecosystem  string       `json:"ecosystem"`
	Backend    string       `json:"backend"`
	BuildCmd   string       `json:"buildCmd"`
	Dependency string       `json:"dependency"`
	Files      []string     `json:"files"`
	Pulls      []PullResult `json:"pulls"`
	Pass       bool         `json:"pass"`
}

// Report is the coverage matrix produced by Run.
type Report struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Total       int       `json:"total"`
	Passed      int       `json:"passed"`
	Failed      int       `json:"failed"`
	// Complete is true when the corpus covers every supported ecosystem and
	// passed validation.
	Complete bool `json:"complete"`
	// ValidationError is set (and no fixtures are run) when the corpus itself is
	// malformed.
	ValidationError string          `json:"validationError,omitempty"`
	Fixtures        []FixtureResult `json:"fixtures"`
}

func newReport() *Report {
	return &Report{GeneratedAt: time.Now().UTC()}
}

func (r *Report) finalize() {
	r.Total = len(r.Fixtures)
	r.Passed = 0
	for _, f := range r.Fixtures {
		if f.Pass {
			r.Passed++
		}
	}
	r.Failed = r.Total - r.Passed
}

// OK reports whether the whole run is clean: the corpus validated and every
// fixture passed.
func (r *Report) OK() bool {
	return r.ValidationError == "" && r.Complete && r.Failed == 0 && r.Total > 0
}

// JSON renders the report as indented JSON.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Markdown renders the report as a human-readable coverage matrix.
func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Ecosystem Test-Set Coverage\n\n")
	fmt.Fprintf(&b, "_Generated %s_\n\n", r.GeneratedAt.Format(time.RFC3339))

	if r.ValidationError != "" {
		b.WriteString("**Corpus validation FAILED — no fixtures were run.**\n\n")
		b.WriteString("```\n")
		b.WriteString(r.ValidationError)
		b.WriteString("\n```\n")
		return b.String()
	}

	verdict := "PASS"
	if !r.OK() {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "**%s** — %d/%d ecosystems passed; corpus complete: %v.\n\n",
		verdict, r.Passed, r.Total, r.Complete)

	b.WriteString("| Ecosystem | Backend | Build | Dependency | Index | Artifact (cached) | Verdict |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, f := range r.Fixtures {
		index, artifact := summarizePulls(f.Pulls)
		mark := "✓"
		if !f.Pass {
			mark = "✗"
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | `%s` | %s | %s | %s |\n",
			f.Ecosystem, f.Backend, f.BuildCmd, f.Dependency, index, artifact, mark)
	}
	b.WriteString("\n")

	// Per-pull detail for anything that did not cleanly pass.
	var notes []string
	for _, f := range r.Fixtures {
		for _, p := range f.Pulls {
			if !p.ok() {
				notes = append(notes, fmt.Sprintf("- **%s** %s `%s`: %s", f.ID, p.Method, p.Path, p.Detail))
			}
		}
	}
	if len(notes) > 0 {
		b.WriteString("## Failures\n\n")
		b.WriteString(strings.Join(notes, "\n"))
		b.WriteString("\n")
	}
	return b.String()
}

// summarizePulls renders the index and artifact columns for a fixture.
func summarizePulls(pulls []PullResult) (index, artifact string) {
	index, artifact = "—", "—"
	for _, p := range pulls {
		switch p.Kind {
		case string(KindIndex):
			// A served GET is the strongest signal; don't let a later
			// documented-only pull (git's POST) overwrite it.
			switch {
			case p.Served:
				index = "✓"
			case index == "✓":
				// keep
			case p.Documented:
				index = "doc"
			default:
				index = "✗"
			}
		case string(KindArtifact):
			switch {
			case !p.Served:
				artifact = "✗"
			case p.Cached != nil && *p.Cached:
				artifact = "✓ cached"
			case p.Cached != nil:
				artifact = "✓ uncached"
			default:
				artifact = "✓"
			}
		}
	}
	return index, artifact
}
