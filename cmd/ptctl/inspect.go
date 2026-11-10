package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
)

// findingsListResp mirrors the admin GET /api/findings envelope (subset).
type findingsListResp struct {
	Enabled bool                `json:"enabled"`
	Total   int                 `json:"total"`
	Items   []findings.Document `json:"items"`
}

// runInspect implements `ptctl inspect <coordinate>`: it retrieves the
// aggregated admission findings for an artifact from the proxy (the same data
// behind the SARIF endpoint) and renders the verdict and findings in a
// human-readable form. With -sarif it streams the SARIF document instead, for
// piping into CI.
func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		ecosystem = fs.String("ecosystem", "", "filter to a specific ecosystem when a name is ambiguous")
		sarifOut  = fs.Bool("sarif", false, "emit the raw SARIF 2.1.0 document instead of a human summary")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl inspect [flags] <name[@version]>")
		fmt.Fprintln(os.Stderr, "Show the admission verdict and findings for a coordinate.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	coord := strings.TrimSpace(fs.Arg(0))
	if coord == "" {
		fs.Usage()
		return fmt.Errorf("a coordinate (name[@version]) is required")
	}
	name, ptVersion := splitCoordinate(coord)

	c, err := newClient(g)
	if err != nil {
		return err
	}

	if *sarifOut {
		return c.streamSARIF(os.Stdout, coord)
	}

	var resp findingsListResp
	u := c.adminURL("api/findings", map[string]string{"tenant": c.tenant, "q": name})
	if err := c.getJSON(u, &resp); err != nil {
		return err
	}
	if !resp.Enabled {
		return fmt.Errorf("findings aggregation is not enabled on the proxy")
	}

	doc, ok := matchDocument(resp.Items, name, ptVersion, *ecosystem)
	if !ok {
		return fmt.Errorf("no findings recorded for %q (it may not have been pulled through the proxy yet)", coord)
	}
	printVerdict(os.Stdout, doc)
	return nil
}

// streamSARIF fetches the single-artifact SARIF document and writes it verbatim.
func (c *client) streamSARIF(w *os.File, coord string) error {
	u := c.adminURL("api/findings/sarif", map[string]string{"tenant": c.tenant, "package": coord})
	var raw any
	if err := c.getJSON(u, &raw); err != nil {
		return err
	}
	return writeJSONIndented(w, raw)
}

// matchDocument selects the best document for a name/version/ecosystem from a
// list returned by the substring query. An exact coordinate match wins; failing
// that, a name+version match; failing that, the first name match.
func matchDocument(docs []findings.Document, name, version, ecosystem string) (findings.Document, bool) {
	var nameMatch *findings.Document
	for i := range docs {
		a := docs[i].Artifact
		if ecosystem != "" && !strings.EqualFold(a.Ecosystem, ecosystem) {
			continue
		}
		if !strings.EqualFold(a.Name, name) && !coordinateHasName(a.Coordinate, name) {
			continue
		}
		if version != "" {
			if strings.EqualFold(a.Version, version) || strings.HasSuffix(a.Coordinate, "@"+version) {
				return docs[i], true
			}
			continue
		}
		if nameMatch == nil {
			nameMatch = &docs[i]
		}
	}
	if nameMatch != nil {
		return *nameMatch, true
	}
	return findings.Document{}, false
}

func coordinateHasName(coordinate, name string) bool {
	if coordinate == "" {
		return false
	}
	base, _ := splitCoordinate(coordinate)
	return strings.EqualFold(base, name)
}

// printVerdict renders a document: a one-line verdict, the artifact identity,
// the severity tally, and a per-finding list grouped for readability.
func printVerdict(w *os.File, doc findings.Document) {
	a := doc.Artifact
	coord := a.Coordinate
	if coord == "" {
		coord = strings.TrimSuffix(a.Name+"@"+a.Version, "@")
	}

	verdict := "ADMITTED"
	if doc.HasBlocking() {
		verdict = "BLOCKED"
	} else if hasWarnings(doc) {
		verdict = "ADMITTED (with warnings)"
	}

	fmt.Fprintf(w, "Artifact:  %s\n", coord)
	if a.Ecosystem != "" {
		fmt.Fprintf(w, "Ecosystem: %s\n", a.Ecosystem)
	}
	if a.Digest != "" {
		fmt.Fprintf(w, "Digest:    %s\n", a.Digest)
	}
	if a.CommitSHA != "" {
		fmt.Fprintf(w, "Source:    %s @ %s\n", a.RepositoryURL, a.CommitSHA)
	}
	fmt.Fprintf(w, "Verdict:   %s\n", verdict)
	fmt.Fprintf(w, "Findings:  %s\n", severitySummary(doc.Counts()))

	if len(doc.Findings) == 0 {
		fmt.Fprintln(w, "\nNo findings — the artifact passed every enabled gate cleanly.")
		return
	}
	fmt.Fprintln(w)
	for _, f := range sortFindings(doc.Findings) {
		mark := levelMark(f)
		id := f.Identifier
		if id == "" {
			id = f.RuleID
		}
		fmt.Fprintf(w, "%s [%s/%s] %s\n", mark, f.Gate, strings.ToUpper(string(f.Severity)), f.Title)
		if f.Message != "" && f.Message != f.Title {
			fmt.Fprintf(w, "     %s\n", f.Message)
		}
		meta := []string{}
		if id != "" {
			meta = append(meta, id)
		}
		if f.Suppressed {
			j := f.Justification
			if j == "" {
				j = "suppressed"
			}
			meta = append(meta, "suppressed: "+j)
		}
		if len(meta) > 0 {
			fmt.Fprintf(w, "     (%s)\n", strings.Join(meta, "; "))
		}
	}
}

func hasWarnings(doc findings.Document) bool {
	for i := range doc.Findings {
		f := &doc.Findings[i]
		if !f.Suppressed && f.Level == findings.LevelWarning {
			return true
		}
	}
	return false
}

// levelMark returns a glyph for a finding's level/suppression state.
func levelMark(f findings.Finding) string {
	switch {
	case f.Suppressed:
		return "○"
	case f.Level == findings.LevelError:
		return "✗"
	case f.Level == findings.LevelWarning:
		return "!"
	default:
		return "·"
	}
}

// severityRank orders severities most-severe-first for display.
var severityRank = map[findings.Severity]int{
	findings.SeverityCritical: 0,
	findings.SeverityHigh:     1,
	findings.SeverityMedium:   2,
	findings.SeverityLow:      3,
	findings.SeverityInfo:     4,
}

func sortFindings(in []findings.Finding) []findings.Finding {
	out := make([]findings.Finding, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		// Non-suppressed before suppressed, then by severity, then by gate.
		if out[i].Suppressed != out[j].Suppressed {
			return !out[i].Suppressed
		}
		if severityRank[out[i].Severity] != severityRank[out[j].Severity] {
			return severityRank[out[i].Severity] < severityRank[out[j].Severity]
		}
		return out[i].Gate < out[j].Gate
	})
	return out
}

// severitySummary renders "2 critical, 1 high, 3 low" from a severity tally.
func severitySummary(counts map[findings.Severity]int) string {
	order := []findings.Severity{
		findings.SeverityCritical, findings.SeverityHigh,
		findings.SeverityMedium, findings.SeverityLow, findings.SeverityInfo,
	}
	parts := []string{}
	total := 0
	for _, s := range order {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
			total += n
		}
	}
	if total == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// splitCoordinate splits "name@version" into its parts. A name containing no '@'
// (or a leading-only '@', as in npm scopes) is returned whole with no version.
func splitCoordinate(coord string) (name, version string) {
	if i := strings.LastIndex(coord, "@"); i > 0 {
		return coord[:i], coord[i+1:]
	}
	return coord, ""
}
