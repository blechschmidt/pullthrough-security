package ecotest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The checks every ecosystem run performs, in the order they are executed and
// reported. Each maps to one column of the matrix.
const (
	// CheckInstall: the real client, configured to use the proxy, installs the
	// good package.
	CheckInstall = "install"
	// CheckCached: the good package's artifact was stored in the proxy's cache,
	// i.e. the download really flowed through the proxy.
	CheckCached = "cached"
	// CheckScanAdmit: the good package was admitted on the strength of its source
	// commit's benign LLM verdict (provenance pin joined with the scan verdict).
	CheckScanAdmit = "scan-admit"
	// CheckCacheHit: a second install from a pristine client is served from the
	// proxy's cache; the artifact is not fetched from the upstream again.
	CheckCacheHit = "cache-hit"
	// CheckBlock: the bad package — source commit flagged malicious by the LLM —
	// is refused by the proxy and the real client fails the install.
	CheckBlock = "block"
	// CheckDownloadLog: the proxy's download log attributes the good package
	// (served) to the address of each client machine that installed it and the
	// bad package (blocked) to the machine that tried. Asserted for the
	// ecosystems that opt in (Ecosystem.DownloadLog).
	CheckDownloadLog = "download-log"
	// CheckPersonalLink: the same install through a personal cache link (Task
	// 177) — the package source behind a path prefix that names a user — is
	// recorded under that user. The real client must stay on its personal
	// address for every request it makes, which means every link the proxy
	// handed it on the way (a tarball URL in an index document, a redirect) led
	// back to that address; and every download the log holds for the run must
	// carry the user and the link. Not asserted where the client has no way to
	// carry a link (Ecosystem.NoPersonalLink says why).
	CheckPersonalLink = "personal-link"
	// CheckIntercept: TLS interception through the forward proxy (Task 172).
	// The client is not pointed at the proxy at all — it keeps its built-in
	// registry — and is given only the proxy environment (HTTPS_PROXY) and the
	// interception CA; the forward proxy is the only thing it can reach. The
	// good package installs, every request reaches the proxy through the
	// interception listener for the registry's own host, the artifact is served
	// from the same cache entry an explicit install uses, and the bad package
	// is refused. Not asserted where Ecosystem.NoIntercept says why.
	CheckIntercept = "intercept"
	// CheckNAT: NAT mode (Task 172). As CheckIntercept, but the client is given
	// nothing except the CA: the network answers the registry's hostnames with
	// the proxy's NAT listeners, and nothing else — not even the proxy's own
	// address — is reachable. Not asserted where Ecosystem.NoNAT says why.
	CheckNAT = "nat"
)

// checkOrder is the canonical column order.
var checkOrder = []string{CheckInstall, CheckCached, CheckScanAdmit, CheckCacheHit, CheckBlock, CheckDownloadLog, CheckPersonalLink, CheckIntercept, CheckNAT}

// checkTitles are the matrix column headings.
var checkTitles = map[string]string{
	CheckInstall:      "Installs via proxy",
	CheckCached:       "Stored in cache",
	CheckScanAdmit:    "Admitted by LLM scan",
	CheckCacheHit:     "Re-install from cache",
	CheckBlock:        "Bad package blocked",
	CheckDownloadLog:  "Downloads logged by client address",
	CheckPersonalLink: "Personal link names the user",
	CheckIntercept:    "TLS interception (HTTPS_PROXY)",
	CheckNAT:          "NAT (no client config)",
}

// Check statuses.
const (
	StatusPass = "pass"
	StatusFail = "fail"
	// StatusNA marks a check that does not apply to the ecosystem (e.g. Git has
	// no package coordinate to block).
	StatusNA = "n/a"
	// StatusSkipped marks a check that was not reached because an earlier one
	// failed.
	StatusSkipped = "skipped"
)

// Check is the outcome of one assertion for one ecosystem.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Result is the outcome of one ecosystem run.
type Result struct {
	Ecosystem     string  `json:"ecosystem"`
	Client        string  `json:"client"`
	ClientVersion string  `json:"clientVersion,omitempty"`
	Image         string  `json:"image"`
	Upstream      string  `json:"upstream"`
	GoodPackage   string  `json:"goodPackage"`
	BadPackage    string  `json:"badPackage,omitempty"`
	LLMCalls      int     `json:"llmCalls"`
	Checks        []Check `json:"checks"`
	Passed        bool    `json:"passed"`
	DurationSec   float64 `json:"durationSeconds"`
	Error         string  `json:"error,omitempty"`
}

// NewResult returns a Result for the ecosystem with every check initialised to
// "skipped" (or "n/a" where it does not apply), so a run that aborts early still
// reports a complete row.
func NewResult(e Ecosystem) *Result {
	r := &Result{
		Ecosystem:   e.ID,
		Client:      e.Client,
		Image:       e.Image,
		Upstream:    e.Upstream.URL,
		GoodPackage: packageLabel(e.Good),
	}
	if e.Bad != nil {
		r.BadPackage = packageLabel(*e.Bad)
	}
	for _, name := range checkOrder {
		status := StatusSkipped
		if !e.applies(name) {
			status = StatusNA
		}
		r.Checks = append(r.Checks, Check{Name: name, Status: status})
	}
	return r
}

// applies reports whether a check applies to the ecosystem.
func (e Ecosystem) applies(check string) bool {
	switch check {
	case CheckCached, CheckCacheHit:
		return e.Artifact != ""
	case CheckScanAdmit, CheckBlock:
		return e.Bad != nil
	case CheckDownloadLog:
		return e.DownloadLog && e.Bad != nil
	case CheckPersonalLink:
		return e.NoPersonalLink == ""
	case CheckIntercept:
		return e.NoIntercept == ""
	case CheckNAT:
		return e.NoNAT == ""
	default:
		return true
	}
}

// packageLabel renders "name@version" (or just the name).
func packageLabel(p Package) string {
	if p.Version == "" {
		return p.Name
	}
	return p.Name + "@" + p.Version
}

// Set records the outcome of a check.
func (r *Result) Set(name, status, detail string) {
	for i := range r.Checks {
		if r.Checks[i].Name == name {
			r.Checks[i].Status = status
			r.Checks[i].Detail = detail
			return
		}
	}
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
}

// Status returns the recorded status of a check ("" when unknown).
func (r *Result) Status(name string) string {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return ""
}

// Finalize derives Passed: every applicable check must have passed.
func (r *Result) Finalize() {
	r.Passed = r.Error == ""
	for _, c := range r.Checks {
		if c.Status != StatusPass && c.Status != StatusNA {
			r.Passed = false
		}
	}
}

// WriteFile writes the result as <dir>/<ecosystem>.json.
func (r *Result) WriteFile(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	data, err := marshalJSON(r)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, r.Ecosystem+".json")
	return path, os.WriteFile(path, data, 0o644)
}

// marshalJSON renders v as indented JSON without HTML escaping: the reports are
// read by people, and details such as "pkg -> commit" should stay legible.
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Matrix is the ecosystem x check outcome matrix over a set of results.
type Matrix struct {
	// Results holds one row per ecosystem that ran, sorted by ecosystem ID.
	Results []*Result `json:"results"`
	// Missing lists catalog ecosystems for which no result was found.
	Missing []string `json:"missing,omitempty"`
	// Passed is true when every catalog ecosystem ran and passed.
	Passed bool `json:"passed"`
}

// LoadResults reads every per-ecosystem result file (<ecosystem>.json) found in
// dir or one directory level below it (CI downloads each leg's artifact into its
// own sub-directory).
func LoadResults(dir string) ([]*Result, error) {
	var paths []string
	for _, pattern := range []string{"*.json", filepath.Join("*", "*.json")} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, err
		}
		paths = append(paths, matches...)
	}
	sort.Strings(paths)

	byID := map[string]*Result{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var r Result
		if err := json.Unmarshal(data, &r); err != nil || r.Ecosystem == "" || len(r.Checks) == 0 {
			continue // not a result file (e.g. the rendered matrix itself)
		}
		byID[r.Ecosystem] = &r
	}
	out := make([]*Result, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ecosystem < out[j].Ecosystem })
	return out, nil
}

// BuildMatrix assembles the matrix. want lists the ecosystems that were expected
// to run; any without a result is reported as missing and fails the matrix.
func BuildMatrix(results []*Result, want []string) *Matrix {
	m := &Matrix{Results: results, Passed: true}
	have := map[string]bool{}
	for _, r := range results {
		have[r.Ecosystem] = true
		if !r.Passed {
			m.Passed = false
		}
	}
	for _, id := range want {
		if !have[id] {
			m.Missing = append(m.Missing, id)
		}
	}
	sort.Strings(m.Missing)
	if len(m.Missing) > 0 || len(results) == 0 {
		m.Passed = false
	}
	return m
}

// Markdown renders the matrix as a GitHub-flavoured Markdown table.
func (m *Matrix) Markdown() string {
	var b strings.Builder
	b.WriteString("## Ecosystem tests — real package managers through the pull-through proxy\n\n")

	passed := 0
	for _, r := range m.Results {
		if r.Passed {
			passed++
		}
	}
	verdict := "✅ all passed"
	if !m.Passed {
		verdict = "❌ failing"
	}
	fmt.Fprintf(&b, "**%s** — %d/%d ecosystems passed", verdict, passed, len(m.Results)+len(m.Missing))
	if len(m.Missing) > 0 {
		fmt.Fprintf(&b, "; no result for: %s", strings.Join(m.Missing, ", "))
	}
	b.WriteString(".\n\n")
	b.WriteString("Each row is the ecosystem's real client, configured to use the proxy instead of the public registry, " +
		"against the real proxy binary. The LLM is mocked; everything else is real.\n\n")

	b.WriteString("| Ecosystem | Client |")
	for _, name := range checkOrder {
		fmt.Fprintf(&b, " %s |", checkTitles[name])
	}
	b.WriteString(" Result |\n|---|---|")
	for range checkOrder {
		b.WriteString(":-:|")
	}
	b.WriteString(":-:|\n")

	for _, r := range m.Results {
		client := r.Client
		if r.ClientVersion != "" {
			client += " " + r.ClientVersion
		}
		fmt.Fprintf(&b, "| %s | %s |", r.Ecosystem, mdEscape(client))
		for _, name := range checkOrder {
			fmt.Fprintf(&b, " %s |", statusIcon(r.Status(name)))
		}
		if r.Passed {
			b.WriteString(" ✅ |\n")
		} else {
			b.WriteString(" ❌ |\n")
		}
	}
	for _, id := range m.Missing {
		fmt.Fprintf(&b, "| %s | — |", id)
		for range checkOrder {
			b.WriteString(" — |")
		}
		b.WriteString(" ❌ no result |\n")
	}

	// Explain every failure below the table, where there is room for detail.
	var failures []string
	for _, r := range m.Results {
		if r.Passed {
			continue
		}
		if r.Error != "" {
			failures = append(failures, fmt.Sprintf("- **%s**: %s", r.Ecosystem, mdEscape(r.Error)))
		}
		for _, c := range r.Checks {
			if c.Status == StatusFail {
				failures = append(failures, fmt.Sprintf("- **%s** / %s: %s", r.Ecosystem, c.Name, mdEscape(c.Detail)))
			}
		}
	}
	if len(failures) > 0 {
		b.WriteString("\n### Failures\n\n")
		b.WriteString(strings.Join(failures, "\n"))
		b.WriteString("\n")
	}

	b.WriteString("\n<sub>✅ pass · ❌ fail · ➖ not applicable · ⏭ not reached</sub>\n")
	return b.String()
}

// statusIcon renders a check status as a table cell.
func statusIcon(status string) string {
	switch status {
	case StatusPass:
		return "✅"
	case StatusFail:
		return "❌"
	case StatusNA:
		return "➖"
	default:
		return "⏭"
	}
}

// mdEscape makes free text safe inside a Markdown table cell or list item.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// WriteMatrix writes the matrix as ecosystem-matrix.json and ecosystem-matrix.md
// in dir and returns the Markdown path.
func WriteMatrix(m *Matrix, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	data, err := marshalJSON(m)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "ecosystem-matrix.json"), data, 0o644); err != nil {
		return "", err
	}
	md := filepath.Join(dir, "ecosystem-matrix.md")
	return md, os.WriteFile(md, []byte(m.Markdown()), 0o644)
}
