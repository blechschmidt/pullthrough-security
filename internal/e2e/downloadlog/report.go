//go:build integration
// +build integration

package downloadlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	dl "github.com/blechschmidt/pullthrough-security/internal/downloadlog"
)

// The checks run for every ecosystem, in order. Each is one column of the
// matrix.
const (
	checkInstall       = "install"
	checkLogged        = "logged"
	checkCacheHit      = "cache-hit"
	checkWhoPulled     = "who-pulled"
	checkBlocked       = "blocked"
	checkWhatPulled    = "what-pulled"
	checkForwarded     = "forwarded"
	checkSpoofRejected = "spoof-rejected"
)

var ecosystemChecks = []string{
	checkInstall, checkLogged, checkCacheHit, checkWhoPulled,
	checkBlocked, checkWhatPulled, checkForwarded, checkSpoofRejected,
}

// checkTitles explains each column in the rendered matrix.
var checkTitles = map[string]string{
	checkInstall:       "the package manager installs a package through the proxy",
	checkLogged:        "the log shows the package, its version and the client address — and nothing for the index requests",
	checkCacheHit:      "a second machine's install is logged against its own address, served from cache",
	checkWhoPulled:     "filtering by the package lists exactly the machines that pulled it",
	checkBlocked:       "a denied package: the client fails and the attempt is logged with the refusing gate",
	checkWhatPulled:    "filtering by an address or a CIDR lists that machine's entries only",
	checkForwarded:     "behind the trusted proxy the client's own address is logged, with the proxy it came through",
	checkSpoofRejected: "an X-Forwarded-For header from an untrusted peer is ignored",
}

// The checks that span both ecosystems.
const (
	checkEcosystems = "ecosystem-filter"
	checkCSV        = "csv-export"
	checkCredential = "admin-credential"
	checkMetrics    = "metrics"
	checkHermetic   = "hermetic"
	checkRestart    = "survives-restart"
)

var commonChecks = []string{checkEcosystems, checkCSV, checkCredential, checkMetrics, checkHermetic, checkRestart}

const (
	statusPass    = "pass"
	statusFail    = "fail"
	statusSkipped = "skipped"
)

// checkResult is the outcome of one assertion.
type checkResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// ecosystemResult is one row of the matrix.
type ecosystemResult struct {
	Ecosystem  string        `json:"ecosystem"`
	Client     string        `json:"client"`
	RealClient bool          `json:"realClient"`
	Checks     []checkResult `json:"checks"`
}

// loggedEntry is one line of the download log as the proxy recorded it, reduced
// to what the suite is about.
type loggedEntry struct {
	ID          uint64 `json:"id"`
	ClientIP    string `json:"clientIp"`
	ForwardedBy string `json:"forwardedBy,omitempty"`
	Ecosystem   string `json:"ecosystem"`
	Package     string `json:"package"`
	Version     string `json:"version,omitempty"`
	Outcome     string `json:"outcome"`
	Gate        string `json:"gate,omitempty"`
	Cache       string `json:"cache,omitempty"`
	Bytes       int64  `json:"bytes"`
	UserAgent   string `json:"userAgent,omitempty"`
}

// report is the suite's artifact: the ecosystem × check matrix, the checks that
// span ecosystems, and the log itself.
type report struct {
	mu sync.Mutex

	GeneratedAt time.Time         `json:"generatedAt"`
	Passed      bool              `json:"passed"`
	Ecosystems  []ecosystemResult `json:"ecosystems"`
	Common      []checkResult     `json:"common"`
	Log         []loggedEntry     `json:"log"`
}

func newReport() *report {
	r := &report{GeneratedAt: time.Now().UTC()}
	for _, name := range commonChecks {
		r.Common = append(r.Common, checkResult{Name: name, Status: statusSkipped})
	}
	return r
}

// addEcosystem registers a row with every check "skipped", so a run that aborts
// early still reports a complete row.
func (r *report) addEcosystem(id string, inst installer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row := ecosystemResult{Ecosystem: id, Client: inst.describe(), RealClient: inst.real()}
	for _, name := range ecosystemChecks {
		row.Checks = append(row.Checks, checkResult{Name: name, Status: statusSkipped})
	}
	r.Ecosystems = append(r.Ecosystems, row)
}

// set records the outcome of a check; ecosystem "" addresses the common checks.
func (r *report) set(ecosystem, name, status, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	checks := r.Common
	for i := range r.Ecosystems {
		if r.Ecosystems[i].Ecosystem == ecosystem {
			checks = r.Ecosystems[i].Checks
		}
	}
	for i := range checks {
		if checks[i].Name == name {
			checks[i].Status, checks[i].Detail = status, detail
			return
		}
	}
	panic("downloadlog suite: unknown check " + ecosystem + "/" + name)
}

func (r *report) setLog(entries []dl.Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Log = r.Log[:0]
	// The API returns newest first; a log reads oldest first.
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		r.Log = append(r.Log, loggedEntry{
			ID: e.ID, ClientIP: e.ClientIP, ForwardedBy: e.ForwardedBy, Ecosystem: e.Ecosystem,
			Package: e.Package, Version: e.Version, Outcome: string(e.Outcome), Gate: e.Gate,
			Cache: e.Cache, Bytes: e.Bytes, UserAgent: e.UserAgent,
		})
	}
}

// finalize computes the overall verdict: every check of every ecosystem and
// every common check must have passed. A skipped check is not a pass — it means
// the suite did not get that far.
func (r *report) finalize() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var problems []string
	note := func(scope string, c checkResult) {
		if c.Status != statusPass {
			problems = append(problems, fmt.Sprintf("%s/%s: %s %s", scope, c.Name, c.Status, c.Detail))
		}
	}
	for _, eco := range r.Ecosystems {
		for _, c := range eco.Checks {
			note(eco.Ecosystem, c)
		}
	}
	for _, c := range r.Common {
		note("common", c)
	}
	r.Passed = len(problems) == 0 && len(r.Ecosystems) > 0
	return problems
}

func mark(status string) string {
	switch status {
	case statusPass:
		return "✓"
	case statusFail:
		return "✗"
	default:
		return "–"
	}
}

// markdown renders the report.
func (r *report) markdown() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	b.WriteString("# Download log — integration matrix\n\n")
	b.WriteString("Which package was downloaded from which address: the real `pullthrough` binary, fronting stub\n")
	b.WriteString("registries, with the package managers of the Rust and Go ecosystems as clients. Every client\n")
	b.WriteString("machine reaches the proxy from its own source address; the log is read through the admin API,\n")
	b.WriteString("as the console's Downloads tab reads it. See `internal/e2e/downloadlog`.\n\n")
	verdict := "**FAILED**"
	if r.Passed {
		verdict = "**passed**"
	}
	fmt.Fprintf(&b, "Result: %s · generated %s\n\n", verdict, r.GeneratedAt.Format(time.RFC3339))

	b.WriteString("| Ecosystem | Client |")
	for _, name := range ecosystemChecks {
		b.WriteString(" " + name + " |")
	}
	b.WriteString("\n|---|---|")
	for range ecosystemChecks {
		b.WriteString(":-:|")
	}
	b.WriteString("\n")
	for _, eco := range r.Ecosystems {
		client := eco.Client
		if !eco.RealClient {
			client += " *(stand-in)*"
		}
		fmt.Fprintf(&b, "| %s | %s |", eco.Ecosystem, client)
		for _, c := range eco.Checks {
			b.WriteString(" " + mark(c.Status) + " |")
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	for _, name := range ecosystemChecks {
		fmt.Fprintf(&b, "- **%s** — %s\n", name, checkTitles[name])
	}

	b.WriteString("\n## Across both ecosystems\n\n| Check | Result | Detail |\n|---|:-:|---|\n")
	for _, c := range r.Common {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", c.Name, mark(c.Status), mdCell(c.Detail))
	}

	var failures []string
	for _, eco := range r.Ecosystems {
		for _, c := range eco.Checks {
			if c.Status == statusFail {
				failures = append(failures, fmt.Sprintf("- **%s / %s** — %s", eco.Ecosystem, c.Name, mdCell(c.Detail)))
			}
		}
	}
	if len(failures) > 0 {
		b.WriteString("\n## Failures\n\n" + strings.Join(failures, "\n") + "\n")
	}

	b.WriteString("\n## What the log recorded\n\n")
	b.WriteString("The download log at the end of the run, oldest entry first, as returned by `GET /admin/api/downloads`.\n\n")
	b.WriteString("| # | Client address | Forwarded by | Ecosystem | Package | Version | Outcome | Cache | Bytes | Client |\n")
	b.WriteString("|--:|---|---|---|---|---|---|---|--:|---|\n")
	for _, e := range r.Log {
		outcome := e.Outcome
		if e.Gate != "" {
			outcome += " (" + e.Gate + ")"
		}
		cache := e.Cache
		if e.Outcome == string(dl.OutcomeBlocked) {
			cache = ""
		}
		fmt.Fprintf(&b, "| %d | `%s` | %s | %s | `%s` | %s | %s | %s | %d | %s |\n",
			e.ID, e.ClientIP, code(e.ForwardedBy), e.Ecosystem, e.Package, e.Version, outcome, cache, e.Bytes, mdCell(clientTool(e.UserAgent)))
	}
	return b.String()
}

func code(s string) string {
	if s == "" {
		return ""
	}
	return "`" + s + "`"
}

// clientTool shortens a User-Agent to the tool and version.
func clientTool(ua string) string {
	if i := strings.IndexByte(ua, ' '); i > 0 {
		return ua[:i]
	}
	return ua
}

// mdCell makes a string safe inside a Markdown table cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "|", "\\|")
}

// write stores the report as download-log-matrix.{md,json} in the report
// directory, when one is configured, and returns the Markdown path.
func (r *report) write() (string, error) {
	dir := os.Getenv(envReportDir)
	if dir == "" {
		dir = os.Getenv(envAttachments)
	}
	if dir == "" {
		return "", nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	md := r.markdown()
	r.mu.Lock()
	data, err := json.MarshalIndent(r, "", "  ")
	r.mu.Unlock()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "download-log-matrix.json"), append(data, '\n'), 0o644); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "download-log-matrix.md")
	return path, os.WriteFile(path, []byte(md), 0o644)
}
