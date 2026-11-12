//go:build integration
// +build integration

package userlinks

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
	checkInstall    = "install"
	checkAttributed = "attributed"
	checkTwoUsers   = "two-users"
	checkNoLeak     = "no-leak"
	checkRevoked    = "revoked"
)

var ecosystemChecks = []string{checkInstall, checkAttributed, checkTwoUsers, checkNoLeak, checkRevoked}

// checkTitles explains each column in the rendered matrix.
var checkTitles = map[string]string{
	checkInstall:    "a signed-in user's package manager installs a package through their personal address, configured with the page's snippet",
	checkAttributed: "the download log names the user and the link; the client never left its personal address",
	checkTwoUsers:   "a second user installs the same package from the same machine: the log tells them apart",
	checkNoLeak:     "the link is not in the files the client wrote that people commit (lock file, manifest)",
	checkRevoked:    "after the user revokes the link, the client fails and nothing is served",
}

// The checks that span ecosystems.
const (
	checkSignIn      = "sign-in"
	checkAnonymous   = "anonymous-stays-anonymous"
	checkLastUse     = "page-shows-last-use"
	checkAdmin       = "admin-api"
	checkRefused     = "refused-links"
	checkReplica     = "second-replica"
	checkRestart     = "survives-restart"
	checkRevokeUser  = "revoke-user"
	checkAccess      = "access-control"
	checkCredential  = "link-as-credential"
	checkPathAuth    = "link-in-path-with-auth"
	checkDockerLogin = "docker-login"
	checkGitHeader   = "git-credential"
	checkMetrics     = "metrics"
	checkTokenSecret = "token-is-nowhere"
)

var commonChecks = []string{
	checkSignIn, checkAnonymous, checkLastUse, checkAdmin, checkRefused, checkReplica, checkRestart,
	checkRevokeUser, checkAccess, checkCredential, checkPathAuth, checkDockerLogin, checkGitHeader, checkMetrics, checkTokenSecret,
}

var commonTitles = map[string]string{
	checkSignIn:      "a user signs in through the identity provider (authorization-code flow with PKCE) and creates a link",
	checkAnonymous:   "a download without a link is recorded without an identity",
	checkLastUse:     "the user's page shows when, from where and with which tool each link was last used",
	checkAdmin:       "the admin API lists the links and summarizes the downloads per user",
	checkRefused:     "an unknown, a mistyped and a misplaced link are refused — never served anonymously",
	checkReplica:     "a second replica sharing the registry honours a new link at once and its revocation within the refresh interval",
	checkRestart:     "links and sign-in sessions survive a restart of the proxy",
	checkRevokeUser:  "an operator revokes everything issued to a user: links and session end, on every replica",
	checkAccess:      "with client authentication on, a link authenticates and its user's groups decide what they may pull",
	checkCredential:  "the link works as an ordinary credential with the real npm, and then no URL carries it",
	checkPathAuth:    "with client authentication on, the real cargo — which presents no token for crate downloads — installs through a link in the path, as the link's user",
	checkDockerLogin: "`docker login` with the link's token as the password authenticates the Docker Engine, and then no image name carries it",
	checkGitHeader:   "git clones under the repository's ordinary URL with the page's credential configuration, and with the token as an HTTP Basic password",
	checkMetrics:     "the metrics count links, sign-ins, requests by outcome and rewritten documents",
	checkTokenSecret: "no link's token is in anything a proxy wrote or sent: logs, audit log, download log, registry, upstream requests",
}

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
	Ecosystem string        `json:"ecosystem"`
	Client    string        `json:"client"`
	Checks    []checkResult `json:"checks"`
}

// loggedEntry is one line of the download log as the proxy recorded it, reduced
// to what the suite is about.
type loggedEntry struct {
	ID         uint64 `json:"id"`
	ClientIP   string `json:"clientIp"`
	Subject    string `json:"subject,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
	AuthMethod string `json:"authMethod,omitempty"`
	Link       string `json:"link,omitempty"`
	Ecosystem  string `json:"ecosystem"`
	Package    string `json:"package"`
	Version    string `json:"version,omitempty"`
	Outcome    string `json:"outcome"`
	Cache      string `json:"cache,omitempty"`
	UserAgent  string `json:"userAgent,omitempty"`
}

// report is the suite's artifact: the ecosystem × check matrix, the checks that
// span ecosystems, and the download log itself.
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
func (r *report) addEcosystem(id, client string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row := ecosystemResult{Ecosystem: id, Client: client}
	for _, name := range ecosystemChecks {
		row.Checks = append(row.Checks, checkResult{Name: name, Status: statusSkipped})
	}
	r.Ecosystems = append(r.Ecosystems, row)
}

func (r *report) set(ecosystem, check, status, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.Common
	if ecosystem != "" {
		for i := range r.Ecosystems {
			if r.Ecosystems[i].Ecosystem == ecosystem {
				list = r.Ecosystems[i].Checks
			}
		}
	}
	for i := range list {
		if list[i].Name == check {
			list[i].Status, list[i].Detail = status, detail
		}
	}
}

func (r *report) setLog(entries []dl.Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Log = r.Log[:0]
	for i := len(entries) - 1; i >= 0; i-- { // oldest first
		e := entries[i]
		r.Log = append(r.Log, loggedEntry{
			ID: e.ID, ClientIP: e.ClientIP, Subject: e.Subject, Tenant: e.Tenant, AuthMethod: e.AuthMethod, Link: e.Link,
			Ecosystem: e.Ecosystem, Package: e.Package, Version: e.Version, Outcome: string(e.Outcome), Cache: e.Cache,
			UserAgent: e.UserAgent,
		})
	}
}

func mark(status string) string {
	switch status {
	case statusPass:
		return "✅"
	case statusFail:
		return "❌"
	default:
		return "—"
	}
}

// markdown renders the report.
func (r *report) markdown() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	b.WriteString("# Personal cache links — integration matrix\n\n")
	fmt.Fprintf(&b, "Generated %s by `go test -tags integration ./internal/e2e/userlinks/`: the real proxy binary, an OpenID Connect "+
		"identity provider that signs real ID tokens, stub registries on loopback, and the real package managers configured with "+
		"the snippet the links page hands out.\n\n", r.GeneratedAt.Format(time.RFC3339))
	if r.Passed {
		b.WriteString("**Result: passed.**\n\n")
	} else {
		b.WriteString("**Result: FAILED.**\n\n")
	}

	b.WriteString("## Per ecosystem\n\n| Ecosystem | Client |")
	for _, c := range ecosystemChecks {
		b.WriteString(" " + c + " |")
	}
	b.WriteString("\n|---|---|")
	for range ecosystemChecks {
		b.WriteString(":-:|")
	}
	b.WriteString("\n")
	for _, row := range r.Ecosystems {
		fmt.Fprintf(&b, "| %s | %s |", row.Ecosystem, row.Client)
		for _, c := range row.Checks {
			b.WriteString(" " + mark(c.Status) + " |")
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	for _, c := range ecosystemChecks {
		fmt.Fprintf(&b, "- **%s** — %s\n", c, checkTitles[c])
	}

	b.WriteString("\n## Across ecosystems\n\n| Check | Result | What it holds |\n|---|:-:|---|\n")
	for _, c := range r.Common {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", c.Name, mark(c.Status), commonTitles[c.Name])
	}

	var failures []string
	for _, row := range r.Ecosystems {
		for _, c := range row.Checks {
			if c.Status == statusFail {
				failures = append(failures, fmt.Sprintf("- `%s` / `%s`: %s", row.Ecosystem, c.Name, c.Detail))
			}
		}
	}
	for _, c := range r.Common {
		if c.Status == statusFail {
			failures = append(failures, fmt.Sprintf("- `%s`: %s", c.Name, c.Detail))
		}
	}
	if len(failures) > 0 {
		b.WriteString("\n## Failures\n\n" + strings.Join(failures, "\n") + "\n")
	}

	b.WriteString("\n## The download log, as the first proxy recorded it\n\n")
	b.WriteString("Every client ran on the same machine: the address column cannot tell the users apart. The user column can.\n\n")
	b.WriteString("| # | Client IP | User | Team | Via | Link | Ecosystem | Package | Outcome | Cache | Client tool |\n|--:|---|---|---|---|---|---|---|---|---|---|\n")
	for _, e := range r.Log {
		pkg := e.Package
		if e.Version != "" {
			pkg += "@" + e.Version
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", e.ID, e.ClientIP, orDash(e.Subject), orDash(e.Tenant),
			orDash(e.AuthMethod), orDash(e.Link), e.Ecosystem, pkg, e.Outcome, orDash(e.Cache), orDash(firstWord(e.UserAgent)))
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}

// write stores the report as Markdown and JSON in dir.
func (r *report) write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "user-links-matrix.md"), []byte(r.markdown()), 0o644); err != nil {
		return err
	}
	r.mu.Lock()
	data, err := json.MarshalIndent(r, "", "  ")
	r.mu.Unlock()
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "user-links-matrix.json"), append(data, '\n'), 0o644)
}
