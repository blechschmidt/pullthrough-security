// Package forge opens — or brings up to date — the pull request (GitHub) or
// merge request (GitLab) of a repository maintenance branch (Task 182). The
// maintenance updater pushes its commit of updated lock files to a branch of
// the tracked repository and then calls Ensure, which keeps exactly one open
// request from that branch to the base branch: it opens one when there is
// none, and otherwise updates the open one's title and description and adds
// the labels it is missing. A request somebody closed or merged is left alone
// — the next update opens a new one.
//
// The client talks to the forges' REST APIs (GitHub's v3 with API version
// 2022-11-28, GitLab's v4) with a token. The token travels in a request header
// only, never follows a redirect to another host, and never appears in an
// error, even when a server echoes it back. What the API answers is untrusted:
// responses are bounded, and the text of an API error is cleaned before it is
// quoted.
package forge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Kind is a forge's API flavour.
type Kind string

const (
	// GitHub is github.com or GitHub Enterprise Server (REST API v3).
	GitHub Kind = "github"
	// GitLab is gitlab.com or a self-managed GitLab (REST API v4).
	GitLab Kind = "gitlab"
)

const (
	// DefaultGitHubAPIURL and DefaultGitLabAPIURL are the APIs of github.com
	// and gitlab.com. GitHub Enterprise Server's is https://<host>/api/v3, a
	// self-managed GitLab's https://<host>/api/v4.
	DefaultGitHubAPIURL = "https://api.github.com"
	DefaultGitLabAPIURL = "https://gitlab.com/api/v4"

	// GitHubBodyLimit is the longest pull request description GitHub accepts
	// (65536 characters). A longer one is cut, with a note, to this many
	// bytes — never more characters, however GitHub counts them.
	GitHubBodyLimit = 65536
	// GitLabBodyLimit is the longest merge request description sent to
	// GitLab, in bytes: well below GitLab's own limit of 1,048,576
	// characters, so that its answers stay within maxResponseBytes.
	GitLabBodyLimit = 262144

	// maxTitleRunes bounds a title: GitLab accepts 255 characters, and a
	// draft prefix may come on top.
	maxTitleRunes = 240
	// maxResponseBytes bounds a response body.
	maxResponseBytes = 4 << 20
	// maxRedirects bounds the redirects followed (on the API's own host).
	maxRedirects = 5

	defaultUserAgent = "pullthrough-security"
	defaultTimeout   = 30 * time.Second
	gitHubAPIVersion = "2022-11-28"
	draftPrefix      = "Draft: "
)

// Config configures a Client.
type Config struct {
	Kind Kind
	// APIURL is the API's base URL; empty is github.com's or gitlab.com's
	// (DefaultGitHubAPIURL, DefaultGitLabAPIURL). It must be https, or http on
	// a loopback address: the token is sent with every request.
	APIURL string
	// Repo names the repository: "owner/name" on GitHub; the project's path
	// ("group/subgroup/name") or numeric ID on GitLab. InferRepo derives it
	// from a clone URL.
	Repo string
	// Token authenticates: a GitHub token that may write pull requests (and
	// issues, for labels), or a GitLab token with the api scope.
	Token string
	// HTTPClient makes the requests; nil is a client with a 30-second
	// timeout. A copy of it is used, whose redirect policy refuses another
	// host.
	HTTPClient *http.Client
	// UserAgent identifies the client to the API (GitHub requires one);
	// default "pullthrough-security".
	UserAgent string
}

// PullRequestSpec is the pull or merge request Ensure keeps open.
type PullRequestSpec struct {
	// Head is the branch with the changes, in the repository itself (not a
	// fork); Base the branch they are to be merged into.
	Head, Base string
	// Title is one line (line breaks become spaces); a long one is cut.
	Title string
	// Body is the description, in Markdown; a long one is cut, with a note
	// saying so (GitHubBodyLimit, GitLabBodyLimit).
	Body string
	// Labels are added to the request (the forge creates a label the
	// repository does not have). Labels already on it stay; matching ignores
	// case. A label must not contain a comma or a control character.
	Labels []string
	// Draft opens a new request as a draft. An existing request's draft state
	// is never changed.
	Draft bool
}

// PullRequest is the request Ensure left open.
type PullRequest struct {
	// Number is the pull request's number (GitHub) or the merge request's
	// project-scoped IID (GitLab): the one in its URL.
	Number int
	// URL is the request's web page; empty when the forge named none, or
	// something that is not an http(s) URL.
	URL string
	// Created reports a request opened by this call; Updated, an existing
	// one whose title, description or labels this call changed.
	Created bool
	Updated bool
	// State is "open".
	State string
}

// APIError is an answer of the forge's API with a status the call did not
// expect.
type APIError struct {
	Method string
	// Path is the request's path (no query).
	Path   string
	Status int
	// Message is what the API said about it, cleaned and cut short; it never
	// holds the token.
	Message string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("forge: %s %s: HTTP %d", e.Method, e.Path, e.Status)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

// Client opens and updates the pull or merge requests of one repository. It
// is safe for concurrent use.
type Client struct {
	kind  Kind
	base  *url.URL
	repo  string
	owner string // GitHub: the owner part of repo
	name  string // GitHub: the name part of repo
	token string
	hc    *http.Client
	ua    string
}

// pathSegment is a component of a repository path on GitHub (an owner, a
// repository name) or GitLab (a group, a project): letters, digits, '_', '.'
// and '-', not starting with '-'.
var pathSegment = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,254}$`)

func validSegment(s string) bool { return pathSegment.MatchString(s) && s != "." && s != ".." }

var numericID = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

// New validates cfg and returns a client.
func New(cfg Config) (*Client, error) {
	c := &Client{kind: cfg.Kind, token: cfg.Token, ua: strings.TrimSpace(cfg.UserAgent)}
	apiURL := strings.TrimSpace(cfg.APIURL)
	switch cfg.Kind {
	case GitHub:
		if apiURL == "" {
			apiURL = DefaultGitHubAPIURL
		}
		owner, name, ok := strings.Cut(cfg.Repo, "/")
		if !ok || !validSegment(owner) || !validSegment(name) {
			return nil, fmt.Errorf("forge: GitHub repository %q is not \"owner/name\"", cfg.Repo)
		}
		c.owner, c.name, c.repo = owner, strings.TrimSuffix(name, ".git"), owner+"/"+strings.TrimSuffix(name, ".git")
		if !validSegment(c.name) {
			return nil, fmt.Errorf("forge: GitHub repository %q is not \"owner/name\"", cfg.Repo)
		}
	case GitLab:
		if apiURL == "" {
			apiURL = DefaultGitLabAPIURL
		}
		if !numericID.MatchString(cfg.Repo) {
			segs := strings.Split(cfg.Repo, "/")
			if len(segs) < 2 {
				return nil, fmt.Errorf("forge: GitLab project %q is neither a path (\"group/name\") nor a numeric ID", cfg.Repo)
			}
			for _, s := range segs {
				if !validSegment(s) {
					return nil, fmt.Errorf("forge: GitLab project %q is neither a path (\"group/name\") nor a numeric ID", cfg.Repo)
				}
			}
		}
		c.repo = cfg.Repo
	default:
		return nil, fmt.Errorf("forge: unknown kind %q (want %q or %q)", cfg.Kind, GitHub, GitLab)
	}

	if cfg.Token == "" {
		return nil, errors.New("forge: a token is required")
	}
	for _, r := range cfg.Token {
		if r <= ' ' || r == 0x7f {
			return nil, errors.New("forge: the token contains whitespace or a control character")
		}
	}
	base, err := parseAPIURL(apiURL)
	if err != nil {
		return nil, err
	}
	c.base = base

	hc := &http.Client{Timeout: defaultTimeout}
	if cfg.HTTPClient != nil {
		copied := *cfg.HTTPClient
		hc = &copied
	}
	hc.CheckRedirect = sameHostRedirects
	c.hc = hc
	if c.ua == "" {
		c.ua = defaultUserAgent
	}
	return c, nil
}

// parseAPIURL checks an API base URL: https (or http on a loopback address),
// with a host, without credentials, a query or a fragment.
func parseAPIURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("forge: API URL: %w", err)
	}
	switch {
	case u.Host == "" || u.Opaque != "":
		return nil, fmt.Errorf("forge: API URL %q has no host", s)
	case u.User != nil:
		return nil, errors.New("forge: the API URL must not carry credentials (the token is configured on its own)")
	case u.RawQuery != "" || u.Fragment != "":
		return nil, fmt.Errorf("forge: API URL %q must not have a query or a fragment", s)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("forge: API URL %q is plain http: the token would cross the network in the clear (use https)", s)
		}
	default:
		return nil, fmt.Errorf("forge: API URL %q is not http(s)", s)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sameHostRedirects follows a redirect on the API's own scheme and host only,
// and only one that keeps the method. Go forwards every header on a redirect —
// Authorization only to the same domain, but GitLab's PRIVATE-TOKEN to any —
// so the token must not follow one anywhere else; and Go turns a POST, PATCH
// or PUT answered with 301, 302 or 303 into a GET, whose 200 would pass for a
// successful update.
func sameHostRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("forge: too many redirects")
	}
	first := via[0]
	if req.URL.Scheme != first.URL.Scheme || !strings.EqualFold(req.URL.Host, first.URL.Host) {
		return fmt.Errorf("forge: refusing to follow a redirect to %s://%s", req.URL.Scheme, req.URL.Host)
	}
	if req.Method != first.Method {
		return fmt.Errorf("forge: refusing a redirect that turns %s into %s", first.Method, req.Method)
	}
	return nil
}

// Ensure opens a pull/merge request from spec.Head to spec.Base or — when an
// open one for the same head and base exists — updates its title and body and
// adds the labels it is missing. It never reopens a closed or merged request;
// it opens a new one instead.
//
// When the request was opened or updated but a later step failed (adding the
// labels), the request is returned together with the error; the next call
// finishes the work.
func (c *Client) Ensure(ctx context.Context, spec PullRequestSpec) (PullRequest, error) {
	spec, err := c.prepare(spec)
	if err != nil {
		return PullRequest{}, err
	}
	if c.kind == GitHub {
		return c.ensureGitHub(ctx, spec)
	}
	return c.ensureGitLab(ctx, spec)
}

// prepare checks a spec and brings it into the shape the forge stores: a
// one-line title, a description within the forge's limit, labels without
// duplicates.
func (c *Client) prepare(spec PullRequestSpec) (PullRequestSpec, error) {
	for _, b := range []struct{ what, name string }{{"head", spec.Head}, {"base", spec.Base}} {
		if !validBranch(b.name) {
			return spec, fmt.Errorf("forge: %s branch %q is not a branch name", b.what, b.name)
		}
	}
	if spec.Head == spec.Base {
		return spec, fmt.Errorf("forge: head and base are the same branch %q", spec.Head)
	}
	spec.Title = oneLine(spec.Title)
	if spec.Title == "" {
		return spec, errors.New("forge: the title is empty")
	}
	if utf8.RuneCountInString(spec.Title) > maxTitleRunes {
		spec.Title = string([]rune(spec.Title)[:maxTitleRunes-1]) + "…"
	}
	limit := GitHubBodyLimit
	forgeName := "GitHub"
	if c.kind == GitLab {
		limit, forgeName = GitLabBodyLimit, "GitLab"
	}
	spec.Body = truncateBody(strings.ToValidUTF8(spec.Body, "\uFFFD"), limit,
		fmt.Sprintf("\n\n---\n*This description was cut short: the whole of it exceeded the %d bytes sent to %s.*\n", limit, forgeName))

	var labels []string
	for _, l := range spec.Labels {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.ContainsRune(l, ',') || strings.IndexFunc(l, unicode.IsControl) >= 0 || !utf8.ValidString(l) {
			return spec, fmt.Errorf("forge: label %q contains a comma or a control character", l)
		}
		if !containsFold(labels, l) {
			labels = append(labels, l)
		}
	}
	spec.Labels = labels
	return spec, nil
}

// validBranch accepts a branch name as a forge API takes it: no whitespace or
// control characters, nothing a ref could not be named.
func validBranch(b string) bool {
	if b == "" || len(b) > 255 || strings.HasPrefix(b, "-") || strings.Contains(b, "..") || !utf8.ValidString(b) {
		return false
	}
	for _, r := range b {
		if r <= ' ' || r == 0x7f || unicode.IsControl(r) || strings.ContainsRune("~^:?*[\\", r) {
			return false
		}
	}
	return true
}

// oneLine turns line breaks and other control characters into spaces and
// trims the result.
func oneLine(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	return strings.TrimSpace(strings.Join(strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || r == ' '
	}), " "))
}

// truncateBody cuts body to at most limit bytes including note, at the end of
// a line when one is near, else at a character boundary.
func truncateBody(body string, limit int, note string) string {
	if len(body) <= limit {
		return body
	}
	cut := limit - len(note)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(body[cut]) {
		cut--
	}
	if nl := strings.LastIndexByte(body[:cut], '\n'); nl >= 0 && cut-nl < 4096 {
		cut = nl
	}
	return body[:cut] + note
}

func containsFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(e string) bool { return strings.EqualFold(e, s) })
}

// missingLabels returns the labels of want that have is lacks.
func missingLabels(have, want []string) []string {
	var out []string
	for _, l := range want {
		if !containsFold(have, l) {
			out = append(out, l)
		}
	}
	return out
}

// sameText compares two descriptions the way a forge may store them: line
// endings normalized, trailing whitespace ignored.
func sameText(a, b string) bool {
	norm := func(s string) string {
		return strings.TrimRightFunc(strings.ReplaceAll(s, "\r\n", "\n"), unicode.IsSpace)
	}
	return norm(a) == norm(b)
}

// webURL returns u when it is an absolute http(s) URL, else "".
func webURL(u string) string {
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
		return ""
	}
	return u
}

// --- GitHub ---

type ghPull struct {
	Number  int     `json:"number"`
	HTMLURL string  `json:"html_url"`
	State   string  `json:"state"`
	Title   string  `json:"title"`
	Body    *string `json:"body"`
	Labels  []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Head struct {
		Ref  string `json:"ref"`
		Repo *struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

func (p *ghPull) body() string {
	if p.Body == nil {
		return ""
	}
	return *p.Body
}

func (p *ghPull) labelNames() []string {
	names := make([]string, 0, len(p.Labels))
	for _, l := range p.Labels {
		names = append(names, l.Name)
	}
	return names
}

func (c *Client) ghPath(rest string) string {
	return "/repos/" + url.PathEscape(c.owner) + "/" + url.PathEscape(c.name) + rest
}

func (c *Client) ensureGitHub(ctx context.Context, spec PullRequestSpec) (PullRequest, error) {
	pr, err := c.findGitHub(ctx, spec)
	if err != nil {
		return PullRequest{}, err
	}
	if pr == nil {
		var created ghPull
		err := c.call(ctx, http.MethodPost, c.ghPath("/pulls"), nil, map[string]any{
			"title": spec.Title, "head": spec.Head, "base": spec.Base, "body": spec.Body, "draft": spec.Draft,
		}, &created, http.StatusCreated)
		if err == nil {
			if created.Number <= 0 {
				return PullRequest{}, errors.New("forge: GitHub answered the new pull request without a number")
			}
			out := PullRequest{Number: created.Number, URL: webURL(created.HTMLURL), Created: true, State: "open"}
			if len(spec.Labels) > 0 {
				if err := c.ghAddLabels(ctx, created.Number, spec.Labels); err != nil {
					return out, err
				}
			}
			return out, nil
		}
		// GitHub answers 422 when an open pull request for the head and base
		// exists — one opened since the lookup.
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnprocessableEntity {
			return PullRequest{}, err
		}
		if pr, _ = c.findGitHub(ctx, spec); pr == nil {
			return PullRequest{}, err
		}
	}

	out := PullRequest{Number: pr.Number, URL: webURL(pr.HTMLURL), State: "open"}
	if pr.Title != spec.Title || !sameText(pr.body(), spec.Body) {
		var updated ghPull
		if err := c.call(ctx, http.MethodPatch, c.ghPath("/pulls/"+strconv.Itoa(pr.Number)), nil,
			map[string]any{"title": spec.Title, "body": spec.Body}, &updated, http.StatusOK); err != nil {
			return PullRequest{}, err
		}
		out.Updated = true
		if u := webURL(updated.HTMLURL); u != "" {
			out.URL = u
		}
	}
	if missing := missingLabels(pr.labelNames(), spec.Labels); len(missing) > 0 {
		if err := c.ghAddLabels(ctx, pr.Number, missing); err != nil {
			return out, err
		}
		out.Updated = true
	}
	return out, nil
}

// findGitHub returns the open pull request from the repository's own head
// branch to the base, or nil.
func (c *Client) findGitHub(ctx context.Context, spec PullRequestSpec) (*ghPull, error) {
	var pulls []ghPull
	q := url.Values{"state": {"open"}, "head": {c.owner + ":" + spec.Head}, "base": {spec.Base}, "per_page": {"100"}}
	if err := c.call(ctx, http.MethodGet, c.ghPath("/pulls"), q, nil, &pulls, http.StatusOK); err != nil {
		return nil, err
	}
	for i := range pulls {
		p := &pulls[i]
		// The filter is the server's; the match is checked here too. A pull
		// request from a fork's branch of the same name is not ours.
		if p.Number > 0 && p.State == "open" && p.Head.Ref == spec.Head && p.Base.Ref == spec.Base &&
			p.Head.Repo != nil && strings.EqualFold(p.Head.Repo.FullName, c.repo) {
			return p, nil
		}
	}
	return nil, nil
}

func (c *Client) ghAddLabels(ctx context.Context, number int, labels []string) error {
	return c.call(ctx, http.MethodPost, c.ghPath("/issues/"+strconv.Itoa(number)+"/labels"), nil,
		map[string]any{"labels": labels}, nil, http.StatusOK)
}

// --- GitLab ---

type glMR struct {
	IID             int      `json:"iid"`
	WebURL          string   `json:"web_url"`
	State           string   `json:"state"`
	Title           string   `json:"title"`
	Description     *string  `json:"description"`
	Draft           bool     `json:"draft"`
	WorkInProgress  bool     `json:"work_in_progress"`
	Labels          []string `json:"labels"`
	SourceBranch    string   `json:"source_branch"`
	TargetBranch    string   `json:"target_branch"`
	SourceProjectID int64    `json:"source_project_id"`
	TargetProjectID int64    `json:"target_project_id"`
}

func (m *glMR) description() string {
	if m.Description == nil {
		return ""
	}
	return *m.Description
}

// isDraft reports a draft merge request: GitLab derives the state from a
// title prefix, and reports it as draft (work_in_progress before 13.x).
func (m *glMR) isDraft() bool {
	if m.Draft || m.WorkInProgress {
		return true
	}
	t := strings.ToLower(m.Title)
	return strings.HasPrefix(t, "draft:") || strings.HasPrefix(t, "[draft]") || strings.HasPrefix(t, "(draft)")
}

// glPath is a path under the project: its ID, or its path with the slashes
// encoded ("group%2Fname"), as GitLab requires.
func (c *Client) glPath(rest string) string {
	return "/projects/" + url.PathEscape(c.repo) + rest
}

func (c *Client) ensureGitLab(ctx context.Context, spec PullRequestSpec) (PullRequest, error) {
	mr, err := c.findGitLab(ctx, spec)
	if err != nil {
		return PullRequest{}, err
	}
	if mr == nil {
		title := spec.Title
		if spec.Draft {
			title = draftPrefix + title
		}
		payload := map[string]any{"source_branch": spec.Head, "target_branch": spec.Base, "title": title, "description": spec.Body}
		if len(spec.Labels) > 0 {
			payload["labels"] = strings.Join(spec.Labels, ",")
		}
		var created glMR
		err := c.call(ctx, http.MethodPost, c.glPath("/merge_requests"), nil, payload, &created, http.StatusCreated)
		if err == nil {
			if created.IID <= 0 {
				return PullRequest{}, errors.New("forge: GitLab answered the new merge request without an IID")
			}
			return PullRequest{Number: created.IID, URL: webURL(created.WebURL), Created: true, State: "open"}, nil
		}
		// GitLab answers 409 when an open merge request for the source and
		// target exists — one opened since the lookup.
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
			return PullRequest{}, err
		}
		if mr, _ = c.findGitLab(ctx, spec); mr == nil {
			return PullRequest{}, err
		}
	}

	out := PullRequest{Number: mr.IID, URL: webURL(mr.WebURL), State: "open"}
	// The title carries the draft state: a draft stays one.
	title := spec.Title
	if mr.isDraft() {
		title = draftPrefix + title
	}
	missing := missingLabels(mr.Labels, spec.Labels)
	if mr.Title == title && sameText(mr.description(), spec.Body) && len(missing) == 0 {
		return out, nil
	}
	payload := map[string]any{"title": title, "description": spec.Body}
	if len(missing) > 0 {
		payload["add_labels"] = strings.Join(missing, ",")
	}
	var updated glMR
	if err := c.call(ctx, http.MethodPut, c.glPath("/merge_requests/"+strconv.Itoa(mr.IID)), nil, payload, &updated, http.StatusOK); err != nil {
		return PullRequest{}, err
	}
	out.Updated = true
	if u := webURL(updated.WebURL); u != "" {
		out.URL = u
	}
	return out, nil
}

// findGitLab returns the open merge request from the project's own source
// branch to the target, or nil.
func (c *Client) findGitLab(ctx context.Context, spec PullRequestSpec) (*glMR, error) {
	var mrs []glMR
	q := url.Values{"state": {"opened"}, "source_branch": {spec.Head}, "target_branch": {spec.Base}, "per_page": {"100"}}
	if err := c.call(ctx, http.MethodGet, c.glPath("/merge_requests"), q, nil, &mrs, http.StatusOK); err != nil {
		return nil, err
	}
	for i := range mrs {
		m := &mrs[i]
		// A merge request from a fork's branch of the same name is not ours.
		if m.IID > 0 && m.State == "opened" && m.SourceBranch == spec.Head && m.TargetBranch == spec.Base &&
			m.SourceProjectID == m.TargetProjectID {
			return m, nil
		}
	}
	return nil, nil
}

// --- requests ---

// call sends one API request with a JSON body (in, unless nil) and decodes a
// JSON answer into out (unless nil). An answer with a status other than want
// is an *APIError.
func (c *Client) call(ctx context.Context, method, path string, query url.Values, in, out any, want ...int) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("forge: encoding the request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path, query), body)
	if err != nil {
		return fmt.Errorf("forge: %s %s: %s", method, path, c.clean(err.Error()))
	}
	req.Header.Set("User-Agent", c.ua)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch c.kind {
	case GitHub:
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", gitHubAPIVersion)
	case GitLab:
		req.Header.Set("PRIVATE-TOKEN", c.token)
		req.Header.Set("Accept", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("forge: %s %s: %s", method, path, c.clean(err.Error()))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("forge: %s %s: reading the answer: %s", method, path, c.clean(err.Error()))
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("forge: %s %s: the answer exceeds %d bytes", method, path, maxResponseBytes)
	}
	if !slices.Contains(want, resp.StatusCode) {
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Message: c.clean(apiMessage(data))}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("forge: %s %s: decoding the answer: %s", method, path, c.clean(err.Error()))
		}
	}
	return nil
}

// endpoint is the URL of an API path below the base URL. path is already
// escaped (a GitLab project path keeps its "%2F"), so it is set as the URL's
// raw path.
func (c *Client) endpoint(path string, query url.Values) string {
	u := *c.base
	u.RawPath = c.base.EscapedPath() + path
	if p, err := url.PathUnescape(u.RawPath); err == nil {
		u.Path = p
	}
	u.RawQuery = query.Encode()
	return u.String()
}

// clean makes text quoted from a response or an error fit for an error
// message: the token removed, control characters turned into spaces, the
// whole cut short.
func (c *Client) clean(s string) string {
	if len(c.token) >= 4 {
		s = strings.ReplaceAll(s, c.token, "***")
	}
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == ' ' }), " ")
	if len(s) > 300 {
		n := 300
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n] + "…"
	}
	return s
}

// apiMessage pulls what an API error says out of its JSON: GitHub's
// "message" and the "message" of each of its "errors"; GitLab's "message"
// (a string, a list, or an object of lists) or "error". Anything else is
// quoted as it is.
func apiMessage(data []byte) string {
	var v struct {
		Message any `json:"message"`
		Error   any `json:"error"`
		Errors  any `json:"errors"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		if len(data) > 300 {
			data = data[:300]
		}
		return string(data)
	}
	var parts []string
	for _, x := range []any{v.Message, v.Error, v.Errors} {
		collectStrings(x, &parts)
	}
	return strings.Join(parts, "; ")
}

// collectStrings appends the text of a decoded JSON value: strings as they
// are, the "message" of an object that has one, the values of one that does
// not (by key). At most 20 pieces are taken.
func collectStrings(v any, out *[]string) {
	if len(*out) >= 20 {
		return
	}
	switch x := v.(type) {
	case string:
		if s := strings.TrimSpace(x); s != "" {
			*out = append(*out, s)
		}
	case []any:
		for _, e := range x {
			collectStrings(e, out)
		}
	case map[string]any:
		if m, ok := x["message"]; ok {
			collectStrings(m, out)
			return
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			var sub []string
			collectStrings(x[k], &sub)
			for _, s := range sub {
				*out = append(*out, k+" "+s)
			}
		}
	}
}

// --- clone URLs ---

// InferRepo derives the repository's name on its forge from a clone URL:
// "owner/name" on github.com, the project path ("group/sub/name") elsewhere.
// It reads https://, http://, ssh:// and git:// URLs and scp-like ones
// ("git@github.com:owner/name.git"); ok is false for anything else — a local
// path, a file:// URL, a URL with fewer than two path components, or one
// whose components are not names a forge would give a repository.
func InferRepo(cloneURL string) (string, bool) {
	s := strings.TrimSpace(cloneURL)
	if s == "" || strings.HasPrefix(s, "-") || strings.ContainsAny(s, " \t\r\n\x00") {
		return "", false
	}
	var host, path string
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return "", false
		}
		switch strings.ToLower(u.Scheme) {
		case "https", "http", "ssh", "git", "git+ssh", "ssh+git":
		default:
			return "", false
		}
		host, path = u.Hostname(), u.Path
	} else {
		// scp-like: [user@]host:path. A colon after a slash makes a local
		// path, and so does a one-letter "host" (a Windows drive).
		hostPart, p, ok := strings.Cut(s, ":")
		if !ok || strings.Contains(hostPart, "/") {
			return "", false
		}
		if i := strings.LastIndexByte(hostPart, '@'); i >= 0 {
			hostPart = hostPart[i+1:]
		}
		if len(hostPart) < 2 {
			return "", false
		}
		host, path = hostPart, p
	}
	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")
	segs := strings.Split(path, "/")
	if len(segs) < 2 {
		return "", false
	}
	for _, seg := range segs {
		if !validSegment(seg) {
			return "", false
		}
	}
	switch strings.ToLower(host) {
	case "github.com", "www.github.com", "ssh.github.com":
		if len(segs) != 2 {
			return "", false
		}
	}
	return strings.Join(segs, "/"), true
}
