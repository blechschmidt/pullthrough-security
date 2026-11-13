package forge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

const testToken = "s3cr3t-TOKEN-value-0123456789"

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// stubRequest is a pull or merge request a stub forge keeps.
type stubRequest struct {
	Number int
	State  string // GitHub: open, closed; GitLab: opened, closed, merged
	Title  string
	Body   string
	Draft  bool
	Labels []string
	Head   string
	// HeadRepo is the repository the head branch is in (GitHub), or whether
	// it is a fork's (GitLab).
	HeadRepo string
	Fork     bool
	Base     string
}

// stubForge is the state both stubs share.
type stubForge struct {
	mu       sync.Mutex
	requests []*stubRequest
	calls    []string
	// loose makes listings return every request, as a server whose filter
	// matches less precisely would: the client must pick the right one.
	loose bool
	// hideOnce makes the next listing come back empty, as a lookup racing
	// another creator does.
	hideOnce bool
	// failStatus answers every request with this status and a message that
	// echoes the token.
	failStatus int
	lastBody   map[string]any
}

func (s *stubForge) record(r *http.Request) map[string]any {
	s.calls = append(s.calls, r.Method+" "+r.URL.Path)
	var in map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&in)
	}
	if in != nil {
		s.lastBody = in
	}
	return in
}

func (s *stubForge) find(n int) *stubRequest {
	for _, p := range s.requests {
		if p.Number == n {
			return p
		}
	}
	return nil
}

func (s *stubForge) callList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *stubForge) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls, s.lastBody = nil, nil
}

// --- GitHub stub ---

type githubStub struct {
	stubForge
	repo string
}

func newGitHub(t *testing.T) (*githubStub, *Client) {
	t.Helper()
	s := &githubStub{repo: "o/r"}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := New(Config{Kind: GitHub, APIURL: srv.URL, Repo: "o/r", Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func (s *githubStub) render(p *stubRequest) map[string]any {
	labels := []any{}
	for _, l := range p.Labels {
		labels = append(labels, map[string]any{"name": l})
	}
	var body any
	if p.Body != "" {
		body = p.Body
	}
	return map[string]any{
		"number": p.Number, "html_url": "https://github.com/" + s.repo + "/pull/" + strconv.Itoa(p.Number),
		"state": p.State, "title": p.Title, "body": body, "draft": p.Draft, "labels": labels,
		"head": map[string]any{"ref": p.Head, "repo": map[string]any{"full_name": p.HeadRepo}},
		"base": map[string]any{"ref": p.Base, "repo": map[string]any{"full_name": s.repo}},
	}
}

func (s *githubStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := s.record(r)
	if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("Accept") != "application/vnd.github+json" ||
		r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" || r.Header.Get("User-Agent") == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"message": "Bad credentials"})
		return
	}
	if s.failStatus != 0 {
		writeJSON(w, s.failStatus, map[string]any{
			"message": "it broke for " + r.Header.Get("Authorization"),
			"errors":  []any{map[string]any{"resource": "PullRequest", "message": "token " + testToken}},
		})
		return
	}
	prefix := "/repos/" + s.repo
	rest, _ := strings.CutPrefix(r.URL.Path, prefix)
	switch {
	case r.Method == http.MethodGet && rest == "/pulls":
		q := r.URL.Query()
		out := []any{}
		if s.hideOnce {
			s.hideOnce = false
			writeJSON(w, http.StatusOK, out)
			return
		}
		for _, p := range s.requests {
			owner, _, _ := strings.Cut(p.HeadRepo, "/")
			if s.loose || (p.State == q.Get("state") && owner+":"+p.Head == q.Get("head") && p.Base == q.Get("base")) {
				out = append(out, s.render(p))
			}
		}
		writeJSON(w, http.StatusOK, out)
	case r.Method == http.MethodPost && rest == "/pulls":
		head, _ := in["head"].(string)
		base, _ := in["base"].(string)
		for _, p := range s.requests {
			if p.State == "open" && p.HeadRepo == s.repo && p.Head == head && p.Base == base {
				writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"message": "Validation Failed",
					"errors": []any{map[string]any{"resource": "PullRequest", "code": "custom", "message": "A pull request already exists for o:" + head + "."}}})
				return
			}
		}
		title, _ := in["title"].(string)
		body, _ := in["body"].(string)
		draft, _ := in["draft"].(bool)
		p := &stubRequest{Number: len(s.requests) + 1, State: "open", Title: title, Body: body, Draft: draft, Head: head, HeadRepo: s.repo, Base: base}
		s.requests = append(s.requests, p)
		writeJSON(w, http.StatusCreated, s.render(p))
	case r.Method == http.MethodPatch && strings.HasPrefix(rest, "/pulls/"):
		n, _ := strconv.Atoi(strings.TrimPrefix(rest, "/pulls/"))
		p := s.find(n)
		if p == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "Not Found"})
			return
		}
		if t, ok := in["title"].(string); ok {
			p.Title = t
		}
		if b, ok := in["body"].(string); ok {
			p.Body = b
		}
		writeJSON(w, http.StatusOK, s.render(p))
	case r.Method == http.MethodPost && strings.HasPrefix(rest, "/issues/") && strings.HasSuffix(rest, "/labels"):
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rest, "/issues/"), "/labels"))
		p := s.find(n)
		if p == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "Not Found"})
			return
		}
		labels, _ := in["labels"].([]any)
		for _, l := range labels {
			p.Labels = append(p.Labels, l.(string))
		}
		writeJSON(w, http.StatusOK, s.render(p)["labels"])
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	}
}

var spec = PullRequestSpec{
	Head: "pullthrough/update-main", Base: "main",
	Title: "Update dependencies", Body: "Bumps a from 1.0.0 to 1.1.0.",
	Labels: []string{"dependencies", "security"}, Draft: true,
}

func TestGitHubOpensThenUpdates(t *testing.T) {
	s, c := newGitHub(t)
	ctx := context.Background()
	pr, err := c.Ensure(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if want := (PullRequest{Number: 1, URL: "https://github.com/o/r/pull/1", Created: true, State: "open"}); pr != want {
		t.Fatalf("%+v, want %+v", pr, want)
	}
	if got := s.callList(); !reflect.DeepEqual(got, []string{"GET /repos/o/r/pulls", "POST /repos/o/r/pulls", "POST /repos/o/r/issues/1/labels"}) {
		t.Fatalf("calls %v", got)
	}
	p := s.requests[0]
	if p.Title != spec.Title || p.Body != spec.Body || !p.Draft || p.Head != spec.Head || p.Base != "main" || !reflect.DeepEqual(p.Labels, spec.Labels) {
		t.Fatalf("opened %+v", p)
	}

	// Nothing to change: one lookup, nothing else.
	s.reset()
	pr, err = c.Ensure(ctx, spec)
	if err != nil || pr.Created || pr.Updated || pr.Number != 1 {
		t.Fatalf("%+v %v", pr, err)
	}
	if got := s.callList(); len(got) != 1 {
		t.Fatalf("calls %v", got)
	}

	// A new description and labels: the existing request is updated, and
	// only the label it lacks is added ("Dependencies" is "dependencies").
	s.reset()
	next := spec
	next.Body = "Bumps a and b."
	next.Labels = []string{"Dependencies", "ci"}
	pr, err = c.Ensure(ctx, next)
	if err != nil || pr.Created || !pr.Updated || pr.Number != 1 {
		t.Fatalf("%+v %v", pr, err)
	}
	if p.Body != next.Body || !p.Draft || !reflect.DeepEqual(p.Labels, []string{"dependencies", "security", "ci"}) {
		t.Fatalf("updated %+v", p)
	}
	if len(s.requests) != 1 {
		t.Fatalf("%d pull requests", len(s.requests))
	}
}

// Closed pull requests and pull requests from a fork's branch of the same
// name are never taken over: a new one is opened.
func TestGitHubLeavesClosedAndForeignPullRequestsAlone(t *testing.T) {
	s, c := newGitHub(t)
	s.loose = true
	s.requests = []*stubRequest{
		{Number: 1, State: "closed", Title: "old", Head: spec.Head, HeadRepo: "o/r", Base: "main"},
		{Number: 2, State: "open", Title: "theirs", Head: spec.Head, HeadRepo: "fork/r", Base: "main"},
		{Number: 3, State: "open", Title: "other base", Head: spec.Head, HeadRepo: "o/r", Base: "release"},
	}
	pr, err := c.Ensure(context.Background(), spec)
	if err != nil || !pr.Created || pr.Number != 4 {
		t.Fatalf("%+v %v", pr, err)
	}
	for _, p := range s.requests[:3] {
		if p.Title == spec.Title || p.State == "open" && p.Number == 1 {
			t.Fatalf("pull request %d was touched: %+v", p.Number, p)
		}
	}
}

// Somebody opened the pull request between the lookup and the creation:
// GitHub refuses the second one, and the existing one is updated instead.
func TestGitHubCreateRace(t *testing.T) {
	s, c := newGitHub(t)
	s.requests = []*stubRequest{{Number: 1, State: "open", Title: "old title", Head: spec.Head, HeadRepo: "o/r", Base: "main", Labels: []string{"security"}}}
	s.hideOnce = true
	pr, err := c.Ensure(context.Background(), spec)
	if err != nil || pr.Created || !pr.Updated || pr.Number != 1 {
		t.Fatalf("%+v %v", pr, err)
	}
	if p := s.requests[0]; p.Title != spec.Title || !reflect.DeepEqual(p.Labels, []string{"security", "dependencies"}) {
		t.Fatalf("%+v", p)
	}
}

func TestGitHubTruncatesLongBodies(t *testing.T) {
	s, c := newGitHub(t)
	long := spec
	long.Body = strings.Repeat("| dependency | ä → ö |\n", 3000) // 75 000 bytes, two-byte characters
	if _, err := c.Ensure(context.Background(), long); err != nil {
		t.Fatal(err)
	}
	body := s.requests[0].Body
	if len(body) > GitHubBodyLimit || !utf8.ValidString(body) || !strings.Contains(body, "cut short") {
		t.Fatalf("body of %d bytes, valid UTF-8 %v", len(body), utf8.ValidString(body))
	}
	if !strings.HasSuffix(strings.SplitN(body, "\n\n---\n", 2)[0], "|") {
		t.Fatal("the body was not cut at the end of a line")
	}
	// The same long description again changes nothing.
	s.reset()
	pr, err := c.Ensure(context.Background(), long)
	if err != nil || pr.Updated {
		t.Fatalf("%+v %v", pr, err)
	}
}

// --- GitLab stub ---

type gitlabStub struct {
	stubForge
	project   string
	projectID int
	rawURIs   []string
}

func newGitLab(t *testing.T, repo string) (*gitlabStub, *Client) {
	t.Helper()
	s := &gitlabStub{project: "group/sub/name", projectID: 1234}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := New(Config{Kind: GitLab, APIURL: srv.URL + "/api/v4/", Repo: repo, Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func (s *gitlabStub) render(m *stubRequest) map[string]any {
	source := s.projectID
	if m.Fork {
		source = 99
	}
	labels := append([]string{}, m.Labels...)
	return map[string]any{
		"iid": m.Number, "web_url": "https://gitlab.example.com/" + s.project + "/-/merge_requests/" + strconv.Itoa(m.Number),
		"state": m.State, "title": m.Title, "description": m.Body, "draft": strings.HasPrefix(m.Title, "Draft: "),
		"labels": labels, "source_branch": m.Head, "target_branch": m.Base,
		"source_project_id": source, "target_project_id": s.projectID,
	}
}

func (s *gitlabStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawURIs = append(s.rawURIs, r.Method+" "+r.RequestURI)
	in := s.record(r)
	if r.Header.Get("PRIVATE-TOKEN") != testToken || r.Header.Get("Authorization") != "" || r.Header.Get("User-Agent") == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"message": "401 Unauthorized"})
		return
	}
	if s.failStatus != 0 {
		writeJSON(w, s.failStatus, map[string]any{"message": map[string]any{"base": []any{"it broke for " + r.Header.Get("PRIVATE-TOKEN")}}})
		return
	}
	// The project is named by its ID or its URL-encoded path, never by a
	// path with bare slashes.
	raw := r.URL.EscapedPath()
	rest, ok := strings.CutPrefix(raw, "/api/v4/projects/"+url.PathEscape(s.project))
	if !ok {
		rest, ok = strings.CutPrefix(raw, "/api/v4/projects/"+strconv.Itoa(s.projectID))
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"message": "404 Project Not Found"})
		return
	}
	switch {
	case r.Method == http.MethodGet && rest == "/merge_requests":
		q := r.URL.Query()
		out := []any{}
		if s.hideOnce {
			s.hideOnce = false
			writeJSON(w, http.StatusOK, out)
			return
		}
		for _, m := range s.requests {
			if s.loose || (m.State == q.Get("state") && m.Head == q.Get("source_branch") && m.Base == q.Get("target_branch")) {
				out = append(out, s.render(m))
			}
		}
		writeJSON(w, http.StatusOK, out)
	case r.Method == http.MethodPost && rest == "/merge_requests":
		head, _ := in["source_branch"].(string)
		base, _ := in["target_branch"].(string)
		for _, m := range s.requests {
			if m.State == "opened" && !m.Fork && m.Head == head && m.Base == base {
				writeJSON(w, http.StatusConflict, map[string]any{"message": []any{"Another open merge request already exists for this source branch: !" + strconv.Itoa(m.Number)}})
				return
			}
		}
		title, _ := in["title"].(string)
		body, _ := in["description"].(string)
		m := &stubRequest{Number: len(s.requests) + 1, State: "opened", Title: title, Body: body, Head: head, Base: base}
		if l, _ := in["labels"].(string); l != "" {
			m.Labels = strings.Split(l, ",")
		}
		s.requests = append(s.requests, m)
		writeJSON(w, http.StatusCreated, s.render(m))
	case r.Method == http.MethodPut && strings.HasPrefix(rest, "/merge_requests/"):
		n, _ := strconv.Atoi(strings.TrimPrefix(rest, "/merge_requests/"))
		m := s.find(n)
		if m == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "404 Not found"})
			return
		}
		if t, ok := in["title"].(string); ok {
			m.Title = t
		}
		if b, ok := in["description"].(string); ok {
			m.Body = b
		}
		if l, _ := in["add_labels"].(string); l != "" {
			m.Labels = append(m.Labels, strings.Split(l, ",")...)
		}
		writeJSON(w, http.StatusOK, s.render(m))
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"message": "404 Not Found"})
	}
}

func TestGitLabOpensThenUpdates(t *testing.T) {
	s, c := newGitLab(t, "group/sub/name")
	ctx := context.Background()
	pr, err := c.Ensure(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if want := (PullRequest{Number: 1, URL: "https://gitlab.example.com/group/sub/name/-/merge_requests/1", Created: true, State: "open"}); pr != want {
		t.Fatalf("%+v, want %+v", pr, want)
	}
	m := s.requests[0]
	if m.Title != "Draft: "+spec.Title || m.Body != spec.Body || !reflect.DeepEqual(m.Labels, spec.Labels) {
		t.Fatalf("opened %+v", m)
	}
	for _, u := range s.rawURIs {
		if !strings.Contains(u, " /api/v4/projects/group%2Fsub%2Fname/merge_requests") {
			t.Fatalf("request %q does not name the project by its encoded path", u)
		}
	}

	// Unchanged: one lookup.
	s.reset()
	if pr, err := c.Ensure(ctx, spec); err != nil || pr.Created || pr.Updated {
		t.Fatalf("%+v %v", pr, err)
	}
	if got := s.callList(); len(got) != 1 {
		t.Fatalf("calls %v", got)
	}

	// A new description and labels: the draft stays a draft, only the
	// missing label is added.
	s.reset()
	next := spec
	next.Body = "Bumps a and b."
	next.Labels = []string{"Dependencies", "ci"}
	next.Draft = false
	pr, err = c.Ensure(ctx, next)
	if err != nil || !pr.Updated || pr.Number != 1 {
		t.Fatalf("%+v %v", pr, err)
	}
	if m.Title != "Draft: "+spec.Title || m.Body != next.Body || !reflect.DeepEqual(m.Labels, []string{"dependencies", "security", "ci"}) {
		t.Fatalf("updated %+v", m)
	}
	if s.lastBody["add_labels"] != "ci" {
		t.Fatalf("sent %v", s.lastBody)
	}

	// Somebody marked it ready: it is not turned back into a draft.
	m.Title = spec.Title
	s.reset()
	pr, err = c.Ensure(ctx, PullRequestSpec{Head: spec.Head, Base: spec.Base, Title: spec.Title, Body: next.Body, Draft: true})
	if err != nil || pr.Updated || m.Title != spec.Title {
		t.Fatalf("%+v %v, title %q", pr, err, m.Title)
	}
}

func TestGitLabLeavesClosedMergedAndForkRequestsAlone(t *testing.T) {
	s, c := newGitLab(t, "group/sub/name")
	s.loose = true
	s.requests = []*stubRequest{
		{Number: 1, State: "closed", Title: "closed", Head: spec.Head, Base: "main"},
		{Number: 2, State: "merged", Title: "merged", Head: spec.Head, Base: "main"},
		{Number: 3, State: "opened", Title: "fork", Head: spec.Head, Base: "main", Fork: true},
	}
	pr, err := c.Ensure(context.Background(), spec)
	if err != nil || !pr.Created || pr.Number != 4 {
		t.Fatalf("%+v %v", pr, err)
	}
	for _, m := range s.requests[:3] {
		if strings.Contains(m.Title, spec.Title) {
			t.Fatalf("merge request %d was touched", m.Number)
		}
	}
}

func TestGitLabCreateRace(t *testing.T) {
	s, c := newGitLab(t, "group/sub/name")
	s.requests = []*stubRequest{{Number: 7, State: "opened", Title: "old", Head: spec.Head, Base: "main"}}
	s.hideOnce = true
	pr, err := c.Ensure(context.Background(), spec)
	if err != nil || pr.Created || !pr.Updated || pr.Number != 7 {
		t.Fatalf("%+v %v", pr, err)
	}
	if m := s.requests[0]; m.Title != spec.Title || !reflect.DeepEqual(m.Labels, spec.Labels) {
		t.Fatalf("%+v", m)
	}
}

func TestGitLabNumericProjectID(t *testing.T) {
	s, c := newGitLab(t, "1234")
	if _, err := c.Ensure(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.rawURIs[0], " /api/v4/projects/1234/merge_requests?") {
		t.Fatalf("requests %v", s.rawURIs)
	}
}

// API errors carry the status and what the API said, never the token — not
// even when the server echoes it back.
func TestErrorsNeverCarryTheToken(t *testing.T) {
	gh, ghc := newGitHub(t)
	gl, glc := newGitLab(t, "group/sub/name")
	for _, tc := range []struct {
		name   string
		stub   *stubForge
		client *Client
	}{{"github", &gh.stubForge, ghc}, {"gitlab", &gl.stubForge, glc}} {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusUnprocessableEntity, http.StatusInternalServerError} {
			tc.stub.mu.Lock()
			tc.stub.failStatus = status
			tc.stub.mu.Unlock()
			_, err := tc.client.Ensure(context.Background(), spec)
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Status != status {
				t.Fatalf("%s %d: %v", tc.name, status, err)
			}
			if strings.Contains(err.Error(), testToken) || !strings.Contains(apiErr.Message, "it broke for") || !strings.Contains(apiErr.Message, "***") {
				t.Fatalf("%s %d: %q", tc.name, status, err)
			}
		}
	}

	// A wrong token, an unreachable server, an answer too large.
	bad, err := New(Config{Kind: GitHub, APIURL: ghc.base.String(), Repo: "o/r", Token: testToken + "x"})
	if err != nil {
		t.Fatal(err)
	}
	gh.mu.Lock()
	gh.failStatus = 0
	gh.mu.Unlock()
	if _, err := bad.Ensure(context.Background(), spec); err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("wrong token: %v", err)
	}
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[" + strings.Repeat(" ", maxResponseBytes) + "]"))
	}))
	defer huge.Close()
	hc, _ := New(Config{Kind: GitHub, APIURL: huge.URL, Repo: "o/r", Token: testToken})
	if _, err := hc.Ensure(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("huge answer: %v", err)
	}
	huge.Close()
	if _, err := hc.Ensure(context.Background(), spec); err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("unreachable: %v", err)
	}
}

// The token never follows a redirect to another host, and a redirect that
// would turn an update into a GET is refused.
func TestRedirects(t *testing.T) {
	var mu sync.Mutex
	var leaked []string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		leaked = append(leaked, r.Header.Get("PRIVATE-TOKEN")+r.Header.Get("Authorization"))
		mu.Unlock()
		writeJSON(w, http.StatusOK, []any{})
	}))
	defer elsewhere.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()
	for _, kind := range []Kind{GitHub, GitLab} {
		c, err := New(Config{Kind: kind, APIURL: redirecting.URL, Repo: "o/r", Token: testToken})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Ensure(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "refusing to follow a redirect") {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	if len(leaked) != 0 {
		t.Fatalf("the other host was asked: %q", leaked)
	}

	// On the API's own host: a POST answered with 301 would come back as a
	// GET of a pull request; that is not an opened pull request.
	sameHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/pulls":
			writeJSON(w, http.StatusOK, []any{})
		case r.Method == http.MethodPost:
			http.Redirect(w, r, "/repos/o/r/pulls/7", http.StatusMovedPermanently)
		default:
			writeJSON(w, http.StatusCreated, map[string]any{"number": 7, "html_url": "https://github.com/o/r/pull/7", "state": "open"})
		}
	}))
	defer sameHost.Close()
	c, _ := New(Config{Kind: GitHub, APIURL: sameHost.URL, Repo: "o/r", Token: testToken})
	if pr, err := c.Ensure(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "turns POST into GET") {
		t.Fatalf("%+v %v", pr, err)
	}
}

func TestNewValidation(t *testing.T) {
	ok := Config{Kind: GitHub, Repo: "o/r", Token: testToken}
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"unknown kind", func(c *Config) { c.Kind = "gitea" }},
		{"no token", func(c *Config) { c.Token = "" }},
		{"token with a newline", func(c *Config) { c.Token = "abc\nX-Evil: 1" }},
		{"github repo of one part", func(c *Config) { c.Repo = "o" }},
		{"github repo of three parts", func(c *Config) { c.Repo = "o/r/x" }},
		{"github repo climbing", func(c *Config) { c.Repo = "../admin" }},
		{"github repo with a query", func(c *Config) { c.Repo = "o/r?x=1" }},
		{"gitlab project of one part", func(c *Config) { c.Kind, c.Repo = GitLab, "name" }},
		{"gitlab project climbing", func(c *Config) { c.Kind, c.Repo = GitLab, "group/../name" }},
		{"plain http elsewhere", func(c *Config) { c.APIURL = "http://gitlab.example.com/api/v4" }},
		{"credentials in the URL", func(c *Config) { c.APIURL = "https://user:pass@api.github.com" }},
		{"not http", func(c *Config) { c.APIURL = "ftp://api.github.com" }},
		{"no host", func(c *Config) { c.APIURL = "https:///api" }},
		{"query", func(c *Config) { c.APIURL = "https://api.github.com/?x=1" }},
	} {
		cfg := ok
		tc.edit(&cfg)
		if c, err := New(cfg); err == nil {
			t.Fatalf("%s: accepted (%+v)", tc.name, c)
		} else if strings.Contains(err.Error(), "pass") && strings.Contains(err.Error(), "user") {
			t.Fatalf("%s: the error quotes credentials: %v", tc.name, err)
		}
	}
	for _, cfg := range []Config{
		ok,
		{Kind: GitHub, Repo: "o/r.git", Token: testToken, APIURL: "https://ghe.example.com/api/v3/"},
		{Kind: GitLab, Repo: "group/sub/name", Token: testToken},
		{Kind: GitLab, Repo: "1234", Token: testToken, APIURL: "http://127.0.0.1:8080/api/v4"},
		{Kind: GitLab, Repo: "g/p", Token: testToken, APIURL: "http://localhost/api/v4"},
	} {
		if _, err := New(cfg); err != nil {
			t.Fatalf("%+v: %v", cfg, err)
		}
	}
	// The default API, and a caller's client left as it was.
	hc := &http.Client{}
	c, err := New(Config{Kind: GitLab, Repo: "g/p", Token: testToken, HTTPClient: hc})
	if err != nil || c.base.String() != DefaultGitLabAPIURL || hc.CheckRedirect != nil || c.hc == hc {
		t.Fatalf("%v %v", c.base, err)
	}
}

func TestSpecChecks(t *testing.T) {
	_, c := newGitHub(t)
	for _, tc := range []struct {
		name string
		edit func(*PullRequestSpec)
	}{
		{"same branch", func(s *PullRequestSpec) { s.Base = s.Head }},
		{"empty head", func(s *PullRequestSpec) { s.Head = "" }},
		{"head with a space", func(s *PullRequestSpec) { s.Head = "a b" }},
		{"head option", func(s *PullRequestSpec) { s.Head = "-x" }},
		{"base with dots", func(s *PullRequestSpec) { s.Base = "a..b" }},
		{"empty title", func(s *PullRequestSpec) { s.Title = " \n " }},
		{"label with a comma", func(s *PullRequestSpec) { s.Labels = []string{"a,b"} }},
		{"label with a newline", func(s *PullRequestSpec) { s.Labels = []string{"a\nb"} }},
	} {
		sp := spec
		tc.edit(&sp)
		if _, err := c.Ensure(context.Background(), sp); err == nil || !strings.HasPrefix(err.Error(), "forge: ") {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	sp := spec
	sp.Title = "Update\r\ndependencies\tnow " + strings.Repeat("é", 300)
	sp.Labels = []string{" dependencies ", "Dependencies", "", "ci"}
	got, err := c.prepare(sp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.Title, "Update dependencies now é") || utf8.RuneCountInString(got.Title) != maxTitleRunes || !strings.HasSuffix(got.Title, "…") {
		t.Fatalf("title %q (%d runes)", got.Title, utf8.RuneCountInString(got.Title))
	}
	if !reflect.DeepEqual(got.Labels, []string{"dependencies", "ci"}) {
		t.Fatalf("labels %q", got.Labels)
	}
}

func TestInferRepo(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/o/r.git":                       "o/r",
		"https://github.com/o/r":                           "o/r",
		"https://github.com/o/r/":                          "o/r",
		"https://x-access-token:tok@github.com/o/r.git":    "o/r",
		"git@github.com:o/r.git":                           "o/r",
		"git@github.com:o/r":                               "o/r",
		"ssh://git@github.com/o/r.git":                     "o/r",
		"ssh://git@ssh.github.com:443/o/r.git":             "o/r",
		"ssh://git@gitlab.example.com/g/s/p.git":           "g/s/p",
		"ssh://git@gitlab.example.com:2222/g/s/p.git":      "g/s/p",
		"https://gitlab.com/group/sub/project.git":         "group/sub/project",
		"git@gitlab.example.com:group/project.git":         "group/project",
		"https://ghe.example.com/owner/my_repo.name-2.git": "owner/my_repo.name-2",
		"https://github.com/o":                             "",
		"https://github.com/o/r/pulls":                     "",
		"https://gitlab.com/g/p/-/tree/main":               "",
		"https://gitlab.com/g/../p":                        "",
		"https://gitlab.com/g/p?ref=x":                     "",
		"file:///srv/git/o/r.git":                          "",
		"/srv/git/o/r.git":                                 "",
		"./o/r":                                            "",
		"C:/repos/o/r":                                     "",
		"ext::ssh -o x host/o/r":                           "",
		"-uhelper:o/r":                                     "",
		"":                                                 "",
		"git@github.com:o/r .git":                          "",
	} {
		got, ok := InferRepo(in)
		if got != want || ok != (want != "") {
			t.Errorf("InferRepo(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}
