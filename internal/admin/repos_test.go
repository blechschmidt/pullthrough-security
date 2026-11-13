package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/repos"
)

const (
	reposAdminToken    = "repos-admin-token-0123456789abcdef"
	reposOperatorToken = "repos-operator-token-0123456789abc"
	reposViewerToken   = "repos-viewer-token-0123456789abcd"
	reposTeamBToken    = "repos-team-b-admin-0123456789abcd"
)

func newReposAdmin(t *testing.T) (*Server, *repos.Service) {
	t.Helper()
	svc, err := repos.New(context.Background(), repos.Config{
		Repos: []repos.Repo{
			{Name: "widgets", URL: "https://git.example/acme/widgets.git", Tenant: "team-a"},
			{Name: "gadgets", URL: "https://git.example/other/gadgets.git", Tenant: "team-b"},
		},
	}, repos.Options{Store: repos.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := adminauth.New(adminauth.Options{
		Prefix: "/admin",
		StaticTokens: []adminauth.StaticToken{
			{Name: "admin", Roles: []string{"admin"}, Secret: reposAdminToken},
			{Name: "operator", Roles: []string{"operator"}, Secret: reposOperatorToken},
			{Name: "viewer", Roles: []string{"viewer"}, Secret: reposViewerToken},
			{Name: "team-b-admin", Roles: []string{"admin"}, Secret: reposTeamBToken, Tenant: "team-b"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return newTestServer(t, Options{Repos: svc, AdminAuth: auth}), svc
}

func TestReposCapabilities(t *testing.T) {
	cases := []struct {
		method, path string
		want         adminauth.Capability
	}{
		{http.MethodGet, "/api/repos", adminauth.CapRead},
		{http.MethodGet, "/api/repos/releases", adminauth.CapRead},
		{http.MethodGet, "/api/repos/lookup", adminauth.CapRead},
		{http.MethodPost, "/api/repos", adminauth.CapAdminister},
		{http.MethodPost, "/api/repos/remove", adminauth.CapAdminister},
		{http.MethodPost, "/api/repos/sync", adminauth.CapOperate},
		{http.MethodPost, "/api/repos/pin", adminauth.CapOperate},
	}
	for _, c := range cases {
		if got := requiredCapability(c.method, c.path); got != c.want {
			t.Errorf("%s %s = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

func TestReposDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	if code := getJSON(t, srv, "/admin/api/repos", "", nil); code != http.StatusNotFound {
		t.Fatalf("disabled registry = %d", code)
	}
}

func TestReposRegistrationThroughTheAPI(t *testing.T) {
	srv, svc := newReposAdmin(t)
	body := `{"name":"tools","url":"https://git.example/acme/tools.git","credentialsRef":"env://TOOLS_TOKEN","tenant":"team-a","lockfiles":["go.*"]}`

	// Registering needs the administer capability.
	if rec := postJSONAs(t, srv, "/admin/api/repos", reposOperatorToken, body); rec.Code != http.StatusForbidden {
		t.Fatalf("operator registered a repository: %d", rec.Code)
	}
	rec := postJSONAs(t, srv, "/admin/api/repos", reposAdminToken, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin: %d %s", rec.Code, rec.Body)
	}
	var added repos.Repo
	_ = json.Unmarshal(rec.Body.Bytes(), &added)
	if added.Source != repos.SourceAPI || added.CreatedBy != "admin" {
		t.Fatalf("added %+v", added)
	}
	// Invalid and conflicting registrations are explained.
	if rec := postJSONAs(t, srv, "/admin/api/repos", reposAdminToken, `{"name":"x","url":"ext::sh -c id"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("ext:: URL: %d", rec.Code)
	}
	if rec := postJSONAs(t, srv, "/admin/api/repos", reposAdminToken, body); rec.Code != http.StatusConflict {
		t.Fatalf("twice: %d", rec.Code)
	}
	if rec := postJSONAs(t, srv, "/admin/api/repos", reposAdminToken, `{"name":"y","url":"https://x/y.git","token":"t"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown field (a token in the body) is refused: %d", rec.Code)
	}
	// A tenant-bound identity registers for its own tenant only.
	if rec := postJSONAs(t, srv, "/admin/api/repos", reposTeamBToken, `{"name":"z","url":"https://x/z.git","tenant":"team-a"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("team-b registered for team-a: %d", rec.Code)
	}
	// ... and cannot choose the roles the release pinner fetches with: they
	// decide which upstreams it may reach.
	if rec := postJSONAs(t, srv, "/admin/api/repos", reposTeamBToken, `{"name":"z","url":"https://x/z.git","roles":["everything"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("team-b chose the release pinner's roles: %d", rec.Code)
	}
	rec = postJSONAs(t, srv, "/admin/api/repos", reposTeamBToken, `{"name":"z","url":"https://x/z.git"}`)
	var own repos.Repo
	_ = json.Unmarshal(rec.Body.Bytes(), &own)
	if rec.Code != http.StatusCreated || own.Tenant != "team-b" {
		t.Fatalf("team-b's own: %d %s", rec.Code, rec.Body)
	}
	// Removing: administer, and not across tenants.
	if rec := postJSONAs(t, srv, "/admin/api/repos/remove?name=tools", reposTeamBToken, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("team-b removed team-a's repository: %d", rec.Code)
	}
	if rec := postJSONAs(t, srv, "/admin/api/repos/remove?name=widgets", reposAdminToken, ""); rec.Code != http.StatusConflict {
		t.Fatalf("a configured repository was removed: %d", rec.Code)
	}
	if rec := postJSONAs(t, srv, "/admin/api/repos/remove?name=tools", reposAdminToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	list, _ := svc.List(context.Background(), "team-a")
	for _, r := range list {
		if r.Name == "tools" && r.State != "removed" {
			t.Fatalf("tools: %+v", r)
		}
	}
}

// A tenant-bound identity sees its own tenant's repositories and releases,
// whatever the query string says.
func TestReposTenantHardScope(t *testing.T) {
	srv, _ := newReposAdmin(t)
	var out struct {
		Repositories []repos.RepoView `json:"repositories"`
	}
	if code := getJSON(t, srv, "/admin/api/repos?tenant=team-a", reposTeamBToken, &out); code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	if len(out.Repositories) != 1 || out.Repositories[0].Name != "gadgets" {
		t.Fatalf("team-b sees %+v", out.Repositories)
	}
	for _, path := range []string{"/admin/api/repos/show?name=widgets", "/admin/api/repos/tags?name=widgets", "/admin/api/repos/releases?name=widgets"} {
		if code := getJSON(t, srv, path+"&tenant=team-a", reposTeamBToken, nil); code != http.StatusNotFound {
			t.Errorf("%s = %d for team-b", path, code)
		}
	}
	// A global identity may narrow to a tenant.
	if code := getJSON(t, srv, "/admin/api/repos?tenant=team-a", reposViewerToken, &out); code != http.StatusOK || len(out.Repositories) != 1 || out.Repositories[0].Name != "widgets" {
		t.Fatalf("global narrowed: %d %+v", code, out.Repositories)
	}
	if code := getJSON(t, srv, "/admin/api/repos", reposViewerToken, &out); code != http.StatusOK || len(out.Repositories) != 2 {
		t.Fatalf("global: %d %+v", code, out.Repositories)
	}
	// Queries validate their input.
	if code := getJSON(t, srv, "/admin/api/repos/releases?commit=xyz", reposViewerToken, nil); code != http.StatusBadRequest {
		t.Fatalf("bad commit: %d", code)
	}
	if code := getJSON(t, srv, "/admin/api/repos/lookup?coordinate=lodash", reposViewerToken, nil); code != http.StatusBadRequest {
		t.Fatalf("bad coordinate: %d", code)
	}
	if code := getJSON(t, srv, "/admin/api/repos/lookup?coordinate=npm/lodash@4.17.21", reposViewerToken, nil); code != http.StatusOK {
		t.Fatalf("lookup: %d", code)
	}
}
