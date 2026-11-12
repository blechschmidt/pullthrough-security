package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

// newTestUserLinks returns a personal-links service holding a small, known set
// of links:
//
//	alice@example.com (platform)  laptop   active, used from 10.0.0.5
//	alice@example.com (platform)  ci       revoked
//	bob@example.com   (payments)  laptop   active, never used
func newTestUserLinks(t *testing.T) (*userlinks.Service, map[string]string) {
	t.Helper()
	svc, err := userlinks.New(userlinks.Config{PublicURL: "https://proxy.example.com", Store: userlinks.NewMemoryStore()})
	if err != nil {
		t.Fatalf("userlinks.New: %v", err)
	}
	ctx := context.Background()
	ids := map[string]string{}
	issue := func(key string, id userlinks.Identity, label string) string {
		token, _, info, err := svc.Issue(ctx, id, userlinks.IssueOptions{Label: label})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		ids[key] = info.ID
		return token
	}
	alice := userlinks.Identity{Subject: "alice@example.com", Name: "Alice", Team: "platform"}
	issue("alice-laptop", alice, "laptop")
	issue("alice-ci", alice, "ci")
	issue("bob-laptop", userlinks.Identity{Subject: "bob@example.com", Name: "Bob", Team: "payments"}, "laptop")
	svc.Registry().Touch(ids["alice-laptop"], "10.0.0.5", "npm/10.9.2")
	if _, err := svc.Revoke(ctx, ids["alice-ci"], "alice@example.com", "rotated", ""); err != nil {
		t.Fatal(err)
	}
	return svc, ids
}

func postJSONAs(t *testing.T, srv *Server, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestUserLinksEndpointLists(t *testing.T) {
	svc, ids := newTestUserLinks(t)
	srv := newTestServer(t, Options{UserLinks: svc})

	var resp userLinksResponse
	if code := getJSON(t, srv, "/admin/api/userlinks", "", &resp); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !resp.Enabled || resp.SignIn || resp.PageURL != "https://proxy.example.com/links/" || resp.PathPrefix != "/u" {
		t.Fatalf("response = %+v", resp)
	}
	if resp.Total != 3 || len(resp.Links) != 3 || resp.Registry.Active != 2 || resp.Registry.Revoked != 1 || resp.Registry.Users != 2 || !resp.Registry.Synced {
		t.Fatalf("total %d, %d links, registry %+v", resp.Total, len(resp.Links), resp.Registry)
	}
	// Newest first.
	if resp.Links[0].ID != ids["bob-laptop"] || resp.Links[2].ID != ids["alice-laptop"] {
		t.Fatalf("order = %s, %s, %s", resp.Links[0].Label, resp.Links[1].Label, resp.Links[2].Label)
	}
	used := resp.Links[2]
	if used.State != userlinks.StateActive || used.LastUsedAt == nil || used.LastAddr != "10.0.0.5" || used.LastAgent != "npm/10.9.2" {
		t.Fatalf("the used link = %+v", used)
	}
	revoked := resp.Links[1]
	if revoked.State != userlinks.StateRevoked || revoked.RevokedBy != "alice@example.com" || revoked.RevokeReason != "rotated" {
		t.Fatalf("the revoked link = %+v", revoked)
	}
	// Per user: the one with the most working links first, the more recently
	// active breaking ties.
	if len(resp.Users) != 2 || resp.Users[0].Subject != "alice@example.com" || resp.Users[0].Links != 2 || resp.Users[0].Active != 1 ||
		resp.Users[0].LastAddr != "10.0.0.5" || resp.Users[1].Subject != "bob@example.com" || resp.Users[1].LastUsedAt != nil {
		t.Fatalf("users = %+v", resp.Users)
	}

	// Filters.
	for query, want := range map[string]int{
		"?subject=alice@example.com":             2,
		"?subject=ALICE@Example.com":             2, // an e-mail address, whatever its capitals
		"?subject=alice":                         0,
		"?state=revoked":                         1,
		"?state=active":                          2,
		"?q=payments":                            1,
		"?q=LAPTOP":                              2,
		"?q=10.0.0.5":                            1,
		"?subject=bob@example.com&state=revoked": 0,
	} {
		var filtered userLinksResponse
		if code := getJSON(t, srv, "/admin/api/userlinks"+query, "", &filtered); code != http.StatusOK || filtered.Total != want {
			t.Errorf("%s: status %d, %d links, want %d", query, code, filtered.Total, want)
		}
	}
	// A limit cuts the list, not the totals.
	var limited userLinksResponse
	if code := getJSON(t, srv, "/admin/api/userlinks?limit=1", "", &limited); code != http.StatusOK || limited.Total != 3 || len(limited.Links) != 1 || len(limited.Users) != 2 {
		t.Fatalf("limit=1: status %d, total %d, %d links, %d users", code, limited.Total, len(limited.Links), len(limited.Users))
	}
	for _, bad := range []string{"?state=bogus", "?limit=0", "?limit=x"} {
		if code := getJSON(t, srv, "/admin/api/userlinks"+bad, "", nil); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, code)
		}
	}

	// No response carries a token or a token hash: the proxy has no tokens, and
	// the hashes are nobody's business.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/api/userlinks", nil))
	if body := rec.Body.String(); strings.Contains(body, "tokenHash") || strings.Contains(body, userlinks.TokenPrefix) {
		t.Fatalf("the listing leaks token material: %s", body)
	}
}

func TestUserLinksEndpointWhenDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp userLinksResponse
	if code := getJSON(t, srv, "/admin/api/userlinks", "", &resp); code != http.StatusOK || resp.Enabled || resp.Links == nil || resp.Users == nil {
		t.Fatalf("status %d, response %+v; want an empty, disabled answer with empty lists", code, resp)
	}
	for _, path := range []string{"/admin/api/userlinks/revoke", "/admin/api/userlinks/issue"} {
		if rec := postJSON(t, srv, path, `{"id":"0000000000000000"}`); rec.Code != http.StatusNotFound {
			t.Errorf("POST %s with the feature off = %d, want 404", path, rec.Code)
		}
	}
	// A typed nil service is the feature off, not a panic.
	var none *userlinks.Service
	srv = newTestServer(t, Options{UserLinks: none})
	if code := getJSON(t, srv, "/admin/api/userlinks", "", &resp); code != http.StatusOK || resp.Enabled {
		t.Fatalf("a nil service: status %d, enabled %v", code, resp.Enabled)
	}
}

func TestUserLinksRevoke(t *testing.T) {
	svc, ids := newTestUserLinks(t)
	audit := &recordingAudit{}
	srv := newTestServer(t, Options{UserLinks: svc, AuditLog: audit})

	// One link.
	rec := postJSON(t, srv, "/admin/api/userlinks/revoke", `{"id":"`+ids["bob-laptop"]+`","reason":"device lost"}`)
	var one struct {
		OK   bool           `json:"ok"`
		Link userlinks.Info `json:"link"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil || rec.Code != http.StatusOK || !one.OK {
		t.Fatalf("revoking a link: %d %s", rec.Code, rec.Body)
	}
	// Without admin SSO the actor is the anonymous "admin".
	if one.Link.State != userlinks.StateRevoked || one.Link.RevokedBy != "admin" || one.Link.RevokeReason != "device lost" {
		t.Fatalf("revoked link = %+v", one.Link)
	}

	// Everything of one user.
	rec = postJSON(t, srv, "/admin/api/userlinks/revoke", `{"subject":" alice@example.com ","reason":"left"}`)
	var all struct {
		OK      bool   `json:"ok"`
		Subject string `json:"subject"`
		Revoked int    `json:"revoked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &all); err != nil || rec.Code != http.StatusOK || all.Subject != "alice@example.com" || all.Revoked != 1 {
		t.Fatalf("revoking a user: %d %s", rec.Code, rec.Body)
	}
	if got := svc.Links(userlinks.Filter{State: userlinks.StateActive}); len(got) != 0 {
		t.Fatalf("%d links still work", len(got))
	}

	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"neither":           {`{}`, http.StatusBadRequest},
		"both":              {`{"id":"` + ids["bob-laptop"] + `","subject":"bob@example.com"}`, http.StatusBadRequest},
		"an unknown link":   {`{"id":"ffffffffffffffff"}`, http.StatusNotFound},
		"not a link id":     {`{"id":"../../etc/passwd"}`, http.StatusNotFound},
		"an unknown field":  {`{"id":"` + ids["bob-laptop"] + `","force":true}`, http.StatusBadRequest},
		"not JSON":          {`id=1`, http.StatusBadRequest},
		"a blank subject":   {`{"subject":"   "}`, http.StatusBadRequest},
		"revoking it again": {`{"id":"` + ids["bob-laptop"] + `"}`, http.StatusOK},
	} {
		if rec := postJSON(t, srv, "/admin/api/userlinks/revoke", tc.body); rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d (%s)", name, rec.Code, tc.want, rec.Body)
		}
	}
}

// Revoking is a POST. A GET of the same path — what a link in a page or an
// e-mail causes a browser to send — changes nothing.
func TestUserLinksRevokeIsNotAGet(t *testing.T) {
	svc, ids := newTestUserLinks(t)
	srv := newTestServer(t, Options{UserLinks: svc})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/api/userlinks/revoke?id="+ids["bob-laptop"], nil))
	if info, _ := svc.Registry().Get(ids["bob-laptop"]); info.State != userlinks.StateActive {
		t.Fatalf("a GET revoked the link (answered %d)", rec.Code)
	}
}

// Issuing a link names the identity it is for. On an admin surface that
// authenticates nobody, that would let anyone on the network write any name
// into the download log — and, with access control on, take any role.
func TestUserLinksIssueNeedsAnAuthenticatedSurface(t *testing.T) {
	svc, _ := newTestUserLinks(t)
	body := `{"subject":"ceo@example.com","roles":["admin"],"label":"x"}`

	open := newTestServer(t, Options{UserLinks: svc})
	rec := postJSON(t, open, "/admin/api/userlinks/issue", body)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "adminToken") {
		t.Fatalf("issuing on an unauthenticated admin surface: %d %s", rec.Code, rec.Body)
	}
	if got := svc.Links(userlinks.Filter{Subject: "ceo@example.com"}); len(got) != 0 {
		t.Fatal("a link was issued on an unauthenticated admin surface")
	}

	// With the admin token it works, and the response carries the token once.
	guarded := newTestServer(t, Options{UserLinks: svc, Token: "admin-token-0123456789"})
	if rec := postJSONAs(t, guarded, "/admin/api/userlinks/issue", "", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("issuing without the admin token: %d", rec.Code)
	}
	rec = postJSONAs(t, guarded, "/admin/api/userlinks/issue", "admin-token-0123456789",
		`{"subject":"ci-bot","team":"platform","roles":["reader"],"label":"pipeline","ttlDays":7}`)
	var issued struct {
		OK      bool           `json:"ok"`
		Token   string         `json:"token"`
		BaseURL string         `json:"baseUrl"`
		Link    userlinks.Info `json:"link"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil || rec.Code != http.StatusCreated {
		t.Fatalf("issuing: %d %s", rec.Code, rec.Body)
	}
	if !userlinks.WellFormed(issued.Token) || issued.BaseURL != "https://proxy.example.com/u/"+issued.Token {
		t.Fatalf("issued = %+v", issued)
	}
	if issued.Link.Subject != "ci-bot" || issued.Link.Team != "platform" || issued.Link.Label != "pipeline" ||
		issued.Link.IssuedBy != "admin" || issued.Link.ExpiresAt == nil || len(issued.Link.Roles) != 1 {
		t.Fatalf("issued link = %+v", issued.Link)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("the response with the token may be stored: Cache-Control %q", rec.Header().Get("Cache-Control"))
	}
	link, err := svc.Registry().Resolve(context.Background(), issued.Token)
	if err != nil || link.Subject != "ci-bot" {
		t.Fatalf("the issued link does not resolve: %+v, %v", link, err)
	}

	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"no subject":         {`{"label":"x"}`, http.StatusBadRequest},
		"a subject of marks": {`{"subject":"a‮b"}`, http.StatusBadRequest},
		"a negative ttl":     {`{"subject":"x","ttlDays":-1}`, http.StatusBadRequest},
		"an unknown field":   {`{"subject":"x","admin":true}`, http.StatusBadRequest},
	} {
		if rec := postJSONAs(t, guarded, "/admin/api/userlinks/issue", "admin-token-0123456789", tc.body); rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d (%s)", name, rec.Code, tc.want, rec.Body)
		}
	}
}

// Under RBAC: anyone who may read the console sees the links, an operator may
// take access away, and only an administrator may hand it out.
func TestUserLinksCapabilities(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         adminauth.Capability
	}{
		{http.MethodGet, "/api/userlinks", adminauth.CapRead},
		{http.MethodPost, "/api/userlinks/revoke", adminauth.CapOperate},
		{http.MethodPost, "/api/userlinks/issue", adminauth.CapAdminister},
	} {
		if got := requiredCapability(tc.method, tc.path); got != tc.want {
			t.Errorf("requiredCapability(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}

	svc, ids := newTestUserLinks(t)
	auth, err := adminauth.New(adminauth.Options{
		Prefix: "/admin",
		StaticTokens: []adminauth.StaticToken{
			{Name: "vera", Roles: []string{"viewer"}, Secret: "viewer-token-abcdef0123456789"},
			{Name: "otto", Roles: []string{"operator"}, Secret: "operator-token-abcdef0123456789"},
			{Name: "ada", Roles: []string{"admin"}, Secret: "admin-token-abcdef0123456789xyz"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(t, Options{UserLinks: svc, AdminAuth: auth})
	revoke := `{"id":"` + ids["bob-laptop"] + `"}`
	issue := `{"subject":"ci-bot"}`

	if code := getJSON(t, srv, "/admin/api/userlinks", "", nil); code != http.StatusUnauthorized {
		t.Errorf("listing without credentials: %d", code)
	}
	if code := getJSON(t, srv, "/admin/api/userlinks", "viewer-token-abcdef0123456789", nil); code != http.StatusOK {
		t.Errorf("a viewer listing: %d", code)
	}
	if rec := postJSONAs(t, srv, "/admin/api/userlinks/revoke", "viewer-token-abcdef0123456789", revoke); rec.Code != http.StatusForbidden {
		t.Errorf("a viewer revoking: %d", rec.Code)
	}
	if rec := postJSONAs(t, srv, "/admin/api/userlinks/issue", "operator-token-abcdef0123456789", issue); rec.Code != http.StatusForbidden {
		t.Errorf("an operator issuing: %d", rec.Code)
	}
	rec := postJSONAs(t, srv, "/admin/api/userlinks/revoke", "operator-token-abcdef0123456789", revoke)
	if rec.Code != http.StatusOK {
		t.Fatalf("an operator revoking: %d %s", rec.Code, rec.Body)
	}
	// The revocation names the administrator who did it.
	if info, _ := svc.Registry().Get(ids["bob-laptop"]); info.RevokedBy != "otto" {
		t.Fatalf("revoked by %q, want the operator", info.RevokedBy)
	}
	rec = postJSONAs(t, srv, "/admin/api/userlinks/issue", "admin-token-abcdef0123456789xyz", issue)
	var issued struct {
		Link userlinks.Info `json:"link"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil || rec.Code != http.StatusCreated || issued.Link.IssuedBy != "ada" {
		t.Fatalf("an administrator issuing: %d %s", rec.Code, rec.Body)
	}
}
