package signin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeFlow is a sign-in whose state on a request is looked up by the request's
// "state" parameter.
type fakeFlow struct {
	name   string
	route  string
	states map[string]State
	served int
}

func (f *fakeFlow) CallbackRoute() string { return f.route }
func (f *fakeFlow) CallbackState(r *http.Request) State {
	return f.states[r.URL.Query().Get("state")]
}
func (f *fakeFlow) HandleCallback(w http.ResponseWriter, r *http.Request) {
	f.served++
	_, _ = w.Write([]byte(f.name))
}

func serve(h http.Handler, state string) string {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/oidc?code=c&state="+state, nil))
	return rr.Body.String()
}

func TestRoutesGroupsCallbacksByPath(t *testing.T) {
	admin := &fakeFlow{name: "admin", route: "/auth/oidc"}
	links := &fakeFlow{name: "links", route: "/auth/oidc"}
	own := &fakeFlow{name: "own", route: ""}
	other := &fakeFlow{name: "other", route: "/sso/back"}
	routes := Routes(admin, nil, own, links, other)
	if len(routes) != 2 || routes["/auth/oidc"] == nil || routes["/sso/back"] == nil {
		t.Fatalf("routes = %v", routes)
	}
	if got := serve(routes["/sso/back"], "x"); got != "other" {
		t.Fatalf("a route of one flow is served by %q", got)
	}
	if len(Routes(own)) != 0 || len(Routes()) != 0 {
		t.Fatal("a flow served under its own mount needs no route")
	}
}

// A shared callback goes to the sign-in the request answers; a request with a
// stale or foreign state goes to the flow that has state on it, so its user
// sees the error of the sign-in they started; one with no state at all goes to
// the first flow.
func TestSharedCallbackDispatch(t *testing.T) {
	admin := &fakeFlow{name: "admin", route: "/auth/oidc", states: map[string]State{
		"a": Matches, "both": Foreign, "stale-admin": Foreign, "stale-both": Foreign,
	}}
	links := &fakeFlow{name: "links", route: "/auth/oidc", states: map[string]State{
		"l": Matches, "both": Matches, "stale-links": Foreign, "stale-both": Foreign,
	}}
	h := Routes(admin, links)["/auth/oidc"]
	for state, want := range map[string]string{
		"a":           "admin",
		"l":           "links",
		"both":        "links", // the admin flow's cookie is there, but the state is the links flow's
		"stale-admin": "admin",
		"stale-links": "links",
		"stale-both":  "admin",
		"none":        "admin",
	} {
		if got := serve(h, state); got != want {
			t.Errorf("state %q is served by %q, want %q", state, got, want)
		}
	}
}
